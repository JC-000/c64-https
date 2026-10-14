#!/usr/bin/env python3
"""BACKEND=uci read pacing: a uci_fence after every UCI register WRITE,
none after a READ (src/net/uci/uci_regs.inc, uci_read_fence).

Runs the SHIPPED machine code (build/c64-https.prg at build/labels.txt's
addresses) on test_uci_abort_recovery.py's interpreter and Command
Interface model, through net_init, a connect, data / idle / EOF / reset
polls, a send and a close, and logs every access to $DF1C-$DF1F with the
uci_fence executions that follow it before the next access. A fence is
recognised by its bytes as assembled (that module's FENCE), whether it is
inline or inside uci_settle.

  every image   each WRITE to $DF1C/$DF1D is followed by a fence before
                the next UCI access.
  default       no READ is followed by a fence, except the one kept before
                net_poll's header read (label uci_poll_stage_fence).
  UCI_READ_FENCE=1 (flags.stamp)
                every READ is followed by a fence (the previous products).

What it does not see: a delay that is not a uci_fence (a NOP sled, a
loop), the trust store's uci_dos.s (not on these flows; still fenced),
and anything about the FPGA's real timing -- the hardware A/B in the PR
is that evidence.

    make BACKEND=uci ... && python3 tools/check_uci_read_pacing.py [--expect default|fenced]

--expect overrides what flags.stamp says, to show the check red on the
other image. Standalone, like tools/check_m3_client.py. Exit 0 pass,
1 fail, 2 cannot run.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_uci_abort_recovery as A                      # noqa: E402
import test_uci_data_acc as base                         # noqa: E402

UCI_REGS = range(0xDF1C, 0xDF20)


class Log:
    def __init__(self):
        self.events = []        # [kind, addr, [fence pcs after it]]

    def access(self, kind, addr):
        if addr in UCI_REGS:
            self.events.append([kind, addr, []])

    def fence(self, pc):
        if self.events:
            self.events[-1][2].append(pc)


def _traced(model, log):
    read, write = model.read, model.write

    def r(addr):
        log.access("r", addr)
        return read(addr)

    def w(addr, value):
        log.access("w", addr)
        return write(addr, value)
    model.read, model.write = r, w
    return model


class PacingCPU(A.FastCPU):
    log = None

    def step(self):
        pc = self.pc
        ram = self.mem.ram
        if ram[pc] == 0x48 and ram[pc:pc + len(A.FENCE)] == A.FENCE:
            self.log.fence(pc)
        super().step()


def _machine(replies, log):
    model = _traced(A.AbortModel(replies), log)
    cpu, mem, labels = A._require(model)
    pcpu = PacingCPU(mem)
    pcpu.log = log
    return pcpu, mem, labels, model


def flows():
    """(name, Log) for each traced session."""
    out = []
    log = Log()
    cpu, mem, labels, uci = _machine([A.CONNECT_OK], log)
    cpu.call(labels["net_init"])
    A._assert_connected(cpu, mem, uci, labels, "pacing: connect")
    out.append(("init+connect", log))
    for name, reply in (("poll data", (b"\x40\x00" + bytes(range(64)), A.OK)),
                        ("poll idle", (b"\xff\xff", b"02,NO DATA: 11")),
                        ("poll EOF", (b"\x00\x00", b"01,CONNECTION CLOSED BY HOST")),
                        ("poll reset", (b"\xff\xff", b"02,NO DATA: 104"))):
        log = Log()
        cpu, mem, labels, uci = _machine([reply], log)
        mem.write(labels["uci_socket_id"], 1)
        mem.write(labels["net_tcp_state"], A.NET_TCP_CONNECTED)
        cpu.call(labels["net_poll"], budget=8_000_000)
        out.append((name, log))
    log = Log()
    cpu, mem, labels, uci = _machine([(b"\x3a\x00", A.OK), (b"", A.OK)], log)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], A.NET_TCP_CONNECTED)
    mem.write(labels["net_send_len"], 58)
    mem.write(labels["net_send_len"] + 1, 0)
    cpu.a, cpu.x = 0x00, 0x04
    cpu.call(labels["net_tcp_send"], budget=4_000_000)
    cpu.call(labels["net_tcp_close"], budget=4_000_000)
    out.append(("send+close", log))
    return out, labels


def _fenced_image():
    stamp = base.LABELS.parent / "flags.stamp"
    for line in stamp.read_text().splitlines():
        if line.startswith("CA65FLAGS="):
            return "-D UCI_READ_FENCE" in line
    raise A.Unavailable("%s has no CA65FLAGS line" % stamp)


def main(argv) -> int:
    expect = None
    if len(argv) == 3 and argv[1] == "--expect" and argv[2] in ("default", "fenced"):
        expect = argv[2] == "fenced"
    elif len(argv) != 1:
        print(__doc__)
        return 2
    try:
        fenced = _fenced_image() if expect is None else expect
        traces, labels = flows()
    except (A.Unavailable, FileNotFoundError) as exc:
        print("COULD NOT RUN: %s" % exc)
        return 2
    keep = labels.get("uci_poll_stage_fence")
    if keep is None:
        print("COULD NOT RUN: uci_poll_stage_fence is not in labels.txt")
        return 2
    fails = 0
    for name, log in traces:
        ev = log.events
        writes = [e for e in ev[:-1] if e[0] == "w"]
        reads = [e for e in ev[:-1] if e[0] == "r"]
        bare = [e for e in writes if not e[2]]
        if fenced:
            bad = [e for e in reads if not e[2]]
            what = "unfenced read(s) in an UCI_READ_FENCE=1 image"
        else:
            bad = [e for e in reads if any(pc != keep for pc in e[2])]
            what = "fenced read(s) in the default image"
        ok = len(writes) > 3 and not bare and not bad
        fails += not ok
        print("%s %-13s %3d writes, %4d reads; %s%s" % (
            "PASS" if ok else "FAIL", name, len(writes), len(reads),
            "%d write(s) with no fence after" % len(bare) if bare else "writes fenced",
            "; %d %s, first $%04X" % (len(bad), what, bad[0][1]) if bad else ""))
    print("\n%d/%d flows pass (%s image)" % (len(traces) - fails, len(traces),
                                            "fenced" if fenced else "default"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
