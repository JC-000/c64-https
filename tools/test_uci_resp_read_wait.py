#!/usr/bin/env python3
"""uci_read_resp_bytes must not wait for response bytes that cannot come.

WHAT THIS TESTS

``uci_read_resp_bytes`` (src/net/uci/uci_cmd.s) copies a staged reply into
a caller's buffer.  It used to wait for every missing byte with an
ITERATION-counted spin: 65,536 fenced ``$DF1C`` reads before giving up on
one byte.  Derived, not measured: a fence is ~5,4xx cycles, so that is
~7.5 s at 48 MHz and ~6 min at 1 MHz, scaling with the clock.  This
breaks CLAUDE.md's "bounded timeouts must use wall-clock time" rule, and
any reply shorter than ``uci_resp_max`` paid it: an empty GET_IPADDR
(an out-of-range interface index) and an empty TCP_CONNECT (a failed
connect or DNS lookup).  SOCKET_WRITE always answers 2 bytes on firmware;
only a #230(a) mis-parsed command ("21,UNKNOWN COMMAND") is shorter.

The wait could never succeed, so the fix removes it rather than bounding
it.  Every caller reaches the read only after ``uci_push_wait`` has seen
STATE bit 5, which VALIDATE sets, and after ``uci_check_err`` has seen
ERROR clear.  The firmware writes the response length BEFORE VALIDATE
(``command_intf.cc`` ``copy_result``: RESPONSE_LEN_H/L, then
HANDSHAKE_VALIDATE_*).  ``command_protocol.vhd`` recomputes DATA_AV every
clock as ``(response_pointer - base) < response_length`` and
``state(1) and not handshake_in(2)``.  After VALIDATE only three things
move those terms, and all three are host-side actions: a ``$DF1E`` read
(advances the pointer), DATA_ACC or ABORT (only the C64 writes these),
and a firmware length/handshake write.  The firmware's single writer is
the command task, and it acts only on events queued by those host
actions.  So once DATA_AV reads low within a reply it stays low, and the
spin's success arm was unreachable.

The one-clock register lag between ``state(1)`` and DATA_AV is modelled
too (``lag``).  Between the read that sees VALID and the first DATA_AV
test, the code makes two more fenced ``$DF1C`` reads; the real lag is
one FPGA clock.

HOW IT TESTS IT

The shipped machine code (``build/c64-https.prg`` at ``build/labels.txt``
addresses) runs on ``test_uci_data_acc.py``'s 6502 interpreter.  The
register model is ``test_uci_timeout_recovery.py``'s, with each inline
``uci_fence`` taken in one step (``test_uci_abort_recovery.FastCPU``).
The cost is counted in ``$DF1C`` reads, which skipping the fence does not
change.

WHAT IT DOES NOT PROVE

Wall-clock time on a device.  The C64 Ultimate's FPGA source is not
public, so the DATA_AV argument above is checked against the U64E's VHDL
only.  The C64U's command task (7b628eb1) is identical in every write
this argument uses.

Anything about the two inline ``uci_fence``s in ``@rd_loop``: FastCPU
takes each in one step, so deleting either one survives this suite.  They
are timing (the FPGA register gap), which the model cannot see.

Runs standalone or under pytest (exit 0 pass, 1 fail, 2 cannot run;
``C64_UCI_TESTS_OPTIONAL=1`` opts out)::

    python3 tools/test_uci_resp_read_wait.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_uci_data_acc import CPUError                    # noqa: E402
import test_uci_timeout_recovery as base                  # noqa: E402
from test_uci_timeout_recovery import (                   # noqa: E402
    CommandInterface, Memory, Unavailable, VoluntarySkip,
    ST_DATA_LAST, UCI_STAT_DATA_AV, UCI_STAT_STAT_AV,
)
from test_uci_abort_recovery import FastCPU               # noqa: E402
from _skip_policy import require, verdict                 # noqa: E402

OPT_OUT_ENV = "C64_UCI_TESTS_OPTIONAL"
CERTIFIES = "uci_read_resp_bytes' short-reply exit"

NET_TCP_CONNECTED = 0x01
NET_TCP_CONNECT_FAIL = 0x03
UCI_ERR_NO_IP = 0x83
UCI_ERR_NO_SOCKET = 0x88
UCI_ERR_SHORT_WRITE = 0x87

OK = b"00,OK"
OUT_OF_RANGE = b"82,PARAMETER(S) OUT OF RANGE"
CONNECT_ERR = b"11,ERROR ON CONNECT: 113"

NET_DHCP_MAX_IFACE = 4          # src/net/uci/net.s
PORT = 443
HOST = b"h"
SEND_SRC = 0x0400

# $DF1C reads one whole command may spend (entry wait, push wait,
# check_err, read, both drains).  A full reply costs ~a dozen; the old
# read of ONE missing byte cost 65,536 on its own.
COMMAND_READ_CEILING = 64

NEEDED_LABELS = ("uci_read_resp_bytes", "uci_resp_dst", "uci_resp_max",
                 "uci_resp_count", "net_dhcp_acquire", "net_tcp_connect",
                 "net_tcp_send", "net_send_len", "uci_ipaddr_resp",
                 "uci_write_resp", "uci_socket_id", "uci_host_buf",
                 "net_local_ip", "net_last_error", "net_tcp_state",
                 "uci_status_len", "uci_status_force", "tcp_recv_head",
                 "tcp_recv_tail")


class CountingInterface(CommandInterface):
    """The sibling model, plus:

    * a ``$DF1C`` read counter per accepted PUSH_CMD (``reads_per_cmd``);
    * ``lag``: for that many ``$DF1C`` reads after VALIDATE, STATE already
      reads "10" while DATA_AV/STAT_AV still read low.  This is
      ``command_protocol.vhd``'s registered response_valid/status_valid,
      one FPGA clock behind state(1), expressed in reads.
    """

    def __init__(self, replies=(), lag=0):
        super().__init__(replies)
        self.lag = lag
        self._lag_left = 0
        self.reads_per_cmd = []
        self.data_reads = 0

    def _tick(self):
        before = self.state
        super()._tick()
        if before != ST_DATA_LAST and self.state == ST_DATA_LAST:
            self._lag_left = self.lag

    def read(self, addr):
        if addr == 0xDF1C:
            if self.reads_per_cmd:
                self.reads_per_cmd[-1] += 1
            value = super().read(addr)
            if self._lag_left > 0:
                self._lag_left -= 1
                value &= ~(UCI_STAT_DATA_AV | UCI_STAT_STAT_AV) & 0xFF
            return value
        if addr == 0xDF1E:
            self.data_reads += 1
        return super().read(addr)

    def write(self, addr, value):
        if addr == 0xDF1C and value & 0x01 and self.state == 0:
            self.reads_per_cmd.append(0)
        super().write(addr, value)


def _machine(uci):
    if not base.PRG.is_file() or not base.LABELS.is_file():
        raise Unavailable("build/c64-https.prg or labels.txt is missing — "
                          "build with `make BACKEND=uci "
                          "USE_NISTCURVES_ONCHIP=1`")
    labels = base._labels()
    for needed in NEEDED_LABELS:
        if needed not in labels:
            raise Unavailable(
                "%s is not in build/labels.txt — this is not a BACKEND=uci "
                "build; rebuild with `make BACKEND=uci "
                "USE_NISTCURVES_ONCHIP=1`" % needed)
    raw = base.PRG.read_bytes()
    # No bounded wait may expire in these tests: a $89 would hide the cost.
    mem = Memory(raw[2:], raw[0] | (raw[1] << 8), uci,
                 tod_reads_per_tenth=1_000_000)
    for name in ("uci_status_len", "uci_status_force", "net_last_error",
                 "net_tcp_state", "uci_socket_id"):
        mem.write(labels[name], 0)
    for off in range(2):
        mem.write(labels["tcp_recv_head"] + off, 0)
        mem.write(labels["tcp_recv_tail"] + off, 0)
    for i, b in enumerate(HOST + b"\x00"):
        mem.write(labels["uci_host_buf"] + i, b)
    return FastCPU(mem), mem, labels


def _require(uci):
    try:
        return _machine(uci)
    except Unavailable as exc:
        if os.environ.get(OPT_OUT_ENV) != "1":
            raise
        require(False, str(exc), executed=0, total=len(TESTS),
                certifies=CERTIFIES, opt_out_env=OPT_OUT_ENV)


def _err(mem, labels):
    return mem.read(labels["net_last_error"])


def _check_cost(uci, what):
    worst = max(uci.reads_per_cmd) if uci.reads_per_cmd else 0
    base._check(worst <= COMMAND_READ_CEILING, (
        "%s: one command spent %d $DF1C reads (ceiling %d) — "
        "uci_read_resp_bytes waited for response bytes the firmware never "
        "staged (per command: %s)"
        % (what, worst, COMMAND_READ_CEILING, uci.reads_per_cmd)))


# ---------------------------------------------------------------------------
# The routine itself
# ---------------------------------------------------------------------------

def test_reads_exactly_what_is_staged():
    """Direct calls against a VALID reply of n bytes, max m: stores
    min(n, m) bytes, returns that count in uci_resp_count and Y, leaves
    the rest for uci_drain_resp, preserves X, and tests DATA_AV at most
    once per byte plus one."""
    for n in (0, 1, 2, 5, 12, 13):
        for m in (0, 1, 2, 12):
            reply = bytes(range(0x30, 0x30 + n))
            uci = CountingInterface()
            cpu, mem, labels = _require(uci)
            uci.state = ST_DATA_LAST
            uci.response, uci.status = reply, OK
            dst = 0x0400
            for i in range(16):
                mem.write(dst + i, 0xEE)
            mem.write(labels["uci_resp_dst"], dst & 0xFF)
            mem.write(labels["uci_resp_dst"] + 1, dst >> 8)
            mem.write(labels["uci_resp_max"], m)
            uci.reads_per_cmd.append(0)
            cpu.x = 0x5A
            cpu.call(labels["uci_read_resp_bytes"], budget=2_000_000)
            got = min(n, m)
            tag = "n=%d max=%d" % (n, m)
            count = mem.read(labels["uci_resp_count"])
            stored = bytes(mem.read(dst + i) for i in range(16))
            base._check(count == got and cpu.y == got,
                        "%s: uci_resp_count=%d Y=%d, expected %d"
                        % (tag, count, cpu.y, got))
            base._check(stored == reply[:got] + b"\xEE" * (16 - got),
                        "%s: buffer holds %s" % (tag, stored.hex()))
            base._check(uci.resp_ptr == got,
                        "%s: %d bytes taken from the queue, expected %d "
                        "(the excess belongs to uci_drain_resp)"
                        % (tag, uci.resp_ptr, got))
            base._check(cpu.x == 0x5A, "%s: X not preserved ($%02X)"
                        % (tag, cpu.x))
            base._check(uci.reads_per_cmd[-1] <= got + 1, (
                "%s: %d $DF1C reads for %d bytes — the read waited on a "
                "DATA_AV that had already settled low"
                % (tag, uci.reads_per_cmd[-1], got)))


# ---------------------------------------------------------------------------
# The three callers, on the short replies the firmware actually sends
# ---------------------------------------------------------------------------

def test_dhcp_out_of_range_probes_are_cheap():
    """GET_IPADDR on an index >= getNumberOfInterfaces() is an EMPTY,
    VALID reply with status "82,..." (network_target.cc) — no ERROR bit.
    Four of them (a box with no lease anywhere) must cost a few reads
    each and still end C=1 / $83, as before."""
    uci = CountingInterface([(b"", OUT_OF_RANGE)] * NET_DHCP_MAX_IFACE)
    cpu, mem, labels = _require(uci)
    for i in range(12):
        mem.write(labels["uci_ipaddr_resp"] + i, 0)
    carry = cpu.call(labels["net_dhcp_acquire"], budget=8_000_000)
    base._check(len(uci.reads_per_cmd) == NET_DHCP_MAX_IFACE,
                "probed %d interfaces, expected %d"
                % (len(uci.reads_per_cmd), NET_DHCP_MAX_IFACE))
    base._check(carry and _err(mem, labels) == UCI_ERR_NO_IP,
                "C=%d net_last_error=$%02X, expected C=1 $%02X"
                % (carry, _err(mem, labels), UCI_ERR_NO_IP))
    base._check(uci.accepts == NET_DHCP_MAX_IFACE and uci.state == 0,
                "every probe must be accepted back to idle")
    _check_cost(uci, "net_dhcp_acquire, 4 out-of-range probes")


def test_dhcp_full_reply_unchanged():
    """Control: a full 12-byte reply on index 0 is a lease, C=0."""
    ip = bytes([10, 43, 23, 83])
    rec = ip + bytes([255, 255, 255, 0, 10, 43, 23, 1])
    uci = CountingInterface([(rec, OK)])
    cpu, mem, labels = _require(uci)
    carry = cpu.call(labels["net_dhcp_acquire"], budget=8_000_000)
    got = bytes(mem.read(labels["net_local_ip"] + i) for i in range(4))
    base._check(not carry and got == ip and _err(mem, labels) == 0,
                "C=%d ip=%s err=$%02X" % (carry, got.hex(),
                                          _err(mem, labels)))
    _check_cost(uci, "net_dhcp_acquire, full reply")


def test_failed_connect_is_cheap_and_still_no_socket():
    """TCP_CONNECT that fails (DNS or connect()) answers c_message_empty
    plus a status line (network_target.cc open_socket). Must stay
    C=1 / $88 UCI_ERR_NO_SOCKET / CONNECT_FAIL, without the wait."""
    for status in (CONNECT_ERR, b"", OK):
        uci = CountingInterface([(b"", status)])
        cpu, mem, labels = _require(uci)
        cpu.a, cpu.x = PORT & 0xFF, PORT >> 8
        carry = cpu.call(labels["net_tcp_connect"], budget=8_000_000)
        base._check(carry and _err(mem, labels) == UCI_ERR_NO_SOCKET
                    and mem.read(labels["net_tcp_state"])
                    == NET_TCP_CONNECT_FAIL,
                    "C=%d err=$%02X state=%d, expected C=1 $88 CONNECT_FAIL"
                    % (carry, _err(mem, labels),
                       mem.read(labels["net_tcp_state"])))
        base._check(uci.accepts == 1 and uci.state == 0,
                    "the empty connect reply was not accepted to idle")
        _check_cost(uci, "net_tcp_connect, empty reply (%r)" % status)


def test_connect_full_reply_under_valid_lag():
    """Control, and the settle: a 1-byte socket id connects, also when
    DATA_AV trails STATE by up to two $DF1C reads (the VHDL lag is one
    FPGA clock; the code puts two fenced reads in between)."""
    for lag in (0, 1, 2):
        uci = CountingInterface([(b"\x07", OK)], lag=lag)
        cpu, mem, labels = _require(uci)
        cpu.a, cpu.x = PORT & 0xFF, PORT >> 8
        carry = cpu.call(labels["net_tcp_connect"], budget=8_000_000)
        base._check(not carry and mem.read(labels["uci_socket_id"]) == 7
                    and mem.read(labels["net_tcp_state"])
                    == NET_TCP_CONNECTED,
                    "lag=%d: C=%d socket=%d err=$%02X" % (
                        lag, carry, mem.read(labels["uci_socket_id"]),
                        _err(mem, labels)))


def test_short_send_reply_is_cheap():
    """SOCKET_WRITE always answers 2 bytes on firmware (send_to_socket);
    a 0- or 1-byte reply is the #230(a) "21,UNKNOWN COMMAND" shape. It
    must return promptly and leave the interface idle."""
    for reply in (b"", b"\x04"):
        uci = CountingInterface([(reply, OK)])
        cpu, mem, labels = _require(uci)
        mem.write(labels["uci_socket_id"], 1)
        mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
        mem.write(labels["uci_write_resp"], 0)
        mem.write(labels["uci_write_resp"] + 1, 0)
        mem.write(labels["net_send_len"], 4)
        mem.write(labels["net_send_len"] + 1, 0)
        cpu.a, cpu.x = SEND_SRC & 0xFF, SEND_SRC >> 8
        cpu.call(labels["net_tcp_send"], budget=8_000_000)
        base._check(uci.accepts >= 1 and uci.state == 0,
                    "short send reply not accepted to idle")
        _check_cost(uci, "net_tcp_send, %d-byte reply" % len(reply))


TESTS = (
    test_reads_exactly_what_is_staged,
    test_dhcp_out_of_range_probes_are_cheap,
    test_dhcp_full_reply_unchanged,
    test_failed_connect_is_cheap_and_still_no_socket,
    test_connect_full_reply_under_valid_lag,
    test_short_send_reply_is_cheap,
)


def main():
    passed = failed = 0
    for test in TESTS:
        try:
            test()
        except VoluntarySkip as exc:
            print("SKIP: %s" % exc)
            return verdict(passed, failed,
                           skipped=len(TESTS) - passed - failed,
                           opt_out_env=OPT_OUT_ENV, certifies=CERTIFIES)
        except Unavailable as exc:
            print("CANNOT RUN: %s" % exc)
            return 2
        except (AssertionError, CPUError) as exc:
            failed += 1
            print("FAIL %s: %s" % (test.__name__, exc))
        else:
            passed += 1
            print("ok   %s" % test.__name__)
    print("%d/%d passed, %d assertions" % (len(TESTS) - failed, len(TESTS),
                                           base.ASSERTIONS_RUN))
    return verdict(passed, failed, certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
