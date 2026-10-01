#!/usr/bin/env python3
"""BACKEND=uci-m3: the shipped 6502 client against a model of the M3 firmware.

WHAT THIS TESTS

The uci-m3 adapter (src/net/uci-m3/) drives the M3 firmware's TLS sockets:
OPEN_TLS `03 21`, INFO `03 23`, RELEASE `03 25`, and READ/WRITE/CLOSE on a
TLS handle. Its rules come from M3-SPEC v1 (sha256 c265fdfc...) and the
errata v1.1 (f9a39ff3...) and v1.2 (a6802f40...). Each test below pins one
rule, by running the SHIPPED machine code (lifted out of build/c64-https.prg
at build/labels.txt's addresses, as tools/test_uci_data_acc.py does) against
`M3Device`: the $DF1B-$DF1F register file of command_protocol.vhd plus a
Nios that answers the M3 commands, with a clock.

`tools/mutate_m3_client.py` breaks each rule in the SOURCE, rebuilds, and
shows the matching test going red. Run it rather than quoting its count.

WHAT THE MODEL IS, AND IS NOT

  * The register file: the four states, error_busy on a PUSH that is not
    idle, DATA_ACC gated on state(1), the queues advancing on read, ABORT
    serviced only after the command in progress returns (command_intf.cc
    run_task is FIFO; ABORT does not shorten PROCESSING, S 1.1), and a
    reset that drops a pending READ reply (S 1.1 Rule 1, M-2).
  * The clock: CIA2 timer B, the deadline clock the adapter uses, advances
    one 10 ms unit per STEPS_PER_UNIT interpreted instructions. The fences
    therefore cost model time too; every bound is about relative order
    (45 s versus 12 s, ABORT + 12 s), not wall-clock accuracy.
  * The Nios: the M3 command layouts and status lines the spec and the
    bench's green wire logs (session-0930/evidence/m3e2e) show. It is a
    MODEL: the hardware evidence is the rig runs, not this file.

It records PROTOCOL VIOLATIONS as it sees them (a write while $DF1C bit 2 is
set, ABORT written together with PUSH, a data-accept before the block was
read to its end, a command naming a handle that went GONE, INFO or RELEASE
with a wrong length) and every test asserts there were none.

    make BACKEND=uci-m3 && python3 tools/check_m3_client.py

Not a pytest module, on purpose: it needs a BACKEND=uci-m3 image in build/,
and bare `pytest` already needs a BACKEND=uci one there for the
test_uci_*.py modules (pytest.ini). No single build satisfies both, so this
runs standalone, like tools/mutate_*.py. Exit 0 pass, 1 fail, 2 cannot run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_uci_data_acc as _cpu_mod                     # noqa: E402
from test_uci_data_acc import CPU, CPUError              # noqa: E402
from _skip_policy import cannot_run                       # noqa: E402

PRG = Path(os.environ.get("M3_PRG", REPO / "build" / "c64-https.prg"))
LABELS = Path(os.environ.get("M3_LABELS", REPO / "build" / "labels.txt"))
CERTIFIES = "the uci-m3 adapter's M3-SPEC rules"
OPT_OUT_ENV = "C64_UCI_TESTS_OPTIONAL"

# Opcodes http.s / data.s need beyond the uci adapter's subset.
_IMM, _ZP, _ZPX, _ABS, _ABX, _ABY, _INDX, _INDY = (
    _cpu_mod.IMM, _cpu_mod.ZP, _cpu_mod.ZPX, _cpu_mod.ABS, _cpu_mod.ABX,
    _cpu_mod.ABY, _cpu_mod.INDX, _cpu_mod.INDY)
_cpu_mod.OPCODES.update({
    0x11: ("ORA", _INDY), 0x31: ("AND", _INDY), 0x51: ("EOR", _INDY),
    0x71: ("ADC", _INDY), 0xF1: ("SBC", _INDY), 0xD1: ("CMP", _INDY),
    0x75: ("ADC", _ZPX), 0xF5: ("SBC", _ZPX), 0x5D: ("EOR", _ABX),
    0x59: ("EOR", _ABY), 0x55: ("EOR", _ZPX), 0x1E: ("ASL", _ABX),
    0x5E: ("LSR", _ABX), 0x3E: ("ROL", _ABX), 0x7E: ("ROR", _ABX),
    0x36: ("ROL", _ZPX), 0x76: ("ROR", _ZPX), 0x16: ("ASL", _ZPX),
    0x56: ("LSR", _ZPX), 0x6E: ("ROR", _ABS), 0x2E: ("ROL", _ABS),
    0x66: ("ROR", _ZP), 0xE1: ("SBC", _INDX), 0x61: ("ADC", _INDX),
})

# --- registers (uci_regs.inc) ------------------------------------------------
DATA_AV, STAT_AV, ERROR_BIT, ABORT_BIT, BUSY_BIT = 0x80, 0x40, 0x08, 0x04, 0x01
CTRL_PUSH, CTRL_ACC, CTRL_ABORT, CTRL_CLR = 0x01, 0x02, 0x04, 0x08
ST_IDLE, ST_BUSY, ST_LAST, ST_MORE = 0, 1, 2, 3

NET_TCP_CLOSED, NET_TCP_CONNECTED = 0x00, 0x01
NET_TCP_ERROR, NET_TCP_CONNECT_FAIL = 0x02, 0x03
ERR_NOT_PRESENT, ERR_CONNECT_FAIL, ERR_WAIT_TIMEOUT = 0x81, 0x84, 0x89

STEPS_PER_UNIT = 200            # interpreted instructions per 10 ms unit
SECOND = 100                    # units
FAST = 2                        # units a quick command takes
NEVER = None

# Status lines, as the bench's green wire logs show them.
OK = b"00,OK"
IDLE = b"02,NO DATA: 11"
NOT_OURS = b"02,NO DATA: 9"
CLOSED_BY_HOST = b"01,CONNECTION CLOSED BY HOST"
NO_NOTIFY = b"05,TLS CLOSED WITHOUT NOTIFY"
ALERT = b"14,TLS ALERT RECEIVED: 70"
CLOSE_UNOWNED = b"12,ERROR ON CLOSE: 9"
UNKNOWN = b"21,UNKNOWN COMMAND"
INVALID = b"81,INVALID PARAMS"
NAME_MISMATCH = b"94,CERTIFICATE NAME MISMATCH: 0x00000004"   # 40 B (ER-8)

INFO_READY = bytes([1, 2, 0, 7, 7, 3, 1, 0x35, 1, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0])


class Unavailable(Exception):
    pass


class M3Device:
    """$DF1B-$DF1F + an M3 Nios, driven by the CPU's reads and writes."""

    def __init__(self, clock):
        self.clock = clock              # () -> units
        self.present = True
        self.tls = True                 # False: firmware without M3 ($23 -> 21)
        self.info = bytearray(INFO_READY)
        self.ready_after = None         # units at which [4] becomes 07
        # register-file state
        self.state = ST_IDLE
        self.new_command = False
        self.error_busy = False
        self.abort_pending = False
        self.cmd = bytearray()
        self.blocks = []                # remaining response blocks
        self.response = b""
        self.status = b""
        self.rp = self.sp = 0
        self.done_at = None             # units at which the reply is staged
        self.pending = None             # (blocks, status) for done_at
        self.abort_due = None
        # the Nios
        self.sessions = {}              # handle -> dict
        self.gone = set()               # handles seen end with 01/05
        self.open_result = ("ok", 5)    # or ("refuse", status) / ("delay", u)
        self.open_delay = FAST
        self.read_delay = FAST
        self.write_result = None        # None = ok, else (hdr, status)
        self.never = set()              # command bytes that never complete
        self.slow = {}                  # command byte -> delay in units
        self.forced_blocks = None       # READ: override the reply blocks
        self.next_handle = 5
        # observation
        self.log = []                   # (units, command bytes)
        self.ctrl_writes = []           # (units, value)
        self.violations = []
        self.pushes_rejected = 0
        self.accepts = 0
        self.accepts_on_more = 0
        self.aborts = 0
        self.abort_times = []
        self.last_abort_cleared = None
        self.writes = []                # (handle, data)

    # ---------------------------------------------------------------- time --
    def _advance(self):
        now = self.clock()
        if self.done_at is not None and now >= self.done_at:
            self.done_at = None
            blocks, status = self.pending
            self.pending = None
            self.new_command = False
            self.blocks = list(blocks)
            self.status = bytes(status)
            self.sp = 0
            self._load_block()
        if (self.abort_pending and self.done_at is None
                and self.pending is None):
            if self.abort_due is None:
                self.abort_due = now + 1
            elif now >= self.abort_due:
                # HANDSHAKE_RESET: the dropped reply is gone, READ data too
                self.abort_due = None
                self.abort_pending = False
                self.state = ST_IDLE
                self.new_command = False
                self.blocks = []
                self.response = self.status = b""
                self.rp = self.sp = 0
                self.cmd = bytearray()
                self.last_abort_cleared = now

    def _load_block(self):
        self.response = self.blocks.pop(0) if self.blocks else b""
        self.rp = 0
        self.state = ST_MORE if self.blocks else ST_LAST

    # --------------------------------------------------------------- reads --
    def read(self, addr):
        self._advance()
        if addr == 0xDF1C:
            if not self.present:
                return 0xFF
            bits = (self.state << 4)
            if self.state & 2:
                if self.rp < len(self.response):
                    bits |= DATA_AV
                if self.sp < len(self.status):
                    bits |= STAT_AV
            if self.error_busy:
                bits |= ERROR_BIT
            if self.abort_pending:
                bits |= ABORT_BIT
            if self.new_command:
                bits |= BUSY_BIT
            return bits
        if addr == 0xDF1D:
            return 0xC9 if self.present else 0xFF
        if addr == 0xDF1E:
            if not self.state & 2 or self.rp >= len(self.response):
                return 0x00
            self.rp += 1
            return self.response[self.rp - 1]
        if addr == 0xDF1F:
            if not self.state & 2 or self.sp >= len(self.status):
                return 0x00
            self.sp += 1
            return self.status[self.sp - 1]
        return 0x00

    # -------------------------------------------------------------- writes --
    def write(self, addr, value):
        self._advance()
        now = self.clock()
        if addr not in (0xDF1C, 0xDF1D):
            return
        if self.abort_pending:
            self.violations.append(
                "wrote $%02X to $%04X while $DF1C bit 2 was set (Appendix A: "
                "write nothing until it reads 0)" % (value, addr))
        if addr == 0xDF1D:
            self.cmd.append(value)
            return
        self.ctrl_writes.append((now, value))
        if value & CTRL_ABORT and value & CTRL_PUSH:
            self.violations.append("ABORT written together with PUSH ($05)")
        if value & CTRL_CLR:
            self.error_busy = False
        if value & CTRL_ACC:
            if self.state & 2:
                if self.rp < len(self.response):
                    self.violations.append(
                        "data-accept with %d unread byte(s) in the block "
                        "(ER-5)" % (len(self.response) - self.rp))
                self.accepts += 1
                if self.state == ST_MORE:
                    self.accepts_on_more += 1
                    self._load_block()
                else:
                    self.state = ST_IDLE
                    self.response = self.status = b""
                    self.rp = self.sp = 0
        if value & CTRL_ABORT:
            self.aborts += 1
            self.abort_times.append(now)
            self.abort_pending = True
            self.abort_due = None
        if value & CTRL_PUSH:
            if self.state != ST_IDLE or self.new_command:
                self.error_busy = True
                self.pushes_rejected += 1
            else:
                self._push(bytes(self.cmd), now)
            self.cmd = bytearray()

    # ----------------------------------------------------------------- Nios --
    def _push(self, cmd, now):
        self.state = ST_BUSY
        self.new_command = True
        self.log.append((now, cmd))
        blocks, status, delay = self._execute(cmd, now)
        self.pending = (blocks, status)
        self.done_at = None if delay is NEVER else now + delay
        if delay is NEVER:
            self.pending = ([], b"")
            self.done_at = float("inf")

    def _claim(self, cmd):
        exempt = (len(cmd) >= 2 and cmd[1] == 0x25) or cmd == b"\x03\x23\xff"
        if not exempt:
            for s in self.sessions.values():
                s["claimed"] = True

    def _check_handle(self, cmd):
        if len(cmd) >= 3 and cmd[2] in self.gone and cmd[2] not in self.sessions:
            self.violations.append(
                "command $%02X names handle %d after it went GONE (01/05 or "
                "02,..: 9): S 1.6 M10 / ER-7 say never again" % (cmd[1], cmd[2]))

    def _execute(self, cmd, now):
        if len(cmd) < 2 or cmd[0] != 0x03:
            return [], INVALID, FAST
        op = cmd[1]
        delay = self.slow.get(op, FAST)
        if op in self.never:
            delay = NEVER
        self._claim(cmd)
        if op == 0x09:                                  # CLOSE
            self._check_handle(cmd)
            h = cmd[2]
            if h in self.sessions:
                del self.sessions[h]
                return [], OK, delay
            return [], CLOSE_UNOWNED, delay
        if op == 0x05:                                  # GET_IPADDR
            if cmd[2] != 0:
                return [], INVALID, delay
            return [bytes([10, 43, 23, 81, 255, 255, 255, 0, 10, 43, 23, 1])], OK, delay
        if op == 0x23:                                  # INFO
            if not self.tls:
                return [], UNKNOWN, delay
            if len(cmd) != 3:
                self.violations.append("INFO of %d bytes (ER-4: exactly 3)"
                                       % len(cmd))
                return [], INVALID, delay
            if cmd[2] == 0xFF:
                rec = bytearray(self.info)
                if self.ready_after is not None and now < self.ready_after:
                    rec[4] = 0x03
                return [bytes(rec)], OK, delay
            return [], INVALID, delay
        if op == 0x25:                                  # RELEASE
            if not self.tls:
                return [], UNKNOWN, delay
            if len(cmd) != 2:
                self.violations.append("RELEASE of %d bytes (ER-4: exactly 2)"
                                       % len(cmd))
                return [], INVALID, delay
            n = 0
            for h in [h for h, s in self.sessions.items() if not s["claimed"]]:
                del self.sessions[h]
                n += 1
            return [bytes([n])], OK, delay
        if op == 0x21:                                  # OPEN_TLS
            if not self.tls:
                return [], UNKNOWN, delay
            self.last_open = cmd
            kind, arg = self.open_result
            d = self.open_delay if op not in self.never else NEVER
            if kind == "refuse":
                return [], arg, d
            h = arg
            self.sessions[h] = {"rx": [], "claimed": False}
            self.gone.discard(h)
            return [bytes([h, 4, 3, 1, 0x13, 0x1D, 0, 0])], OK, d
        if op == 0x10:                                  # READ
            self._check_handle(cmd)
            h, maxlen = cmd[2], cmd[3] | (cmd[4] << 8)
            d = self.read_delay if op not in self.never else NEVER
            if maxlen == 0 or maxlen > 1472:
                return [], b"82,PARAMETER(S) OUT OF RANGE", d
            s = self.sessions.get(h)
            if s is None:
                self.gone.add(h)            # the client has now been told
                return [b"\xff\xff"], NOT_OURS, d
            if self.forced_blocks is not None:
                blocks, status = self.forced_blocks
                self.forced_blocks = None
                return blocks, status, d
            if not s["rx"]:
                return [b"\xff\xff"], IDLE, d
            ev = s["rx"][0]
            if ev[0] == "data":
                chunk = ev[1][:maxlen]
                rest = ev[1][maxlen:]
                if rest:
                    s["rx"][0] = ("data", rest)
                else:
                    s["rx"].pop(0)
                return [bytes([len(chunk) & 0xFF, len(chunk) >> 8]) + chunk], OK, d
            if ev[0] == "idle":
                s["rx"].pop(0)
                return [b"\xff\xff"], IDLE, d
            # ("end", status): 01/05 untrack the handle; others are sticky
            status = ev[1]
            if status[:2] in (b"01", b"05"):
                del self.sessions[h]
                self.gone.add(h)
            return [b"\x00\x00"], status, d
        if op == 0x11:                                  # WRITE
            self._check_handle(cmd)
            h, data = cmd[2], cmd[3:]
            if h not in self.sessions:
                return [b"\xff\xff"], b"12,SEND ERROR: 9", delay
            if self.write_result is not None:
                hdr, status = self.write_result
                return [hdr], status, delay
            self.writes.append((h, bytes(data)))
            if "on_write" in self.sessions[h]:
                self.sessions[h]["rx"].extend(self.sessions[h].pop("on_write"))
            return [bytes([len(data) & 0xFF, len(data) >> 8])], OK, delay
        return [], UNKNOWN, delay

    # ------------------------------------------------------------- helpers --
    def commands(self):
        return [c for _, c in self.log]

    def ops(self):
        return [c[1] for c in self.commands() if len(c) >= 2]

    @property
    def idle(self):
        self._advance()
        return (self.state == ST_IDLE and not self.new_command
                and not self.abort_pending)


class Memory:
    """64 KB RAM, the M3 device at $DF1B-$DF1F, CIA2 timer B as the clock."""

    def __init__(self, image, load_addr):
        self.ram = bytearray(0x10000)
        self.ram[load_addr:load_addr + len(image)] = image
        self.cpu = None
        self.dev = M3Device(self.units)
        self.cia2_writes = {}

    def units(self):
        return (self.cpu.steps // STEPS_PER_UNIT) if self.cpu else 0

    def read(self, addr):
        addr &= 0xFFFF
        if 0xDF00 <= addr <= 0xDFFF:
            return self.dev.read(addr)
        if addr == 0xDD06:
            return (0xFFFF - self.units()) & 0xFF
        if addr == 0xDD07:
            return ((0xFFFF - self.units()) >> 8) & 0xFF
        if 0xDC00 <= addr <= 0xDDFF:
            return 0x00
        return self.ram[addr]

    def write(self, addr, value):
        addr &= 0xFFFF
        if 0xDF00 <= addr <= 0xDFFF:
            self.dev.write(addr, value & 0xFF)
            return
        if 0xDC00 <= addr <= 0xDDFF:
            self.cia2_writes[addr] = value & 0xFF
            return
        self.ram[addr] = value & 0xFF


# ---------------------------------------------------------------------------
# Rig
# ---------------------------------------------------------------------------

ASSERTIONS_RUN = 0
NEEDED = ("m3_wedged", "m3_owned", "m3_handle", "net_init", "net_tcp_connect",
          "net_poll", "net_tcp_send", "net_tcp_close", "net_dns_resolve",
          "http_recv_body", "m3_status", "m3_status_len")
HOST_AT = 0x0400
SRC_AT = 0x0500


def _check(cond, msg):
    global ASSERTIONS_RUN
    ASSERTIONS_RUN += 1
    if not cond:
        raise AssertionError(msg)


def _labels(path=None):
    path = Path(path or LABELS)
    if not path.is_file():
        raise Unavailable("%s is missing: build with `make BACKEND=uci-m3`" % path)
    table = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "al" and parts[2].startswith("."):
            table[parts[2][1:]] = int(parts[1].split(":")[-1], 16)
    for name in NEEDED:
        if name not in table:
            raise Unavailable("%s is not in %s: not a BACKEND=uci-m3 build"
                              % (name, path))
    return table


class Machine:
    def __init__(self, prg=None, labels=None):
        prg = Path(prg or PRG)
        if not prg.is_file():
            raise Unavailable("%s is missing: build with `make BACKEND=uci-m3`"
                              % prg)
        self.L = _labels(labels)
        raw = prg.read_bytes()
        self.mem = Memory(raw[2:], raw[0] | (raw[1] << 8))
        self.cpu = CPU(self.mem)
        self.mem.cpu = self.cpu
        self.dev = self.mem.dev
        # BSS lives at $A000+ and is zeroed by boot.s; the image's RAM is
        # zero already, which is that state.

    def peek(self, name, off=0):
        return self.mem.read(self.L[name] + off)

    def poke(self, name, value, off=0):
        self.mem.write(self.L[name] + off, value)

    def call(self, name, a=0, x=0, budget=40_000_000):
        self.cpu.a, self.cpu.x = a & 0xFF, x & 0xFF
        return self.cpu.call(self.L[name], budget=budget)

    def status_line(self):
        n = self.peek("m3_status_len")
        return bytes(self.peek("m3_status", i) for i in range(n))

    # -- flows ---------------------------------------------------------------
    def init(self):
        return self.call("net_init")

    def connect(self, host=b"example.org", port=443):
        for i, b in enumerate(host + b"\x00"):
            self.mem.write(HOST_AT + i, b)
        _check(self.call("net_dns_resolve", HOST_AT & 0xFF, HOST_AT >> 8) is False,
               "net_dns_resolve refused %r" % host)
        return self.call("net_tcp_connect", port & 0xFF, port >> 8)

    def send(self, data):
        for i, b in enumerate(data):
            self.mem.write(SRC_AT + i, b)
        self.poke("net_send_len", len(data) & 0xFF)
        self.poke("net_send_len", len(data) >> 8, 1)
        return self.call("net_tcp_send", SRC_AT & 0xFF, SRC_AT >> 8)

    def ring(self):
        head = self.peek("tcp_recv_head") | (self.peek("tcp_recv_head", 1) << 8)
        tail = self.peek("tcp_recv_tail") | (self.peek("tcp_recv_tail", 1) << 8)
        out = bytearray()
        while head != tail:
            out.append(self.mem.read(0xC000 + head))
            head = (head + 1) & 0x0FFF
        return bytes(out)

    def no_violations(self):
        _check(not self.dev.violations,
               "protocol violations: " + "; ".join(self.dev.violations))


def _connected(m, handle=5):
    m.dev.open_result = ("ok", handle)
    _check(m.init() is False, "net_init failed (net_last_error $%02X)"
           % m.peek("net_last_error"))
    _check(m.connect() is False, "net_tcp_connect failed: %r"
           % m.status_line())
    return m


# ---------------------------------------------------------------------------
# Tests: one spec rule each
# ---------------------------------------------------------------------------

def test_startup_sequence(prg=None, labels=None):
    """ER-2: $0C (ABORT + clear error), bit-2 wait, CLOSE 0..15, then INFO.

    A leftover session at handle 3 (an earlier program that exited without a
    reset) must be closed by the sweep; no `03 25` at boot; INFO is exactly
    `03 23 FF` (ER-4).
    """
    m = Machine(prg, labels)
    m.dev.sessions[3] = {"rx": [], "claimed": True}
    m.dev.error_busy = True                     # survives a C64 reset (ER-2)
    _check(m.init() is False, "net_init failed (net_last_error $%02X)"
           % m.peek("net_last_error"))
    first = m.dev.ctrl_writes[0][1] if m.dev.ctrl_writes else None
    _check(first == 0x0C, "the first $DF1C write was %r, not $0C (ABORT + "
           "clear error, ER-2)" % first)
    cmds = m.dev.commands()
    sweep = [bytes([3, 9, h]) for h in range(16)]
    _check(cmds[:16] == sweep, "the startup CLOSE sweep is not `03 09 h` for "
           "h = 0..15 in order (ER-2): %r" % [c.hex() for c in cmds[:17]])
    _check(cmds[16:] == [b"\x03\x23\xff"], "after the sweep: %r, expected "
           "exactly `03 23 FF` (ER-4) and no `03 25` (ER-2)"
           % [c.hex() for c in cmds[16:]])
    _check(3 not in m.dev.sessions, "the leftover session survived the sweep")
    _check(m.dev.idle, "the interface is not idle after net_init")
    m.no_violations()


def test_no_uci_writes_nothing(prg=None, labels=None):
    """ER-2: $DF1D not $C9/$49 = no UCI: no ABORT, no wait, $81."""
    m = Machine(prg, labels)
    m.dev.present = False
    _check(m.init() is True, "net_init returned C=0 with no UCI present")
    _check(m.peek("net_last_error") == ERR_NOT_PRESENT,
           "net_last_error $%02X, expected $81" % m.peek("net_last_error"))
    _check(not m.dev.ctrl_writes, "net_init wrote $DF1C %d time(s) with no "
           "UCI present (ER-2: do not ABORT, do not wait)"
           % len(m.dev.ctrl_writes))


def test_no_tls_firmware(prg=None, labels=None):
    """S 1.3 Detect / ER-22: `21,UNKNOWN COMMAND` = no TLS: C=1, line kept."""
    m = Machine(prg, labels)
    m.dev.tls = False
    _check(m.init() is True, "net_init returned C=0 on firmware without M3")
    _check(m.status_line() == UNKNOWN, "status line %r, expected %r"
           % (m.status_line(), UNKNOWN))
    m.no_violations()


def test_handle_zero_is_legal(prg=None, labels=None):
    """ER-9: handle 0 is a handle. READ, WRITE and CLOSE must name it."""
    m = Machine(prg, labels)
    _connected(m, handle=0)
    _check(m.peek("net_tcp_state") == NET_TCP_CONNECTED,
           "handle 0 was refused (net_tcp_state $%02X, net_last_error $%02X)"
           % (m.peek("net_tcp_state"), m.peek("net_last_error")))
    m.call("net_poll")
    _check(m.dev.commands()[-1][:3] == b"\x03\x10\x00", "READ did not name handle 0")
    m.call("net_tcp_close")
    _check(m.dev.commands()[-1] == b"\x03\x09\x00", "CLOSE did not name handle 0")
    _check(0 not in m.dev.sessions, "handle 0's session was left open")
    m.no_violations()


def test_open_layout(prg=None, labels=None):
    """S 1.1: `03 21 portLo portHi trust flags host`, no trailing $00."""
    m = Machine(prg, labels)
    _connected(m)
    want = b"\x03\x21\xbb\x01\x00\x01example.org"
    _check(m.dev.last_open == want, "OPEN_TLS bytes %s, expected %s"
           % (m.dev.last_open.hex(), want.hex()))
    m.no_violations()


def test_open_waits_45s_not_12(prg=None, labels=None):
    """ER-1: OPEN_TLS's bound is 45 s from the PUSH. A 30 s Open succeeds."""
    m = Machine(prg, labels)
    m.dev.open_delay = 30 * SECOND
    _connected(m)
    _check(m.dev.aborts == 1, "an OPEN that took 30 s was ABORTed (%d ABORTs "
           "beyond the startup one): its bound is 45 s, not 12 (ER-1)"
           % (m.dev.aborts - 1))
    m.no_violations()


def test_open_timeout_aborts_then_releases(prg=None, labels=None):
    """ER-1 + S 1.8: no reply by PUSH + 45 s -> ABORT (alone), wait for bit
    2 within ABORT + 12 s, then `03 25` (exactly 2 bytes) as the NEXT network
    command. The Open completes at 50 s, after the ABORT: its session is
    unclaimed and `03 25` must close it."""
    m = Machine(prg, labels)
    m.dev.open_delay = 50 * SECOND
    _check(m.init() is False, "net_init failed")
    _check(m.connect() is True, "a 50 s Open returned C=0")
    _check(m.peek("net_last_error") == ERR_WAIT_TIMEOUT,
           "net_last_error $%02X, expected $89" % m.peek("net_last_error"))
    _check(m.dev.aborts == 2, "%d ABORT(s) after the Open, expected 1"
           % (m.dev.aborts - 1))
    t_push = [t for t, c in m.dev.log if c[1] == 0x21][0]
    t_abort = m.dev.abort_times[-1]
    _check(45 * SECOND <= t_abort - t_push < 47 * SECOND,
           "ABORT at PUSH + %.1f s, expected PUSH + 45 s" % ((t_abort - t_push) / SECOND))
    ops = m.dev.ops()
    i = ops.index(0x21)
    after = [c for c in m.dev.commands()[i + 1:] if c != b"\x03\x23\xff"]
    _check(after[:1] == [b"\x03\x25"], "after the ABORTed Open the next "
           "network command was %r, expected exactly `03 25` (S 1.8, ER-4)"
           % [c.hex() for c in after[:1]])
    _check(not m.dev.sessions, "the ABORTed Open's session is still open: %r"
           % list(m.dev.sessions))
    _check(m.peek("m3_owned") == 0, "a handle is held after a failed Open")
    m.no_violations()


def test_wedge_writes_nothing_more(prg=None, labels=None):
    """ER-1/ER-11: bit 2 still set at the post-ABORT deadline = wedged: write
    nothing more to the UCI. Here the Open never returns, so the ABORT is
    never serviced; a later CLOSE must not touch the interface."""
    m = Machine(prg, labels)
    _check(m.init() is False, "net_init failed")
    m.dev.never.add(0x21)
    _check(m.connect() is True, "a never-answering Open returned C=0")
    _check(m.peek("m3_wedged") & 0x80, "m3_wedged is not set after bit 2 "
           "stayed set past ABORT + 12 s")
    n = (len(m.dev.ctrl_writes), len(m.dev.log))
    m.call("net_tcp_close")
    m.call("net_poll")
    _check((len(m.dev.ctrl_writes), len(m.dev.log)) == n,
           "the client kept writing to a wedged interface (ER-11)")


def test_refusal_line_is_kept_whole(prg=None, labels=None):
    """S 2 + ER-8: a refusal leaves nothing open and its 40-byte status line
    is kept whole for the user."""
    m = Machine(prg, labels)
    m.dev.open_result = ("refuse", NAME_MISMATCH)
    _check(m.init() is False, "net_init failed")
    _check(m.connect() is True, "a refused Open returned C=0")
    _check(m.status_line() == NAME_MISMATCH, "status line %r, expected %r"
           % (m.status_line(), NAME_MISMATCH))
    _check(m.peek("net_tcp_state") == NET_TCP_CONNECT_FAIL,
           "net_tcp_state $%02X after a refusal" % m.peek("net_tcp_state"))
    _check(m.peek("m3_owned") == 0, "a refused Open left a handle held")
    m.no_violations()


def test_ready_bits_polled_before_open(prg=None, labels=None):
    """ER-10: INFO [4] polled about once a second until module, entropy and
    time are set; the Open goes out only then."""
    m = Machine(prg, labels)
    _check(m.init() is False, "net_init failed")
    m.dev.ready_after = m.mem.units() + 3 * SECOND
    _check(m.connect() is False, "connect failed: %r" % m.status_line())
    t_open = [t for t, c in m.dev.log if c[1] == 0x21][0]
    _check(t_open >= m.dev.ready_after, "OPEN_TLS went out %.1f s before "
           "INFO [4] had the ready bits (ER-10)"
           % ((m.dev.ready_after - t_open) / SECOND))
    infos = [c for c in m.dev.commands() if c == b"\x03\x23\xff"]
    _check(2 <= len(infos) <= 8, "%d INFO polls for a 3 s wait" % len(infos))
    m.no_violations()


def test_read_end_01_is_gone(prg=None, labels=None):
    """S 1.6 / Appendix A: $0000 + 01 = GONE: CLOSED, and do NOT CLOSE it."""
    m = _connected(Machine(prg, labels))
    m.dev.sessions[5]["rx"] = [("data", b"hello"), ("end", CLOSED_BY_HOST)]
    for _ in range(3):
        m.call("net_poll")
    _check(m.ring() == b"hello", "ring holds %r" % m.ring())
    _check(m.peek("net_tcp_state") == NET_TCP_CLOSED,
           "net_tcp_state $%02X after 01, expected CLOSED" % m.peek("net_tcp_state"))
    n = len(m.dev.log)
    m.call("net_tcp_close")
    _check(len(m.dev.log) == n, "net_tcp_close sent %r after the handle went "
           "GONE (01): the number may already be another socket's (M10)"
           % [c.hex() for c in m.dev.commands()[n:]])
    m.no_violations()


def test_read_end_14_is_closed(prg=None, labels=None):
    """S 1.6: $0000 + 12/14/16/17 = dead but still ours: ERROR, then CLOSE."""
    m = _connected(Machine(prg, labels))
    m.dev.sessions[5]["rx"] = [("end", ALERT)]
    m.call("net_poll")
    _check(m.peek("net_tcp_state") == NET_TCP_ERROR,
           "net_tcp_state $%02X after 14, expected ERROR" % m.peek("net_tcp_state"))
    m.call("net_tcp_close")
    _check(m.dev.commands()[-1] == b"\x03\x09\x05", "no CLOSE after a sticky "
           "14: the entry stays in the table (91 after two)")
    _check(not m.dev.sessions, "the dead session was not closed")
    m.no_violations()


def test_read_not_ours_stops(prg=None, labels=None):
    """ER-7: $FFFF + `02,NO DATA: 9` = not our handle: stop, never CLOSE."""
    m = _connected(Machine(prg, labels))
    del m.dev.sessions[5]                       # closed under us
    m.call("net_poll")
    _check(m.peek("net_tcp_state") != NET_TCP_CONNECTED,
           "still CONNECTED after `02,NO DATA: 9`: it would poll forever")
    n = len(m.dev.log)
    m.call("net_poll")
    m.call("net_tcp_close")
    _check(len(m.dev.log) == n, "commands after `: 9`: %r (ER-7: stop "
           "polling, do not CLOSE)" % [c.hex() for c in m.dev.commands()[n:]])
    m.no_violations()


def test_idle_read_stays_connected(prg=None, labels=None):
    """S 1.6: $FFFF + `02,NO DATA: 11` = nothing yet: still CONNECTED."""
    m = _connected(Machine(prg, labels))
    m.call("net_poll")
    _check(m.peek("net_tcp_state") == NET_TCP_CONNECTED,
           "an idle READ ended the connection")
    _check(m.peek("m3_poll_result") == 1, "m3_poll_result is not IDLE")
    m.no_violations()


def test_empty_read_reply_is_not_eof(prg=None, labels=None):
    """ER-12: an empty reply (no header: 81/82) is not $0000 = end. The
    handle stays ours, so it gets CLOSEd."""
    m = _connected(Machine(prg, labels))
    m.dev.forced_blocks = ([], b"82,PARAMETER(S) OUT OF RANGE")
    m.call("net_poll")
    _check(m.peek("net_tcp_state") != NET_TCP_CLOSED,
           "an empty READ reply was taken as the end of the stream (ER-12)")
    m.call("net_tcp_close")
    _check(m.dev.commands()[-1] == b"\x03\x09\x05",
           "the handle was not CLOSEd after an empty READ reply")
    m.no_violations()


def test_data_more_is_never_accepted(prg=None, labels=None):
    """ER-5: a block not read to its end must not be data-accepted; on a Data
    More block an accept would continue the stream over a hole. ABORT, then
    CLOSE."""
    m = _connected(Machine(prg, labels))
    m.dev.forced_blocks = ([b"\x0a\x00" + b"abc", b"defghij"], OK)
    m.call("net_poll")
    _check(m.peek("net_tcp_state") == NET_TCP_ERROR,
           "net_tcp_state $%02X after a short block + Data More"
           % m.peek("net_tcp_state"))
    _check(m.dev.accepts_on_more == 0, "a Data More block was data-accepted "
           "after a short read: the next block continues over the hole (ER-5)")
    m.call("net_tcp_close")
    _check(m.dev.commands()[-1] == b"\x03\x09\x05",
           "the handle was not CLOSEd after a hole in the stream")
    _check(b"defghij" not in m.ring(), "the stream continued past the hole")
    m.no_violations()


def test_read_timeout_aborts_and_closes(prg=None, labels=None):
    """S 1.1 M-2: a READ with no reply by PUSH + 12 s is ABORTed; its data is
    lost, so the handle is CLOSEd."""
    m = _connected(Machine(prg, labels))
    m.dev.read_delay = 15 * SECOND
    m.call("net_poll")
    _check(m.dev.aborts == 2, "the 15 s READ was not ABORTed")
    m.dev.read_delay = FAST
    _check(m.peek("net_tcp_state") == NET_TCP_ERROR, "still CONNECTED after "
           "an ABORTed READ: its data is gone from the stream")
    m.call("net_tcp_close")
    _check(m.dev.commands()[-1] == b"\x03\x09\x05",
           "no CLOSE after an ABORTed READ (S 1.1 M-2)")
    m.no_violations()


def test_read_before_write(prg=None, labels=None):
    """ER-21: READ until $FFFF + 11 (or $0000) before any WRITE."""
    m = _connected(Machine(prg, labels))
    m.dev.sessions[5]["rx"] = [("data", b"early")]
    _check(m.send(b"GET / HTTP/1.1\r\n\r\n") is False, "net_tcp_send failed")
    ops = m.dev.ops()
    i = ops.index(0x11)
    _check(m.ring() == b"early", "the pending data was not read before the "
           "WRITE (ring %r)" % m.ring())
    _check(ops[i - 2:i] == [0x10, 0x10], "WRITE went out before a READ "
           "answered `02,NO DATA: 11` (ER-21): %r" % ops)
    m.no_violations()


def test_write_failure_is_reported(prg=None, labels=None):
    """S 1.6: WRITE $FFFF + a sticky 12 = failed: C=1, ERROR, then CLOSE
    (ER-21: on a WRITE 12, CLOSE at once)."""
    m = _connected(Machine(prg, labels))
    m.dev.write_result = (b"\xff\xff", b"12,SEND ERROR: 104")
    _check(m.send(b"GET /") is True, "a failed WRITE returned C=0")
    _check(m.peek("net_tcp_state") == NET_TCP_ERROR, "not ERROR after WRITE $FFFF")
    m.call("net_tcp_close")
    _check(m.dev.commands()[-1] == b"\x03\x09\x05", "no CLOSE after WRITE 12")
    m.no_violations()


def test_long_write_is_split_at_892(prg=None, labels=None):
    """S 1.5: WRITE takes 0..892 plaintext bytes; longer data is split."""
    m = _connected(Machine(prg, labels))
    data = bytes(range(256)) * 4                # 1024 B
    _check(m.send(data) is False, "net_tcp_send failed")
    sizes = [len(d) for _, d in m.dev.writes]
    _check(sizes == [892, 132], "WRITE sizes %r, expected [892, 132]" % sizes)
    _check(b"".join(d for _, d in m.dev.writes) == data, "data mangled")
    m.no_violations()


def _http_fetch(m, response_events):
    m.dev.sessions[5]["on_write"] = response_events
    req = b"GET / HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n"
    _check(m.send(req) is False, "net_tcp_send failed")
    carry = m.call("http_recv_body", budget=200_000_000)
    status = m.peek("http_status") | (m.peek("http_status", 1) << 8)
    total = (m.peek("http_body_total") | (m.peek("http_body_total", 1) << 8)
             | (m.peek("http_body_total", 2) << 16))
    return carry, status, total


def test_http_content_length_end_to_end(prg=None, labels=None):
    """The whole path: OPEN, GET, a 2,000 B Content-Length body over several
    READs (each at most 893 B), C=0, then CLOSE."""
    m = _connected(Machine(prg, labels))
    body = bytes((i * 7) & 0x7F | 0x20 for i in range(2000))
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n" + body
    carry, status, total = _http_fetch(
        m, [("data", resp[:700]), ("idle",), ("data", resp[700:]),
            ("end", CLOSED_BY_HOST)])
    _check(carry is False, "http_recv_body C=1 on a complete body")
    _check(status == 200, "http_status %d" % status)
    _check(total == 2000, "http_body_total %d, expected 2000" % total)
    reads = [c for c in m.dev.commands() if c[1] == 0x10]
    _check(all((c[3] | c[4] << 8) <= 893 for c in reads),
           "a READ asked for more than 893 B (one block, S 1.5)")
    m.call("net_tcp_close")
    m.no_violations()


def test_http_05_unframed_is_short(prg=None, labels=None):
    """S 1.6: 05 = ended without close_notify: "trust the data only if you
    know its length". An unframed body ending in 05 is C=1; in 01, C=0."""
    for end, want in ((NO_NOTIFY, True), (CLOSED_BY_HOST, False)):
        m = _connected(Machine(prg, labels))
        resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nshort body"
        carry, status, _ = _http_fetch(m, [("data", resp), ("end", end)])
        _check(status == 200, "http_status %d" % status)
        _check(carry is want, "unframed body ending in %r: C=%s, expected %s"
               % (end[:2], carry, want))
        m.no_violations()


TESTS = (
    test_startup_sequence,
    test_no_uci_writes_nothing,
    test_no_tls_firmware,
    test_handle_zero_is_legal,
    test_open_layout,
    test_open_waits_45s_not_12,
    test_open_timeout_aborts_then_releases,
    test_wedge_writes_nothing_more,
    test_refusal_line_is_kept_whole,
    test_ready_bits_polled_before_open,
    test_read_end_01_is_gone,
    test_read_end_14_is_closed,
    test_read_not_ours_stops,
    test_idle_read_stays_connected,
    test_empty_read_reply_is_not_eof,
    test_data_more_is_never_accepted,
    test_read_timeout_aborts_and_closes,
    test_read_before_write,
    test_write_failure_is_reported,
    test_long_write_is_split_at_892,
    test_http_content_length_end_to_end,
    test_http_05_unframed_is_short,
)


def run(prg=None, labels=None, only=None, quiet=False):
    """Run TESTS (or `only`, names) on one image. Returns {name: error|None}."""
    results = {}
    for fn in TESTS:
        if only and fn.__name__ not in only:
            continue
        try:
            fn(prg, labels)
            results[fn.__name__] = None
        except (AssertionError, CPUError) as exc:
            results[fn.__name__] = "%s: %s" % (type(exc).__name__, exc)
        if not quiet:
            err = results[fn.__name__]
            print(("PASS %s" % fn.__name__) if err is None
                  else ("FAIL %s\n     %s" % (fn.__name__, err)))
    return results


def main():
    try:
        _labels()
        if not PRG.is_file():
            raise Unavailable("no PRG")
    except Unavailable as exc:
        return cannot_run(str(exc), executed=0, total=len(TESTS),
                          certifies=CERTIFIES, opt_out_env=OPT_OUT_ENV)
    results = run()
    failed = [n for n, e in results.items() if e]
    print("\n%d/%d passed, %d assertions" % (len(results) - len(failed),
                                             len(results), ASSERTIONS_RUN))
    if failed:
        return 1
    if not results or ASSERTIONS_RUN == 0:
        return cannot_run("no check executed", executed=0, total=len(TESTS),
                          certifies=CERTIFIES, opt_out_env=OPT_OUT_ENV)
    return 0


if __name__ == "__main__":
    sys.exit(main())
