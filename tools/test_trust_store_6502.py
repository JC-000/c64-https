#!/usr/bin/env python3
"""test_trust_store_6502.py -- the SHIPPED trust-store bytes vs a DOS model (#155).

WHAT THIS TESTS

src/net/uci/trust_store.s + uci_dos.s, as linked into a TRUST_STORE=1 PRG,
executed on the repo's 6502 interpreter (tools/test_uci_data_acc.py)
against a model of the Ultimate's UCI DOS target, and checked byte for byte
against the host mirror, tools/trust_store.py:

  * load: EMPTY, VALID, the newer generation (and across the 16-bit wrap),
    case-insensitive lookup;
  * every fail-closed case of S3 §4.3 -- checksum on both slots, one
    corrupt slot beside an absent one, no medium, a DOS error, an unknown
    version, a generation tie -- plus an oversize file and a firmware that
    sends more than was asked for (nothing may be stored past the request);
  * save: into an empty store (slot A, generation 1), ping-pong, replace in
    place, the 32-record limit, a 2,064 B image (five 512 B read parts,
    nine write chunks, none over the 891 B WRITE_DATA cap), a failed
    write, a read-back that does not verify, a store changed since load;
  * a TORN save: the machine stops mid-write (a reset), the target slot is
    left empty or partial with its handle still open in the firmware; the
    next load closes that handle, falls back to the older slot, and the
    next save repairs the torn one;
  * the socket guard: load and save refuse, with no DOS traffic, while
    net_tcp_state is CONNECTED (the image lives in the TCP ring).

HOW

The DOS model follows 1541ultimate software/filemanager/dos.cc and
command_intf.cc: OPEN_FILE with FA_WRITE|FA_CREATE_ALWAYS empties the file
at once, data is durable only at CLOSE_FILE, READ_DATA replies in 512 B
parts (state "11" while more follow), a failed read never assigns the
status line, a new OPEN overwrites (leaks) a handle still open, errors are
get_error_string() text. Register-level behaviour (state bits, DATA_AV,
STAT_AV, DATA_ACC) is test_uci_timeout_recovery.py's model. The CIA1 TOD
runs, so a wait that never ends trips a bounded timeout, not a hang.

Two concessions to Python speed, neither in the code under test: the
uci_fence delay loop is fast-forwarded, and sha256_process_block runs as a
Python SHA-256 compression over the same state (C64_TS_REAL_SHA=1 runs the
6502 SHA instead; slow, but it is how the hook itself was validated).

WHAT IT DOES NOT PROVE

The model is a reading of the firmware source, not a measurement. FPGA
timing, FatFS caching (whether a read-back really reaches the medium), and
what a real reset does to an open handle are tools/uci/rig_trust_store.py's
job, on the U64E.

Usage:
    python3 tools/test_trust_store_6502.py     # make clean && make <profile>
    C64_SKIP_BUILD=1 python3 tools/test_trust_store_6502.py
    C64_TS_PROFILE="BACKEND=uci TRUST_STORE=1" python3 tools/test_trust_store_6502.py
    C64_TS_PROFILE="BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1 TRUST_STORE=1" \
        python3 tools/test_trust_store_6502.py

On a uci-comb image the store runs from the cold bank (src/net/uci/
cold_bank.s): each machine gets a modelled REU (tools/_reu_model.py) and
runs cold_bank_init first, as boot does, so every case below goes through
the trampoline and executes the copy it fetched into cert_buf.

Leaves build/ holding the TRUST_STORE=1 image. Exit 0 pass, 1 fail, 2
could not run.
"""
from __future__ import annotations

import hashlib
import os
import shlex
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_uci_data_acc as cpu_mod                        # noqa: E402
from test_uci_data_acc import CPU, CPUError               # noqa: E402
from test_uci_timeout_recovery import Memory              # noqa: E402
from _skip_policy import cannot_run, verdict              # noqa: E402
from _reu_model import REU, Bus                           # noqa: E402
import trust_store as ts                                  # noqa: E402

REPO = HERE.parent
PRG = REPO / "build" / "c64-https.prg"
LABELS = REPO / "build" / "labels.txt"
PROFILE = shlex.split(os.environ.get(
    "C64_TS_PROFILE", "BACKEND=uci USE_NISTCURVES_ONCHIP=1 TRUST_STORE=1"))
CERTIFIES = "the trust store's 6502 load/save logic (#155 phase 2)"
DIR = "/USB1"

# Opcodes the store's path uses beyond the interpreter's NMOS subset.
cpu_mod.OPCODES.update({
    0xD1: ("CMP", cpu_mod.INDY), 0x11: ("ORA", cpu_mod.INDY),
    0x31: ("AND", cpu_mod.INDY), 0x51: ("EOR", cpu_mod.INDY),
    0x71: ("ADC", cpu_mod.INDY), 0xF1: ("SBC", cpu_mod.INDY),
    0x55: ("EOR", cpu_mod.ZPX), 0x5D: ("EOR", cpu_mod.ABX),
    0x59: ("EOR", cpu_mod.ABY), 0x75: ("ADC", cpu_mod.ZPX),
    0xF5: ("SBC", cpu_mod.ZPX), 0x66: ("ROR", cpu_mod.ZP),
    0x76: ("ROR", cpu_mod.ZPX), 0x36: ("ROL", cpu_mod.ZPX),
    0x16: ("ASL", cpu_mod.ZPX), 0x56: ("LSR", cpu_mod.ZPX),
    0x7E: ("ROR", cpu_mod.ABX), 0x3E: ("ROL", cpu_mod.ABX),
    0x1E: ("ASL", cpu_mod.ABX), 0x5E: ("LSR", cpu_mod.ABX),
    0x6E: ("ROR", cpu_mod.ABS), 0x2E: ("ROL", cpu_mod.ABS),
    0x96: ("STX", cpu_mod.ZPY), 0x94: ("STY", cpu_mod.ZPX),
    0x45: ("EOR", cpu_mod.ZP), 0x1D: ("ORA", cpu_mod.ABX),
    0xE6: ("INC", cpu_mod.ZP), 0xFE: ("INC", cpu_mod.ABX),
})

# --- register level (uci_regs.inc) -----------------------------------------
ST_IDLE, ST_BUSY, ST_LAST, ST_MORE = 0, 1, 2, 3
DATA_AV, STAT_AV, ERROR, CMD_BUSY = 0x80, 0x40, 0x08, 0x01
PUSH, ACC, ABORT, CLR_ERR = 0x01, 0x02, 0x04, 0x08
NET_TCP_CONNECTED = 0x01
UCI_TARGET_DOS = 0x01
WRITE_CAP = 891                 # S1, measured: one WRITE_DATA stores <= 891


class Reset(Exception):
    """The C64 was reset: the CPU stops wherever it was."""


class Dos:
    """The Ultimate's DOS target 1 over the command-interface registers."""

    def __init__(self, files=None, dirs=None):
        self.files = dict(files or {})      # path -> bytes (durable)
        self.dirs = set((DIR,) if dirs is None else dirs)
        self.state = ST_IDLE
        self.new_command = False
        self.error_busy = False
        self.cmd = bytearray()
        self.resp = b""
        self.stat = b""
        self.rp = self.sp = 0
        self.fw_wait = None
        # the DOS object
        self.handle = None                  # [path, mode, data, pos]
        self.remaining = 0
        self.leaked = []                    # handles a new OPEN overwrote
        # fault injection
        self.tear_after_writes = None       # Reset after N WRITE_DATA
        self.tear_keeps_partial = False     # torn file = data so far
        self.write_error = None             # status text for WRITE_DATA
        self.read_error_on = None           # (path, bytes delivered)
        self.corrupt_next_read_of = None    # path: flip a byte on read
        self.extra_bytes = 0                # misbehave: send more than asked
        self.open_error = {}                # path -> status text for a READ open
        self.stale_next_read_of = None      # path: serve its pre-write content
        self.junk_on_open = 0               # misbehave: data bytes on OPEN
        self.prev = {}                      # path -> content before its last W|CA
        # observations
        self.log = []                       # (cmd, detail)
        self.write_sizes = []

    # -- firmware ------------------------------------------------------------
    def _run_command(self):
        c = bytes(self.cmd)
        self.cmd = bytearray()
        resp, stat, more = b"", b"00,OK", False
        if len(c) < 2 or c[0] != UCI_TARGET_DOS:
            return b"", b"21,UNKNOWN COMMAND", False
        op = c[1]
        if op == 0x02:                                  # OPEN_FILE
            mode, name = c[2], c[3:].split(b"\x00")[0].decode("latin1")
            self.log.append(("open", (name, mode)))
            if self.junk_on_open:
                return bytes(self.junk_on_open), b"00,OK", False
            if not mode & 0x02 and name in self.open_error:
                return b"", self.open_error[name].encode(), False
            if self.handle is not None:
                self.leaked.append(self.handle)         # fm->fopen overwrites
                self.handle = None
            d = name.rsplit("/", 1)[0]
            if d not in self.dirs:
                return b"", b"PATH DOESN'T EXIST", False
            if mode & 0x08:                             # FA_CREATE_ALWAYS
                self.prev[name] = self.files.get(name)
                self.files[name] = b""                  # empties it NOW
                self.handle = [name, mode, bytearray(), 0]
            elif name in self.files:
                data = self.files[name]
                if self.stale_next_read_of == name and self.prev.get(name):
                    data = self.prev[name]              # a stale cache hit
                    self.stale_next_read_of = None
                self.handle = [name, mode, bytearray(data), 0]
            else:
                return b"", b"FILE DOESN'T EXIST", False
        elif op == 0x03:                                # CLOSE_FILE
            self.log.append(("close", self.handle[0] if self.handle else None))
            if self.handle is None:
                return b"", b"84,NO FILE TO CLOSE", False
            if self.handle[1] & 0x02:
                self.files[self.handle[0]] = bytes(self.handle[2])
            self.handle = None
        elif op == 0x04:                                # READ_DATA
            if self.handle is None:
                return b"", b"85,NO FILE OPEN", False
            self.remaining = c[2] | (c[3] << 8)
            self.log.append(("read", (self.handle[0], self.remaining)))
            return self._more()
        elif op == 0x05:                                # WRITE_DATA
            data = c[4:]
            self.write_sizes.append(len(data))
            self.log.append(("write", len(data)))
            if self.handle is None:
                return b"", b"85,NO FILE OPEN", False
            if self.write_error:
                return b"", self.write_error.encode(), False
            self.handle[2] += data[:WRITE_CAP]
            if (self.tear_after_writes is not None
                    and len(self.write_sizes) >= self.tear_after_writes):
                if self.tear_keeps_partial:
                    self.files[self.handle[0]] = bytes(self.handle[2])
                raise Reset()
        else:
            return b"", b"21,UNKNOWN COMMAND", False
        return resp, stat, more

    def _more(self):
        """dos.cc get_more_data, e_dos_in_file."""
        name, _, data, pos = self.handle
        length = min(self.remaining, 512)
        chunk = bytes(data[pos:pos + length])
        if self.read_error_on and self.read_error_on[0] == name:
            chunk = chunk[:self.read_error_on[1]]       # FR_DISK_ERR mid-read
            self.read_error_on = None
            self.remaining = 0
            self.handle[3] = pos + len(chunk)
            return chunk, b"", False                    # status NOT assigned
        if self.corrupt_next_read_of == name and chunk:
            chunk = bytes([chunk[0] ^ 0x40]) + chunk[1:]
            self.corrupt_next_read_of = None
        self.handle[3] = pos + len(chunk)
        self.remaining -= len(chunk)
        last = len(chunk) != length or self.remaining == 0
        if last and self.extra_bytes:
            chunk += bytes(self.extra_bytes)            # misbehaving firmware
        return chunk, b"", not last

    def _tick(self):
        if self.fw_wait is None:
            return
        self.fw_wait -= 1
        if self.fw_wait > 0:
            return
        self.fw_wait = None
        if self.state == ST_BUSY and self.new_command:
            self.resp, self.stat, more = self._run_command()
        else:                                           # accept of "11"
            self.resp, self.stat, more = self._more()
        self.rp = self.sp = 0
        self.new_command = False
        self.state = ST_MORE if more else ST_LAST

    # -- registers -----------------------------------------------------------
    def read(self, addr):
        if addr == 0xDF1C:
            self._tick()
            bits = self.state << 4
            if self.state & 0b10:
                if self.rp < len(self.resp):
                    bits |= DATA_AV
                if self.sp < len(self.stat):
                    bits |= STAT_AV
            if self.error_busy:
                bits |= ERROR
            if self.new_command:
                bits |= CMD_BUSY
            return bits
        if addr == 0xDF1D:
            return 0xC9
        if addr == 0xDF1E:
            if not self.state & 0b10 or self.rp >= len(self.resp):
                return 0
            v = self.resp[self.rp]
            self.rp += 1
            return v
        if addr == 0xDF1F:
            if not self.state & 0b10 or self.sp >= len(self.stat):
                return 0
            v = self.stat[self.sp]
            self.sp += 1
            return v
        return 0

    def write(self, addr, value):
        if addr == 0xDF1D:
            if self.state == ST_IDLE:
                self.cmd.append(value)
            return
        if addr != 0xDF1C:
            return
        if value & CLR_ERR:
            self.error_busy = False
        if value & PUSH:
            if self.state == ST_IDLE:
                self.state = ST_BUSY
                self.new_command = True
                self.fw_wait = 2
            else:
                self.error_busy = True
        if value & ACC and self.state & 0b10:
            if self.state == ST_MORE:
                self.state = ST_BUSY                    # get_more_data
                self.fw_wait = 2
            else:
                self.state = ST_IDLE
            self.resp = self.stat = b""
            self.rp = self.sp = 0
        if value & ABORT:
            self.state = ST_IDLE
            self.new_command = False
            self.cmd = bytearray()

    def reset_c64(self, drop_handle=False):
        """What a C64 reset leaves behind: the interface returns to idle.
        By default the firmware's DOS object is untouched and the handle
        stays open (S1's reading); drop_handle models a firmware that
        forgets it without closing. Which one is real is the rig's call."""
        if drop_handle:
            self.handle = None
        self.state = ST_IDLE
        self.new_command = False
        self.cmd = bytearray()
        self.fw_wait = None


# --- the machine ------------------------------------------------------------

def sha256_compress(h_bytes, block):
    """One SHA-256 compression: 32 B state (big-endian words) x 64 B block."""
    K = _K
    w = list(struct.unpack(">16L", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    h = list(struct.unpack(">8L", h_bytes))
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (hh + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
    return struct.pack(">8L", *[(x + y) & 0xFFFFFFFF for x, y in zip(h, (a, b, c, d, e, f, g, hh))])


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


_K = [int(x, 16) for x in """
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
""".split()]

FENCE = bytes([0xE9, 0x01, 0xD0, 0xFC])     # sbc #1 / bne *-2: uci_fence


class FastCPU(CPU):
    def __init__(self, mem, labels, real_sha):
        super().__init__(mem)
        self.sha_block = None if real_sha else labels["sha256_process_block"]
        self.h0 = labels["sha256_h0"]
        self.blk = labels["sha256_block"]

    def step(self):
        pc = self.pc
        if pc == self.sha_block:
            ram = self.mem.ram
            ram[self.h0:self.h0 + 32] = sha256_compress(
                bytes(ram[self.h0:self.h0 + 32]), bytes(ram[self.blk:self.blk + 64]))
            self._op_RTS(None)
            self.steps += 1
            return
        ram = self.mem.ram
        if ram[pc] == 0xE9 and ram[pc:pc + 4] == FENCE:
            self.a, self.c, self.z, self.n = 0, True, True, False
            self.pc = pc + 4
            self.steps += 1
            return
        super().step()


class Machine:
    def __init__(self, image, load_addr, labels, dos):
        self.labels = labels
        self.dos = dos
        self.mem = Memory(image, load_addr, dos)
        for n in ("uci_status_len", "uci_status_force", "net_last_error",
                  "net_tcp_state"):
            self.mem.write(labels[n], 0)
        self.cpu = FastCPU(self.mem, labels,
                           os.environ.get("C64_TS_REAL_SHA") == "1")
        self.reu = None
        if "cold_bank_init" in labels:          # uci-comb: the cold bank
            self.reu = REU(self.mem.ram)
            self.mem.uci = Bus(self.reu, dos)
            self.cpu.call(labels["cold_bank_init"])

    def r8(self, name, off=0):
        return self.mem.ram[self.labels[name] + off]

    def rn(self, name, n):
        a = self.labels[name]
        return bytes(self.mem.ram[a:a + n])

    def call(self, name, ax=None):
        if ax is not None:
            self.cpu.a, self.cpu.x = ax & 0xFF, ax >> 8
        c = self.cpu.call(self.labels[name], budget=40_000_000)
        return c

    def put(self, addr, data):
        self.mem.ram[addr:addr + len(data)] = data

    def load(self, host):
        buf = 0x0334                          # page 3: free in every build
        self.put(buf, host.encode("ascii") + b"\x00")
        c = self.call("trust_store_load", buf)
        return c, self.cpu.a

    def stage(self, record: bytes):
        buf = 0x0340
        self.put(buf, record)
        self.call("trust_store_stage", buf)

    def save(self):
        return self.call("trust_store_save")

    def lookup(self):
        c = self.call("trust_store_lookup")
        if c:
            return None
        return bytes(self.mem.ram[self.cpu.a | (self.cpu.x << 8):][:64])

    @property
    def state(self):
        return (self.r8("ts_state"), self.r8("ts_reason"), self.r8("ts_slot"),
                self.r8("ts_gen") | self.r8("ts_gen", 1) << 8,
                (self.r8("ts_slot_st"), self.r8("ts_slot_st", 1)))


# --- the suite --------------------------------------------------------------

PASSED = 0
FAILED = []
SPKI_1 = hashlib.sha256(b"key one").digest()
SPKI_2 = hashlib.sha256(b"key two").digest()
A, B = f"{DIR}/TRUST.A", f"{DIR}/TRUST.B"


def check(cond, what):
    global PASSED
    if cond:
        PASSED += 1
    else:
        FAILED.append(what)
        print(f"    FAIL: {what}")


def rec(host, spki=SPKI_1, **kw):
    return ts.Record.for_host(host, spki, **kw)


def st(gen, *hosts):
    return ts.encode(gen, [rec(h) for h in hosts])


class Env:
    def __init__(self):
        raw = PRG.read_bytes()
        self.load_addr = raw[0] | raw[1] << 8
        self.image = raw[2:]
        self.labels = {}
        for line in LABELS.read_text().splitlines():
            p = line.split()
            if len(p) >= 3 and p[0] == "al" and p[2].startswith("."):
                self.labels[p[2][1:]] = int(p[1].split(":")[-1], 16)

    def machine(self, dos):
        return Machine(self.image, self.load_addr, self.labels, dos)


def case_empty(env):
    m = env.machine(Dos())
    c, a = m.load("github.com")
    check(not c and a == ts.ST_EMPTY, f"empty: C={c} A={a}")
    check(m.state[4] == (ts.SLOT_ABSENT, ts.SLOT_ABSENT), f"empty slot_st {m.state[4]}")
    check(m.lookup() is None, "empty: lookup found something")
    check(m.rn("ts_key", 16) == ts.host_key("github.com"), "host key differs from the mirror")
    closes = [x for x in m.dos.log if x[0] == "close"]
    check(len(closes) >= 1 and m.dos.handle is None, "empty: a handle left open")


def case_save_roundtrip(env):
    dos = Dos()
    m = env.machine(dos)
    m.load("GitHub.com")
    m.stage(rec("anything", SPKI_1).pack())
    c = m.save()
    check(not c, f"save into EMPTY failed, reason {m.state[1]}")
    want = ts.save(None, None, "github.com", rec("anything", SPKI_1))
    check((0, dos.files.get(A)) == want, "save into EMPTY: TRUST.A != mirror")
    check(B not in dos.files, "save into EMPTY touched TRUST.B")
    check(m.state[0] == ts.ST_NONE and m.r8("ts_found") == 0 and m.lookup() is None,
          f"after save the loaded state must be cleared: {m.state}")
    m.load("github.com")
    check(m.state[:4] == (ts.ST_VALID, 0, 0, 1), f"reload after save: {m.state}")
    check(dos.handle is None and not dos.leaked, "save left a handle open")
    # the read-back: after the last write+close the file was opened again for read
    ops = [x[0] for x in dos.log]
    last_close = len(ops) - 1 - ops[::-1].index("close")
    check(ops[last_close - 2:last_close + 1] == ["open", "read", "close"],
          f"no read-back after the write: {ops[-8:]}")
    # a fresh machine loads what was written
    m2 = env.machine(dos)
    c, a = m2.load("GITHUB.COM")
    check(not c and a == ts.ST_VALID, f"reload: C={c} A={a}")
    got = m2.lookup()
    check(got == ts.Record.for_host("github.com", SPKI_1, display=b"anything").pack(),
          "reload: record differs")


def case_ping_pong_and_replace(env):
    dos = Dos({A: st(1, "a.example")})
    m = env.machine(dos)
    m.load("b.example")
    check(m.lookup() is None, "b.example found before it was saved")
    m.stage(rec("b.example", SPKI_2).pack())
    check(not m.save(), "second save failed")
    want = ts.save(st(1, "a.example"), None, "b.example", rec("b.example", SPKI_2))
    check((1, dos.files.get(B)) == want, "ping-pong: TRUST.B != mirror")
    check(dos.files[A] == st(1, "a.example"), "ping-pong rewrote the loaded slot")
    # replace a.example in place: goes back to A, generation 3, still 2 records
    m = env.machine(dos)
    m.load("a.example")
    check(m.lookup() is not None, "a.example lost")
    m.stage(rec("a.example", SPKI_2).pack())
    want = ts.save(dos.files[A], dos.files[B], "a.example", rec("a.example", SPKI_2))
    check(not m.save(), "replace failed")
    gen, recs = ts.decode(dos.files[A])
    check(gen == 3 and len(recs) == 2 and recs[0].spki == SPKI_2,
          f"replace: gen {gen}, {len(recs)} records")
    check((0, dos.files[A]) == want, "replace: TRUST.A != mirror")


def case_newer_and_wrap(env):
    for a, b, slot, gen in ((st(4, "x.example"), st(5, "x.example"), 1, 5),
                            (st(9, "x.example"), st(8, "x.example"), 0, 9),
                            (st(0xFFFF, "x.example"), st(0, "x.example"), 1, 0),
                            (st(0, "x.example"), st(0xFFFF, "x.example"), 0, 0)):
        m = env.machine(Dos({A: a, B: b}))
        c, _ = m.load("x.example")
        check(not c and m.state[:4] == (ts.ST_VALID, 0, slot, gen),
              f"newer: want slot {slot} gen {gen}, got {m.state}")


def case_fail_closed(env):
    good = st(3, "a.example")
    flip = bytearray(good)
    flip[30] ^= 1
    flip = bytes(flip)
    v2 = bytearray(good)
    v2[4] = 2
    cases = [
        ("checksum both", {A: flip, B: flip}, ts.R_CHECKSUM),
        ("corrupt + absent", {A: flip}, ts.R_CHECKSUM),
        ("absent + corrupt", {B: flip}, ts.R_CHECKSUM),
        ("unknown version", {A: bytes(v2)}, ts.R_VERSION),
        ("tie", {A: st(7, "a.example"), B: st(7, "b.example")}, ts.R_TIE),
        ("tie 0x8000", {A: st(0, "a.example"), B: st(0x8000, "b.example")}, ts.R_TIE),
        ("zero-length", {A: b""}, ts.R_FORMAT),
        ("oversize", {A: ts.encode(1, [rec(f"h{i}") for i in range(32)]) + bytes(40)},
         ts.R_FORMAT),
    ]
    for name, files, reason in cases:
        m = env.machine(Dos(files))
        c, a = m.load("a.example")
        check(c and a == ts.ST_FAIL and m.state[1] == reason,
              f"{name}: C={c} A={a} state {m.state}, want reason {reason}")
        sel = ts.select(files.get(A), files.get(B))
        check(sel.state == ts.ST_FAIL and sel.reason == reason, f"{name}: mirror disagrees")
        check(m.lookup() is None, f"{name}: lookup after FAIL")
    m = env.machine(Dos(dirs=()))                        # no medium / no dir
    c, a = m.load("a.example")
    check(c and m.state[1] == ts.R_NOPATH, f"no path: {m.state}")
    dos = Dos({A: good})
    dos.read_error_on = (A, 5)                           # stale OK, short read
    m = env.machine(dos)
    c, a = m.load("a.example")
    check(c and m.state[1] == ts.R_FORMAT and m.state[4][0] == ts.R_FORMAT,
          f"short read with a stale OK: {m.state}")
    check(dos.handle is None, "short read left the file open")


def case_other_slot_open_failure_fails_closed(env):
    # adv-l2 #1: a valid slot beside one that fails to OPEN is not a torn
    # write (a torn save always opens); it may be the NEWER slot. S3 §4.3:
    # a DOS error other than 62 fails closed. Torn damage (FORMAT,
    # CHECKSUM) and absence stay tolerated; an unknown version fails too.
    older, newer = st(5, "old.example"), st(6, "old.example", "new.example")
    for text, reason in (("DISK ERROR", ts.R_DOS), ("PATH DOESN'T EXIST", ts.R_NOPATH)):
        for bad, good, good_slot in ((B, older, 0), (A, newer, 1)):
            files = {A: older, B: newer}
            files[good_slot and A or B] = good
            dos = Dos(files)
            dos.open_error[bad] = text
            m = env.machine(dos)
            c, a = m.load("new.example")
            check(c and a == ts.ST_FAIL and m.state[1] == reason,
                  f"valid slot beside a {text!r} open on {bad[-1]}: {m.state}")
            m.stage(rec("new.example", SPKI_2).pack())
            n = len(dos.write_sizes)
            check(m.save() and len(dos.write_sizes) == n,
                  f"{text!r}: a save went ahead over the failed slot")
    v9 = bytearray(newer)
    v9[4] = 9
    m = env.machine(Dos({A: older, B: bytes(v9)}))
    c, a = m.load("old.example")
    check(c and m.state[1] == ts.R_VERSION, f"valid beside unknown version: {m.state}")
    dos = Dos({A: older, B: newer})
    dos.read_error_on = None
    for torn in (b"", newer[:40]):
        m = env.machine(Dos({A: older, B: torn}))
        c, a = m.load("old.example")
        check(not c and m.state[2] == 0, f"torn B must stay tolerated: {m.state}")
    for code, text in ((ts.R_DOS, "DISK ERROR"),):
        sel = ts.select(older, code)
        check(sel.state == ts.ST_FAIL and sel.reason == code, "mirror: valid + DOS")


def case_stage_and_failed_save(env):
    # adv-l2 #2: a staged record must never be reported as stored.
    dos = Dos({A: st(5, "h.example")})
    m = env.machine(dos)
    m.load("h.example")
    m.stage(rec("h.example", SPKI_2).pack())
    check(m.lookup() is None and m.state[0] == ts.ST_NONE,
          f"after stage, lookup/state still claim the loaded store: {m.state}")
    dos.write_error = "DISK IS FULL"
    check(m.save(), "save with a write error succeeded")
    check(m.lookup() is None and m.state[0] == ts.ST_NONE,
          f"after a failed save the unsaved record is visible: {m.state}")
    dos.write_error = None
    check(m.save() and m.state[1] == ts.R_NOTREADY,
          "a failed save left a record staged for a blind retry")
    m.load("h.example")
    check(m.lookup()[16:48] == SPKI_1, "reload after the failed save lost the old record")


def case_stale_read_back(env):
    # adv-l2 #3: a read-back that is valid but is NOT what was written (an
    # older generation from a cache) must fail VERIFY.
    dos = Dos({A: st(3, "a.example"), B: st(2, "a.example")})
    m = env.machine(dos)
    m.load("a.example")
    m.stage(rec("a.example", SPKI_2).pack())
    dos.stale_next_read_of = B
    check(m.save() and m.state[1] == ts.R_VERIFY, f"stale read-back accepted: {m.state}")


def case_junk_reply_on_open(env):
    # adv-l2 #4: data on a command whose reply must be empty is refused, and
    # never stored (dos_store still points past the previous read).
    dos = Dos({A: st(2, "a.example")})
    m = env.machine(dos)
    m.load("a.example")                    # leaves dos_store past a read
    end = 0xC000 + len(dos.files[A])
    m.put(end, b"\xA5" * 16)
    dos.junk_on_open = 8
    c, a = m.load("a.example")
    check(c and m.state[4] == (ts.R_DOS, ts.R_DOS), f"junk on OPEN not refused: {m.state}")
    check(bytes(m.mem.ram[end:end + 16]) == b"\xA5" * 16,
          "junk OPEN reply was stored at the stale read pointer")


def case_torn_slot_falls_back(env):
    good = st(6, "a.example")
    for torn in (b"", st(7, "a.example", "b.example")[:40]):
        m = env.machine(Dos({A: good, B: torn}))
        c, a = m.load("a.example")
        check(not c and m.state[:4] == (ts.ST_VALID, 0, 0, 6),
              f"torn B (len {len(torn)}): {m.state}")
        check(m.lookup() is not None, "torn B: record lost")


def case_torn_save(env):
    # Four records loaded, a fifth saved: a 336 B image, two WRITE_DATA
    # chunks (256 + 80). The reset lands after the first chunk.
    hosts = ["a.example", "b.example", "c.example", "d.example"]
    older = ts.encode(1, [rec(h) for h in hosts])
    variants = [
        # (name, bytes the torn file holds at the reset, drop the handle?)
        ("handle survives, nothing flushed", False, False),
        ("handle survives, partial flushed", True, False),
        ("handle dropped, nothing flushed", False, True),
        ("handle dropped, partial flushed", True, True),
    ]
    for name, partial, drop in variants:
        dos = Dos({A: older})
        m = env.machine(dos)
        m.load("e.example")
        m.stage(rec("e.example", SPKI_2).pack())
        dos.tear_after_writes = 1
        dos.tear_keeps_partial = partial
        try:
            m.save()
            check(False, f"{name}: the model never reset the machine")
            continue
        except Reset:
            pass
        dos.reset_c64(drop_handle=drop)
        dos.tear_after_writes = None
        check(dos.files[A] == older, f"{name}: torn save damaged the loaded slot")
        m = env.machine(dos)                              # the program restarts
        c, a = m.load("e.example")
        check(not c and m.state[:4] == (ts.ST_VALID, 0, 0, 1),
              f"{name}: after the torn save {m.state}")
        check(m.state[4][1] == ts.R_FORMAT, f"{name}: torn slot result {m.state[4]}")
        check(dos.handle is None and not dos.leaked,
              f"{name}: the load left the torn handle open / leaked it")
        check(m.lookup() is None, f"{name}: torn record visible")
        m.stage(rec("e.example", SPKI_2).pack())
        check(not m.save(), f"{name}: save after the torn save: {m.state}")
        gen, recs = ts.decode(dos.files[B])
        check(gen == 2 and len(recs) == 5, f"{name}: repair wrote gen {gen}, {len(recs)} recs")
    # A one-chunk image torn after its only chunk: everything is written but
    # nothing is closed. If the handle survives the reset, the next load's
    # close-first commits it, and it is a complete, valid generation 2.
    dos = Dos({A: st(1, "a.example")})
    m = env.machine(dos)
    m.load("b.example")
    m.stage(rec("b.example", SPKI_2).pack())
    dos.tear_after_writes = 1
    try:
        m.save()
    except Reset:
        pass
    dos.reset_c64()
    dos.tear_after_writes = None
    m = env.machine(dos)
    c, _ = m.load("b.example")
    check(not c and m.state[:4] == (ts.ST_VALID, 0, 1, 2) and m.lookup() is not None,
          f"unclosed complete image: {m.state}")


def case_full_store_and_big_image(env):
    hosts = [f"h{i}.example" for i in range(32)]
    full = ts.encode(40, [rec(h) for h in hosts])
    dos = Dos({A: full})
    m = env.machine(dos)
    c, a = m.load("h31.example")
    check(not c and m.lookup() == rec("h31.example").pack(), "record 32 of 32 not found")
    reads = [x[1][1] for x in dos.log if x[0] == "read"]
    check(reads and all(r == ts.FILE_MAX + 1 for r in reads), f"read sizes {reads}")
    m.stage(rec("h31.example", SPKI_2).pack())
    check(not m.save(), f"replace in a full store failed: {m.state}")
    check(dos.write_sizes and max(dos.write_sizes) <= 256 and sum(dos.write_sizes) == ts.FILE_MAX,
          f"write chunks {dos.write_sizes}")
    check(dos.files[B] == ts.save(full, None, "h31.example", rec("h31.example", SPKI_2))[1],
          "full-store image != mirror")
    m = env.machine(dos)
    m.load("new.example")
    m.stage(rec("new.example").pack())
    check(m.save() and m.state[1] == ts.R_FULL, f"33rd record: {m.state}")


def case_save_refusals(env):
    m = env.machine(Dos())
    m.load("a.example")
    check(m.save() and m.state[1] == ts.R_NOTREADY, "save with nothing staged")
    m = env.machine(Dos(dirs=()))
    m.load("a.example")
    m.stage(rec("a.example").pack())
    check(m.save() and m.state[1] == ts.R_NOTREADY, "save after a FAIL load")
    # changed on disk between load and save
    dos = Dos({A: st(1, "a.example")})
    m = env.machine(dos)
    m.load("a.example")
    m.stage(rec("a.example", SPKI_2).pack())
    dos.files[B] = st(2, "a.example")
    n = len(dos.write_sizes)
    check(m.save() and m.state[1] == ts.R_CHANGED, f"changed store: {m.state}")
    check(len(dos.write_sizes) == n, "changed store was written anyway")
    # a write the firmware rejects
    dos = Dos({A: st(1, "a.example")})
    m = env.machine(dos)
    m.load("a.example")
    m.stage(rec("a.example", SPKI_2).pack())
    dos.write_error = "DISK IS FULL"
    check(m.save() and m.state[1] == ts.R_WRITE, f"write error: {m.state}")
    check(dos.handle is None, "write error left the file open")
    dos.write_error = None
    m = env.machine(dos)
    c, _ = m.load("a.example")
    check(not c and m.state[2] == 0 and m.lookup() == rec("a.example").pack(),
          "after a failed write the old slot is not the one loaded")
    # the read-back does not verify
    dos = Dos({A: st(1, "a.example")})
    m = env.machine(dos)
    m.load("a.example")
    m.stage(rec("a.example", SPKI_2).pack())
    dos.corrupt_next_read_of = B
    check(m.save() and m.state[1] == ts.R_VERIFY, f"bad read-back: {m.state}")
    check(m.state[:2] == (ts.ST_NONE, ts.R_VERIFY),
          f"a failed save must consume the load: {m.state}")
    # VERIFY means "not confirmed", not "not written": here only the read
    # was corrupted, so the disk holds a good generation 2 in B. The reload
    # must agree with the mirror's reading of what is actually on disk.
    m.load("a.example")
    sel = ts.select(dos.files.get(A), dos.files.get(B))
    check((m.state[0], m.state[2], m.state[3]) == (sel.state, sel.slot, sel.gen),
          f"reload after a failed save {m.state} != mirror {sel}")


def case_socket_guard(env):
    dos = Dos({A: st(1, "a.example")})
    m = env.machine(dos)
    m.mem.write(env.labels["net_tcp_state"], NET_TCP_CONNECTED)
    c, a = m.load("a.example")
    check(c and m.state[:2] == (ts.ST_FAIL, ts.R_BUSY), f"busy load: {m.state}")
    check(not dos.log, f"busy load touched the DOS target: {dos.log}")
    m.mem.write(env.labels["net_tcp_state"], 0)
    m.load("a.example")
    m.stage(rec("a.example", SPKI_2).pack())
    m.mem.write(env.labels["net_tcp_state"], NET_TCP_CONNECTED)
    n = len(dos.log)
    check(m.save() and m.state[1] == ts.R_BUSY, "busy save")
    check(len(dos.log) == n, "busy save touched the DOS target")


def case_read_cap(env):
    dos = Dos({A: st(2, "a.example")})
    dos.extra_bytes = 3000                   # far past the 2,065 B request
    m = env.machine(dos)
    guard = 0xC000 + ts.FILE_MAX + 1
    m.put(guard, b"\xA5" * 64)
    c, a = m.load("a.example")
    check(c and m.state[4][0] == ts.R_IO, f"over-long reply: {m.state}")
    check(bytes(m.mem.ram[guard:guard + 64]) == b"\xA5" * 64,
          "bytes stored past the read request")


CASES = [case_empty, case_save_roundtrip, case_ping_pong_and_replace,
         case_newer_and_wrap, case_fail_closed, case_torn_slot_falls_back,
         case_other_slot_open_failure_fails_closed, case_stage_and_failed_save,
         case_stale_read_back, case_junk_reply_on_open,
         case_torn_save, case_full_store_and_big_image, case_save_refusals,
         case_socket_guard, case_read_cap]


def main() -> int:
    if os.environ.get("C64_SKIP_BUILD") != "1":
        subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
        p = subprocess.run(["make", *PROFILE], cwd=REPO, capture_output=True, text=True)
        if p.returncode != 0:
            return cannot_run(f"make {' '.join(PROFILE)} failed:\n{p.stdout[-1500:]}{p.stderr[-1500:]}",
                              executed=0, total=len(CASES), certifies=CERTIFIES)
    if not PRG.is_file() or not LABELS.is_file():
        return cannot_run("no build/c64-https.prg + labels.txt", executed=0,
                          total=len(CASES), certifies=CERTIFIES)
    env = Env()
    if "trust_store_load" not in env.labels:
        return cannot_run("build/ is not a TRUST_STORE=1 image", executed=0,
                          total=len(CASES), certifies=CERTIFIES)
    global DIR, A, B
    lo, hi = env.labels["ts_name"], env.labels["ts_letter"]
    if "__TRUST_STORE_CODE_RUN__" in env.labels:  # cold bank: linked to run
        delta = env.labels["__TRUST_STORE_CODE_LOAD__"] - env.labels["__TRUST_STORE_CODE_RUN__"]
        lo, hi = lo + delta, hi + delta         #  in cert_buf, carried at $C000
    prefix = env.image[lo - env.load_addr:hi - env.load_addr].decode("ascii")
    DIR = prefix.rsplit("/", 1)[0]
    A, B = prefix + "A", prefix + "B"
    print(f"store path {prefix}A / B")
    print(f"PRG sha256 {hashlib.sha256(PRG.read_bytes()).hexdigest()}")
    for case in CASES:
        before = len(FAILED)
        try:
            case(env)
        except (CPUError, Reset) as e:
            FAILED.append(f"{case.__name__}: {e}")
        print(f"{'PASS' if len(FAILED) == before else 'FAIL'} {case.__name__}")
    print(f"{PASSED} checks passed, {len(FAILED)} failed")
    return verdict(PASSED, len(FAILED), certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
