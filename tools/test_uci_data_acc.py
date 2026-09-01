#!/usr/bin/env python3
"""Behavioural test for the UCI DATA_ACC handshake (issue #144, item 1).

WHAT THIS TESTS

``$02`` written to ``$DF1C`` is **DATA_ACC**, the accept that *ends* a
transfer — not a per-byte "advance the FIFO" pulse.  Register API v1.1
§2.4.1:

    "Writing a '1' to this register bit tells the communication layer
     that all data from the Ultimate was accepted. ... Writing to this
     bit also causes the transfer of the data/status queues to be
     aborted and reset.  Thus, the data response and status response
     queues will be empty after writing this bit."

and ``command_protocol.vhd`` advances both pointers on the C64 *read*
strobe with no host action::

    when c_cif_slot_response =>  response_pointer <= response_pointer + 1;
    when c_cif_slot_status   =>  status_pointer   <= status_pointer   + 1;

So a drain loop that pulses ``$02`` after each byte reads exactly one
byte and then destroys **both** queues — including the status line the
firmware wrote to explain itself, which ``uci_drain_status`` is supposed
to capture right afterwards (#147).

HOW IT TESTS IT

There is no VICE path for the UCI backend: ``$DF1B-$DF1F`` is unmapped
in the emulator, so a drain loop cannot be exercised there, and this
repo has no hardware in CI.  Instead this module executes the *shipped
machine code* — the actual bytes of ``uci_drain_resp`` and
``uci_drain_status`` lifted out of ``build/c64-https.prg`` at the
addresses in ``build/labels.txt`` — on a small 6502 interpreter, against
a model of the Command Interface built from the two quotes above:

  * reading ``$DF1E`` / ``$DF1F`` returns the next queued byte and
    auto-advances that queue,
  * ``$DF1C`` reports DATA_AV ($80) / STAT_AV ($40) while the
    corresponding queue still has bytes and the data phase is live,
  * writing ``$02`` to ``$DF1C`` ends the data phase: both queues are
    reset and every later read returns $00.

WHAT IT DOES NOT PROVE

The FPGA model is a reading of the documentation and the VHDL, not a
measurement.  If the model is wrong, this test is wrong with it.  It
also says nothing about FPGA register timing (the ``uci_fence`` floor),
about anything the firmware does above the register layer, or about the
other two defects in #144.  A hardware run is what closes those; see the
PR for the exact one.

WHAT A MISSING UCI BUILD MEANS (issue #165)

This module reads whatever PRG happens to be sitting in ``build/``.  On a
``BACKEND=ip65`` build — or a stale tree — the ``uci_*`` labels are absent
and none of the three checks can run.  That is an **involuntary** skip: the
suite did not choose it, the environment forced it, and it certifies
nothing.  Per the rule adopted in #158 (audit commit ``7497e48``) an
involuntary skip is a **failure**, exit 2, never a silent 0 — otherwise a
runner reads "green" for a run in which the DATA_ACC semantics pinned by
#144 were never exercised.

A *voluntary* skip stays available and stays distinguishable: set
``C64_UCI_TESTS_OPTIONAL=1`` to declare "I know this is not a UCI build and
I am choosing not to test it".  That prints what did not run and exits 0.

Runs standalone or under pytest::

    python3 tools/test_uci_data_acc.py
    pytest tools/test_uci_data_acc.py
"""

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PRG = REPO / "build" / "c64-https.prg"
LABELS = REPO / "build" / "labels.txt"

# The one deliberate, announced way to skip this suite.  Anything else that
# stops it running is a failure (#165).
OPT_OUT_ENV = "C64_UCI_TESTS_OPTIONAL"

# The status line the firmware is imagined to have written.  Deliberately
# NOT a "00,..." or "02,..." line: uci_drain_status filters those two as
# routine (see its @dst_filter), so they would not reach uci_status_len.
STATUS_LINE = b"04,GENERAL ERR"

# Leftover response bytes the caller did not want, which uci_drain_resp
# exists to consume.  Any value; only the count matters.
RESP_LEFTOVER = bytes([0x11, 0x22, 0x33, 0x44, 0x55])


# ---------------------------------------------------------------------------
# Command Interface model
# ---------------------------------------------------------------------------

UCI_STAT_DATA_AV = 0x80
UCI_STAT_STAT_AV = 0x40
UCI_CTRL_DATA_ACC = 0x02


class CommandInterface:
    """The $DF1B-$DF1F register file, per Register API v1.1 + the VHDL."""

    def __init__(self, response=b"", status=b""):
        self.response = bytes(response)
        self.status = bytes(status)
        self.resp_ptr = 0
        self.stat_ptr = 0
        self.data_phase = True          # DATA_ACC has not been written yet
        self.accepts = 0                # DATA_ACC writes seen

    # -- host reads ---------------------------------------------------------
    def read(self, addr):
        if addr == 0xDF1C:              # STATUS
            bits = 0
            if self.data_phase:
                if self.resp_ptr < len(self.response):
                    bits |= UCI_STAT_DATA_AV
                if self.stat_ptr < len(self.status):
                    bits |= UCI_STAT_STAT_AV
            return bits
        if addr == 0xDF1D:              # ID
            return 0xC9
        if addr == 0xDF1E:              # response queue
            if not self.data_phase or self.resp_ptr >= len(self.response):
                return 0x00
            value = self.response[self.resp_ptr]
            self.resp_ptr += 1          # reads auto-advance
            return value
        if addr == 0xDF1F:              # status queue
            if not self.data_phase or self.stat_ptr >= len(self.status):
                return 0x00
            value = self.status[self.stat_ptr]
            self.stat_ptr += 1          # reads auto-advance
            return value
        return 0x00

    # -- host writes --------------------------------------------------------
    def write(self, addr, value):
        if addr == 0xDF1C and (value & UCI_CTRL_DATA_ACC):
            # "the data response and status response queues will be
            #  empty after writing this bit"
            self.accepts += 1
            self.data_phase = False
            self.resp_ptr = len(self.response)
            self.stat_ptr = len(self.status)

    # -- observations -------------------------------------------------------
    @property
    def status_untouched(self):
        return self.stat_ptr == 0

    @property
    def response_fully_drained(self):
        return self.resp_ptr == len(self.response)


class Memory:
    """64 KB of RAM with the CIA1 TOD and the UCI registers overlaid."""

    def __init__(self, image, load_addr, uci):
        self.ram = bytearray(0x10000)
        self.ram[load_addr:load_addr + len(image)] = image
        self.uci = uci

    def read(self, addr):
        addr &= 0xFFFF
        if 0xDF00 <= addr <= 0xDFFF:
            return self.uci.read(addr)
        if 0xDC00 <= addr <= 0xDCFF:
            # CIA1.  TOD tenths/hour read as a constant, so no bounded
            # wait in the drain loops can ever expire here; a hang shows
            # up as the instruction-budget trip below, not as a spurious
            # UCI_ERR_WAIT_TIMEOUT.
            return 0x00
        return self.ram[addr]

    def write(self, addr, value):
        addr &= 0xFFFF
        if 0xDF00 <= addr <= 0xDFFF:
            self.uci.write(addr, value & 0xFF)
            return
        if 0xDC00 <= addr <= 0xDCFF:
            return
        self.ram[addr] = value & 0xFF


# ---------------------------------------------------------------------------
# 6502 interpreter (NMOS subset, binary mode; enough for src/net/uci)
# ---------------------------------------------------------------------------

IMP, IMM, ZP, ZPX, ZPY, ABS, ABX, ABY, INDX, INDY, IND, REL, ACC = range(13)

OPCODES = {
    0xA9: ("LDA", IMM), 0xA5: ("LDA", ZP), 0xB5: ("LDA", ZPX),
    0xAD: ("LDA", ABS), 0xBD: ("LDA", ABX), 0xB9: ("LDA", ABY),
    0xA1: ("LDA", INDX), 0xB1: ("LDA", INDY),
    0xA2: ("LDX", IMM), 0xA6: ("LDX", ZP), 0xB6: ("LDX", ZPY),
    0xAE: ("LDX", ABS), 0xBE: ("LDX", ABY),
    0xA0: ("LDY", IMM), 0xA4: ("LDY", ZP), 0xB4: ("LDY", ZPX),
    0xAC: ("LDY", ABS), 0xBC: ("LDY", ABX),
    0x85: ("STA", ZP), 0x95: ("STA", ZPX), 0x8D: ("STA", ABS),
    0x9D: ("STA", ABX), 0x99: ("STA", ABY), 0x81: ("STA", INDX),
    0x91: ("STA", INDY),
    0x86: ("STX", ZP), 0x96: ("STX", ZPY), 0x8E: ("STX", ABS),
    0x84: ("STY", ZP), 0x94: ("STY", ZPX), 0x8C: ("STY", ABS),
    0xAA: ("TAX", IMP), 0xA8: ("TAY", IMP), 0x8A: ("TXA", IMP),
    0x98: ("TYA", IMP), 0xBA: ("TSX", IMP), 0x9A: ("TXS", IMP),
    0x48: ("PHA", IMP), 0x68: ("PLA", IMP), 0x08: ("PHP", IMP),
    0x28: ("PLP", IMP),
    0x29: ("AND", IMM), 0x25: ("AND", ZP), 0x35: ("AND", ZPX),
    0x2D: ("AND", ABS), 0x3D: ("AND", ABX), 0x39: ("AND", ABY),
    0x09: ("ORA", IMM), 0x05: ("ORA", ZP), 0x15: ("ORA", ZPX),
    0x0D: ("ORA", ABS), 0x1D: ("ORA", ABX), 0x19: ("ORA", ABY),
    0x49: ("EOR", IMM), 0x45: ("EOR", ZP), 0x4D: ("EOR", ABS),
    0x24: ("BIT", ZP), 0x2C: ("BIT", ABS),
    0x69: ("ADC", IMM), 0x65: ("ADC", ZP), 0x6D: ("ADC", ABS),
    0x7D: ("ADC", ABX), 0x79: ("ADC", ABY),
    0xE9: ("SBC", IMM), 0xE5: ("SBC", ZP), 0xED: ("SBC", ABS),
    0xFD: ("SBC", ABX), 0xF9: ("SBC", ABY),
    0xC9: ("CMP", IMM), 0xC5: ("CMP", ZP), 0xD5: ("CMP", ZPX),
    0xCD: ("CMP", ABS), 0xDD: ("CMP", ABX), 0xD9: ("CMP", ABY),
    0xE0: ("CPX", IMM), 0xE4: ("CPX", ZP), 0xEC: ("CPX", ABS),
    0xC0: ("CPY", IMM), 0xC4: ("CPY", ZP), 0xCC: ("CPY", ABS),
    0xE6: ("INC", ZP), 0xF6: ("INC", ZPX), 0xEE: ("INC", ABS),
    0xFE: ("INC", ABX),
    0xC6: ("DEC", ZP), 0xD6: ("DEC", ZPX), 0xCE: ("DEC", ABS),
    0xDE: ("DEC", ABX),
    0xE8: ("INX", IMP), 0xC8: ("INY", IMP), 0xCA: ("DEX", IMP),
    0x88: ("DEY", IMP),
    0x0A: ("ASL", ACC), 0x06: ("ASL", ZP), 0x0E: ("ASL", ABS),
    0x4A: ("LSR", ACC), 0x46: ("LSR", ZP), 0x4E: ("LSR", ABS),
    0x2A: ("ROL", ACC), 0x26: ("ROL", ZP), 0x2E: ("ROL", ABS),
    0x6A: ("ROR", ACC), 0x66: ("ROR", ZP), 0x6E: ("ROR", ABS),
    0x4C: ("JMP", ABS), 0x6C: ("JMP", IND), 0x20: ("JSR", ABS),
    0x60: ("RTS", IMP),
    0x10: ("BPL", REL), 0x30: ("BMI", REL), 0x50: ("BVC", REL),
    0x70: ("BVS", REL), 0x90: ("BCC", REL), 0xB0: ("BCS", REL),
    0xD0: ("BNE", REL), 0xF0: ("BEQ", REL),
    0x18: ("CLC", IMP), 0x38: ("SEC", IMP), 0x58: ("CLI", IMP),
    0x78: ("SEI", IMP), 0xB8: ("CLV", IMP), 0xD8: ("CLD", IMP),
    0xF8: ("SED", IMP), 0xEA: ("NOP", IMP),
}

SENTINEL = 0xFFF0       # RTS to here means "the routine returned"


class CPUError(RuntimeError):
    pass


class CPU:
    def __init__(self, mem):
        self.mem = mem
        self.a = self.x = self.y = 0
        self.sp = 0xFD
        self.pc = 0
        self.c = self.z = self.v = self.n = False
        self.d = False
        self.i = True
        self.steps = 0

    # -- helpers ------------------------------------------------------------
    def _push(self, value):
        self.mem.write(0x0100 + self.sp, value & 0xFF)
        self.sp = (self.sp - 1) & 0xFF

    def _pull(self):
        self.sp = (self.sp + 1) & 0xFF
        return self.mem.read(0x0100 + self.sp)

    def _fetch(self):
        value = self.mem.read(self.pc)
        self.pc = (self.pc + 1) & 0xFFFF
        return value

    def _fetch_word(self):
        lo = self._fetch()
        return lo | (self._fetch() << 8)

    def _nz(self, value):
        self.z = (value & 0xFF) == 0
        self.n = bool(value & 0x80)
        return value & 0xFF

    def _status_byte(self):
        return (0x20 | (0x80 if self.n else 0) | (0x40 if self.v else 0)
                | (0x10) | (0x08 if self.d else 0) | (0x04 if self.i else 0)
                | (0x02 if self.z else 0) | (0x01 if self.c else 0))

    def _set_status(self, value):
        self.n = bool(value & 0x80)
        self.v = bool(value & 0x40)
        self.d = bool(value & 0x08)
        self.i = bool(value & 0x04)
        self.z = bool(value & 0x02)
        self.c = bool(value & 0x01)

    def _addr(self, mode):
        if mode == ZP:
            return self._fetch()
        if mode == ZPX:
            return (self._fetch() + self.x) & 0xFF
        if mode == ZPY:
            return (self._fetch() + self.y) & 0xFF
        if mode == ABS:
            return self._fetch_word()
        if mode == ABX:
            return (self._fetch_word() + self.x) & 0xFFFF
        if mode == ABY:
            return (self._fetch_word() + self.y) & 0xFFFF
        if mode == INDX:
            base = (self._fetch() + self.x) & 0xFF
            return self.mem.read(base) | (self.mem.read((base + 1) & 0xFF) << 8)
        if mode == INDY:
            base = self._fetch()
            ptr = self.mem.read(base) | (self.mem.read((base + 1) & 0xFF) << 8)
            return (ptr + self.y) & 0xFFFF
        if mode == IND:
            ptr = self._fetch_word()
            # NMOS page-wrap bug, faithfully
            hi = (ptr & 0xFF00) | ((ptr + 1) & 0x00FF)
            return self.mem.read(ptr) | (self.mem.read(hi) << 8)
        raise CPUError("bad address mode %r" % (mode,))

    def _operand(self, mode):
        if mode == IMM:
            return self._fetch()
        return self.mem.read(self._addr(mode))

    # -- the loop -----------------------------------------------------------
    def call(self, addr, budget=8_000_000):
        """JSR `addr`; run until it returns.  Returns the carry flag."""
        self.pc = addr
        self.sp = 0xFD
        self._push((SENTINEL - 1) >> 8)
        self._push((SENTINEL - 1) & 0xFF)
        start = self.steps
        while True:
            if self.pc == SENTINEL:
                return self.c
            self.step()
            if self.steps - start > budget:
                raise CPUError(
                    "instruction budget exhausted at $%04X — the routine "
                    "did not return (a real spin-wait would hang here)"
                    % self.pc)

    def step(self):
        self.steps += 1
        pc0 = self.pc
        opcode = self._fetch()
        entry = OPCODES.get(opcode)
        if entry is None:
            raise CPUError("unimplemented opcode $%02X at $%04X"
                           % (opcode, pc0))
        name, mode = entry
        getattr(self, "_op_" + name)(mode)

    # -- operations ---------------------------------------------------------
    def _op_LDA(self, mode):
        self.a = self._nz(self._operand(mode))

    def _op_LDX(self, mode):
        self.x = self._nz(self._operand(mode))

    def _op_LDY(self, mode):
        self.y = self._nz(self._operand(mode))

    def _op_STA(self, mode):
        self.mem.write(self._addr(mode), self.a)

    def _op_STX(self, mode):
        self.mem.write(self._addr(mode), self.x)

    def _op_STY(self, mode):
        self.mem.write(self._addr(mode), self.y)

    def _op_TAX(self, mode):
        self.x = self._nz(self.a)

    def _op_TAY(self, mode):
        self.y = self._nz(self.a)

    def _op_TXA(self, mode):
        self.a = self._nz(self.x)

    def _op_TYA(self, mode):
        self.a = self._nz(self.y)

    def _op_TSX(self, mode):
        self.x = self._nz(self.sp)

    def _op_TXS(self, mode):
        self.sp = self.x

    def _op_PHA(self, mode):
        self._push(self.a)

    def _op_PLA(self, mode):
        self.a = self._nz(self._pull())

    def _op_PHP(self, mode):
        self._push(self._status_byte())

    def _op_PLP(self, mode):
        self._set_status(self._pull())

    def _op_AND(self, mode):
        self.a = self._nz(self.a & self._operand(mode))

    def _op_ORA(self, mode):
        self.a = self._nz(self.a | self._operand(mode))

    def _op_EOR(self, mode):
        self.a = self._nz(self.a ^ self._operand(mode))

    def _op_BIT(self, mode):
        value = self._operand(mode)
        self.z = (self.a & value) == 0
        self.n = bool(value & 0x80)
        self.v = bool(value & 0x40)

    def _op_ADC(self, mode):
        value = self._operand(mode)
        total = self.a + value + (1 if self.c else 0)
        self.c = total > 0xFF
        self.v = bool((~(self.a ^ value) & (self.a ^ total)) & 0x80)
        self.a = self._nz(total)

    def _op_SBC(self, mode):
        value = self._operand(mode) ^ 0xFF
        total = self.a + value + (1 if self.c else 0)
        self.c = total > 0xFF
        self.v = bool((~(self.a ^ value) & (self.a ^ total)) & 0x80)
        self.a = self._nz(total)

    def _compare(self, reg, value):
        self.c = reg >= value
        self._nz((reg - value) & 0xFF)

    def _op_CMP(self, mode):
        self._compare(self.a, self._operand(mode))

    def _op_CPX(self, mode):
        self._compare(self.x, self._operand(mode))

    def _op_CPY(self, mode):
        self._compare(self.y, self._operand(mode))

    def _op_INC(self, mode):
        addr = self._addr(mode)
        self.mem.write(addr, self._nz(self.mem.read(addr) + 1))

    def _op_DEC(self, mode):
        addr = self._addr(mode)
        self.mem.write(addr, self._nz(self.mem.read(addr) - 1))

    def _op_INX(self, mode):
        self.x = self._nz(self.x + 1)

    def _op_INY(self, mode):
        self.y = self._nz(self.y + 1)

    def _op_DEX(self, mode):
        self.x = self._nz(self.x - 1)

    def _op_DEY(self, mode):
        self.y = self._nz(self.y - 1)

    def _rmw(self, mode, fn):
        if mode == ACC:
            self.a = fn(self.a)
            return
        addr = self._addr(mode)
        self.mem.write(addr, fn(self.mem.read(addr)))

    def _op_ASL(self, mode):
        def fn(value):
            self.c = bool(value & 0x80)
            return self._nz(value << 1)
        self._rmw(mode, fn)

    def _op_LSR(self, mode):
        def fn(value):
            self.c = bool(value & 0x01)
            return self._nz(value >> 1)
        self._rmw(mode, fn)

    def _op_ROL(self, mode):
        def fn(value):
            carry_in = 1 if self.c else 0
            self.c = bool(value & 0x80)
            return self._nz((value << 1) | carry_in)
        self._rmw(mode, fn)

    def _op_ROR(self, mode):
        def fn(value):
            carry_in = 0x80 if self.c else 0
            self.c = bool(value & 0x01)
            return self._nz((value >> 1) | carry_in)
        self._rmw(mode, fn)

    def _op_JMP(self, mode):
        self.pc = self._addr(mode)

    def _op_JSR(self, mode):
        target = self._fetch_word()
        ret = (self.pc - 1) & 0xFFFF
        self._push(ret >> 8)
        self._push(ret & 0xFF)
        self.pc = target

    def _op_RTS(self, mode):
        lo = self._pull()
        hi = self._pull()
        self.pc = ((lo | (hi << 8)) + 1) & 0xFFFF

    def _branch(self, taken):
        offset = self._fetch()
        if taken:
            if offset & 0x80:
                offset -= 0x100
            self.pc = (self.pc + offset) & 0xFFFF

    def _op_BPL(self, mode):
        self._branch(not self.n)

    def _op_BMI(self, mode):
        self._branch(self.n)

    def _op_BVC(self, mode):
        self._branch(not self.v)

    def _op_BVS(self, mode):
        self._branch(self.v)

    def _op_BCC(self, mode):
        self._branch(not self.c)

    def _op_BCS(self, mode):
        self._branch(self.c)

    def _op_BNE(self, mode):
        self._branch(not self.z)

    def _op_BEQ(self, mode):
        self._branch(self.z)

    def _op_CLC(self, mode):
        self.c = False

    def _op_SEC(self, mode):
        self.c = True

    def _op_CLI(self, mode):
        self.i = False

    def _op_SEI(self, mode):
        self.i = True

    def _op_CLV(self, mode):
        self.v = False

    def _op_CLD(self, mode):
        self.d = False

    def _op_SED(self, mode):
        self.d = True

    def _op_NOP(self, mode):
        pass


# ---------------------------------------------------------------------------
# Fixture plumbing
# ---------------------------------------------------------------------------

class Unavailable(Exception):
    """No UCI-backend build to test against — an INVOLUNTARY skip.

    Never caught into a pass.  ``_require`` re-raises it (so pytest records
    an error and standalone ``main`` counts it) unless the operator has
    opted out explicitly via ``C64_UCI_TESTS_OPTIONAL=1``.
    """


class VoluntarySkip(Exception):
    """The operator declared this run deliberately untested (opt-out env)."""


# Every assertion this module runs goes through _check, so the count it
# reports is measured, not declared.  A run that says "0 assertions" cannot
# also say "passed".
ASSERTIONS_RUN = 0


def _check(condition, message):
    """assert, but counted."""
    global ASSERTIONS_RUN
    ASSERTIONS_RUN += 1
    if not condition:
        raise AssertionError(message)


def _require(fn, *args):
    """Run a fixture builder; turn Unavailable into the right outcome.

    Default (involuntary): re-raise, so the check fails loudly and names the
    wrong-backend reason.  With ``C64_UCI_TESTS_OPTIONAL=1``: a voluntary,
    announced skip.
    """
    try:
        return fn(*args)
    except Unavailable as exc:
        if os.environ.get(OPT_OUT_ENV) != "1":
            raise
        # The reason carries the vacuity warning itself, because under
        # pytest this string is the ONLY channel: `-ra` (pinned in
        # pytest.ini addopts) prints it and nothing else. An opt-out that
        # reads as a bare "skipped" would be #165 again with a flag on it.
        reason = ("EXPLICIT SKIP (%s=1 is set in this environment): %s "
                  "0 of %d checks and 0 assertions ran; this exit-0 "
                  "certifies NOTHING about the DATA_ACC accept protocol "
                  "(#144 item 1). Unset %s to make it a failure again."
                  % (OPT_OUT_ENV, exc, len(TESTS), OPT_OUT_ENV))
        # Only hand the skip to pytest when pytest is actually driving; the
        # standalone runner has its own reporting and must not see Skipped.
        pytest = sys.modules.get("pytest")
        if pytest is None:
            raise VoluntarySkip(reason)
        pytest.skip(reason, allow_module_level=False)


def _labels():
    if not LABELS.is_file():
        raise Unavailable("build/labels.txt is missing — build first with "
                          "`make BACKEND=uci USE_NISTCURVES_ONCHIP=1`")
    table = {}
    for line in LABELS.read_text().splitlines():
        parts = line.split()
        # `al C:26BE .uci_drain_resp`
        if len(parts) >= 3 and parts[0] == "al" and parts[2].startswith("."):
            addr = parts[1].split(":")[-1]
            table[parts[2][1:]] = int(addr, 16)
    return table


def _machine(response, status):
    """A CPU with the shipped PRG image loaded and the CI armed."""
    if not PRG.is_file():
        raise Unavailable("build/c64-https.prg is missing — build first with "
                          "`make BACKEND=uci USE_NISTCURVES_ONCHIP=1`")
    labels = _labels()
    for needed in ("uci_drain_resp", "uci_drain_status", "uci_ack",
                   "uci_status_buf", "uci_status_len", "uci_status_seen",
                   "uci_status_force"):
        if needed not in labels:
            raise Unavailable(
                "%s is not in build/labels.txt — this is not a BACKEND=uci "
                "build; rebuild with `make clean && make BACKEND=uci "
                "USE_NISTCURVES_ONCHIP=1`" % needed)

    raw = PRG.read_bytes()
    load_addr = raw[0] | (raw[1] << 8)
    uci = CommandInterface(response=response, status=status)
    mem = Memory(raw[2:], load_addr, uci)

    # UCI_BSS is not initialised by the file image in any meaningful way;
    # net_init zeroes what matters at boot.  Do the same here so the run
    # is deterministic.
    for name in ("uci_status_len", "uci_status_seen", "uci_status_force"):
        mem.write(labels[name], 0)
    for i in range(16):
        mem.write(labels["uci_status_buf"] + i, 0)

    return CPU(mem), mem, uci, labels


def _captured_status(mem, labels):
    length = mem.read(labels["uci_status_len"])
    return bytes(mem.read(labels["uci_status_buf"] + i) for i in range(length))


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------

def test_drain_resp_leaves_the_status_line_readable():
    """uci_drain_resp must not accept — the status line is drained after it.

    This is the #144 item-1 regression.  With a per-byte DATA_ACC pulse in
    the loop, the first byte's pulse ends the data phase, so the drain
    stops one byte in AND the status queue the firmware wrote is gone
    before uci_drain_status ever looks at it.
    """
    cpu, mem, uci, labels = _require(_machine, RESP_LEFTOVER, STATUS_LINE)

    carry = cpu.call(labels["uci_drain_resp"])
    _check(carry is False, "uci_drain_resp reported a timeout (C=1)")

    _check(uci.accepts == 0, (
        "uci_drain_resp wrote DATA_ACC ($02 -> $DF1C) %d time(s). DATA_ACC "
        "is the end-of-transfer accept, not a FIFO advance: it resets the "
        "response AND status queues, so the drain stops early and the "
        "status line is destroyed before uci_drain_status reads it "
        "(issue #144 item 1)." % uci.accepts))

    _check(uci.response_fully_drained, (
        "uci_drain_resp consumed %d of %d response bytes — DATA_AV dropped "
        "under it because something ended the data phase"
        % (uci.resp_ptr, len(RESP_LEFTOVER))))

    _check(uci.status_untouched, (
        "uci_drain_resp consumed %d status byte(s); the status queue is "
        "uci_drain_status's to read" % uci.stat_ptr))

    # And the payoff: the firmware's own line survives into the capture.
    carry = cpu.call(labels["uci_drain_status"])
    _check(carry is False, "uci_drain_status reported a timeout (C=1)")

    seen = mem.read(labels["uci_status_seen"])
    _check(seen == len(STATUS_LINE), (
        "uci_drain_status saw %d of %d status bytes after uci_drain_resp "
        "ran; this is the truncated capture #147 fixed, reintroduced one "
        "routine upstream" % (seen, len(STATUS_LINE))))

    captured = _captured_status(mem, labels)
    _check(captured == STATUS_LINE, (
        "captured status line %r != %r" % (captured, STATUS_LINE)))


def test_drain_status_capture_control():
    """Control: with nothing queued for uci_drain_resp, the capture works.

    Isolates the assertion above.  If this one ever fails too, the fault
    is in uci_drain_status or in this harness, not in the accept.
    """
    cpu, mem, uci, labels = _require(_machine, b"", STATUS_LINE)

    _check(cpu.call(labels["uci_drain_resp"]) is False,
           "uci_drain_resp reported a timeout (C=1) with an empty queue")
    _check(cpu.call(labels["uci_drain_status"]) is False,
           "uci_drain_status reported a timeout (C=1)")

    _check(mem.read(labels["uci_status_seen"]) == len(STATUS_LINE),
           "uci_drain_status saw %d of %d status bytes"
           % (mem.read(labels["uci_status_seen"]), len(STATUS_LINE)))
    _check(_captured_status(mem, labels) == STATUS_LINE,
           "captured status line %r != %r"
           % (_captured_status(mem, labels), STATUS_LINE))


def test_accept_still_ends_the_transfer():
    """uci_ack is the one place that writes DATA_ACC, and it still does.

    Deleting the per-byte pulse must not delete the accept itself: without
    it the state machine never returns to idle and the next PUSH_CMD is
    silently dropped (#144 item 2).  Every drain site in net.s runs
    drain_resp -> drain_status -> uci_ack; this pins the third step.
    """
    cpu, mem, uci, labels = _require(_machine, RESP_LEFTOVER, STATUS_LINE)

    cpu.call(labels["uci_ack"])
    _check(uci.accepts == 1, (
        "uci_ack wrote DATA_ACC %d times, expected exactly 1" % uci.accepts))
    _check(uci.data_phase is False, "the transfer was not ended")


# ---------------------------------------------------------------------------
# Dual-mode runner (the repo declares no pytest dependency)
# ---------------------------------------------------------------------------

TESTS = (
    test_drain_resp_leaves_the_status_line_readable,
    test_drain_status_capture_control,
    test_accept_still_ends_the_transfer,
)

# Exit codes, matching the convention #158 established across the suites:
#   0  everything that was supposed to run, ran and passed
#   1  a check failed
#   2  the suite could not run at all (involuntary skip)
EXIT_OK, EXIT_FAILED, EXIT_CANNOT_RUN = 0, 1, 2


def _cannot_run(reason):
    print("CANNOT RUN: %s" % reason)
    print("  0 of %d checks executed; %d assertions ran. This run certifies "
          "nothing about the\n  DATA_ACC accept protocol (#144 item 1)."
          % (len(TESTS), ASSERTIONS_RUN))
    print("  Set %s=1 to make skipping it a deliberate, exit-0 choice."
          % OPT_OUT_ENV)
    return EXIT_CANNOT_RUN


def main():
    if not PRG.is_file() or not LABELS.is_file():
        if os.environ.get(OPT_OUT_ENV) == "1":
            print("EXPLICIT SKIP (%s=1): no build in build/; "
                  "test_uci_data_acc.py did NOT run." % OPT_OUT_ENV)
            print("  0 of %d checks executed; this exit 0 certifies nothing."
                  % len(TESTS))
            return EXIT_OK
        return _cannot_run(
            "no build to test. Run `make clean && make BACKEND=uci "
            "USE_NISTCURVES_ONCHIP=1`")

    failures = 0
    executed = 0
    skipped = []
    for fn in TESTS:
        try:
            fn()
        except VoluntarySkip as exc:
            skipped.append((fn.__name__, str(exc)))
            print("SKIP %s: %s" % (fn.__name__, exc))
        except Unavailable as exc:
            # Involuntary: the wrong build is present. Not a pass, and not a
            # partial result either — abandon the run and say why (#165).
            return _cannot_run(str(exc))
        except AssertionError as exc:
            failures += 1
            executed += 1
            print("FAIL %s\n     %s" % (fn.__name__, exc))
        except CPUError as exc:
            failures += 1
            executed += 1
            print("FAIL %s (interpreter): %s" % (fn.__name__, exc))
        else:
            executed += 1
            print("PASS %s" % fn.__name__)

    if skipped:
        print("\nEXPLICIT SKIP (%s=1): %d of %d checks did NOT run; this run "
              "certifies\nnothing about them." % (OPT_OUT_ENV, len(skipped),
                                                  len(TESTS)))
        if executed == 0:
            print("  0 assertions executed.")
            return EXIT_OK

    if failures:
        print("\n%d/%d checks failed (%d assertions executed)"
              % (failures, executed, ASSERTIONS_RUN))
        return EXIT_FAILED

    # A run with nothing in it is never a pass.
    if executed == 0 or ASSERTIONS_RUN == 0:
        return _cannot_run("no check executed and no assertion ran")

    print("\nall %d checks passed (%d assertions executed)"
          % (executed, ASSERTIONS_RUN))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
