#!/usr/bin/env python3
"""test_reu_execute.py - every REU execute is confirmed and settled (#191).

Why this exists
---------------
c64-lib-contract SPEC §8.2: after a REU execute, before the next REU
register access, confirm END OF BLOCK ($DF00 bit 6, bounded spin) and
settle. Both sibling libraries do it in their own code; our own execute
sites did not. src/reu_exec.s is now the single place that writes
reu_command, and this suite holds that in place.

What it checks
--------------
  static    no `sta reu_command` anywhere in src/ outside src/reu_exec.s,
            and reu_exec.s still reads reu_status and branches on bit 6.
            (A text guard: it is what fails on a new bare execute site.)

  VICE, REU attached (the default build: REU row-fetch profile, so
  reu_mul_init's 512 boot stashes and reu_fetch_mul_row are all live):
    boot    reu_dma_timeout == 0: every boot stash saw bit 6 inside the
            bound. $DF00 bit 6 reads CLEAR after boot -- the last boot
            stash's END OF BLOCK was consumed by a status read. On a tree
            where boot stores reu_command bare, nothing reads $DF00 and
            the bit is still set (the red case; the harness reads $DF00
            with side_effects=0, so looking does not clear it).
    call    jsr reu_execute with a STASH of a 256 B pattern to REU bank 7
            and a FETCH back: data round-trips, bit 6 consumed, timeout
            still 0, and X, Y and C come back as they went in (the helper
            replaced bare stores whose callers did not expect X/Y/C to move).

  VICE, NO REU ($DF00 is open bus):
    boot    the menu still appears (the bounded spin cannot hang a stock
            C64's boot -- ip65-onchip ships there and still runs
            reu_mul_init), and reu_dma_timeout reads 1: the bound, not
            bit 6, ended at least one spin.
    call    reu_execute returns, with X, Y and C preserved.

Usage:
    python3 tools/test_reu_execute.py [--verbose]

Env:
    C64_SKIP_BUILD=1   reuse the already-built PRG (must be the default
                       REU-profile build, or the boot checks prove less)

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config  # noqa: E402
from _skip_policy import verdict  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
HELPER_SRC = os.path.join(SRC_DIR, "reu_exec.s")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

REU_STATUS = 0xDF00
EOB = 0x40                     # $DF00 bit 6, END OF BLOCK

REQUIRED_LABELS = ["reu_execute", "reu_dma_timeout", "reu_mul_init"]

# Harness jsr() trampoline is $0334-$0338. The driver sits in the cassette
# buffer above it; the pattern buffers use the ip65 TCP ring at $C000,
# idle while the menu waits.
DRIVER_ADDR = 0x0340
SRC_BUF = 0xC000
DST_BUF = 0xC100
TEST_BANK = 7                  # REU bank reserved for the parked P-384 lane
CMD_STASH = 0x90               # execute, no autoload, C64 -> REU
CMD_FETCH = 0x91               # execute, no autoload, REU -> C64
FLAG_C = 0x01

BARE_STORE = re.compile(r"^\s*sta\s+reu_command\b", re.I | re.M)


def static_checks() -> list[tuple[str, bool, str]]:
    out = []
    offenders = []
    for root, _dirs, files in os.walk(SRC_DIR):
        for fn in files:
            if not fn.endswith((".s", ".inc")):
                continue
            path = os.path.join(root, fn)
            if os.path.abspath(path) == os.path.abspath(HELPER_SRC):
                continue
            with open(path, encoding="latin-1") as f:
                text = f.read()
            for m in BARE_STORE.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                offenders.append(f"{os.path.relpath(path, PROJECT_ROOT)}:{line}")
    out.append(("no bare `sta reu_command` outside src/reu_exec.s",
                not offenders,
                ", ".join(offenders) if offenders else "none"))
    try:
        with open(HELPER_SRC, encoding="latin-1") as f:
            helper = re.sub(r";[^\n]*", "", f.read())
    except FileNotFoundError:
        helper = ""
    shape = (len(BARE_STORE.findall(helper)) == 1
             and re.search(r"\bbit\s+reu_status\b", helper, re.I)
             and re.search(r"\bbvs\b", helper, re.I))
    out.append(("src/reu_exec.s executes once, then reads reu_status and "
                "branches on bit 6", bool(shape),
                "present" if helper else "src/reu_exec.s missing"))
    return out


def _lohi(addr: int) -> tuple[int, int]:
    return addr & 0xFF, (addr >> 8) & 0xFF


def driver(labels, c64_addr: int, cmd: int) -> bytes:
    """Program a 256 B transfer to/from TEST_BANK:$0000, then
    X=$5A, Y=$A5, SEC, LDA #cmd, JSR reu_execute, RTS."""
    c_lo, c_hi = _lohi(c64_addr)
    r_lo, r_hi = _lohi(labels["reu_execute"])
    return bytes([
        0xA9, c_lo, 0x8D, 0x02, 0xDF,        # c64 addr
        0xA9, c_hi, 0x8D, 0x03, 0xDF,
        0xA9, 0x00, 0x8D, 0x04, 0xDF,        # reu addr $0000
        0x8D, 0x05, 0xDF,
        0x8D, 0x07, 0xDF,                    # len lo = 0
        0x8D, 0x0A, 0xDF,                    # addr ctrl: both increment
        0xA9, TEST_BANK, 0x8D, 0x06, 0xDF,
        0xA9, 0x01, 0x8D, 0x08, 0xDF,        # len hi = 1 -> 256 B
        0xA2, 0x5A,                          # LDX #$5A
        0xA0, 0xA5,                          # LDY #$A5
        0x38,                                # SEC
        0xA9, cmd,                           # LDA #cmd
        0x20, r_lo, r_hi,                    # JSR reu_execute
        0x60,                                # RTS
    ])


def call_execute(transport, labels, c64_addr: int, cmd: int) -> dict:
    write_bytes(transport, DRIVER_ADDR, driver(labels, c64_addr, cmd))
    t0 = time.monotonic()
    regs = jsr(transport, DRIVER_ADDR, timeout=30.0)
    regs["_seconds"] = time.monotonic() - t0
    return regs


def regs_preserved(regs: dict) -> list[tuple[str, bool]]:
    fl = regs.get("FL", regs.get("P", 0))
    return [("X preserved ($5A)", regs.get("X") == 0x5A),
            ("Y preserved ($A5)", regs.get("Y") == 0xA5),
            ("C preserved (set)", bool(fl & FLAG_C))]


def boot(mgr) -> object:
    inst = mgr.acquire()
    grid = wait_for_text(inst.transport, "Q=QUIT", timeout=180.0,
                         verbose=False)
    if grid is None:
        mgr.release(inst)
        return None
    return inst


def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)
    VERBOSE = "--verbose" in sys.argv
    passed = failed = 0

    def report(label, ok, detail=""):
        nonlocal passed, failed
        print(f"  [{'+' if ok else '-'}] {label}" + (f"  ({detail})" if detail
                                                     and (VERBOSE or not ok)
                                                     else ""))
        if ok:
            passed += 1
        else:
            failed += 1

    print("\n=== Static: one execute site ===")
    for label, ok, detail in static_checks():
        report(label, ok, detail)

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building (default: REU row-fetch profile) ===")
        subprocess.run(["make", "clean"], capture_output=True)
        result = subprocess.run(["make"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return 1
        print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        return 1
    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

    pattern = bytes((i * 37 + 11) & 0xFF for i in range(256))

    print("\n=== VICE with REU ===")
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = boot(mgr)
        if inst is None:
            print("FATAL: main menu did not appear (REU attached)")
            return 1
        t = inst.transport
        try:
            timeout = read_bytes(t, labels["reu_dma_timeout"], 1)[0]
            status = read_bytes(t, REU_STATUS, 1)[0]
            report("boot: reu_dma_timeout == 0 (all 512 stashes confirmed "
                   "inside the bound)", timeout == 0, f"${timeout:02X}")
            report("boot: $DF00 END OF BLOCK consumed after the last boot "
                   "stash", not status & EOB, f"$DF00=${status:02X}")

            write_bytes(t, SRC_BUF, pattern)
            write_bytes(t, DST_BUF, bytes(256))
            regs = call_execute(t, labels, SRC_BUF, CMD_STASH)
            status = read_bytes(t, REU_STATUS, 1)[0]
            for label, ok in regs_preserved(regs):
                report(f"call STASH: {label}", ok, str(regs))
            report("call STASH: $DF00 END OF BLOCK consumed", not status & EOB,
                   f"$DF00=${status:02X}")
            regs = call_execute(t, labels, DST_BUF, CMD_FETCH)
            got = read_bytes(t, DST_BUF, 256)
            report("call FETCH: 256 B pattern round-trips through REU bank 7",
                   got == pattern,
                   f"{sum(a == b for a, b in zip(got, pattern))}/256 match")
            for label, ok in regs_preserved(regs):
                report(f"call FETCH: {label}", ok, str(regs))
            timeout = read_bytes(t, labels["reu_dma_timeout"], 1)[0]
            report("call: reu_dma_timeout still 0", timeout == 0,
                   f"${timeout:02X}")
        finally:
            mgr.release(inst)

    print("\n=== VICE without REU ($DF00 open bus) ===")
    # Deliberately NOT default_vice_config(): this instance must have no
    # REU. Only boot and the helper run here -- no crypto, so the
    # REU-profile build's wrong-answers-without-REU trap is not reached.
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = boot(mgr)
        report("boot without REU reaches the menu (bounded spin, no hang)",
               inst is not None)
        if inst is not None:
            t = inst.transport
            try:
                timeout = read_bytes(t, labels["reu_dma_timeout"], 1)[0]
                report("boot without REU: reu_dma_timeout == 1 (the bound "
                       "ended a spin)", timeout == 1, f"${timeout:02X}")
                regs = call_execute(t, labels, SRC_BUF, CMD_STASH)
                report("call without REU returns", True,
                       f"{regs['_seconds']:.2f}s")
                for label, ok in regs_preserved(regs):
                    report(f"call without REU: {label}", ok, str(regs))
            finally:
                mgr.release(inst)

    total = passed + failed
    print("\n" + "=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    print("=" * 60)
    return verdict(passed, failed,
                   certifies="the REU execute confirm + settle (#191)")


if __name__ == "__main__":
    sys.exit(main())
