#!/usr/bin/env python3
"""bench_x25519.py -- X25519 key generation benchmark on C64.

Runs x25519_base (scalar * basepoint 9) on the C64 and measures
wall-clock and C64 time (CIA1 time-of-day clock). Verifies result
against RFC 7748.

Usage:
    python3 tools/bench_x25519.py [--no-verify] [--no-blank]
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

from _vice_helpers import default_vice_config

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

NTSC_HZ = 60
NTSC_CYCLES_PER_SEC = 1_022_727

# Trampoline and result storage in cassette buffer area
TRAMPOLINE_ADDR = 0x0360
BENCH_TICKS_ADDR = 0x0350  # 4 bytes: CIA1 TOD hours/min/sec/tenths (BCD)

# Test scalar for basepoint multiply (x25519_base clamps this internally)
BENCH_SCALAR = bytes.fromhex(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
)


def compute_expected_pubkey(scalar_bytes):
    """Compute expected public key = clamp(scalar) * basepoint(9) via Python."""
    if not HAS_CRYPTO:
        return None
    # X25519PrivateKey.from_private_bytes applies clamping internally
    privkey = X25519PrivateKey.from_private_bytes(scalar_bytes)
    pubkey_bytes = privkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pubkey_bytes


def build_trampoline(labels, blank=True):
    """Build 6502 trampoline: build tables, zero TOD, [blank VIC], jsr x25519_base,
    snap TOD, [unblank], rts."""
    code = bytearray()

    # The sibling's lookup tables are generated at runtime (src/crypto/
    # x25519_tables.s); src/tls_ecdh.s runs this before every scalar mult,
    # so do the same, outside the timed window.
    init = labels["x25519_tables_init"]
    code += bytes([0x20, init & 0xFF, init >> 8])  # JSR x25519_tables_init

    # Zero and start CIA1's time-of-day clock. NOT the jiffy clock: the
    # libs/x25519 sibling masks IRQs for the whole scalar mult (sei in
    # x25519_scalarmult), so the KERNAL jiffy counter stands still across
    # exactly the interval being timed. TOD counts in hardware regardless.
    # Writing hours stops TOD; writing tenths restarts it.
    code += bytes([0xA9, 0x00])                 # LDA #$00
    for reg in (0xDC0B, 0xDC0A, 0xDC09, 0xDC08):  # hours, min, sec, tenths
        code += bytes([0x8D, reg & 0xFF, reg >> 8])

    # Blank VIC-II (disable DEN bit 4 of $D011). Worth ~6.3%, NOT the
    # "~20-25%" this comment used to claim -- see the measurement in
    # CLAUDE.md's "VIC-II blanking" section. Run this script with and
    # without --no-blank to reproduce.
    if blank:
        code += bytes([0xAD, 0x11, 0xD0])       # LDA $D011
        code += bytes([0x29, 0xEF])              # AND #$EF
        code += bytes([0x8D, 0x11, 0xD0])        # STA $D011

    # JSR x25519_base
    addr = labels["x25519_base"]
    code += bytes([0x20, addr & 0xFF, addr >> 8])

    # Snapshot TOD (reading hours latches, reading tenths unlatches).
    bt = BENCH_TICKS_ADDR
    for i, reg in enumerate((0xDC0B, 0xDC0A, 0xDC09, 0xDC08)):
        code += bytes([0xAD, reg & 0xFF, reg >> 8])            # LDA reg
        code += bytes([0x8D, (bt + i) & 0xFF, (bt + i) >> 8])  # STA bt+i

    # Unblank VIC-II
    if blank:
        code += bytes([0xAD, 0x11, 0xD0])       # LDA $D011
        code += bytes([0x09, 0x10])              # ORA #$10
        code += bytes([0x8D, 0x11, 0xD0])        # STA $D011

    code += bytes([0x60])  # RTS
    return bytes(code)


def bcd(v):
    return (v >> 4) * 10 + (v & 0x0F)


def tod_seconds(raw):
    """Elapsed seconds from a TOD snapshot taken after zeroing (hh mm ss t)."""
    hours, mins, secs, tenths = raw
    if bcd(hours & 0x1F) not in (0, 12):
        print(f"  WARNING: TOD hours moved ({hours:#04x}); run exceeded an hour")
    return bcd(mins) * 60 + bcd(secs) + bcd(tenths) / 10.0


def main():
    os.chdir(PROJECT_ROOT)

    verify = True
    blank = True
    for arg in sys.argv[1:]:
        if arg == "--no-verify":
            verify = False
        elif arg == "--no-blank":
            blank = False

    # Build
    print("Building...")
    result = subprocess.run(["make"], capture_output=True, text=True,
                            cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)

    for name in ["x25519_base", "x25_scalar", "x25_result"]:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)

    trampoline = build_trampoline(labels, blank=blank)

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    print(f"Trampoline: {len(trampoline)} bytes at ${TRAMPOLINE_ADDR:04X}")
    print(f"VIC-II blanking: {'ON' if blank else 'OFF'}")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        grid = wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False)
        if grid is None:
            print("FATAL: Boot menu did not appear")
            sys.exit(1)

        # Safety loop at $0339
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Compute expected result
        expected = compute_expected_pubkey(BENCH_SCALAR)

        # Write scalar and trampoline
        write_bytes(transport, labels["x25_scalar"], BENCH_SCALAR)
        write_bytes(transport, TRAMPOLINE_ADDR, trampoline)

        print(f"\n{'='*60}")
        print(f"  X25519 key generation: scalar * basepoint(9)")
        print(f"  Scalar: {BENCH_SCALAR[:16].hex()}...")
        print(f"{'='*60}")
        print(f"\n  Running... (expect ~2-5 min wall clock in warp mode)")

        wall_start = time.time()
        jsr(transport, TRAMPOLINE_ADDR, timeout=7200.0)
        wall_elapsed = time.time() - wall_start

        c64_secs = tod_seconds(read_bytes(transport, BENCH_TICKS_ADDR, 4))

        # Read result
        result_bytes = read_bytes(transport, labels["x25_result"], 32)

        est_cycles = c64_secs * NTSC_CYCLES_PER_SEC

        print(f"\n--- Results ---")
        print(f"  C64 time (TOD): {c64_secs:.1f}s")
        print(f"  Wall clock:    {wall_elapsed:.1f}s ({wall_elapsed/60:.1f} min)")
        if wall_elapsed > 0:
            print(f"  Warp factor:   {c64_secs/wall_elapsed:.1f}x")
        print(f"  Est. cycles:   {est_cycles:,.0f}")
        print(f"  C64 real-time: {c64_secs:.0f}s ({c64_secs/60:.1f} min)")

        if verify:
            if expected is None:
                print(f"  Correctness:   SKIPPED (pip install cryptography)")
                print(f"    result:   {result_bytes.hex()}")
            elif result_bytes == expected:
                print(f"  Correctness:   PASS (matches Python X25519)")
            else:
                print(f"  Correctness:   FAIL")
                print(f"    expected: {expected.hex()}")
                print(f"    got:      {result_bytes.hex()}")

        mgr.release(inst)

    print("\nDone.")


if __name__ == "__main__":
    main()
