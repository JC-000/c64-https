#!/usr/bin/env python3
"""bench_x25519.py -- X25519 key generation benchmark on C64.

Runs x25519_base (scalar * basepoint 9) on the C64 and measures
wall-clock and jiffy-clock time. Verifies result against RFC 7748.

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
BENCH_TICKS_ADDR = 0x0350  # 3 bytes for jiffy clock snapshot

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
    """Build 6502 trampoline: zero jiffy, [blank VIC], jsr x25519_base,
    snap jiffy, [unblank], rts."""
    code = bytearray()

    # SEI; zero jiffy clock ($A0-$A2, big-endian)
    code += bytes([0x78])                       # SEI
    code += bytes([0xA9, 0x00])                 # LDA #$00
    code += bytes([0x85, 0xA0])                 # STA $A0
    code += bytes([0x85, 0xA1])                 # STA $A1
    code += bytes([0x85, 0xA2])                 # STA $A2
    code += bytes([0x58])                       # CLI

    # Blank VIC-II (disable DEN bit 4 of $D011) for ~20-25% speedup
    if blank:
        code += bytes([0xAD, 0x11, 0xD0])       # LDA $D011
        code += bytes([0x29, 0xEF])              # AND #$EF
        code += bytes([0x8D, 0x11, 0xD0])        # STA $D011

    # JSR x25519_base
    addr = labels["x25519_base"]
    code += bytes([0x20, addr & 0xFF, addr >> 8])

    # SEI; snapshot jiffy clock to BENCH_TICKS_ADDR
    bt = BENCH_TICKS_ADDR
    code += bytes([0x78])                                   # SEI
    code += bytes([0xA5, 0xA0])                             # LDA $A0
    code += bytes([0x8D, bt & 0xFF, bt >> 8])               # STA bench_ticks+0
    code += bytes([0xA5, 0xA1])                             # LDA $A1
    code += bytes([0x8D, (bt+1) & 0xFF, (bt+1) >> 8])      # STA bench_ticks+1
    code += bytes([0xA5, 0xA2])                             # LDA $A2
    code += bytes([0x8D, (bt+2) & 0xFF, (bt+2) >> 8])      # STA bench_ticks+2
    code += bytes([0x58])                                   # CLI

    # Unblank VIC-II
    if blank:
        code += bytes([0xAD, 0x11, 0xD0])       # LDA $D011
        code += bytes([0x09, 0x10])              # ORA #$10
        code += bytes([0x8D, 0x11, 0xD0])        # STA $D011

    code += bytes([0x60])  # RTS
    return bytes(code)


def jiffies_to_str(ticks):
    secs = ticks / NTSC_HZ
    if secs < 60:
        return f"{ticks} jiffies ({secs:.1f}s)"
    mins = secs / 60
    return f"{ticks} jiffies ({mins:.1f} min / {secs:.0f}s)"


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

        # Read jiffy ticks (3 bytes, big-endian)
        ticks_data = read_bytes(transport, BENCH_TICKS_ADDR, 3)
        ticks = (ticks_data[0] << 16) | (ticks_data[1] << 8) | ticks_data[2]

        # Read result
        result_bytes = read_bytes(transport, labels["x25_result"], 32)

        c64_secs = ticks / NTSC_HZ
        est_cycles = c64_secs * NTSC_CYCLES_PER_SEC

        print(f"\n--- Results ---")
        print(f"  Jiffy clock:   {jiffies_to_str(ticks)}")
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
