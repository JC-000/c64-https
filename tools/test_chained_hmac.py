#!/usr/bin/env python3
"""test_chained_hmac.py - Minimal reproduction test for VICE stability
under chained HMAC-SHA256 calls.

Determines whether VICE crashes on long computations or if failures are
caused by monitor port contention. Builds a trampoline that chains N
calls to hmac_sha256 (N=1..10), each in a fresh VICE instance.

Usage:
    python3 tools/test_chained_hmac.py
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    ScreenGrid,
    read_bytes,
    write_bytes,
    set_breakpoint,
    delete_breakpoint,
    goto,
    wait_for_pc,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

SCRATCH_ADDR = 0x0334  # Cassette buffer, safe scratch area


def build_trampoline(hmac_addr, n):
    """Build trampoline bytes: N x JSR hmac_sha256 + NOP NOP.

    Returns (trampoline_bytes, breakpoint_offset).
    """
    lo = hmac_addr & 0xFF
    hi = (hmac_addr >> 8) & 0xFF
    code = bytearray()
    for _ in range(n):
        code.extend([0x20, lo, hi])  # JSR hmac_sha256
    code.extend([0xEA, 0xEA])        # NOP NOP
    bp_offset = n * 3                # offset of first NOP
    return bytes(code), bp_offset


def main():
    os.chdir(PROJECT_ROOT)

    # Build
    print("=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    result = subprocess.run(["make"], capture_output=True, text=True,
                            cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)
    print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required = ["hmac_sha256", "hmac_key", "hmac_data_buf", "hmac_data_len"]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: required label '{name}' not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"  Labels OK: hmac_sha256=${labels['hmac_sha256']:04X}")

    # Run chained tests
    print("\n=== Chained HMAC-SHA256 Stability Test ===")
    results = []

    for n in range(1, 11):
        config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
        with ViceInstanceManager(config=config) as mgr:
            inst = mgr.acquire()
            transport = inst.transport
            print(f"  N={n}: VICE PID={inst.pid}, port={inst.port}")

            # Wait for program menu (binary monitor: resume CPU between polls)
            grid = None
            deadline = time.time() + 60
            while time.time() < deadline:
                g = ScreenGrid.from_transport(transport)
                if "Q=QUIT" in g.continuous_text().upper():
                    grid = g
                    break
                transport.resume()
                time.sleep(1.0)
            if grid is None:
                print(f"  N={n}: FAIL - main menu did not appear")
                results.append((n, False, 0.0, True))
                mgr.release(inst)
                continue
            hmac_addr = labels["hmac_sha256"]

            # Set up HMAC inputs: 32-byte key, 32-byte data, data_len=32
            key_data = bytes(range(0x01, 0x21))   # 1..32
            msg_data = bytes(range(0x41, 0x61))   # 'A'..'`' (32 bytes)

            write_bytes(transport, labels["hmac_key"], key_data)
            write_bytes(transport, labels["hmac_data_buf"], msg_data)
            write_bytes(transport, labels["hmac_data_len"], [32])

            # Build and write trampoline
            trampoline, bp_offset = build_trampoline(hmac_addr, n)
            write_bytes(transport, SCRATCH_ADDR, trampoline)

            bp_addr = SCRATCH_ADDR + bp_offset
            bp_id = set_breakpoint(transport, bp_addr)

            timeout = n * 5 + 10
            t0 = time.time()
            try:
                goto(transport, SCRATCH_ADDR)
                wait_for_pc(transport, bp_addr, timeout=timeout)
                elapsed = time.time() - t0
                delete_breakpoint(transport, bp_id)
                results.append((n, True, elapsed, True))
            except Exception as e:
                elapsed = time.time() - t0
                print(f"  N={n}: exception after {elapsed:.1f}s: {e}")
                try:
                    delete_breakpoint(transport, bp_id)
                except Exception:
                    pass
                results.append((n, False, elapsed, True))

            mgr.release(inst)

        # Brief stagger before next VICE launch
        time.sleep(0.1)

    # Summary
    print("\n" + "=" * 60)
    print("RESULTS: Chained HMAC-SHA256 (N calls per trampoline)")
    print("=" * 60)
    all_ok = True
    for n, ok, elapsed, alive in results:
        if ok:
            print(f"  N={n:2d}: OK ({elapsed:.1f}s)")
        else:
            all_ok = False
            status = "VICE alive" if alive else "VICE dead"
            print(f"  N={n:2d}: FAIL ({elapsed:.1f}s, {status})")
    print("=" * 60)

    if all_ok:
        print("\nConclusion: All N=1..10 succeeded -- no VICE crash on long computation.")
        print("Failures were likely port contention, not VICE instability.")
    else:
        failed_ns = [n for n, ok, _, _ in results if not ok]
        dead_ns = [n for n, ok, _, alive in results if not ok and not alive]
        if dead_ns:
            print(f"\nConclusion: VICE died at N={dead_ns} -- genuine crash on long computation.")
        else:
            print(f"\nConclusion: Failures at N={failed_ns} but VICE stayed alive -- port contention.")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
