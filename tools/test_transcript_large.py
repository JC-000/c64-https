#!/usr/bin/env python3
"""test_transcript_large.py - large-buffer SHA-256 transcript test.

Covers the 16-bit length rewrite of tls_transcript_update. Previously the
routine used an 8-bit zp_count, so any single call with >=256 bytes was
silently truncated (the classic symptom: 352 B TLS 1.3 Certificate was
only hashed for its first 96 B, wrapping Y at 64 within the block buffer).

This test calls tls_transcript_update with:
  - a single 352-byte chunk,
  - the same 352 bytes split across three sub-calls (100 + 100 + 152),
and compares the resulting transcript against hashlib.sha256 over the
same bytes.  Both must match the Python reference.

Usage:
    python3 tools/test_transcript_large.py [--seed S]
"""

import hashlib
import os
import random
import subprocess
import sys

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

ZP_PTR = 0xFB        # zp_ptr ($FB-$FC)
ZP_COUNT = 0xFE      # zp_count ($FE-$FF) — 16-bit LE


def feed_chunk(transport, scratch_addr, update_addr, data):
    """Write data to scratch, set zp_ptr + zp_count (16-bit), call update."""
    write_bytes(transport, scratch_addr, data)
    write_bytes(transport, ZP_PTR,
                [scratch_addr & 0xFF, (scratch_addr >> 8) & 0xFF])
    write_bytes(transport, ZP_COUNT,
                [len(data) & 0xFF, (len(data) >> 8) & 0xFF])
    jsr(transport, update_addr, timeout=180.0)


def get_hash(transport, hash_addr, transcript_addr):
    jsr(transport, hash_addr, timeout=180.0)
    return read_bytes(transport, transcript_addr, 32)


def run(transport, labels, rng):
    for name in ("tls_transcript_init", "tls_transcript_update",
                 "tls_transcript_hash", "tls_transcript", "tls_rec_buf"):
        if labels.address(name) is None:
            print(f"FATAL: required label '{name}' not found")
            return 0, 1

    init_addr = labels["tls_transcript_init"]
    update_addr = labels["tls_transcript_update"]
    hash_addr = labels["tls_transcript_hash"]
    transcript_addr = labels["tls_transcript"]
    # tls_rec_buf is a 548 B buffer in data.s — plenty for 352 B payload.
    scratch_addr = labels["tls_rec_buf"]

    # Deterministic 352 B payload (shape-compatible with a TLS 1.3
    # Certificate handshake message, but contents are random since we
    # only care about SHA-256 correctness).
    data = bytes(rng.getrandbits(8) for _ in range(352))
    expected = hashlib.sha256(data).digest()

    passed = 0
    failed = 0

    # --- Test A: single 352-byte call ---
    print("\n  [A] 352 B in one update call")
    try:
        jsr(transport, init_addr, timeout=60.0)
        feed_chunk(transport, scratch_addr, update_addr, data)
        result = get_hash(transport, hash_addr, transcript_addr)
        if result == expected:
            passed += 1
            print(f"      PASS: {result[:8].hex()}...")
        else:
            failed += 1
            print(f"      FAIL: expected {expected[:8].hex()}...")
            print(f"            got      {result[:8].hex()}...")
            print(f"            (full expected: {expected.hex()})")
            print(f"            (full got:      {result.hex()})")
    except Exception as e:
        failed += 1
        print(f"      FAIL: {e}")

    # --- Test B: same 352 bytes, split 100 + 100 + 152 ---
    print("  [B] 352 B split across three calls (100 + 100 + 152)")
    try:
        jsr(transport, init_addr, timeout=60.0)
        feed_chunk(transport, scratch_addr, update_addr, data[:100])
        feed_chunk(transport, scratch_addr, update_addr, data[100:200])
        feed_chunk(transport, scratch_addr, update_addr, data[200:])
        result = get_hash(transport, hash_addr, transcript_addr)
        if result == expected:
            passed += 1
            print(f"      PASS: {result[:8].hex()}...")
        else:
            failed += 1
            print(f"      FAIL: expected {expected[:8].hex()}...")
            print(f"            got      {result[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"      FAIL: {e}")

    # --- Test C: 1000 B single call (well past 8-bit wrap) ---
    print("  [C] 1000 B in one update call (8-bit wrap regression)")
    big = bytes(rng.getrandbits(8) for _ in range(1000))
    # NOTE: 1000 B won't fit in tls_rec_buf (548 B). Feed in chunks of 500
    # for the scratch write, but test both single- and multi-call variants
    # where the per-call length itself exceeds 256.
    try:
        jsr(transport, init_addr, timeout=60.0)
        # single call of 500 B -> requires 16-bit counter to work at all
        feed_chunk(transport, scratch_addr, update_addr, big[:500])
        # another single call of 500 B
        feed_chunk(transport, scratch_addr, update_addr, big[500:])
        result = get_hash(transport, hash_addr, transcript_addr)
        expected_big = hashlib.sha256(big).digest()
        if result == expected_big:
            passed += 1
            print(f"      PASS: {result[:8].hex()}...")
        else:
            failed += 1
            print(f"      FAIL: expected {expected_big[:8].hex()}...")
            print(f"            got      {result[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"      FAIL: {e}")

    return passed, failed


def main():
    os.chdir(PROJECT_ROOT)

    seed = 1234
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        else:
            i += 1

    rng = random.Random(seed)
    print(f"Random seed: {seed}")

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building ===")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)
        print(f"  Build OK: {PRG_PATH}")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    print("\n=== Starting VICE ===")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        print("\n=== Transcript large-buffer tests ===")
        passed, failed = run(transport, labels, rng)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0 and total > 0:
        print(f"  [+] TRANSCRIPT LARGE: ALL {total} PASSED")
    else:
        print(f"  [-] TRANSCRIPT LARGE: {failed} TEST(S) FAILED")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
