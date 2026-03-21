#!/usr/bin/env python3
"""test_hkdf.py - HKDF-SHA256 Test Suite for c64-https.

Tests the C64 HKDF implementation (Extract, Expand, Expand-Label) by calling
routines directly via jsr() -- writing parameters and reading results through
memory, bypassing the menu UI entirely.

Covers RFC 5869 test vectors, TLS 1.3 key schedule derivations, and
randomised tests for Extract and Expand-Label.

Usage:
    python3 tools/test_hkdf.py [--seed S] [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import hashlib
import hmac
import os
import random
import struct
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

REQUIRED_LABELS = [
    "hkdf_extract", "hkdf_expand", "hkdf_expand_label",
    "hkdf_prk", "hkdf_okm",
    "hkdf_salt_ptr", "hkdf_salt_len",
    "hkdf_ikm_ptr", "hkdf_ikm_len",
    "hkdf_info_buf", "hkdf_info_len",
    "hkdf_label_ptr", "hkdf_label_len",
    "hkdf_context_ptr", "hkdf_context_len",
    "hkdf_out_len",
    "input_buffer",
]


# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def hkdf_extract_ref(salt, ikm):
    """HKDF-Extract (RFC 5869). Empty salt becomes 32 zero bytes."""
    if not salt:
        salt = b'\x00' * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_ref(prk, info, length):
    """HKDF-Expand (RFC 5869). Only supports L <= 32 (single iteration)."""
    assert length <= 32
    t1 = hmac.new(prk, info + b'\x01', hashlib.sha256).digest()
    return t1[:length]


def hkdf_expand_label_ref(secret, label, context, length):
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)."""
    hkdf_label = struct.pack(">H", length)
    hkdf_label += bytes([6 + len(label)]) + b"tls13 " + label
    hkdf_label += bytes([len(context)]) + context
    return hkdf_expand_ref(secret, hkdf_label, length)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def robust_jsr(transport, addr, timeout=60.0, retries=3):
    """jsr() wrapper with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.3)
                continue
            raise


def c64_hkdf_extract(transport, labels, salt, ikm):
    """Call hkdf_extract on C64, return 32-byte PRK."""
    salt_addr = labels["input_buffer"]
    if salt:
        write_bytes(transport, salt_addr, salt)
    write_bytes(transport, labels["hkdf_salt_ptr"],
                [salt_addr & 0xFF, salt_addr >> 8])
    write_bytes(transport, labels["hkdf_salt_len"], [len(salt)])

    ikm_addr = salt_addr + len(salt)
    write_bytes(transport, ikm_addr, ikm)
    write_bytes(transport, labels["hkdf_ikm_ptr"],
                [ikm_addr & 0xFF, ikm_addr >> 8])
    write_bytes(transport, labels["hkdf_ikm_len"], [len(ikm)])

    robust_jsr(transport, labels["hkdf_extract"], timeout=60.0)
    return bytes(read_bytes(transport, labels["hkdf_prk"], 32))


def c64_hkdf_expand(transport, labels, prk, info, length):
    """Call hkdf_expand on C64, return OKM of given length."""
    write_bytes(transport, labels["hkdf_prk"], prk)
    if info:
        write_bytes(transport, labels["hkdf_info_buf"], info)
    write_bytes(transport, labels["hkdf_info_len"], [len(info)])
    write_bytes(transport, labels["hkdf_out_len"], [length])

    robust_jsr(transport, labels["hkdf_expand"], timeout=60.0)
    return bytes(read_bytes(transport, labels["hkdf_okm"], length))


def c64_hkdf_expand_label(transport, labels, secret, label, context, length):
    """Call hkdf_expand_label on C64, return OKM of given length."""
    write_bytes(transport, labels["hkdf_prk"], secret)

    label_addr = labels["input_buffer"]
    write_bytes(transport, label_addr, label)
    write_bytes(transport, labels["hkdf_label_ptr"],
                [label_addr & 0xFF, label_addr >> 8])
    write_bytes(transport, labels["hkdf_label_len"], [len(label)])

    ctx_addr = label_addr + len(label)
    if context:
        write_bytes(transport, ctx_addr, context)
    write_bytes(transport, labels["hkdf_context_ptr"],
                [ctx_addr & 0xFF, ctx_addr >> 8])
    write_bytes(transport, labels["hkdf_context_len"], [len(context)])

    write_bytes(transport, labels["hkdf_out_len"], [length])

    robust_jsr(transport, labels["hkdf_expand_label"], timeout=60.0)
    return bytes(read_bytes(transport, labels["hkdf_okm"], length))


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_extract_rfc5869_case1(transport, labels):
    """HKDF-Extract: RFC 5869 Test Case 1."""
    print("\n--- Extract: RFC 5869 Test Case 1 ---")

    ikm = bytes([0x0b] * 22)
    salt = bytes(range(0x00, 0x0d))  # 13 bytes: 0x00..0x0c
    expected = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )

    try:
        result = c64_hkdf_extract(transport, labels, salt, ikm)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: PRK matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: PRK mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


def test_extract_rfc5869_case3(transport, labels):
    """HKDF-Extract: RFC 5869 Test Case 3 (empty salt)."""
    print("\n--- Extract: RFC 5869 Test Case 3 (empty salt) ---")

    ikm = bytes([0x0b] * 22)
    salt = b""
    expected = bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf"
        "96596776afdb6377ac434c1c293ccb04"
    )

    try:
        result = c64_hkdf_extract(transport, labels, salt, ikm)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: PRK matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: PRK mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


def test_expand_rfc5869_case1(transport, labels):
    """HKDF-Expand: RFC 5869 Test Case 1 (L=32, truncated from 42)."""
    print("\n--- Expand: RFC 5869 Test Case 1 (L=32) ---")

    prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    info = bytes(range(0xf0, 0xfa))  # 10 bytes
    expected_okm_42 = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    expected = expected_okm_42[:32]

    try:
        result = c64_hkdf_expand(transport, labels, prk, info, 32)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: OKM matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: OKM mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


def test_expand_rfc5869_case3(transport, labels):
    """HKDF-Expand: RFC 5869 Test Case 3 (empty info, L=32)."""
    print("\n--- Expand: RFC 5869 Test Case 3 (empty info, L=32) ---")

    prk = bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf"
        "96596776afdb6377ac434c1c293ccb04"
    )
    info = b""
    expected_okm_42 = bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )
    expected = expected_okm_42[:32]

    try:
        result = c64_hkdf_expand(transport, labels, prk, info, 32)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: OKM matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: OKM mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


def test_tls13_early_secret(transport, labels):
    """TLS 1.3 Early Secret: HKDF-Extract(salt=0x00*32, IKM=0x00*32)."""
    print("\n--- TLS 1.3 Early Secret ---")

    salt = b'\x00' * 32
    ikm = b'\x00' * 32
    expected = hmac.new(salt, ikm, hashlib.sha256).digest()

    try:
        result = c64_hkdf_extract(transport, labels, salt, ikm)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: early_secret matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: early_secret mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


def test_expand_label_derived(transport, labels):
    """HKDF-Expand-Label with TLS 1.3 'derived' label.

    Derive-Secret(early_secret, "derived", "") =
    HKDF-Expand-Label(early_secret, "derived", SHA-256(""), 32)
    """
    print('\n--- Expand-Label: TLS 1.3 "derived" ---')

    # Compute early_secret via Python reference
    early_secret = hkdf_extract_ref(b'\x00' * 32, b'\x00' * 32)
    empty_hash = hashlib.sha256(b"").digest()
    label = b"derived"
    context = empty_hash
    expected = hkdf_expand_label_ref(early_secret, label, context, 32)

    try:
        result = c64_hkdf_expand_label(transport, labels, early_secret,
                                       label, context, 32)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: OKM matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: OKM mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


def test_random_extract(transport, labels, iteration, verbose=False):
    """Random HKDF-Extract: random salt (0-32 bytes) and IKM (1-64 bytes)."""
    salt_len = random.randint(0, 32)
    ikm_len = random.randint(1, 64)
    salt = bytes(random.getrandbits(8) for _ in range(salt_len))
    ikm = bytes(random.getrandbits(8) for _ in range(ikm_len))
    label = f"Random Extract {iteration} (salt={salt_len}B, ikm={ikm_len}B)"
    print(f"\n--- {label} ---")

    expected = hkdf_extract_ref(salt, ikm)

    try:
        result = c64_hkdf_extract(transport, labels, salt, ikm)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: PRK matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: PRK mismatch")
        print(f"    Salt:     {salt.hex() if salt else '(empty)'}")
        print(f"    IKM:      {ikm.hex()}")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


def test_random_expand_label(transport, labels, iteration, verbose=False):
    """Random HKDF-Expand-Label: random secret, label, context."""
    secret = bytes(random.getrandbits(8) for _ in range(32))
    label_len = random.randint(3, 12)
    ctx_len = random.randint(0, 32)
    # Use printable ASCII for label
    label_bytes = bytes(random.choice(range(0x61, 0x7b)) for _ in range(label_len))
    context = bytes(random.getrandbits(8) for _ in range(ctx_len))
    desc = f"Random Expand-Label {iteration} (label={label_len}B, ctx={ctx_len}B)"
    print(f"\n--- {desc} ---")

    expected = hkdf_expand_label_ref(secret, label_bytes, context, 32)

    try:
        result = c64_hkdf_expand_label(transport, labels, secret,
                                       label_bytes, context, 32)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if result == expected:
        print(f"  PASS: OKM matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: OKM mismatch")
        print(f"    Secret:   {secret.hex()}")
        print(f"    Label:    {label_bytes.decode('ascii')}")
        print(f"    Context:  {context.hex() if context else '(empty)'}")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {result.hex()}")
        return False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels, verbose=False):
    """Run all HKDF tests. Returns (passed, failed)."""
    passed = 0
    failed = 0

    def tally(ok):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1

    # 1. RFC 5869 Extract tests
    tally(test_extract_rfc5869_case1(transport, labels))
    tally(test_extract_rfc5869_case3(transport, labels))

    # 2. RFC 5869 Expand tests
    tally(test_expand_rfc5869_case1(transport, labels))
    tally(test_expand_rfc5869_case3(transport, labels))

    # 3. TLS 1.3 Early Secret
    tally(test_tls13_early_secret(transport, labels))

    # 4. TLS 1.3 Expand-Label with "derived"
    tally(test_expand_label_derived(transport, labels))

    # 5. Random Extract tests (3 iterations)
    for i in range(1, 4):
        tally(test_random_extract(transport, labels, i, verbose))

    # 6. Random Expand-Label tests (3 iterations)
    for i in range(1, 4):
        tally(test_random_expand_label(transport, labels, i, verbose))

    return passed, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    # Parse args
    seed = random.randint(0, 2**32 - 1)
    verbose = False
    if "--seed" in sys.argv:
        idx = sys.argv.index("--seed")
        if idx + 1 < len(sys.argv):
            seed = int(sys.argv[idx + 1])
    if "--verbose" in sys.argv:
        verbose = True
    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build
    print("\n=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)
    print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    for name in REQUIRED_LABELS:
        if labels.address(name) is None:
            print(f"FATAL: required label '{name}' not found")
            sys.exit(1)
    print(f"  Labels loaded, hkdf_prk at ${labels['hkdf_prk']:04X}")

    # Start VICE
    print("\n=== Starting VICE ===")
    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

    with ViceInstanceManager(config=config, port_range_start=6510, port_range_end=6530, max_retries=3) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        # Wait for main menu
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        # Safety loop to prevent runaway execution
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Run tests
        print("\n=== HKDF-SHA256 Tests (12 total) ===")
        passed, failed = run_tests(transport, labels, verbose)

        mgr.release(inst)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] HKDF-SHA256: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] HKDF-SHA256: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
