#!/usr/bin/env python3
"""test_sha256.py - Direct-Memory SHA-256 Test Suite for c64-https.

Tests the C64 SHA-256 implementation by calling sha256_init, sha256_update,
and sha256_final directly via jsr() -- writing input data and reading hash
output through memory, bypassing the menu UI entirely.

Usage:
    python3 tools/test_sha256.py [--iterations N] [--seed S] [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import hashlib
import os
import random
import struct
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

MAX_INPUT_LEN = 63
DEFAULT_ITERATIONS = 10

SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# SHA-256 initial hash values (FIPS 180-4, Section 5.3.3)
SHA256_IV = bytes.fromhex(
    "6a09e667" "bb67ae85" "3c6ef372" "a54ff53a"
    "510e527f" "9b05688c" "1f83d9ab" "5be0cd19"
)

# NIST "abc" test vector (SHA-256 of 0x61 0x62 0x63)
NIST_ABC_HASH = bytes.fromhex(
    "ba7816bf" "8f01cfea" "414140de" "5dae2223"
    "b00361a3" "96177a9c" "b410ff61" "f20015ad"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_string(min_len, max_len):
    """Generate a random string of safe characters with random length."""
    length = random.randint(min_len, max_len)
    return "".join(random.choice(SAFE_CHARS) for _ in range(length))


def sha256_direct(transport, labels, message):
    """Hash message via direct memory writes + jsr() calls.

    Returns the 32-byte SHA-256 digest.
    """
    write_bytes(transport, labels["input_buffer"], message)
    write_bytes(transport, labels["input_length"], bytes([len(message)]))
    jsr(transport, labels["sha256_init"], timeout=5.0)
    jsr(transport, labels["sha256_update"], timeout=10.0)
    jsr(transport, labels["sha256_final"], timeout=5.0)
    return read_bytes(transport, labels["sha256_hash"], 32)


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_sha256_init(transport, labels):
    """Verify sha256_init loads the standard IV into H0-H7."""
    print("\n--- Init Verification ---")

    try:
        jsr(transport, labels["sha256_init"], timeout=5.0)
    except Exception as e:
        print(f"  FAIL: jsr(sha256_init) raised {e}")
        return False

    h_state = read_bytes(transport, labels["sha256_h0"], 32)

    if h_state == SHA256_IV:
        print("  PASS: H0-H7 match standard IV")
        return True
    else:
        print(f"  FAIL: H0-H7 mismatch")
        print(f"    Expected: {SHA256_IV.hex()}")
        print(f"    Got:      {h_state.hex()}")
        return False


def test_sha256_process_block(transport, labels):
    """Test sha256_process_block in isolation with NIST "abc" vector.

    Manually prepares a padded 64-byte block for the 3-byte message "abc",
    writes it to sha256_block, calls sha256_init + sha256_process_block +
    sha256_final, and verifies against the known NIST hash.
    """
    print('\n--- Process Block: NIST "abc" ---')

    # Build the padded block for "abc" (3 bytes):
    # "abc" + 0x80 + 57 zero bytes + 8-byte big-endian bit length (24 = 0x18)
    msg = b"abc"
    block = bytearray(64)
    block[0:3] = msg
    block[3] = 0x80
    # Bit length = 3 * 8 = 24, stored as big-endian 64-bit at offset 56
    struct.pack_into(">Q", block, 56, len(msg) * 8)

    try:
        # Write padded block before init (sha256_init doesn't touch the block)
        write_bytes(transport, labels["sha256_block"], bytes(block))

        # Initialize hash state
        jsr(transport, labels["sha256_init"], timeout=5.0)

        # Call process_block directly
        jsr(transport, labels["sha256_process_block"], timeout=10.0)

        # Finalize (copy H0-H7 to sha256_hash)
        jsr(transport, labels["sha256_final"], timeout=5.0)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    c64_hash = read_bytes(transport, labels["sha256_hash"], 32)

    if c64_hash == NIST_ABC_HASH:
        print(f"  PASS: hash matches {NIST_ABC_HASH[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: hash mismatch")
        print(f"    Expected: {NIST_ABC_HASH.hex()}")
        print(f"    Got:      {c64_hash.hex()}")
        return False


def test_sha256_empty(transport, labels):
    """Test SHA-256 of empty input (0 bytes)."""
    print("\n--- Empty input (0 bytes) ---")

    expected = hashlib.sha256(b"").digest()

    try:
        write_bytes(transport, labels["input_length"], bytes([0]))
        jsr(transport, labels["sha256_init"], timeout=5.0)
        jsr(transport, labels["sha256_update"], timeout=10.0)
        jsr(transport, labels["sha256_final"], timeout=5.0)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    c64_hash = read_bytes(transport, labels["sha256_hash"], 32)

    if c64_hash == expected:
        print(f"  PASS: hash matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: hash mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {c64_hash.hex()}")
        return False


def test_sha256_pipeline(transport, labels, message, label):
    """Test full sha256_init/update/final pipeline for a given message.

    Returns True on pass, False on fail.
    """
    input_bytes = message.encode("ascii")
    input_len = len(input_bytes)
    block_type = "single-block" if input_len <= 55 else "two-block"
    print(f"\n--- {label}: {input_len} bytes ({block_type}) ---")

    expected = hashlib.sha256(input_bytes).digest()

    try:
        c64_hash = sha256_direct(transport, labels, input_bytes)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if c64_hash == expected:
        print("  PASS")
        return True
    else:
        print(f"  FAIL: hash mismatch")
        print(f"    Input:    \"{message}\"")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {c64_hash.hex()}")
        return False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels, iterations, verbose=False):
    """Run all SHA-256 direct tests. Returns (passed, failed)."""
    passed = 0
    failed = 0

    # 1. Init verification
    if test_sha256_init(transport, labels):
        passed += 1
    else:
        failed += 1

    # 2. NIST "abc" process_block isolation
    if test_sha256_process_block(transport, labels):
        passed += 1
    else:
        failed += 1

    # 3. Empty input
    if test_sha256_empty(transport, labels):
        passed += 1
    else:
        failed += 1

    # 4. Boundary cases
    boundary_cases = [
        (generate_random_string(1, 1), "Boundary: 1 byte"),
        (generate_random_string(55, 55), "Boundary: 55 bytes"),
        (generate_random_string(56, 56), "Boundary: 56 bytes"),
        (generate_random_string(63, 63), "Boundary: 63 bytes"),
    ]

    for message, label in boundary_cases:
        if test_sha256_pipeline(transport, labels, message, label):
            passed += 1
        else:
            failed += 1

    # 5. Random pipeline tests -- fill remaining iterations
    fixed_count = 3 + len(boundary_cases)  # init + process_block + empty + boundaries
    random_count = max(0, iterations - fixed_count)

    for i in range(random_count):
        message = generate_random_string(1, MAX_INPUT_LEN)
        label = f"Random test {i + 1}/{random_count}"
        if test_sha256_pipeline(transport, labels, message, label):
            passed += 1
        else:
            failed += 1

    return passed, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    # Parse args
    iterations = DEFAULT_ITERATIONS
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        if idx + 1 < len(sys.argv):
            iterations = int(sys.argv[idx + 1])

    seed = random.randint(0, 2**32 - 1)
    if "--seed" in sys.argv:
        idx = sys.argv.index("--seed")
        if idx + 1 < len(sys.argv):
            seed = int(sys.argv[idx + 1])
    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    verbose = "--verbose" in sys.argv

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
    required_labels = [
        "sha256_hash", "sha256_init", "sha256_update", "sha256_final",
        "sha256_h0", "sha256_block", "sha256_process_block",
        "input_buffer", "input_length",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)
    print(f"  Labels loaded, sha256_hash at ${labels['sha256_hash']:04X}")

    # Start VICE
    print("\n=== Starting VICE ===")
    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

    with ViceInstanceManager(config=config) as mgr:
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

        # Run tests
        print(f"\n=== SHA-256 Direct Tests ({iterations} iterations) ===")

        passed, failed = run_tests(transport, labels, iterations, verbose)

        mgr.release(inst)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] SHA-256 Direct: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] SHA-256 Direct: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
