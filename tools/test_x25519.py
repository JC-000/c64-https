#!/usr/bin/env python3
"""test_x25519.py -- fe25519 field arithmetic and X25519 key exchange tests.

Tests fe_add, fe_sub, fe_mul, fe_sqr, fe_inv, fe_cswap, fe_mul_a24,
fe_copy, fe_zero, fe_one, x25519_clamp, and (with --slow) x25519_scalarmult
against Python reference implementations and RFC 7748 test vectors.

Uses the binary monitor test harness -- jsr() is event-based via
checkpoints, so no polling or retry wrappers are needed.

Usage:
    python3 tools/test_x25519.py [--seed S] [--verbose] [--slow]
"""

import os
import random
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False
SLOW = False

# p = 2^255 - 19
P = (1 << 255) - 19


# ============================================================================
# Python reference implementations
# ============================================================================

def fe_add_ref(a, b):
    return (a + b) % P

def fe_sub_ref(a, b):
    return (a - b) % P

def fe_mul_ref(a, b):
    return (a * b) % P

def fe_sqr_ref(a):
    return (a * a) % P

def fe_inv_ref(a):
    return pow(a, P - 2, P)

def fe_mul_a24_ref(a):
    return (a * 121665) % P

def int_to_le32(val):
    """Convert integer to 32-byte little-endian bytes."""
    return (val % P).to_bytes(32, "little")

def le32_to_int(data):
    """Convert 32-byte little-endian bytes to integer."""
    return int.from_bytes(data, "little")

def rand_fe(rng):
    """Generate a random field element in [0, p-1]."""
    return rng.randint(0, P - 1)

def clamp_ref(scalar):
    """Clamp scalar per RFC 7748."""
    s = bytearray(scalar)
    s[0] &= 0xF8
    s[31] = (s[31] & 0x7F) | 0x40
    return bytes(s)


# RFC 7748 Section 6.1 test vectors
SCALAR_1 = bytes.fromhex(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
U_1 = bytes.fromhex(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
EXPECTED_1 = bytes.fromhex(
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

SCALAR_2 = bytes.fromhex(
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
U_2 = bytes.fromhex(
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
EXPECTED_2 = bytes.fromhex(
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")


# ============================================================================
# C64 helper functions
# ============================================================================

def set_fe_ptrs(transport, labels, src1=None, src2=None, dst=None):
    """Set fe_src1, fe_src2, fe_dst zero-page pointers."""
    if src1 is not None:
        write_bytes(transport, labels["fe_src1"],
                    bytes([src1 & 0xFF, src1 >> 8]))
    if src2 is not None:
        write_bytes(transport, labels["fe_src2"],
                    bytes([src2 & 0xFF, src2 >> 8]))
    if dst is not None:
        write_bytes(transport, labels["fe_dst"],
                    bytes([dst & 0xFF, dst >> 8]))


def write_fe(transport, addr, val):
    """Write a field element (integer) to C64 memory as 32-byte LE."""
    write_bytes(transport, addr, int_to_le32(val))


def read_fe(transport, addr):
    """Read a 32-byte LE field element from C64 memory, return as integer."""
    return le32_to_int(read_bytes(transport, addr, 32))


def c64_fe_add(transport, labels, a, b):
    """Compute a + b mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_add"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_sub(transport, labels, a, b):
    """Compute a - b mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_sub"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_mul(transport, labels, a, b):
    """Compute a * b mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_mul"], timeout=120.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_sqr(transport, labels, a):
    """Compute a^2 mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_sqr"], timeout=120.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_inv(transport, labels, a):
    """Compute a^(p-2) mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    # fe_inv takes ~253 squarings + 11 muls -- very slow
    jsr(transport, labels["fe_inv"], timeout=600.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_mul_a24(transport, labels, a):
    """Compute a * 121665 mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_mul_a24"], timeout=60.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_copy(transport, labels, a):
    """Copy a field element via fe_copy."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_copy"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_zero(transport, labels):
    """Zero a field element via fe_zero."""
    # Write nonzero first to prove it gets zeroed
    write_fe(transport, labels["fe_tmp3"], P - 1)
    set_fe_ptrs(transport, labels, dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_zero"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_one(transport, labels):
    """Set a field element to 1 via fe_one."""
    write_fe(transport, labels["fe_tmp3"], P - 1)
    set_fe_ptrs(transport, labels, dst=labels["fe_tmp3"])
    jsr(transport, labels["fe_one"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_x25519_clamp(transport, labels, scalar):
    """Clamp a scalar on C64. Returns clamped scalar bytes."""
    write_bytes(transport, labels["x25_scalar"], scalar)
    jsr(transport, labels["x25519_clamp"])
    return read_bytes(transport, labels["x25_scalar"], 32)


def c64_x25519_scalarmult(transport, labels, scalar, u):
    """Compute scalar * u on C64. Returns 32-byte result."""
    write_bytes(transport, labels["x25_scalar"], scalar)
    write_bytes(transport, labels["x25_u"], u)
    jsr(transport, labels["x25519_scalarmult"], timeout=7200.0)
    return read_bytes(transport, labels["x25_result"], 32)


# ============================================================================
# Test functions -- fe25519 field operations
# ============================================================================

def test_fe_copy_zero_one(transport, labels):
    """Test fe_copy, fe_zero, fe_one."""
    passed = failed = 0

    # fe_zero
    result = c64_fe_zero(transport, labels)
    if result == 0:
        passed += 1
        if VERBOSE:
            print("  PASS fe_zero")
    else:
        failed += 1
        print(f"  FAIL fe_zero: got {result}")

    # fe_one
    result = c64_fe_one(transport, labels)
    if result == 1:
        passed += 1
        if VERBOSE:
            print("  PASS fe_one")
    else:
        failed += 1
        print(f"  FAIL fe_one: got {result}")

    # fe_copy
    test_val = 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0
    result = c64_fe_copy(transport, labels, test_val)
    if result == test_val:
        passed += 1
        if VERBOSE:
            print("  PASS fe_copy")
    else:
        failed += 1
        print(f"  FAIL fe_copy: expected {test_val:#x}, got {result:#x}")

    return passed, failed


def test_fe_add(transport, labels, rng):
    """Test fe_add with boundary cases and random inputs."""
    passed = failed = 0

    cases = [
        ("0+0", 0, 0),
        ("0+1", 0, 1),
        ("1+1", 1, 1),
        ("p-1+1", P - 1, 1),
        ("p-1+p-1", P - 1, P - 1),
        ("large+large", P - 10, 15),
    ]
    for i in range(6):
        a, b = rand_fe(rng), rand_fe(rng)
        cases.append((f"random #{i}", a, b))

    for name, a, b in cases:
        expected = fe_add_ref(a, b)
        result = c64_fe_add(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS add {name}")
        else:
            failed += 1
            print(f"  FAIL add {name}: expected {expected}, got {result}")

    return passed, failed


def test_fe_sub(transport, labels, rng):
    """Test fe_sub with boundary cases and random inputs."""
    passed = failed = 0

    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("1-1", 1, 1),
        ("0-1", 0, 1),
        ("10-20", 10, 20),
        ("p-1-0", P - 1, 0),
    ]
    for i in range(6):
        a, b = rand_fe(rng), rand_fe(rng)
        cases.append((f"random #{i}", a, b))

    for name, a, b in cases:
        expected = fe_sub_ref(a, b)
        result = c64_fe_sub(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS sub {name}")
        else:
            failed += 1
            print(f"  FAIL sub {name}: expected {expected}, got {result}")

    return passed, failed


def test_fe_mul(transport, labels, rng):
    """Test fe_mul with identity, zero, and random inputs."""
    passed = failed = 0

    cases = [
        ("0*0", 0, 0),
        ("0*1", 0, 1),
        ("1*1", 1, 1),
        ("2*3", 2, 3),
        ("a*0", rand_fe(rng), 0),
        ("1*a", 1, rand_fe(rng)),
    ]
    for i in range(4):
        a, b = rand_fe(rng), rand_fe(rng)
        cases.append((f"random #{i}", a, b))

    for name, a, b in cases:
        expected = fe_mul_ref(a, b)
        result = c64_fe_mul(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mul {name}")
        else:
            failed += 1
            print(f"  FAIL mul {name}:")
            print(f"    a = {a}")
            print(f"    b = {b}")
            print(f"    expected = {expected}")
            print(f"    got      = {result}")

    return passed, failed


def test_fe_sqr(transport, labels, rng):
    """Test fe_sqr against Python reference."""
    passed = failed = 0

    cases = [0, 1, 2, P - 1, rand_fe(rng), rand_fe(rng), rand_fe(rng)]

    for i, a in enumerate(cases):
        expected = fe_sqr_ref(a)
        result = c64_fe_sqr(transport, labels, a)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS sqr #{i}")
        else:
            failed += 1
            print(f"  FAIL sqr #{i}: a={a}, expected={expected}, got={result}")

    return passed, failed


def test_fe_inv(transport, labels, rng):
    """Test fe_inv: inv(1)==1, inv(2)*2==1.

    Full fe_inv takes ~10 minutes per call in VICE. Test inv(1) which is
    fast, plus inv(2) as a second case (small value, verifiable).
    """
    passed = failed = 0

    cases = [1, 2]

    for i, a in enumerate(cases):
        print(f"    inv test #{i} (a={a:#x})...", end="", flush=True)
        inv_a = c64_fe_inv(transport, labels, a)
        expected = fe_inv_ref(a)

        if inv_a == expected:
            passed += 1
            print(" PASS" if VERBOSE else " ok")
        else:
            failed += 1
            print(" FAIL")
            print(f"    expected inv = {expected}")
            print(f"    got inv      = {inv_a}")
            product = (a * inv_a) % P
            print(f"    a * got_inv mod p = {product}")

    return passed, failed


def test_fe_cswap(transport, labels, rng):
    """Test fe_cswap constant-time swap with mask=$00 and mask=$FF."""
    passed = failed = 0

    a = rand_fe(rng)
    b = rand_fe(rng)

    cswap_addr = labels["fe_cswap"]
    trampoline = labels["input_buffer"]

    # No-swap test (mask = $00)
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"])
    write_bytes(transport, trampoline, bytes([
        0xA9, 0x00,                                        # LDA #$00
        0x4C, cswap_addr & 0xFF, cswap_addr >> 8,         # JMP fe_cswap
    ]))
    jsr(transport, trampoline)
    r_a = read_fe(transport, labels["fe_tmp1"])
    r_b = read_fe(transport, labels["fe_tmp2"])

    if r_a == a and r_b == b:
        passed += 1
        if VERBOSE:
            print("  PASS cswap no-swap")
    else:
        failed += 1
        print(f"  FAIL cswap no-swap: a changed={r_a != a}, b changed={r_b != b}")

    # Swap test (mask = $FF)
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"])
    write_bytes(transport, trampoline, bytes([
        0xA9, 0xFF,                                        # LDA #$FF
        0x4C, cswap_addr & 0xFF, cswap_addr >> 8,         # JMP fe_cswap
    ]))
    jsr(transport, trampoline)
    r_a = read_fe(transport, labels["fe_tmp1"])
    r_b = read_fe(transport, labels["fe_tmp2"])

    if r_a == b and r_b == a:
        passed += 1
        if VERBOSE:
            print("  PASS cswap swap")
    else:
        failed += 1
        print(f"  FAIL cswap swap: expected ({b:#x},{a:#x}), "
              f"got ({r_a:#x},{r_b:#x})")

    return passed, failed


def test_fe_mul_a24(transport, labels, rng):
    """Test fe_mul_a24 (multiply by 121665)."""
    passed = failed = 0

    cases = [0, 1, 2, 121665, P - 1,
             rand_fe(rng), rand_fe(rng), rand_fe(rng)]

    for i, a in enumerate(cases):
        expected = fe_mul_a24_ref(a)
        result = c64_fe_mul_a24(transport, labels, a)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mul_a24 #{i}")
        else:
            failed += 1
            print(f"  FAIL mul_a24 #{i}: a={a}, expected={expected}, "
                  f"got={result}")

    return passed, failed


def test_fe_add_sub_inverse(transport, labels, rng):
    """Test that (a + b) - b == a (add/sub are inverses)."""
    passed = failed = 0

    for i in range(5):
        a = rand_fe(rng)
        b = rand_fe(rng)
        sum_ab = c64_fe_add(transport, labels, a, b)
        result = c64_fe_sub(transport, labels, sum_ab, b)
        if result == a:
            passed += 1
            if VERBOSE:
                print(f"  PASS add_sub_inverse #{i}")
        else:
            failed += 1
            print(f"  FAIL add_sub_inverse #{i}: expected {a}, got {result}")

    return passed, failed


# ============================================================================
# Test functions -- x25519
# ============================================================================

def test_x25519_clamp(transport, labels, rng):
    """Test x25519_clamp against reference implementation."""
    passed = failed = 0

    # Fixed cases
    cases = [
        bytes(range(32)),
        bytes([0xFF] * 32),
        bytes([0x00] * 32),
        bytes([0xA5] * 32),
    ]
    # Random cases
    for _ in range(6):
        cases.append(bytes(rng.getrandbits(8) for _ in range(32)))

    for i, scalar in enumerate(cases):
        expected = clamp_ref(scalar)
        result = c64_x25519_clamp(transport, labels, scalar)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS clamp #{i}")
        else:
            failed += 1
            print(f"  FAIL clamp #{i}:")
            print(f"    input:    {scalar.hex()}")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")
            # Show which bytes differ
            for j in range(32):
                if expected[j] != result[j]:
                    print(f"    byte[{j}]: expected 0x{expected[j]:02x}, "
                          f"got 0x{result[j]:02x}")

    return passed, failed


def test_x25519_rfc7748_vector1(transport, labels):
    """RFC 7748 Section 6.1 test vector 1."""
    passed = failed = 0

    print("    RFC 7748 vector 1...", end="", flush=True)
    result = c64_x25519_scalarmult(transport, labels, SCALAR_1, U_1)

    if result == EXPECTED_1:
        passed += 1
        print(" PASS")
    else:
        failed += 1
        print(" FAIL")
        print(f"    expected: {EXPECTED_1.hex()}")
        print(f"    got:      {result.hex()}")

    return passed, failed


def test_x25519_rfc7748_vector2(transport, labels):
    """RFC 7748 Section 6.1 test vector 2."""
    passed = failed = 0

    print("    RFC 7748 vector 2...", end="", flush=True)
    result = c64_x25519_scalarmult(transport, labels, SCALAR_2, U_2)

    if result == EXPECTED_2:
        passed += 1
        print(" PASS")
    else:
        failed += 1
        print(" FAIL")
        print(f"    expected: {EXPECTED_2.hex()}")
        print(f"    got:      {result.hex()}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups. Returns (passed, failed)."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    test_groups = [
        ("fe_copy/zero/one",
         lambda: test_fe_copy_zero_one(transport, labels)),
        ("fe_add",
         lambda: test_fe_add(transport, labels, rng)),
        ("fe_sub",
         lambda: test_fe_sub(transport, labels, rng)),
        ("fe_add/sub inverse",
         lambda: test_fe_add_sub_inverse(transport, labels, rng)),
        ("fe_mul",
         lambda: test_fe_mul(transport, labels, rng)),
        ("fe_sqr",
         lambda: test_fe_sqr(transport, labels, rng)),
        ("fe_mul_a24",
         lambda: test_fe_mul_a24(transport, labels, rng)),
        ("fe_cswap",
         lambda: test_fe_cswap(transport, labels, rng)),
        ("fe_inv",
         lambda: test_fe_inv(transport, labels, rng)),
        ("x25519_clamp",
         lambda: test_x25519_clamp(transport, labels, rng)),
    ]

    if SLOW:
        test_groups += [
            ("x25519 RFC 7748 vector 1",
             lambda: test_x25519_rfc7748_vector1(transport, labels)),
            ("x25519 RFC 7748 vector 2",
             lambda: test_x25519_rfc7748_vector2(transport, labels)),
        ]
    else:
        print("\n  (x25519 scalarmult tests skipped -- "
              "use --slow to enable, ~100 min each)")

    for name, test_fn in test_groups:
        print(f"\n--- {name} ---")
        try:
            p, f = test_fn()
            total_passed += p
            total_failed += f
            status = "OK" if f == 0 else "FAIL"
            print(f"  {status}: {p}/{p + f} passed")
        except Exception as e:
            total_failed += 1
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()

    return total_passed, total_failed


def main():
    global VERBOSE, SLOW
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        elif args[i] == "--slow":
            SLOW = True
            i += 1
        else:
            i += 1

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build
    print("\n=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    result = subprocess.run(["make"], capture_output=True, text=True,
                            cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"  Build OK: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    required = [
        "fe_src1", "fe_src2", "fe_dst",
        "fe_copy", "fe_zero", "fe_one",
        "fe_add", "fe_sub", "fe_mul", "fe_sqr", "fe_inv",
        "fe_cswap", "fe_mul_a24",
        "fe_tmp1", "fe_tmp2", "fe_tmp3",
        "x25519_clamp", "x25519_scalarmult",
        "x25_scalar", "x25_u", "x25_result",
        "input_buffer",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)

    print(f"  Labels loaded: {len(required)} required labels verified")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    print("\n=== Starting VICE ===")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Program menu did not appear")
            sys.exit(1)

        print("  VICE ready, running tests...")

        # Safety: write JMP $0339 at $0339 so CPU loops harmlessly
        # after jsr() returns (prevents crash when BASIC ROM is banked out)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
