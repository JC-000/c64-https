#!/usr/bin/env python3
"""test_x25519.py -- fe25519 field arithmetic and X25519 key exchange tests.

Tests fe_add, fe_sub, fe_mul, fe_sqr, fe_inv, fe_cswap, fe_mul_a24,
fe_copy, fe_zero, fe_one, x25519_clamp, and x25519_scalarmult against
Python reference implementations and RFC 7748 test vectors.

The two RFC 7748 scalarmult vectors run BY DEFAULT. They are the only
end-to-end `x25519_scalarmult` coverage in this file -- everything else
is field arithmetic -- so a run that omits them certifies nothing about
X25519 itself. They used to be gated behind `--slow` on the strength of
a "~100 min each" comment; measured under VICE warp on the in-tree ip65
build they cost **~16.5 s each** (full suite 37.9 s with them, 4.8 s
without). The gate was buying 33 seconds and hiding the only test that
matters. `--fast` still skips them, and any skip is now named in the
summary line rather than silently leaving the denominator.

Uses the binary monitor test harness -- jsr() is event-based via
checkpoints, so no polling or retry wrappers are needed.

Usage:
    python3 tools/test_x25519.py [--seed S] [--verbose] [--fast]

    --fast   skip the RFC 7748 scalarmult vectors (~33 s). The summary
             line then reports them as SKIPPED.
    --slow   accepted and ignored; the vectors it used to enable are
             now the default.
"""

import os
import random
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

from _vice_helpers import default_vice_config

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False
FAST = False

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


# RFC 7748 Section 5.2 test vectors (the scalarmult vectors -- Section 6.1
# is the Alice/Bob Diffie-Hellman pair, which these are not).
#
# U_2 ends 0x93, i.e. bit 255 of the u-coordinate is SET. That makes
# vector 2 the RFC 7748 decodeUCoordinate MSB-masking regression test:
# it is the vector that caught upstream c64-x25519 #64, the bug present
# in our pinned libs/x25519 v0.6.0. Do not drop it as "redundant".
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
    """Compute X25519(scalar, u) on C64. Returns 32-byte result.

    x25519_scalarmult does NOT clamp — production clamps via
    x25519_clamp first (see src/tls_ecdh.s), and the RFC 7748 test
    vectors assume decodeScalar25519 (clamping). Without the clamp jsr
    the ladder computes the mathematically-correct product for the RAW
    scalar, which does not match the RFC expected outputs.
    """
    write_bytes(transport, labels["x25_scalar"], scalar)
    write_bytes(transport, labels["x25_u"], u)
    jsr(transport, labels["x25519_clamp"])
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


# ----------------------------------------------------------------------------
# Issue #242: fe_reduce_wide dropped a carry past byte 2 of its final fold.
#
# @reduce1_check folds the first pass's leftover carry (x38) into bytes 0-1
# and ripples the carry through @prop2 with `adc #0 / inx / cpx #32 / bcc`.
# `cpx` rewrites C, so from byte 3 on the loop added 0 instead of 1: a
# fold that carried out of byte 2 silently lost 2^24 (and @prop3, the wrap
# past byte 31, was unreachable). ~1.3% of X25519 scalar mults hit it
# (byte-faithful model, 2,000 random keygens), which on hardware is a
# ClientHello key_share that does not match the private key: the server
# derives other handshake keys, every encrypted record fails its tag, and
# the handshake stalls at tls_state=3 / tls_read_seq=0.
# ----------------------------------------------------------------------------

# Captured on the U64E (issue #242, PRG 2596bd34...): the client private
# key, and the X25519 public key the C64 derived from it and sent.
ISSUE_242_PRIV = bytes.fromhex(
    "6070a17ca41b28c9a767bbcb5c09984db799efe30fcdd27b772c4c5273d854ca")
ISSUE_242_BAD_PUB = bytes.fromhex(
    "eca6f47c0dac9595f0d33a5cac283324122155b610cbf8bde7af3852d0603a12")
# RFC 7748 X25519(priv, 9), confirmed with the `cryptography` package.
ISSUE_242_GOOD_PUB = bytes.fromhex(
    "c689799caae3aaaf8e2bc4a2906c7394508ad112306a1f7bb01d277e58aaca03")
# The one fe_mul in that scalar mult (ladder bit 110, CB = C * B) that came
# out 2^24 short.
ISSUE_242_MUL_A = int(
    "7d3a8b9166a36a3b11107c68fcd8e736b366b042200b454f875aff297199f38a", 16)
ISSUE_242_MUL_B = int(
    "7062a30ead657b4aee32c934a97d7530a3d5a63b4072c6be1e4a33d1f070b597", 16)


def _wide_vector(low_bytes, high):
    """64-byte fe_wide image: low 32 bytes given, high half = {index: byte}."""
    w = bytearray(64)
    w[:32] = low_bytes
    for i, v in high.items():
        w[32 + i] = v
    return bytes(w)


# (name, fe_wide image). Each is built so the first pass leaves a carry whose
# x38 fold overflows byte 1 and then has to ripple through $FF bytes.
REDUCE_WIDE_VECTORS = [
    # Pass 1 leaves carry 2 (w[63]=7 at byte 31) -> fold 76 overflows byte 1,
    # ripples through bytes 2..30 ($FF) and stops in byte 31.
    ("ripple bytes 2-30", _wide_vector(b"\xff" * 32, {31: 0x07})),
    # w[63]=$80: 128*38 = $1300 leaves byte 31 at $FF and carry $13; the
    # fold ripples through bytes 2..31 and wraps past 2^256 (@prop3).
    ("ripple past byte 31 (@prop3)", _wide_vector(b"\xff" * 32, {31: 0x80})),
]


def test_fe_reduce_wide_carry(transport, labels):
    """fe_reduce_wide must propagate its final-fold carry through $FF bytes."""
    passed = failed = 0
    for name, wide in REDUCE_WIDE_VECTORS:
        write_bytes(transport, labels["fe_wide"], wide)
        jsr(transport, labels["fe_reduce_wide"], timeout=60.0)
        got = le32_to_int(bytes(read_bytes(transport, labels["fe_wide"], 32)))
        want = int.from_bytes(wide, "little") % P
        if got % P == want:
            passed += 1
            if VERBOSE:
                print(f"  PASS fe_reduce_wide {name}")
        else:
            failed += 1
            print(f"  FAIL fe_reduce_wide {name}")
            print(f"    expected (mod p): {want:064x}")
            print(f"    got:              {got:064x}")

    result = c64_fe_mul(transport, labels, ISSUE_242_MUL_A, ISSUE_242_MUL_B)
    want = fe_mul_ref(ISSUE_242_MUL_A, ISSUE_242_MUL_B)
    if result == want:
        passed += 1
        if VERBOSE:
            print("  PASS fe_mul #242 captured operands")
    else:
        failed += 1
        print("  FAIL fe_mul #242 captured operands")
        print(f"    expected: {want:064x}")
        print(f"    got:      {result:064x}")
    return passed, failed


# ----------------------------------------------------------------------------
# fe_mul_a24 had the sibling defect (found in review of #244): its three
# folds of bytes 32..34 (x38) rippled with INC but simply stopped when the
# ripple ran off byte 31, losing 2^256 = 38 (mod p). Random inputs almost
# never reach it (bytes 3..31 must all be $FF), but a PEER can: at ladder
# bit 254 (always set after clamping) E = AA - BB = 4u exactly, so a
# server key_share u = a/4 with a*121665 = (H+1)*2^256 - r faults every
# handshake that uses it.
# ----------------------------------------------------------------------------

def a24_trap(h):
    """a < p with a*121665 = (h+1)*2^256 - r, r < 121665: bytes 3..31 of
    the product are $FF and bytes 32..34 hold h."""
    r = ((h + 1) << 256) % 121665
    return (((h + 1) << 256) - r) // 121665


# Which fold wraps depends on H: bytes 32..34 of the product are H, and the
# fold stages add them x38 at offsets 0, 1, 2. The large H values wrap at
# the byte-33 stage; H = 70 and 103 (byte 33 = 0) wrap at the byte-32
# stage. Both entries into @a24_wrap38 are peer-forceable with canonical
# input. The byte-34 entry is not (a*121665 < 2^272 for a < 2^255) and is
# kept only as a defensive fold, so it has no vector here.
A24_TRAP_HS = (50000, 40000, 30000, 60000, 70, 103)
# u = a24_trap(50000) / 4 mod p, and X25519(ISSUE_242_PRIV, u) from the
# `cryptography` package (RFC 7748). Unfixed code returns 67c65d3c...
A24_TRAP_U = bytes.fromhex(
    "566921b9502455f0956529a6c75c428d42b3b613a7d438bfc111c979a9604d5a")
A24_TRAP_EXPECTED = bytes.fromhex(
    "81de4f2b4753ba75f04b1f1740966d3c53506a4d696ecca7be36fb9e0c44ba56")
# Same for H = 70, which wraps at the byte-32 fold stage instead.
A24_TRAP_U_B32 = bytes.fromhex(
    "77df4be5d2bb505fcdbcbf0c15ec79a87baff978ea36cd47b411a220ab8f0960")
A24_TRAP_EXPECTED_B32 = bytes.fromhex(
    "bcd4697ebed243e33f5517d73fe54c6b31b645c04bdadbe309fdf25987802e08")


def test_fe_mul_a24_fold_carry(transport, labels):
    """fe_mul_a24 must fold a ripple that runs off byte 31 back in as +38."""
    passed = failed = 0
    for h in A24_TRAP_HS:
        a = a24_trap(h)
        got = c64_fe_mul_a24(transport, labels, a)
        want = fe_mul_a24_ref(a)
        if got % P == want:
            passed += 1
            if VERBOSE:
                print(f"  PASS fe_mul_a24 trap H={h}")
        else:
            failed += 1
            print(f"  FAIL fe_mul_a24 trap H={h}: short by "
                  f"{(want - got) % P} (mod p)")
            print(f"    expected: {want:064x}")
            print(f"    got:      {got:064x}")
    return passed, failed


def test_x25519_a24_trap_u(transport, labels):
    """X25519 with a peer-chosen u that hits the fe_mul_a24 fold at bit 254."""
    passed = failed = 0
    for name, u, want in (("H=50000 (b33 fold)", A24_TRAP_U, A24_TRAP_EXPECTED),
                          ("H=70 (b32 fold)", A24_TRAP_U_B32,
                           A24_TRAP_EXPECTED_B32)):
        print(f"    a24 trap u {name}...", end="", flush=True)
        result = c64_x25519_scalarmult(transport, labels, ISSUE_242_PRIV, u)
        if result == want:
            passed += 1
            print(" PASS")
        else:
            failed += 1
            print(" FAIL")
            print(f"    expected: {want.hex()}")
            print(f"    got:      {result.hex()}")
    return passed, failed


def test_x25519_issue_242_keygen(transport, labels):
    """X25519(captured #242 private key, 9) must be the RFC 7748 value."""
    passed = failed = 0
    print("    #242 captured keygen...", end="", flush=True)
    result = c64_x25519_scalarmult(transport, labels, ISSUE_242_PRIV,
                                   (9).to_bytes(32, "little"))
    if result == ISSUE_242_GOOD_PUB:
        passed += 1
        print(" PASS")
    else:
        failed += 1
        print(" FAIL")
        print(f"    expected: {ISSUE_242_GOOD_PUB.hex()}")
        print(f"    got:      {result.hex()}"
              + ("  (= the key the U64E sent in #242)"
                 if result == ISSUE_242_BAD_PUB else ""))
    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups. Returns (passed, failed)."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    # A USE_X25519_SIBLING=1 link contains no src/crypto/fe25519.s, so its
    # private fe_* entry points are absent and these nine groups cannot
    # run. main() has already verified that the absence is total (see the
    # required-label split there) rather than a partial link.
    sibling_build = labels.address("fe_copy") is None

    fe_groups = [
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
        ("fe_reduce_wide carry (#242)",
         lambda: test_fe_reduce_wide_carry(transport, labels)),
        ("fe_mul_a24 fold carry (#244 review)",
         lambda: test_fe_mul_a24_fold_carry(transport, labels)),
    ]

    skipped_groups = []
    if sibling_build:
        skipped_groups += [name for name, _ in fe_groups]
        test_groups = []
    else:
        test_groups = list(fe_groups)

    # x25519_clamp is public: both implementations export it.
    test_groups.append(
        ("x25519_clamp",
         lambda: test_x25519_clamp(transport, labels, rng)))
    scalarmult_groups = [
        ("x25519 RFC 7748 vector 1",
         lambda: test_x25519_rfc7748_vector1(transport, labels)),
        ("x25519 RFC 7748 vector 2",
         lambda: test_x25519_rfc7748_vector2(transport, labels)),
        ("x25519 #242 captured keygen",
         lambda: test_x25519_issue_242_keygen(transport, labels)),
        ("x25519 fe_mul_a24 trap u",
         lambda: test_x25519_a24_trap_u(transport, labels)),
    ]
    if FAST:
        # A skipped group must not silently leave the denominator: record
        # it so the verdict can name it. These two are the only end-to-end
        # x25519_scalarmult coverage in the file.
        skipped_groups += [name for name, _ in scalarmult_groups]
        print("\n  (--fast: skipping x25519 scalarmult vectors, ~33 s)")
    else:
        test_groups += scalarmult_groups

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

    return total_passed, total_failed, skipped_groups


def main():
    global VERBOSE, FAST
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
        elif args[i] == "--fast":
            FAST = True
            i += 1
        elif args[i] == "--slow":
            # Back-compat no-op: the vectors --slow used to enable now
            # run by default. Kept so existing invocations don't break.
            i += 1
        else:
            i += 1

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build
    # BACKEND env var (ip65 or uci) selects the linker cfg. Defaults to
    # ip65 so the legacy test path is unchanged; under uci the c64-x25519
    # sibling archive (REU overlay) provides fe25519/x25519 instead of
    # the in-tree sources.
    backend = os.environ.get("BACKEND", "ip65")
    make_args = [f"BACKEND={backend}"]
    print(f"\n=== Building (BACKEND={backend}) ===")
    if os.environ.get("C64_SKIP_BUILD") != "1":
        subprocess.run(["make", "clean"] + make_args,
                       capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"] + make_args, capture_output=True,
                                text=True, cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)
    else:
        print("  C64_SKIP_BUILD=1 — reusing existing build artifacts")

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"  Build OK: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    # The fe_* unit-test groups drive the IN-TREE src/crypto/fe25519.s by
    # its private symbol names. A `USE_X25519_SIBLING=1` build evicts that
    # file from the link (Makefile CRYPTO_SRCS_EFFECTIVE) and the sibling
    # exports the contract's `fe25519_*` surface instead, so none of these
    # labels exist there and the script used to abort at
    # `FATAL: 'fe_copy' label not found` before launching VICE — i.e. the
    # sibling had NO runnable coverage at all, which is a bad thing to
    # discover only after deciding to flip the default.
    #
    # The public path is spelled identically by both implementations, so
    # the RFC 7748 vectors — the only end-to-end scalarmult coverage in
    # this file — run against either. Split the requirement list
    # accordingly: the public set is mandatory always, the fe_* set is
    # mandatory only when the build claims to contain it.
    #
    # Detection is by ABSENCE OF THE WHOLE FAMILY, never by one probe
    # label: a partially-linked in-tree build must still fail loudly
    # rather than quietly downgrade itself to two vectors.
    required_public = [
        "x25519_clamp", "x25519_scalarmult",
        "x25_scalar", "x25_u", "x25_result",
        "input_buffer",
    ]
    # Detection reads the ROUTINE entry points only. `fe_src1/2/dst` are ZP
    # equates from src/constants.inc and are present in every link,
    # sibling or not (measured: those three are exactly what survives), so
    # including them in the probe set makes it never fire.
    required_intree_fe_routines = [
        "fe_copy", "fe_zero", "fe_one",
        "fe_add", "fe_sub", "fe_mul", "fe_sqr", "fe_inv",
        "fe_cswap", "fe_mul_a24", "fe_reduce_wide",
    ]
    required_intree_fe_data = [
        "fe_src1", "fe_src2", "fe_dst",
        "fe_tmp1", "fe_tmp2", "fe_tmp3", "fe_wide",
    ]
    required_intree_fe = required_intree_fe_routines + required_intree_fe_data

    fe_present = [n for n in required_intree_fe_routines
                  if labels.address(n) is not None]
    sibling_build = len(fe_present) == 0
    if fe_present and len(fe_present) != len(required_intree_fe_routines):
        # Partial presence is neither an in-tree build nor a sibling one.
        # Fail rather than guess: silently downgrading to two vectors here
        # is how a broken link passes as a green run.
        missing = [n for n in required_intree_fe_routines
                   if labels.address(n) is None]
        print("FATAL: in-tree fe25519 is only partially linked — present "
              f"{fe_present}, missing {missing}. Neither an in-tree nor a "
              "USE_X25519_SIBLING build; not guessing.")
        sys.exit(1)

    required = list(required_public)
    if not sibling_build:
        required += required_intree_fe

    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)

    if sibling_build:
        print("  NOTE: no in-tree fe_* symbols in this link — treating it as a")
        print("        USE_X25519_SIBLING=1 build. The fe_* unit groups are")
        print("        SKIPPED (they test src/crypto/fe25519.s internals, which")
        print("        this PRG does not contain); the RFC 7748 end-to-end")
        print("        vectors still run and are the whole of the coverage.")

    print(f"  Labels loaded: {len(required)} required labels verified")

    # Launch VICE
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
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

        passed, failed, skipped_groups = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    summary = f"RESULTS: {passed}/{total} passed, {failed}/{total} failed"
    if skipped_groups:
        # Never print an unqualified clean pass over a group that did not
        # run. Skipped assertions leave the denominator entirely, so the
        # counters alone cannot express the gap -- name it explicitly.
        summary += (f" -- {len(skipped_groups)} group(s) SKIPPED: "
                    + ", ".join(skipped_groups))
    print(summary)
    # Two different skips are possible and they mean opposite things, so
    # the warning must name the one that actually happened rather than
    # firing on any skip at all. --fast drops the only end-to-end
    # coverage; a sibling build drops the field-arithmetic units but
    # KEEPS the end-to-end vectors.
    scalarmult_skipped = any(g.startswith("x25519 RFC 7748")
                             for g in skipped_groups)
    fe_skipped = any(g.startswith("fe_") for g in skipped_groups)
    if scalarmult_skipped:
        print("WARNING: end-to-end x25519_scalarmult coverage did NOT run; "
              "this run does not certify X25519.")
    elif fe_skipped:
        print("NOTE: field-arithmetic unit coverage did NOT run (no in-tree "
              "fe25519 in this link). The RFC 7748 end-to-end vectors did, "
              "and are the whole of this run's evidence.")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
