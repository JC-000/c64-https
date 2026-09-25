#!/usr/bin/env python3
"""test_x25519.py -- X25519 field arithmetic and key exchange tests.

Drives the libs/x25519 sibling that every build links (issue #245 retired
the in-tree src/crypto/{x25519,fe25519}.s): fe25519_add / sub / mul / sqr /
inv / cswap / mul_a24 / copy / zero / one, fe_reduce_wide, x25519_clamp and
x25519_scalarmult, against Python reference implementations and RFC 7748
test vectors. Also checks src/crypto/x25519_tables.s, which generates the
sibling's lookup tables at runtime instead of shipping them as RODATA.

The end-to-end scalarmult groups (RFC 7748 vectors, the #242 capture, the
#244 a24 trap, and a random-scalar loop against a Python RFC 7748 ladder)
run by default; each scalar mult is ~15 s under VICE warp. `--fast` skips
them and says so in the summary line.

Uses the binary monitor test harness -- jsr() is event-based via
checkpoints, so no polling or retry wrappers are needed.

Usage:
    python3 tools/test_x25519.py [--seed S] [--verbose] [--fast] [--keygen N]

    --fast      skip every scalarmult group. The summary line then reports
                them as SKIPPED.
    --keygen N  random scalar mults checked against the Python ladder
                (default 4). #242 was a ~1.3%-per-mult defect, so the
                default loop is a smoke test, not a rate bound; run a few
                hundred to bound a rate.
    --keygen-only  run only the table check and the random-scalar loop (for
                long rate-bounding batches; parallel copies with distinct
                --seed values and C64_SKIP_BUILD=1 share one PRG).
    --slow      accepted and ignored.
"""

import os
import random
import re
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

from _vice_helpers import default_vice_config
from _skip_policy import verdict  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False
FAST = False
KEYGEN_N = 4
KEYGEN_ONLY = False

# The sibling's ZP slots are its own zp_config.s defaults (the wrapper passes
# no overrides, tools/integration/build_x25519.sh ZP_DEFINES=()), and they are
# not in labels.txt: constants.s includes zp_config.s with exports suppressed.
# Read them from the pinned source rather than restating addresses here.
X25519_SRC = os.path.join(PROJECT_ROOT, "libs", "x25519", "src")


def load_sibling_zp():
    zp = {}
    pat = re.compile(r"^\s*([a-z0-9_]+)\s*=\s*\$([0-9a-fA-F]{2})\b")
    for name in ("zp_config.s", "constants.s"):
        with open(os.path.join(X25519_SRC, name)) as f:
            for line in f:
                m = pat.match(line)
                if m:
                    zp.setdefault(m.group(1), int(m.group(2), 16))
    for need in ("fe25519_src1", "fe25519_src2", "fe25519_dst", "fe_wide"):
        if need not in zp:
            raise SystemExit(f"FATAL: {need} not found in libs/x25519 zp_config.s/constants.s")
    return zp


ZP = {}

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
    """Set the sibling's fe25519_src1 / src2 / dst zero-page pointers."""
    if src1 is not None:
        write_bytes(transport, ZP["fe25519_src1"],
                    bytes([src1 & 0xFF, src1 >> 8]))
    if src2 is not None:
        write_bytes(transport, ZP["fe25519_src2"],
                    bytes([src2 & 0xFF, src2 >> 8]))
    if dst is not None:
        write_bytes(transport, ZP["fe25519_dst"],
                    bytes([dst & 0xFF, dst >> 8]))


def write_fe(transport, addr, val):
    """Write a field element (integer) to C64 memory as 32-byte LE."""
    write_bytes(transport, addr, int_to_le32(val))


def read_fe(transport, addr):
    """Read a 32-byte LE field element from C64 memory, return as integer."""
    return le32_to_int(read_bytes(transport, addr, 32))


def c64_fe_add(transport, labels, a, b):
    """Compute a + b mod p on C64."""
    write_fe(transport, labels["fe25519_tmp1"], a)
    write_fe(transport, labels["fe25519_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                src2=labels["fe25519_tmp2"],
                dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_add"])
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_sub(transport, labels, a, b):
    """Compute a - b mod p on C64."""
    write_fe(transport, labels["fe25519_tmp1"], a)
    write_fe(transport, labels["fe25519_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                src2=labels["fe25519_tmp2"],
                dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_sub"])
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_mul(transport, labels, a, b):
    """Compute a * b mod p on C64."""
    write_fe(transport, labels["fe25519_tmp1"], a)
    write_fe(transport, labels["fe25519_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                src2=labels["fe25519_tmp2"],
                dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_mul"], timeout=120.0)
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_sqr(transport, labels, a):
    """Compute a^2 mod p on C64."""
    write_fe(transport, labels["fe25519_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_sqr"], timeout=120.0)
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_inv(transport, labels, a):
    """Compute a^(p-2) mod p on C64."""
    write_fe(transport, labels["fe25519_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                dst=labels["fe25519_tmp3"])
    # fe_inv takes ~253 squarings + 11 muls -- very slow
    jsr(transport, labels["fe25519_inv"], timeout=600.0)
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_mul_a24(transport, labels, a):
    """Compute a * 121665 mod p on C64."""
    write_fe(transport, labels["fe25519_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_mul_a24"], timeout=60.0)
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_copy(transport, labels, a):
    """Copy a field element via fe_copy."""
    write_fe(transport, labels["fe25519_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_copy"])
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_zero(transport, labels):
    """Zero a field element via fe_zero."""
    # Write nonzero first to prove it gets zeroed
    write_fe(transport, labels["fe25519_tmp3"], P - 1)
    set_fe_ptrs(transport, labels, dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_zero"])
    return read_fe(transport, labels["fe25519_tmp3"])


def c64_fe_one(transport, labels):
    """Set a field element to 1 via fe_one."""
    write_fe(transport, labels["fe25519_tmp3"], P - 1)
    set_fe_ptrs(transport, labels, dst=labels["fe25519_tmp3"])
    jsr(transport, labels["fe25519_one"])
    return read_fe(transport, labels["fe25519_tmp3"])


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
#
# The sibling's field ops return any 32-byte value congruent to the result
# (R < 2^256 = 2p + 38; only fe25519_reduce_final and the end of
# x25519_scalarmult canonicalize — libs/x25519 fe25519.s, "Inv3"), so the
# checks below compare mod p. The retired in-tree copy happened to return
# canonical values; exact comparison against the sibling fails on e.g.
# 1^2 = p + 1.
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
        if result % P == expected:
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
        if result % P == expected:
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
        if result % P == expected:
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
        if result % P == expected:
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

        if inv_a % P == expected:
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

    cswap_addr = labels["fe25519_cswap"]
    trampoline = labels["input_buffer"]

    # No-swap test (mask = $00)
    write_fe(transport, labels["fe25519_tmp1"], a)
    write_fe(transport, labels["fe25519_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                src2=labels["fe25519_tmp2"])
    write_bytes(transport, trampoline, bytes([
        0xA9, 0x00,                                        # LDA #$00
        0x4C, cswap_addr & 0xFF, cswap_addr >> 8,         # JMP fe_cswap
    ]))
    jsr(transport, trampoline)
    r_a = read_fe(transport, labels["fe25519_tmp1"])
    r_b = read_fe(transport, labels["fe25519_tmp2"])

    if r_a == a and r_b == b:
        passed += 1
        if VERBOSE:
            print("  PASS cswap no-swap")
    else:
        failed += 1
        print(f"  FAIL cswap no-swap: a changed={r_a != a}, b changed={r_b != b}")

    # Swap test (mask = $FF)
    write_fe(transport, labels["fe25519_tmp1"], a)
    write_fe(transport, labels["fe25519_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe25519_tmp1"],
                src2=labels["fe25519_tmp2"])
    write_bytes(transport, trampoline, bytes([
        0xA9, 0xFF,                                        # LDA #$FF
        0x4C, cswap_addr & 0xFF, cswap_addr >> 8,         # JMP fe_cswap
    ]))
    jsr(transport, trampoline)
    r_a = read_fe(transport, labels["fe25519_tmp1"])
    r_b = read_fe(transport, labels["fe25519_tmp2"])

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
        if result % P == expected:
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
        if result % P == a:
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
        write_bytes(transport, ZP["fe_wide"], wide)
        jsr(transport, labels["fe_reduce_wide"], timeout=60.0)
        got = le32_to_int(bytes(read_bytes(transport, ZP["fe_wide"], 32)))
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


# ----------------------------------------------------------------------------
# src/crypto/x25519_tables.s generates the sibling's lookup tables at
# runtime. A wrong entry is a wrong field op on some inputs only, which the
# vectors above may never touch, so compare all 2 KB against upstream's
# definitions (libs/x25519/src/data.s).
# ----------------------------------------------------------------------------

def expected_tables():
    t = {}
    t["mul38_lo_tab"] = bytes((i * 38) & 0xFF for i in range(256))
    t["mul38_hi_tab"] = bytes((i * 38) >> 8 for i in range(256))
    t["sqr_lo"] = bytes((i * i) & 0xFF for i in range(256))
    t["sqr_hi"] = bytes((i * i) >> 8 for i in range(256))
    for k in range(4):
        t[f"a24_b{k}"] = bytes(((121665 * i) >> (8 * k)) & 0xFF
                               for i in range(256))
    return t


def test_x25519_tables(transport, labels):
    """Every generated table byte equals upstream's .repeat definition."""
    passed = failed = 0
    for name, want in expected_tables().items():
        addr = labels[name]
        got = bytes(read_bytes(transport, addr, 256))
        if addr & 0xFF:
            failed += 1
            print(f"  FAIL {name} at ${addr:04X} is not page-aligned")
        elif got == want:
            passed += 1
            if VERBOSE:
                print(f"  PASS {name}")
        else:
            failed += 1
            bad = [i for i in range(256) if got[i] != want[i]]
            print(f"  FAIL {name}: {len(bad)} wrong entries, first i={bad[0]}"
                  f" want {want[bad[0]]:#04x} got {got[bad[0]]:#04x}")
    return passed, failed


# ----------------------------------------------------------------------------
# Random scalars against a Python RFC 7748 ladder. This is the group that can
# see a rare-input defect like #242 (~1.3% of mults); the fixed vectors above
# cannot. `--keygen N` sets the count.
# ----------------------------------------------------------------------------

def x25519_ref(k, u):
    """RFC 7748 §5 X25519 (decodeScalar25519 + decodeUCoordinate + ladder)."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def test_x25519_random_keygen(transport, labels, rng):
    """N random scalars: keygen (u=9) and a random-u mult, vs x25519_ref."""
    passed = failed = 0
    assert x25519_ref(SCALAR_1, U_1) == EXPECTED_1  # the reference itself
    for i in range(KEYGEN_N):
        k = bytes(rng.getrandbits(8) for _ in range(32))
        u = (9).to_bytes(32, "little") if i % 2 == 0 else \
            bytes(rng.getrandbits(8) for _ in range(32))
        want = x25519_ref(k, u)
        got = c64_x25519_scalarmult(transport, labels, k, u)
        if got == want:
            passed += 1
            if VERBOSE:
                print(f"  PASS random #{i}")
        else:
            failed += 1
            print(f"  FAIL random #{i}: k={k.hex()} u={u.hex()}")
            print(f"    expected: {want.hex()}")
            print(f"    got:      {bytes(got).hex()}")
    return passed, failed


# ----------------------------------------------------------------------------
# The two unions (issue #245). On every profile the field buffers overlay
# tls_rec_buf; on ip65 the lookup tables overlay cert_buf as well, which a
# first handshake's Certificate overwrites before the NEXT handshake's
# keygen. So src/tls_ecdh.s's entries (x25519_base_fresh /
# x25519_scalarmult_fresh) must produce the right answer from a state where
# both regions hold garbage. Fill them with junk, write only the inputs the
# caller writes (x25_scalar, x25_u), run the fresh entry, check the result.
# ----------------------------------------------------------------------------

def _clobber_x25519_state(transport, labels, byte):
    tables = labels["mul38_lo_tab"]
    write_bytes(transport, tables, bytes([byte]) * 2048)
    bss = labels["fe25519_tmp1"]
    write_bytes(transport, bss, bytes([byte]) * (17 * 32))


def test_x25519_fresh_after_clobber(transport, labels):
    """Fresh entries are correct with tables + field buffers overwritten."""
    passed = failed = 0
    cases = [
        ("scalarmult_fresh, RFC vector 1, junk $A5", "x25519_scalarmult_fresh",
         SCALAR_1, U_1, EXPECTED_1, 0xA5),
        ("scalarmult_fresh, RFC vector 2, junk $FF", "x25519_scalarmult_fresh",
         SCALAR_2, U_2, EXPECTED_2, 0xFF),
        ("base_fresh, #242 key, junk $5A", "x25519_base_fresh",
         ISSUE_242_PRIV, None, ISSUE_242_GOOD_PUB, 0x5A),
    ]
    for name, entry, k, u, want, junk in cases:
        print(f"    {name}...", end="", flush=True)
        _clobber_x25519_state(transport, labels, junk)
        write_bytes(transport, labels["x25_scalar"], k)
        if u is not None:
            write_bytes(transport, labels["x25_u"], u)
            jsr(transport, labels["x25519_clamp"])
        jsr(transport, labels[entry], timeout=7200.0)
        got = bytes(read_bytes(transport, labels["x25_result"], 32))
        if got == want:
            passed += 1
            print(" PASS")
        else:
            failed += 1
            print(" FAIL")
            print(f"    expected: {want.hex()}")
            print(f"    got:      {got.hex()}")
    # Leave the tables valid for any group that runs after this one.
    jsr(transport, labels["x25519_tables_init"], timeout=60.0)
    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups. Returns (passed, failed, skipped_groups)."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    # The sibling's lookup tables are generated, not loaded; tls_ecdh.s
    # builds them ahead of every scalar mult, and so must a harness that
    # calls the field ops directly.
    jsr(transport, labels["x25519_tables_init"], timeout=60.0)

    test_groups = [
        ("x25519_tables_init",
         lambda: test_x25519_tables(transport, labels)),
        ("fe25519 copy/zero/one",
         lambda: test_fe_copy_zero_one(transport, labels)),
        ("fe25519_add",
         lambda: test_fe_add(transport, labels, rng)),
        ("fe25519_sub",
         lambda: test_fe_sub(transport, labels, rng)),
        ("fe25519 add/sub inverse",
         lambda: test_fe_add_sub_inverse(transport, labels, rng)),
        ("fe25519_mul",
         lambda: test_fe_mul(transport, labels, rng)),
        ("fe25519_sqr",
         lambda: test_fe_sqr(transport, labels, rng)),
        ("fe25519_mul_a24",
         lambda: test_fe_mul_a24(transport, labels, rng)),
        ("fe25519_cswap",
         lambda: test_fe_cswap(transport, labels, rng)),
        ("fe25519_inv",
         lambda: test_fe_inv(transport, labels, rng)),
        ("fe_reduce_wide carry (#242)",
         lambda: test_fe_reduce_wide_carry(transport, labels)),
        ("fe25519_mul_a24 fold carry (#244)",
         lambda: test_fe_mul_a24_fold_carry(transport, labels)),
        ("x25519_clamp",
         lambda: test_x25519_clamp(transport, labels, rng)),
    ]
    scalarmult_groups = [
        ("x25519 RFC 7748 vector 1",
         lambda: test_x25519_rfc7748_vector1(transport, labels)),
        ("x25519 RFC 7748 vector 2",
         lambda: test_x25519_rfc7748_vector2(transport, labels)),
        ("x25519 #242 captured keygen",
         lambda: test_x25519_issue_242_keygen(transport, labels)),
        ("x25519 fe25519_mul_a24 trap u (#244)",
         lambda: test_x25519_a24_trap_u(transport, labels)),
        ("x25519 fresh entries after clobbered unions",
         lambda: test_x25519_fresh_after_clobber(transport, labels)),
        (f"x25519 random scalars x{KEYGEN_N}",
         lambda: test_x25519_random_keygen(transport, labels, rng)),
    ]
    skipped_groups = []
    if KEYGEN_ONLY:
        skipped_groups += [name for name, _ in test_groups[1:]
                           + scalarmult_groups[:-1]]
        test_groups = test_groups[:1] + scalarmult_groups[-1:]
    elif FAST:
        # A skipped group must not silently leave the denominator: record
        # it so the verdict can name it.
        skipped_groups += [name for name, _ in scalarmult_groups]
        print("\n  (--fast: skipping every x25519 scalarmult group)")
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
    global VERBOSE, FAST, KEYGEN_N, KEYGEN_ONLY, ZP
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
        elif args[i] == "--keygen-only":
            KEYGEN_ONLY = True
            i += 1
        elif args[i] == "--keygen" and i + 1 < len(args):
            KEYGEN_N = int(args[i + 1])
            i += 2
        elif args[i] == "--slow":
            # Back-compat no-op: the vectors --slow used to enable now
            # run by default. Kept so existing invocations don't break.
            i += 1
        else:
            i += 1

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build
    # BACKEND (ip65|uci) and MAKE_ARGS (e.g. "USE_NISTCURVES_ONCHIP=1")
    # select the profile. Every profile links the same X25519 archive, but
    # its buffers sit in different unions per cfg, so run more than one.
    backend = os.environ.get("BACKEND", "ip65")
    make_args = [f"BACKEND={backend}"] + os.environ.get("MAKE_ARGS", "").split()
    print(f"\n=== Building ({' '.join(make_args)}) ===")
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

    ZP = load_sibling_zp()
    required = [
        "x25519_clamp", "x25519_scalarmult", "x25519_tables_init",
        "x25519_scalarmult_fresh", "x25519_base_fresh",
        "x25_scalar", "x25_u", "x25_result",
        "fe25519_copy", "fe25519_zero", "fe25519_one",
        "fe25519_add", "fe25519_sub", "fe25519_mul", "fe25519_sqr",
        "fe25519_inv", "fe25519_cswap", "fe25519_mul_a24", "fe_reduce_wide",
        "fe25519_tmp1", "fe25519_tmp2", "fe25519_tmp3",
        "input_buffer",
    ] + list(expected_tables())
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)

    print(f"  Labels loaded: {len(required)} required labels verified")

    # Launch VICE
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    print("\n=== Starting VICE ===")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        # Comb builds run the boot precompute first (C64_INIT_TIMEOUT, as in
        # test_ecdsa_kat_oracle.py).
        grid = wait_for_text(transport, "Q=QUIT",
                             timeout=float(os.environ.get("C64_INIT_TIMEOUT", "60")),
                             verbose=False)
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
    if skipped_groups:
        print("WARNING: not every group ran (see SKIPPED above); this run "
              "does not certify X25519 on its own.")
    print(f"{'='*60}")
    sys.exit(verdict(passed, failed, certifies="X25519"))


if __name__ == "__main__":
    main()
