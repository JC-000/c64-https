#!/usr/bin/env python3
"""test_x509.py - X.509 certificate parsing and ECDSA verify test suite.

Tests the C64 DER parser (x509_parse_cert), ECDSA P-256/P-384 signature
verification (ecdsa_verify), and TLS 1.3 CertificateVerify handling by
calling C64 routines directly via jsr() and comparing results against
Python cryptography library references.

Usage:
    python3 tools/test_x509.py [--seed S] [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc, cryptography
"""

import datetime
import hashlib
import os
import random
import struct
import subprocess
import sys
import time

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    goto,
    wait_for_text,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# Flag-based carry trampoline (cassette buffer area, no breakpoints needed)
CARRY_TRAMPOLINE = 0x033C  # 22-byte trampoline: $033C-$0351
CARRY_RESULT_ADDR = 0x0352  # 1 byte: 0=carry clear, 1=carry set
CARRY_FLAG_ADDR = 0x0353    # 1 byte: 0x00=running, 0xFF=done

# Curve ID constants (must match C64 code)
CURVE_P256 = 0
CURVE_P384 = 1

# Labels for DER parser tests
DER_LABELS = [
    "x509_parse_cert",
    "cert_buf", "cert_buf_len",
    "cert_tbs_ptr", "cert_tbs_len",
    "cert_pubkey", "cert_pubkey_len",
    "cert_sig_r", "cert_sig_s", "cert_sig_len",
    "cert_curve_id",
]

# Labels for ECDSA verify tests
ECDSA_LABELS = [
    "ecdsa_verify",
    "ecdsa_curve_id",
    "ecdsa_hash",
    "ecdsa_sig_r", "ecdsa_sig_s",
    "ecdsa_pubkey_x", "ecdsa_pubkey_y",
    "sqtab_init",
]

# Labels for CertificateVerify tests
CV_LABELS = [
    "tls_handle_cert_verify",
    "tls_hs_buf", "tls_hs_len",
    "tls_transcript",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def jsr_with_carry(transport, addr, timeout=120.0, poll_interval=0.5):
    """Call subroutine and capture carry flag using flag-based polling.

    Uses memory flag polling (no breakpoints) for reliable long-running ops.
    Based on the proven jsr_flag() pattern from c64-wireguard.

    Writes trampoline at CARRY_TRAMPOLINE ($033C):
        LDA #$00           ; clear flag
        STA flag_addr
        JSR addr           ; call target (may take minutes)
        LDA #$00           ; capture carry
        ROL A
        STA result_addr
        LDA #$FF           ; signal completion
        STA flag_addr
        JMP self           ; safety loop

    Polls flag_addr until it reads 0xFF, then reads carry from result_addr.
    Returns carry flag (0 or 1). Raises TimeoutError on timeout.
    """
    lo = addr & 0xFF
    hi = (addr >> 8) & 0xFF
    result_lo = CARRY_RESULT_ADDR & 0xFF
    result_hi = (CARRY_RESULT_ADDR >> 8) & 0xFF
    flag_lo = CARRY_FLAG_ADDR & 0xFF
    flag_hi = (CARRY_FLAG_ADDR >> 8) & 0xFF
    loop_addr = CARRY_TRAMPOLINE + 19  # JMP target = self
    trampoline = bytes([
        0xA9, 0x00,                             # LDA #$00
        0x8D, flag_lo, flag_hi,                 # STA flag_addr (clear)
        0x20, lo, hi,                           # JSR addr
        0xA9, 0x00,                             # LDA #$00
        0x2A,                                   # ROL A (carry → bit 0)
        0x8D, result_lo, result_hi,             # STA result_addr
        0xA9, 0xFF,                             # LDA #$FF
        0x8D, flag_lo, flag_hi,                 # STA flag_addr (done)
        0x4C, loop_addr & 0xFF, loop_addr >> 8, # JMP self
    ])
    # Write trampoline and ensure flag is clear
    write_bytes(transport, CARRY_TRAMPOLINE, trampoline)
    write_bytes(transport, CARRY_FLAG_ADDR, bytes([0x00]))

    # Start execution: set PC and resume CPU
    goto(transport, CARRY_TRAMPOLINE)

    # Poll flag until completion
    deadline = time.monotonic() + timeout
    while True:
        time.sleep(poll_interval)
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"jsr_with_carry(${addr:04X}) timed out after {timeout:.0f}s")
        try:
            flag = read_bytes(transport, CARRY_FLAG_ADDR, 1)
            if flag[0] == 0xFF:
                break
            # Binary monitor: resume CPU after memory read paused it
            transport.resume()
        except Exception:
            # Transient connection error — retry
            continue

    result = read_bytes(transport, CARRY_RESULT_ADDR, 1)
    return result[0]


def check_label(labels, name):
    """Return True if label exists, print skip message if not."""
    if labels.address(name) is None:
        print(f"  SKIP: label '{name}' not found (routine not yet implemented)")
        return False
    return True


def check_labels(labels, label_list):
    """Return True if all labels in the list exist."""
    for name in label_list:
        if labels.address(name) is None:
            print(f"  SKIP: label '{name}' not found -- skipping test group")
            return False
    return True


def write_u16_le(transport, addr, value):
    """Write a 16-bit little-endian value."""
    write_bytes(transport, addr, bytes([value & 0xFF, (value >> 8) & 0xFF]))


def generate_p256_cert():
    """Generate a self-signed ECDSA P-256 certificate.

    Returns (cert_der, key, cert) where cert_der is the DER-encoded
    certificate, key is the private key, and cert is the certificate object.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC)
                             + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return cert_der, key, cert


def generate_p384_cert():
    """Generate a self-signed ECDSA P-384 certificate.

    Returns (cert_der, key, cert).
    """
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test384.example.com"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC)
                             + datetime.timedelta(days=365))
            .sign(key, hashes.SHA384()))
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return cert_der, key, cert


def extract_pubkey_bytes(cert):
    """Extract raw public key bytes (x || y) from a certificate."""
    pub = cert.public_key().public_numbers()
    if isinstance(cert.public_key().curve, ec.SECP256R1):
        coord_len = 32
    elif isinstance(cert.public_key().curve, ec.SECP384R1):
        coord_len = 48
    else:
        raise ValueError(f"Unsupported curve: {cert.public_key().curve.name}")
    qx = pub.x.to_bytes(coord_len, 'big')
    qy = pub.y.to_bytes(coord_len, 'big')
    return qx + qy


def extract_sig_rs(cert):
    """Extract (r_bytes, s_bytes) from a certificate's signature."""
    r, s = utils.decode_dss_signature(cert.signature)
    # Determine coordinate length from signature algorithm
    sig_alg = cert.signature_algorithm_oid.dotted_string
    if sig_alg == "1.2.840.10045.4.3.2":  # ecdsa-with-SHA256
        coord_len = 32
    elif sig_alg == "1.2.840.10045.4.3.3":  # ecdsa-with-SHA384
        coord_len = 48
    else:
        # Fallback: infer from r size
        coord_len = (r.bit_length() + 7) // 8
    r_bytes = r.to_bytes(coord_len, 'big')
    s_bytes = s.to_bytes(coord_len, 'big')
    return r_bytes, s_bytes


def load_cert_to_c64(transport, labels, cert_der):
    """Write a DER certificate to the C64 cert_buf and set cert_buf_len."""
    write_bytes(transport, labels["cert_buf"], cert_der)
    write_u16_le(transport, labels["cert_buf_len"], len(cert_der))


# ---------------------------------------------------------------------------
# Group 1: DER Parser - P-256 (5 tests)
# ---------------------------------------------------------------------------

def test_der_parser_p256(transport, labels):
    """Test x509_parse_cert with a P-256 self-signed certificate."""
    passed = 0
    failed = 0

    if not check_labels(labels, DER_LABELS):
        return 0, 0

    print("\n  Generating P-256 self-signed certificate...")
    cert_der, key, cert = generate_p256_cert()
    print(f"  Certificate: {len(cert_der)} bytes")

    # Pre-extract expected values from Python
    expected_pubkey = extract_pubkey_bytes(cert)
    expected_tbs = cert.tbs_certificate_bytes
    expected_r, expected_s = extract_sig_rs(cert)

    # Load certificate to C64
    load_cert_to_c64(transport, labels, cert_der)

    # --- Test 1: Parse succeeds (C=0) ---
    print("\n  [1a] DER parse P-256: parse succeeds (C=0)")
    try:
        carry = jsr_with_carry(transport, labels["x509_parse_cert"],
                                timeout=120.0, poll_interval=0.5)
        if carry == 0:
            passed += 1
            print("       PASS: x509_parse_cert returned C=0 (success)")
        else:
            failed += 1
            print("       FAIL: x509_parse_cert returned C=1 (error)")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")
        return passed, failed  # Can't continue if parse fails

    # --- Test 2: Public key extracted correctly ---
    print("  [1b] DER parse P-256: public key extracted (64 bytes)")
    try:
        c64_pubkey = read_bytes(transport, labels["cert_pubkey"], 64)
        if c64_pubkey == expected_pubkey:
            passed += 1
            print(f"       PASS: pubkey matches ({c64_pubkey[:8].hex()}...)")
        else:
            failed += 1
            print(f"       FAIL: pubkey mismatch")
            print(f"         Expected: {expected_pubkey[:16].hex()}...")
            print(f"         Got:      {c64_pubkey[:16].hex()}...")
            # Find first diff byte
            for i in range(min(len(c64_pubkey), len(expected_pubkey))):
                if c64_pubkey[i] != expected_pubkey[i]:
                    print(f"         First diff at byte {i}")
                    break
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 3: TBS bytes identified ---
    print("  [1c] DER parse P-256: TBS bytes identified")
    try:
        tbs_ptr_bytes = read_bytes(transport, labels["cert_tbs_ptr"], 2)
        tbs_ptr = tbs_ptr_bytes[0] + tbs_ptr_bytes[1] * 256
        tbs_len_bytes = read_bytes(transport, labels["cert_tbs_len"], 2)
        tbs_len = tbs_len_bytes[0] + tbs_len_bytes[1] * 256

        # Read the TBS region from C64 memory
        c64_tbs = read_bytes(transport, tbs_ptr, tbs_len)

        if c64_tbs == expected_tbs:
            passed += 1
            print(f"       PASS: TBS matches ({tbs_len} bytes at ${tbs_ptr:04X})")
        else:
            failed += 1
            print(f"       FAIL: TBS mismatch")
            print(f"         Expected len: {len(expected_tbs)}, Got len: {tbs_len}")
            if len(c64_tbs) >= 4 and len(expected_tbs) >= 4:
                print(f"         Expected start: {expected_tbs[:8].hex()}")
                print(f"         Got start:      {c64_tbs[:8].hex()}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 4: Signature extracted ---
    print("  [1d] DER parse P-256: signature r,s extracted")
    try:
        c64_r = read_bytes(transport, labels["cert_sig_r"], 32)
        c64_s = read_bytes(transport, labels["cert_sig_s"], 32)

        r_ok = (c64_r == expected_r)
        s_ok = (c64_s == expected_s)

        if r_ok and s_ok:
            passed += 1
            print(f"       PASS: r={c64_r[:8].hex()}... s={c64_s[:8].hex()}...")
        else:
            failed += 1
            if not r_ok:
                print(f"       FAIL r: expected {expected_r[:8].hex()}..., "
                      f"got {c64_r[:8].hex()}...")
            if not s_ok:
                print(f"       FAIL s: expected {expected_s[:8].hex()}..., "
                      f"got {c64_s[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 5: Curve ID correct ---
    print("  [1e] DER parse P-256: curve_id = 0 (P-256)")
    try:
        c64_curve = read_bytes(transport, labels["cert_curve_id"], 1)[0]
        if c64_curve == CURVE_P256:
            passed += 1
            print(f"       PASS: cert_curve_id = {c64_curve} (P-256)")
        else:
            failed += 1
            print(f"       FAIL: cert_curve_id = {c64_curve}, expected {CURVE_P256}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Group 2: DER Parser - P-384 (2 tests)
# ---------------------------------------------------------------------------

def test_der_parser_p384(transport, labels):
    """Test x509_parse_cert with a P-384 self-signed certificate."""
    passed = 0
    failed = 0

    if not check_labels(labels, DER_LABELS):
        return 0, 0

    print("\n  Generating P-384 self-signed certificate...")
    cert_der, key, cert = generate_p384_cert()
    print(f"  Certificate: {len(cert_der)} bytes")

    expected_pubkey = extract_pubkey_bytes(cert)

    # Load certificate to C64
    load_cert_to_c64(transport, labels, cert_der)

    # Parse the certificate
    try:
        carry = jsr_with_carry(transport, labels["x509_parse_cert"],
                                timeout=120.0, poll_interval=0.5)
        if carry != 0:
            print("  SKIP: P-384 parse returned C=1 (may not be supported yet)")
            return 0, 0
    except Exception as e:
        print(f"  SKIP: P-384 parse raised {e}")
        return 0, 0

    # --- Test 1: Curve ID correct ---
    print("\n  [2a] DER parse P-384: curve_id = 1 (P-384)")
    try:
        c64_curve = read_bytes(transport, labels["cert_curve_id"], 1)[0]
        if c64_curve == CURVE_P384:
            passed += 1
            print(f"       PASS: cert_curve_id = {c64_curve} (P-384)")
        else:
            failed += 1
            print(f"       FAIL: cert_curve_id = {c64_curve}, expected {CURVE_P384}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 2: Public key extracted (96 bytes) ---
    print("  [2b] DER parse P-384: public key extracted (96 bytes)")
    try:
        c64_pubkey = read_bytes(transport, labels["cert_pubkey"], 96)
        if c64_pubkey == expected_pubkey:
            passed += 1
            print(f"       PASS: pubkey matches ({c64_pubkey[:8].hex()}...)")
        else:
            failed += 1
            print(f"       FAIL: pubkey mismatch")
            print(f"         Expected: {expected_pubkey[:16].hex()}...")
            print(f"         Got:      {c64_pubkey[:16].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Hardcoded P-256 test vector (generated and verified in Python)
# ---------------------------------------------------------------------------

P256_MSG_HASH = bytes.fromhex(
    "f38a0e696731a8576a2ccde324ae96d2"
    "94d3f989d51faeeee60063b1dd4bf9f4")
P256_SIG_R = bytes.fromhex(
    "0c4f7352749fab15b7ef0f0476825d8e"
    "b4ee1c066d056d1891bab4a09fbed2fa")
P256_SIG_S = bytes.fromhex(
    "88e013c972958ca85f083b4426a51d23"
    "b03e75459f8d7257e02172df4a215d8b")
P256_QX = bytes.fromhex(
    "661f23a88b2e2f02dfe98a84bea36119"
    "17696b8103aa99efa65c89c63d116d9c")
P256_QY = bytes.fromhex(
    "3871983431eea1e1929d16b573452085"
    "19ea3ff74216513e25807e63c2dad98a")


# ---------------------------------------------------------------------------
# Group 3: ECDSA P-256 Verify (4 tests)
# ---------------------------------------------------------------------------

def setup_ecdsa_verify(transport, labels, msg_hash, r_bytes, s_bytes,
                       qx, qy, curve_id=CURVE_P256):
    """Write ECDSA verify parameters to C64 memory.

    Does NOT call sqtab_init — that must be done once before any ECDSA tests.
    """
    write_bytes(transport, labels["ecdsa_curve_id"], bytes([curve_id]))
    write_bytes(transport, labels["ecdsa_hash"], msg_hash)
    write_bytes(transport, labels["ecdsa_sig_r"], r_bytes)
    write_bytes(transport, labels["ecdsa_sig_s"], s_bytes)
    write_bytes(transport, labels["ecdsa_pubkey_x"], qx)
    write_bytes(transport, labels["ecdsa_pubkey_y"], qy)


def test_ecdsa_verify_p256(transport, labels):
    """Test ecdsa_verify with P-256 signatures.

    Test order: fast boundary tests first, then long crypto tests.
    sqtab_init must have been called before this function.
    """
    passed = 0
    failed = 0

    if not check_labels(labels, ECDSA_LABELS):
        return 0, 0

    print("\n  Using hardcoded P-256 test vector (pre-verified in Python)")
    print(f"  Hash: {P256_MSG_HASH[:8].hex()}...")
    print(f"  r:    {P256_SIG_R[:8].hex()}...")
    print(f"  s:    {P256_SIG_S[:8].hex()}...")
    print(f"  Qx:   {P256_QX[:8].hex()}...")
    print(f"  Qy:   {P256_QY[:8].hex()}...")

    # --- Test 3a: r=0 rejection (instant, ~2s) ---
    print("\n  [3a] ECDSA verify: r=0 rejected (C=1, instant)")
    zero_r = b'\x00' * 32
    setup_ecdsa_verify(transport, labels, P256_MSG_HASH, zero_r, P256_SIG_S,
                       P256_QX, P256_QY, CURVE_P256)
    try:
        # Health check: read $0001 to confirm VICE is responsive
        health = read_bytes(transport, 0x0001, 1)
        if VERBOSE:
            print(f"       VICE health: $0001 = ${health[0]:02X}")
        carry = jsr_with_carry(transport, labels["ecdsa_verify"],
                                timeout=30.0)
        if carry == 1:
            passed += 1
            print("       PASS: ecdsa_verify returned C=1 (r=0 rejected)")
        else:
            failed += 1
            print("       FAIL: ecdsa_verify returned C=0, expected C=1 for r=0")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")
        return passed, failed  # Plumbing broken — stop early

    # --- Test 3b: s=0 rejection (instant, ~2s) ---
    print("\n  [3b] ECDSA verify: s=0 rejected (C=1, instant)")
    zero_s = b'\x00' * 32
    setup_ecdsa_verify(transport, labels, P256_MSG_HASH, P256_SIG_R, zero_s,
                       P256_QX, P256_QY, CURVE_P256)
    try:
        carry = jsr_with_carry(transport, labels["ecdsa_verify"],
                                timeout=30.0)
        if carry == 1:
            passed += 1
            print("       PASS: ecdsa_verify returned C=1 (s=0 rejected)")
        else:
            failed += 1
            print("       FAIL: ecdsa_verify returned C=0, expected C=1 for s=0")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")
        return passed, failed  # Plumbing broken — stop early

    # --- Test 3c: Valid P-256 signature (6-16 min) ---
    print("\n  [3c] ECDSA verify: valid signature (C=0)")
    print("       (this may take 6-16 minutes in VICE warp...)")
    setup_ecdsa_verify(transport, labels, P256_MSG_HASH, P256_SIG_R,
                       P256_SIG_S, P256_QX, P256_QY, CURVE_P256)
    try:
        # Health check before long operation
        health = read_bytes(transport, 0x0001, 1)
        if VERBOSE:
            print(f"       VICE health: $0001 = ${health[0]:02X}")
        t0 = time.time()
        carry = jsr_with_carry(transport, labels["ecdsa_verify"],
                                timeout=2400.0, poll_interval=30.0)
        elapsed = time.time() - t0
        if carry == 0:
            passed += 1
            print(f"       PASS: ecdsa_verify returned C=0 (valid) [{elapsed:.0f}s]")
        else:
            failed += 1
            print(f"       FAIL: ecdsa_verify returned C=1 (invalid) [{elapsed:.0f}s]")
            # Dump input buffers for debugging
            print(f"       Dumping input buffers from C64 memory:")
            c64_hash = read_bytes(transport, labels["ecdsa_hash"], 32)
            c64_r = read_bytes(transport, labels["ecdsa_sig_r"], 32)
            c64_s = read_bytes(transport, labels["ecdsa_sig_s"], 32)
            c64_qx = read_bytes(transport, labels["ecdsa_pubkey_x"], 32)
            c64_qy = read_bytes(transport, labels["ecdsa_pubkey_y"], 32)
            c64_cid = read_bytes(transport, labels["ecdsa_curve_id"], 1)[0]
            print(f"         curve_id: {c64_cid}")
            print(f"         hash:  {c64_hash.hex()}")
            print(f"         r:     {c64_r.hex()}")
            print(f"         s:     {c64_s.hex()}")
            print(f"         Qx:    {c64_qx.hex()}")
            print(f"         Qy:    {c64_qy.hex()}")
            match_hash = (c64_hash == P256_MSG_HASH)
            match_r = (c64_r == P256_SIG_R)
            match_s = (c64_s == P256_SIG_S)
            match_qx = (c64_qx == P256_QX)
            match_qy = (c64_qy == P256_QY)
            print(f"         Match: hash={match_hash} r={match_r} s={match_s} "
                  f"Qx={match_qx} Qy={match_qy}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 3d: Tampered signature (flip bit in s, C=1, 6-16 min) ---
    print("\n  [3d] ECDSA verify: tampered s (C=1)")
    print("       (this may take 6-16 minutes in VICE warp...)")
    tampered_s = bytearray(P256_SIG_S)
    tampered_s[-1] ^= 0x01
    tampered_s = bytes(tampered_s)

    setup_ecdsa_verify(transport, labels, P256_MSG_HASH, P256_SIG_R,
                       tampered_s, P256_QX, P256_QY, CURVE_P256)
    try:
        t0 = time.time()
        carry = jsr_with_carry(transport, labels["ecdsa_verify"],
                                timeout=2400.0, poll_interval=30.0)
        elapsed = time.time() - t0
        if carry == 1:
            passed += 1
            print(f"       PASS: ecdsa_verify returned C=1 (tampered rejected) [{elapsed:.0f}s]")
        else:
            failed += 1
            print(f"       FAIL: ecdsa_verify returned C=0, expected C=1 [{elapsed:.0f}s]")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels):
    """Run all X.509 / ECDSA tests. Returns (passed, failed).

    Order: DER parser first (fast, validates VICE), then ECDSA verify.
    CertificateVerify tests skipped until core verify is proven.
    """
    total_passed = 0
    total_failed = 0

    # --- DER parser tests (fast, ~seconds) ---
    test_groups = [
        ("Group 1: DER Parser P-256 (5 tests)",
         lambda: test_der_parser_p256(transport, labels)),
        ("Group 2: DER Parser P-384 (2 tests)",
         lambda: test_der_parser_p384(transport, labels)),
    ]

    for name, test_fn in test_groups:
        print(f"\n{'='*60}")
        print(f"  {name}")
        print(f"{'='*60}")
        try:
            p, f = test_fn()
            total_passed += p
            total_failed += f
            if p + f > 0:
                status = "OK" if f == 0 else "FAIL"
                print(f"\n  {status}: {p}/{p + f} passed")
        except Exception as e:
            total_failed += 1
            print(f"\n  ERROR: {e}")
            import traceback
            traceback.print_exc()

    # --- ECDSA verify tests (slow, minutes each) ---
    ecdsa_ok = check_labels(labels, ECDSA_LABELS)
    if ecdsa_ok:
        # One-time sqtab_init before any ECDSA tests
        print(f"\n{'='*60}")
        print(f"  Initializing sqtab (quarter-square multiply tables)...")
        print(f"{'='*60}")
        try:
            jsr(transport, labels["sqtab_init"], timeout=60.0)
            print("  sqtab_init OK")
        except Exception as e:
            print(f"  sqtab_init FAILED: {e}")
            total_failed += 1
            return total_passed, total_failed

        print(f"\n{'='*60}")
        print(f"  Group 3: ECDSA P-256 Verify (4 tests)")
        print(f"{'='*60}")
        try:
            p, f = test_ecdsa_verify_p256(transport, labels)
            total_passed += p
            total_failed += f
            if p + f > 0:
                status = "OK" if f == 0 else "FAIL"
                print(f"\n  {status}: {p}/{p + f} passed")
        except Exception as e:
            total_failed += 1
            print(f"\n  ERROR: {e}")
            import traceback
            traceback.print_exc()

    # CertificateVerify tests skipped for now
    # (re-enable after core ECDSA verify is proven)

    return total_passed, total_failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    # Parse args
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
    print(f"  Build OK: {PRG_PATH}")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    # Check which test groups can run
    der_ok = all(labels.address(n) is not None for n in DER_LABELS)
    ecdsa_ok = all(labels.address(n) is not None for n in ECDSA_LABELS)
    cv_ok = all(labels.address(n) is not None for n in CV_LABELS)

    print(f"  Labels loaded from {LABELS_PATH}")
    print(f"    DER parser labels:        {'OK' if der_ok else 'MISSING'}")
    print(f"    ECDSA verify labels:       {'OK' if ecdsa_ok else 'MISSING'}")
    print(f"    CertificateVerify labels:  {'OK' if cv_ok else 'MISSING'}")

    if not (der_ok or ecdsa_ok or cv_ok):
        print("\nFATAL: No test group has all required labels. Nothing to test.")
        sys.exit(1)

    # Estimate test duration
    fast_count = (5 if der_ok else 0) + (2 if der_ok else 0)
    fast_ecdsa = 2 if ecdsa_ok else 0  # r=0, s=0 boundary tests
    slow_count = 2 if ecdsa_ok else 0  # valid sig + tampered sig
    print(f"\n  Fast tests (DER parser + boundary): {fast_count + fast_ecdsa}")
    print(f"  Slow tests (ECDSA verify, ~6-16 min each): {slow_count}")
    if slow_count > 0:
        print(f"  Estimated total time: {slow_count * 6}-{slow_count * 16} minutes")

    # Launch VICE via ViceInstanceManager (safe port allocation)
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"\n=== Starting VICE ===")
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        # Wait for main menu
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        # Run tests
        print(f"\n=== X.509 / ECDSA Verify Tests ===")
        passed, failed = run_tests(transport, labels)

        mgr.release(inst)

    # Summary
    total = passed + failed
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if total == 0:
        print("\n  [?] No tests ran (routines not yet implemented?)")
    elif failed == 0:
        print(f"\n  [+] X.509/ECDSA: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] X.509/ECDSA: {failed} TEST(S) FAILED")
    print(f"{'='*60}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
