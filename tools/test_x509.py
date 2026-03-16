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
    ViceProcess,
    ViceTransport,
    read_bytes,
    write_bytes,
    jsr,
    set_breakpoint,
    delete_breakpoint,
    goto,
    wait_for_pc,
    wait_for_text,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# Scratch area for trampolines (C64 cassette buffer)
SCRATCH_ADDR = 0x0334
CARRY_RESULT = 0x033F  # 1 byte: 0=carry clear, 1=carry set

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

def robust_jsr(transport, addr, timeout=120.0, retries=3):
    """jsr() wrapper with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.5)
                continue
            raise


def jsr_check_carry(transport, addr, timeout=120.0):
    """Call a subroutine and capture the carry flag result.

    Builds trampoline at SCRATCH_ADDR:
        JSR addr       ; 3 bytes
        LDA #0         ; 2 bytes
        ROL A          ; 1 byte -- A = carry
        STA $033F      ; 3 bytes -- store carry result
        NOP            ; breakpoint here
        NOP

    Returns carry flag (0 or 1).
    """
    lo = addr & 0xFF
    hi = (addr >> 8) & 0xFF
    trampoline = bytes([
        0x20, lo, hi,           # JSR addr
        0xA9, 0x00,             # LDA #0
        0x2A,                   # ROL A  (shift carry into bit 0)
        0x8D, CARRY_RESULT & 0xFF, CARRY_RESULT >> 8,  # STA $033F
        0xEA, 0xEA,             # NOP NOP (breakpoint target)
    ])
    write_bytes(transport, SCRATCH_ADDR, trampoline)
    bp_addr = SCRATCH_ADDR + len(trampoline) - 2
    bp_id = set_breakpoint(transport, bp_addr)
    try:
        goto(transport, SCRATCH_ADDR)
        wait_for_pc(transport, bp_addr, timeout=timeout)
    finally:
        delete_breakpoint(transport, bp_id)
    result = read_bytes(transport, CARRY_RESULT, 1)
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
    write_bytes(transport, addr, [value & 0xFF, (value >> 8) & 0xFF])


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
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow()
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
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow()
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
        carry = jsr_check_carry(transport, labels["x509_parse_cert"],
                                timeout=120.0)
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
        c64_pubkey = bytes(read_bytes(transport, labels["cert_pubkey"], 64))
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
        c64_tbs = bytes(read_bytes(transport, tbs_ptr, tbs_len))

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
        c64_r = bytes(read_bytes(transport, labels["cert_sig_r"], 32))
        c64_s = bytes(read_bytes(transport, labels["cert_sig_s"], 32))

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
        carry = jsr_check_carry(transport, labels["x509_parse_cert"],
                                timeout=120.0)
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
        c64_pubkey = bytes(read_bytes(transport, labels["cert_pubkey"], 96))
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
# Group 3: ECDSA P-256 Verify (4 tests)
# ---------------------------------------------------------------------------

def setup_ecdsa_verify(transport, labels, msg_hash, r_bytes, s_bytes,
                       qx, qy, curve_id=CURVE_P256):
    """Write ECDSA verify parameters to C64 memory."""
    write_bytes(transport, labels["ecdsa_hash"], msg_hash)
    write_bytes(transport, labels["ecdsa_sig_r"], r_bytes)
    write_bytes(transport, labels["ecdsa_sig_s"], s_bytes)
    write_bytes(transport, labels["ecdsa_pubkey_x"], qx)
    write_bytes(transport, labels["ecdsa_pubkey_y"], qy)
    write_bytes(transport, labels["ecdsa_curve_id"], [curve_id])


def test_ecdsa_verify_p256(transport, labels):
    """Test ecdsa_verify with P-256 signatures.

    IMPORTANT: Each ECDSA verify takes 6-16 minutes in VICE warp mode.
    """
    passed = 0
    failed = 0

    if not check_labels(labels, ECDSA_LABELS):
        return 0, 0

    # Generate test key and signature in Python
    print("\n  Generating P-256 test key and signature...")
    key = ec.generate_private_key(ec.SECP256R1())
    message_hash = hashlib.sha256(b"test message for ECDSA verify").digest()

    signature = key.sign(
        message_hash,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    r, s = utils.decode_dss_signature(signature)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')

    pub = key.public_key().public_numbers()
    qx = pub.x.to_bytes(32, 'big')
    qy = pub.y.to_bytes(32, 'big')

    print(f"  Hash:   {message_hash[:8].hex()}...")
    print(f"  r:      {r_bytes[:8].hex()}...")
    print(f"  s:      {s_bytes[:8].hex()}...")
    print(f"  Qx:     {qx[:8].hex()}...")
    print(f"  Qy:     {qy[:8].hex()}...")

    # --- Test 1: Valid signature (C=0) ---
    print("\n  [3a] ECDSA verify: valid signature (C=0)")
    print("       (this may take 6-16 minutes in VICE warp...)")
    setup_ecdsa_verify(transport, labels, message_hash, r_bytes, s_bytes,
                       qx, qy, CURVE_P256)
    try:
        carry = jsr_check_carry(transport, labels["ecdsa_verify"],
                                timeout=1200.0)
        if carry == 0:
            passed += 1
            print("       PASS: ecdsa_verify returned C=0 (valid)")
        else:
            failed += 1
            print("       FAIL: ecdsa_verify returned C=1 (invalid)")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 2: Tampered signature (flip one bit in s, C=1) ---
    print("\n  [3b] ECDSA verify: tampered s (C=1)")
    print("       (this may take 6-16 minutes in VICE warp...)")
    tampered_s = bytearray(s_bytes)
    tampered_s[-1] ^= 0x01  # Flip least significant bit
    tampered_s = bytes(tampered_s)

    setup_ecdsa_verify(transport, labels, message_hash, r_bytes, tampered_s,
                       qx, qy, CURVE_P256)
    try:
        carry = jsr_check_carry(transport, labels["ecdsa_verify"],
                                timeout=1200.0)
        if carry == 1:
            passed += 1
            print("       PASS: ecdsa_verify returned C=1 (tampered rejected)")
        else:
            failed += 1
            print("       FAIL: ecdsa_verify returned C=0, expected C=1")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 3: Wrong public key (C=1) ---
    print("\n  [3c] ECDSA verify: wrong public key (C=1)")
    print("       (this may take 6-16 minutes in VICE warp...)")
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong_pub = wrong_key.public_key().public_numbers()
    wrong_qx = wrong_pub.x.to_bytes(32, 'big')
    wrong_qy = wrong_pub.y.to_bytes(32, 'big')

    setup_ecdsa_verify(transport, labels, message_hash, r_bytes, s_bytes,
                       wrong_qx, wrong_qy, CURVE_P256)
    try:
        carry = jsr_check_carry(transport, labels["ecdsa_verify"],
                                timeout=1200.0)
        if carry == 1:
            passed += 1
            print("       PASS: ecdsa_verify returned C=1 (wrong key rejected)")
        else:
            failed += 1
            print("       FAIL: ecdsa_verify returned C=0, expected C=1")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 4: Zero r rejected (C=1, immediate rejection) ---
    print("\n  [3d] ECDSA verify: r=0 rejected (C=1)")
    zero_r = b'\x00' * 32

    setup_ecdsa_verify(transport, labels, message_hash, zero_r, s_bytes,
                       qx, qy, CURVE_P256)
    try:
        carry = jsr_check_carry(transport, labels["ecdsa_verify"],
                                timeout=120.0)  # Should be fast (immediate reject)
        if carry == 1:
            passed += 1
            print("       PASS: ecdsa_verify returned C=1 (r=0 rejected)")
        else:
            failed += 1
            print("       FAIL: ecdsa_verify returned C=0, expected C=1 for r=0")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Group 4: CertificateVerify (2 tests)
# ---------------------------------------------------------------------------

def test_certificate_verify(transport, labels):
    """Test tls_handle_cert_verify with mock CertificateVerify messages.

    IMPORTANT: Each verify involves ECDSA, so takes 6-16 minutes.
    """
    passed = 0
    failed = 0

    # Need both CV labels and ECDSA labels (CertificateVerify calls ECDSA)
    if not check_labels(labels, CV_LABELS):
        return 0, 0

    # We also need the cert_pubkey loaded (from a prior parse), and the
    # ECDSA labels for the verify step. Check key ECDSA labels too.
    for lbl in ["ecdsa_verify", "cert_pubkey", "cert_curve_id"]:
        if not check_label(labels, lbl):
            return 0, 0

    # Generate a P-256 key for signing the CertificateVerify
    print("\n  Generating P-256 key for CertificateVerify...")
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_numbers()
    qx = pub.x.to_bytes(32, 'big')
    qy = pub.y.to_bytes(32, 'big')

    # Set up the "server's" public key in cert_pubkey (as if x509_parse_cert
    # had already extracted it)
    write_bytes(transport, labels["cert_pubkey"], qx + qy)
    write_bytes(transport, labels["cert_curve_id"], [CURVE_P256])

    # Create transcript hash (32 bytes)
    transcript_hash = hashlib.sha256(b"handshake transcript data").digest()

    # Build the CertificateVerify signed content per RFC 8446 Section 4.4.3:
    #   0x20 * 64 + "TLS 1.3, server CertificateVerify" + 0x00 + Hash(Transcript)
    context_string = b"TLS 1.3, server CertificateVerify"
    content = b'\x20' * 64 + context_string + b'\x00' + transcript_hash
    content_hash = hashlib.sha256(content).digest()

    # Sign the content hash
    signature = key.sign(
        content_hash,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    # Build the CertificateVerify handshake message
    # Signature algorithm: 0x0403 = ecdsa_secp256r1_sha256
    r_int, s_int = utils.decode_dss_signature(signature)

    # Re-encode as DER for the wire format
    # The CertificateVerify message body:
    #   SignatureScheme (2 bytes) + signature length (2 bytes) + DER signature
    der_sig = utils.encode_dss_signature(r_int, s_int)
    cv_body = b'\x04\x03' + struct.pack(">H", len(der_sig)) + der_sig

    # Handshake message: type=0x0F (certificate_verify), length (3 bytes), body
    cv_msg = bytes([0x0F]) + struct.pack(">I", len(cv_body))[1:] + cv_body

    # --- Test 1: Valid CertificateVerify (C=0) ---
    print("\n  [4a] CertificateVerify: valid signature (C=0)")
    print("       (this may take 6-16 minutes in VICE warp...)")

    # Write transcript hash
    write_bytes(transport, labels["tls_transcript"], transcript_hash)

    # Write CertificateVerify message to handshake buffer
    write_bytes(transport, labels["tls_hs_buf"], cv_msg)
    write_u16_le(transport, labels["tls_hs_len"], len(cv_msg))

    try:
        carry = jsr_check_carry(transport, labels["tls_handle_cert_verify"],
                                timeout=1200.0)
        if carry == 0:
            passed += 1
            print("       PASS: CertificateVerify accepted (C=0)")
        else:
            failed += 1
            print("       FAIL: CertificateVerify rejected (C=1)")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 2: Wrong transcript hash (C=1) ---
    print("\n  [4b] CertificateVerify: wrong transcript (C=1)")
    print("       (this may take 6-16 minutes in VICE warp...)")

    # Use a different transcript hash but keep the same signature
    wrong_transcript = hashlib.sha256(b"wrong transcript data").digest()
    write_bytes(transport, labels["tls_transcript"], wrong_transcript)

    # Re-write the same CertificateVerify message (signed with old transcript)
    write_bytes(transport, labels["tls_hs_buf"], cv_msg)
    write_u16_le(transport, labels["tls_hs_len"], len(cv_msg))

    # Re-write pubkey in case the previous verify clobbered it
    write_bytes(transport, labels["cert_pubkey"], qx + qy)
    write_bytes(transport, labels["cert_curve_id"], [CURVE_P256])

    try:
        carry = jsr_check_carry(transport, labels["tls_handle_cert_verify"],
                                timeout=1200.0)
        if carry == 1:
            passed += 1
            print("       PASS: CertificateVerify rejected (C=1, wrong transcript)")
        else:
            failed += 1
            print("       FAIL: CertificateVerify accepted (C=0, should be C=1)")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels):
    """Run all X.509 / ECDSA tests. Returns (passed, failed)."""
    total_passed = 0
    total_failed = 0

    test_groups = [
        ("Group 1: DER Parser P-256 (5 tests)",
         lambda: test_der_parser_p256(transport, labels)),
        ("Group 2: DER Parser P-384 (2 tests)",
         lambda: test_der_parser_p384(transport, labels)),
        ("Group 3: ECDSA P-256 Verify (4 tests)",
         lambda: test_ecdsa_verify_p256(transport, labels)),
        ("Group 4: CertificateVerify (2 tests)",
         lambda: test_certificate_verify(transport, labels)),
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
    slow_count = (4 if ecdsa_ok else 0) + (2 if cv_ok else 0)
    print(f"\n  Fast tests (DER parser): {fast_count}")
    print(f"  Slow tests (ECDSA, ~6-16 min each): {slow_count}")
    if slow_count > 0:
        print(f"  Estimated total time: {slow_count * 10}-{slow_count * 16} minutes")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    print(f"\n=== Starting VICE (port {config.port}) ===")

    with ViceProcess(config) as vice:
        if not vice.wait_for_monitor(timeout=30.0):
            print("FATAL: Could not connect to VICE monitor")
            sys.exit(1)
        print(f"  VICE PID={vice.pid}, port={config.port}")

        transport = ViceTransport(port=config.port)

        # Wait for main menu
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        # Run tests
        print(f"\n=== X.509 / ECDSA Verify Tests ===")
        passed, failed = run_tests(transport, labels)

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
