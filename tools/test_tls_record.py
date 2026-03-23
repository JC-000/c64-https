#!/usr/bin/env python3
"""test_tls_record.py - TLS 1.3 record layer test suite for c64-https.

Tests nonce construction, sequence number increment, record encrypt/decrypt,
and encrypt/decrypt roundtrips by calling C64 routines directly via jsr()
and comparing results against Python ChaCha20-Poly1305 reference.

Usage:
    python3 tools/test_tls_record.py [--seed S] [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc, cryptography
"""

import os
import random
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    ScreenGrid,
    read_bytes,
    write_bytes,
    jsr,
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

# TLS state values
TLS_STATE_IDLE = 0
TLS_STATE_SERVER_HELLO = 2
TLS_STATE_CONNECTED = 7

# Zero-page addresses
ZP_TLS_REC_PTR = 0x1E
ZP_TLS_DIRECTION = 0x21

# Scratch area for trampolines (C64 cassette buffer)
SCRATCH_ADDR = 0x0334

VERBOSE = False

REQUIRED_LABELS = [
    "tls_build_nonce", "tls_record_decrypt", "tls_record_encrypt",
    "tls_nonce",
    "tls_write_seq", "tls_read_seq",
    "tls_hs_write_key", "tls_hs_write_iv",
    "tls_hs_read_key", "tls_hs_read_iv",
    "tls_app_write_key", "tls_app_write_iv",
    "tls_app_read_key", "tls_app_read_iv",
    "tls_rec_buf", "tls_rec_header", "tls_rec_type", "tls_rec_len",
    "tls_state",
    "aead_key", "aead_nonce", "aead_tag", "poly1305_tag",
    "sqtab_init",
    "input_buffer",
]

# Labels that may not exist yet (routines still in development)
OPTIONAL_LABELS = [
    "tls_seq_increment",
]


# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def build_tls_nonce(iv, seq_num):
    """RFC 8446 Section 5.3: nonce = iv XOR (0000 || seq)."""
    padded_seq = b'\x00' * 4 + seq_num  # 4 zero bytes + 8-byte seq = 12 bytes
    return bytes(a ^ b for a, b in zip(iv, padded_seq))


def tls_record_encrypt_ref(key, iv, seq_num, content_type, plaintext):
    """Encrypt a TLS 1.3 record. Returns (header, ciphertext, tag)."""
    nonce = build_tls_nonce(iv, seq_num)
    # Inner plaintext = plaintext + content_type_byte
    inner = plaintext + bytes([content_type])
    # AAD = record header: type=23, version=0x0303, length=len(inner)+16
    total_len = len(inner) + 16
    aad = bytes([23, 3, 3, total_len >> 8, total_len & 0xFF])
    # Encrypt
    cipher = ChaCha20Poly1305(key)
    ct_and_tag = cipher.encrypt(nonce, inner, aad)
    # ct_and_tag = ciphertext + 16-byte tag
    return aad, ct_and_tag[:-16], ct_and_tag[-16:]


def tls_record_decrypt_ref(key, iv, seq_num, header, ciphertext_and_tag):
    """Decrypt a TLS 1.3 record. Returns (plaintext, content_type)."""
    nonce = build_tls_nonce(iv, seq_num)
    cipher = ChaCha20Poly1305(key)
    inner = cipher.decrypt(nonce, ciphertext_and_tag, header)
    # inner = plaintext + content_type_byte
    content_type = inner[-1]
    plaintext = inner[:-1]
    return plaintext, content_type


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def jsr_with_a(transport, addr, a_value, timeout=120.0):
    """Call a subroutine with the A register set to a_value.

    Builds a trampoline at SCRATCH_ADDR:
        LDA #a_value   ; $A9, a_value   (2 bytes)
        JSR addr       ; $20, lo, hi    (3 bytes)
        NOP            ;                (1 byte) <- breakpoint
        NOP            ;                (1 byte)

    Breakpoint at SCRATCH_ADDR + 5, then goto SCRATCH_ADDR.
    """
    lo = addr & 0xFF
    hi = (addr >> 8) & 0xFF
    trampoline = bytes([0xA9, a_value, 0x20, lo, hi, 0xEA, 0xEA])
    write_bytes(transport, SCRATCH_ADDR, trampoline)
    bp_addr = SCRATCH_ADDR + 5
    bp_id = set_breakpoint(transport, bp_addr)
    try:
        goto(transport, SCRATCH_ADDR)
        wait_for_pc(transport, bp_addr, timeout=timeout)
    finally:
        delete_breakpoint(transport, bp_id)


def check_label(labels, name):
    """Return True if label exists, print skip message if not."""
    if labels.address(name) is None:
        print(f"  SKIP: label '{name}' not found (routine not yet implemented)")
        return False
    return True


# ---------------------------------------------------------------------------
# Test group 1: Nonce construction (3 tests)
# ---------------------------------------------------------------------------

def test_nonce_construction(transport, labels):
    """Test tls_build_nonce: XOR IV with sequence number."""
    passed = 0
    failed = 0

    if not check_label(labels, "tls_build_nonce"):
        return 0, 0

    # --- Test 1: Zero sequence number -> nonce equals IV ---
    print("\n  [1a] Nonce: zero seq -> nonce == IV")
    iv = bytes(random.getrandbits(8) for _ in range(12))
    seq = b'\x00' * 8

    write_bytes(transport, labels["tls_hs_write_iv"], iv)
    write_bytes(transport, labels["tls_write_seq"], seq)
    write_bytes(transport, labels["tls_state"], [TLS_STATE_SERVER_HELLO])

    try:
        jsr_with_a(transport, labels["tls_build_nonce"], 0)  # A=0 -> write
        result = read_bytes(transport, labels["tls_nonce"], 12)
        expected = build_tls_nonce(iv, seq)
        if result == expected:
            passed += 1
            print(f"       PASS: nonce = {result.hex()}")
        else:
            failed += 1
            print(f"       FAIL: expected {expected.hex()}, got {result.hex()}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 2: Known sequence number ---
    print("  [1b] Nonce: known seq 0x0000000000000001")
    iv = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C])
    seq = b'\x00' * 7 + b'\x01'  # big-endian 1

    write_bytes(transport, labels["tls_hs_write_iv"], iv)
    write_bytes(transport, labels["tls_write_seq"], seq)
    write_bytes(transport, labels["tls_state"], [TLS_STATE_SERVER_HELLO])

    try:
        jsr_with_a(transport, labels["tls_build_nonce"], 0)
        result = read_bytes(transport, labels["tls_nonce"], 12)
        expected = build_tls_nonce(iv, seq)
        if result == expected:
            passed += 1
            print(f"       PASS: nonce = {result.hex()}")
        else:
            failed += 1
            print(f"       FAIL: expected {expected.hex()}, got {result.hex()}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 3: Read nonce (A=1) with read IV/seq ---
    print("  [1c] Nonce: read direction (A=1)")
    iv_read = bytes(random.getrandbits(8) for _ in range(12))
    seq_read = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05])

    write_bytes(transport, labels["tls_hs_read_iv"], iv_read)
    write_bytes(transport, labels["tls_read_seq"], seq_read)
    write_bytes(transport, labels["tls_state"], [TLS_STATE_SERVER_HELLO])

    try:
        jsr_with_a(transport, labels["tls_build_nonce"], 1)  # A=1 -> read
        result = read_bytes(transport, labels["tls_nonce"], 12)
        expected = build_tls_nonce(iv_read, seq_read)
        if result == expected:
            passed += 1
            print(f"       PASS: nonce = {result.hex()}")
        else:
            failed += 1
            print(f"       FAIL: expected {expected.hex()}, got {result.hex()}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 2: Sequence number increment (3 tests)
# ---------------------------------------------------------------------------

def test_seq_increment(transport, labels):
    """Test tls_seq_increment: 8-byte big-endian increment."""
    passed = 0
    failed = 0

    if not check_label(labels, "tls_seq_increment"):
        return 0, 0

    seq_inc_addr = labels["tls_seq_increment"]
    scratch_buf = labels["input_buffer"]

    test_cases = [
        ("simple 0->1",
         b'\x00\x00\x00\x00\x00\x00\x00\x00',
         b'\x00\x00\x00\x00\x00\x00\x00\x01'),
        ("carry 0x00FF->0x0100",
         b'\x00\x00\x00\x00\x00\x00\x00\xFF',
         b'\x00\x00\x00\x00\x00\x00\x01\x00'),
        ("multi-byte carry 0x00FFFFFF->0x01000000",
         b'\x00\x00\x00\x00\x00\xFF\xFF\xFF',
         b'\x00\x00\x00\x00\x01\x00\x00\x00'),
    ]

    for i, (desc, seq_before, seq_after) in enumerate(test_cases):
        print(f"\n  [2{chr(97+i)}] Seq increment: {desc}")

        # Write seq to scratch area
        write_bytes(transport, scratch_buf, seq_before)

        # Set tls_rec_ptr (ZP $1E-$1F) to point at scratch_buf
        write_bytes(transport, ZP_TLS_REC_PTR,
                    [scratch_buf & 0xFF, (scratch_buf >> 8) & 0xFF])

        try:
            jsr(transport, seq_inc_addr, timeout=30.0)
            result = read_bytes(transport, scratch_buf, 8)

            if result == seq_after:
                passed += 1
                print(f"       PASS: {result.hex()}")
            else:
                failed += 1
                print(f"       FAIL: expected {seq_after.hex()}, got {result.hex()}")
        except Exception as e:
            failed += 1
            print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 3: Record encrypt (3 tests)
# ---------------------------------------------------------------------------

def setup_encrypt(transport, labels, key, iv, seq, state, plaintext,
                  content_type):
    """Set up C64 memory for tls_record_encrypt."""
    if state == TLS_STATE_SERVER_HELLO:
        write_bytes(transport, labels["tls_hs_write_key"], key)
        write_bytes(transport, labels["tls_hs_write_iv"], iv)
    elif state == TLS_STATE_CONNECTED:
        write_bytes(transport, labels["tls_app_write_key"], key)
        write_bytes(transport, labels["tls_app_write_iv"], iv)
    write_bytes(transport, labels["tls_write_seq"], seq)
    write_bytes(transport, labels["tls_state"], [state])
    write_bytes(transport, labels["tls_rec_buf"], plaintext)
    # tls_rec_len is little-endian 16-bit
    pt_len = len(plaintext)
    write_bytes(transport, labels["tls_rec_len"],
                [pt_len & 0xFF, (pt_len >> 8) & 0xFF])
    write_bytes(transport, labels["tls_rec_type"], [content_type])


def read_encrypt_result(transport, labels):
    """Read the encrypted record from C64 after tls_record_encrypt."""
    enc_len_bytes = read_bytes(transport, labels["tls_rec_len"], 2)
    enc_len = enc_len_bytes[0] + enc_len_bytes[1] * 256
    payload = read_bytes(transport, labels["tls_rec_buf"], enc_len)
    header = read_bytes(transport, labels["tls_rec_header"], 5)
    return header, payload


def test_record_encrypt(transport, labels, rng):
    """Test tls_record_encrypt against Python reference."""
    passed = 0
    failed = 0

    if not check_label(labels, "tls_record_encrypt"):
        return 0, 0

    test_cases = [
        {
            "desc": 'short plaintext "Hello", type=23',
            "plaintext": b"Hello",
            "content_type": 23,
        },
        {
            "desc": "handshake content type=22",
            "plaintext": b"\x02\x00\x00\x4d" + bytes(rng.getrandbits(8)
                          for _ in range(20)),
            "content_type": 22,
        },
        {
            "desc": "64-byte plaintext, type=23",
            "plaintext": bytes(rng.getrandbits(8) for _ in range(64)),
            "content_type": 23,
        },
    ]

    for i, tc in enumerate(test_cases):
        print(f"\n  [3{chr(97+i)}] Encrypt: {tc['desc']}")

        key = bytes(rng.getrandbits(8) for _ in range(32))
        iv = bytes(rng.getrandbits(8) for _ in range(12))
        seq = b'\x00' * 8  # start at zero
        plaintext = tc["plaintext"]
        content_type = tc["content_type"]

        # Python reference
        ref_header, ref_ct, ref_tag = tls_record_encrypt_ref(
            key, iv, seq, content_type, plaintext)

        # C64 encrypt
        setup_encrypt(transport, labels, key, iv, seq,
                      TLS_STATE_SERVER_HELLO, plaintext, content_type)

        try:
            jsr(transport, labels["tls_record_encrypt"], timeout=120.0)
            header, payload = read_encrypt_result(transport, labels)

            # payload should be ciphertext + tag
            expected_payload = ref_ct + ref_tag

            if header == ref_header and payload == expected_payload:
                passed += 1
                print(f"       PASS: {len(payload)} bytes, tag OK")
            else:
                failed += 1
                if header != ref_header:
                    print(f"       FAIL header: expected {ref_header.hex()}, "
                          f"got {header.hex()}")
                if payload != expected_payload:
                    print(f"       FAIL payload ({len(payload)} bytes):")
                    print(f"         expected: {expected_payload[:32].hex()}...")
                    print(f"         got:      {payload[:32].hex()}...")
                    # Find first diff
                    for j in range(min(len(payload), len(expected_payload))):
                        if payload[j] != expected_payload[j]:
                            print(f"         first diff at byte {j}")
                            break
        except Exception as e:
            failed += 1
            print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 4: Record decrypt (3 tests)
# ---------------------------------------------------------------------------

def setup_decrypt(transport, labels, key, iv, seq, state, header,
                  ciphertext_and_tag):
    """Set up C64 memory for tls_record_decrypt."""
    if state == TLS_STATE_SERVER_HELLO:
        write_bytes(transport, labels["tls_hs_read_key"], key)
        write_bytes(transport, labels["tls_hs_read_iv"], iv)
    elif state == TLS_STATE_CONNECTED:
        write_bytes(transport, labels["tls_app_read_key"], key)
        write_bytes(transport, labels["tls_app_read_iv"], iv)
    write_bytes(transport, labels["tls_read_seq"], seq)
    write_bytes(transport, labels["tls_state"], [state])
    write_bytes(transport, labels["tls_rec_header"], header)
    write_bytes(transport, labels["tls_rec_buf"], ciphertext_and_tag)
    ct_len = len(ciphertext_and_tag)
    write_bytes(transport, labels["tls_rec_len"],
                [ct_len & 0xFF, (ct_len >> 8) & 0xFF])


def test_record_decrypt(transport, labels, rng):
    """Test tls_record_decrypt against Python reference."""
    passed = 0
    failed = 0

    if not check_label(labels, "tls_record_decrypt"):
        return 0, 0

    # --- Test 4a: Decrypt a Python-encrypted record ---
    print("\n  [4a] Decrypt: Python-encrypted record")

    key = bytes(rng.getrandbits(8) for _ in range(32))
    iv = bytes(rng.getrandbits(8) for _ in range(12))
    seq = b'\x00' * 8
    plaintext = b"Hello, C64!"
    content_type = 23

    ref_header, ref_ct, ref_tag = tls_record_encrypt_ref(
        key, iv, seq, content_type, plaintext)
    ciphertext_and_tag = ref_ct + ref_tag

    setup_decrypt(transport, labels, key, iv, seq,
                  TLS_STATE_SERVER_HELLO, ref_header, ciphertext_and_tag)

    try:
        jsr(transport, labels["tls_record_decrypt"], timeout=120.0)

        # Read decrypted plaintext length
        dec_len_bytes = read_bytes(transport, labels["tls_rec_len"], 2)
        dec_len = dec_len_bytes[0] + dec_len_bytes[1] * 256
        dec_data = read_bytes(transport, labels["tls_rec_buf"], dec_len)
        dec_type = read_bytes(transport, labels["tls_rec_type"], 1)[0]

        if dec_data == plaintext and dec_type == content_type:
            passed += 1
            print(f"       PASS: plaintext recovered, type={dec_type}")
        else:
            failed += 1
            if dec_data != plaintext:
                print(f"       FAIL plaintext: expected {plaintext.hex()}, "
                      f"got {dec_data.hex()}")
            if dec_type != content_type:
                print(f"       FAIL type: expected {content_type}, "
                      f"got {dec_type}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 4b: Tag verification failure (tampered ciphertext) ---
    print("  [4b] Decrypt: tampered ciphertext (tag verify fail)")

    key = bytes(rng.getrandbits(8) for _ in range(32))
    iv = bytes(rng.getrandbits(8) for _ in range(12))
    seq = b'\x00' * 8
    plaintext = b"Tamper test data"
    content_type = 23

    ref_header, ref_ct, ref_tag = tls_record_encrypt_ref(
        key, iv, seq, content_type, plaintext)

    # Tamper with first byte of ciphertext
    tampered_ct = bytes([ref_ct[0] ^ 0xFF]) + ref_ct[1:]
    tampered_payload = tampered_ct + ref_tag

    setup_decrypt(transport, labels, key, iv, seq,
                  TLS_STATE_SERVER_HELLO, ref_header, tampered_payload)

    try:
        regs = jsr(transport, labels["tls_record_decrypt"],
                          timeout=120.0)

        # Expect carry flag set (C=1) indicating AEAD failure
        # The carry flag is bit 0 of the status register (P)
        if regs and "P" in regs:
            carry = regs["P"] & 0x01
            if carry:
                passed += 1
                print("       PASS: decrypt returned C=1 (tag mismatch)")
            else:
                failed += 1
                print("       FAIL: decrypt returned C=0 (should be C=1 "
                      "for tampered data)")
        else:
            # If we can't read P, check if tag comparison area differs
            c64_tag = read_bytes(transport, labels["poly1305_tag"], 16)
            aead_tag = read_bytes(transport, labels["aead_tag"], 16)
            if c64_tag != aead_tag:
                passed += 1
                print("       PASS: tags differ (tamper detected)")
            else:
                failed += 1
                print("       FAIL: tags match despite tampered ciphertext")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 4c: Decrypt with application keys (TLS_STATE_CONNECTED) ---
    print("  [4c] Decrypt: application keys (state=CONNECTED)")

    key = bytes(rng.getrandbits(8) for _ in range(32))
    iv = bytes(rng.getrandbits(8) for _ in range(12))
    seq = b'\x00' * 8
    plaintext = bytes(rng.getrandbits(8) for _ in range(40))
    content_type = 23

    ref_header, ref_ct, ref_tag = tls_record_encrypt_ref(
        key, iv, seq, content_type, plaintext)
    ciphertext_and_tag = ref_ct + ref_tag

    setup_decrypt(transport, labels, key, iv, seq,
                  TLS_STATE_CONNECTED, ref_header, ciphertext_and_tag)

    try:
        jsr(transport, labels["tls_record_decrypt"], timeout=120.0)

        dec_len_bytes = read_bytes(transport, labels["tls_rec_len"], 2)
        dec_len = dec_len_bytes[0] + dec_len_bytes[1] * 256
        dec_data = read_bytes(transport, labels["tls_rec_buf"], dec_len)
        dec_type = read_bytes(transport, labels["tls_rec_type"], 1)[0]

        if dec_data == plaintext and dec_type == content_type:
            passed += 1
            print(f"       PASS: plaintext recovered ({dec_len} bytes), "
                  f"type={dec_type}")
        else:
            failed += 1
            if dec_data != plaintext:
                print(f"       FAIL plaintext: expected {plaintext.hex()}")
                print(f"                       got      {dec_data.hex()}")
            if dec_type != content_type:
                print(f"       FAIL type: expected {content_type}, "
                      f"got {dec_type}")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 5: Encrypt/decrypt roundtrip (5 tests)
# ---------------------------------------------------------------------------

def test_roundtrip(transport, labels, rng):
    """Encrypt on C64, verify against Python, decrypt on C64, verify."""
    passed = 0
    failed = 0

    if not check_label(labels, "tls_record_encrypt"):
        return 0, 0
    if not check_label(labels, "tls_record_decrypt"):
        return 0, 0

    content_types = [23, 22, 23, 23, 21]

    for i in range(5):
        pt_len = rng.randint(1, 100)
        plaintext = bytes(rng.getrandbits(8) for _ in range(pt_len))
        key = bytes(rng.getrandbits(8) for _ in range(32))
        iv = bytes(rng.getrandbits(8) for _ in range(12))
        seq = b'\x00' * 8
        content_type = content_types[i]
        state = TLS_STATE_CONNECTED if i >= 3 else TLS_STATE_SERVER_HELLO

        print(f"\n  [5{chr(97+i)}] Roundtrip: {pt_len}B plaintext, "
              f"type={content_type}, "
              f"state={'CONNECTED' if state == TLS_STATE_CONNECTED else 'HS'}")

        # Python reference
        ref_header, ref_ct, ref_tag = tls_record_encrypt_ref(
            key, iv, seq, content_type, plaintext)

        # --- Encrypt on C64 ---
        setup_encrypt(transport, labels, key, iv, seq, state,
                      plaintext, content_type)

        try:
            jsr(transport, labels["tls_record_encrypt"], timeout=120.0)
            header, payload = read_encrypt_result(transport, labels)
        except Exception as e:
            failed += 1
            print(f"       FAIL encrypt: {e}")
            continue

        expected_payload = ref_ct + ref_tag
        if header != ref_header or payload != expected_payload:
            failed += 1
            print("       FAIL: C64 encrypt mismatch with Python reference")
            if header != ref_header:
                print(f"         header: expected {ref_header.hex()}, "
                      f"got {header.hex()}")
            if payload != expected_payload:
                print(f"         payload len: expected {len(expected_payload)}, "
                      f"got {len(payload)}")
            continue

        # --- Decrypt on C64 ---
        # Use read keys for decrypt (simulate receiving our own record)
        if state == TLS_STATE_SERVER_HELLO:
            write_bytes(transport, labels["tls_hs_read_key"], key)
            write_bytes(transport, labels["tls_hs_read_iv"], iv)
        else:
            write_bytes(transport, labels["tls_app_read_key"], key)
            write_bytes(transport, labels["tls_app_read_iv"], iv)

        # Reset read seq to zero (encrypt may have incremented write seq)
        write_bytes(transport, labels["tls_read_seq"], seq)
        # Re-write encrypted payload and header for decrypt
        write_bytes(transport, labels["tls_rec_buf"], payload)
        write_bytes(transport, labels["tls_rec_header"], header)
        enc_len = len(payload)
        write_bytes(transport, labels["tls_rec_len"],
                    [enc_len & 0xFF, (enc_len >> 8) & 0xFF])

        try:
            jsr(transport, labels["tls_record_decrypt"], timeout=120.0)
        except Exception as e:
            failed += 1
            print(f"       FAIL decrypt: {e}")
            continue

        dec_len_bytes = read_bytes(transport, labels["tls_rec_len"], 2)
        dec_len = dec_len_bytes[0] + dec_len_bytes[1] * 256
        dec_data = read_bytes(transport, labels["tls_rec_buf"], dec_len)
        dec_type = read_bytes(transport, labels["tls_rec_type"], 1)[0]

        if dec_data == plaintext and dec_type == content_type:
            passed += 1
            print(f"       PASS: roundtrip OK ({pt_len} bytes)")
        else:
            failed += 1
            if dec_data != plaintext:
                print(f"       FAIL plaintext: expected {plaintext[:16].hex()}..."
                      f" ({len(plaintext)}B)")
                print(f"                       got      {dec_data[:16].hex()}..."
                      f" ({len(dec_data)}B)")
            if dec_type != content_type:
                print(f"       FAIL type: expected {content_type}, "
                      f"got {dec_type}")

    return passed, failed


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels, seed):
    """Run all TLS record layer tests. Returns (passed, failed)."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    # Initialize sqtab (required for Poly1305 multiply)
    print("\n  Initializing sqtab...")
    jsr(transport, labels["sqtab_init"], timeout=60.0)
    print("  sqtab ready")

    test_groups = [
        ("Nonce construction (3 tests)",
         lambda: test_nonce_construction(transport, labels)),
        ("Sequence number increment (3 tests)",
         lambda: test_seq_increment(transport, labels)),
        ("Record encrypt (3 tests)",
         lambda: test_record_encrypt(transport, labels, rng)),
        ("Record decrypt (3 tests)",
         lambda: test_record_decrypt(transport, labels, rng)),
        ("Encrypt/decrypt roundtrip (5 tests)",
         lambda: test_roundtrip(transport, labels, rng)),
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

    missing = []
    for name in REQUIRED_LABELS:
        if labels.address(name) is None:
            missing.append(name)
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)

    # Check optional labels
    for name in OPTIONAL_LABELS:
        if labels.address(name) is None:
            print(f"  NOTE: optional label '{name}' not found (tests will skip)")

    print(f"  Labels loaded: {len(REQUIRED_LABELS)} required labels verified")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    print(f"\n=== Starting VICE ===")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        # Wait for main menu (binary monitor: resume CPU between polls)
        print("  Waiting for main menu...")
        grid = None
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            g = ScreenGrid.from_transport(transport)
            if "Q=QUIT" in g.continuous_text().upper():
                grid = g
                break
            transport.resume()
            time.sleep(1.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        # Run tests
        print(f"\n=== TLS 1.3 Record Layer Tests ===")
        passed, failed = run_tests(transport, labels, seed)

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
        print(f"\n  [+] TLS RECORD LAYER: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] TLS RECORD LAYER: {failed} TEST(S) FAILED")
    print(f"{'='*60}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
