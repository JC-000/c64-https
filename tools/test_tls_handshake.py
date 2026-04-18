#!/usr/bin/env python3
"""test_tls_handshake.py - TLS 1.3 handshake test suite for c64-https.

Tests the TLS 1.3 handshake routines: streaming transcript hash,
ClientHello construction, ServerHello parsing, key schedule derivation,
and Finished MAC computation, by calling C64 routines directly via jsr()
and comparing results against Python reference / RFC 8448 test vectors.

Usage:
    python3 tools/test_tls_handshake.py [--seed S] [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import hashlib
import hmac
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

# Zero-page addresses
ZP_PTR = 0xFB        # zp_ptr ($FB-$FC)
ZP_COUNT = 0xFE      # zp_count ($FE-$FF) — 16-bit LE count

# ---------------------------------------------------------------------------
# RFC 8448 Section 3 test values (Simple 1-RTT Handshake)
# The key schedule uses SHA-256 regardless of AEAD cipher.
# ---------------------------------------------------------------------------

EARLY_SECRET = bytes.fromhex(
    "33ad0a1c607ec03b09e6cd9893680ce2"
    "10adf300aa1f2660e1b22e10f170f92a"
)

DERIVED_FROM_EARLY = bytes.fromhex(
    "6f2615a108c702c5678f54fc9dbab697"
    "16c076189c48250cebeac3576c3611ba"
)

# ECDH shared secret (x25519 in RFC 8448)
SHARED_SECRET = bytes.fromhex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d"
    "35e6d63f537563efd46272900f89492d"
)

HANDSHAKE_SECRET = bytes.fromhex(
    "1dc826e93606aa6fdc0aadc12f741b01"
    "046aa6b99f691ed221a9f0ca043fbeac"
)

# Transcript hash after ClientHello || ServerHello
TRANSCRIPT_CH_SH = bytes.fromhex(
    "860c06edc07858ee8e78f0e7428c58ed"
    "d6b43f2ca3e6e95f02ed063cf0e1cad8"
)

CLIENT_HS_TRAFFIC_SECRET = bytes.fromhex(
    "b3eddb126e067f35a780b3abf45e2d8f"
    "3b1a950738f52e9600746a0e27a55a21"
)

SERVER_HS_TRAFFIC_SECRET = bytes.fromhex(
    "b67b7d690cc16c4e75e54213cb2d37b4"
    "e9c912bcded9105d42befd59d391ad38"
)

DERIVED_FROM_HS = bytes.fromhex(
    "43de77e0c77713859a944db9db2590b5"
    "3190a65b3ee2e4f12dd7a0bb7ce254b4"
)

MASTER_SECRET = bytes.fromhex(
    "18df06843d13a08bf2a449844c5f8a47"
    "8001bc4d4c627984d5a41da8d0402919"
)

SERVER_FINISHED_VERIFY = bytes.fromhex(
    "9b9b141d906337fbd2cbdce71df4deda"
    "4ab42c309572cb7fffee5454b78f0718"
)

CLIENT_FINISHED_VERIFY = bytes.fromhex(
    "a8ec436d677634ae525ac1fcebe11a03"
    "9ec17694fac6e98527b642f2edd5ce61"
)

EMPTY_HASH = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"
)


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


def derive_secret_ref(secret, label, transcript_hash):
    """TLS 1.3 Derive-Secret (RFC 8446 Section 7.1)."""
    return hkdf_expand_label_ref(secret, label, transcript_hash, 32)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCRATCH_ADDR = 0x0334
CARRY_RESULT = 0x033F  # 1 byte: 0=carry clear, 1=carry set

def jsr_check_carry(transport, addr, timeout=120.0):
    """Call a subroutine and capture the carry flag result.

    Builds trampoline at SCRATCH_ADDR:
        JSR addr       ; 3 bytes
        LDA #0         ; 2 bytes
        ROL A          ; 1 byte — A = carry
        STA $033F      ; 3 bytes — store carry result
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


def check_labels(labels, names):
    """Return True if all labels exist, print skip for first missing."""
    for name in names:
        if not check_label(labels, name):
            return False
    return True


# ---------------------------------------------------------------------------
# C64 helper functions
# ---------------------------------------------------------------------------

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

    jsr(transport, labels["hkdf_extract"], timeout=120.0)
    return read_bytes(transport, labels["hkdf_prk"], 32)


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

    jsr(transport, labels["hkdf_expand_label"], timeout=120.0)
    return read_bytes(transport, labels["hkdf_okm"], length)


# ---------------------------------------------------------------------------
# Test group 1: Streaming transcript hash (4 tests)
# ---------------------------------------------------------------------------

def test_transcript_hash(transport, labels, rng):
    """Test tls_transcript_init, tls_transcript_update, tls_transcript_hash."""
    passed = 0
    failed = 0

    required = [
        "tls_transcript_init", "tls_transcript_update",
        "tls_transcript_hash", "tls_transcript", "input_buffer",
    ]
    if not check_labels(labels, required):
        return 0, 0

    transcript_init = labels["tls_transcript_init"]
    transcript_update = labels["tls_transcript_update"]
    transcript_hash = labels["tls_transcript_hash"]
    transcript_out = labels["tls_transcript"]
    input_buf = labels["input_buffer"]

    def feed_chunk(data):
        """Write data to input_buffer, set zp_ptr and zp_count (16-bit), call update."""
        write_bytes(transport, input_buf, data)
        write_bytes(transport, ZP_PTR,
                    [input_buf & 0xFF, (input_buf >> 8) & 0xFF])
        write_bytes(transport, ZP_COUNT,
                    [len(data) & 0xFF, (len(data) >> 8) & 0xFF])
        jsr(transport, transcript_update, timeout=120.0)

    def get_hash():
        """Call tls_transcript_hash and read 32-byte result."""
        jsr(transport, transcript_hash, timeout=120.0)
        return read_bytes(transport, transcript_out, 32)

    # --- Test 1a: Init + hash empty -> SHA-256("") ---
    print("\n  [1a] Transcript: init + hash empty -> SHA-256(\"\")")
    try:
        jsr(transport, transcript_init, timeout=60.0)
        result = get_hash()
        if result == EMPTY_HASH:
            passed += 1
            print(f"       PASS: {result[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {EMPTY_HASH[:8].hex()}...")
            print(f"             got      {result[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 1b: Feed "abc" (3 bytes) ---
    print("  [1b] Transcript: feed \"abc\" (3 bytes)")
    expected = hashlib.sha256(b"abc").digest()
    try:
        jsr(transport, transcript_init, timeout=60.0)
        feed_chunk(b"abc")
        result = get_hash()
        if result == expected:
            passed += 1
            print(f"       PASS: {result[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {expected[:8].hex()}...")
            print(f"             got      {result[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 1c: 100 bytes in two chunks (60 + 40) ---
    print("  [1c] Transcript: 100 bytes in two chunks (60 + 40)")
    data = bytes(rng.getrandbits(8) for _ in range(100))
    expected = hashlib.sha256(data).digest()
    try:
        jsr(transport, transcript_init, timeout=60.0)
        feed_chunk(data[:60])
        feed_chunk(data[60:])
        result = get_hash()
        if result == expected:
            passed += 1
            print(f"       PASS: {result[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {expected[:8].hex()}...")
            print(f"             got      {result[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 1d: 200 bytes in three chunks (80 + 70 + 50) ---
    print("  [1d] Transcript: 200 bytes in three chunks (80 + 70 + 50)")
    data = bytes(rng.getrandbits(8) for _ in range(200))
    expected = hashlib.sha256(data).digest()
    try:
        jsr(transport, transcript_init, timeout=60.0)
        feed_chunk(data[:80])
        feed_chunk(data[80:150])
        feed_chunk(data[150:])
        result = get_hash()
        if result == expected:
            passed += 1
            print(f"       PASS: {result[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {expected[:8].hex()}...")
            print(f"             got      {result[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 2: ClientHello format (3 tests)
# ---------------------------------------------------------------------------

def test_client_hello(transport, labels, rng):
    """Test tls_build_client_hello: verify structure and fields."""
    passed = 0
    failed = 0

    required = [
        "tls_build_client_hello", "tls_rec_buf", "tls_rec_len",
        "tls_client_random", "tls_ecdhe_pubkey",
    ]
    if not check_labels(labels, required):
        return 0, 0

    build_ch = labels["tls_build_client_hello"]
    hs_buf = labels["tls_rec_buf"]
    hs_len_addr = labels["tls_rec_len"]

    # Write known client_random and pubkey
    client_random = bytes(rng.getrandbits(8) for _ in range(32))
    pubkey = bytes(rng.getrandbits(8) for _ in range(65))
    pubkey = bytes([0x04]) + pubkey[1:]  # uncompressed point prefix

    write_bytes(transport, labels["tls_client_random"], client_random)
    write_bytes(transport, labels["tls_ecdhe_pubkey"], pubkey)

    try:
        jsr(transport, build_ch, timeout=120.0)
    except Exception as e:
        print(f"\n  ClientHello build failed: {e}")
        return 0, 3  # all 3 tests fail

    # Read the handshake message length
    len_bytes = read_bytes(transport, hs_len_addr, 2)
    msg_len = len_bytes[0] | (len_bytes[1] << 8)

    if msg_len == 0:
        print("\n  SKIP: tls_build_client_hello produced 0-length output "
              "(stub not yet implemented)")
        return 0, 0

    # Read the handshake message
    msg = read_bytes(transport, hs_buf, min(msg_len, 256))

    # --- Test 2a: Handshake type and version ---
    print("\n  [2a] ClientHello: handshake type and legacy version")
    try:
        ok = True
        # Byte [0] = handshake type 0x01 (ClientHello)
        if msg[0] != 0x01:
            print(f"       FAIL: handshake type = 0x{msg[0]:02X}, expected 0x01")
            ok = False
        # Bytes [4-5] = legacy version 0x03 0x03
        if msg[4] != 0x03 or msg[5] != 0x03:
            print(f"       FAIL: version = 0x{msg[4]:02X}{msg[5]:02X}, "
                  f"expected 0x0303")
            ok = False
        if ok:
            passed += 1
            print("       PASS: type=0x01, version=0x0303")
        else:
            failed += 1
    except (IndexError, Exception) as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 2b: Client random ---
    print("  [2b] ClientHello: client_random at offset 6")
    try:
        extracted_random = msg[6:38]
        if extracted_random == client_random:
            passed += 1
            print(f"       PASS: client_random = {extracted_random[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {client_random[:8].hex()}...")
            print(f"             got      {extracted_random[:8].hex()}...")
    except (IndexError, Exception) as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 2c: Cipher suite and extensions ---
    print("  [2c] ClientHello: cipher suite and key extensions")
    try:
        ok = True
        # After random (38), skip session_id (1 byte length + data)
        pos = 38
        session_id_len = msg[pos]
        pos += 1 + session_id_len

        # Cipher suites: 2-byte length, then suites
        cs_len = (msg[pos] << 8) | msg[pos + 1]
        pos += 2
        cipher_suites = msg[pos:pos + cs_len]

        # Check that 0x1303 (TLS_CHACHA20_POLY1305_SHA256) is in the list
        found_1303 = False
        for i in range(0, len(cipher_suites), 2):
            if cipher_suites[i] == 0x13 and cipher_suites[i + 1] == 0x03:
                found_1303 = True
                break
        if not found_1303:
            print(f"       FAIL: cipher suite 0x1303 not found in "
                  f"{cipher_suites.hex()}")
            ok = False
        pos += cs_len

        # Skip compression methods (1 byte length + data)
        comp_len = msg[pos]
        pos += 1 + comp_len

        # Extensions: 2-byte total length, then extension list
        ext_total_len = (msg[pos] << 8) | msg[pos + 1]
        pos += 2
        ext_end = pos + ext_total_len

        # Parse extensions looking for supported_versions and key_share
        found_versions = False
        found_key_share = False

        while pos + 4 <= ext_end and pos + 4 <= len(msg):
            ext_type = (msg[pos] << 8) | msg[pos + 1]
            ext_len = (msg[pos + 2] << 8) | msg[pos + 3]
            ext_data = msg[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len

            # supported_versions (0x002B)
            if ext_type == 0x002B:
                # Should contain 0x0304 (TLS 1.3)
                if b'\x03\x04' in ext_data:
                    found_versions = True

            # key_share (0x0033)
            if ext_type == 0x0033:
                # Should contain group 0x001D (x25519) or 0x0017 (secp256r1)
                # and our public key
                if len(ext_data) >= 4:
                    found_key_share = True

        if not found_versions:
            print("       FAIL: supported_versions extension with 0x0304 "
                  "not found")
            ok = False
        if not found_key_share:
            print("       FAIL: key_share extension not found")
            ok = False

        if ok:
            passed += 1
            print("       PASS: cipher=0x1303, supported_versions=0x0304, "
                  "key_share present")
        else:
            failed += 1
    except (IndexError, Exception) as e:
        failed += 1
        print(f"       FAIL: parse error: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 3: ServerHello parse (3 tests)
# ---------------------------------------------------------------------------

def build_server_hello(server_random, cipher_suite, session_id,
                       key_share_group=None, key_share_pubkey=None,
                       include_versions=True):
    """Build a ServerHello message (without the handshake header)."""
    msg = bytearray()

    # legacy_version (2 bytes)
    msg.extend(b'\x03\x03')

    # server random (32 bytes)
    msg.extend(server_random)

    # session_id echo (length-prefixed)
    msg.append(len(session_id))
    msg.extend(session_id)

    # cipher suite (2 bytes)
    msg.extend(cipher_suite)

    # compression method (1 byte)
    msg.append(0x00)

    # Build extensions
    exts = bytearray()

    # supported_versions extension (0x002B)
    if include_versions:
        exts.extend(b'\x00\x2B')  # extension type
        exts.extend(b'\x00\x02')  # extension length
        exts.extend(b'\x03\x04')  # TLS 1.3

    # key_share extension (0x0033)
    if key_share_group is not None and key_share_pubkey is not None:
        key_share_data = bytearray()
        key_share_data.extend(key_share_group)  # group (2 bytes)
        key_share_data.extend(struct.pack(">H", len(key_share_pubkey)))
        key_share_data.extend(key_share_pubkey)

        exts.extend(b'\x00\x33')  # extension type
        exts.extend(struct.pack(">H", len(key_share_data)))
        exts.extend(key_share_data)

    # extensions length (2 bytes)
    msg.extend(struct.pack(">H", len(exts)))
    msg.extend(exts)

    return bytes(msg)


def test_server_hello_parse(transport, labels, rng):
    """Test tls_parse_server_hello: extract fields and detect errors."""
    passed = 0
    failed = 0

    required = [
        "tls_parse_server_hello", "tls_rec_buf", "tls_rec_len",
        "tls_server_random", "tls_server_pubkey",
    ]
    if not check_labels(labels, required):
        return 0, 0

    parse_sh = labels["tls_parse_server_hello"]
    hs_buf = labels["tls_rec_buf"]
    hs_len_addr = labels["tls_rec_len"]

    # --- Test 3a: Valid ServerHello with x25519 ---
    print("\n  [3a] ServerHello: valid parse (x25519, cipher 0x1303)")
    server_random = bytes(rng.getrandbits(8) for _ in range(32))
    server_pubkey = bytes(rng.getrandbits(8) for _ in range(32))  # x25519 = 32 bytes
    session_id = b''

    sh_body = build_server_hello(
        server_random=server_random,
        cipher_suite=b'\x13\x03',
        session_id=session_id,
        key_share_group=b'\x00\x1D',  # x25519
        key_share_pubkey=server_pubkey,
    )

    # Write to tls_rec_buf with handshake header
    hs_msg = bytes([0x02]) + struct.pack(">I", len(sh_body))[1:] + sh_body
    write_bytes(transport, hs_buf, hs_msg)
    write_bytes(transport, hs_len_addr,
                [len(hs_msg) & 0xFF, (len(hs_msg) >> 8) & 0xFF])

    try:
        regs = jsr(transport, parse_sh, timeout=120.0)

        # Check carry flag (C=0 means success)
        carry = 0
        if regs and "P" in regs:
            carry = regs["P"] & 0x01

        if carry == 0:
            # Verify server_random was extracted
            got_random = read_bytes(transport, labels["tls_server_random"], 32)
            # Verify server pubkey was extracted
            got_pubkey = read_bytes(transport, labels["tls_server_pubkey"], 32)

            random_ok = (got_random == server_random)
            pubkey_ok = (got_pubkey == server_pubkey)

            if random_ok and pubkey_ok:
                passed += 1
                print(f"       PASS: server_random and pubkey extracted correctly")
            else:
                failed += 1
                if not random_ok:
                    print(f"       FAIL: server_random mismatch")
                    print(f"         expected: {server_random[:8].hex()}...")
                    print(f"         got:      {got_random[:8].hex()}...")
                if not pubkey_ok:
                    print(f"       FAIL: server_pubkey mismatch")
                    print(f"         expected: {server_pubkey[:8].hex()}...")
                    print(f"         got:      {got_pubkey[:8].hex()}...")
        else:
            # Parser returned error but it might be a stub
            # Check if the implementation is a stub (just clc; rts)
            code = read_bytes(transport, parse_sh, 2)
            if code == bytes([0x18, 0x60]):  # CLC; RTS
                print("       SKIP: tls_parse_server_hello is a stub (clc; rts)")
                return 0, 0
            failed += 1
            print("       FAIL: parser returned C=1 (error) for valid ServerHello")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # Check if this is a stub before running error tests
    code = read_bytes(transport, parse_sh, 3)
    if code[:2] == bytes([0x18, 0x60]):  # CLC; RTS
        print("  SKIP: remaining ServerHello tests (stub implementation)")
        return 0, 0

    # --- Test 3b: Wrong cipher suite -> C=1 ---
    print("  [3b] ServerHello: wrong cipher suite -> error")
    sh_body_bad_cipher = build_server_hello(
        server_random=server_random,
        cipher_suite=b'\x13\x01',  # TLS_AES_128_GCM_SHA256, not supported
        session_id=session_id,
        key_share_group=b'\x00\x1D',
        key_share_pubkey=server_pubkey,
    )
    hs_msg = bytes([0x02]) + struct.pack(">I", len(sh_body_bad_cipher))[1:] + sh_body_bad_cipher
    write_bytes(transport, hs_buf, hs_msg)
    write_bytes(transport, hs_len_addr,
                [len(hs_msg) & 0xFF, (len(hs_msg) >> 8) & 0xFF])

    try:
        carry = jsr_check_carry(transport, parse_sh, timeout=120.0)
        if carry == 1:
            passed += 1
            print("       PASS: returned C=1 for wrong cipher suite")
        else:
            failed += 1
            print("       FAIL: returned C=0, expected C=1 for wrong cipher")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 3c: Missing key_share extension -> C=1 ---
    print("  [3c] ServerHello: missing key_share -> error")
    sh_body_no_ks = build_server_hello(
        server_random=server_random,
        cipher_suite=b'\x13\x03',
        session_id=session_id,
        key_share_group=None,
        key_share_pubkey=None,
        include_versions=True,
    )
    hs_msg = bytes([0x02]) + struct.pack(">I", len(sh_body_no_ks))[1:] + sh_body_no_ks
    write_bytes(transport, hs_buf, hs_msg)
    write_bytes(transport, hs_len_addr,
                [len(hs_msg) & 0xFF, (len(hs_msg) >> 8) & 0xFF])

    try:
        carry = jsr_check_carry(transport, parse_sh, timeout=120.0)
        if carry == 1:
            passed += 1
            print("       PASS: returned C=1 for missing key_share")
        else:
            failed += 1
            print("       FAIL: returned C=0, expected C=1 for missing key_share")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 4: Key schedule (5 tests)
# ---------------------------------------------------------------------------

def test_key_schedule_steps(transport, labels):
    """Test key schedule step-by-step via individual jsr() calls.

    VICE 3.9 crashes when 5+ HMAC-SHA256 calls are chained in a single
    continuous execution. This test calls each HKDF step individually,
    which works around the VICE bug while verifying the assembly code
    produces correct RFC 8448 values.
    """
    passed = 0
    failed = 0

    required = [
        "hkdf_extract", "hkdf_expand_label", "tls_derive_secret",
        "hkdf_prk", "hkdf_okm", "hkdf_salt_ptr", "hkdf_salt_len",
        "hkdf_ikm_ptr", "hkdf_ikm_len", "hkdf_label_ptr", "hkdf_label_len",
        "hkdf_context_ptr", "hkdf_context_len", "hkdf_out_len",
        "input_buffer", "tls_shared_secret", "tls_transcript",
        "lbl_derived", "lbl_c_hs_traffic", "lbl_s_hs_traffic",
        "lbl_key", "lbl_iv", "empty_hash",
    ]
    if not check_labels(labels, required):
        return 0, 0

    def do_extract(salt_data, ikm_data):
        ib = labels["input_buffer"]
        write_bytes(transport, ib, salt_data + ikm_data)
        write_bytes(transport, labels["hkdf_salt_ptr"],
                    [ib & 0xFF, ib >> 8])
        write_bytes(transport, labels["hkdf_salt_len"], [len(salt_data)])
        ikm_addr = ib + len(salt_data)
        write_bytes(transport, labels["hkdf_ikm_ptr"],
                    [ikm_addr & 0xFF, ikm_addr >> 8])
        write_bytes(transport, labels["hkdf_ikm_len"], [len(ikm_data)])
        jsr(transport, labels["hkdf_extract"], timeout=30)
        return read_bytes(transport, labels["hkdf_prk"], 32)

    def do_expand_label(prk, label_addr, label_len, ctx_addr, ctx_len, out_len):
        write_bytes(transport, labels["hkdf_prk"], prk)
        write_bytes(transport, labels["hkdf_label_ptr"],
                    [label_addr & 0xFF, label_addr >> 8])
        write_bytes(transport, labels["hkdf_label_len"], [label_len])
        write_bytes(transport, labels["hkdf_context_ptr"],
                    [ctx_addr & 0xFF, ctx_addr >> 8])
        write_bytes(transport, labels["hkdf_context_len"], [ctx_len])
        write_bytes(transport, labels["hkdf_out_len"], [out_len])
        jsr(transport, labels["hkdf_expand_label"], timeout=30)
        return read_bytes(transport, labels["hkdf_okm"], out_len)

    def do_derive_secret(prk, label_addr, label_len, transcript):
        write_bytes(transport, labels["hkdf_prk"], prk)
        write_bytes(transport, labels["tls_transcript"], transcript)
        write_bytes(transport, labels["hkdf_label_ptr"],
                    [label_addr & 0xFF, label_addr >> 8])
        write_bytes(transport, labels["hkdf_label_len"], [label_len])
        jsr(transport, labels["tls_derive_secret"], timeout=30)
        return read_bytes(transport, labels["hkdf_okm"], 32)

    def check(name, got, expected):
        nonlocal passed, failed
        if got == expected:
            passed += 1
            print(f"       PASS: {got[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {expected[:8].hex()}...")
            print(f"             got      {got[:8].hex()}...")

    # Step 1: early_secret
    print("  [4a] early_secret = Extract(zeros, zeros)")
    early = do_extract(bytes(32), bytes(32))
    check("early_secret", early, EARLY_SECRET)

    # Step 2: derived
    print("  [4b] derived = Expand-Label(early, 'derived', empty_hash)")
    derived = do_expand_label(early, labels["lbl_derived"], 7,
                              labels["empty_hash"], 32, 32)
    check("derived", derived, DERIVED_FROM_EARLY)

    # Step 3: handshake_secret
    print("  [4c] handshake_secret = Extract(derived, shared)")
    hs_secret = do_extract(derived, SHARED_SECRET)
    check("handshake_secret", hs_secret, HANDSHAKE_SECRET)

    # Step 4: c_hs_traffic
    print("  [4d] c_hs_traffic = Derive-Secret(hs, 'c hs traffic')")
    c_hs = do_derive_secret(hs_secret, labels["lbl_c_hs_traffic"], 12,
                            TRANSCRIPT_CH_SH)
    check("c_hs_traffic", c_hs, CLIENT_HS_TRAFFIC_SECRET)

    # Step 5: s_hs_traffic
    print("  [4e] s_hs_traffic = Derive-Secret(hs, 's hs traffic')")
    s_hs = do_derive_secret(hs_secret, labels["lbl_s_hs_traffic"], 12,
                            TRANSCRIPT_CH_SH)
    check("s_hs_traffic", s_hs, SERVER_HS_TRAFFIC_SECRET)

    # Step 6: client key
    print("  [4f] client_key = Expand-Label(c_hs, 'key', '', 32)")
    client_key = do_expand_label(c_hs, labels["lbl_key"], 3,
                                 labels["empty_hash"], 0, 32)
    expected_ck = hkdf_expand_label_ref(c_hs, b"key", b"", 32)
    check("client_key", client_key, expected_ck)

    # Step 7: client iv
    print("  [4g] client_iv = Expand-Label(c_hs, 'iv', '', 12)")
    client_iv = do_expand_label(c_hs, labels["lbl_iv"], 2,
                                labels["empty_hash"], 0, 12)
    expected_civ = hkdf_expand_label_ref(c_hs, b"iv", b"", 12)
    check("client_iv", client_iv, expected_civ)

    # Step 8: server key
    print("  [4h] server_key = Expand-Label(s_hs, 'key', '', 32)")
    server_key = do_expand_label(s_hs, labels["lbl_key"], 3,
                                 labels["empty_hash"], 0, 32)
    expected_sk = hkdf_expand_label_ref(s_hs, b"key", b"", 32)
    check("server_key", server_key, expected_sk)

    # Step 9: server iv
    print("  [4i] server_iv = Expand-Label(s_hs, 'iv', '', 12)")
    server_iv = do_expand_label(s_hs, labels["lbl_iv"], 2,
                                labels["empty_hash"], 0, 12)
    expected_siv = hkdf_expand_label_ref(s_hs, b"iv", b"", 12)
    check("server_iv", server_iv, expected_siv)

    return passed, failed


def test_key_schedule(transport, labels):
    """Test tls_derive_handshake_keys with RFC 8448 values."""
    passed = 0
    failed = 0

    required = [
        "tls_derive_handshake_keys",
        "tls_shared_secret", "tls_transcript",
        "tls_early_secret", "tls_handshake_secret",
        "tls_hs_write_key", "tls_hs_write_iv",
        "tls_hs_read_key", "tls_hs_read_iv",
        "hkdf_extract", "hkdf_expand_label",
    ]
    if not check_labels(labels, required):
        return 0, 0

    derive_hs = labels["tls_derive_handshake_keys"]

    # Check if this is a stub (clc; rts)
    code = read_bytes(transport, derive_hs, 2)
    if code == bytes([0x18, 0x60]):
        print("\n  SKIP: tls_derive_handshake_keys is a stub (clc; rts)")
        return 0, 0

    # Set up inputs: shared secret and transcript hash
    write_bytes(transport, labels["tls_shared_secret"], SHARED_SECRET)
    write_bytes(transport, labels["tls_transcript"], TRANSCRIPT_CH_SH)

    print("\n  [4a-e] Key schedule: calling tls_derive_handshake_keys "
          "(this may take several minutes)...")

    try:
        jsr(transport, derive_hs, timeout=600.0)
    except Exception as e:
        print(f"\n  FAIL: tls_derive_handshake_keys raised {e}")
        return 0, 5

    # --- Test 4a: Early secret ---
    print("  [4a] Key schedule: early_secret")
    got_early = read_bytes(transport, labels["tls_early_secret"], 32)
    if got_early == EARLY_SECRET:
        passed += 1
        print(f"       PASS: {got_early[:8].hex()}...")
    else:
        failed += 1
        print(f"       FAIL: expected {EARLY_SECRET[:8].hex()}...")
        print(f"             got      {got_early[:8].hex()}...")

    # --- Test 4b: Handshake secret ---
    print("  [4b] Key schedule: handshake_secret")
    got_hs = read_bytes(transport, labels["tls_handshake_secret"], 32)
    if got_hs == HANDSHAKE_SECRET:
        passed += 1
        print(f"       PASS: {got_hs[:8].hex()}...")
    else:
        failed += 1
        print(f"       FAIL: expected {HANDSHAKE_SECRET[:8].hex()}...")
        print(f"             got      {got_hs[:8].hex()}...")

    # --- Test 4c: Client handshake traffic key ---
    # For ChaCha20-Poly1305, key length = 32 bytes
    print("  [4c] Key schedule: client handshake write key")
    expected_client_key = hkdf_expand_label_ref(
        CLIENT_HS_TRAFFIC_SECRET, b"key", b"", 32)
    got_client_key = read_bytes(transport, labels["tls_hs_write_key"], 32)
    if got_client_key == expected_client_key:
        passed += 1
        print(f"       PASS: {got_client_key[:8].hex()}...")
    else:
        failed += 1
        print(f"       FAIL: expected {expected_client_key[:8].hex()}...")
        print(f"             got      {got_client_key[:8].hex()}...")

    # --- Test 4d: Client handshake traffic IV ---
    print("  [4d] Key schedule: client handshake write IV")
    expected_client_iv = hkdf_expand_label_ref(
        CLIENT_HS_TRAFFIC_SECRET, b"iv", b"", 12)
    got_client_iv = read_bytes(transport, labels["tls_hs_write_iv"], 12)
    if got_client_iv == expected_client_iv:
        passed += 1
        print(f"       PASS: {got_client_iv.hex()}")
    else:
        failed += 1
        print(f"       FAIL: expected {expected_client_iv.hex()}")
        print(f"             got      {got_client_iv.hex()}")

    # --- Test 4e: Server handshake read key ---
    print("  [4e] Key schedule: server handshake read key")
    expected_server_key = hkdf_expand_label_ref(
        SERVER_HS_TRAFFIC_SECRET, b"key", b"", 32)
    got_server_key = read_bytes(transport, labels["tls_hs_read_key"], 32)
    if got_server_key == expected_server_key:
        passed += 1
        print(f"       PASS: {got_server_key[:8].hex()}...")
    else:
        failed += 1
        print(f"       FAIL: expected {expected_server_key[:8].hex()}...")
        print(f"             got      {got_server_key[:8].hex()}...")

    return passed, failed


# ---------------------------------------------------------------------------
# Test group 5: Finished MAC (2 tests)
# ---------------------------------------------------------------------------

def test_finished_mac(transport, labels):
    """Test Finished verify_data computation against RFC 8448 values."""
    passed = 0
    failed = 0

    # The Finished MAC is: HMAC-SHA256(finished_key, transcript_hash)
    # where finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
    #
    # We test this by:
    #   1. Computing finished_key in Python
    #   2. Setting up the C64 with the correct traffic secret and transcript
    #   3. Calling tls_compute_finished (or tls_verify_finished)
    #   4. Comparing the result

    # Check for a dedicated compute_finished routine
    # If not present, try to test via tls_verify_finished or the HKDF primitives
    has_compute = check_label(labels, "tls_compute_finished")
    has_verify = check_label(labels, "tls_verify_finished")

    if not has_compute and not has_verify:
        print("  SKIP: no tls_compute_finished or tls_verify_finished label found")
        return 0, 0

    # If tls_verify_finished is a stub, test via HKDF primitives instead
    if has_verify:
        code = read_bytes(transport, labels["tls_verify_finished"], 2)
        if code == bytes([0x18, 0x60]):
            print("  NOTE: tls_verify_finished is a stub")
            has_verify = False

    if has_compute:
        code = read_bytes(transport, labels["tls_compute_finished"], 2)
        if code == bytes([0x18, 0x60]):
            print("  NOTE: tls_compute_finished is a stub")
            has_compute = False

    if not has_compute and not has_verify:
        # Fall back to testing Finished computation via HKDF primitives
        print("\n  [5a] Finished: server verify_data via HKDF primitives")
        required = ["hkdf_expand_label", "hkdf_prk", "hkdf_okm"]
        if not check_labels(labels, required):
            return 0, 0

        # Compute server finished_key
        server_finished_key = hkdf_expand_label_ref(
            SERVER_HS_TRAFFIC_SECRET, b"finished", b"", 32)

        # Compute on C64
        try:
            got_key = c64_hkdf_expand_label(
                transport, labels, SERVER_HS_TRAFFIC_SECRET,
                b"finished", b"", 32)
            if got_key == server_finished_key:
                passed += 1
                print(f"       PASS: finished_key = {got_key[:8].hex()}...")
            else:
                failed += 1
                print(f"       FAIL: finished_key mismatch")
                print(f"         expected: {server_finished_key[:8].hex()}...")
                print(f"         got:      {got_key[:8].hex()}...")
        except Exception as e:
            failed += 1
            print(f"       FAIL: {e}")

        # Now verify that HMAC-SHA256(finished_key, transcript_hash)
        # produces the expected verify_data
        # We test this using the HMAC via hkdf_extract (since HMAC-SHA256 is
        # the same as HKDF-Extract with key=finished_key, data=transcript_hash)
        print("  [5b] Finished: server verify_data = "
              "HMAC(finished_key, transcript)")

        # For RFC 8448, the transcript hash at the point of server Finished
        # is not the same as TRANSCRIPT_CH_SH (which is after CH+SH only).
        # The server Finished transcript includes CH+SH+EE+Cert+CV.
        # We use HKDF-Extract as HMAC-SHA256 to compute:
        #   verify_data = HMAC-SHA256(finished_key, transcript_hash)
        # Using a known transcript hash that gives us the expected verify_data.
        #
        # For a self-contained test, use:
        #   HMAC-SHA256(finished_key, some_hash) and verify C64 matches Python
        test_transcript = bytes(range(32))
        expected_verify = hmac.new(
            server_finished_key, test_transcript, hashlib.sha256).digest()

        try:
            # Use hkdf_extract with salt=finished_key, ikm=transcript
            got_verify = c64_hkdf_extract(
                transport, labels, server_finished_key, test_transcript)
            if got_verify == expected_verify:
                passed += 1
                print(f"       PASS: verify_data = {got_verify[:8].hex()}...")
            else:
                failed += 1
                print(f"       FAIL: verify_data mismatch")
                print(f"         expected: {expected_verify[:8].hex()}...")
                print(f"         got:      {got_verify[:8].hex()}...")
        except Exception as e:
            failed += 1
            print(f"       FAIL: {e}")

        return passed, failed

    # If we have a real compute_finished or verify_finished, use it
    compute_addr = (labels["tls_compute_finished"] if has_compute
                    else labels["tls_verify_finished"])

    # --- Test 5a: Server Finished verify_data ---
    print("\n  [5a] Finished: server verify_data")
    try:
        # tls_compute_finished reads hkdf_prk (= traffic secret) and tls_transcript
        write_bytes(transport, labels["hkdf_prk"], SERVER_HS_TRAFFIC_SECRET)
        write_bytes(transport, labels["tls_transcript"], TRANSCRIPT_CH_SH)

        jsr(transport, compute_addr, timeout=120.0)

        # Read verify_data from tls_verify_data buffer
        vd_addr = labels.address("tls_verify_data")
        if vd_addr:
            got_verify = read_bytes(transport, vd_addr, 32)
        else:
            got_verify = read_bytes(transport, labels["hkdf_okm"], 32)

        # Compute expected: HMAC(finished_key, transcript_hash)
        # finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
        server_fk = hkdf_expand_label_ref(
            SERVER_HS_TRAFFIC_SECRET, b"finished", b"", 32)
        expected = hmac.new(
            server_fk, TRANSCRIPT_CH_SH, hashlib.sha256).digest()

        if got_verify == expected:
            passed += 1
            print(f"       PASS: {got_verify[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {expected[:8].hex()}...")
            print(f"             got      {got_verify[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    # --- Test 5b: Client Finished verify_data ---
    print("  [5b] Finished: client verify_data")
    try:
        write_bytes(transport, labels["hkdf_prk"], CLIENT_HS_TRAFFIC_SECRET)
        write_bytes(transport, labels["tls_transcript"], TRANSCRIPT_CH_SH)
        jsr(transport, compute_addr, timeout=120.0)
        vd_addr = labels.address("tls_verify_data")
        if vd_addr:
            got_verify = read_bytes(transport, vd_addr, 32)
        else:
            got_verify = read_bytes(transport, labels["hkdf_okm"], 32)
        client_fk = hkdf_expand_label_ref(
            CLIENT_HS_TRAFFIC_SECRET, b"finished", b"", 32)
        expected = hmac.new(
            client_fk, TRANSCRIPT_CH_SH, hashlib.sha256).digest()
        if got_verify == expected:
            passed += 1
            print(f"       PASS: {got_verify[:8].hex()}...")
        else:
            failed += 1
            print(f"       FAIL: expected {expected[:8].hex()}...")
            print(f"             got      {got_verify[:8].hex()}...")
    except Exception as e:
        failed += 1
        print(f"       FAIL: {e}")

    return passed, failed


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels, seed):
    """Run all TLS handshake tests. Returns (passed, failed)."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    # Initialize sqtab (required for any Poly1305 in AEAD paths)
    print("\n  Initializing sqtab...")
    jsr(transport, labels["sqtab_init"], timeout=60.0)
    print("  sqtab ready")

    test_groups = [
        ("Streaming transcript hash (4 tests)",
         lambda: test_transcript_hash(transport, labels, rng)),
        ("ClientHello format (3 tests)",
         lambda: test_client_hello(transport, labels, rng)),
        ("ServerHello parse (3 tests)",
         lambda: test_server_hello_parse(transport, labels, rng)),
        ("Key schedule step-by-step (9 tests)",
         lambda: test_key_schedule_steps(transport, labels)),
        ("Finished MAC (2 tests)",
         lambda: test_finished_mac(transport, labels)),
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

    # Build (skippable via C64_SKIP_BUILD=1 when a caller has already built)
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

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    required_labels = [
        "sqtab_init", "input_buffer",
        "hkdf_extract", "hkdf_expand_label",
        "hkdf_prk", "hkdf_okm",
        "hkdf_salt_ptr", "hkdf_salt_len",
        "hkdf_ikm_ptr", "hkdf_ikm_len",
        "hkdf_label_ptr", "hkdf_label_len",
        "hkdf_context_ptr", "hkdf_context_len",
        "hkdf_out_len",
    ]

    missing = []
    for name in required_labels:
        if labels.address(name) is None:
            missing.append(name)
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)

    # Check optional TLS handshake labels
    optional_labels = [
        "tls_transcript_init", "tls_transcript_update", "tls_transcript_hash",
        "tls_transcript",
        "tls_build_client_hello", "tls_rec_buf", "tls_rec_len",
        "tls_client_random", "tls_ecdhe_pubkey",
        "tls_parse_server_hello", "tls_server_random", "tls_server_pubkey",
        "tls_derive_handshake_keys",
        "tls_shared_secret", "tls_early_secret", "tls_handshake_secret",
        "tls_hs_write_key", "tls_hs_write_iv",
        "tls_hs_read_key", "tls_hs_read_iv",
        "tls_compute_finished", "tls_verify_finished",
    ]
    found_optional = 0
    for name in optional_labels:
        if labels.address(name) is not None:
            found_optional += 1
        else:
            print(f"  NOTE: optional label '{name}' not found (tests will skip)")

    print(f"  Labels loaded: {len(required_labels)} required, "
          f"{found_optional}/{len(optional_labels)} optional TLS labels found")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    print(f"\n=== Starting VICE ===")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        # Wait for main menu (binary monitor: resume CPU between polls)
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        # Run tests
        print(f"\n=== TLS 1.3 Handshake Tests ===")
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
        print(f"\n  [+] TLS HANDSHAKE: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] TLS HANDSHAKE: {failed} TEST(S) FAILED")
    print(f"{'='*60}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
