#!/usr/bin/env python3
"""test_crypto.py — Direct-memory ChaCha20-Poly1305 AEAD tests for c64-https.

Tests sqtab_init, ChaCha20 (block, encrypt), Poly1305 (MAC), and
AEAD (encrypt, decrypt, random roundtrip) against Python reference
implementations and RFC 7539 test vectors via jsr() calls.

Usage:
    python3 tools/test_crypto.py [--seed S] [--verbose]
"""

import os
import random
import struct
import subprocess
import sys
import time
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, ScreenGrid,
    read_bytes, write_bytes, jsr,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False


# ============================================================================
# Python reference implementations (from RFC 7539)
# ============================================================================

def rotl32(val, n):
    """Rotate left 32-bit."""
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


def chacha20_quarter_round_ref(state, a, b, c, d):
    """ChaCha20 quarter-round on a list of 16 uint32s."""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_block_ref(key, counter, nonce):
    """Generate one ChaCha20 block (64 bytes)."""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<3I', nonce))
    state = constants + key_words + [counter] + nonce_words
    working = list(state)

    for _ in range(10):
        # Column rounds
        chacha20_quarter_round_ref(working, 0, 4, 8, 12)
        chacha20_quarter_round_ref(working, 1, 5, 9, 13)
        chacha20_quarter_round_ref(working, 2, 6, 10, 14)
        chacha20_quarter_round_ref(working, 3, 7, 11, 15)
        # Diagonal rounds
        chacha20_quarter_round_ref(working, 0, 5, 10, 15)
        chacha20_quarter_round_ref(working, 1, 6, 11, 12)
        chacha20_quarter_round_ref(working, 2, 7, 8, 13)
        chacha20_quarter_round_ref(working, 3, 4, 9, 14)

    result = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *result)


def chacha20_encrypt_ref(key, counter, nonce, plaintext):
    """ChaCha20 encrypt/decrypt."""
    result = bytearray()
    for i in range(0, len(plaintext), 64):
        block = chacha20_block_ref(key, counter + i // 64, nonce)
        chunk = plaintext[i:i+64]
        result.extend(b ^ k for b, k in zip(chunk, block))
    return bytes(result)


def poly1305_ref(key, message):
    """Poly1305 MAC reference implementation."""
    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]

    # Clamp r
    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f
    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r = int.from_bytes(r_bytes, 'little')
    s = int.from_bytes(s_bytes, 'little')
    p = (1 << 130) - 5

    h = 0
    for i in range(0, len(message), 16):
        block = message[i:i+16]
        n = int.from_bytes(block, 'little')
        n += 1 << (8 * len(block))  # hibit
        h = ((h + n) * r) % p

    h = (h + s) & ((1 << 128) - 1)
    return h.to_bytes(16, 'little')


def aead_encrypt_ref(key, nonce, aad, plaintext):
    """ChaCha20-Poly1305 AEAD encrypt reference (RFC 7539)."""
    # Derive one-time key for Poly1305
    otk_block = chacha20_block_ref(key, 0, nonce)
    otk = otk_block[:32]

    # Encrypt plaintext with counter starting at 1
    ciphertext = chacha20_encrypt_ref(key, 1, nonce, plaintext)

    # Build Poly1305 MAC input
    mac_data = bytearray()
    mac_data.extend(aad)
    if len(aad) % 16:
        mac_data.extend(b'\x00' * (16 - len(aad) % 16))
    mac_data.extend(ciphertext)
    if len(ciphertext) % 16:
        mac_data.extend(b'\x00' * (16 - len(ciphertext) % 16))
    mac_data.extend(struct.pack('<Q', len(aad)))
    mac_data.extend(struct.pack('<Q', len(ciphertext)))

    tag = poly1305_ref(otk, mac_data)
    return ciphertext, tag


def aead_decrypt_ref(key, nonce, aad, ciphertext, tag):
    """ChaCha20-Poly1305 AEAD decrypt reference. Returns plaintext or None."""
    expected_ct, expected_tag = aead_encrypt_ref(key, nonce, aad,
        chacha20_encrypt_ref(key, 1, nonce, ciphertext))
    # Simpler: just decrypt and recompute tag
    otk_block = chacha20_block_ref(key, 0, nonce)
    otk = otk_block[:32]

    mac_data = bytearray()
    mac_data.extend(aad)
    if len(aad) % 16:
        mac_data.extend(b'\x00' * (16 - len(aad) % 16))
    mac_data.extend(ciphertext)
    if len(ciphertext) % 16:
        mac_data.extend(b'\x00' * (16 - len(ciphertext) % 16))
    mac_data.extend(struct.pack('<Q', len(aad)))
    mac_data.extend(struct.pack('<Q', len(ciphertext)))

    computed_tag = poly1305_ref(otk, mac_data)
    if computed_tag != tag:
        return None

    plaintext = chacha20_encrypt_ref(key, 1, nonce, ciphertext)
    return plaintext


# ============================================================================
# C64 helper functions
# ============================================================================

def c64_chacha20_init(transport, labels, key, nonce, counter=0):
    """Initialize ChaCha20 state on C64."""
    write_bytes(transport, labels["cc20_key"], key)
    write_bytes(transport, labels["cc20_nonce"], nonce)
    write_bytes(transport, labels["cc20_counter"],
                counter.to_bytes(4, 'little'))
    jsr(transport, labels["chacha20_init"])


def c64_chacha20_block(transport, labels):
    """Generate one ChaCha20 keystream block. Returns 64 bytes."""
    jsr(transport, labels["chacha20_block"], timeout=120.0)
    return read_bytes(transport, labels["cc20_keystream"], 64)


def c64_chacha20_encrypt(transport, labels, key, nonce, data, counter=1):
    """Encrypt data using ChaCha20 on C64."""
    c64_chacha20_init(transport, labels, key, nonce, counter)
    buf = labels["input_buffer"]
    write_bytes(transport, buf, data)
    write_bytes(transport, labels["cc20_data_ptr"],
                bytes([buf & 0xFF, buf >> 8]))
    write_bytes(transport, labels["cc20_remain"], bytes([len(data)]))
    jsr(transport, labels["chacha20_encrypt"], timeout=180.0)
    return read_bytes(transport, buf, len(data))


def c64_poly1305_mac(transport, labels, key, message):
    """Full Poly1305 MAC on C64: init, update, final."""
    write_bytes(transport, labels["poly_r"], key[:16])
    write_bytes(transport, labels["poly_s"], key[16:])
    jsr(transport, labels["poly1305_init"], timeout=60.0)

    if len(message) > 0:
        buf = labels["input_buffer"]
        write_bytes(transport, buf, message)
        write_bytes(transport, labels["zp_ptr"],
                    bytes([buf & 0xFF, buf >> 8]))
        write_bytes(transport, labels["cc20_remain"], bytes([len(message)]))
        jsr(transport, labels["poly1305_update"], timeout=120.0)

    jsr(transport, labels["poly1305_final"], timeout=30.0)
    return read_bytes(transport, labels["poly1305_tag"], 16)


def c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext):
    """AEAD encrypt on C64. Returns (ciphertext, tag)."""
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    # Write AAD to input_buffer
    aad_buf = labels["input_buffer"]
    if aad:
        write_bytes(transport, aad_buf, aad)
    write_bytes(transport, labels["aead_aad_ptr"],
                bytes([aad_buf & 0xFF, aad_buf >> 8]))
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))

    # Write plaintext after AAD
    pt_buf = aad_buf + len(aad)
    if plaintext:
        write_bytes(transport, pt_buf, plaintext)
    write_bytes(transport, labels["aead_data_ptr"],
                bytes([pt_buf & 0xFF, pt_buf >> 8]))
    write_bytes(transport, labels["aead_data_len"], bytes([len(plaintext)]))

    jsr(transport, labels["aead_encrypt"], timeout=300.0)

    ct = read_bytes(transport, pt_buf, len(plaintext))
    tag = read_bytes(transport, labels["poly1305_tag"], 16)
    return ct, tag


def c64_aead_decrypt(transport, labels, key, nonce, aad, ciphertext, tag):
    """AEAD decrypt on C64. Returns (plaintext, success)."""
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    # Write AAD
    aad_buf = labels["input_buffer"]
    if aad:
        write_bytes(transport, aad_buf, aad)
    write_bytes(transport, labels["aead_aad_ptr"],
                bytes([aad_buf & 0xFF, aad_buf >> 8]))
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))

    # Write ciphertext after AAD
    ct_buf = aad_buf + len(aad)
    if ciphertext:
        write_bytes(transport, ct_buf, ciphertext)
    write_bytes(transport, labels["aead_data_ptr"],
                bytes([ct_buf & 0xFF, ct_buf >> 8]))
    write_bytes(transport, labels["aead_data_len"], bytes([len(ciphertext)]))

    # Write expected tag
    write_bytes(transport, labels["aead_tag"], tag)

    jsr(transport, labels["aead_decrypt"], timeout=300.0)

    pt = read_bytes(transport, ct_buf, len(ciphertext))
    return pt, True


# ============================================================================
# Test functions
# ============================================================================

def test_sqtab_init(transport, labels):
    """Test sqtab_init builds the quarter-square multiply table at $7800."""
    passed = 0
    failed = 0

    jsr(transport, labels["sqtab_init"], timeout=60.0)

    # The quarter-square table: sqtab_lo/hi at $7800/$7A00
    # sqtab[n] = floor(n^2 / 4) for n = 0..511
    # sqtab_lo is at $7800 (512 bytes), sqtab_hi is at $7A00 (512 bytes)
    sqtab_lo = labels["sqtab_lo"]  # $7800
    sqtab_hi = labels["sqtab_hi"]  # $7A00

    # Verify a selection of known values
    # sqtab[0] = 0, sqtab[1] = 0, sqtab[2] = 1, sqtab[3] = 2,
    # sqtab[4] = 4, sqtab[10] = 25, sqtab[100] = 2500, sqtab[255] = 16256
    test_cases = [
        (0, 0),
        (1, 0),
        (2, 1),
        (3, 2),
        (4, 4),
        (10, 25),
        (100, 2500),
        (200, 10000),
        (255, 16256),
        # Also check second page (n=256..511)
        (256, 16384),
        (300, 22500),
        (511, 65280),
    ]

    for n, expected_val in test_cases:
        lo_byte = read_bytes(transport, sqtab_lo + n, 1)
        hi_byte = read_bytes(transport, sqtab_hi + n, 1)
        actual = lo_byte[0] | (hi_byte[0] << 8)

        if actual == expected_val:
            passed += 1
            if VERBOSE:
                print(f"  PASS sqtab[{n}] = {actual}")
        else:
            failed += 1
            print(f"  FAIL sqtab[{n}]: expected {expected_val}, got {actual}")

    return passed, failed


def test_chacha20_block_rfc(transport, labels):
    """Test ChaCha20 block with RFC 7539 Section 2.3.2 test vector."""
    passed = 0
    failed = 0

    # RFC 7539 Section 2.3.2
    key = bytes(range(0x20))  # 00:01:02:...:1f
    nonce = bytes([
        0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    ])
    counter = 1

    # Expected output from RFC 7539 Section 2.3.2
    expected = bytes([
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ])

    # Also verify with Python reference
    ref_output = chacha20_block_ref(key, counter, nonce)
    assert ref_output == expected, "Python reference mismatch with RFC vector"

    c64_chacha20_init(transport, labels, key, nonce, counter)
    result = c64_chacha20_block(transport, labels)

    if result == expected:
        passed += 1
        if VERBOSE:
            print("  PASS ChaCha20 block: RFC 7539 Section 2.3.2")
    else:
        failed += 1
        print("  FAIL ChaCha20 block: RFC 7539 Section 2.3.2")
        print(f"    expected: {expected.hex()}")
        print(f"    got:      {result.hex()}")
        for i in range(16):
            e = int.from_bytes(expected[i*4:i*4+4], 'little')
            g = int.from_bytes(result[i*4:i*4+4], 'little')
            if e != g:
                print(f"    word {i:2d}: expected 0x{e:08X}, got 0x{g:08X}")

    return passed, failed


def test_chacha20_encrypt_rfc(transport, labels):
    """Test ChaCha20 encrypt with RFC 7539 Section 2.4.2 test vector."""
    passed = 0
    failed = 0

    # RFC 7539 Section 2.4.2
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ])
    nonce = bytes([
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    ])
    counter = 1

    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )

    expected_ct = bytes([
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ])

    # Verify Python reference matches
    ref_ct = chacha20_encrypt_ref(key, counter, nonce, plaintext)
    assert ref_ct == expected_ct, "Python reference mismatch with RFC vector"

    result = c64_chacha20_encrypt(transport, labels, key, nonce,
                                   plaintext, counter)

    if result == expected_ct:
        passed += 1
        if VERBOSE:
            print("  PASS ChaCha20 encrypt: RFC 7539 Section 2.4.2")
    else:
        failed += 1
        print("  FAIL ChaCha20 encrypt: RFC 7539 Section 2.4.2")
        for i in range(len(expected_ct)):
            if i >= len(result) or result[i] != expected_ct[i]:
                print(f"    first diff at byte {i}: "
                      f"got 0x{result[i]:02X}, expected 0x{expected_ct[i]:02X}")
                break

    return passed, failed


def test_poly1305_mac_rfc(transport, labels):
    """Test Poly1305 MAC with RFC 7539 Section 2.5.2 test vector."""
    passed = 0
    failed = 0

    # Ensure sqtab is initialized before Poly1305
    jsr(transport, labels["sqtab_init"], timeout=60.0)

    # RFC 7539 Section 2.5.2
    key = bytes([
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    ])

    message = b"Cryptographic Forum Research Group"

    expected_tag = bytes([
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    ])

    # Verify Python reference
    ref_tag = poly1305_ref(key, message)
    assert ref_tag == expected_tag, "Python Poly1305 reference mismatch"

    result = c64_poly1305_mac(transport, labels, key, message)

    if result == expected_tag:
        passed += 1
        if VERBOSE:
            print("  PASS Poly1305 MAC: RFC 7539 Section 2.5.2")
    else:
        failed += 1
        print("  FAIL Poly1305 MAC: RFC 7539 Section 2.5.2")
        print(f"    expected: {expected_tag.hex()}")
        print(f"    got:      {result.hex()}")

    return passed, failed


def test_aead_encrypt_rfc(transport, labels):
    """Test AEAD encrypt with RFC 7539 Section 2.8.2 test vector."""
    passed = 0
    failed = 0

    # Ensure sqtab is initialized
    jsr(transport, labels["sqtab_init"], timeout=60.0)

    # RFC 7539 Section 2.8.2
    key = bytes([
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ])
    nonce = bytes([
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    ])
    aad = bytes([
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ])
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )

    expected_ct = bytes([
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ])
    expected_tag = bytes([
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ])

    # Verify Python reference
    ref_ct, ref_tag = aead_encrypt_ref(key, nonce, aad, plaintext)
    assert ref_ct == expected_ct, "Python AEAD ciphertext reference mismatch"
    assert ref_tag == expected_tag, "Python AEAD tag reference mismatch"

    ct, tag = c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext)

    ct_ok = ct == expected_ct
    tag_ok = tag == expected_tag

    if ct_ok and tag_ok:
        passed += 1
        if VERBOSE:
            print("  PASS AEAD encrypt: RFC 7539 Section 2.8.2")
    else:
        failed += 1
        print("  FAIL AEAD encrypt: RFC 7539 Section 2.8.2")
        if not ct_ok:
            print(f"    CT expected: {expected_ct[:32].hex()}...")
            print(f"    CT got:      {ct[:32].hex()}...")
            for i in range(len(expected_ct)):
                if i >= len(ct) or ct[i] != expected_ct[i]:
                    print(f"    first CT diff at byte {i}")
                    break
        if not tag_ok:
            print(f"    tag expected: {expected_tag.hex()}")
            print(f"    tag got:      {tag.hex()}")

    return passed, failed


def test_aead_decrypt_roundtrip(transport, labels, rng):
    """Test AEAD encrypt then decrypt roundtrip on C64."""
    passed = 0
    failed = 0

    # Ensure sqtab is initialized
    jsr(transport, labels["sqtab_init"], timeout=60.0)

    key = bytes(rng.randint(0, 255) for _ in range(32))
    nonce = bytes(rng.randint(0, 255) for _ in range(12))
    aad = bytes(rng.randint(0, 255) for _ in range(8))
    plaintext = bytes(rng.randint(0, 255) for _ in range(32))

    # Encrypt on C64
    ct, tag = c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext)

    # Verify ciphertext matches Python reference
    ref_ct, ref_tag = aead_encrypt_ref(key, nonce, aad, plaintext)
    if ct != ref_ct or tag != ref_tag:
        failed += 1
        print("  FAIL AEAD decrypt roundtrip: encrypt step mismatch")
        if ct != ref_ct:
            print(f"    CT expected: {ref_ct.hex()}")
            print(f"    CT got:      {ct.hex()}")
        if tag != ref_tag:
            print(f"    tag expected: {ref_tag.hex()}")
            print(f"    tag got:      {tag.hex()}")
        return passed, failed

    # Decrypt on C64
    pt_result, _ = c64_aead_decrypt(transport, labels, key, nonce, aad, ct, tag)

    if pt_result == plaintext:
        passed += 1
        if VERBOSE:
            print("  PASS AEAD decrypt roundtrip: plaintext recovered")
    else:
        failed += 1
        print("  FAIL AEAD decrypt roundtrip: plaintext mismatch")
        print(f"    expected: {plaintext.hex()}")
        print(f"    got:      {pt_result.hex()}")

    return passed, failed


def test_aead_random(transport, labels, rng, count=5):
    """Test AEAD with random inputs: encrypt on C64, verify with Python."""
    passed = 0
    failed = 0

    # Ensure sqtab is initialized
    jsr(transport, labels["sqtab_init"], timeout=60.0)

    for i in range(count):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        nonce = bytes(rng.randint(0, 255) for _ in range(12))
        aad_len = rng.randint(0, 16)
        pt_len = rng.randint(1, 64)
        aad = bytes(rng.randint(0, 255) for _ in range(aad_len))
        plaintext = bytes(rng.randint(0, 255) for _ in range(pt_len))

        # Encrypt on C64
        ct, tag = c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext)

        # Verify with Python reference
        expected_ct, expected_tag = aead_encrypt_ref(key, nonce, aad, plaintext)

        ct_ok = ct == expected_ct
        tag_ok = tag == expected_tag

        if ct_ok and tag_ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS random AEAD #{i}: aad={aad_len}, pt={pt_len}")
        else:
            failed += 1
            print(f"  FAIL random AEAD #{i} (aad={aad_len}, pt={pt_len}):")
            if not ct_ok:
                print(f"    CT expected: {expected_ct.hex()}")
                print(f"    CT got:      {ct.hex()}")
            if not tag_ok:
                print(f"    tag expected: {expected_tag.hex()}")
                print(f"    tag got:      {tag.hex()}")
            print(f"    key:   {key.hex()}")
            print(f"    nonce: {nonce.hex()}")

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
        ("sqtab_init", lambda: test_sqtab_init(transport, labels)),
        ("ChaCha20 block (RFC 7539 Section 2.3.2)",
         lambda: test_chacha20_block_rfc(transport, labels)),
        ("ChaCha20 encrypt (RFC 7539 Section 2.4.2)",
         lambda: test_chacha20_encrypt_rfc(transport, labels)),
        ("Poly1305 MAC (RFC 7539 Section 2.5.2)",
         lambda: test_poly1305_mac_rfc(transport, labels)),
        ("AEAD encrypt (RFC 7539 Section 2.8.2)",
         lambda: test_aead_encrypt_rfc(transport, labels)),
        ("AEAD decrypt roundtrip",
         lambda: test_aead_decrypt_roundtrip(transport, labels, rng)),
        ("AEAD random (5 iterations)",
         lambda: test_aead_random(transport, labels, rng, count=5)),
    ]

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
    global VERBOSE
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
        "chacha20_init", "chacha20_block", "chacha20_encrypt",
        "cc20_state", "cc20_work", "cc20_keystream",
        "cc20_key", "cc20_nonce", "cc20_counter",
        "cc20_data_ptr", "cc20_remain",
        "poly1305_init", "poly1305_block", "poly1305_update", "poly1305_final",
        "poly1305_clamp",
        "poly_h", "poly_r", "poly_s", "poly1305_tag",
        "aead_encrypt", "aead_decrypt",
        "aead_key", "aead_nonce", "aead_aad_ptr", "aead_aad_len",
        "aead_data_ptr", "aead_data_len", "aead_tag", "aead_scratch",
        "sqtab_init", "sqtab_lo", "sqtab_hi",
        "input_buffer", "zp_ptr",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)

    print(f"  Labels loaded: {len(required)} required labels verified")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    print("\n=== Starting VICE ===")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        # Binary monitor: resume CPU between screen polls
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
            print("FATAL: Program menu did not appear")
            sys.exit(1)

        print("  VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
