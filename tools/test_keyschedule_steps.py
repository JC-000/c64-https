#!/usr/bin/env python3
"""test_keyschedule_steps.py - Test each step of tls_derive_handshake_keys individually.

Calls each of the 9 HKDF steps via separate jsr() calls, verifying each
against RFC 8448 Section 3 expected values. This tests whether each assembly
routine is correct, independent of chaining them in one function.

Usage:
    python3 tools/test_keyschedule_steps.py [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import hashlib
import hmac
import os
import struct
import subprocess
import sys

import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    ScreenGrid,
    read_bytes,
    write_bytes,
    jsr,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

REQUIRED_LABELS = [
    "hkdf_extract", "hkdf_expand_label", "tls_derive_secret",
    "hkdf_prk", "hkdf_okm",
    "hkdf_salt_ptr", "hkdf_salt_len",
    "hkdf_ikm_ptr", "hkdf_ikm_len",
    "hkdf_label_ptr", "hkdf_label_len",
    "hkdf_context_ptr", "hkdf_context_len",
    "hkdf_out_len",
    "input_buffer",
    "empty_hash", "empty_context",
    "lbl_derived", "lbl_c_hs_traffic", "lbl_s_hs_traffic",
    "lbl_key", "lbl_iv",
    "tls_transcript", "tls_shared_secret",
]

# ---------------------------------------------------------------------------
# RFC 8448 Section 3 expected values
# ---------------------------------------------------------------------------

EARLY_SECRET = bytes.fromhex(
    "33ad0a1c607ec03b09e6cd9893680ce2"
    "10adf300aa1f2660e1b22e10f170f92a"
)

DERIVED_FROM_EARLY = bytes.fromhex(
    "6f2615a108c702c5678f54fc9dbab697"
    "16c076189c48250cebeac3576c3611ba"
)

SHARED_SECRET = bytes.fromhex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d"
    "35e6d63f537563efd46272900f89492d"
)

HANDSHAKE_SECRET = bytes.fromhex(
    "1dc826e93606aa6fdc0aadc12f741b01"
    "046aa6b99f691ed221a9f0ca043fbeac"
)

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

def c64_hkdf_extract(transport, labels, salt, ikm):
    """Call hkdf_extract on C64 with given salt and IKM, return 32-byte PRK."""
    salt_addr = labels["input_buffer"]
    write_bytes(transport, salt_addr, salt)
    write_bytes(transport, labels["hkdf_salt_ptr"],
                bytes([salt_addr & 0xFF, salt_addr >> 8]))
    write_bytes(transport, labels["hkdf_salt_len"], bytes([len(salt)]))

    ikm_addr = salt_addr + len(salt)
    write_bytes(transport, ikm_addr, ikm)
    write_bytes(transport, labels["hkdf_ikm_ptr"],
                bytes([ikm_addr & 0xFF, ikm_addr >> 8]))
    write_bytes(transport, labels["hkdf_ikm_len"], bytes([len(ikm)]))

    jsr(transport, labels["hkdf_extract"], timeout=60.0)
    return read_bytes(transport, labels["hkdf_prk"], 32)


def c64_hkdf_expand_label(transport, labels, secret, label, context, length):
    """Call hkdf_expand_label on C64 with given parameters, return OKM."""
    write_bytes(transport, labels["hkdf_prk"], secret)

    label_addr = labels["input_buffer"]
    write_bytes(transport, label_addr, label)
    write_bytes(transport, labels["hkdf_label_ptr"],
                bytes([label_addr & 0xFF, label_addr >> 8]))
    write_bytes(transport, labels["hkdf_label_len"], bytes([len(label)]))

    ctx_addr = label_addr + len(label)
    if context:
        write_bytes(transport, ctx_addr, context)
    write_bytes(transport, labels["hkdf_context_ptr"],
                bytes([ctx_addr & 0xFF, ctx_addr >> 8]))
    write_bytes(transport, labels["hkdf_context_len"], bytes([len(context)]))

    write_bytes(transport, labels["hkdf_out_len"], bytes([length]))

    jsr(transport, labels["hkdf_expand_label"], timeout=60.0)
    return read_bytes(transport, labels["hkdf_okm"], length)


def c64_derive_secret(transport, labels, secret, label_addr, label_len, transcript):
    """Call tls_derive_secret on C64.

    tls_derive_secret reads context from tls_transcript automatically,
    so we write the transcript hash there and set hkdf_prk + label.
    """
    write_bytes(transport, labels["hkdf_prk"], secret)
    write_bytes(transport, labels["tls_transcript"], transcript)

    write_bytes(transport, labels["hkdf_label_ptr"],
                bytes([label_addr & 0xFF, label_addr >> 8]))
    write_bytes(transport, labels["hkdf_label_len"], bytes([label_len]))

    jsr(transport, labels["tls_derive_secret"], timeout=60.0)
    return read_bytes(transport, labels["hkdf_okm"], 32)


def check_result(step_name, expected, got):
    """Compare expected vs got, print PASS/FAIL. Returns True on match."""
    if got == expected:
        print(f"  PASS: {step_name}")
        if VERBOSE:
            print(f"    Value: {got.hex()}")
        return True
    else:
        print(f"  FAIL: {step_name}")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {got.hex()}")
        return False


# ---------------------------------------------------------------------------
# Test functions — one per step
# ---------------------------------------------------------------------------

def test_step1_early_secret(transport, labels):
    """Step 1: early_secret = HKDF-Extract(salt=zeros32, IKM=zeros32)"""
    print("\n--- Step 1: Early Secret ---")
    salt = b'\x00' * 32
    ikm = b'\x00' * 32
    result = c64_hkdf_extract(transport, labels, salt, ikm)
    return check_result("early_secret", EARLY_SECRET, result)


def test_step2_derived(transport, labels):
    """Step 2: derived = HKDF-Expand-Label(early_secret, 'derived', SHA256(''), 32)"""
    print("\n--- Step 2: Derived from Early Secret ---")
    empty_hash = hashlib.sha256(b"").digest()
    result = c64_hkdf_expand_label(
        transport, labels, EARLY_SECRET, b"derived", empty_hash, 32
    )
    return check_result("derived", DERIVED_FROM_EARLY, result)


def test_step3_handshake_secret(transport, labels):
    """Step 3: handshake_secret = HKDF-Extract(salt=derived, IKM=shared_secret)"""
    print("\n--- Step 3: Handshake Secret ---")
    result = c64_hkdf_extract(transport, labels, DERIVED_FROM_EARLY, SHARED_SECRET)
    return check_result("handshake_secret", HANDSHAKE_SECRET, result)


def test_step4_c_hs_traffic(transport, labels):
    """Step 4: c_hs_traffic = Derive-Secret(hs_secret, 'c hs traffic', transcript)"""
    print("\n--- Step 4: Client Handshake Traffic Secret ---")
    result = c64_derive_secret(
        transport, labels,
        HANDSHAKE_SECRET,
        labels["lbl_c_hs_traffic"], 12,
        TRANSCRIPT_CH_SH,
    )
    return check_result("c_hs_traffic", CLIENT_HS_TRAFFIC_SECRET, result)


def test_step5_s_hs_traffic(transport, labels):
    """Step 5: s_hs_traffic = Derive-Secret(hs_secret, 's hs traffic', transcript)"""
    print("\n--- Step 5: Server Handshake Traffic Secret ---")
    result = c64_derive_secret(
        transport, labels,
        HANDSHAKE_SECRET,
        labels["lbl_s_hs_traffic"], 12,
        TRANSCRIPT_CH_SH,
    )
    return check_result("s_hs_traffic", SERVER_HS_TRAFFIC_SECRET, result)


def test_step6_client_hs_key(transport, labels):
    """Step 6: client_hs_key = HKDF-Expand-Label(c_hs_traffic, 'key', '', 32)"""
    print("\n--- Step 6: Client Handshake Key ---")
    expected = hkdf_expand_label_ref(CLIENT_HS_TRAFFIC_SECRET, b"key", b"", 32)
    result = c64_hkdf_expand_label(
        transport, labels, CLIENT_HS_TRAFFIC_SECRET, b"key", b"", 32
    )
    return check_result(
        f"client_hs_key (expected {expected[:8].hex()}...)",
        expected, result
    )


def test_step7_client_hs_iv(transport, labels):
    """Step 7: client_hs_iv = HKDF-Expand-Label(c_hs_traffic, 'iv', '', 12)"""
    print("\n--- Step 7: Client Handshake IV ---")
    expected = hkdf_expand_label_ref(CLIENT_HS_TRAFFIC_SECRET, b"iv", b"", 12)
    result = c64_hkdf_expand_label(
        transport, labels, CLIENT_HS_TRAFFIC_SECRET, b"iv", b"", 12
    )
    return check_result(
        f"client_hs_iv (expected {expected.hex()})",
        expected, result
    )


def test_step8_server_hs_key(transport, labels):
    """Step 8: server_hs_key = HKDF-Expand-Label(s_hs_traffic, 'key', '', 32)"""
    print("\n--- Step 8: Server Handshake Key ---")
    expected = hkdf_expand_label_ref(SERVER_HS_TRAFFIC_SECRET, b"key", b"", 32)
    result = c64_hkdf_expand_label(
        transport, labels, SERVER_HS_TRAFFIC_SECRET, b"key", b"", 32
    )
    return check_result(
        f"server_hs_key (expected {expected[:8].hex()}...)",
        expected, result
    )


def test_step9_server_hs_iv(transport, labels):
    """Step 9: server_hs_iv = HKDF-Expand-Label(s_hs_traffic, 'iv', '', 12)"""
    print("\n--- Step 9: Server Handshake IV ---")
    expected = hkdf_expand_label_ref(SERVER_HS_TRAFFIC_SECRET, b"iv", b"", 12)
    result = c64_hkdf_expand_label(
        transport, labels, SERVER_HS_TRAFFIC_SECRET, b"iv", b"", 12
    )
    return check_result(
        f"server_hs_iv (expected {expected.hex()})",
        expected, result
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels):
    """Run all 9 key schedule steps. Returns (passed, failed)."""
    passed = 0
    failed = 0

    tests = [
        test_step1_early_secret,
        test_step2_derived,
        test_step3_handshake_secret,
        test_step4_c_hs_traffic,
        test_step5_s_hs_traffic,
        test_step6_client_hs_key,
        test_step7_client_hs_iv,
        test_step8_server_hs_key,
        test_step9_server_hs_iv,
    ]

    for test_fn in tests:
        try:
            ok = test_fn(transport, labels)
        except Exception as e:
            print(f"  FAIL: {test_fn.__doc__}")
            print(f"    Exception: {e}")
            ok = False
        if ok:
            passed += 1
        else:
            failed += 1

    return passed, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    if "--verbose" in sys.argv:
        VERBOSE = True

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

    # Print key label addresses for debugging
    print(f"  hkdf_extract      = ${labels['hkdf_extract']:04X}")
    print(f"  hkdf_expand_label = ${labels['hkdf_expand_label']:04X}")
    print(f"  tls_derive_secret = ${labels['tls_derive_secret']:04X}")
    print(f"  tls_transcript    = ${labels['tls_transcript']:04X}")
    print(f"  lbl_derived       = ${labels['lbl_derived']:04X}")
    print(f"  lbl_c_hs_traffic  = ${labels['lbl_c_hs_traffic']:04X}")
    print(f"  lbl_s_hs_traffic  = ${labels['lbl_s_hs_traffic']:04X}")
    print(f"  lbl_key           = ${labels['lbl_key']:04X}")
    print(f"  lbl_iv            = ${labels['lbl_iv']:04X}")

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

        # Run all 9 steps
        print("\n=== Key Schedule Steps (9 total) ===")
        passed, failed = run_tests(transport, labels)

        mgr.release(inst)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] Key Schedule Steps: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] Key Schedule Steps: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
