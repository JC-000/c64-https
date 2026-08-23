#!/usr/bin/env python3
"""test_tls_p384_negotiation.py - Phase 4b negotiation plumbing test.

Phase 4b originally verified that the TLS layer OFFERS ecdsa_secp384r1_sha384
(0x0503). That assertion is inverted now: advertising 0x0503 was the bug, since
the client answers it destructively. This file verifies
alongside ecdsa_secp256r1_sha256 (0x0403) in the ClientHello, and that the
CertificateVerify handler accepts a 0x0503 signature_scheme by routing
through the ecdsa_verify dispatcher with curve_id=1.

This test does NOT require a successful P-384 verification; the
ecdsa_verify dispatcher's P-384 branch is still a `sec / rts` stub that
Phase 4a fills in.  Successful negotiation = the carry-set return came
out of the dispatcher (curve_id was set to 1, cv_sig_scheme was set to
1, the routine entered the short-circuit branch).

Two sub-tests:

  [1a] ClientHello signature_algorithms extension contains BOTH 0x0403
       and 0x0503.
  [1b] tls_handle_cert_verify with a synthesized CertificateVerify
       handshake message whose signature_scheme = 0x0503 sets
       cv_sig_scheme = 1, ecdsa_curve_id = 1, and returns C=1.
       Pre-Phase-4a this came from the `sec / rts` stub in
       ecdsa_verify; post-Phase-4a (commit-this-PR) it comes from
       ecdsa_verify_384_tls's DER parse rejecting the 48-zero-byte
       dummy signature (first byte must be 0x30 SEQUENCE; rejection
       still propagates C=1).  The negotiation contract under test
       (cv_sig_scheme=1, ecdsa_curve_id=1, dispatcher reached) is
       unchanged.  Phase 5 will replace this synthetic test with a
       real-signature test once a SHA-384 transcript path lands.

Usage:
    /Users/someone/.local/share/c64-test-harness/venv/bin/python \\
        tools/test_tls_p384_negotiation.py [--seed S]

Requires VICE x64sc.  -reu is passed to satisfy the sibling P-256
fp_mul row-fetch invariant (see "VICE harness gotcha" in CLAUDE.md);
it does not exercise REU but the residency requirement applies to any
test that links the sibling library.
"""

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

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Carry-flag trampoline (cassette buffer).  Mirrors test_x509.py.
CARRY_TRAMPOLINE = 0x033C
CARRY_RESULT_ADDR = 0x0352
CARRY_FLAG_ADDR = 0x0353


def jsr_with_carry(transport, addr, timeout=120.0, poll_interval=0.5):
    """Call subroutine and capture the carry flag via a memory trampoline.

    Returns the value of the C flag after the JSR (0 = clear, 1 = set).
    """
    import time

    target_lo = addr & 0xFF
    target_hi = (addr >> 8) & 0xFF

    # Trampoline:
    #   LDA #$00 / STA flag
    #   JSR target
    #   ROL A=0 / AND #$01 (capture C into A)
    #   STA result
    #   LDA #$FF / STA flag
    #   RTS
    trampoline = bytes([
        0xA9, 0x00,                         # LDA #$00
        0x8D, CARRY_FLAG_ADDR & 0xFF, (CARRY_FLAG_ADDR >> 8) & 0xFF,
        0x20, target_lo, target_hi,         # JSR target
        0xA9, 0x00,                         # LDA #$00
        0x2A,                               # ROL A  (C -> bit 0)
        0x29, 0x01,                         # AND #$01
        0x8D, CARRY_RESULT_ADDR & 0xFF, (CARRY_RESULT_ADDR >> 8) & 0xFF,
        0xA9, 0xFF,                         # LDA #$FF
        0x8D, CARRY_FLAG_ADDR & 0xFF, (CARRY_FLAG_ADDR >> 8) & 0xFF,
        0x60,                               # RTS
    ])
    write_bytes(transport, CARRY_TRAMPOLINE, trampoline)
    write_bytes(transport, CARRY_FLAG_ADDR, bytes([0x00]))

    jsr(transport, CARRY_TRAMPOLINE, timeout=timeout)

    deadline = time.time() + timeout
    while time.time() < deadline:
        flag = read_bytes(transport, CARRY_FLAG_ADDR, 1)[0]
        if flag == 0xFF:
            break
        time.sleep(poll_interval)
    else:
        raise TimeoutError(f"jsr_with_carry timed out after {timeout}s")

    return read_bytes(transport, CARRY_RESULT_ADDR, 1)[0]


# ---------------------------------------------------------------------------
# Test 1a: ClientHello advertises both 0x0403 and 0x0503
# ---------------------------------------------------------------------------

def test_client_hello_sig_algs(transport, labels, rng):
    """Verify ClientHello offers 0x0403 and does NOT offer 0x0503."""
    print("\n  [1a] ClientHello signature_algorithms: 0x0403 only, NOT 0x0503")

    required = [
        "tls_build_client_hello", "tls_rec_buf", "tls_rec_len",
        "tls_client_random", "tls_ecdhe_pubkey",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"       SKIP: missing labels {missing}")
        return 0, 0

    build_ch = labels.address("tls_build_client_hello")
    hs_buf = labels.address("tls_rec_buf")
    hs_len_addr = labels.address("tls_rec_len")

    # Seed the input buffers with deterministic-ish data.
    client_random = bytes(rng.getrandbits(8) for _ in range(32))
    pubkey = bytes(rng.getrandbits(8) for _ in range(32))
    write_bytes(transport, labels.address("tls_client_random"), client_random)
    write_bytes(transport, labels.address("tls_ecdhe_pubkey"), pubkey)

    try:
        jsr(transport, build_ch, timeout=60.0)
    except Exception as e:
        print(f"       FAIL: tls_build_client_hello jsr raised {e}")
        return 0, 1

    msg_len_bytes = read_bytes(transport, hs_len_addr, 2)
    msg_len = msg_len_bytes[0] | (msg_len_bytes[1] << 8)
    if msg_len == 0:
        print("       FAIL: tls_build_client_hello produced 0-length output")
        return 0, 1

    msg = read_bytes(transport, hs_buf, min(msg_len, 320))

    # Walk to extensions.  Layout after the 4-byte handshake header:
    #   [4-5]    legacy_version
    #   [6-37]   client_random
    #   [38]     session_id_len (0)
    #   [39-40]  cipher_suites_len = 0x0002
    #   [41-42]  cipher_suite     = 0x1303
    #   [43]     compression_methods_len = 0x01
    #   [44]     compression_method = 0x00
    #   [45-46]  extensions_len
    #   [47..]   extension list
    if len(msg) < 49:
        print(f"       FAIL: msg too short ({len(msg)} B)")
        return 0, 1

    pos = 47
    ext_total = (msg[45] << 8) | msg[46]
    ext_end = min(pos + ext_total, len(msg))

    sig_algs_payload = None
    while pos + 4 <= ext_end:
        ext_type = (msg[pos] << 8) | msg[pos + 1]
        ext_len = (msg[pos + 2] << 8) | msg[pos + 3]
        ext_data = msg[pos + 4:pos + 4 + ext_len]
        if ext_type == 0x000D:
            sig_algs_payload = ext_data
            break
        pos += 4 + ext_len

    if sig_algs_payload is None:
        print("       FAIL: signature_algorithms (0x000D) extension not found")
        return 0, 1

    if len(sig_algs_payload) < 2:
        print(f"       FAIL: signature_algorithms payload too short "
              f"({len(sig_algs_payload)} B)")
        return 0, 1

    inner_len = (sig_algs_payload[0] << 8) | sig_algs_payload[1]
    inner = sig_algs_payload[2:2 + inner_len]

    # Inner is a list of 16-bit big-endian schemes.
    schemes = set()
    for i in range(0, len(inner), 2):
        if i + 2 <= len(inner):
            schemes.add((inner[i] << 8) | inner[i + 1])

    # This assertion is INVERTED from Phase 4b on purpose. It used to require
    # 0x0503 to be advertised; advertising it was the bug. The client cannot
    # perform P-384 — the verify path swaps in an overlay image no shipped
    # build stages, corrupting live resident code — so offering the scheme
    # handed a server the choice of breaking us. See the gate in
    # src/crypto/ecdsa_verify.s and tools/test_p384_overlay_hazard.py.
    scheme_hex = ", ".join(f"0x{s:04x}" for s in sorted(schemes)) or "(none)"
    problems = []
    if 0x0403 not in schemes:
        problems.append("0x0403 (ecdsa_secp256r1_sha256) MISSING — "
                        "the one scheme we can actually verify")
    if 0x0503 in schemes:
        problems.append("0x0503 (ecdsa_secp384r1_sha384) ADVERTISED — "
                        "P-384 is parked and answering it is destructive")

    if problems:
        for pr in problems:
            print(f"       FAIL: {pr}")
        print(f"             advertised: {scheme_hex}")
        return 0, 1

    print(f"       PASS: schemes advertised = {scheme_hex} "
          "(0x0503 correctly absent)")
    return 1, 0


# ---------------------------------------------------------------------------
# Test 1b: CertificateVerify handler accepts 0x0503 and dispatches
# ---------------------------------------------------------------------------

def test_cert_verify_p384_dispatch(transport, labels):
    """Verify tls_handle_cert_verify routes 0x0503 through the dispatcher.

    Synthesizes a CertificateVerify handshake message whose
    signature_scheme = 0x0503, calls tls_handle_cert_verify, and asserts:
      - cv_sig_scheme = 1
      - ecdsa_curve_id = 1
      - C=1 (carry set).  Post-Phase-4a this comes from the dispatcher's
        DER parse rejecting the 48-byte all-zero dummy signature (the
        first byte must be the DER SEQUENCE tag 0x30); pre-Phase-4a it
        came from the `sec / rts` stub in ecdsa_verify.  Either path
        proves cv_sig_scheme=1, ecdsa_curve_id=1, and dispatcher
        reachability -- the contract this subtest exercises.

    The signature payload itself is irrelevant for the negotiation
    plumbing under test -- a real-signature P-384 verify needs both a
    real ECDSA-P384 cert + signature AND a SHA-384 transcript hash
    (Phase 5).  Phase 4a's dispatcher composes the dual-overlay swap
    (sha384 -> curve) + sibling ecdsa_verify_384, but the SHA-384
    transcript source is a 32 B SHA-256 placeholder zero-padded to
    48 B until Phase 5 wires up tls_transcript_384.
    """
    print("\n  [1b] CertificateVerify dispatch on signature_scheme=0x0503")

    required = [
        "tls_handle_cert_verify", "tls_hs_ptr_reset", "tls_rec_buf", "cv_sig_scheme",
        "ecdsa_curve_id",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"       SKIP: missing labels {missing}")
        return 0, 0

    handler = labels.address("tls_handle_cert_verify")
    rec_buf = labels.address("tls_rec_buf")
    cv_scheme_addr = labels.address("cv_sig_scheme")
    curve_id_addr = labels.address("ecdsa_curve_id")

    # Build a minimal CertificateVerify handshake message:
    #   [0]      handshake type = 15 (TLS_HS_CERT_VERIFY)
    #   [1..3]   24-bit length placeholder (handler doesn't validate it)
    #   [4..5]   signature_scheme = 0x0503
    #   [6..7]   signature length (16-bit BE; high byte must be 0)
    #   [8..]    signature bytes (untouched by the P-384 short-circuit)
    sig = bytes(48)  # 48 dummy bytes — value irrelevant under the stub
    msg = bytearray()
    msg.append(0x0F)                          # handshake type
    msg.extend(b"\x00\x00\x00")               # 24-bit length placeholder
    msg.extend(b"\x05\x03")                   # signature_scheme
    msg.extend(struct.pack(">H", len(sig)))   # signature length
    msg.extend(sig)

    write_bytes(transport, rec_buf, bytes(msg))

    # Pre-clear the state we expect the handler to set.
    write_bytes(transport, cv_scheme_addr, bytes([0xFF]))
    write_bytes(transport, curve_id_addr, bytes([0xFF]))

    try:
        # Point the handler at the message we just staged.
        #
        # Under TLS_STREAM_DEFRAME — the DEFAULT for BACKEND=uci —
        # tls_handle_cert_verify deliberately does NOT reset tls_hs_ptr,
        # because the deframer sets it before dispatch. This test wrote the
        # message to tls_rec_buf and called the handler without setting it, so
        # on a UCI build the handler read whatever tls_hs_ptr happened to hold
        # and reported cv_sig_scheme=0xFF. It only ever worked on ip65, which
        # still has the .ifndef reset — a backend-dependent pass that looked
        # like coverage on both. tls_hs_ptr_reset is exported and does the
        # right thing on either backend.
        jsr(transport, labels["tls_hs_ptr_reset"], timeout=30.0)
        carry = jsr_with_carry(transport, handler, timeout=60.0)
    except Exception as e:
        print(f"       FAIL: jsr_with_carry raised {e}")
        return 0, 1

    cv_scheme = read_bytes(transport, cv_scheme_addr, 1)[0]
    curve_id = read_bytes(transport, curve_id_addr, 1)[0]

    ok = True
    if cv_scheme != 1:
        print(f"       FAIL: cv_sig_scheme = {cv_scheme:#x}, expected 0x01")
        ok = False
    if curve_id != 1:
        print(f"       FAIL: ecdsa_curve_id = {curve_id:#x}, expected 0x01")
        ok = False
    if carry != 1:
        # Phase 4a's dispatcher should also reject a 48-zero-byte sig at
        # the DER parse step (first byte must be 0x30 SEQUENCE).  Phase 5
        # will replace this with a real-signature test once SHA-384
        # transcript wiring lands.
        print(f"       FAIL: carry = {carry}, expected 1 "
              f"(DER rejection / stub rejection)")
        ok = False

    if ok:
        print("       PASS: cv_sig_scheme=1, ecdsa_curve_id=1, "
              "C=1 (Phase 4a dispatcher reached)")
        return 1, 0
    return 0, 1


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    # Args
    seed = random.randint(0, 2**32 - 1)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        else:
            i += 1
    random.seed(seed)
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

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

    labels = Labels.from_file(LABELS_PATH)
    print(f"  Labels loaded from {LABELS_PATH}")

    # -reu is required: the sibling c64-nist-curves fp_mul fetches 8x8
    # multiply rows from REU banks 0/1 (see CLAUDE.md "VICE harness gotcha"
    # under Known issues).  This test does not call into the dispatcher's
    # body but the link includes the sibling, so the same boot-time
    # invariants apply.
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"\n=== Starting VICE ===")
        print(f"  VICE PID={inst.pid}, port={inst.port}")
        print("  Waiting for main menu...")
        if wait_for_text(transport, "Q=QUIT", timeout=60.0,
                         verbose=False) is None:
            print("FATAL: main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        passed = 0
        failed = 0

        p, f = test_client_hello_sig_algs(transport, labels, rng)
        passed += p
        failed += f

        p, f = test_cert_verify_p384_dispatch(transport, labels)
        passed += p
        failed += f

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'=' * 60}")
    print("RESULTS")
    print(f"{'=' * 60}")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0 and passed > 0:
        print("\n  [+] P-384 negotiation plumbing: PASS")
        sys.exit(0)
    print("\n  [-] P-384 negotiation plumbing: FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
