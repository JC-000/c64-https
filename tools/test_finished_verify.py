#!/usr/bin/env python3
"""test_finished_verify.py - negative + positive coverage for tls_verify_finished.

Why this exists
---------------
``tls_verify_finished`` (src/tls_keyschedule.s) is the *only* thing standing
between the client and a forged server Finished: it recomputes the expected
``verify_data`` and constant-time-compares it with the 32 bytes the server sent
at ``tls_rec_buf+4``.  On mismatch it returns C=1, which ``tls13.s`` turns into
a handshake abort::

    src/tls13.s   jsr tls_verify_finished
                  bcs @enc_error          -> sec/rts out of tls_recv_encrypted
    src/tls13.s   jsr tls_recv_encrypted
                  bcs -> @error           -> handshake aborted

Before this test, *nothing in the repo exercised the mismatch path*.  A
mutation audit confirmed it: inverting the mismatch branch (``sec`` -> ``clc``
in ``tls_verify_finished``) let the full hardware end-to-end handshake still
reach HTTP 200 with the correct body, undetected, because every listener the
suite ever talks to sends a *correct* Finished.

This test drives the routine directly over DMA with hand-built inputs, so it
can present a Finished the client must reject.  It is deliberately narrow: it
tests one branch, but it tests it for real.

Coverage
--------
For each of two independent (server_hs_secret, transcript) vector sets:

  positive          correct verify_data                      -> expect C=0
  flip_first_byte   correct, one bit flipped in byte 0       -> expect C=1
  flip_last_byte    correct, one bit flipped in byte 31      -> expect C=1
  all_zeros         32 x 0x00                                -> expect C=1
  all_ones          32 x 0xFF                                -> expect C=1
  truncated         first 31 correct bytes then 0x00         -> expect C=1
  rotated           correct bytes rotated left by one        -> expect C=1
  wrong_secret      valid HMAC under a *different* secret    -> expect C=1
  wrong_transcript  valid HMAC over a *different* transcript -> expect C=1

The last two are the realistic attacks: an active attacker who cannot derive
the server handshake traffic secret, and one who tries to substitute a
different transcript.  ``truncated`` and ``rotated`` specifically catch a
compare loop that stops early or is off by one.

The positive case additionally asserts that the C64's *computed*
``tls_verify_data`` equals an independent Python computation, so a routine that
learned to always return C=0 without doing the HMAC cannot pass.

Reference implementation
------------------------
``hkdf_expand_label`` / HMAC-SHA256 are recomputed here in plain Python.  That
reference is itself pinned to RFC 8448 by ``tools/test_hkdf.py`` and
``tools/test_keyschedule_steps.py``; this file reuses RFC 8448 Section 3's
server handshake traffic secret as vector set A so the inputs are not
self-invented.

Usage:
    python3 tools/test_finished_verify.py [--verbose]

Env:
    C64_SKIP_BUILD=1   reuse the already-built PRG

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import subprocess
import sys

from c64_test_harness import (
    Labels,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _vice_helpers import default_vice_config  # noqa: E402

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

REQUIRED_LABELS = [
    "tls_verify_finished",
    "tls_verify_data",
    "tls_s_hs_secret",
    "tls_transcript",
    "tls_rec_buf",
]

# Cassette buffer. $033C-$03FB is free once BASIC has booted. The harness's
# own jsr() trampoline lives at $0334 (5 bytes) and run_subroutine's U64
# trampoline at $0360 (14 bytes) with flags at $03F0/$03F1 — $0340 and $034C
# collide with none of them.
CARRY_STUB_ADDR = 0x0340
CARRY_RESULT_ADDR = 0x034C


# ---------------------------------------------------------------------------
# Python reference (see module docstring for provenance)
# ---------------------------------------------------------------------------

def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1). L <= 32 only."""
    assert length <= 32
    info = struct.pack(">H", length)
    info += bytes([6 + len(label)]) + b"tls13 " + label
    info += bytes([len(context)]) + context
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def finished_verify_data(traffic_secret: bytes, transcript: bytes) -> bytes:
    """RFC 8446 Section 4.4.4 verify_data."""
    finished_key = hkdf_expand_label(traffic_secret, b"finished", b"", 32)
    return hmac.new(finished_key, transcript, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------

# RFC 8448 Section 3 server handshake traffic secret (same value the existing
# key-schedule test pins the C64 against).
SECRET_A = bytes.fromhex(
    "b67b7d690cc16c4e75e54213cb2d37b4"
    "e9c912bcded9105d42befd59d391ad38"
)
# An arbitrary but fixed transcript hash. Any 32 bytes is a legal input here;
# the HMAC is defined over whatever the running hash produced.
TRANSCRIPT_A = hashlib.sha256(b"c64-https lane B transcript A").digest()

# A second, independent vector set, so a routine that happens to be correct
# for one input pair cannot coast.
SECRET_B = hashlib.sha256(b"c64-https lane B secret B").digest()
TRANSCRIPT_B = hashlib.sha256(b"c64-https lane B transcript B").digest()

# Used only to build "valid HMAC, wrong key/context" forgeries.
DECOY_SECRET = hashlib.sha256(b"c64-https lane B decoy secret").digest()
DECOY_TRANSCRIPT = hashlib.sha256(b"c64-https lane B decoy transcript").digest()

VECTOR_SETS = [
    ("A (RFC 8448 s_hs_traffic)", SECRET_A, TRANSCRIPT_A),
    ("B (independent)", SECRET_B, TRANSCRIPT_B),
]


def build_cases(secret: bytes, transcript: bytes):
    """Return [(name, received_verify_data, expect_carry), ...]."""
    good = finished_verify_data(secret, transcript)

    flip_first = bytes([good[0] ^ 0x01]) + good[1:]
    flip_last = good[:31] + bytes([good[31] ^ 0x80])
    truncated = good[:31] + b"\x00"
    rotated = good[1:] + good[:1]
    wrong_secret = finished_verify_data(DECOY_SECRET, transcript)
    wrong_transcript = finished_verify_data(secret, DECOY_TRANSCRIPT)

    cases = [
        ("positive", good, 0),
        ("flip_first_byte", flip_first, 1),
        ("flip_last_byte", flip_last, 1),
        ("all_zeros", b"\x00" * 32, 1),
        ("all_ones", b"\xff" * 32, 1),
        ("truncated", truncated, 1),
        ("rotated", rotated, 1),
        ("wrong_secret", wrong_secret, 1),
        ("wrong_transcript", wrong_transcript, 1),
    ]

    # Sanity: every negative vector must genuinely differ from the correct one,
    # otherwise the "case" is not a negative case at all. Guards against a
    # degenerate vector (e.g. rotated == good for an all-same-byte digest).
    for name, vd, expect in cases:
        assert len(vd) == 32, f"{name}: verify_data must be 32 bytes"
        if expect == 1:
            assert vd != good, f"{name}: negative vector is not actually wrong"
        else:
            assert vd == good, f"{name}: positive vector is not the correct value"

    return cases, good


# ---------------------------------------------------------------------------
# C64 plumbing
# ---------------------------------------------------------------------------

def install_carry_stub(transport, target_addr: int) -> None:
    """Install a stub that calls *target_addr* and latches the carry flag.

        JSR target      20 lo hi
        LDA #$00        A9 00
        ROL A           2A        ; carry -> bit 0
        STA result      8D lo hi
        RTS             60

    Reading the P register back over the monitor is unreliable across
    backends; latching the flag into RAM from 6502 code is not. The stub is
    written once and reused for every case.
    """
    lo, hi = target_addr & 0xFF, (target_addr >> 8) & 0xFF
    rlo, rhi = CARRY_RESULT_ADDR & 0xFF, (CARRY_RESULT_ADDR >> 8) & 0xFF
    stub = bytes([0x20, lo, hi, 0xA9, 0x00, 0x2A, 0x8D, rlo, rhi, 0x60])
    write_bytes(transport, CARRY_STUB_ADDR, stub)
    readback = read_bytes(transport, CARRY_STUB_ADDR, len(stub))
    if readback != stub:
        raise RuntimeError(
            f"carry stub readback mismatch at ${CARRY_STUB_ADDR:04X}: "
            f"wrote {stub.hex()}, read {readback.hex()}"
        )


def call_verify_finished(transport, labels, secret: bytes, transcript: bytes,
                         received: bytes) -> tuple[int, bytes]:
    """Set up inputs, run tls_verify_finished, return (carry, computed_vd)."""
    write_bytes(transport, labels["tls_s_hs_secret"], secret)
    write_bytes(transport, labels["tls_transcript"], transcript)
    write_bytes(transport, labels["tls_rec_buf"] + 4, received)

    # Poison the output buffer and the carry latch so a routine that never
    # runs cannot be mistaken for one that ran and agreed with us.
    write_bytes(transport, labels["tls_verify_data"], b"\xa5" * 32)
    write_bytes(transport, CARRY_RESULT_ADDR, b"\xa5")

    jsr(transport, CARRY_STUB_ADDR, timeout=60.0)

    carry = read_bytes(transport, CARRY_RESULT_ADDR, 1)[0]
    if carry not in (0, 1):
        raise RuntimeError(
            f"carry latch never written (read ${carry:02X}) — the stub did "
            f"not complete; treat this run as inconclusive, not a pass"
        )
    computed = read_bytes(transport, labels["tls_verify_data"], 32)
    return carry, computed


# ---------------------------------------------------------------------------
# Test driver
# ---------------------------------------------------------------------------

def run_tests(transport, labels) -> tuple[int, int]:
    passed = failed = 0

    install_carry_stub(transport, labels["tls_verify_finished"])

    for set_name, secret, transcript in VECTOR_SETS:
        print(f"\n--- Vector set {set_name} ---")
        cases, good = build_cases(secret, transcript)

        for name, received, expect_carry in cases:
            carry, computed = call_verify_finished(
                transport, labels, secret, transcript, received
            )

            ok = carry == expect_carry
            detail = ""

            # The positive case also proves the routine actually computed the
            # HMAC rather than short-circuiting to "accept".
            if expect_carry == 0 and ok:
                if computed != good:
                    ok = False
                    detail = (
                        f"\n    computed verify_data mismatch"
                        f"\n      expected {good.hex()}"
                        f"\n      got      {computed.hex()}"
                    )

            verdict = "PASS" if ok else "FAIL"
            want = "C=0 accept" if expect_carry == 0 else "C=1 reject"
            got = "C=0 accept" if carry == 0 else "C=1 reject"
            print(f"  {verdict}: {name:<17} want {want}, got {got}{detail}")
            if VERBOSE:
                print(f"    received {received.hex()}")
                print(f"    computed {computed.hex()}")

            if ok:
                passed += 1
            else:
                failed += 1

    return passed, failed


def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    if "--verbose" in sys.argv:
        VERBOSE = True

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building ===")
        subprocess.run(["make", "clean"], capture_output=True)
        result = subprocess.run(["make"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return 1
        print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        return 1

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        # A missing label means the routine under test moved or was renamed.
        # That is a failure, never a skip — see audit finding F3.
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

    print("\n=== Labels ===")
    for name in REQUIRED_LABELS:
        print(f"  {name:<22} = ${labels[name]:04X}")

    print("\n=== Starting VICE ===")
    config = default_vice_config(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            mgr.release(inst)
            return 1
        print("  Main menu ready")

        print("\n=== tls_verify_finished ===")
        try:
            passed, failed = run_tests(transport, labels)
        finally:
            mgr.release(inst)

    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] Finished verify: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] Finished verify: {failed} TEST(S) FAILED")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
