#!/usr/bin/env python3
"""test_ecdh_zero_check.py — X25519 all-zero shared-secret rejection (issue #153).

Why this exists
---------------
RFC 8446 Section 7.4.2 and RFC 7748 Section 6.1 both require the same check:

    "the recipient MUST check whether the computed shared secret is the
     all-zero value and abort if so"

Until this test existed, ``tls_ecdh_compute_shared`` (src/tls_ecdh.s) copied
``x25_result`` into ``tls_shared_secret`` unconditionally and returned with the
carry undefined, and ``tls13.s`` followed the call with an unconditional ``clc``.

A server (or an on-path attacker rewriting the ServerHello) that sends a
low-order ``key_share`` — 32 zero bytes is the simplest one — drives
``x25519(k, U) = 0`` for every clamped scalar ``k``. The whole key schedule
then collapses to a constant:

    early_secret      = HKDF-Extract(0^32, 0^32)            constant
    derived           = Derive-Secret(early, "derived", H(""))  constant
    handshake_secret  = HKDF-Extract(derived, 0^32)         constant

and every secret below it is ``Derive-Secret(constant, label,
Transcript-Hash(CH || SH))`` over two *plaintext* messages. Any passive
observer who recorded the session can then derive the traffic keys and decrypt
it — the attacker who injected the bad key_share need not stay on the path.
That is a passive break, strictly worse than the documented "an active attacker
can impersonate any server" caveat.

What this test does
-------------------
It drives ``tls_ecdh_compute_shared`` directly over the binary monitor with a
chosen ``tls_server_pubkey`` and asserts the returned carry, using the same
carry-latching stub pattern as ``tools/test_finished_verify.py`` (reading the
P register back over the monitor is not reliable across backends; latching the
flag into RAM from 6502 code is).

Cases (one X25519 scalar multiplication each, ~15-20 s under VICE warp):

  zero               32 x 0x00                       -> expect C=1
  one                0x01 then 31 x 0x00             -> expect C=1
  order8_a           low-order point, order 8        -> expect C=1
  order8_b           low-order point, order 8        -> expect C=1
  p_minus_1          p-1 (order 2)                   -> expect C=1
  honest_basepoint   u = 9 (the X25519 base point)   -> expect C=0

The negative vectors are the canonical small-subgroup points listed in
RFC 7748 Section 6.1's security note and reproduced in every "contributory
behaviour" test suite. Because the client clamps its scalar (k is a multiple
of 8), each of them multiplies to the identity and X25519 emits 32 zero bytes.

The honest case is the anti-vacuity control in two independent ways: the carry
must be clear, AND the 32 bytes the C64 computed must equal an independent
Python X25519 of the same inputs. A "fix" that rejects everything, or one that
returns C=0 without computing anything, fails here.

Usage:
    python3 tools/test_ecdh_zero_check.py [--verbose]

Env:
    C64_SKIP_BUILD=1   reuse the already-built PRG

Requires: Python 3.10+, c64_test_harness, cryptography, VICE x64sc
"""

from __future__ import annotations

import os
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

from cryptography.hazmat.primitives.asymmetric import x25519

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _vice_helpers import default_vice_config  # noqa: E402

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

REQUIRED_LABELS = [
    "tls_ecdh_compute_shared",
    "tls_ecdhe_privkey",
    "tls_server_pubkey",
    "tls_shared_secret",
]

# Same cassette-buffer slots test_finished_verify.py uses: $0334 (harness jsr
# trampoline), $0360/$03F0 (U64 trampoline + flags) are the occupied ones.
CARRY_STUB_ADDR = 0x0340
CARRY_RESULT_ADDR = 0x034C

# A fixed, arbitrary client scalar. Clamping happens inside
# tls_ecdh_compute_shared (and inside the Python reference), so the raw bytes
# can be anything.
CLIENT_PRIVKEY = bytes(range(0x40, 0x60))

P = (1 << 255) - 19


def _le32(n: int) -> bytes:
    return n.to_bytes(32, "little")


# RFC 7748 Section 6.1 security note: the points of small order on
# Curve25519. Every one of them yields an all-zero X25519 output for any
# clamped scalar.
LOW_ORDER_POINTS = [
    ("zero", bytes(32)),
    ("one", b"\x01" + bytes(31)),
    ("order8_a", bytes.fromhex(
        "e0eb7a7c3b41b8ae1656e3faf19fc46a"
        "da098deb9c32b1fd866205165f49b800")),
    ("order8_b", bytes.fromhex(
        "5f9c95bca3508c24b1d0b1559c83ef5b"
        "04445cc4581c8e86d8224eddd09f1157")),
    ("p_minus_1", _le32(P - 1)),
]

HONEST_PUBKEY = b"\x09" + bytes(31)


def python_x25519(priv: bytes, pub: bytes) -> bytes:
    """Reference X25519. Returns b'' when the output is all-zero.

    ``cryptography`` refuses to hand back an all-zero shared secret (it raises
    ValueError), which is itself an independent confirmation that these
    vectors are the degenerate ones — but it means the reference cannot be
    used to *produce* the zero value, only to recognise it.
    """
    try:
        return (x25519.X25519PrivateKey.from_private_bytes(priv)
                .exchange(x25519.X25519PublicKey.from_public_bytes(pub)))
    except ValueError:
        return b""


def install_carry_stub(transport, target_addr: int) -> None:
    """Install a stub that calls *target_addr* and latches the carry flag.

        JSR target      20 lo hi
        LDA #$00        A9 00
        ROL A           2A        ; carry -> bit 0
        STA result      8D lo hi
        RTS             60
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


def call_compute_shared(transport, labels, server_pub: bytes) -> tuple[int, bytes]:
    """Run tls_ecdh_compute_shared for *server_pub*; return (carry, secret)."""
    write_bytes(transport, labels["tls_ecdhe_privkey"], CLIENT_PRIVKEY)
    write_bytes(transport, labels["tls_server_pubkey"], server_pub)

    # Poison the output and the carry latch: a routine that never runs must
    # not be mistaken for one that ran and agreed with us.
    write_bytes(transport, labels["tls_shared_secret"], b"\xa5" * 32)
    write_bytes(transport, CARRY_RESULT_ADDR, b"\xa5")

    # A single scalar multiplication is ~15-20 s under VICE warp.
    jsr(transport, CARRY_STUB_ADDR, timeout=600.0)

    carry = read_bytes(transport, CARRY_RESULT_ADDR, 1)[0]
    if carry not in (0, 1):
        raise RuntimeError(
            f"carry latch never written (read ${carry:02X}) — the stub did "
            f"not complete; treat this run as inconclusive, not a pass"
        )
    secret = read_bytes(transport, labels["tls_shared_secret"], 32)
    return carry, secret


def run_tests(transport, labels) -> tuple[int, int]:
    passed = failed = 0

    install_carry_stub(transport, labels["tls_ecdh_compute_shared"])

    cases = [(name, pub, 1) for name, pub in LOW_ORDER_POINTS]
    cases.append(("honest_basepoint", HONEST_PUBKEY, 0))

    for name, server_pub, expect_carry in cases:
        carry, secret = call_compute_shared(transport, labels, server_pub)

        ok = carry == expect_carry
        detail = ""

        if expect_carry == 1:
            # The premise of the case: this key_share really does drive the
            # shared secret to zero. If the C64 computed something non-zero
            # the vector is wrong, not the check.
            if secret != bytes(32) and secret != b"\xa5" * 32:
                ok = False
                detail = (
                    f"\n    vector premise broken: shared secret is not "
                    f"all-zero ({secret.hex()})"
                )
        else:
            # Compared unconditionally, so a carry failure still reports
            # whether the arithmetic itself was right — the two are
            # independent defects and the output must say which one bit.
            reference = python_x25519(CLIENT_PRIVKEY, server_pub)
            if secret != reference:
                ok = False
                detail = (
                    f"\n    computed shared secret mismatch"
                    f"\n      expected {reference.hex()}"
                    f"\n      got      {secret.hex()}"
                )
            else:
                detail = "\n    (shared secret matches the Python reference)"

        verdict = "PASS" if ok else "FAIL"
        want = "C=0 accept" if expect_carry == 0 else "C=1 abort"
        got = "C=0 accept" if carry == 0 else "C=1 abort"
        print(f"  {verdict}: {name:<17} want {want}, got {got}{detail}")
        if VERBOSE:
            print(f"    key_share     {server_pub.hex()}")
            print(f"    shared_secret {secret.hex()}")

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
        # That is a failure, never a skip.
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

    print("\n=== Labels ===")
    for name in REQUIRED_LABELS:
        print(f"  {name:<24} = ${labels[name]:04X}")

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

        print("\n=== tls_ecdh_compute_shared: all-zero shared secret ===")
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
        print(f"\n  [+] X25519 zero-check: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] X25519 zero-check: {failed} TEST(S) FAILED")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
