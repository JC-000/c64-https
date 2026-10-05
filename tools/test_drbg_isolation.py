#!/usr/bin/env python3
"""test_drbg_isolation.py - the DRBG's K is not the HKDF's key buffer.

Why this exists
---------------
``hmac_sha256`` takes its key in ``hmac_key``. HKDF (extract and expand)
and the Finished MAC write that buffer, and until this fix it was ALSO the
HMAC_DRBG's K. A handshake's key schedule therefore left K holding a value
the peer knows (after ``tls_derive_traffic_keys``: the server application
traffic secret), and the next ``tls_connect`` in the same boot drew its
client_random (sent in clear) and then its ECDHE private key from that K:

    K' = HMAC(Kx, R || 00), V' = HMAC(K', R), privkey = HMAC(K', V')

where Kx is the key-schedule residue and R is ClientHello.random. Whoever
knew the previous session's key schedule -- its server, a keylog, or a MITM
whose handshake was rejected after ServerHello -- could compute the next
session's ECDHE key and decrypt it passively. The DRBG now keeps K in
``drbg_k``, private to src/crypto/hmac_drbg.s.

What this drives
----------------
No network. The image's own key-schedule routines run on random inputs,
then the exact two draws ``tls_connect`` makes (client_random, then the
ECDHE private key, 32 bytes each, through ``drbg_fill_bytes``) run from a
stub in the cassette buffer. On a tree without ``drbg_k`` the DRBG's K is
read from ``hmac_key``, so the same suite runs (and goes red) on a tree
that still aliases them.

Cases:

  state untouched     the DRBG state (K and V) is byte-identical before and
                      after each of tls_derive_handshake_keys,
                      tls_compute_finished and tls_derive_traffic_keys --
                      every HMAC user outside the DRBG. A future one that
                      writes DRBG state fails here.
  model check         a host HMAC_DRBG (SP 800-90A) started from the K and
                      V read off the image reproduces both draws exactly.
                      This is what makes the next case mean something: a
                      wrong host model would make "not predicted" vacuous.
  not predictable     after a full key schedule (session 1 completed) and
                      after only the handshake keys (a handshake rejected
                      at the certificate), the attacker's prediction --
                      K := hmac_key as the key schedule left it, plus the
                      ClientHello.random seen on the wire -- does NOT give
                      the second session's ECDHE private key.

Usage:
    python3 tools/test_drbg_isolation.py [--verbose]

Env:
    C64_SKIP_BUILD=1   reuse the already-built PRG (any backend but uci-m3,
                       which has no 6502 TLS and no DRBG)

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config, menu_wait  # noqa: E402
from _skip_policy import verdict  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# Every HMAC user outside the DRBG, as the entry points that reach it.
HMAC_USERS = [
    "tls_derive_handshake_keys",
    "tls_compute_finished",
    "tls_derive_traffic_keys",
]

# Key-schedule inputs, filled with random bytes before the routines run.
KS_INPUTS = [
    "tls_shared_secret",
    "tls_transcript",
    "tls_handshake_secret",
    "hkdf_prk",
]

REQUIRED_LABELS = [
    "hmac_key",
    "hmac_val",
    "drbg_fill_bytes",
    "drbg_buf_idx",
    "tls_client_random",
    "tls_ecdhe_privkey",
] + HMAC_USERS + KS_INPUTS

# Cassette buffer. Harness jsr() trampoline $0334, run_all_tests.py's loop
# $0339, test_finished_verify.py $0340-$0350, run_subroutine's U64
# trampoline $0360-$036D, test_body_truncation.py $0380-$03B1,
# test_tls_connected_latch.py $03C0-$03CB, run_subroutine's flags
# $03F0/$03F1. $03D0-$03EA collides with none of them.
DRAW_STUB_ADDR = 0x03D0   # 27 B -> $03EA


def H(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def drbg_generate(k: bytes, v: bytes) -> tuple[bytes, bytes, bytes]:
    """One HMAC_DRBG generate (32 B, no additional input): out, K, V."""
    v = H(k, v)
    out = v
    k = H(k, v + b"\x00")
    v = H(k, v)
    return out, k, v


def predict_from_k(k: bytes, client_random: bytes) -> bytes:
    """The attacker's computation: K known, V unknown, R seen on the wire.

    R is the first generate's output, i.e. the V that update() then uses,
    so V before the draw is never needed.
    """
    k2 = H(k, client_random + b"\x00")
    v2 = H(k2, client_random)
    return H(k2, v2)


class Patcher:
    """Write patches, remember the originals, put them all back."""

    def __init__(self, transport):
        self.transport = transport
        self.saved = []

    def patch(self, addr: int, data: bytes, what: str) -> None:
        self.saved.append((addr, read_bytes(self.transport, addr, len(data))))
        write_bytes(self.transport, addr, data)
        back = read_bytes(self.transport, addr, len(data))
        if back != data:
            raise RuntimeError(
                f"{what}: readback mismatch at ${addr:04X} - wrote "
                f"{data.hex()}, read {back.hex()}")

    def restore(self) -> None:
        for addr, original in reversed(self.saved):
            write_bytes(self.transport, addr, original)
        self.saved.clear()


def k_label(labels) -> str:
    """The DRBG's K: drbg_k on a fixed tree, hmac_key on one that aliases."""
    return "drbg_k" if labels.address("drbg_k") is not None else "hmac_key"


def assert_shadow_ram_readable(transport, labels) -> None:
    """FATAL unless the DRBG state reads back as RAM, not BASIC ROM."""
    for name in (k_label(labels), "hmac_val"):
        addr = labels[name]
        original = read_bytes(transport, addr, 1)
        for probe in (0x5A, 0xA5):
            write_bytes(transport, addr, bytes([probe]))
            got = read_bytes(transport, addr, 1)[0]
            if got != probe:
                raise RuntimeError(
                    f"shadow RAM not readable at {name} (${addr:04X}): "
                    f"wrote ${probe:02X}, read ${got:02X}. Inconclusive, "
                    f"not a pass.")
        write_bytes(transport, addr, original)


def drbg_state(transport, labels) -> tuple[bytes, bytes]:
    return (read_bytes(transport, labels[k_label(labels)], 32),
            read_bytes(transport, labels["hmac_val"], 32))


def randomize_ks_inputs(transport, labels) -> None:
    for name in KS_INPUTS:
        write_bytes(transport, labels[name], os.urandom(32))


def two_draws(transport, labels) -> tuple[bytes, bytes, bytes, bytes]:
    """tls_connect's two draws, from a stub; returns (K, V, R, privkey).

    drbg_buf_idx is set to 32 first: that is what both a fresh boot and a
    completed connection (exactly 64 bytes drawn) leave, and it makes the
    first byte come from a fresh generate as it does in the field.
    """
    cr = labels["tls_client_random"]
    pk = labels["tls_ecdhe_privkey"]
    fill = labels["drbg_fill_bytes"]
    stub = bytearray()
    for dst in (cr, pk):
        stub += bytes([0xA9, dst & 0xFF, 0x85, 0xFB,      # zp_ptr = dst
                       0xA9, dst >> 8, 0x85, 0xFC,
                       0xA9, 32,                          # A = 32
                       0x20, fill & 0xFF, fill >> 8])     # JSR drbg_fill_bytes
    stub += b"\x60"
    p = Patcher(transport)
    try:
        p.patch(DRAW_STUB_ADDR, bytes(stub), "draw stub")
        write_bytes(transport, labels["drbg_buf_idx"], bytes([32]))
        k, v = drbg_state(transport, labels)
        jsr(transport, DRAW_STUB_ADDR, timeout=120.0)
    finally:
        p.restore()
    return (k, v, read_bytes(transport, cr, 32), read_bytes(transport, pk, 32))


def run_tests(transport, labels) -> tuple[int, int]:
    passed = failed = 0

    assert_shadow_ram_readable(transport, labels)
    print(f"  DRBG K read from {k_label(labels)}; shadow RAM readable "
          f"(positive control OK)")

    def report(name, why, checks, detail=""):
        nonlocal passed, failed
        ok = all(good for _, good in checks)
        print(f"\n  [{'+' if ok else '-'}] {name}")
        print(f"        {why}")
        if detail:
            print(f"        {detail}")
        for label, good in checks:
            if not good or VERBOSE:
                print(f"        {'ok  ' if good else 'FAIL'} {label}")
        if ok:
            passed += 1
        else:
            failed += 1

    # --- every HMAC user leaves the DRBG state alone ---------------------
    for name in HMAC_USERS:
        randomize_ks_inputs(transport, labels)
        k0, v0 = drbg_state(transport, labels)
        jsr(transport, labels[name], timeout=300.0)
        k1, v1 = drbg_state(transport, labels)
        report(f"{name} leaves the DRBG state alone",
               "an HMAC user outside the DRBG must not write K or V",
               [("K unchanged", k0 == k1), ("V unchanged", v0 == v1)],
               f"K {k0.hex()[:16]}.. -> {k1.hex()[:16]}..")

    # --- the next session's key is not a function of the last schedule ---
    for scenario, routines in (
            ("after a completed handshake (session 1 key schedule)",
             ["tls_derive_handshake_keys", "tls_derive_traffic_keys"]),
            ("after a handshake rejected at the certificate",
             ["tls_derive_handshake_keys"])):
        randomize_ks_inputs(transport, labels)
        for name in routines:
            jsr(transport, labels[name], timeout=300.0)
        kx = read_bytes(transport, labels["hmac_key"], 32)
        k, v, r2, priv2 = two_draws(transport, labels)
        out1, k1, v1 = drbg_generate(k, v)
        out2, _, _ = drbg_generate(k1, v1)
        report(f"model check {scenario}",
               "a host HMAC_DRBG from the image's own K,V reproduces both "
               "draws, so the prediction below is a fair attack",
               [("client_random == generate #1", out1 == r2),
                ("ECDHE privkey == generate #2", out2 == priv2)])
        pred = predict_from_k(kx, r2)
        report(f"ECDHE key not predictable {scenario}",
               "K := the key-schedule residue in hmac_key, plus the "
               "ClientHello.random on the wire, must not give the key",
               [("prediction != ECDHE privkey", pred != priv2),
                ("DRBG K != key-schedule residue", k != kx)],
               f"privkey {priv2.hex()[:16]}..  predicted {pred.hex()[:16]}..")

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
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

    print("\n=== Labels ===")
    for name in [k_label(labels)] + REQUIRED_LABELS:
        print(f"  {name:<26} = ${labels[name]:04X}")

    print("\n=== Starting VICE ===")
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=menu_wait(120),
                             verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            mgr.release(inst)
            return 1
        print("  Main menu ready")

        print("\n=== DRBG state isolation ===")
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
        print(f"\n  [+] DRBG isolation: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] DRBG isolation: {failed} TEST(S) FAILED")
    print("=" * 60)

    return verdict(passed, failed,
                   certifies="DRBG state isolation from HKDF/HMAC")


if __name__ == "__main__":
    sys.exit(main())
