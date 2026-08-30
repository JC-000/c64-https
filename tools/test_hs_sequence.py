#!/usr/bin/env python3
"""test_hs_sequence.py — TLS 1.3 handshake message SEQUENCE enforcement (issue #152).

Why this exists
---------------
``tls_connect`` (src/tls13.s) walks the encrypted half of the handshake with
four *unconditional* receives::

    lda #TLS_STATE_ENCRYPTED_EXT / sta tls_state / jsr tls_recv_encrypted
    lda #TLS_STATE_CERTIFICATE   / sta tls_state / jsr tls_recv_encrypted
    lda #TLS_STATE_CERT_VERIFY   / sta tls_state / jsr tls_recv_encrypted
    lda #TLS_STATE_FINISHED      / sta tls_state / jsr tls_recv_encrypted

Each returns C=0 as soon as **one** handshake message of **any** type has
dispatched. Before the fix, nothing compared the received type against
``tls_state``, so a server could satisfy all four calls with four messages of
one harmless type and the client would derive traffic keys having
authenticated nothing — no Certificate, no CertificateVerify, no server
Finished. It also bypasses the issue #135 server-name validation, which is a
tail call off ``x509_extract_pubkey``: omit the Certificate and it never runs.

Why this test drives the PUMP and not the dispatcher
----------------------------------------------------
The first version of this file called ``df_dispatch`` directly. It passed, and
it was worthless as a security test: adversarial review then found a working
exploit against the very build it had just certified. ``df_dispatch`` is only
one of the deframer's exits. A Certificate whose bytes span records is routed
at ``@route_spanning`` to ``df_stream_begin`` and consumed incrementally by
``df_stream_body``, which returns C=0 from ``@msg_end`` **without ever calling
df_dispatch**. The gate lived in ``df_dispatch``, so streamed Certificates
skipped it, and four of them — the attacker picks the record framing, so a
2-byte first record forces the spanning route for a Certificate of any size —
satisfied the whole flight.

The property under test is therefore **"no message is accepted without passing
the check"**, which is a claim about every path, not about one function. So
every case here goes through the real entry point, ``tls_deframe_pump``, and
each is run in three record framings that provably take three different routes
through the deframer:

    one_record    header + body in one record   -> @in_place    -> df_dispatch
    body_split    body cut across records       -> @route_carry -> df_dispatch
                  ...except Certificate, which  -> df_stream_begin
    header_split  2-byte first record           -> @route_carry -> df_dispatch
                  ...except Certificate, which  -> df_stream_begin

The gate now sits at ``@hdr_complete``, upstream of the fork, so all three
inherit it; these framings are what proves that rather than assuming it.

Oracle
------
For a message presented at the WRONG step, the only acceptable outcome is
``[("err", DF_ERR_SEQ)]``: rejected, and rejected *because of the sequence*,
before any handler ran. "Rejected with some other error" is not a pass — that
is what master did when a handler happened to choke on the bytes, and it is
how a reordered flight could still be laundered through a tolerant handler.

For a message presented at the RIGHT step, the gate must let it reach its
route. EncryptedExtensions has no handler, so it must be accepted outright;
the other three carry deliberately malformed bodies here, so they must fail
*downstream* with any error except DF_ERR_SEQ. Those cases are the
anti-vacuity control: a gate that rejected everything, or one that rejected by
message type alone, fails them.

Requires a ``TLS_STREAM_DEFRAME`` build (default under BACKEND=uci)::

    make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1
    C64_SKIP_BUILD=1 python3 tools/test_hs_sequence.py

Under ip65 the deframer does not exist and the test skips loudly (exit 2). The
ip65 arm carries the same gate from the same ``TLS_HS_SEQ_CHECK`` macro, but
its dispatch is inline inside ``tls_recv_encrypted`` with no callable entry
point; exercise it with ``CERT_MODE=omit`` in
``tools/https_e2e/evil_listener.py``.

Usage:
    python3 tools/test_hs_sequence.py [--verbose]

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
    wait_for_text,
)

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _vice_helpers import default_vice_config  # noqa: E402

# The deframer rig (stub installer + Rig.drive) lives in the deframer's own
# test module. Sharing it keeps ONE implementation of "pump this flight and
# report the events", so this file cannot drift into testing a different
# entry point than the deframer suite does — which is the exact mistake this
# rewrite exists to correct.
import test_tls_deframe as D  # noqa: E402

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

REQUIRED_LABELS = [
    "tls_deframe_pump",
    "tls_hs_allowed",
    "tls_hostname", "tls_hostname_len",
    "tls_deframe_init",
    "tls_deframe_new_record",
    "df_last_err",
    "tls_rec_buf", "tls_rec_len",
    "tls_transcript_init", "tls_transcript_hash", "tls_transcript",
    "tls_state",
]

STATE_NAMES = {
    D.TLS_STATE_ENCRYPTED_EXT: "ENCRYPTED_EXT",
    D.TLS_STATE_CERTIFICATE: "CERTIFICATE",
    D.TLS_STATE_CERT_VERIFY: "CERT_VERIFY",
    D.TLS_STATE_FINISHED: "FINISHED",
}

TYPE_NAMES = {
    D.HS_EE: "EncryptedExtensions",
    D.HS_CERT: "Certificate",
    D.HS_CV: "CertificateVerify",
    D.HS_FIN: "Finished",
}

# Bodies are deliberately malformed (not DER, not a valid verify_data) so the
# right-step cases fail fast downstream instead of running real crypto. 40
# bytes is long enough to cut in the middle for the spanning framings.
BODY = bytes(range(40))

ALL_TYPES = [D.HS_EE, D.HS_CERT, D.HS_CV, D.HS_FIN]

# Hostname for the real-certificate control. x509_name.s rejects a cert whose
# SAN does not match tls_hostname — and rejects everything when
# tls_hostname_len is 0, which is the state a DMA rig leaves it in because
# http_get (the only writer) never runs. Setting it is what makes the accept
# control an actual accept instead of a reject for an unrelated reason.
CONTROL_HOST = "www.foo.bar"


def gen_cert_with_san(host: str) -> bytes:
    """Self-signed P-256 leaf carrying a SAN dNSName — the only shape
    x509_name.s accepts (no-SAN certs are rejected outright)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC)
                             + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)
ALL_STATES = [
    D.TLS_STATE_ENCRYPTED_EXT,
    D.TLS_STATE_CERTIFICATE,
    D.TLS_STATE_CERT_VERIFY,
    D.TLS_STATE_FINISHED,
]


def framings(msg: bytes) -> list[tuple[str, list[bytes], str]]:
    """(name, records, route) for each of the three deframer routes."""
    return [
        ("one_record", [msg], "@in_place"),
        # Header intact, body cut: @route_spanning. Certificate goes to the
        # streaming consumer from there, everything else to the carry buffer.
        ("body_split", [msg[:12], msg[12:]], "@route_spanning"),
        # Two-byte first record: splits the 4-byte handshake header itself.
        # This is the framing that costs an attacker nothing and forces the
        # spanning route for a message of ANY size.
        ("header_split", [msg[:2], msg[2:]], "@route_spanning"),
    ]


def route_for(msg_type: int, framing: str) -> str:
    if framing == "one_record":
        return "in-place -> df_dispatch"
    if msg_type == D.HS_CERT:
        return "spanning -> df_stream_begin"
    return "spanning -> carry -> df_dispatch"


def run_tests(transport, labels) -> tuple[int, int]:
    passed = failed = 0
    rig = D.Rig(transport, labels)
    D.install_stub(transport, labels["tls_deframe_pump"])

    for msg_type in ALL_TYPES:
        msg = D.hs_msg(msg_type, BODY)
        due_state = D.STATE_FOR_TYPE[msg_type]

        for state in ALL_STATES:
            wrong_step = state != due_state

            for framing, records, _fork in framings(msg):
                rig.reset()
                ev = rig.drive(records, states=[state])

                route = route_for(msg_type, framing)
                if wrong_step:
                    ok = ev == [("err", D.ERR_SEQ)]
                    want = "ERR_SEQ before any handler"
                else:
                    # Right step: the gate must let it through to its route.
                    if msg_type == D.HS_EE:
                        ok = ev == ["msg"]
                        want = "accepted"
                    else:
                        ok = (len(ev) == 1 and isinstance(ev[0], tuple)
                              and ev[0][0] == "err" and ev[0][1] != D.ERR_SEQ)
                        want = "reaches its route (any error but ERR_SEQ)"

                verdict = "PASS" if ok else "FAIL"
                print(f"  {verdict}: {STATE_NAMES[state]:<14} <- "
                      f"{TYPE_NAMES[msg_type]:<20} {framing:<13} "
                      f"want {want}, got {ev}")
                if VERBOSE:
                    print(f"        route: {route}")

                if ok:
                    passed += 1
                else:
                    failed += 1

    # ---- Teeth for the two range checks -----------------------------------
    # The gate's `cpx` bounds are what stop an out-of-window tls_state from
    # indexing outside the 4-byte table. Simply presenting a message at state
    # 0 or 7 does NOT test them: with the bounds deleted the index lands on
    # neighbouring CODE bytes, which are unlikely to equal the type under
    # test, so the reject still happens — by accident of code layout.
    # (Measured: deleting both bounds left an earlier version of this file at
    # 11/11.) So read the bytes the mutated compare WOULD hit and use each as
    # the message type. With the bounds present these are refused for being
    # out of window; with either bound gone the compare matches and the
    # message escapes into the type switch.
    table_addr = labels["tls_hs_allowed"]
    table = read_bytes(transport, table_addr, 4)
    want_table = bytes([D.HS_EE, D.HS_CERT, D.HS_CV, D.HS_FIN])
    ok = table == want_table
    print(f"  {'PASS' if ok else 'FAIL'}: tls_hs_allowed = {table.hex()} "
          f"(want {want_table.hex()})")
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

    for state, label in ((0, "IDLE"), (7, "CONNECTED"), (0xFF, "ERROR")):
        # Index the gate would compute for this state, without the bounds.
        ghost_addr = table_addr + (state - D.TLS_STATE_ENCRYPTED_EXT)
        ghost = read_bytes(transport, ghost_addr & 0xFFFF, 1)[0]
        msg = D.hs_msg(ghost, BODY)
        for framing, records, _fork in framings(msg):
            rig.reset()
            ev = rig.drive(records, states=[state])
            ok = ev == [("err", D.ERR_SEQ)]
            verdict = "PASS" if ok else "FAIL"
            print(f"  {verdict}: state {label:<9} <- type ${ghost:02X} "
                  f"(the byte at tls_hs_allowed{state - 3:+d}) {framing:<13} "
                  f"want ERR_SEQ, got {ev}")
            if ok:
                passed += 1
            else:
                failed += 1

    # ---- Real certificate: the accept control on the streamed route -------
    # Everything above uses malformed bodies, so none of it proves the gate
    # still lets a GENUINE Certificate through the route that was bypassed.
    # This does: a real P-256 leaf with a matching SAN, staged into cert_buf
    # by the streaming consumer, parsed by x509_extract_pubkey and passed by
    # the issue #135 hostname check — then the SAME BYTES at the wrong step,
    # in both framings, which must be refused. That pair (accept here, reject
    # there, identical input) is the property in one screenful.
    write_bytes(transport, labels["tls_hostname"],
                CONTROL_HOST.encode() + b"\x00")
    write_bytes(transport, labels["tls_hostname_len"], bytes([len(CONTROL_HOST)]))

    leaf = gen_cert_with_san(CONTROL_HOST)
    real_cert = D.cert_msg([(leaf, b"")])

    controls = [
        ("real Certificate, spanning, at CERTIFICATE step",
         [real_cert[:2], real_cert[2:]], D.TLS_STATE_CERTIFICATE, ["msg"]),
        ("real Certificate, spanning, at FINISHED step",
         [real_cert[:2], real_cert[2:]], D.TLS_STATE_FINISHED,
         [("err", D.ERR_SEQ)]),
        ("real Certificate, one record, at FINISHED step",
         [real_cert], D.TLS_STATE_FINISHED, [("err", D.ERR_SEQ)]),
    ]
    for name, records, state, want in controls:
        rig.reset()
        ev = rig.drive(records, states=[state])
        ok = ev == want
        verdict = "PASS" if ok else "FAIL"
        print(f"  {verdict}: {name}, want {want}, got {ev}")
        if ok:
            passed += 1
        else:
            failed += 1

    # ---- The exploit itself, as one assertion -----------------------------
    # Four spanning Certificates, one per tls_connect receive. Before the fix
    # this returned ['msg', 'msg', 'msg', 'msg'] — all four receives satisfied
    # with no CertificateVerify and no server Finished.
    # Uses the REAL certificate: with a malformed body the flight dies in the
    # DER parser on a vulnerable build, which looks like a reject and hides
    # the finding. A valid leaf with a matching SAN is what the attacker
    # would actually send — it costs them nothing, since nothing here
    # validates a chain.
    flight: list[bytes] = []
    for _ in range(4):
        flight += [real_cert[:2], real_cert[2:]]
    rig.reset()
    ev = rig.drive(flight, states=ALL_STATES)
    ok = ev == [("err", D.ERR_SEQ)]
    verdict = "PASS" if ok else "FAIL"
    print(f"  {verdict}: four spanning Certificates cannot satisfy the four "
          f"receives, got {ev}")
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
        result = subprocess.run(
            ["make", "BACKEND=uci", "USE_NISTCURVES_ONCHIP=1"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return 1
        print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        return 1

    labels = Labels.from_file(LABELS_PATH)

    if labels.address("tls_deframe_pump") is None:
        print(
            "\nSKIP: tls_deframe_pump not in build/labels.txt — this is not a\n"
            "      TLS_STREAM_DEFRAME build. Rebuild with\n"
            "        make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1\n"
            "      The ip65 arm carries the same gate (same TLS_HS_SEQ_CHECK\n"
            "      macro) but is inline inside tls_recv_encrypted; exercise it\n"
            "      with CERT_MODE=omit in tools/https_e2e/evil_listener.py."
        )
        return 2

    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

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

        print("\n=== handshake sequence gate, through tls_deframe_pump ===")
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
        print(f"\n  [+] Handshake sequence: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] Handshake sequence: {failed} TEST(S) FAILED")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
