#!/usr/bin/env python3
"""test_x509_name.py — server name validation (issue #135).

Drives `x509_verify_hostname` directly over DMA: stage a DER certificate in
cert_buf, point cert_data_ptr at it, set tls_hostname, JSR, read the carry.

The vector set is deliberately NEGATIVE-HEAVY. An all-positive set passes
against a routine stubbed to `clc; rts` and therefore proves nothing — the
same trap recorded as finding F7 in tools/test_ecdsa_kat_oracle.py. Nine of
the fourteen vectors below expect a REJECT, including the four wildcard
over-match cases that are the classic way name checking goes wrong.

One vector is a REAL certificate — tools/https_e2e/certs/server.pem, the one
the bundled listener serves — parsed from its own DER rather than synthesised
here. A parser that only ever sees certificates written by its own test is
not being tested against reality.

    make BACKEND=uci && C64_SKIP_BUILD=1 python3 tools/test_x509_name.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceInstanceManager, read_bytes, write_bytes, goto, wait_for_text,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools", "package", "listener"))
# The names the bundled listener's certificate actually carries. Single
# source (gen_certs.DEFAULT_SANS); the real-cert vectors below are built
# from it so they can never drift out of step with server.pem.
from gen_certs import DEFAULT_SANS as CERT_SANS  # noqa: E402
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
REAL_CERT = os.path.join(PROJECT_ROOT, "tools", "https_e2e", "certs", "server.pem")

CARRY_TRAMPOLINE = 0x033C
CARRY_RESULT_ADDR = 0x0352
CARRY_FLAG_ADDR = 0x0353


# --- minimal DER builder -----------------------------------------------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len(len(payload)) + payload


def make_cert(dns_names, *, san=True, tag=0x82, include_version=True,
              critical=False) -> bytes:
    """A structurally valid certificate carrying only what the walker reads.

    issuer / validity / subject / SPKI are empty SEQUENCEs: the routine skips
    them with der_skip_tlv and never looks inside, so their contents are
    irrelevant to what is under test and inventing plausible ones would only
    add ways for the fixture itself to be wrong.
    """
    tbs = b""
    if include_version:
        tbs += tlv(0xA0, tlv(0x02, b"\x02"))
    tbs += tlv(0x02, b"\x01")            # serialNumber
    tbs += tlv(0x30, b"")                # signature AlgorithmIdentifier
    tbs += tlv(0x30, b"")                # issuer
    tbs += tlv(0x30, b"")                # validity
    tbs += tlv(0x30, b"")                # subject
    tbs += tlv(0x30, b"")                # subjectPublicKeyInfo
    if san:
        names = b"".join(tlv(tag, n.encode()) for n in dns_names)
        ext = tlv(0x06, b"\x55\x1d\x11")
        if critical:
            ext += tlv(0x01, b"\xff")
        ext += tlv(0x04, tlv(0x30, names))
        tbs += tlv(0xA3, tlv(0x30, tlv(0x30, ext)))
    else:
        # extensions present but no SAN among them (basicConstraints 2.5.29.19)
        other = tlv(0x06, b"\x55\x1d\x13") + tlv(0x04, tlv(0x30, b""))
        tbs += tlv(0xA3, tlv(0x30, tlv(0x30, other)))
    return tlv(0x30, tlv(0x30, tbs) + tlv(0x30, b"") + tlv(0x03, b"\x00"))


def live_leaf(host: str):
    """Fetch a real server's leaf DER. Returns None if offline.

    This is the vector class that matters most: a parser exercised only against
    certificates its own test wrote is not evidence about the certificates the
    client will actually meet. These leaves carry a dozen real extensions, SAN
    is not the first of them, and wikipedia's has 30+ names.
    """
    import ssl, socket
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sk:
            with ctx.wrap_socket(sk, server_hostname=host) as t:
                return t.getpeercert(True)
    except Exception:
        return None


def real_cert_der() -> bytes | None:
    try:
        out = subprocess.run(["openssl", "x509", "-in", REAL_CERT, "-outform", "der"],
                             capture_output=True, check=True)
        return out.stdout
    except Exception:
        return None


# --- vectors -----------------------------------------------------------------
# (name, cert bytes-or-None-for-real, hostname, expected carry)
def build_vectors():
    v = []
    real = real_cert_der()
    if real:
        # Derived from the cert's own SAN entries rather than spelled out, so
        # renaming the test identity cannot leave these vectors testing a name
        # the listener no longer serves — they would still all PASS, having
        # quietly stopped exercising the real certificate at all. CERT_SANS is
        # the bare name + its `www.` prefix; that shape is what makes the last
        # two vectors meaningful, and tools/test_reserved_test_host.py pins it.
        bare, www = sorted(CERT_SANS, key=len)
        for host, want, why in [
            (www,          0, "matches the 2nd SAN entry of the real listener cert"),
            (bare,         0, "matches the 1st SAN entry"),
            (www.upper(),  0, "DNS names are case-insensitive (RFC 4343)"),
            ("evil.example", 1, "REJECT: name not in the cert"),
            (www[:-1],     1, "REJECT: prefix of a SAN entry must not match"),
            (www + "x",    1, "REJECT: SAN entry is a prefix of the host"),
        ]:
            v.append((f"real cert / {host}", real, host, want, why))
    else:
        print("  NOTE: openssl unavailable — real-certificate vectors skipped")

    for cert_names, host, want, why in [
        (["example.org"],   "example.org",     0, "exact single name"),
        (["*.example.org"], "www.example.org", 0, "wildcard matches one label"),
        (["*.example.org"], "example.org",     1, "REJECT: wildcard needs a label"),
        (["*.example.org"], "a.b.example.org", 1, "REJECT: wildcard spans one label only"),
        (["*.com"],         "example.com",     1, "REJECT: wildcard suffix has no dot"),
        (["a.test", "b.test"], "b.test",       0, "matches a later entry in the list"),
        (["example.org"],   "attacker.org",    1, "REJECT: different name"),
    ]:
        v.append((f"synthetic {cert_names} / {host}", make_cert(cert_names), host, want, why))

    v.append(("SAN present, no dNSName (tag 0x81)",
              make_cert(["a@example.org"], tag=0x81), "example.org", 1,
              "REJECT: rfc822Name is not a dNSName"))
    v.append(("no SAN extension at all",
              make_cert([], san=False), "example.org", 1,
              "REJECT: modern clients require SAN"))
    v.append(("SAN marked critical",
              make_cert(["example.org"], critical=True), "example.org", 0,
              "the optional critical BOOLEAN must be stepped over"))
    if os.environ.get("X509_NAME_OFFLINE") != "1":
        for host, wrong in [("en.wikipedia.org", "en.wikipedia.org.evil.test"),
                            ("github.com",       "githubb.com"),
                            ("lwn.net",          "lwn.net.attacker.test")]:
            der = live_leaf(host)
            if der is None:
                print(f"  NOTE: {host} unreachable — live vector skipped")
                continue
            v.append((f"LIVE {host} ({len(der)} B) / {host}", der, host, 0,
                      "a real CA-issued leaf must still be ACCEPTED"))
            v.append((f"LIVE {host} / {wrong}", der, wrong, 1,
                      "REJECT: real cert, wrong host"))

    v.append(("v1 cert (no [0] version)",
              make_cert(["example.org"], include_version=False), "example.org", 0,
              "version is OPTIONAL; the walk must not assume it"))
    return v


def jsr_with_carry(transport, addr, timeout=60.0, poll=1.0):
    lo, hi = addr & 0xFF, (addr >> 8) & 0xFF
    rl, rh = CARRY_RESULT_ADDR & 0xFF, (CARRY_RESULT_ADDR >> 8) & 0xFF
    fl, fh = CARRY_FLAG_ADDR & 0xFF, (CARRY_FLAG_ADDR >> 8) & 0xFF
    loop = CARRY_TRAMPOLINE + 19
    tramp = bytes([0xA9, 0x00, 0x8D, fl, fh, 0x20, lo, hi, 0xA9, 0x00, 0x2A,
                   0x8D, rl, rh, 0xA9, 0xFF, 0x8D, fl, fh,
                   0x4C, loop & 0xFF, loop >> 8])
    write_bytes(transport, CARRY_TRAMPOLINE, tramp)
    write_bytes(transport, CARRY_FLAG_ADDR, bytes([0x00]))
    goto(transport, CARRY_TRAMPOLINE)
    deadline = time.monotonic() + timeout
    while True:
        time.sleep(poll)
        if time.monotonic() >= deadline:
            return None
        try:
            if read_bytes(transport, CARRY_FLAG_ADDR, 1)[0] == 0xFF:
                break
            transport.resume()
        except Exception:
            continue
    return read_bytes(transport, CARRY_RESULT_ADDR, 1)[0]


def main() -> int:
    os.chdir(PROJECT_ROOT)
    if not os.path.exists(PRG_PATH):
        print("FATAL: build/c64-https.prg missing", file=sys.stderr)
        return 2
    labels = Labels.from_file(LABELS_PATH)
    need = ["x509_verify_hostname", "cert_buf", "cert_data_ptr",
            "tls_hostname", "tls_hostname_len", "cert_buf_size"]
    for n in need:
        if labels.address(n) is None:
            # An involuntary skip is a failure. This suite is the only
            # coverage server-name validation has; on a build that does not
            # export the routine (BACKEND=ip65, see #135) every one of the
            # vectors below is silently dropped, and exiting 0 here would
            # report "hostname checking is fine" having checked nothing.
            # Run it against a BACKEND=uci build, or do not run it.
            print(f"CANNOT RUN: label {n} missing — server name validation is "
                  f"a BACKEND=uci-only feature (see #135). None of the "
                  f"vectors executed; this run certifies nothing.",
                  file=sys.stderr)
            return 2
    cert_cap = labels.address("cert_buf_size")

    vectors = build_vectors()
    n_neg = sum(1 for x in vectors if x[3] == 1)
    if n_neg == 0:
        print("FATAL: no negative vectors — this set cannot fail against a stub.",
              file=sys.stderr)
        return 2
    print(f"  {len(vectors)} vectors ({len(vectors)-n_neg} accept / {n_neg} reject), "
          f"cert_buf capacity {cert_cap} B")

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        if wait_for_text(t, "Q=QUIT", timeout=float(os.environ.get("C64_INIT_TIMEOUT", "120")),
                         verbose=False) is None:
            print("FATAL: menu never appeared", file=sys.stderr)
            return 2

        passed = failed = 0
        oversize = []
        for name, der, host, want, why in vectors:
            if len(der) > cert_cap:
                # Declared vector, no verdict: it leaves the denominator
                # unless it is accounted for. Same rule as the KAT oracle's
                # "every declared vector must produce a verdict" check, and
                # this one is load-bearing — the vectors most likely to
                # outgrow cert_buf are the real CA-issued leaves, i.e. the
                # ones the client actually has to get right.
                print(f"  [-] CANNOT RUN {name}: {len(der)} B exceeds "
                      f"cert_buf ({cert_cap} B) — counted as a failure")
                oversize.append((name, len(der)))
                failed += 1
                continue
            write_bytes(t, labels["cert_buf"], der)
            write_bytes(t, labels["cert_data_ptr"],
                        bytes([labels["cert_buf"] & 0xFF, labels["cert_buf"] >> 8]))
            hb = host.encode()
            write_bytes(t, labels["tls_hostname"], hb + b"\x00")
            write_bytes(t, labels["tls_hostname_len"], bytes([len(hb)]))
            got = jsr_with_carry(t, labels["x509_verify_hostname"])
            ok = (got == want)
            passed += ok
            failed += (not ok)
            verdict = "PASS" if ok else "FAIL"
            gs = "hung" if got is None else f"C={got}"
            print(f"  [{verdict}] {name}: {gs} (want C={want}) — {why}")

        if oversize:
            print(f"\n  VECTORS THAT COULD NOT RUN (counted as failures)")
            for name, n in oversize:
                print(f"  [-] {name}: {n} B > cert_buf {cert_cap} B")
        print(f"\nRESULTS: {passed}/{passed+failed} passed"
              f"{f' ({len(oversize)} could not run)' if oversize else ''}")
        return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
