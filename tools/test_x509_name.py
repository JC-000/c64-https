#!/usr/bin/env python3
"""test_x509_name.py — server name validation (issue #135).

Drives `x509_verify_hostname` directly over DMA: stage a DER certificate in
cert_buf, point cert_data_ptr at it, set tls_hostname, JSR, read the carry.

The vector set is deliberately NEGATIVE-HEAVY. An all-positive set passes
against a routine stubbed to `clc; rts` and therefore proves nothing — the
same trap recorded as finding F7 in tools/test_ecdsa_kat_oracle.py. More
than half the vectors expect a REJECT, including the four wildcard
over-match cases that are the classic way name checking goes wrong, and
main() refuses to run a set that has no negative vector at all.

Composition: 6 vectors from a REAL certificate (tools/https_e2e/certs/
server.pem, the one the bundled listener serves), 6 from live CA-issued
leaves fetched over the network, and 11 synthesised here. A parser that
only ever sees certificates written by its own test is not being tested
against reality, so the first twelve are the ones that matter, and of them
only the real-certificate six need no network — which is why they are
MANDATORY: the certificate is minted on demand and a failure to produce it
stops the suite (real_cert_der(), issue #167).

**No total is asserted anywhere, and none should be.** 23 with a network,
17 under `X509_NAME_OFFLINE=1`: that is a fact about the machine, not about
the code, and pinning it would be the same defect one level up. What IS
enforced is that every vector the suite set out to build was built — see
the intent-vs-built check in main(). Beware the totals when reading older
logs, too: the real-certificate six and the live six have the same
3-accept/3-reject shape, so "17 vectors, 8 accept / 9 reject" has two
possible causes — no network, or (before #167) no certificate. The header
line now reports how many vectors came from the real certificate, which
tells the two apart.

    make BACKEND=uci && C64_SKIP_BUILD=1 python3 tools/test_x509_name.py
"""
from __future__ import annotations

import base64
import binascii
import os
import sys
import time
from pathlib import Path

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
# Marks the vectors built from the listener's own certificate. They are
# minted on demand (real_cert_der), so unlike the live-leaf vectors they
# need no network and have no excuse to be absent: fewer of them than
# real_cert_rows() declares is a FAILURE, not a smaller run.
REAL_VECTOR_PREFIX = "real cert / "

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


class RealCertUnavailable(RuntimeError):
    """The bundled listener's certificate could not be produced.

    Carries the ACTUAL cause. Its predecessor was a bare
    ``except Exception: return None`` that reported "openssl unavailable"
    for every failure mode — including the only one that ever fired, which
    is that server.pem is gitignored and a fresh checkout therefore has no
    such file (issue #167). Three causes, one message, and the message
    named the one thing that was not wrong.
    """


def _der_tlv_len(der: bytes) -> int | None:
    """Total encoded length of the DER TLV at the head of *der*, else None."""
    if len(der) < 2:
        return None
    n, off = der[1], 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or len(der) < 2 + k:
            return None
        n = int.from_bytes(der[2:2 + k], "big")
        off += k
    return off + n


def real_cert_der() -> bytes:
    """DER of the certificate the bundled listener serves, minting if absent.

    ``tools/https_e2e/certs/server.pem`` is generated, never committed
    (.gitignore ``tools/https_e2e/certs/*``), so "no such file" is the
    NORMAL state of a fresh checkout rather than an error. ``ensure_certs``
    mints it here — idempotent, stdlib-only, and the same generator the
    listener and the other in-tree suites use — which removes the failure
    mode instead of reporting it: the six vectors below now run everywhere
    rather than being skipped everywhere.

    openssl is deliberately no longer consulted. It was never needed — a PEM
    is base64-armoured DER, and gen_certs.san_dns_names already walks one
    with the stdlib — and it is not a documented dependency of this repo
    (PR #96 went the other way, removing `cryptography` from the cert path).
    Keeping it would only preserve a way for a missing tool to drop vectors.

    Raises RealCertUnavailable naming which of the three causes that CAN
    still fire did: generation failed, the file is absent/unreadable anyway,
    or what is on disk is not a certificate.
    """
    e2e = os.path.join(PROJECT_ROOT, "tools", "https_e2e")
    if e2e not in sys.path:
        sys.path.insert(0, e2e)
    from ensure_certs import ensure_certs  # noqa: PLC0415

    try:
        cert_path, _key = ensure_certs("p256")
    except SystemExit as exc:            # ensure_certs' own one-line diagnosis
        raise RealCertUnavailable(                # its text already says what
            f"{exc} (generator: "                 # went wrong; do not restate
            f"tools/package/listener/gen_certs.py)") from exc
    except Exception as exc:             # noqa: BLE001
        raise RealCertUnavailable(
            f"generating the test certificate raised "
            f"{type(exc).__name__}: {exc}") from exc

    try:
        pem = Path(cert_path).read_text()
    except OSError as exc:
        raise RealCertUnavailable(
            f"{cert_path} is unreadable after generation ({exc.strerror}) — "
            f"re-mint with `python3 tools/https_e2e/ensure_certs.py --force`"
        ) from exc

    try:
        der = base64.b64decode(
            "".join(ln for ln in pem.splitlines() if "-----" not in ln),
            validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RealCertUnavailable(
            f"{cert_path} is not PEM ({exc}) — re-mint with "
            f"`python3 tools/https_e2e/ensure_certs.py --force`") from exc

    # base64 decodes almost anything, so prove the result is one DER SEQUENCE
    # filling the file before handing it to the C64 as a certificate.
    if der[:1] != b"\x30" or _der_tlv_len(der) != len(der):
        raise RealCertUnavailable(
            f"{cert_path} decodes to {len(der)} B that are not a single DER "
            f"SEQUENCE — re-mint with "
            f"`python3 tools/https_e2e/ensure_certs.py --force`")
    return der


# --- vectors -----------------------------------------------------------------

def real_cert_rows():
    """(host, expected carry, why) for every vector built from the real cert.

    Declared as data, and separately from the certificate itself, so main()
    can compare vectors BUILT against vectors INTENDED without either count
    being written down as a literal anywhere. Do not replace this with a
    number: the suite's total is environment-dependent (the live-leaf
    vectors come and go with the network) and an asserted total would pass
    or fail on the state of the machine rather than on the code.

    The names are derived from the cert's own SAN entries rather than
    spelled out, so renaming the test identity cannot leave these vectors
    testing a name the listener no longer serves — they would still all
    PASS, having quietly stopped exercising the real certificate at all.
    CERT_SANS is the bare name + its `www.` prefix; that shape is what makes
    the last two rows meaningful, and tools/test_reserved_test_host.py pins
    it.
    """
    bare, www = sorted(CERT_SANS, key=len)
    return [
        (www,            0, "matches the 2nd SAN entry of the real listener cert"),
        (bare,           0, "matches the 1st SAN entry"),
        (www.upper(),    0, "DNS names are case-insensitive (RFC 4343)"),
        ("evil.example", 1, "REJECT: name not in the cert"),
        (www[:-1],       1, "REJECT: prefix of a SAN entry must not match"),
        (www + "x",      1, "REJECT: SAN entry is a prefix of the host"),
    ]


# (name, cert DER, hostname, expected carry, why)
def build_vectors():
    v = []
    # Unconditional: real_cert_der() mints the certificate if it is absent
    # and RAISES otherwise, so these vectors either run or stop the suite.
    # They used to be wrapped in `if real:` with an else-branch that printed
    # a note and carried on — the silent drop of issue #167.
    real = real_cert_der()
    for host, want, why in real_cert_rows():
        v.append((REAL_VECTOR_PREFIX + host, real, host, want, why))

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

    # Intent, not a constant: how many real-certificate vectors this file
    # declares. Compared against how many were actually built, below.
    want_real = len(real_cert_rows())

    try:
        vectors = build_vectors()
    except RealCertUnavailable as exc:
        # An involuntary skip is a failure (the standard adopted in #158).
        # These are the only vectors in the suite that parse a certificate a
        # TLS listener actually produced — everything else is DER this file
        # wrote itself — so dropping them and exiting 0, which is what this
        # suite did before #167, reports "name checking is fine" having
        # never seen a real certificate.
        print(f"CANNOT RUN: {exc}", file=sys.stderr)
        print(f"  The {want_real} real-certificate vectors did not run and no other "
              f"vector\n  covers what they cover; this run certifies nothing about real\n"
              f"  certificates. Counted as a failure, not a skip.", file=sys.stderr)
        return 2

    # Every vector the suite set out to build must have been built. This is
    # deliberately a comparison against the declared set rather than against
    # a number: what must not happen is a vector disappearing between
    # declaration and execution, whatever the totals happen to be today.
    n_real = sum(1 for x in vectors if x[0].startswith(REAL_VECTOR_PREFIX))
    if n_real != want_real:
        print(f"FATAL: {n_real} of the {want_real} declared real-certificate "
              f"vectors were built — the fixture path dropped vectors without "
              f"raising. Fix the vector set; a run of the remainder would be "
              f"green for a reason unrelated to what it measured.",
              file=sys.stderr)
        return 2

    n_neg = sum(1 for x in vectors if x[3] == 1)
    if n_neg == 0:
        print("FATAL: no negative vectors — this set cannot fail against a stub.",
              file=sys.stderr)
        return 2
    print(f"  {len(vectors)} vectors ({len(vectors)-n_neg} accept / {n_neg} reject), "
          f"{n_real} of them from the listener's real certificate, "
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
