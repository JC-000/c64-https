#!/usr/bin/env python3
"""Generate a fresh self-signed ECDSA P-256 cert for the c64-https listener.

**Python standard library only.** No `cryptography`, no pip, no venv.

That is the whole point of this module. The listener is shipped as a single
self-extracting .py file, and `cryptography` is a compiled extension: it
cannot be embedded in a portable source bundle. Rather than bootstrap a venv
on first run (network required, minutes of pip, and a new class of failure on
every machine that has a broken toolchain), the one thing that actually needed
`cryptography` — minting a self-signed P-256 certificate — is done here in
pure Python. TLS itself was always stdlib `ssl`.

What that leaves as the listener's real requirement is a property of the
*interpreter*, not of any installable package: an `ssl` module with TLS 1.3
(OpenSSL 1.1.1+). See listener.py, which checks for it and says so in one line.

The certificate this produces is byte-shaped like the one the previous
`cryptography`-based generator emitted, deliberately:

  * key   : ECDSA on NIST P-256 (secp256r1 / prime256v1)
  * sig   : ecdsa-with-SHA256
  * CN    : www.foo.invalid  (overridable via --cn)
  * files : server.pem / server.key
  * SAN   : foo.invalid, www.foo.invalid  (overridable via --san, repeatable)
  * valid : now-5min .. now+3650 days, UTCTime
  * exts  : subjectAltName ONLY, non-critical

That last line is a constraint, not an oversight. The C64 client parses this
certificate with a hand-written 6502 DER walker, and the extension set above
is the one it has been validated against end to end. Do not add
basicConstraints/keyUsage/EKU here "for correctness" without re-running the
hardware e2e — this cert is a test fixture, never a trust anchor, and must not
be deployed anywhere real.

`--curve p384` mints the same shape on secp384r1 with ecdsa-with-SHA384,
into server-p384.{pem,key}. The packaged listener never asks for it; it
exists so the in-tree P-384 e2e tests (tools/https_e2e/ensure_certs.py)
have a generator, which previously meant `cryptography` and now means
none. P-384 is the same algorithm over different numbers — the arithmetic
above is parameterised by curve rather than duplicated.

Idempotent: refuses to overwrite existing files unless --force. Writes into
./certs/ relative to the current directory unless --out-dir is given.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import secrets
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# The test identity — ONE definition, imported by every other minting path
# (listener.py's auto-generate, tools/https_e2e/ensure_certs.py) so they
# cannot drift apart. Three copies of these literals used to exist.
#
# `.invalid` is reserved by RFC 2606 §2 and RFC 6761 §6.4: never delegated,
# and resolvers are required not to resolve it. That is the whole
# requirement here. The predecessor was `www.foo.bar`, and `.bar` is a live
# gTLD — a default-built PRG dialled a name the open internet could answer.
# Do NOT "improve" this to `.com`/`.local`/`example.com`: example.com
# resolves to real IANA servers and `.local` is mDNS.
#
# The two-entry shape is load-bearing too — a bare name plus its `www.`
# prefix is what tools/test_x509_name.py's leftmost-label and
# "SAN entry is a prefix of the host" vectors are built from.
# tools/test_reserved_test_host.py pins both properties.
DEFAULT_CN = "www.foo.invalid"
DEFAULT_SANS = ["foo.invalid", "www.foo.invalid"]


def san_dns_names(cert_path) -> list:
    """dNSName entries from a PEM certificate's subjectAltName.

    Stdlib only, and a deliberate hand walk of the DER — `ssl` cannot read
    a self-signed leaf's SAN off disk without a connection, and this file's
    entire premise is no third-party dependency.

    Callers use it to decide whether a cert already on disk is *stale*
    rather than merely present: the pairs are gitignored and nothing deletes
    them, so renaming the identity above would otherwise leave every machine
    that had run before serving the old names, silently.

    Returns [] if the file is unreadable or carries no SAN — either way the
    caller should re-mint, which is the safe direction.
    """
    import base64

    def tlv(buf, off):
        tag, n, off = buf[off], buf[off + 1], off + 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[off:off + k], "big")
            off += k
        return tag, off, n, off + n

    try:
        der = base64.b64decode("".join(
            line for line in Path(cert_path).read_text().splitlines()
            if "-----" not in line))
        i = der.find(b"\x06\x03\x55\x1d\x11")   # OID 2.5.29.17 subjectAltName
        if i == -1:
            return []
        tag, vs, vl, nxt = tlv(der, i + 5)
        if tag == 0x01:                          # optional `critical` BOOLEAN
            tag, vs, vl, nxt = tlv(der, nxt)
        tag, vs, vl, _ = tlv(der, vs)            # OCTET STRING -> GeneralNames
        names, cur, end = [], vs, vs + vl
        while cur < end:
            tag, s, ln, cur = tlv(der, cur)
            if tag == 0x82:                      # [2] IMPLICIT dNSName
                names.append(der[s:s + ln].decode("ascii"))
        return names
    except Exception:                            # noqa: BLE001
        return []


def sans_match(cert_path, wanted=None) -> bool:
    """True iff the cert on disk carries exactly *wanted* (default: DEFAULT_SANS)."""
    wanted = DEFAULT_SANS if wanted is None else wanted
    return sorted(n.lower() for n in san_dns_names(cert_path)) == \
        sorted(n.lower() for n in wanted)

# ---------------------------------------------------------------------------
# Domain parameters — SEC 2 / FIPS 186-4.
#
# P-256 is what the packaged listener ships and all the constants below with
# bare names are its. P-384 exists for the in-tree e2e tests
# (tools/https_e2e/certs/server-p384.*), which used to need `cryptography`
# purely to mint a cert on a different curve — the same algorithm over
# different numbers. Carrying it here keeps the dependency at zero on both
# paths and leaves one generator to maintain rather than two.
# ---------------------------------------------------------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

P384_P = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
             "ffffffff0000000000000000ffffffff", 16)
P384_A = P384_P - 3
P384_B = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
             "c656398d8a2ed19d2a85c8edd3ec2aef", 16)
P384_N = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
             "581a0db248b0a77aecec196accc52973", 16)
P384_GX = int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
              "5502f25dbf55296c3a545e3872760ab7", 16)
P384_GY = int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
              "0a60b1ce1d7e819d7a431d7c90ea0e5f", 16)

# Affine point arithmetic, parameterised by curve. None is the point at
# infinity. This runs a handful of times per invocation (one keygen, one
# signature), so clarity beats speed.


def _inv(x: int, m: int) -> int:
    return pow(x, m - 2, m)


def _add(p1, p2, p: int = P, a: int = A):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * _inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * _inv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def _mul(k: int, point, p: int = P, a: int = A):
    """Double-and-add. Not constant time — this is a test fixture minting a
    throwaway key on the operator's own machine, not a production signer."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend, p, a)
        addend = _add(addend, addend, p, a)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# Minimal DER encoder. Every helper returns a complete TLV.
# ---------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _int(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
    # Positive INTEGERs need a leading 0x00 when the top bit would read as a
    # sign bit; the +8 above already reserves that byte, so this is minimal.
    return _tlv(0x02, body)


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(chunk)
    return _tlv(0x06, body)


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _bitstring(data: bytes, unused: int = 0) -> bytes:
    return _tlv(0x03, bytes([unused]) + data)


def _octetstring(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _utf8(text: str) -> bytes:
    return _tlv(0x0C, text.encode("utf-8"))


def _ia5(text: str) -> bytes:
    return _tlv(0x16, text.encode("ascii"))


def _utctime(when: datetime.datetime) -> bytes:
    # UTCTime is YYMMDDHHMMSSZ and is only valid through 2049; the caller's
    # 10-year validity keeps us well inside that.
    if when.year >= 2050:
        raise ValueError("date beyond UTCTime range; GeneralizedTime needed")
    return _tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _explicit(num: int, body: bytes) -> bytes:
    return _tlv(0xA0 | num, body)


OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_PRIME256V1 = "1.2.840.10045.3.1.7"
OID_SECP384R1 = "1.3.132.0.34"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_COMMON_NAME = "2.5.4.3"
OID_SUBJECT_ALT_NAME = "2.5.29.17"


class _Curve:
    """Everything that differs between the two supported profiles."""

    def __init__(self, name, p, a, n, gx, gy, size, curve_oid, sig_oid,
                 hasher, cert_name, key_name, label):
        self.name = name              # profile key: "p256" / "p384"
        self.p, self.a, self.n = p, a, n
        self.gx, self.gy = gx, gy
        self.size = size              # coordinate width in bytes
        self.curve_oid = curve_oid
        self.sig_oid = sig_oid
        self.hasher = hasher          # hashlib constructor
        self.cert_name = cert_name
        self.key_name = key_name
        self.label = label            # for the human-readable summary


CURVES = {
    "p256": _Curve("p256", P, A, N, GX, GY, 32,
                   OID_PRIME256V1, OID_ECDSA_SHA256, hashlib.sha256,
                   "server.pem", "server.key",
                   "ECDSA P-256 (secp256r1), sig = ecdsa-with-SHA256"),
    "p384": _Curve("p384", P384_P, P384_A, P384_N, P384_GX, P384_GY, 48,
                   OID_SECP384R1, OID_ECDSA_SHA384, hashlib.sha384,
                   "server-p384.pem", "server-p384.key",
                   "ECDSA P-384 (secp384r1), sig = ecdsa-with-SHA384"),
}


def _pem(label: str, der: bytes) -> bytes:
    import base64
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN %s-----\n%s\n-----END %s-----\n"
            % (label, "\n".join(lines), label)).encode("ascii")


def _ecdsa_sign(digest: bytes, d: int, curve) -> bytes:
    """ECDSA over *curve*. Returns the DER SEQUENCE{r,s}.

    Each profile pairs its curve with the equal-width hash (P-256/SHA-256,
    P-384/SHA-384), so the digest is exactly as wide as n and FIPS 186-4's
    leftmost-bits truncation is a no-op. Pair them differently and this
    needs the truncation put back.
    """
    n = curve.n
    e = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(n - 1) + 1
        point = _mul(k, (curve.gx, curve.gy), curve.p, curve.a)
        r = point[0] % n
        if r == 0:
            continue
        s = _inv(k, n) * (e + r * d) % n
        if s == 0:
            continue
        return _seq(_int(r), _int(s))


def generate(cn: str, sans: list, out_dir: Path,
             force: bool = False, curve: str = "p256"):
    """Generate key + self-signed cert into out_dir. Returns (cert, key).

    *curve* selects a profile from CURVES; it also picks the filenames, so
    a P-256 and a P-384 pair coexist in one directory.
    """
    try:
        crv = CURVES[curve]
    except KeyError:
        raise ValueError(f"unknown curve profile {curve!r}; "
                         f"expected one of {sorted(CURVES)}") from None

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / crv.cert_name
    key_path = out_dir / crv.key_name

    if cert_path.exists() and key_path.exists() and not force:
        print(f"certs already present: {cert_path} / {key_path} "
              f"(use --force to regenerate)")
        return cert_path, key_path

    # --- key ---
    d = secrets.randbelow(crv.n - 1) + 1
    qx, qy = _mul(d, (crv.gx, crv.gy), crv.p, crv.a)
    pub_point = (b"\x04" + qx.to_bytes(crv.size, "big")
                 + qy.to_bytes(crv.size, "big"))

    # --- names / validity ---
    name = _seq(_set(_seq(_oid(OID_COMMON_NAME), _utf8(cn))))
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(days=3650)

    sig_alg = _seq(_oid(crv.sig_oid))
    spki = _seq(
        _seq(_oid(OID_EC_PUBLIC_KEY), _oid(crv.curve_oid)),
        _bitstring(pub_point),
    )
    # GeneralNames: dNSName is [2] IMPLICIT IA5String, i.e. tag 0x82.
    san_value = _seq(*[_tlv(0x82, h.encode("ascii")) for h in sans])
    extensions = _explicit(3, _seq(
        _seq(_oid(OID_SUBJECT_ALT_NAME), _octetstring(san_value)),
    ))

    tbs = _seq(
        _explicit(0, _int(2)),                       # version v3
        _int(secrets.randbits(159) | 1),             # positive serial, <20 B
        sig_alg,
        name,                                        # issuer == subject
        _seq(_utctime(not_before), _utctime(not_after)),
        name,
        spki,
        extensions,
    )

    signature = _ecdsa_sign(crv.hasher(tbs).digest(), d, crv)
    cert_der = _seq(tbs, sig_alg, _bitstring(signature))

    # SEC1 / RFC 5915 ECPrivateKey — "EC PRIVATE KEY" PEM, which is what the
    # previous generator's TraditionalOpenSSL format produced.
    key_der = _seq(
        _int(1),
        _octetstring(d.to_bytes(crv.size, "big")),
        _explicit(0, _oid(crv.curve_oid)),
        _explicit(1, _bitstring(pub_point)),
    )

    key_path.write_bytes(_pem("EC PRIVATE KEY", key_der))
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    cert_path.write_bytes(_pem("CERTIFICATE", cert_der))

    print(f"wrote {cert_path}")
    print(f"wrote {key_path}")
    print(f"  CN  = {cn}")
    print(f"  SAN = {', '.join(sans)}")
    print(f"  key = {crv.label}")
    print("  (generated with the Python stdlib only — no 'cryptography')")
    return cert_path, key_path


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cn", default=DEFAULT_CN,
                   help=f"certificate Common Name (default: {DEFAULT_CN})")
    p.add_argument("--san", action="append", default=None, metavar="DNS",
                   help="Subject Alternative Name DNS entry (repeatable; "
                        f"default: {' and '.join(DEFAULT_SANS)})")
    p.add_argument("--out-dir", default=None,
                   help="output directory for server.pem/server.key "
                        "(default: ./certs)")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing cert/key")
    p.add_argument("--curve", default="p256", choices=sorted(CURVES),
                   help="curve profile (default: p256, which is what the "
                        "listener serves). p384 writes "
                        "server-p384.{pem,key} so both pairs can coexist")
    args = p.parse_args(argv)

    sans = args.san if args.san else list(DEFAULT_SANS)
    out_dir = Path(args.out_dir) if args.out_dir else Path.cwd() / "certs"

    generate(args.cn, sans, out_dir, force=args.force, curve=args.curve)
    return 0


if __name__ == "__main__":
    sys.exit(main())
