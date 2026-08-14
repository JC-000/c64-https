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
  * CN    : www.foo.bar  (overridable via --cn)
  * SAN   : foo.bar, www.foo.bar  (overridable via --san, repeatable)
  * valid : now-5min .. now+3650 days, UTCTime
  * exts  : subjectAltName ONLY, non-critical

That last line is a constraint, not an oversight. The C64 client parses this
certificate with a hand-written 6502 DER walker, and the extension set above
is the one it has been validated against end to end. Do not add
basicConstraints/keyUsage/EKU here "for correctness" without re-running the
hardware e2e — this cert is a test fixture, never a trust anchor, and must not
be deployed anywhere real.

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
# NIST P-256 (secp256r1) domain parameters — SEC 2 / FIPS 186-4.
# ---------------------------------------------------------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Affine point arithmetic. None is the point at infinity. This runs a handful
# of times per invocation (one keygen, one signature), so clarity beats speed.


def _inv(x: int, m: int) -> int:
    return pow(x, m - 2, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k: int, point):
    """Double-and-add. Not constant time — this is a test fixture minting a
    throwaway key on the operator's own machine, not a production signer."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
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
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_COMMON_NAME = "2.5.4.3"
OID_SUBJECT_ALT_NAME = "2.5.29.17"


def _pem(label: str, der: bytes) -> bytes:
    import base64
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN %s-----\n%s\n-----END %s-----\n"
            % (label, "\n".join(lines), label)).encode("ascii")


def _ecdsa_sign(digest: bytes, d: int) -> bytes:
    """ECDSA-SHA256 over P-256. Returns the DER SEQUENCE{r,s}."""
    e = int.from_bytes(digest, "big")  # SHA-256 and n are both 256 bits
    while True:
        k = secrets.randbelow(N - 1) + 1
        point = _mul(k, (GX, GY))
        r = point[0] % N
        if r == 0:
            continue
        s = _inv(k, N) * (e + r * d) % N
        if s == 0:
            continue
        return _seq(_int(r), _int(s))


def generate(cn: str, sans: list, out_dir: Path,
             force: bool = False):
    """Generate key + self-signed cert into out_dir. Returns (cert, key)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "server.pem"
    key_path = out_dir / "server.key"

    if cert_path.exists() and key_path.exists() and not force:
        print(f"certs already present: {cert_path} / {key_path} "
              f"(use --force to regenerate)")
        return cert_path, key_path

    # --- key ---
    d = secrets.randbelow(N - 1) + 1
    qx, qy = _mul(d, (GX, GY))
    pub_point = b"\x04" + qx.to_bytes(32, "big") + qy.to_bytes(32, "big")

    # --- names / validity ---
    name = _seq(_set(_seq(_oid(OID_COMMON_NAME), _utf8(cn))))
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(days=3650)

    sig_alg = _seq(_oid(OID_ECDSA_SHA256))
    spki = _seq(
        _seq(_oid(OID_EC_PUBLIC_KEY), _oid(OID_PRIME256V1)),
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

    signature = _ecdsa_sign(hashlib.sha256(tbs).digest(), d)
    cert_der = _seq(tbs, sig_alg, _bitstring(signature))

    # SEC1 / RFC 5915 ECPrivateKey — "EC PRIVATE KEY" PEM, which is what the
    # previous generator's TraditionalOpenSSL format produced.
    key_der = _seq(
        _int(1),
        _octetstring(d.to_bytes(32, "big")),
        _explicit(0, _oid(OID_PRIME256V1)),
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
    print("  key = ECDSA P-256 (secp256r1), sig = ecdsa-with-SHA256")
    print("  (generated with the Python stdlib only — no 'cryptography')")
    return cert_path, key_path


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cn", default="www.foo.bar",
                   help="certificate Common Name (default: www.foo.bar)")
    p.add_argument("--san", action="append", default=None, metavar="DNS",
                   help="Subject Alternative Name DNS entry (repeatable; "
                        "default: foo.bar and www.foo.bar)")
    p.add_argument("--out-dir", default=None,
                   help="output directory for server.pem/server.key "
                        "(default: ./certs)")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing cert/key")
    args = p.parse_args(argv)

    sans = args.san if args.san else ["foo.bar", "www.foo.bar"]
    out_dir = Path(args.out_dir) if args.out_dir else Path.cwd() / "certs"

    generate(args.cn, sans, out_dir, force=args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
