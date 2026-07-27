#!/usr/bin/env python3
"""Generate a fresh self-signed ECDSA P-256 cert for the c64-https listener.

This mirrors the cert the c64-https end-to-end test harness expects:

  * key   : ECDSA on NIST P-256 (secp256r1 / prime256v1)
  * sig   : ecdsa-with-SHA256
  * CN    : www.foo.bar  (overridable via --cn)
  * SAN   : foo.bar, www.foo.bar  (overridable via --san, repeatable)
  * valid : 10 years from now

The C64 client verifies the server's CertificateVerify signature against
the leaf public key, so any freshly generated P-256 self-signed cert works
— there is no trust-anchor requirement. Do NOT deploy these anywhere real.

Idempotent: by default it refuses to overwrite existing files (pass
--force to regenerate). Writes into ./certs/ next to this script unless
--out-dir is given.
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate(cn: str, sans: list[str], out_dir: Path,
             force: bool = False) -> tuple[Path, Path]:
    """Generate key + self-signed cert into out_dir. Returns (cert, key)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "server.pem"
    key_path = out_dir / "server.key"

    if cert_path.exists() and key_path.exists() and not force:
        print(f"certs already present: {cert_path} / {key_path} "
              f"(use --force to regenerate)")
        return cert_path, key_path

    # ECDSA P-256 private key (matches tools/https_e2e/certs/server.key).
    key = ec.generate_private_key(ec.SECP256R1())

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    san = x509.SubjectAlternativeName([x509.DNSName(h) for h in sans])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(san, critical=False)
        # Sign with SHA-256 -> ecdsa-with-SHA256, matching the P-256 profile.
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"wrote {cert_path}")
    print(f"wrote {key_path}")
    print(f"  CN  = {cn}")
    print(f"  SAN = {', '.join(sans)}")
    print(f"  key = ECDSA P-256 (secp256r1), sig = ecdsa-with-SHA256")
    return cert_path, key_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cn", default="www.foo.bar",
                   help="certificate Common Name (default: www.foo.bar)")
    p.add_argument("--san", action="append", default=None, metavar="DNS",
                   help="Subject Alternative Name DNS entry (repeatable; "
                        "default: foo.bar and www.foo.bar)")
    p.add_argument("--out-dir", default=None,
                   help="output directory for server.pem/server.key "
                        "(default: ./certs next to this script)")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing cert/key")
    args = p.parse_args(argv)

    sans = args.san if args.san else ["foo.bar", "www.foo.bar"]
    out_dir = (Path(args.out_dir) if args.out_dir
               else Path(__file__).resolve().parent / "certs")

    generate(args.cn, sans, out_dir, force=args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
