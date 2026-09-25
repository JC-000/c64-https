#!/usr/bin/env python3
"""spki_pin.py — compute the value for `make HTTPS_PIN_SPKI_SHA256=` (issue #155).

The pin is SHA-256 over the leaf certificate's SubjectPublicKeyInfo DER — the
same bytes as

    openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256

and the same bytes src/cert_pin.s hashes on the C64 (the 91-byte window the key
extractor read Qx/Qy from; for a P-256 leaf that window IS the SPKI TLV).

Usage:
    python3 tools/spki_pin.py github.com            # live host, CA-verified fetch
    python3 tools/spki_pin.py 10.0.0.5:4433 --insecure --servername www.foo.invalid
    python3 tools/spki_pin.py --pem tools/https_e2e/certs/server.pem
    python3 tools/spki_pin.py --check-baseline      # re-fetch every host in
                                                    # tools/spki_pin_baseline.json
                                                    # and report which keys rotated

A live fetch validates the chain against the system trust store by default:
the point of a pin is to bake in the key a CA-validated connection sees, not
whatever an on-path attacker served the machine you ran this on. `--insecure`
is for local listeners with self-signed leaves.

Exit codes: 0 ok; 1 fetch/parse failure; 2 the leaf is not P-256 (this client
cannot verify it, so a pin for it could never pass); 3 --check-baseline found
a rotated key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import ssl
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "spki_pin_baseline.json")


class NotP256(Exception):
    pass


def spki_der(cert: x509.Certificate) -> bytes:
    key = cert.public_key()
    if not (isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP256R1)):
        raise NotP256(f"leaf key is {type(key).__name__}"
                      + (f"/{key.curve.name}" if isinstance(key, ec.EllipticCurvePublicKey) else "")
                      + ", not P-256: c64-https can only verify P-256 leaves")
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    # The C64 hashes a fixed 91-byte window (src/cert_pin.s PIN_SPKI_LEN).
    assert len(der) == 91, len(der)
    return der


def pin_of(cert: x509.Certificate) -> str:
    return hashlib.sha256(spki_der(cert)).hexdigest()


def fetch_leaf(host: str, port: int, servername: str | None,
               insecure: bool, timeout: float = 15.0) -> x509.Certificate:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=servername or host) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)


def split_hostport(arg: str) -> tuple[str, int]:
    if ":" in arg:
        h, p = arg.rsplit(":", 1)
        return h, int(p)
    return arg, 443


def check_baseline(insecure: bool) -> int:
    with open(BASELINE_PATH) as f:
        base = json.load(f)
    print(f"baseline captured {base['captured']}")
    rotated = 0
    failed = 0
    for host, want in base["hosts"].items():
        try:
            got = pin_of(fetch_leaf(host, 443, None, insecure))
        except Exception as e:  # noqa: BLE001 — report every host
            print(f"  {host:24s} FETCH FAILED: {e}")
            failed += 1
            continue
        same = got == want
        rotated += not same
        print(f"  {host:24s} {'same   ' if same else 'ROTATED'} {got}")
    if failed:
        print(f"{failed} host(s) could not be fetched")
    return 3 if rotated else (1 if failed else 0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("host", nargs="?", help="HOST or HOST:PORT")
    src.add_argument("--pem", help="read the leaf from a PEM file instead")
    src.add_argument("--check-baseline", action="store_true",
                     help=f"re-fetch every host in {os.path.basename(BASELINE_PATH)}")
    ap.add_argument("--servername", help="SNI to send (default: the host)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip chain validation (local self-signed listeners)")
    args = ap.parse_args(argv)

    if args.check_baseline:
        return check_baseline(args.insecure)
    try:
        if args.pem:
            with open(args.pem, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
        else:
            host, port = split_hostport(args.host)
            cert = fetch_leaf(host, port, args.servername, args.insecure)
        pin = pin_of(cert)
    except NotP256 as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (OSError, ssl.SSLError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(pin)
    print(f"# make BACKEND=uci ... HTTPS_PIN_SPKI_SHA256={pin}", file=sys.stderr)
    print(f"# leaf expires {cert.not_valid_after_utc:%Y-%m-%d}; the pin breaks only if"
          " the server rotates its KEY", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
