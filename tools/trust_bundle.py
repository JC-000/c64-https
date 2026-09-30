#!/usr/bin/env python3
"""trust_bundle.py — build, sign, verify and dump a signed pin bundle (#155 phase 2).

A trust bundle is a separate file the C64 loads (from disk, or into the REU)
and checks with the P-256 `ecdsa_verify_256` it already links. The public key
and a generation floor are compiled into the PRG (DECISIONS.md item 4). This
tool is the host half only; loading and verifying on the C64 is not here.

Byte format, version 1. Multi-byte integers are LITTLE-endian unless marked
BE. Records reuse the TOFU store's 64 B layout (S3-trust-design.md §5), so one
C64 record parser serves both files; only the magic and the trailer differ.

    offset  len  field
    ------  ---  -----------------------------------------------------------
    header (8 B)
      0      4   magic  "C6TB" = $43 $36 $54 $42   (the TOFU store is "C6TS")
      4      1   version = $01
      5      2   generation, u16 LE. Anti-replay: the C64 accepts the file
                 only if generation >= the TRUST_BUNDLE_GEN_FLOOR compiled
                 into its PRG (plain unsigned compare, not serial arithmetic)
      7      1   N = record count, 0..32
    records (N x 64 B), strictly ascending by host key (so no duplicates)
      +0    16   host key = SHA-256(host)[0:16], host = the ASCII name with
                 A-Z folded to a-z and nothing else changed (no trailing-dot
                 strip, no IDNA). The C64 must hash the same ASCII bytes it
                 sends as SNI, lowercased, NOT PETSCII.
      +16   32   SPKI SHA-256 — the value tools/spki_pin.py prints and
                 src/cert_pin.s compares (the 91-byte P-256 SPKI window)
      +48    1   mode. $10 = BUNDLE_LEAF, the only mode a v1 bundle carries.
                 $01-$0F are left to the TOFU store's modes (S3 §5:
                 TOFU / ACCEPTED / OVERRIDE) so the two files never collide.
      +49    1   flags. bit 0 = WARN_ONLY, REQUIRED on BUNDLE_LEAF
                 (DECISIONS.md item 3: bundle leaf pins are advisory).
                 Every other bit must be 0.
      +50    2   use count, u16 LE; always 0 in a bundle
      +52   12   display prefix: the first 12 bytes of the lowercased host,
                 $00-padded. Non-authoritative (a trust-list screen label).
    trailer (64 B)
      +0    32   r, BE
      +32   32   s, BE

The signature is ECDSA P-256 with SHA-256 over header||records (everything
but the trailer): e = SHA-256(file[0 : 8+64N]). That is standard
ECDSA-SHA256, so `openssl dgst -sha256 -verify` checks it unmodified (see
`openssl-files`). Total length is exactly 8 + 64N + 64; anything else is
rejected.

How the C64 feeds `ecdsa_verify_256` with no byte conversion: the routine
takes A/X = pointer to a 160 B struct r|s|h|Qx|Qy, 32 B each, all BE
(src/crypto/ecdsa_verify.s, which hands it `ecdsa_sig_r`; the TLS buffers
ecdsa_sig_r, _sig_s, _hash, _pubkey_x, _pubkey_y are laid out contiguously
in exactly that order). So:

    ecdsa_sig_r .. +63   <- the 64-byte trailer, copied as-is (r then s)
    ecdsa_hash           <- SHA-256 digest bytes as the hash emits them
                            (tls_transcript / sha256_hash order, i.e. BE)
    ecdsa_pubkey_x, _y   <- TRUST_BUNDLE_PUBKEY_BYTES from the generated .inc
    lda #<ecdsa_sig_r / ldx #>ecdsa_sig_r / jsr ecdsa_verify_256   ; C=0 valid

`c64_verify_struct()` below builds exactly those 160 bytes, and
tools/test_trust_bundle_c64.py runs them through the real routine in VICE.

Subcommands:

    # live fetch (CA-validated, via tools/spki_pin.py), sign, write
    python3 tools/trust_bundle.py build --test-key --generation 1 \\
        -o bundle.bin en.wikipedia.org github.com
    # offline: pins you already hold
    python3 tools/trust_bundle.py build --key K.pem --generation 2 \\
        --pin en.wikipedia.org=c0a0...c3fe -o bundle.bin
    python3 tools/trust_bundle.py verify --test-key --floor 1 bundle.bin
    python3 tools/trust_bundle.py dump bundle.bin
    python3 tools/trust_bundle.py inc --test-key --floor 1 -o key.inc
    python3 tools/trust_bundle.py openssl-files bundle.bin --test-key DIR

There is deliberately no key-generation subcommand. The only key in the tree
is tools/trust_bundle_TEST_ONLY_signing_key.pem (`--test-key`); choosing and
holding a production key is the maintainer's decision. Signing with the test
key prints a warning, and `inc` marks it with TRUST_BUNDLE_KEY_IS_TEST_ONLY.

Exit codes: 0 ok; 1 the bundle is invalid / a fetch failed; 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_KEY_PATH = os.path.join(TOOLS_DIR, "trust_bundle_TEST_ONLY_signing_key.pem")
TEST_INC_PATH = os.path.join(TOOLS_DIR, "trust_bundle_TEST_ONLY_pubkey.inc")
SAMPLE_BUNDLE_PATH = os.path.join(TOOLS_DIR, "trust_bundle_sample_TEST_ONLY.bin")

MAGIC = b"C6TB"
VERSION = 1
HEADER_LEN = 8
RECORD_LEN = 64
SIG_LEN = 64
MAX_RECORDS = 32
HOST_KEY_LEN = 16
DISPLAY_LEN = 12
MAX_HOST_LEN = 63                       # boot.s's HTTPS_HOST assert

MODE_BUNDLE_LEAF = 0x10
FLAG_WARN_ONLY = 0x01

# P-256 group order, for the range check the parser applies to r and s.
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class BundleError(ValueError):
    """The file is not a valid v1 bundle (structure, signature or floor)."""


def canonical_host(host: str) -> bytes:
    """The exact bytes hashed into a host key: ASCII, A-Z folded to a-z."""
    try:
        raw = host.encode("ascii")
    except UnicodeEncodeError:
        raise BundleError(f"host {host!r} is not ASCII (give the IDNA A-label)")
    if not raw or len(raw) > MAX_HOST_LEN:
        raise BundleError(f"host {host!r}: length must be 1..{MAX_HOST_LEN}")
    if raw.endswith(b".") or any(c <= 0x20 or c >= 0x7F for c in raw):
        raise BundleError(f"host {host!r}: trailing dot or non-printable byte")
    return raw.lower()                  # bytes.lower() folds A-Z only


def host_key(host: str) -> bytes:
    return hashlib.sha256(canonical_host(host)).digest()[:HOST_KEY_LEN]


@dataclass(frozen=True)
class Record:
    host_key: bytes
    spki_sha256: bytes
    mode: int = MODE_BUNDLE_LEAF
    flags: int = FLAG_WARN_ONLY
    use_count: int = 0
    display: bytes = b""

    @classmethod
    def leaf(cls, host: str, spki_sha256: bytes) -> "Record":
        canon = canonical_host(host)
        return cls(host_key=host_key(host), spki_sha256=spki_sha256,
                   display=canon[:DISPLAY_LEN])

    def pack(self) -> bytes:
        out = (self.host_key + self.spki_sha256
               + bytes([self.mode, self.flags])
               + self.use_count.to_bytes(2, "little")
               + self.display.ljust(DISPLAY_LEN, b"\x00"))
        assert len(out) == RECORD_LEN, len(out)
        return out

    @classmethod
    def unpack(cls, b: bytes) -> "Record":
        return cls(host_key=b[0:16], spki_sha256=b[16:48], mode=b[48],
                   flags=b[49], use_count=int.from_bytes(b[50:52], "little"),
                   display=b[52:64].rstrip(b"\x00"))

    def check(self) -> None:
        if self.mode != MODE_BUNDLE_LEAF:
            raise BundleError(f"record mode ${self.mode:02X} is not BUNDLE_LEAF")
        if self.flags != FLAG_WARN_ONLY:
            raise BundleError(f"record flags ${self.flags:02X}: v1 leaf pins "
                              "must be exactly WARN_ONLY ($01)")
        if self.use_count != 0:
            raise BundleError("record use count must be 0 in a bundle")


@dataclass(frozen=True)
class Bundle:
    generation: int
    records: tuple
    r: int
    s: int
    signed: bytes                       # header || records, the ECDSA message


def pack_header(generation: int, n: int) -> bytes:
    if not 0 <= generation <= 0xFFFF:
        raise BundleError(f"generation {generation} does not fit u16")
    if not 0 <= n <= MAX_RECORDS:
        raise BundleError(f"{n} records; at most {MAX_RECORDS}")
    return MAGIC + bytes([VERSION]) + generation.to_bytes(2, "little") + bytes([n])


def unsigned_body(generation: int, records) -> bytes:
    recs = sorted(records, key=lambda r: r.host_key)
    keys = [r.host_key for r in recs]
    if len(set(keys)) != len(keys):
        raise BundleError("two records share a host key (duplicate host)")
    for r in recs:
        r.check()
    return pack_header(generation, len(recs)) + b"".join(r.pack() for r in recs)


# --- keys -------------------------------------------------------------------

def load_private_key(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not (isinstance(key, ec.EllipticCurvePrivateKey)
            and isinstance(key.curve, ec.SECP256R1)):
        raise BundleError(f"{path}: not a P-256 private key")
    return key


def load_public_key(path: str) -> ec.EllipticCurvePublicKey:
    """PEM public key, or the public half of a PEM private key."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        key = serialization.load_pem_private_key(data, password=None).public_key()
    if not (isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP256R1)):
        raise BundleError(f"{path}: not a P-256 key")
    return key


def pubkey_xy(pub: ec.EllipticCurvePublicKey) -> bytes:
    """Qx||Qy, 32 B BE each — the ecdsa_pubkey_x/_y layout."""
    pt = pub.public_bytes(serialization.Encoding.X962,
                          serialization.PublicFormat.UncompressedPoint)
    assert pt[0] == 0x04 and len(pt) == 65
    return pt[1:]


def is_test_key(pub: ec.EllipticCurvePublicKey) -> bool:
    return pubkey_xy(pub) == pubkey_xy(load_public_key(TEST_KEY_PATH))


def key_fingerprint(pub: ec.EllipticCurvePublicKey) -> str:
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def warn_if_test_key(pub, stream=sys.stderr) -> None:
    if is_test_key(pub):
        print("WARNING: this is the TEST-ONLY key committed to the repository "
              "(tools/trust_bundle_TEST_ONLY_signing_key.pem). Anyone can sign "
              "with it. Never compile it into a shipped PRG.", file=stream)


# --- sign / parse / verify --------------------------------------------------

def sign(key: ec.EllipticCurvePrivateKey, generation: int, records) -> bytes:
    """Return the complete bundle file. Deterministic (RFC 6979)."""
    body = unsigned_body(generation, records)
    der = key.sign(body, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return body + r.to_bytes(32, "big") + s.to_bytes(32, "big")


def parse(blob: bytes) -> Bundle:
    """Structural checks only — no signature, no floor. Raises BundleError."""
    if len(blob) < HEADER_LEN + SIG_LEN:
        raise BundleError(f"{len(blob)} B is shorter than header + signature")
    if blob[0:4] != MAGIC:
        raise BundleError(f"magic {blob[0:4]!r}, want {MAGIC!r}")
    if blob[4] != VERSION:
        raise BundleError(f"version {blob[4]}, want {VERSION}")
    generation = int.from_bytes(blob[5:7], "little")
    n = blob[7]
    if n > MAX_RECORDS:
        raise BundleError(f"N = {n}; at most {MAX_RECORDS}")
    want = HEADER_LEN + RECORD_LEN * n + SIG_LEN
    if len(blob) != want:
        raise BundleError(f"length {len(blob)}, want exactly {want} for N = {n}")
    end = HEADER_LEN + RECORD_LEN * n
    records = tuple(Record.unpack(blob[HEADER_LEN + i * RECORD_LEN:
                                       HEADER_LEN + (i + 1) * RECORD_LEN])
                    for i in range(n))
    for i, rec in enumerate(records):
        rec.check()
        if i and not records[i - 1].host_key < rec.host_key:
            raise BundleError(f"record {i}: host keys not strictly ascending")
    r = int.from_bytes(blob[end:end + 32], "big")
    s = int.from_bytes(blob[end + 32:end + 64], "big")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        raise BundleError("signature r or s out of [1, n-1]")
    return Bundle(generation, records, r, s, blob[:end])


def verify(blob: bytes, pub: ec.EllipticCurvePublicKey, floor: int) -> Bundle:
    """Everything the C64 must check, in the order it can: structure,
    signature, then the generation floor. Returns the parsed bundle."""
    b = parse(blob)
    try:
        pub.verify(encode_dss_signature(b.r, b.s), b.signed,
                   ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise BundleError("signature does not verify")
    if b.generation < floor:
        raise BundleError(f"generation {b.generation} is below the floor "
                          f"{floor} (replayed older bundle)")
    return b


def c64_verify_struct(blob: bytes, pub_xy: bytes) -> bytes:
    """The 160 B r|s|h|Qx|Qy (all BE) the C64 hands `ecdsa_verify_256`.

    Built from the raw file with no parsing, the way the C64 does it: the
    trailer is copied verbatim and h is SHA-256 of everything before it.
    """
    assert len(pub_xy) == 64
    trailer = blob[-SIG_LEN:]
    return trailer + hashlib.sha256(blob[:-SIG_LEN]).digest() + pub_xy


# --- generated .inc ---------------------------------------------------------

def render_inc(pub: ec.EllipticCurvePublicKey, floor: int) -> str:
    if not 0 <= floor <= 0xFFFF:
        raise BundleError(f"floor {floor} does not fit u16")
    xy = pubkey_xy(pub)
    test = is_test_key(pub)

    def rows(b: bytes) -> list:
        return ["        .byte " + ", ".join(f"${x:02X}" for x in b[i:i + 8])
                for i in range(0, len(b), 8)]

    banner = [
        "; *** TEST-ONLY KEY: its private half is committed to the repository. ***",
        "; *** Anyone can sign a bundle this PRG will accept. Never ship it.   ***",
    ] if test else []
    lines = [
        "; GENERATED by tools/trust_bundle.py inc -- do not edit by hand.",
        "; Trust-bundle verification key + anti-replay floor (#155 phase 2).",
        *banner,
        f"; key SPKI SHA-256: {key_fingerprint(pub)}",
        ";",
        "; Equates and a macro only: including this file emits no bytes. The",
        "; consumer invokes TRUST_BUNDLE_PUBKEY_BYTES in the segment of its",
        "; choice; the 64 bytes are Qx then Qy, each 32 B big-endian, i.e. the",
        "; ecdsa_pubkey_x / ecdsa_pubkey_y layout ecdsa_verify_256 reads.",
        "",
        f"TRUST_BUNDLE_KEY_IS_TEST_ONLY = {1 if test else 0}",
        f"TRUST_BUNDLE_GEN_FLOOR        = ${floor:04X}",
        "",
        "; format v1 constants (tools/trust_bundle.py module docstring)",
        "TB_VERSION         = $%02X" % VERSION,
        "TB_HEADER_LEN      = %d" % HEADER_LEN,
        "TB_RECORD_LEN      = %d" % RECORD_LEN,
        "TB_SIG_LEN         = %d" % SIG_LEN,
        "TB_MAX_RECORDS     = %d" % MAX_RECORDS,
        "TB_MODE_BUNDLE_LEAF = $%02X" % MODE_BUNDLE_LEAF,
        "TB_FLAG_WARN_ONLY  = $%02X" % FLAG_WARN_ONLY,
        "",
        ".macro TRUST_BUNDLE_MAGIC_BYTES",
        '        .byte "C6TB"',
        ".endmacro",
        "",
        ".macro TRUST_BUNDLE_PUBKEY_BYTES",
        "        ; Qx, big-endian",
        *rows(xy[:32]),
        "        ; Qy, big-endian",
        *rows(xy[32:]),
        ".endmacro",
        "",
    ]
    return "\n".join(lines)


# --- CLI ----------------------------------------------------------------------

def parse_pin_arg(arg: str) -> tuple:
    host, sep, hexpin = arg.partition("=")
    if not sep:
        raise BundleError(f"--pin {arg!r}: want HOST=<64 hex>")
    try:
        pin = bytes.fromhex(hexpin)
    except ValueError:
        pin = b""
    if len(pin) != 32:
        raise BundleError(f"--pin {arg!r}: want 64 hex digits")
    return host, pin


def fetch_pin(host: str) -> bytes:
    sys.path.insert(0, TOOLS_DIR)
    import spki_pin                     # noqa: E402 — needs the tools dir
    h, port = spki_pin.split_hostport(host)
    cert = spki_pin.fetch_leaf(h, port, None, insecure=False)
    try:
        pin = bytes.fromhex(spki_pin.pin_of(cert))
    except spki_pin.NotP256 as e:
        raise BundleError(f"{host}: {e}")
    print(f"  {h:28s} {pin.hex()}  (leaf expires "
          f"{cert.not_valid_after_utc:%Y-%m-%d})", file=sys.stderr)
    return pin


def _key_path(args) -> str:
    if args.test_key:
        return TEST_KEY_PATH
    if not args.key:
        raise SystemExit("error: give --key PEM or --test-key")
    return args.key


def dump_text(blob: bytes) -> str:
    b = parse(blob)
    out = [f"magic C6TB  version {VERSION}  generation {b.generation}  "
           f"N {len(b.records)}  {len(blob)} B",
           f"signed SHA-256 {hashlib.sha256(b.signed).hexdigest()}",
           f"r {b.r:064x}", f"s {b.s:064x}"]
    for i, rec in enumerate(b.records):
        out.append(f"  [{i:2d}] {rec.host_key.hex()}  spki {rec.spki_sha256.hex()}"
                   f"  mode ${rec.mode:02X} flags ${rec.flags:02X}"
                   f"  {rec.display.decode('ascii', 'replace')!r}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_key(p, public_ok):
        g = p.add_mutually_exclusive_group()
        g.add_argument("--key", help="PEM " + ("key (private or public)"
                                               if public_ok else "private key"))
        g.add_argument("--test-key", action="store_true",
                       help="the committed TEST-ONLY key")

    p = sub.add_parser("build", help="fetch/collect pins, sign, write a bundle")
    add_key(p, False)
    p.add_argument("--generation", type=int, required=True)
    p.add_argument("--pin", action="append", default=[], metavar="HOST=HEX",
                   help="an SPKI pin you already hold (no fetch)")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("hosts", nargs="*",
                   help="HOST[:PORT] to fetch live (CA-validated)")

    p = sub.add_parser("verify", help="check structure, signature, floor")
    add_key(p, True)
    p.add_argument("--floor", type=int, required=True)
    p.add_argument("bundle")

    p = sub.add_parser("dump", help="print a bundle (structure-checked only)")
    p.add_argument("bundle")

    p = sub.add_parser("inc", help="write the PRG-side .inc (pubkey + floor)")
    add_key(p, True)
    p.add_argument("--floor", type=int, required=True)
    p.add_argument("-o", "--out", required=True)

    p = sub.add_parser("openssl-files",
                       help="write msg.bin/sig.der/pub.pem for openssl dgst")
    add_key(p, True)
    p.add_argument("bundle")
    p.add_argument("outdir")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "build":
            key = load_private_key(_key_path(args))
            warn_if_test_key(key.public_key())
            recs = [Record.leaf(h, pin) for h, pin in map(parse_pin_arg, args.pin)]
            recs += [Record.leaf(h.rsplit(":", 1)[0], fetch_pin(h))
                     for h in args.hosts]
            blob = sign(key, args.generation, recs)
            with open(args.out, "wb") as f:
                f.write(blob)
            print(dump_text(blob))
        elif args.cmd == "verify":
            pub = load_public_key(_key_path(args))
            b = verify(open(args.bundle, "rb").read(), pub, args.floor)
            print(f"OK: generation {b.generation} >= floor {args.floor}, "
                  f"{len(b.records)} record(s), signature valid")
        elif args.cmd == "dump":
            print(dump_text(open(args.bundle, "rb").read()))
        elif args.cmd == "inc":
            pub = load_public_key(_key_path(args))
            warn_if_test_key(pub)
            with open(args.out, "w") as f:
                f.write(render_inc(pub, args.floor))
        elif args.cmd == "openssl-files":
            pub = load_public_key(_key_path(args))
            b = parse(open(args.bundle, "rb").read())
            os.makedirs(args.outdir, exist_ok=True)
            for name, data in (
                    ("msg.bin", b.signed),
                    ("sig.der", encode_dss_signature(b.r, b.s)),
                    ("pub.pem", pub.public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo))):
                with open(os.path.join(args.outdir, name), "wb") as f:
                    f.write(data)
            d = args.outdir
            print(f"openssl dgst -sha256 -verify {d}/pub.pem "
                  f"-signature {d}/sig.der {d}/msg.bin")
    except BundleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
