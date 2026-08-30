#!/usr/bin/env python3
"""Padded 3-cert chain for the local HTTPS listener — real-record-count bench.

Why this exists (real-server sprint, bench de-risk)
---------------------------------------------------
The local e2e listener serves ONE small self-signed cert, so its encrypted
flight is ~4 records. The real sprint targets send 3-4 certs totalling
2.7-4.1 KB, which — with max_fragment_length honored — arrives as 11-14
records (2026-08-21 probe: github 11, browserleaks 12, en.wikipedia.org 14).
Every extra record costs the C64 a ChaCha20+Poly1305 decrypt, a SHA-256
transcript update, and UCI ``net_poll`` round-trips at ~40 ms each. This
module makes that overhead measurable on the bench, with no internet egress:

    leaf   — the EXISTING P-256 test cert (certs/server.pem), unchanged,
             so the C64 still verifies CertificateVerify against it;
    + two padded throwaway "intermediates" minted here, sized so the whole
      chain lands in the real-target 2.7-3.5 KB window.

The intermediates are deliberately fake: self-signed, unrelated keys, no
issuer linkage to the leaf. Nothing on either side checks linkage — Python's
``load_cert_chain`` sends the extra certs verbatim, and the C64 client
copies only the FIRST CertificateEntry into ``cert_buf`` (W2) and discards
the rest without parsing them. What is under test is the *byte count and
record count*, not PKI. Do not deploy any of this anywhere real.

Padding mechanism: each intermediate carries one non-critical private-OID
extension (1.3.6.1.4.1.55555.1) whose OCTET STRING is ``pad_bytes`` of
0x5A. That is DER-legal, ignored by every TLS stack, and lets the chain be
sized to the byte.

Usage
-----
As a listener profile (mirrors the existing ``cert_profile="p384"`` shape):

    from https_listener import start_https_listener
    h = start_https_listener(host, port, cert_profile="p256-chain")

or via the env var the listener already honors:

    HTTPS_LISTENER_CERT_PROFILE=p256-chain python3 ... (any listener user)

Files: ``certs/server-chain.pem`` (leaf + 2 intermediates) served with the
existing ``certs/server.key``. The chain file is rebuilt whenever it is
missing or older than ``server.pem`` (leaf regeneration invalidates it).

``CHAIN_PAD_BYTES`` (env or kwarg) tunes the per-intermediate padding;
the default lands the chain at ~3.2 KB, mid-window.

Host-side selftest (no C64, no hardware):

    python3 tools/https_e2e/chain_certs.py --selftest

serves the chain on loopback, checks with a stdlib ``ssl`` client that all
3 certificates are sent and the leaf is byte-identical to server.pem, then
replays the C64's ClientHello replica (tools/probe_server_tls.py) to
confirm max_fragment_length is honored: every flight record <= 548 B
(``TLS_REC_BUF_MAX``) and the flight is >= 8 records.
"""
from __future__ import annotations

import datetime
import os
import secrets
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
GEN_DIR = REPO_ROOT / "tools" / "package" / "listener"
TOOLS_DIR = REPO_ROOT / "tools"

CHAIN_PEM_NAME = "server-chain.pem"

#: Per-intermediate padding (bytes of the private-OID extension payload).
#: Two intermediates at (~420 B base + pad) plus the ~480 B leaf lands the
#: chain around 3.2 KB — the middle of the real-target 2.7-3.5 KB window.
DEFAULT_PAD_BYTES = int(os.environ.get("CHAIN_PAD_BYTES", "950"))

#: Private enterprise arc — payload is opaque padding, never interpreted.
_PAD_OID = "1.3.6.1.4.1.55555.1"


def _gen_certs():
    """Import the stdlib-only DER/cert toolkit the listener package ships."""
    if str(GEN_DIR) not in sys.path:
        sys.path.insert(0, str(GEN_DIR))
    import gen_certs  # noqa: PLC0415
    return gen_certs


def build_padded_intermediate(cn: str, pad_bytes: int) -> bytes:
    """Mint one self-signed throwaway P-256 cert of ~(420 + pad_bytes) B.

    Returns the DER. The key is generated and discarded — these certs are
    padding, not signers of anything.
    """
    g = _gen_certs()
    crv = g.CURVES["p256"]

    d = secrets.randbelow(crv.n - 1) + 1
    qx, qy = g._mul(d, (crv.gx, crv.gy), crv.p, crv.a)
    pub_point = (b"\x04" + qx.to_bytes(crv.size, "big")
                 + qy.to_bytes(crv.size, "big"))

    name = g._seq(g._set(g._seq(g._oid(g.OID_COMMON_NAME), g._utf8(cn))))
    now = datetime.datetime.now(datetime.timezone.utc)
    validity = g._seq(
        g._utctime(now - datetime.timedelta(minutes=5)),
        g._utctime(now + datetime.timedelta(days=3650)),
    )
    sig_alg = g._seq(g._oid(g.OID_ECDSA_SHA256))
    spki = g._seq(
        g._seq(g._oid(g.OID_EC_PUBLIC_KEY), g._oid(g.OID_PRIME256V1)),
        g._bitstring(pub_point),
    )
    # One non-critical private-OID extension carrying opaque padding.
    extensions = g._explicit(3, g._seq(
        g._seq(g._oid(_PAD_OID), g._octetstring(b"\x5a" * pad_bytes)),
    ))
    tbs = g._seq(
        g._explicit(0, g._int(2)),
        g._int(secrets.randbits(159) | 1),
        sig_alg,
        name,                     # issuer == subject (throwaway self-signed)
        validity,
        name,
        spki,
        extensions,
    )
    signature = g._ecdsa_sign(crv.hasher(tbs).digest(), d, crv)
    return g._seq(tbs, sig_alg, g._bitstring(signature))


def ensure_chain_certs(certs_dir: Path | None = None,
                       force: bool = False,
                       pad_bytes: int | None = None,
                       quiet: bool = False) -> tuple[Path, Path]:
    """Return (chain_pem, key) for the p256-chain profile, building if stale.

    The leaf pair is ensured first (delegates to ensure_certs "p256"); the
    chain file is (re)built when absent, older than the leaf, or *force*.
    """
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    from ensure_certs import ensure_certs  # noqa: PLC0415

    leaf_pem, key_path = ensure_certs("p256", certs_dir, force=force,
                                      quiet=quiet)
    chain_pem = leaf_pem.parent / CHAIN_PEM_NAME

    stale = (
        force
        or not chain_pem.is_file()
        or chain_pem.stat().st_mtime < leaf_pem.stat().st_mtime
    )
    if not stale:
        return chain_pem, key_path

    pad = DEFAULT_PAD_BYTES if pad_bytes is None else pad_bytes
    g = _gen_certs()
    leaf_bytes = leaf_pem.read_bytes()
    ders = [build_padded_intermediate(f"C64 Test Padding Intermediate {i}",
                                      pad)
            for i in (1, 2)]
    pems = [g._pem("CERTIFICATE", der) for der in ders]
    chain_pem.write_bytes(leaf_bytes + b"".join(pems))

    if not quiet:
        import base64  # noqa: PLC0415
        leaf_der_len = len(base64.b64decode("".join(
            line for line in leaf_bytes.decode().splitlines()
            if not line.startswith("-"))))
        total = leaf_der_len + sum(len(d) for d in ders)
        print(f"wrote {chain_pem}")
        print(f"  leaf          = {leaf_der_len} B DER (certs/server.pem, "
              f"unchanged — the C64 still verifies it)")
        for i, der in enumerate(ders, 1):
            print(f"  intermediate{i} = {len(der)} B DER (padded, throwaway)")
        print(f"  chain total   = {total} B DER "
              f"(real targets: 2719-4114 B)")
    return chain_pem, key_path


# ---------------------------------------------------------------------------
# Selftest — host-only proof that the chain serves and MFL keeps records
# under TLS_REC_BUF_MAX. No C64, no hardware, loopback only.
# ---------------------------------------------------------------------------

def _selftest() -> int:
    import base64
    import socket
    import ssl

    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    from https_listener import start_https_listener, stop_https_listener
    import probe_server_tls

    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        print(f"  [{'ok' if cond else 'FAIL'}] {name}"
              + (f" — {detail}" if detail else ""))
        if not cond:
            failures.append(name)

    print("chain_certs selftest (host-only, loopback)")
    from ensure_certs import SANS  # noqa: PLC0415
    sni = SANS[-1]                 # derived, never spelled — see gen_certs
    chain_pem, key_path = ensure_chain_certs()
    leaf_der = base64.b64decode("".join(
        line for line in
        (chain_pem.parent / "server.pem").read_text().splitlines()
        if not line.startswith("-")))

    handle = start_https_listener(host="127.0.0.1", port=0,
                                  cert_profile="p256-chain")
    # A raw probe below deliberately abandons its handshake; keep the
    # resulting per-connection SSL errors out of the selftest output.
    handle.server.handle_error = lambda *a: None
    port = handle.server.server_port
    print(f"  listener on 127.0.0.1:{port} serving {handle.cert_path}")
    try:
        # --- 1. stdlib ssl client: chain content -------------------------
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=sni) as tls:
                check("TLS 1.3 negotiated", tls.version() == "TLSv1.3",
                      str(tls.version()))
                peer_leaf = tls.getpeercert(binary_form=True)
                check("served leaf == certs/server.pem",
                      peer_leaf == leaf_der,
                      f"{len(peer_leaf)} B")
                if hasattr(tls, "get_unverified_chain"):
                    chain = tls.get_unverified_chain() or []
                    # Depending on the Python build this yields Certificate
                    # objects or raw DER bytes — normalize to DER.
                    ders = [c if isinstance(c, (bytes, bytearray))
                            else c.public_bytes(ssl._ssl.ENCODING_DER)
                            for c in chain]
                    total = sum(len(d) for d in ders)
                    check("3 certificates served", len(ders) == 3,
                          f"per-cert {[len(d) for d in ders]}")
                    check("chain total in 2.7-3.5 KB window",
                          2700 <= total <= 3500, f"{total} B")
                else:
                    print("  (get_unverified_chain unavailable on this "
                          "Python — chain count unchecked)")
                tls.sendall(b"GET / HTTP/1.0\r\nHost: "
                            + sni.encode("ascii") + b"\r\n\r\n")
                resp = b""
                try:
                    while True:
                        b = tls.recv(4096)
                        if not b:
                            break
                        resp += b
                except (ssl.SSLError, OSError):
                    pass
                check("HTTP 200 over the chain",
                      resp.startswith(b"HTTP/1.0 200"), resp[:30].decode(
                          "ascii", "replace"))

        # --- 2. C64 ClientHello replica: record sizing -------------------
        # probe_server_tls sends the byte-faithful CH (single suite, X25519,
        # MFL=512) and splits the server flight into records. cap=1 keeps
        # the silent-tolerance leg short — sizing is all we want here.
        r = probe_server_tls.probe("127.0.0.1", port, send_mfl=True, cap=1)
        check("server accepted the C64's narrow ClientHello",
              not r.get("alert", True) and r.get("flight", 0) > 0,
              f"tolerance={r.get('tolerance')}")
        check("MFL honored: max record <= 548 B "
              "(TLS_REC_BUF_MAX; ~529 B expected)",
              0 < r.get("max_record", 0) <= probe_server_tls.TLS_REC_BUF_MAX,
              f"max={r.get('max_record')} B")
        check("flight >= 8 records (real targets: 11-14)",
              r.get("records", 0) >= 8,
              f"{r.get('records')} records, {r.get('flight')} B flight")
    finally:
        stop_https_listener(handle)

    if failures:
        print(f"\nSELFTEST FAIL: {failures}")
        return 1
    print("\nSELFTEST PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--selftest", action="store_true",
                   help="serve the chain on loopback and verify it "
                        "(stdlib ssl client + C64 ClientHello replica)")
    p.add_argument("--force", action="store_true",
                   help="rebuild the chain file even if fresh")
    p.add_argument("--pad-bytes", type=int, default=None,
                   help=f"per-intermediate padding (default "
                        f"{DEFAULT_PAD_BYTES}, or CHAIN_PAD_BYTES env)")
    args = p.parse_args(argv)

    if args.selftest:
        return _selftest()
    chain, key = ensure_chain_certs(force=args.force,
                                    pad_bytes=args.pad_bytes)
    print(f"chain: {chain}\nkey:   {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
