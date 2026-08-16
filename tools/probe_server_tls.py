#!/usr/bin/env python3
"""Probe a real HTTPS server for c64-https compatibility. No C64, no hardware.

Sends a byte-faithful replica of the ClientHello src/tls_handshake.s actually
emits and reports the three things that decide whether the C64 can talk to a
given server:

  1. Does it accept our very narrow ClientHello at all?  We offer exactly one
     cipher suite (TLS_CHACHA20_POLY1305_SHA256), one group (X25519) and two
     ECDSA signature algorithms.  No RSA path exists in the client.
  2. How large are its records?  src/tls_record_io.s rejects any record whose
     length field exceeds TLS_REC_BUF_MAX (548).  We ask for small records via
     max_fragment_length=512 (RFC 6066); servers are free to ignore it.
  3. How long will it wait for a silent client?  The C64 goes quiet for tens of
     seconds computing the X25519 shared secret and the ECDSA verify, and the
     server's handshake timer is running the whole time.

Measured 2026-08-15 (see the sprint plan and the real-server-tls-tolerance
memory note):

    server              max record   silence tolerance   leaf
    github.com               529 B          90 s        1010 B
    browserleaks.com         529 B          45 s         952 B
    en.wikipedia.org         529 B        >100 s        1636 B  (> cert_buf)
    cloudflare.com          2714 B          15 s         981 B  (out of scope)

These are live third-party servers.  Re-run this before relying on any of those
numbers.

Usage:
    tools/probe_server_tls.py github.com browserleaks.com
    tools/probe_server_tls.py --no-mfl cloudflare.com     # omit MFL extension
    tools/probe_server_tls.py --cap 120 example.com       # silence-probe cap
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import threading
import time

# src/tls_record_io.s:43 — the client hard-rejects anything larger.
TLS_REC_BUF_MAX = 548
# src/der_decode.s — leaf certificate staging buffer.
CERT_BUF = 1536


def client_hello(hostname: str, send_mfl: bool = True) -> bytes:
    """Rebuild src/tls_handshake.s's ClientHello byte-for-byte.

    The key share is arbitrary bytes: we never complete the handshake, we only
    need the server to commit to a flight.
    """
    kx = bytes(range(32))
    body = b"\x03\x03" + os.urandom(32)          # legacy_version + random
    body += b"\x00"                              # session_id_length = 0
    body += b"\x00\x02\x13\x03"                  # TLS_CHACHA20_POLY1305_SHA256
    body += b"\x01\x00"                          # compression: null

    ext = b"\x00\x2b\x00\x03\x02\x03\x04"                     # supported_versions
    ext += b"\x00\x0a\x00\x04\x00\x02\x00\x1d"                # supported_groups
    ext += b"\x00\x0d\x00\x06\x00\x04\x04\x03\x05\x03"        # sigalgs 0403/0503
    ext += b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20" + kx   # key_share x25519
    hn = hostname.encode()
    ext += (b"\x00\x00" + struct.pack(">H", len(hn) + 5)
            + struct.pack(">H", len(hn) + 3) + b"\x00"
            + struct.pack(">H", len(hn)) + hn)                # SNI
    if send_mfl:
        ext += b"\x00\x01\x00\x01\x01"                        # MFL = 512

    body += struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def split_records(buf: bytes) -> list[tuple[int, int]]:
    out, off = [], 0
    while off + 5 <= len(buf):
        typ = buf[off]
        ln = struct.unpack(">H", buf[off + 3:off + 5])[0]
        out.append((typ, ln))
        off += 5 + ln
    return out


def probe(host: str, port: int, send_mfl: bool, cap: float) -> dict:
    r: dict = {"host": host}
    try:
        s = socket.create_connection((host, port), timeout=15)
        t0 = time.time()
        s.sendall(client_hello(host, send_mfl))
        s.settimeout(4)
        buf = b""
        try:
            while True:
                chunk = s.recv(16384)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        recs = split_records(buf)
        r["flight"] = len(buf)
        r["records"] = len(recs)
        r["max_record"] = max((ln for t, ln in recs if t in (22, 23)), default=0)
        r["alert"] = any(t == 21 for t, _ in recs)
        if not buf:
            r["tolerance"] = "no reply"
        elif r["alert"]:
            r["tolerance"] = "REJECTED our ClientHello"
        else:
            # Go silent, exactly as the C64 does while it computes.
            s.settimeout(5)
            r["tolerance"] = f">{cap:.0f}s"
            while time.time() - t0 < cap:
                try:
                    if not s.recv(4096):
                        r["tolerance"] = f"{time.time() - t0:.0f}s"
                        break
                except socket.timeout:
                    continue
                except OSError:
                    r["tolerance"] = f"{time.time() - t0:.0f}s (RST)"
                    break
        s.close()
    except Exception as exc:                       # noqa: BLE001 - report, don't raise
        r["tolerance"] = f"ERROR {type(exc).__name__}: {exc}"
    return r


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", nargs="+")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--no-mfl", action="store_true",
                    help="omit max_fragment_length (shows unfragmented sizes)")
    ap.add_argument("--cap", type=float, default=100.0,
                    help="seconds to stay silent before giving up (default 100)")
    args = ap.parse_args()

    results: dict[str, dict] = {}
    threads = [threading.Thread(
        target=lambda h: results.__setitem__(
            h, probe(h, args.port, not args.no_mfl, args.cap)),
        args=(h,)) for h in args.hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"max_fragment_length: {'omitted' if args.no_mfl else 'sent (512)'}; "
          f"silence cap {args.cap:.0f}s\n")
    print(f"{'host':24s} {'flight':>8s} {'#rec':>5s} {'max rec':>8s} "
          f"{'fits 548':>9s}  tolerance")
    print("-" * 78)
    worst = 0
    for h in args.hosts:
        r = results.get(h, {})
        mx = r.get("max_record", 0)
        fits = "-" if not mx else ("YES" if mx <= TLS_REC_BUF_MAX else "NO")
        if fits == "NO":
            worst += 1
        print(f"{h:24s} {r.get('flight', 0):8d} {r.get('records', 0):5d} "
              f"{mx:8d} {fits:>9s}  {r.get('tolerance', '?')}")

    print(f"\nRecords over {TLS_REC_BUF_MAX} B are rejected outright by "
          f"src/tls_record_io.s.")
    print("Tolerance is how long the server waits with the client silent — the "
          "C64's\nbudget for the X25519 shared secret plus the ECDSA verify.")
    if worst:
        print(f"\n{worst} server(s) exceed the record limit and need the "
              "large-record path.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
