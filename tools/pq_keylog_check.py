#!/usr/bin/env python3
"""pq_keylog_check.py - did the C64's Decaps agree with the server's Encaps?

The oracle for the X25519MLKEM768 hardware rig (PQC phase P4). OpenSSL's
`s_server -keylogfile` writes the handshake traffic secrets it derived:

    SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random hex> <secret hex>
    CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random hex> <secret hex>

The C64 (P4) does not run the hybrid key schedule yet, so it cannot read the
first encrypted record - but its Decaps output, its X25519 shared secret and
its transcript hash are in RAM. This tool runs the RFC 8446 section 7.1
schedule on them OFFLINE (hashlib/hmac only) with the hybrid input

    IKM = mlkem_ss || x25519_ss          (draft-ietf-tls-ecdhe-mlkem: ML-KEM first)

and compares the derived handshake traffic secrets with the keylog's. A match
proves the C64's ML-KEM secret equals the server's Encaps secret AND that the
transcript the C64 folded (CH || SH) is the one the server hashed: nothing else
reproduces 32 bytes of HKDF output.

    pq_keylog_check.py --keylog K --client-random HEX --mlkem-ss HEX \
        --x25519-ss HEX --transcript HEX
    pq_keylog_check.py --selftest

Exit 0: both secrets match. 1: mismatch (it also says if the OTHER ikm order,
x25519 || mlkem, would have matched). 2: usage / missing keylog line.
"""

import argparse
import hashlib
import hmac
import struct
import sys


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def expand_label(secret, label, context, n):
    full = b"tls13 " + label
    info = struct.pack(">H", n) + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(secret, info, n)


def handshake_secrets(ikm, transcript_hash):
    """(client, server) handshake traffic secrets for *ikm* and the hash of
    ClientHello..ServerHello."""
    early = hkdf_extract(bytes(32), bytes(32))
    derived = expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
    hs = hkdf_extract(derived, ikm)
    return (expand_label(hs, b"c hs traffic", transcript_hash, 32),
            expand_label(hs, b"s hs traffic", transcript_hash, 32))


def parse_keylog(text, client_random_hex):
    found = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1].lower() == client_random_hex.lower():
            found[parts[0]] = bytes.fromhex(parts[2])
    return found


def check(keylog_text, client_random, mlkem_ss, x25519_ss, transcript):
    """Returns (ok, message)."""
    log = parse_keylog(keylog_text, client_random.hex())
    need = ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
    for n in need:
        if n not in log:
            return None, f"keylog has no {n} for client_random {client_random.hex()}"
    c, s = handshake_secrets(mlkem_ss + x25519_ss, transcript)
    if c == log[need[1]] and s == log[need[0]]:
        return True, "match: mlkem_ss || x25519_ss reproduces the server and client handshake traffic secrets"
    c2, s2 = handshake_secrets(x25519_ss + mlkem_ss, transcript)
    if s2 == log[need[0]]:
        return False, "MISMATCH, but x25519_ss || mlkem_ss matches: the concatenation order is swapped"
    c3, s3 = handshake_secrets(x25519_ss, transcript)
    if s3 == log[need[0]]:
        return False, "MISMATCH, but x25519_ss alone matches: the server did not run the hybrid"
    return False, "MISMATCH: neither IKM order reproduces the server's secret (wrong ML-KEM secret, X25519 secret or transcript)"


def selftest():
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import test_tls_handshake as TH      # the repo's own HKDF reference
    ok = True

    def expect(cond, what):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + what)
        ok = ok and cond

    rnd = bytes(range(32))
    mk, xs = bytes(range(100, 132)), bytes(range(200, 232))
    th = hashlib.sha256(b"ch||sh").digest()
    # independent derivation through the repo's reference functions
    early = TH.hkdf_extract_ref(bytes(32), bytes(32))
    derived = TH.derive_secret_ref(early, b"derived", hashlib.sha256(b"").digest())
    hs = TH.hkdf_extract_ref(derived, mk + xs)
    s_ref = TH.hkdf_expand_label_ref(hs, b"s hs traffic", th, 32)
    c_ref = TH.hkdf_expand_label_ref(hs, b"c hs traffic", th, 32)
    c, s = handshake_secrets(mk + xs, th)
    expect((c, s) == (c_ref, s_ref), "agrees with the repo's HKDF reference (test_tls_handshake)")
    log = (f"SERVER_HANDSHAKE_TRAFFIC_SECRET {rnd.hex()} {s.hex()}\n"
           f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {rnd.hex()} {c.hex()}\n"
           f"SERVER_HANDSHAKE_TRAFFIC_SECRET {bytes(32).hex()} {bytes(32).hex()}\n")
    r, m = check(log, rnd, mk, xs, th)
    expect(r is True, "green: matching secrets accepted")
    bad = bytearray(mk)
    bad[5] ^= 1
    r, m = check(log, rnd, bytes(bad), xs, th)
    expect(r is False, "red: one flipped bit in the ML-KEM secret is a mismatch")
    bad = bytearray(xs)
    bad[31] ^= 0x80
    r, m = check(log, rnd, mk, bytes(bad), th)
    expect(r is False, "red: one flipped bit in the X25519 secret is a mismatch")
    bad = bytearray(th)
    bad[0] ^= 1
    r, m = check(log, rnd, mk, xs, bytes(bad))
    expect(r is False, "red: one flipped bit in the transcript hash is a mismatch")
    r, m = check(log, rnd, xs, mk, th)
    expect(r is False and "swapped" in m, "red: swapped concatenation order is named")
    log2 = (f"SERVER_HANDSHAKE_TRAFFIC_SECRET {rnd.hex()} "
            f"{handshake_secrets(xs, th)[1].hex()}\n"
            f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {rnd.hex()} {c.hex()}\n")
    r, m = check(log2, rnd, mk, xs, th)
    expect(r is False and "did not run the hybrid" in m, "red: a classic-only server is named")
    r, m = check(log, bytes(31) + b"\x01", mk, xs, th)
    expect(r is None, "a keylog without the client_random's lines is a usage error, not a pass")
    print("SELFTEST " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--keylog")
    ap.add_argument("--client-random")
    ap.add_argument("--mlkem-ss")
    ap.add_argument("--x25519-ss")
    ap.add_argument("--transcript", help="SHA-256(ClientHello || ServerHello), as the C64 hashed it")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    for n in ("keylog", "client_random", "mlkem_ss", "x25519_ss", "transcript"):
        if getattr(a, n) is None:
            ap.error(f"--{n.replace('_', '-')} is required")
    text = open(a.keylog).read()
    r, msg = check(text, bytes.fromhex(a.client_random), bytes.fromhex(a.mlkem_ss),
                   bytes.fromhex(a.x25519_ss), bytes.fromhex(a.transcript))
    print(msg)
    return 0 if r else (2 if r is None else 1)


if __name__ == "__main__":
    sys.exit(main())
