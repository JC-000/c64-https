#!/usr/bin/env python3
"""pq_keylog_check.py - did the C64's Decaps agree with the server's Encaps?

The oracle for the X25519MLKEM768 hardware rig (PQC phases P4/P5). OpenSSL's
`s_server -keylogfile` writes the traffic secrets it derived:

    SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random hex> <secret hex>
    CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random hex> <secret hex>

--state (P5, the rig mode): the C64 runs the hybrid key schedule and zeroes both
shared secrets, so the verdict compares its application traffic secrets with
the keylog's CLIENT/SERVER_TRAFFIC_SECRET_0, gated on tls_reached_connected.
The explicit mode below (P4) takes the secrets as arguments: it runs the
RFC 8446 section 7.1 schedule on them OFFLINE (hashlib/hmac only) with the hybrid input

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
78: --state mode and the run did not reach the point (the sentinel gate).
In --state mode exit 1 is also a RESIDUE failure (a hybrid secret left in RAM).
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


def check_state(state, keylog_text):
    """*state* is tools/uci/rig_https_local.py's PQ_DUMP pq_state.json (P5).
    Returns (verdict, message): True / False; None = a usage problem;
    "inconclusive" when the run provably did not reach the point whose memory
    is being quoted (the sentinel gate: a run that stopped earlier leaves
    plausible-looking bytes in uninitialised memory).

    Since P5 the C64 zeroes both shared secrets once the handshake secret is
    extracted, so the secrets themselves are no longer there to compare. What
    stays is the APPLICATION traffic secrets (tls_c_hs_secret / tls_s_hs_secret
    are reused for them): a pure function of the hybrid handshake secret and
    the transcript through the server Finished, which OpenSSL logs as
    CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0. Equal bytes prove the
    C64's key schedule ran with the server's own mlkem_ss || x25519_ss. The
    gate is the tls_reached_connected latch (#204), not tls_state, which is
    IDLE again after tls_close."""
    h = lambda k: bytes.fromhex(state[k])          # noqa: E731
    if h("tls_kex_group") != b"\xec":
        return "inconclusive", f"tls_kex_group=${state['tls_kex_group']}: the server did not choose 11EC, no hybrid run to check"
    if h("tls_sh_err") != b"\x00":
        return "inconclusive", f"tls_sh_err=${state['tls_sh_err']}: the ServerHello was refused"
    if h("tls_reached_connected") != b"\x07":
        return "inconclusive", (f"tls_reached_connected=${state['tls_reached_connected']}: the handshake never "
                                f"completed (tls_state=${state['tls_state']}, last_state=${state['tls_last_state']})")
    for k in ("tls_c_hs_secret", "tls_s_hs_secret"):
        if h(k) == bytes(32):
            return "inconclusive", f"{k} is all zero: not produced"
    # Hygiene first: a connected run must have scrubbed every hybrid secret.
    for k in ("tls_pq_seed", "tls_mlkem_ss", "tls_shared_secret"):
        if h(k) != bytes(len(h(k))):
            return False, f"RESIDUE: {k} is not zero after the handshake secret was extracted"
    log = parse_keylog(keylog_text, h("tls_client_random").hex())
    need = ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")
    for n in need:
        if n not in log:
            return None, f"keylog has no {n} for client_random {state['tls_client_random']}"
    if log[need[0]] == h("tls_c_hs_secret") and log[need[1]] == h("tls_s_hs_secret"):
        return True, "match: the C64's application traffic secrets equal the server's CLIENT/SERVER_TRAFFIC_SECRET_0 (hybrid key schedule agreed)"
    return False, "MISMATCH: the C64's application traffic secrets differ from the server's (key schedule, secret or transcript disagree)"


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
    # --- state-file mode (P5): application traffic secrets + sentinel gate ---
    ca, sa = bytes(range(1, 33)), bytes(range(50, 82))
    log3 = log + (f"CLIENT_TRAFFIC_SECRET_0 {rnd.hex()} {ca.hex()}\n"
                  f"SERVER_TRAFFIC_SECRET_0 {rnd.hex()} {sa.hex()}\n")
    good = {"tls_c_hs_secret": ca.hex(), "tls_s_hs_secret": sa.hex(),
            "tls_client_random": rnd.hex(), "tls_kex_group": "ec", "tls_sh_err": "00",
            "tls_state": "00", "tls_last_state": "00", "tls_reached_connected": "07",
            "tls_pq_seed": "00" * 64, "tls_mlkem_ss": "00" * 32, "tls_shared_secret": "00" * 32}
    r, m = check_state(good, log3)
    expect(r is True, "state mode: a CONNECTED-then-closed run (tls_state=0) matches")
    for key, val, why in (("tls_kex_group", "1d", "11EC"),
                          ("tls_sh_err", "07", "refused"),
                          ("tls_reached_connected", "00", "never connected"),
                          ("tls_reached_connected", "03", "stopped at ServerHello"),
                          ("tls_c_hs_secret", "00" * 32, "client secret all zero"),
                          ("tls_s_hs_secret", "00" * 32, "server secret all zero")):
        bad = dict(good)
        bad[key] = val
        r, m = check_state(bad, log3)
        expect(r == "inconclusive", f"state mode: gate ({why}) -> inconclusive, not a verdict")
    for key in ("tls_pq_seed", "tls_mlkem_ss", "tls_shared_secret"):
        bad = dict(good)
        bad[key] = "11" * len(bytes.fromhex(good[key]))
        r, m = check_state(bad, log3)
        expect(r is False and "RESIDUE" in m, f"state mode: {key} left non-zero is a RESIDUE failure")
    for key in ("tls_c_hs_secret", "tls_s_hs_secret"):
        bad = dict(good)
        bad[key] = bytes(range(9, 41)).hex()
        r, m = check_state(bad, log3)
        expect(r is False, f"state mode: a wrong {key} is a mismatch")
    r, m = check_state(good, log)
    expect(r is None, "state mode: a keylog without the traffic-secret lines is a usage error")
    print("SELFTEST " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--keylog")
    ap.add_argument("--client-random")
    ap.add_argument("--mlkem-ss")
    ap.add_argument("--x25519-ss")
    ap.add_argument("--transcript", help="SHA-256(ClientHello || ServerHello), as the C64 hashed it")
    ap.add_argument("--state", help="pq_state.json from rig_https_local.py with PQ_DUMP=<dir> "
                    "(replaces --client-random/--mlkem-ss/--x25519-ss/--transcript)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if a.state:
        import json
        if not a.keylog:
            ap.error("--keylog is required")
        r, msg = check_state(json.load(open(a.state)), open(a.keylog).read())
        print(msg)
        return 78 if r == "inconclusive" else (0 if r else (2 if r is None else 1))
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
