#!/usr/bin/env python3
"""test_trust_bundle_unit.py — pure-logic tests for tools/trust_bundle.py (#155 phase 2).

No VICE, no network, no build. The C64-side proof (the same bytes through the
real `ecdsa_verify_256`) is tools/test_trust_bundle_c64.py.

The signer is `cryptography` (OpenSSL). Its output is checked here by two
verifiers that share nothing with it: a textbook affine P-256 ECDSA verify
written below in plain Python integers, and the `openssl` CLI. A bundle that
only verified under the library that signed it would prove nothing.

    python3 -m pytest tools/test_trust_bundle_unit.py
    python3 tools/test_trust_bundle_unit.py          # standalone
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import trust_bundle as tb  # noqa: E402
from _skip_policy import require, verdict  # noqa: E402

# --- independent P-256 ECDSA verify (FIPS 186-4 §6.4.2), plain integers -----

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def indep_verify(digest: bytes, r: int, s: int, qxy: bytes) -> bool:
    q = (int.from_bytes(qxy[:32], "big"), int.from_bytes(qxy[32:], "big"))
    if (q[1] ** 2 - q[0] ** 3 - A * q[0] - B) % P:
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = int.from_bytes(digest, "big")
    w = pow(s, -1, N)
    pt = _add(_mul(e * w % N, G), _mul(r * w % N, q))
    return pt is not None and pt[0] % N == r


def indep_verify_struct(struct160: bytes) -> bool:
    """Verify the exact 160 B r|s|h|Qx|Qy block the C64 is handed."""
    return indep_verify(struct160[64:96], int.from_bytes(struct160[0:32], "big"),
                        int.from_bytes(struct160[32:64], "big"), struct160[96:])


# --- fixtures -----------------------------------------------------------------

KEY = tb.load_private_key(tb.TEST_KEY_PATH)
PUB = KEY.public_key()
QXY = tb.pubkey_xy(PUB)
WIKI_PIN = bytes.fromhex(
    "c0a0573a0bfb1cc696f3ccb6a0be4e784fb9d887755b3e509a44adc41481c3fe")


def _pins(n):
    return [tb.Record.leaf(f"host{i}.example", hashlib.sha256(bytes([i])).digest())
            for i in range(n)]


def _rejects(blob, floor=0):
    try:
        tb.verify(bytes(blob), PUB, floor)
    except tb.BundleError:
        return True
    return False


# --- tests --------------------------------------------------------------------

def test_layout_is_the_documented_one() -> None:
    blob = tb.sign(KEY, 0x1234, [tb.Record.leaf("En.Wikipedia.ORG", WIKI_PIN)])
    assert len(blob) == 8 + 64 + 64
    assert blob[:4] == b"C6TB" and blob[4] == 1
    assert blob[5:7] == b"\x34\x12", "generation is u16 LITTLE-endian"
    assert blob[7] == 1
    rec = blob[8:72]
    assert rec[0:16] == hashlib.sha256(b"en.wikipedia.org").digest()[:16]
    assert rec[16:48] == WIKI_PIN
    assert rec[48] == 0x10 and rec[49] == 0x01
    assert rec[50:52] == b"\x00\x00"
    assert rec[52:64] == b"en.wikipedia"
    b = tb.parse(blob)
    assert blob[72:104] == b.r.to_bytes(32, "big")
    assert blob[104:136] == b.s.to_bytes(32, "big")


def test_host_key_folds_ascii_case_only() -> None:
    assert tb.host_key("GitHub.COM") == tb.host_key("github.com")
    for bad in ("", "a" * 64, "example.com.", "bücher.de", "a b"):
        try:
            tb.host_key(bad)
        except tb.BundleError:
            continue
        raise AssertionError(f"host {bad!r} accepted")


def test_signing_is_deterministic_and_sorted() -> None:
    recs = _pins(5)
    a = tb.sign(KEY, 3, recs)
    assert a == tb.sign(KEY, 3, list(reversed(recs)))
    keys = [r.host_key for r in tb.parse(a).records]
    assert keys == sorted(keys)


def test_signature_is_ecdsa_sha256_over_header_and_records() -> None:
    for n in (0, 1, 7, 32):
        blob = tb.sign(KEY, n, _pins(n))
        b = tb.verify(blob, PUB, 0)
        digest = hashlib.sha256(blob[:8 + 64 * n]).digest()
        assert indep_verify(digest, b.r, b.s, QXY), f"N={n}"
        struct = tb.c64_verify_struct(blob, QXY)
        assert struct[0:64] == blob[-64:]
        assert struct[64:96] == digest
        assert struct[96:] == QXY
        assert indep_verify_struct(struct), f"N={n}"


def test_openssl_cli_accepts_it() -> None:
    require(shutil.which("openssl") is not None, "openssl not on PATH",
            executed=0, total=1,
            certifies="the bundle signature under an independent verifier",
            opt_out_env="C64_ALLOW_SKIP")
    blob = tb.sign(KEY, 1, [tb.Record.leaf("en.wikipedia.org", WIKI_PIN)])
    with tempfile.TemporaryDirectory() as d:
        bpath = os.path.join(d, "b.bin")
        with open(bpath, "wb") as f:
            f.write(blob)
        assert tb.main(["openssl-files", "--test-key", bpath, d]) == 0
        cmd = ["openssl", "dgst", "-sha256", "-verify", f"{d}/pub.pem",
               "-signature", f"{d}/sig.der", f"{d}/msg.bin"]
        ok = subprocess.run(cmd, capture_output=True, text=True)
        assert ok.returncode == 0 and "Verified OK" in ok.stdout, ok
        msg = bytearray(open(f"{d}/msg.bin", "rb").read())
        msg[20] ^= 0x01
        with open(f"{d}/msg.bin", "wb") as f:
            f.write(msg)
        bad = subprocess.run(cmd, capture_output=True, text=True)
        assert bad.returncode != 0, "openssl accepted a tampered message"


def test_every_single_bit_flip_is_rejected() -> None:
    blob = tb.sign(KEY, 5, _pins(2))
    assert not _rejects(blob)
    for i in range(len(blob)):
        for bit in range(8):
            t = bytearray(blob)
            t[i] ^= 1 << bit
            assert _rejects(t), f"flip byte {i} bit {bit} accepted"


def test_bit_flips_fail_the_c64_math_too() -> None:
    # What the C64 computes, byte for byte, with no host-side parsing: any
    # flip in the signed part or the trailer must fail the raw ECDSA check.
    # A sample, since the pure-Python verify is slow.
    blob = tb.sign(KEY, 5, [tb.Record.leaf("en.wikipedia.org", WIKI_PIN)])
    assert indep_verify_struct(tb.c64_verify_struct(blob, QXY))
    for i in (0, 5, 6, 7, 8, 30, 60, 71, 72, 103, 104, 135):
        t = bytearray(blob)
        t[i] ^= 0x80
        assert not indep_verify_struct(tb.c64_verify_struct(bytes(t), QXY)), i


def test_structural_rejects() -> None:
    good = tb.sign(KEY, 5, _pins(2))
    assert not _rejects(good, 5)
    assert _rejects(good, 6), "generation below the floor accepted"
    assert _rejects(good + b"\x00"), "trailing byte accepted"
    assert _rejects(good[:-1]), "short file accepted"
    assert _rejects(b""), "empty file accepted"

    # Structure is checked before the signature, so each of these is rejected
    # even when re-signed with the right key — build them unsigned by hand.
    body = bytearray(tb.unsigned_body(5, _pins(2)))

    def resign(b):
        der = KEY.sign(bytes(b), tb.ec.ECDSA(tb.hashes.SHA256()))
        r, s = tb.decode_dss_signature(der)
        return bytes(b) + r.to_bytes(32, "big") + s.to_bytes(32, "big")

    assert not _rejects(resign(body))
    for off, val, why in ((4, 2, "version 2"), (7, 3, "N disagrees with length"),
                          (8 + 48, 0x01, "store mode in a bundle"),
                          (8 + 49, 0x00, "leaf pin without WARN_ONLY"),
                          (8 + 49, 0x03, "unknown flag bit"),
                          (8 + 50, 0x01, "non-zero use count")):
        t = bytearray(body)
        t[off] = val
        assert _rejects(resign(t)), why
    swapped = body[:8] + body[72:136] + body[8:72]
    assert _rejects(resign(swapped)), "records out of order accepted"
    dup = body[:8] + body[8:72] + body[8:72]
    assert _rejects(resign(dup)), "duplicate host key accepted"
    try:
        tb.sign(KEY, 1, _pins(33))
    except tb.BundleError:
        pass
    else:
        raise AssertionError("33 records signed")


def test_r_s_out_of_range_rejected() -> None:
    body = tb.unsigned_body(1, _pins(1))
    for r, s in ((0, 1), (1, 0), (tb.P256_N, 1), (1, tb.P256_N)):
        blob = body + r.to_bytes(32, "big") + s.to_bytes(32, "big")
        assert _rejects(blob), (r, s)


def test_test_key_is_labelled_as_such() -> None:
    assert "TEST_ONLY" in os.path.basename(tb.TEST_KEY_PATH)
    head = open(tb.TEST_KEY_PATH).read().split("-----BEGIN")[0]
    assert "TEST-ONLY" in head and "DO NOT SHIP" in head
    assert tb.is_test_key(PUB)
    other = tb.ec.generate_private_key(tb.ec.SECP256R1())
    assert not tb.is_test_key(other.public_key())
    assert "TRUST_BUNDLE_KEY_IS_TEST_ONLY = 0" in tb.render_inc(other.public_key(), 1)


def test_committed_inc_matches_the_generator() -> None:
    with open(tb.TEST_INC_PATH) as f:
        committed = f.read()
    assert committed == tb.render_inc(PUB, 1), \
        "regenerate: trust_bundle.py inc --test-key --floor 1 -o " + tb.TEST_INC_PATH
    assert "TRUST_BUNDLE_KEY_IS_TEST_ONLY = 1" in committed
    assert "TRUST_BUNDLE_GEN_FLOOR        = $0001" in committed


def test_inc_assembles_and_emits_the_key() -> None:
    have = shutil.which("ca65") and shutil.which("ld65")
    require(bool(have), "ca65/ld65 not on PATH", executed=0, total=1,
            certifies="the generated .inc under ca65",
            opt_out_env="C64_ALLOW_SKIP")
    with tempfile.TemporaryDirectory() as d:
        with open(f"{d}/t.s", "w") as f:
            f.write('.include "k.inc"\n.segment "CODE"\n'
                    ".assert TRUST_BUNDLE_GEN_FLOOR = 1, error\n"
                    "TRUST_BUNDLE_MAGIC_BYTES\nTRUST_BUNDLE_PUBKEY_BYTES\n")
        with open(f"{d}/k.inc", "w") as f:
            f.write(tb.render_inc(PUB, 1))
        with open(f"{d}/t.cfg", "w") as f:
            f.write("MEMORY { M: start=$1000, size=$100, file=%O; }\n"
                    "SEGMENTS { CODE: load=M, type=ro; }\n")
        for cmd in (["ca65", "-o", f"{d}/t.o", f"{d}/t.s"],
                    ["ld65", "-C", f"{d}/t.cfg", "-o", f"{d}/t.bin", f"{d}/t.o"]):
            res = subprocess.run(cmd, capture_output=True, text=True)
            assert res.returncode == 0, res.stderr
        # an include with no macro invocation emits nothing
        with open(f"{d}/e.s", "w") as f:
            f.write('.include "k.inc"\n')
        subprocess.run(["ca65", "-o", f"{d}/e.o", f"{d}/e.s"], check=True)
        out = open(f"{d}/t.bin", "rb").read()
    assert out == b"C6TB" + QXY, out.hex()


def test_committed_sample_bundle() -> None:
    blob = open(tb.SAMPLE_BUNDLE_PATH, "rb").read()
    b = tb.verify(blob, PUB, 1)
    assert b.generation == 1
    [rec] = b.records
    assert rec.host_key == tb.host_key("en.wikipedia.org")
    assert rec.mode == tb.MODE_BUNDLE_LEAF and rec.flags == tb.FLAG_WARN_ONLY
    assert len(rec.spki_sha256) == 32
    assert indep_verify_struct(tb.c64_verify_struct(blob, QXY))


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    passed = failed = 0
    for t in TESTS:
        try:
            t()
            passed += 1
            print(f"PASS {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    sys.exit(verdict(passed, failed, certifies="tools/trust_bundle.py"))
