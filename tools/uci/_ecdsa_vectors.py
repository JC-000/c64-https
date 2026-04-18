#!/usr/bin/env python3
"""Generate ECDSA P-256 test vectors for the U64E ecdsa_verify measurement.

Produces three kinds of vectors, written to _ecdsa_vectors.json next to this
file:
  - "pos_rfc6979": RFC 6979 §A.2.5 sample — d/message/expected r,s
    transcribed verbatim, then hashed and verified by us to confirm.
  - "pos_rfc6979_test": RFC 6979 §A.2.5 test — same.
  - "pos_fresh_1" / "pos_fresh_2": freshly-generated (signed here) — the
    private key is discarded, only pubkey + hash + r + s are kept.
  - "neg_tampered_s":  pos_rfc6979 with one byte of s flipped.
  - "neg_tampered_hash": pos_rfc6979 with one byte of hash flipped.

All integers are 32-byte big-endian fixed-length hex strings so the 6502
stub can memcpy them directly into the ecdsa_* buffers.

We self-verify every positive vector with python's ECDSA before writing,
so if a transcribed constant is wrong the script fails loudly here rather
than silently blaming the 6502 code.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# --- RFC 6979 §A.2.5 P-256 / SHA-256 ---
# https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
RFC6979_D_HEX = (
    "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
)
# Qx / Qy derived from d:
RFC6979_QX_HEX = (
    "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
)
RFC6979_QY_HEX = (
    "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
)

RFC6979_SAMPLE_MSG = b"sample"
# SHA-256("sample") -> z is the hash directly
RFC6979_SAMPLE_R = (
    "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
)
RFC6979_SAMPLE_S = (
    "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
)

RFC6979_TEST_MSG = b"test"
RFC6979_TEST_R = (
    "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"
)
RFC6979_TEST_S = (
    "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"
)


def _int_from_hex32(s: str) -> int:
    return int(s, 16)


def _build_pubkey(qx: int, qy: int) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicNumbers(qx, qy, ec.SECP256R1()).public_key()


def _self_verify(vec: dict) -> bool:
    """Run python-cryptography's verify against the vector. Returns bool."""
    qx = _int_from_hex32(vec["pubkey_x"])
    qy = _int_from_hex32(vec["pubkey_y"])
    r = _int_from_hex32(vec["sig_r"])
    s = _int_from_hex32(vec["sig_s"])
    digest = bytes.fromhex(vec["hash"])
    pub = _build_pubkey(qx, qy)
    der = encode_dss_signature(r, s)
    # Use ECDSA with pre-hashed "prehashed" mode by wrapping SHA-256 with the
    # proper utils. The cryptography API wants a hash algorithm; use
    # Prehashed to feed the digest directly.
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    try:
        pub.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def _make_rfc6979(name: str, msg: bytes, r_hex: str, s_hex: str) -> dict:
    digest = hashlib.sha256(msg).digest()
    return {
        "name": name,
        "curve": "P-256",
        "expected_valid": True,
        "msg_ascii": msg.decode("ascii"),
        "hash": digest.hex().upper(),
        "pubkey_x": RFC6979_QX_HEX,
        "pubkey_y": RFC6979_QY_HEX,
        "sig_r": r_hex,
        "sig_s": s_hex,
    }


def _make_fresh(name: str, msg: bytes) -> dict:
    """Sign `msg` with a freshly-generated P-256 key; keep only public parts."""
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    numbers = pk.public_numbers()
    der = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    digest = hashlib.sha256(msg).digest()
    return {
        "name": name,
        "curve": "P-256",
        "expected_valid": True,
        "msg_ascii": msg.decode("ascii", errors="replace"),
        "hash": digest.hex().upper(),
        "pubkey_x": f"{numbers.x:064X}",
        "pubkey_y": f"{numbers.y:064X}",
        "sig_r": f"{r:064X}",
        "sig_s": f"{s:064X}",
    }


def _tamper_byte(hex_str: str, offset: int) -> str:
    """Flip all bits of the given byte offset inside a hex-encoded string."""
    raw = bytearray.fromhex(hex_str)
    raw[offset] ^= 0xFF
    return raw.hex().upper()


def main() -> int:
    vectors: list[dict] = []

    # --- Positive vectors from RFC 6979 ---
    v_sample = _make_rfc6979(
        "pos_rfc6979_sample",
        RFC6979_SAMPLE_MSG,
        RFC6979_SAMPLE_R,
        RFC6979_SAMPLE_S,
    )
    v_test = _make_rfc6979(
        "pos_rfc6979_test",
        RFC6979_TEST_MSG,
        RFC6979_TEST_R,
        RFC6979_TEST_S,
    )
    vectors.append(v_sample)
    vectors.append(v_test)

    # --- Fresh positive vector (deterministic-by-luck; independent from RFC) ---
    v_fresh = _make_fresh("pos_fresh_1", b"c64-ecdsa-measurement")
    vectors.append(v_fresh)

    # --- Negative vectors: tamper from pos_rfc6979_sample ---
    v_neg_s = dict(v_sample)
    v_neg_s["name"] = "neg_tampered_s"
    v_neg_s["expected_valid"] = False
    v_neg_s["sig_s"] = _tamper_byte(v_sample["sig_s"], 7)
    vectors.append(v_neg_s)

    v_neg_h = dict(v_sample)
    v_neg_h["name"] = "neg_tampered_hash"
    v_neg_h["expected_valid"] = False
    v_neg_h["hash"] = _tamper_byte(v_sample["hash"], 3)
    vectors.append(v_neg_h)

    # --- Host-side self-verification: sanity-check our transcription ---
    for v in vectors:
        actual = _self_verify(v)
        ok = (actual == v["expected_valid"])
        status = "OK" if ok else "MISMATCH"
        print(f"  {v['name']:<22s} expected_valid={v['expected_valid']}  "
              f"python_ecdsa={actual}  [{status}]")
        if not ok:
            raise SystemExit(
                f"ERROR: host-side self-verify disagrees with expected "
                f"for vector {v['name']!r} — refusing to write JSON."
            )

    out_path = Path(__file__).with_suffix(".json")
    out_path.write_text(json.dumps({"vectors": vectors}, indent=2))
    print(f"\nWrote {len(vectors)} vectors to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
