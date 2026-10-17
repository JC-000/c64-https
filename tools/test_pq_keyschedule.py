#!/usr/bin/env python3
"""test_pq_keyschedule.py - the PQ_HYBRID hybrid key schedule (PQC phase P5).

A VICE boot of the BACKEND=uci USE_NISTCURVES_ONCHIP=1 PQ_HYBRID=1 image. Each
case plants tls_shared_secret (X25519), tls_mlkem_ss, tls_kex_group and a
transcript hash, runs tls_derive_handshake_keys, and compares everything it
leaves behind against a HOST reference (hashlib/hmac HKDF, tools/pq_keylog_check
.handshake_secrets' schedule) computed from the same inputs:

  [1] group $EC: IKM = mlkem_ss || x25519_ss (64 B, ML-KEM first). The
      handshake secret, both handshake traffic secrets and the four traffic
      key/iv buffers equal the host values for that IKM, and differ from the
      classic-IKM and the swapped-order values (so a wrong IKM cannot pass).
  [2] group $1D and group 0: the classic 32 B x25519 IKM, unchanged.
  [3] hygiene: afterwards tls_shared_secret, tls_mlkem_ss, the 64 B IKM
      concatenation in input_buffer are zero, and no 8-byte window of the IKM
      survives in hmac_data_buf (hkdf_extract's copy); nothing past the first
      64 bytes of input_buffer was touched.

    python3 tools/test_pq_keyschedule.py        # builds the PQ image first
    C64_SKIP_BUILD=1 python3 tools/test_pq_keyschedule.py
"""

import hashlib
import random
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _pq_testlib import Tally, Session, build_or_reuse, require_pq_image  # noqa: E402
from _skip_policy import cannot_run, verdict  # noqa: E402
import pq_keylog_check as K  # noqa: E402

RNG = random.Random(0x50355035)
SENT = 0xA5


def rb(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


MK, XS, TH = rb(32), rb(32), rb(32)


def host_schedule(ikm, th):
    """(handshake_secret, c_hs, s_hs, c_key, c_iv, s_key, s_iv)."""
    early = K.hkdf_extract(bytes(32), bytes(32))
    derived = K.expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
    hs = K.hkdf_extract(derived, ikm)
    c = K.expand_label(hs, b"c hs traffic", th, 32)
    s = K.expand_label(hs, b"s hs traffic", th, 32)
    return (hs, c, s, K.expand_label(c, b"key", b"", 32), K.expand_label(c, b"iv", b"", 12),
            K.expand_label(s, b"key", b"", 32), K.expand_label(s, b"iv", b"", 12))


NAMES = ("handshake_secret", "client hs traffic secret", "server hs traffic secret",
         "client write key", "client write iv", "server read key", "server read iv")


def case(s, t, tag, group, ikm):
    s.wr(s.L("tls_kex_group"), [group])
    s.wr(s.L("tls_mlkem_ss"), MK)
    s.wr(s.L("tls_shared_secret"), XS)
    s.wr(s.L("tls_transcript"), TH)
    s.wr(s.L("input_buffer"), bytes([SENT]) * 256)
    s.wr(s.L("hmac_data_buf"), bytes([SENT]) * 97)
    a, p = s.call("tls_derive_handshake_keys")
    t.check(p & 1 == 0, f"{tag}: tls_derive_handshake_keys returns (C=0)", f"P=${p:02X}")
    got = (s.rd(s.L("tls_handshake_secret"), 32), s.rd(s.L("tls_c_hs_secret"), 32),
           s.rd(s.L("tls_s_hs_secret"), 32), s.rd(s.L("tls_hs_write_key"), 32),
           s.rd(s.L("tls_hs_write_iv"), 12), s.rd(s.L("tls_hs_read_key"), 32),
           s.rd(s.L("tls_hs_read_iv"), 12))
    want = host_schedule(ikm, TH)
    for n, g, w in zip(NAMES, got, want):
        t.check(g == w, f"{tag}: {n} == host HKDF over the expected IKM",
                f"got {g[:6].hex()}.. want {w[:6].hex()}..")
    return got


def hygiene(s, t, tag, ikm):
    z = lambda n, addr, ln: t.check(s.rd(s.L(addr), ln) == bytes(ln),   # noqa: E731
                                    f"{tag}: {n} is zero afterwards")
    z("tls_shared_secret (x25519 ss)", "tls_shared_secret", 32)
    z("tls_mlkem_ss", "tls_mlkem_ss", 32)
    z("input_buffer[0:64] (the IKM concatenation)", "input_buffer", 64)
    # Later HKDF calls reuse hmac_data_buf for their (public) info strings, so
    # the copy hkdf_extract made of the IKM is checked by content: no 8-byte
    # window of the IKM survives anywhere in the buffer.
    buf = s.rd(s.L("hmac_data_buf"), 97)
    left = [i for i in range(len(ikm) - 7) if ikm[i:i + 8] in buf]
    t.check(not left, f"{tag}: no 8-byte window of the IKM survives in hmac_data_buf",
            f"windows at IKM offsets {left[:6]}")
    t.check(s.rd(s.L("input_buffer") + 64, 192) == bytes([SENT]) * 192,
            f"{tag}: input_buffer past the 64 B is untouched")


def main():
    t = Tally()
    if shutil.which("ca65") is None:
        return cannot_run("cc65 not found", certifies="the PQ hybrid key schedule")
    rc, out = build_or_reuse()
    if rc != 0:
        print(out[-1500:])
        return cannot_run("the PQ_HYBRID build failed", certifies="the PQ hybrid key schedule")
    why = require_pq_image()
    if why:
        return cannot_run(why, certifies="the PQ hybrid key schedule")
    classic = host_schedule(XS, TH)
    swapped = host_schedule(XS + MK, TH)
    hyb = host_schedule(MK + XS, TH)
    t.check(hyb[0] != classic[0] and hyb[0] != swapped[0] and classic[0] != swapped[0],
            "host references: hybrid, classic and swapped-order handshake secrets all differ")
    with Session() as s:
        print("\n[1] group $EC: IKM = mlkem_ss || x25519_ss")
        case(s, t, "EC", 0xEC, MK + XS)
        hygiene(s, t, "EC", MK + XS)
        print("\n[2] group $1D and group 0: the classic 32 B IKM")
        case(s, t, "1D", 0x1D, XS)
        hygiene(s, t, "1D", XS)
        case(s, t, "0", 0x00, XS)
        hygiene(s, t, "0", XS)
        print("\n[3] a second hybrid run on the same boot (state does not leak across runs)")
        case(s, t, "EC again", 0xEC, MK + XS)
    print(f"\nRESULTS: {t.passed}/{t.passed + t.failed} passed, {t.failed} failed")
    return verdict(t.passed, t.failed, certifies="the PQ hybrid key schedule")


if __name__ == "__main__":
    sys.exit(main())
