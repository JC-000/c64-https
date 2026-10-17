#!/usr/bin/env python3
"""tools/test_pq_keylog_check.py - the hardware oracle can go RED.

tools/pq_keylog_check.py decides whether the C64's Decaps agreed with an
OpenSSL server's Encaps by reproducing the server's handshake traffic secrets
from the C64's memory. A verdict that cannot fail proves nothing (the #210
lesson), so every input is flipped here and the verdict must change, the HKDF
is checked against the repo's own independent reference, and the sentinel gate
(a run that never reached Decaps must be INCONCLUSIVE, never a pass or a
mismatch) is exercised arm by arm. No VICE, no hardware.

    pytest tools/test_pq_keylog_check.py
    python3 tools/test_pq_keylog_check.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import pq_keylog_check as K  # noqa: E402

RND = bytes(range(32))
MK, XS = bytes(range(100, 132)), bytes(range(200, 232))
TH = hashlib.sha256(b"ch||sh").digest()


def _log(ikm=MK + XS, th=TH, rnd=RND):
    c, s = K.handshake_secrets(ikm, th)
    return (f"SERVER_HANDSHAKE_TRAFFIC_SECRET {rnd.hex()} {s.hex()}\n"
            f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {rnd.hex()} {c.hex()}\n")


def _state(**over):
    st = {"tls_mlkem_ss": MK.hex(), "tls_shared_secret": XS.hex(),
          "tls_transcript": TH.hex(), "tls_client_random": RND.hex(),
          "tls_kex_group": "ec", "tls_sh_err": "00", "tls_state": "ff",
          "tls_last_state": "03", "tls_pq_seed": "00" * 64}
    st.update(over)
    return st


def test_schedule_matches_the_repo_reference():
    import test_tls_handshake as TH_
    early = TH_.hkdf_extract_ref(bytes(32), bytes(32))
    derived = TH_.derive_secret_ref(early, b"derived", hashlib.sha256(b"").digest())
    hs = TH_.hkdf_extract_ref(derived, MK + XS)
    c, s = K.handshake_secrets(MK + XS, TH)
    assert s == TH_.hkdf_expand_label_ref(hs, b"s hs traffic", TH, 32)
    assert c == TH_.hkdf_expand_label_ref(hs, b"c hs traffic", TH, 32)


def test_green_control():
    assert K.check(_log(), RND, MK, XS, TH)[0] is True


def test_every_input_is_load_bearing():
    flip = lambda b, i: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]    # noqa: E731
    for i in (0, 15, 31):
        assert K.check(_log(), RND, flip(MK, i), XS, TH)[0] is False
        assert K.check(_log(), RND, MK, flip(XS, i), TH)[0] is False
        assert K.check(_log(), RND, MK, XS, flip(TH, i))[0] is False


def test_concatenation_order_is_named():
    r, msg = K.check(_log(), RND, XS, MK, TH)
    assert r is False and "swapped" in msg
    r, msg = K.check(_log(MK + XS), RND, MK, XS, TH)
    assert r is True


def test_a_classic_only_server_is_named():
    r, msg = K.check(_log(ikm=XS), RND, MK, XS, TH)
    assert r is False and "did not run the hybrid" in msg


def test_a_keylog_without_the_run_is_a_usage_error():
    assert K.check(_log(), bytes(31) + b"\x01", MK, XS, TH)[0] is None


def test_state_mode_green_and_red():
    assert K.check_state(_state(), _log())[0] is True
    assert K.check_state(_state(tls_mlkem_ss=bytes(range(32)).hex()), _log())[0] is False


def test_the_sentinel_gate_never_gives_a_verdict_from_unreached_memory():
    cases = [dict(tls_kex_group="1d"), dict(tls_sh_err="07"),
             dict(tls_last_state="01", tls_state="01"),
             dict(tls_pq_seed="11" * 64), dict(tls_mlkem_ss="00" * 32),
             dict(tls_shared_secret="00" * 32), dict(tls_transcript="00" * 32)]
    for over in cases:
        assert K.check_state(_state(**over), _log())[0] == "inconclusive", over


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    from _skip_policy import verdict
    return verdict(len(tests) - failed, failed,
                   certifies="the PQ hardware oracle")


if __name__ == "__main__":
    sys.exit(main())
