#!/usr/bin/env python3
"""test_rig_https_local_trust.py - rig_https_local must enter http_get with a trust mode.

rig_https_local DMAs a trampoline that calls http_get directly, so
do_https_get's trust_pre never runs. On a TRUST_STORE=1 build tp_mode is then
TP_M_NONE and the cert_pin hook refuses the client Finished (#301). The
trampoline must store TP_M_FIRST into tp_mode before the jsr, when the label
exists, and must emit nothing extra on a build without the store.

No hardware, no build. Run: python3 tools/test_rig_https_local_trust.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "uci"))

import rig_https_local as rig  # noqa: E402

LABELS = {
    "http_get": 0x7000, "http_host_ptr": 0x7100, "http_host_len": 0x7102,
    "http_path_ptr": 0x7103, "http_path_len": 0x7105, "http_port": 0x7106,
    "net_init": 0x2000, "tcp_recv_head": 0x7200, "tcp_recv_tail": 0x7202,
}
TP_MODE = 0x7300


def _routine(labels):
    rig.ROUTINE_ADDR, rig.HOST_STR_ADDR, rig.PATH_STR_ADDR = 0x035F, 0x0337, 0x0357
    rig.SENTINEL_ADDR, rig.PROGRESS_ADDR, rig.CARRY_FLAG_ADDR = 0x0334, 0x0335, 0x0336
    code, _ = rig._build_http_routine(labels, 4433)
    return code


def test_constant_matches_include():
    inc = (ROOT / "src" / "trust_policy.inc").read_text()
    m = re.search(r"^TP_M_FIRST\s*=\s*(\d+)", inc, re.M)
    assert m and int(m.group(1)) == rig.TP_M_FIRST


def test_store_build_sets_mode_before_http_get():
    code = _routine({**LABELS, "tp_mode": TP_MODE})
    seq = bytes([0xA9, rig.TP_M_FIRST, 0x8D, TP_MODE & 0xFF, TP_MODE >> 8])
    jsr = bytes([0x20, 0x00, 0x70])
    assert seq in code and jsr in code
    assert code.index(seq) < code.index(jsr)


def test_non_store_build_unchanged():
    code = _routine(LABELS)
    assert bytes([TP_MODE & 0xFF, TP_MODE >> 8]) not in code
    assert len(_routine({**LABELS, "tp_mode": TP_MODE})) == len(code) + 5


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            f()
            print("ok", n)
