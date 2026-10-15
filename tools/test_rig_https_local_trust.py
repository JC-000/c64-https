#!/usr/bin/env python3
"""test_rig_https_local_trust.py - rig trampolines must enter http_get with a trust mode.

The rigs DMA a trampoline that calls http_get directly, so do_https_get's
trust_pre never runs. On a TRUST_STORE=1 build tp_mode is then TP_M_NONE and
cert_pin_check (x509_extract_pubkey's tail call, tls_cert.s) refuses at the
Certificate step (#304). Each trampoline must store TP_M_FIRST into tp_mode
before the jsr http_get when the label exists (tools/uci/_trust_mode.py), and
emit nothing extra on a build without the store.

Covers rig_https_local, _print_body, _live, _wiki and _bad_finished.
No hardware, no build. Run: python3 tools/test_rig_https_local_trust.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "uci"))

import _trust_mode  # noqa: E402
import rig_https_local as rig  # noqa: E402
import rig_https_print_body as print_body  # noqa: E402
import rig_https_live as live  # noqa: E402
import rig_https_wiki as wiki  # noqa: E402
import rig_https_bad_finished as bad  # noqa: E402

TP_M_FIRST = _trust_mode.TP_M_FIRST
LABELS = {
    "http_get": 0x7000, "http_host_ptr": 0x7100, "http_host_len": 0x7102,
    "http_path_ptr": 0x7103, "http_path_len": 0x7105, "http_port": 0x7106,
    "net_init": 0x2000, "tcp_recv_head": 0x7200, "tcp_recv_tail": 0x7202,
    "print_resp_body": 0x7400, "viewer_enter": 0x7500,
}
TP_MODE = 0x7300
KW = dict(routine_addr=0x035F, host_str_addr=0x0337, path_str_addr=0x0357,
          sentinel_addr=0x0334, progress_addr=0x0335, carry_flag_addr=0x0336,
          host_len=4, port=4433)


def _set_globals(mod):
    for k, v in (("ROUTINE_ADDR", 0x035F), ("HOST_STR_ADDR", 0x0337),
                 ("PATH_STR_ADDR", 0x0357), ("SENTINEL_ADDR", 0x0334),
                 ("PROGRESS_ADDR", 0x0335), ("CARRY_FLAG_ADDR", 0x0336)):
        setattr(mod, k, v)


def _builders():
    _set_globals(rig)
    _set_globals(bad)
    return {
        "local": lambda l: rig._build_http_routine(l, 4433)[0],
        "print_body": lambda l: print_body._build_routine(l, 4433)[0],
        "live": lambda l: live.build_live_routine(l, **KW),
        "wiki": lambda l: wiki.build_wiki_routine(l, **KW, path_len=1),
        "bad_finished": lambda l: bad._build_http_routine(l, 4433)[0],
    }


def test_constant_matches_include():
    inc = (ROOT / "src" / "trust_policy.inc").read_text()
    m = re.search(r"^TP_M_FIRST\s*=\s*(\d+)", inc, re.M)
    assert m and int(m.group(1)) == TP_M_FIRST


def test_store_build_sets_mode_before_http_get():
    seq = bytes([0xA9, TP_M_FIRST, 0x8D, TP_MODE & 0xFF, TP_MODE >> 8])
    jsr = bytes([0x20, 0x00, 0x70])
    for name, build in _builders().items():
        code = bytes(build({**LABELS, "tp_mode": TP_MODE}))
        assert seq in code, name
        assert code.index(seq) < code.index(jsr), name


def test_non_store_build_unchanged():
    for name, build in _builders().items():
        plain = bytes(build(dict(LABELS)))
        store = bytes(build({**LABELS, "tp_mode": TP_MODE}))
        assert bytes([TP_MODE & 0xFF, TP_MODE >> 8]) not in plain, name
        assert len(store) == len(plain) + 5, name


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            f()
            print("ok", n)
