"""Unit tests for tools/handoff_checks.py: one red case per verdict.

No hardware, no VICE: the rig's verdicts are pure functions over the bytes
it reads back, so each is driven here with a good run and one broken field.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_checks as hc  # noqa: E402

L = hc.L
BODY = b"<html>" + b"x" * 300 + b"</html>"
HEAD = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        b"Content-Length: %d\r\n\r\n" % len(BODY))


def mailbox(**kw) -> bytes:
    f = dict(state=L["HO_ST_DONE"], result=0, http=200, body_len=len(BODY),
             body_total=len(BODY),
             flags=L["HO_F_COMPLETE"] | L["HO_F_HANDSHAKE"],
             hdr_len=len(HEAD), magic=b"C64HTTPS")
    f.update(kw)
    m = bytearray(0x200)
    m[0:8] = f["magic"]
    m[L["HO_O_STATE"]] = f["state"]
    m[L["HO_O_RESULT"]] = f["result"]
    for name, off, n in (("http", "HO_O_HTTP", 2), ("body_len", "HO_O_BODY_LEN", 3),
                         ("body_total", "HO_O_BODY_TOTAL", 3),
                         ("hdr_len", "HO_O_HDR_LEN", 2)):
        m[L[off]:L[off] + n] = f[name].to_bytes(n, "little")
    m[L["HO_O_FLAGS"]] = f["flags"]
    return bytes(m)


def run(mb=None, head=HEAD, body=BODY, errs=0, **kw):
    checks = hc.check_handoff(mailbox=mb or mailbox(), head_raw=head,
                              body_prefix=body, bank_errors=errs, **kw)
    return [c for c in checks if not c.ok], checks


def red(fails, word):
    assert any(word in c.what for c in fails), [c.what for c in fails]


def test_a_good_run_passes_every_check():
    fails, checks = run(expect_status=200, expect_body_prefix=BODY[:64])
    assert not fails, [c.what for c in fails]
    assert len(checks) >= 13


def test_bad_magic():
    red(run(mailbox(magic=b"XXXXXXXX"))[0], "magic")


def test_state_not_done():
    red(run(mailbox(state=L["HO_ST_RUNNING"]))[0], "state DONE")


def test_ram_drive_damaged():
    red(run(errs=1)[0], "banks 0-7")


def test_wrong_result():
    red(run(mailbox(result=L["HO_R_TLS"]))[0], "result 0")


def test_expected_failure_code_is_a_pass_and_skips_the_body_checks():
    fails, checks = run(mailbox(result=L["HO_R_DNS"]),
                        expect_result=L["HO_R_DNS"])
    assert not fails and len(checks) == 4


def test_no_handshake_flag():
    red(run(mailbox(flags=L["HO_F_COMPLETE"]))[0], "handshake")


def test_not_complete():
    red(run(mailbox(flags=L["HO_F_HANDSHAKE"]))[0], "body complete")


def test_sink_full():
    red(run(mailbox(flags=L["HO_F_COMPLETE"] | L["HO_F_HANDSHAKE"]
                    | L["HO_F_SINK_FULL"]))[0], "fitted")


def test_head_cut():
    red(run(head=HEAD[:-4], mb=mailbox(hdr_len=len(HEAD) - 4))[0], "head stored whole")


def test_status_mismatch():
    red(run(mailbox(http=404))[0], "stored status line")


def test_body_bytes_lost():
    red(run(mailbox(body_len=len(BODY) - 1))[0], "every received")


def test_unframed_body():
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    red(run(head=head, mb=mailbox(hdr_len=len(head)))[0], "framing")


def test_short_of_content_length():
    n = len(BODY) - 10
    red(run(mailbox(body_len=n, body_total=n))[0], "Content-Length")


def test_expected_status():
    red(run(expect_status=301)[0], "HTTP 301")


def test_expected_body_prefix():
    red(run(expect_body_prefix=b"<HTML>")[0], "body starts")


def test_chunked_is_framed():
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    fails, _ = run(head=head, mb=mailbox(hdr_len=len(head)))
    assert not fails, [c.what for c in fails]
