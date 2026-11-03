"""handoff_checks.py - the verdicts of tools/uci/rig_https_handoff.py.

Pure functions over the bytes the rig reads back (mailbox, response head,
body prefix, the stand-in host's bank-check count), so every check has a
hardware-free red case in tools/test_handoff_checks_unit.py. The layout is
read from src/handoff.inc, never restated here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

INC = Path(__file__).resolve().parents[1] / "src" / "handoff.inc"


def load_layout(path: Path = INC) -> dict[str, int]:
    """src/handoff.inc's `HO_NAME = value` lines (the normative layout)."""
    vals: dict[str, int] = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^(HO_\w+)\s*=\s*([^;]+)", line)
        if m:
            vals[m.group(1)] = eval(m.group(2).strip().replace("$", "0x"),
                                    {}, dict(vals))
    return vals


L = load_layout()


def u(buf: bytes, off: int, n: int) -> int:
    return int.from_bytes(buf[off:off + n], "little")


@dataclass
class Reply:
    state: int
    result: int
    http: int
    body_len: int
    body_total: int
    flags: int
    hdr_len: int
    net_err: int
    trust: int
    magic_ok: bool

    @classmethod
    def parse(cls, mailbox: bytes) -> "Reply":
        return cls(state=mailbox[L["HO_O_STATE"]],
                   result=mailbox[L["HO_O_RESULT"]],
                   http=u(mailbox, L["HO_O_HTTP"], 2),
                   body_len=u(mailbox, L["HO_O_BODY_LEN"], 3),
                   body_total=u(mailbox, L["HO_O_BODY_TOTAL"], 3),
                   flags=mailbox[L["HO_O_FLAGS"]],
                   hdr_len=u(mailbox, L["HO_O_HDR_LEN"], 2),
                   net_err=mailbox[L["HO_O_NET_ERR"]],
                   trust=mailbox[L["HO_O_TRUST"]],
                   magic_ok=mailbox[:8] == b"C64HTTPS")

    def summary(self) -> str:
        return (f"state=${self.state:02X} result={self.result} http={self.http} "
                f"body={self.body_len}/{self.body_total} flags=${self.flags:02X} "
                f"head={self.hdr_len} net_err=${self.net_err:02X} "
                f"trust=${self.trust:02X}")


@dataclass
class Head:
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    complete: bool = False          # ends with the blank line

    @property
    def framing(self) -> tuple[str, int | None]:
        if "content-length" in self.headers:
            try:
                return ("length", int(self.headers["content-length"]))
            except ValueError:
                return ("bad-length", None)
        if "chunked" in self.headers.get("transfer-encoding", "").lower():
            return ("chunked", None)
        return ("close", None)


def parse_head(raw: bytes) -> Head:
    text = raw.decode("latin-1")
    complete = "\r\n\r\n" in text or "\n\n" in text
    lines = text.replace("\r\n", "\n").split("\n")
    m = re.match(r"HTTP/\d\.\d (\d{3})", lines[0] if lines else "")
    head = Head(status=int(m.group(1)) if m else None, complete=complete)
    for line in lines[1:]:
        if not line:
            break
        name, sep, value = line.partition(":")
        if sep:
            head.headers[name.strip().lower()] = value.strip()
    return head


@dataclass
class Check:
    ok: bool
    what: str


def check_handoff(*, mailbox: bytes, head_raw: bytes, body_prefix: bytes,
                  bank_errors: int, expect_result: int = 0,
                  expect_status: int | None = None,
                  expect_body_prefix: bytes | None = None) -> list[Check]:
    """Every verdict of one run. `head_raw` and `body_prefix` are what the
    stand-in host copied (4 KB / 16 KB); only their stored lengths count."""
    r = Reply.parse(mailbox)
    out = [
        Check(r.magic_ok, "mailbox magic intact"),
        Check(r.state == L["HO_ST_DONE"],
              f"mailbox state DONE (got ${r.state:02X})"),
        Check(bank_errors == 0,
              f"REU banks 0-7 (the host's) unchanged ({bank_errors} bytes differ)"),
        Check(r.result == expect_result,
              f"result {expect_result} (got {r.result}; {r.summary()})"),
    ]
    if expect_result != L["HO_R_OK"] or r.result != L["HO_R_OK"]:
        return out
    head = parse_head(head_raw[:min(r.hdr_len, len(head_raw))])
    kind, length = head.framing
    out += [
        Check(bool(r.flags & L["HO_F_HANDSHAKE"]), "flag: handshake completed"),
        Check(bool(r.flags & L["HO_F_COMPLETE"]), "flag: body complete"),
        Check(not r.flags & L["HO_F_SINK_FULL"], "flag: body fitted the REU"),
        Check(not r.flags & L["HO_F_HDR_TRUNC"] and head.complete,
              "response head stored whole (ends with the blank line)"),
        Check(head.status is not None and head.status == r.http,
              f"reply HTTP status {r.http} = the stored status line's "
              f"({head.status})"),
        Check(r.body_len == r.body_total,
              f"every received body byte stored ({r.body_len}/{r.body_total})"),
        Check(kind in ("length", "chunked"),
              f"framing says when the body ends ({kind})"),
    ]
    if kind == "length":
        out.append(Check(r.body_total == length,
                         f"body = Content-Length ({r.body_total} vs {length})"))
    if expect_status is not None:
        out.append(Check(r.http == expect_status,
                         f"HTTP {expect_status} (got {r.http})"))
    if expect_body_prefix is not None:
        n = min(len(expect_body_prefix), r.body_len, len(body_prefix))
        out.append(Check(n == min(len(expect_body_prefix), r.body_len)
                         and body_prefix[:n] == expect_body_prefix[:n],
                         f"body starts with the expected {n} bytes"))
    return out
