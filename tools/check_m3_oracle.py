#!/usr/bin/env python3
"""Red cases for rig_https_m3.py's large-page body oracle (`timed` mode).

The oracle excuses MediaWiki's per-render metadata between the body the
C64 fetched and a host reference fetched just before. These cases pin
that a corruption cannot widen its own excuse (adv-296 round 3): a block
that breaks a report comment's `-->` or the wgPageParseReport object's
closing `}` must be DIFFERENT, and so must the controls around them.

Synthetic pages with the same structure as en.wikipedia.org's, so no
fetched content is committed. No hardware, no build.

    python3 tools/check_m3_oracle.py [path/to/rig_https_m3.py]

The optional path checks another copy of the rig (an older oracle) with
the same cases. Exit 0 all pass, 1 any fail.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

RIG = Path(__file__).resolve().parent / "uci" / "rig_https_m3.py"

ARTICLE = b" ".join(b"Commodore 64 paragraph %d: the C64 is an 8-bit home "
                    b"computer introduced in 1982." % i for i in range(40))


def page(rid, ms, host, cpu, wall, ts, pct, gen):
    return (b"<!DOCTYPE html>\n<html><head>\n<script>RLCONF={\"wgRequestId\":\""
            + rid + b"\",\"wgBackendResponseTime\":" + ms + b",\"wgHostname\":\""
            + host + b"\",\"wgPageParseReport\":{\"limitreport\":{\"cputime\":\""
            + cpu + b"\",\"walltime\":\"" + wall + b"\"},\"cachereport\":{"
            b"\"timestamp\":\"" + ts + b"\",\"ttl\":86400}},\"wgCategories\":["
            + CATEGORIES + b"]};</script>\n"
            b"</head><body>\n<p>" + ARTICLE + b"</p>\n<p>" + ARTICLE
            + b"</p>\n<!--\nNewPP limit report\nCPU time usage: " + cpu
            + b" seconds\nReal time usage: " + wall + b" seconds\n-->\n"
            b"<!--\nTransclusion expansion time report (%,ms,calls,template)\n"
            + pct + b"      1 -total\n-->\n\n<!-- Parsoid 0.24.0.0 -->\n"
            b"</div><!--\nPost-processing cache key enwiki:x, generated at "
            + gen + b"\n--><script>(RLQ=window.RLQ||[]).push(1);</script>\n"
            b"</body></html>")


CATEGORIES = b",".join(b"\"Home computer category %d\"" % i for i in range(30))

REF = page(b"4428ca7e-172e-424e-b439-7cf1d498867f", b"155", b"mw-web.codfw.a",
           b"3.374", b"3.647", b"20261014002700", b"100.00% 2710.452",
           b"20261014002701")
BODY = page(b"9f1c22aa-0b3d-4e11-8c0d-2a7e55e1c9b0", b"4302", b"mw-web.eqiad.b",
            b"3.101", b"3.388", b"20261013120001", b"100.00% 2533.019",
            b"20261013120002")


def flip(b, lo, hi):
    """XOR 0x20 over [lo, hi), newlines kept (the line structure survives)."""
    return b[:lo] + bytes(c if c == 10 else c ^ 0x20 for c in b[lo:hi]) + b[hi:]


def cases():
    obj_end = BODY.index(b"}},\"wgCategories") + 2  # the report object's }
    c3 = BODY.index(b"-->", BODY.index(b"Transclusion")) + 3
    gap = BODY.index(b"<!--\nPost")             # end of the gap after c3
    cat = BODY.index(b"wgCategories") + 400      # config, far from any key
    art = BODY.index(b"paragraph 30")
    eof = len(BODY)
    yield "two renders of one revision", BODY, "metadata-only"
    yield "identical", REF, "equal"
    yield "1a: tail only, after the report object", flip(BODY, obj_end + 5, obj_end + 40), "DIFFERENT"
    yield "1b: block across the report object's closing }", flip(BODY, obj_end - 30, obj_end + 40), "DIFFERENT"
    yield "1c: from inside the report object to EOF", flip(BODY, obj_end - 30, eof), "DIFFERENT"
    yield "2a: the gap after a report comment only", flip(BODY, c3 + 1, gap - 1), "DIFFERENT"
    yield "2b: from inside a comment across its --> into the gap", flip(BODY, c3 - 12, gap - 1), "DIFFERENT"
    yield "3: one bit, article text far past a key", BODY[:art] + bytes([BODY[art] ^ 1]) + BODY[art + 1:], "DIFFERENT"
    yield "4: one bit on a key's line, 400 B past it", BODY[:cat] + bytes([BODY[cat] ^ 1]) + BODY[cat + 1:], "DIFFERENT"
    yield "5: truncated before </body>", BODY[:-40], "DIFFERENT"
    drop = BODY.index(b"<p>", BODY.index(b"</p>"))
    yield "6: an article line dropped", BODY[:drop] + BODY[BODY.index(b"\n", drop) + 1:], "DIFFERENT"


def main(argv) -> int:
    rig = Path(argv[1]) if len(argv) > 1 else RIG
    sys.path.insert(0, str(RIG.parent))
    spec = importlib.util.spec_from_file_location("rig_under_test", rig)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fails = 0
    for name, body, want in cases():
        got = mod.body_oracle(body, REF)[0]
        ok = got == want
        fails += not ok
        print("%s %-55s %s%s" % ("PASS" if ok else "FAIL", name, got,
                                 "" if ok else " (want %s)" % want))
    print("\n%d/%d passed (%s)" % (len(list(cases())) - fails, len(list(cases())), rig))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
