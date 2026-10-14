#!/usr/bin/env python3
"""Red cases for rig_https_m3.py's large-page body oracle (`timed` mode).

The oracle excuses MediaWiki's per-render metadata between the body the
C64 fetched and a host reference fetched just before. These cases pin
that a corruption cannot widen its own excuse (adv-296 rounds 3-4): a
block that breaks a report comment's `<!--` / `-->` or the
wgPageParseReport object's closing `}` must be DIFFERENT, as must an
insertion or deletion just outside a region, a payload hidden inside one
(REGION_SLACK), and the controls around them.

Synthetic pages with the same structure as en.wikipedia.org's, so no
fetched content is committed. No hardware, no build.

    python3 tools/check_m3_oracle.py [path/to/rig_https_m3.py]
    python3 tools/check_m3_oracle.py --mutants

The optional path checks another copy of the rig (an older oracle) with
the same cases. --mutants breaks each rule of the oracle in turn (MUTANTS)
and requires some case to go red on every one. Exit 0 all pass / all
killed, 1 otherwise.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
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
            b"<p><!-- Render ID " + rid + b" --><b>Commodore</b> 64</p>\n"
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
    # adv-296 round 4: each pins one rule (MUTANTS names which)
    yield "7: the object's closing } replaced by 200 B", BODY[:obj_end - 1] + b"q" * 200 + BODY[obj_end:], "DIFFERENT"
    yield "7b: the object's last 60 B, } included, overwritten", BODY[:obj_end - 60] + b"q" * 60 + BODY[obj_end:], "DIFFERENT"
    yield "8: 50 B inserted right after the object's }", BODY[:obj_end] + b"Z" * 50 + BODY[obj_end:], "DIFFERENT"
    yield "9: 6 B deleted right after the object's }", BODY[:obj_end] + BODY[obj_end + 6:], "DIFFERENT"
    val = BODY.index(b",", BODY.index(b"wgBackendResponseTime"))
    yield "10: 'x,yy' inserted at a value's end", BODY[:val] + b"x,yy" + BODY[val:], "DIFFERENT"
    newpp = BODY.index(b"CPU time usage:")
    yield "11: 50 KB inside the NewPP report comment", BODY[:newpp] + b"A" * 50000 + BODY[newpp:], "DIFFERENT"
    rid_end = BODY.index(b" --><b>")
    yield "12: the --> after a Render ID value changed", BODY[:rid_end + 3] + b"!" + BODY[rid_end + 4:], "DIFFERENT"
    opener = BODY.index(b"<!--\nNewPP")
    yield "13: a report comment's <!-- changed", BODY[:opener + 3] + b"!" + BODY[opener + 4:], "DIFFERENT"
    key = BODY.index(b"wgHostname")
    yield "14: a per-render key itself changed", BODY[:key + 9] + b"X" + BODY[key + 10:], "DIFFERENT"


#: (name, rule, old text in rig_https_m3.py, new text). Each must turn
#: some case red.
MUTANTS = [
    ("closer-not-checked", "a region's closing delimiter is unchanged",
     "            bc = to_body(r1 - d_close, r1)\n            if bc is None:\n"
     "                continue\n            b1 = bc + d_close",
     "            b1 = b0 + (r1 - r0)"),
    ("opener-not-checked", "a region's opening delimiter is unchanged",
     "        b0 = to_body(r0, r0 + d_open)\n        if b0 is None:\n            continue",
     "        b0 = to_body(r0 + d_open, r0 + d_open + 1)\n        if b0 is None:\n"
     "            continue\n        b0 -= d_open"),
    ("no-body-extent", "the body extent lies inside the region",
     " and h0 <= b0 and b1 <= h1", ""),
    ("no-ref-extent", "the reference extent lies inside the region",
     "g0 <= r0 and r1 <= g1 and ", ""),
    ("window-120-flat", "a key's window ends at its value",
     "    m = VALUE_END.search(page, at, at + KEY_WINDOW)\n"
     "    return m.start() if m else min(at + KEY_WINDOW, len(page))",
     "    return min(at + KEY_WINDOW, len(page))"),
    ("no-arrow-end", "--> ends a key's window",
     'VALUE_END = re.compile(rb"[,}\\]<\\n]|-->")',
     'VALUE_END = re.compile(rb"[,}\\]<\\n]")'),
    ("no-slack-cap", "a region grows or shrinks by at most REGION_SLACK",
     "        if abs((b1 - b0) - (r1 - r0)) > REGION_SLACK:\n", "        if False:\n"),
]


def load(path: Path):
    sys.path.insert(0, str(RIG.parent))
    spec = importlib.util.spec_from_file_location("rig_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_cases(mod, quiet=False):
    red = []
    for name, body, want in cases():
        got = mod.body_oracle(body, REF)[0]
        if got != want:
            red.append(name)
        if not quiet:
            print("%s %-55s %s%s" % ("PASS" if got == want else "FAIL", name,
                                     got, "" if got == want else " (want %s)" % want))
    return red


def mutants() -> int:
    src = RIG.read_text()
    survivors = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, rule, old, new in MUTANTS:
            if src.count(old) != 1:
                print("BROKEN   %-20s mutant text matches %d times" % (name, src.count(old)))
                survivors += 1
                continue
            path = Path(tmp) / ("rig_%s.py" % name.replace("-", "_"))
            path.write_text(src.replace(old, new))
            red = run_cases(load(path), quiet=True)
            if red:
                print("KILLED   %-20s %-48s by %s" % (name, rule, ", ".join(c.split(":")[0] for c in red)))
            else:
                survivors += 1
                print("SURVIVED %-20s %s" % (name, rule))
    print("\n%d mutants, %d killed" % (len(MUTANTS), len(MUTANTS) - survivors))
    return 1 if survivors else 0


def main(argv) -> int:
    if len(argv) > 1 and argv[1] == "--mutants":
        return mutants()
    rig = Path(argv[1]) if len(argv) > 1 else RIG
    n = len(list(cases()))
    red = run_cases(load(rig))
    print("\n%d/%d passed (%s)" % (n - len(red), n, rig))
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
