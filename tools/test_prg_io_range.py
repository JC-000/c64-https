#!/usr/bin/env python3
"""No image may load into the I/O page at $D000-$DFFF (#288).

A KERNAL LOAD (disk, .d64, a real 1541) stores every byte of a PRG with
the CPU, so bytes at $D000-$DFFF land in the chip registers. The UCI
images used to carry a zero pad to $DFFF (OVERLAY_FILE_PAD, which
positioned the retired P-384 curve blob at $E000); in VICE under true
drive emulation that froze the load with its pointer in CIA1's page
($DC06 and $DC09 observed). The checker is tools/check_prg_io_range.py;
this is its test:

  * cfg: every ``cfg/c64-https-*.cfg`` is run through the checker's
    load map (where each file-backed area LOADS, from file order and
    evaluated sizes), and the three cfg shapes that beat the first
    version of this guard are red cases: a size written as an expression,
    the old pad split over two lines, and a fill area after the last one.
  * PRG: synthetic images at the boundaries. Standalone, it also checks
    the PRGs named on the command line, or build/ and dist/ ones.

The Makefile checks every linked PRG's range after ld65, and
make package-verify checks every dist/*.prg.

    pytest tools/test_prg_io_range.py
    python3 tools/test_prg_io_range.py [PRG ...]
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from _skip_policy import verdict  # noqa: E402
from check_prg_io_range import (  # noqa: E402
    CfgError, cfg_io_violations, load_map, prg_io_violation, prg_range,
)

CERTIFIES = "no linked image loads into the $D000-$DFFF I/O page (#288)"
# Every profile the Makefile can select links one of these; a rename that
# hid one from the glob would otherwise shrink this suite silently.
CFGS = ("c64-https-ip65.cfg", "c64-https-uci.cfg", "c64-https-uci-onchip.cfg",
        "c64-https-uci-onchip-cold.cfg", "c64-https-uci-m3.cfg")
# Where each real cfg's file bytes end (the linked PRGs end there too).
LOAD_END = {"c64-https-ip65.cfg": 0xBFFF, "c64-https-uci.cfg": 0xBFFF,
            "c64-https-uci-onchip.cfg": 0xBFFF,
            "c64-https-uci-onchip-cold.cfg": 0xCFFF,
            "c64-https-uci-m3.cfg": 0x9FFF}

ANCHOR = "    X25519_SCRATCH:     start = $A000, size = $0224, type = rw, define = yes;\n"
MUTANTS = {
    # (a) the old pad, its size an expression: relinks the 55,297 B image
    "size expression": ANCHOR + "    OVERLAY_FILE_PAD: start = $C000, "
        "size = $1000 + $1000, file = %O, define = yes, fill = yes, fillval = $00;\n",
    # (b) the old pad split over two lines
    "split over lines": ANCHOR + "    OVERLAY_FILE_PAD: start = $C000, size = $2000,\n"
        "        file = %O, define = yes, fill = yes, fillval = $00;\n",
    # (c) a fill area after the last one, STARTING above I/O: its bytes
    # follow $BFFF in the file, so they load at $C000-$D0FF
    "fill after the last area": ANCHOR + "    HIGHPAD: start = $E000, "
        "size = $1100, file = %O, fill = yes;\n",
}


def _uci_cfg() -> str:
    text = (REPO / "cfg" / "c64-https-uci.cfg").read_text()
    assert text.count(ANCHOR) == 1, "mutation anchor moved: re-derive it"
    return text


def _synthetic(last: int, la: int = 0x0801) -> bytes:
    return bytes([la & 0xFF, la >> 8]) + bytes(last - la + 1)


# --- pytest ------------------------------------------------------------------
def test_cfg_mutants_are_red():
    base = _uci_cfg()
    for name, repl in MUTANTS.items():
        bad = cfg_io_violations(base.replace(ANCHOR, repl))
        assert bad, f"mutant {name!r} passed the cfg check"
    assert "$C000-$DFFF" in cfg_io_violations(
        base.replace(ANCHOR, MUTANTS["size expression"]))[0]
    assert "$C000-$D0FF" in cfg_io_violations(
        base.replace(ANCHOR, MUTANTS["fill after the last area"]))[0]


def test_cfg_check_fails_closed():
    base = _uci_cfg()
    for broken in (ANCHOR + "    PAD: start = $C000, size = PADLEN, fill = yes;\n",
                   ANCHOR + "    PAD start = $C000, size = $10;\n",
                   ANCHOR + "    PAD: start = $C000, fill = yes;\n"):
        try:
            cfg_io_violations(base.replace(ANCHOR, broken))
        except CfgError:
            continue
        raise AssertionError(f"unparseable area accepted: {broken.strip()!r}")


def test_prg_checker_sees_the_defect():
    assert prg_io_violation(_synthetic(0xDFFF))           # the old 55,297 B image
    assert prg_io_violation(_synthetic(0xD000))           # one byte in
    assert prg_io_violation(_synthetic(0xBFFF)) is None    # 47,105 B
    assert prg_io_violation(_synthetic(0xCFFF)) is None    # comb cold bank, 51,201 B
    assert len(_synthetic(0xBFFF)) == 47105 and len(_synthetic(0xCFFF)) == 51201


def test_no_cfg_loads_into_the_io_page():
    checked = 0
    for name in CFGS:
        text = (REPO / "cfg" / name).read_text()
        assert not cfg_io_violations(text), f"{name}: {cfg_io_violations(text)}"
        assert load_map(text)[-1]["hi"] == LOAD_END[name], name
        checked += 1
    assert checked == len(CFGS)
    others = {p.name for p in (REPO / "cfg").glob("c64-https-*.cfg")} - set(CFGS)
    assert not others, f"unlisted cfgs (add them to CFGS): {sorted(others)}"


# --- standalone --------------------------------------------------------------
def main(argv: list[str]) -> int:
    passed = failed = 0

    def check(ok: bool, msg: str) -> None:
        nonlocal passed, failed
        print(("  PASS  " if ok else "  FAIL  ") + msg)
        if ok:
            passed += 1
        else:
            failed += 1

    for fn in (test_cfg_mutants_are_red, test_cfg_check_fails_closed,
               test_prg_checker_sees_the_defect, test_no_cfg_loads_into_the_io_page):
        try:
            fn()
            check(True, fn.__name__)
        except (AssertionError, CfgError) as e:
            check(False, f"{fn.__name__}: {e}")

    prgs = [Path(a) for a in argv] or [
        p for p in [REPO / "build" / "c64-https.prg",
                    *sorted((REPO / "dist").glob("*.prg"))] if p.is_file()]
    for p in prgs:
        data = p.read_bytes()
        bad = prg_io_violation(data)
        lo, hi = prg_range(data)
        check(bad is None, f"{p}: {len(data)} B, ${lo:04X}-${hi:04X}"
                           + (f" -- {bad}" if bad else ""))
    if not prgs:
        print("  (no PRG named or built: the cfg half above is the check)")
    return verdict(passed, failed, certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
