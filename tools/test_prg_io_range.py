#!/usr/bin/env python3
"""No image may load into the I/O page at $D000-$DFFF (#288).

A KERNAL LOAD (disk, .d64, a real 1541) stores every byte of a PRG with
the CPU, and with the default $01 those stores land in the VIC-II, SID,
colour RAM and both CIAs -- CIA2 drives the IEC bus the drive is loading
over. Only DMA loaders (VICE autostart injection, U64 REST) put such bytes
in the RAM underneath. The UCI images used to carry a zero pad to $DFFF
(OVERLAY_FILE_PAD, which positioned the retired P-384 curve blob at
$E000); this suite fails if anything puts it back.

Two halves, no build needed for the first:

  * cfg: every ``cfg/c64-https-*.cfg`` MEMORY area that overlaps the I/O
    page must be non-file (``file = ""``). ld65's default for an area with
    no ``file`` attribute is the output file, so a missing attribute
    counts as file-backed. This is stricter than the PRG (a file-backed
    area holding only BSS writes nothing) and it covers every profile,
    built or not.
  * PRG: a PRG's load range ($0801 + body length) must end below $D000.
    Standalone, it checks the PRGs named on the command line, or else
    whatever ``build/c64-https.prg`` and ``dist/*.prg`` exist.

The checkers are pure functions with red cases below (a synthetic image
ending at $DFFF, the old pad line), so a checker that stopped seeing the
defect fails here too.

    pytest tools/test_prg_io_range.py
    python3 tools/test_prg_io_range.py [PRG ...]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from _skip_policy import verdict  # noqa: E402

IO_LO, IO_HI = 0xD000, 0xDFFF            # inclusive
CERTIFIES = "no linked image loads into the $D000-$DFFF I/O page (#288)"
# Every profile the Makefile can select links one of these; a rename that
# hid one from the glob would otherwise shrink this suite silently.
UCI_CFGS = ("c64-https-uci.cfg", "c64-https-uci-onchip.cfg",
            "c64-https-uci-onchip-cold.cfg", "c64-https-uci-m3.cfg")

_AREA = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?);", re.M)
_ATTR = re.compile(r"(\w+)\s*=\s*(\"[^\"]*\"|[^,;\s]+)")


def _num(tok: str) -> int:
    tok = tok.strip()
    return int(tok[1:], 16) if tok.startswith("$") else int(tok, 0)


def memory_areas(cfg_text: str) -> list[dict]:
    """The MEMORY block's areas: name, start, size, file (None = absent)."""
    text = re.sub(r"#[^\n]*", "", cfg_text)
    m = re.search(r"\bMEMORY\s*\{(.*?)\}", text, re.S)
    if not m:
        raise ValueError("no MEMORY block")
    out = []
    for name, body in _AREA.findall(m.group(1)):
        attrs = dict(_ATTR.findall(body))
        out.append({"name": name, "start": _num(attrs["start"]),
                    "size": _num(attrs["size"]), "file": attrs.get("file")})
    if not out:
        raise ValueError("MEMORY block has no areas")
    return out


def cfg_io_violations(cfg_text: str) -> list[str]:
    """File-backed MEMORY areas overlapping $D000-$DFFF."""
    bad = []
    for a in memory_areas(cfg_text):
        lo, hi = a["start"], a["start"] + a["size"] - 1
        if a["file"] == '""' or hi < IO_LO or lo > IO_HI:
            continue
        bad.append(f"{a['name']} ${lo:04X}-${hi:04X} file={a['file'] or '(default %O)'}")
    return bad


def prg_range(prg: bytes) -> tuple[int, int]:
    """(first, last) address a PRG loads to, inclusive."""
    if len(prg) < 3:
        raise ValueError(f"PRG is {len(prg)} bytes")
    la = prg[0] | prg[1] << 8
    return la, la + len(prg) - 3


def prg_io_violation(prg: bytes) -> str | None:
    lo, hi = prg_range(prg)
    if hi < IO_LO or lo > IO_HI:
        return None
    return f"loads ${lo:04X}-${hi:04X}, into ${max(lo, IO_LO):04X}-${min(hi, IO_HI):04X}"


def _synthetic(last: int, la: int = 0x0801) -> bytes:
    return bytes([la & 0xFF, la >> 8]) + bytes(last - la + 1)


OLD_PAD = ("MEMORY {\n    CRYPTO_COLD_SHADOW: start = $A000, size = $2000, "
           "file = %O, fill = yes;\n    OVERLAY_FILE_PAD: start = $C000, "
           "size = $2000, file = %O, define = yes, fill = yes, fillval = $00;\n}\n")


# --- pytest ------------------------------------------------------------------
def test_checkers_see_the_defect():
    # red cases: the shape #288 removed, in both halves
    assert prg_io_violation(_synthetic(0xDFFF))           # the old 55,297 B image
    assert prg_io_violation(_synthetic(0xD000))           # one byte in
    assert cfg_io_violations(OLD_PAD) == [
        "OVERLAY_FILE_PAD $C000-$DFFF file=%O"]
    assert cfg_io_violations(OLD_PAD.replace(", file = %O, define", ", define"))
    # green cases at the boundary
    assert prg_io_violation(_synthetic(0xBFFF)) is None    # onchip, 47,105 B
    assert prg_io_violation(_synthetic(0xCFFF)) is None    # comb, 51,201 B
    assert len(_synthetic(0xBFFF)) == 47105 and len(_synthetic(0xCFFF)) == 51201
    assert cfg_io_violations(OLD_PAD.replace("file = %O, define", 'file = "", define')) == []


def test_no_cfg_area_reaches_the_io_page():
    cfgs = sorted((REPO / "cfg").glob("c64-https-*.cfg"))
    names = {p.name for p in cfgs}
    assert set(UCI_CFGS) <= names, f"missing: {set(UCI_CFGS) - names}"
    checked = 0
    for p in cfgs:
        bad = cfg_io_violations(p.read_text())
        assert not bad, f"{p.name}: {bad}"
        checked += 1
    assert checked >= len(UCI_CFGS) + 1                   # + ip65


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

    for fn in (test_checkers_see_the_defect, test_no_cfg_area_reaches_the_io_page):
        try:
            fn()
            check(True, fn.__name__)
        except AssertionError as e:
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
