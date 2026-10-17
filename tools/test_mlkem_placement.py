#!/usr/bin/env python3
"""PQ_HYBRID=1 placement guard (libs/mlkem, PQC plan phase P0).

Nothing calls ML-KEM yet, so nothing at runtime can notice it landed on top
of something live. The whole proof is link-time, in src/crypto/mlkem_link.s
and the cfgs' MLKEM_*_RAM areas. This suite proves the proof:

  [1] cfg shape (no build): the three uci cfgs carry the three areas with
      the exact addresses, every MEMORY area is `define = yes`, and every
      area has an sqtab-window guard in mlkem_link.s (or is the one
      documented exemption). A synthetic extra area is a red case: this is
      the half of the sqtab rule ld65 cannot enforce for us.
  [2] the knob matrix (make -n): allowed on uci onchip/comb, refused with
      its own message on ip65, uci-m3, the uci REU profile and a bad value.
  [3] green controls: uci-onchip and both comb cfgs LINK with PQ_HYBRID=1,
      and the map holds the layout the asserts describe (nothing but
      LIB_MLKEM_BSS, X25519_TABLES and TABLES_BSS in $B100-$BFFF; the
      code at $E000 and the polys at $D000; the PRG still ends below $D000).
  [4] mutations: each assert that guards a number is broken in turn and the
      link must fail with THAT assert's text. A mutant that does not fail,
      or fails with a different message, is a FAIL: the assert was not what
      stopped it. Every mutated file is restored in a finally block and the
      control re-linked at the end.

The build steps run `make` in this checkout and overwrite build/. ~6 min.

    python3 tools/test_mlkem_placement.py          # everything
    python3 tools/test_mlkem_placement.py --static # [1] and [2] only
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "tools" / "uci"))
from _skip_policy import cannot_run, verdict  # noqa: E402
from check_prg_io_range import prg_io_violation  # noqa: E402

CFGS = {
    "c64-https-uci.cfg": False,             # uci-onchip (and the REU profile)
    "c64-https-uci-onchip.cfg": False,      # comb, COLD_BANK=0
    "c64-https-uci-onchip-cold.cfg": True,  # comb (cold bank)
}
LINK_S = REPO / "src" / "crypto" / "mlkem_link.s"
# The one area that CONTAINS the sqtab window by design: the window is
# c64-https's own table (TABLES_BSS). mlkem_link.s asserts the equivalent.
EXEMPT = {"CRYPTO_COLD_SHADOW", "COLD_FILE"}
EXPECT_AREAS = {
    "MLKEM_CODE_RAM": ("$E000", "$1E00"),
    "MLKEM_BSS_RAM": ("$B100", "$0B00"),
    "MLKEM_POLY_RAM": ("$D000", "$1000"),
}

AREA_RE = re.compile(r"^\s*([A-Z0-9_]+):\s*(start\s*=.*?);", re.M)


class Tally:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
            print(f"  PASS  {what}")
        else:
            self.failed += 1
            print(f"  FAIL  {what}" + (f": {detail}" if detail else ""))
        return ok


def memory_areas(cfg_text):
    """{name: attribute-string} for the MEMORY block (comments stripped)."""
    body = re.search(r"^MEMORY\s*\{(.*?)^\}", cfg_text, re.M | re.S).group(1)
    body = "\n".join(ln.split("#")[0] for ln in body.splitlines())
    return {m.group(1): m.group(2) for m in AREA_RE.finditer(body)}


def guarded_areas(link_text=None):
    link_text = link_text if link_text is not None else LINK_S.read_text()
    return set(re.findall(r'^SQTAB_GUARD\s+"([A-Z0-9_]+)"', link_text, re.M))


def unguarded(cfg_text, cold, link_text=None):
    """Areas of *cfg_text* with neither a guard nor the exemption."""
    guards = guarded_areas(link_text)
    out = []
    for name in memory_areas(cfg_text):
        if name in EXEMPT or name in guards:
            continue
        out.append(name)
    return out


def no_define(cfg_text):
    return [n for n, a in memory_areas(cfg_text).items()
            if not re.search(r"define\s*=\s*yes", a)]


ENTRY_RE = re.compile(r"\bmlkem_(keygen|encaps|decaps|decaps_seed|arith_init)\b")


def unwrapped_callers(extra=None):
    """Source files other than mlkem_link.s that name a library entry."""
    files = {str(p.relative_to(REPO)): p.read_text()
             for p in (REPO / "src").rglob("*.s")
             if p.name != "mlkem_link.s"}
    files.update(extra or {})
    return sorted(f for f, txt in files.items() if ENTRY_RE.search(txt))


EXPORT_RE = re.compile(r"(\S+)\s+([0-9A-F]{6})\s+[RL][EL]?[A-Z]?(?:\s|$)")


def rom_shadowed_symbols(map_path):
    """Names the linker puts in $E000-$FDFF (the ML-KEM run image), from the
    map's Exports list - not a name regex, so a library addition is covered.
    Nothing is exempt by prefix: __LIB_MLKEM_CODE_RUN__ is a way in too.

    Known gaps, accepted: a literal address (`jsr $E123`) and symbol
    arithmetic on a non-banned symbol (`__LIB_MLKEM_CODE_LOAD__+$4000`) name
    no banned symbol; the Imports check below closes the spellings the source
    scan misses (`.ident(.concat(...))`, a ';' inside a string)."""
    text = Path(map_path).read_text()
    sec = text.split("Exports list by name:")[1].split("Imports list")[0]
    out = {}
    for name, addr in EXPORT_RE.findall(sec):
        a = int(addr, 16)
        if 0xE000 <= a <= 0xFDFF:
            out[name] = a
    return out


def map_importers(map_path):
    """{symbol: {importing module.o}} from the ld65 map's Imports list."""
    text = Path(map_path).read_text()
    sec = text.split("Imports list:")[1].split("Exports list")[0] \
        if "Exports list" in text.split("Imports list:")[1] else text.split("Imports list:")[1]
    out, cur = {}, None
    for ln in sec.splitlines():
        m = re.match(r"^(\S+) \(\S+\):\s*$", ln)
        if m:
            cur = m.group(1)
            out.setdefault(cur, set())
        elif cur and ln.startswith("    "):
            out[cur].add(ln.split()[0])
    return out


def library_members():
    r = subprocess.run(["ar65", "t", str(REPO / "build" / "lib" / "mlkem.a")],
                       capture_output=True, text=True)
    return set(r.stdout.split()) | {"mlkem_link.o"}


def illegal_importers(symbols, importers, allowed):
    """{symbol: modules} where a module outside *allowed* imports a banned symbol."""
    return {s: sorted(m - allowed) for s, m in importers.items()
            if s in symbols and m - allowed}


def banned_references(symbols, extra=None):
    """{file: [symbols]} for every source file except mlkem_link.s that names
    a symbol in the run image: such a reference is an unbanked call into
    KERNAL ROM (or skips mlkem_arith_init)."""
    files = {str(p.relative_to(REPO)): p.read_text()
             for pat in ("*.s", "*.inc") for p in (REPO / "src").rglob(pat)
             if p.name != "mlkem_link.s"}
    files.update(extra or {})
    hits = {}
    for f, txt in files.items():
        txt = "\n".join(ln.split(";")[0] for ln in txt.splitlines())
        found = sorted(s for s in symbols if re.search(rf"\b{re.escape(s)}\b", txt))
        if found:
            hits[f] = found
    return hits


SQTAB_BASE = 0xBC00


def sqtab_byte_at(addr, base=SQTAB_BASE):
    """The byte c64-https's boot leaves at *addr* inside the sqtab window
    (lo plane base..base+511 = floor(n*n/4) & $FF, hi plane = >> 8)."""
    n = addr - base
    if 0 <= n < 512:
        return ((n * n) // 4) & 0xFF
    if 512 <= n < 1024:
        m = n - 512
        return ((m * m) // 4) >> 8
    raise ValueError(f"${addr:04X} is outside the sqtab window")


def marker_collides(addr, value=0x5C):
    return sqtab_byte_at(addr) == value


def run_make(args, extra_env=None, timeout=1800):
    env = dict(os.environ, **(extra_env or {}))
    r = subprocess.run(["make"] + args, cwd=REPO, capture_output=True,
                       text=True, env=env, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def static_checks(t):
    print("\n[1] cfg shape")
    for cfg, cold in CFGS.items():
        text = (REPO / "cfg" / cfg).read_text()
        areas = memory_areas(text)
        for name, (start, size) in EXPECT_AREAS.items():
            a = areas.get(name, "")
            t.check(a and f"start = {start}" in a and f"size = {size}" in a
                    and 'file = ""' in a and "define = yes" in a,
                    f"{cfg}: {name} = {start}/{size}, file=\"\", define",
                    a or "area missing")
        t.check("file = %O" in areas.get("COLD_FILE", "") and
                'file = ""' in areas.get("CRYPTO_COLD_SHADOW", ""),
                f"{cfg}: COLD_FILE is the file view, CRYPTO_COLD_SHADOW the RAM view")
        t.check(not no_define(text), f"{cfg}: every MEMORY area is define = yes",
                ", ".join(no_define(text)))
        t.check(not unguarded(text, cold),
                f"{cfg}: every MEMORY area has an sqtab-window guard",
                ", ".join(unguarded(text, cold)))
        for seg in ("LIB_MLKEM_CODE", "LIB_MLKEM_RODATA", "LIB_MLKEM_BSS",
                    "LIB_MLKEM_POLY_BSS"):
            t.check(re.search(rf"^\s*{seg}:.*optional\s*=\s*yes", text, re.M),
                    f"{cfg}: {seg} is optional (unset builds stay identical)")

    # The entry rule: nothing but mlkem_link.s names a library entry, so
    # pq_mlkem_call (which runs mlkem_arith_init) is the only way in.
    stray = unwrapped_callers()
    t.check(not stray, "only mlkem_link.s references the ML-KEM entries",
            ", ".join(stray))
    t.check(unwrapped_callers({"src/zz.s": "  jsr mlkem_keygen\n"}) == ["src/zz.s"],
            "red: a direct jsr mlkem_keygen elsewhere is reported")

    # Red cases for the guard: it must see a new area and a missing define.
    base = (REPO / "cfg" / "c64-https-uci.cfg").read_text()
    anchor = "    X25519_SCRATCH:     start = $A000"
    assert anchor in base
    extra = base.replace(anchor, "    ZZ_NEW: start = $BD00, size = $0100, "
                         "type = rw, file = \"\", define = yes;\n" + anchor)
    t.check(unguarded(extra, False) == ["ZZ_NEW"],
            "red: a new MEMORY area with no guard is reported",
            str(unguarded(extra, False)))
    nodef = base.replace("LOADADDR:       start = $07FF, size = $0002, file = %O, "
                         "define = yes;", "LOADADDR:       start = $07FF, "
                         "size = $0002, file = %O;")
    t.check(no_define(nodef) == ["LOADADDR"],
            "red: an area without define = yes is reported", str(no_define(nodef)))
    link = LINK_S.read_text()
    t.check("ZP_CRYPTO" in unguarded(base, False, link.replace(
        'SQTAB_GUARD "ZP_CRYPTO"', 'SQTAB_GUARD "XX"')),
        "red: removing a guard line is reported")

    print("\n[2] the PQ_HYBRID knob matrix (make -n)")
    cases = [
        (["BACKEND=ip65", "PQ_HYBRID=1"], False, "PQ_HYBRID=1 is UCI-only"),
        (["BACKEND=ip65", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=1"], False,
         "PQ_HYBRID=1 is UCI-only"),
        (["BACKEND=uci-m3", "PQ_HYBRID=1"], False, "does not apply to BACKEND=uci-m3"),
        (["BACKEND=uci", "PQ_HYBRID=1"], False, "needs USE_NISTCURVES_ONCHIP=1"),
        (["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=2"], False,
         "PQ_HYBRID must be 1"),
        (["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=1"], True, ""),
        (["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=1",
          "TRUST_STORE=1"], True, ""),
        (["BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1", "PQ_HYBRID=1"], True, ""),
        (["BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1", "PQ_HYBRID=1",
          "TRUST_STORE=1"], True, ""),
        (["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=0"], True, ""),
    ]
    for args, ok, msg in cases:
        rc, out = run_make(["-n"] + args)
        label = " ".join(args)
        if ok:
            t.check(rc == 0, f"allowed: {label}", out.strip()[-200:])
        else:
            t.check(rc != 0 and msg in out, f"refused: {label}",
                    f"rc={rc} {out.strip()[-200:]}")


def map_segments(map_path):
    text = Path(map_path).read_text()
    sec = text.split("Segment list:")[1].split("Exports list")[0]
    segs = {}
    for ln in sec.splitlines():
        m = re.match(r"^(\S+)\s+([0-9A-F]{6})\s+([0-9A-F]{6})\s+([0-9A-F]{6})\s+", ln)
        if m:
            segs[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))
    return segs


def layout_checks(t, tag):
    segs = map_segments(REPO / "build" / "c64-https.map")
    inside = {n for n, (s, e) in segs.items() if s >= 0xB100 and s < 0xC000
              and n != "BSS"}
    t.check(inside == {"LIB_MLKEM_BSS", "X25519_TABLES", "TABLES_BSS"},
            f"{tag}: only LIB_MLKEM_BSS, X25519_TABLES, TABLES_BSS start in "
            f"$B100-$BFFF", str(sorted(inside)))
    t.check(segs["LIB_MLKEM_BSS"][0] == 0xB100 and segs["LIB_MLKEM_BSS"][1] < 0xBC00,
            f"{tag}: LIB_MLKEM_BSS = $B100-${segs['LIB_MLKEM_BSS'][1]:04X}, below sqtab")
    t.check(segs["LIB_MLKEM_POLY_BSS"] == (0xD000, 0xDFFF),
            f"{tag}: LIB_MLKEM_POLY_BSS = $D000-$DFFF")
    t.check(segs["LIB_MLKEM_CODE"][0] == 0xE000
            and segs["LIB_MLKEM_RODATA"][1] <= 0xFDFF,
            f"{tag}: code+rodata = $E000-${segs['LIB_MLKEM_RODATA'][1]:04X}, "
            f"inside $E000-$FDFF")
    syms = rom_shadowed_symbols(REPO / "build" / "c64-https.map")
    t.check(len(syms) >= 20 and "mlkem_keygen" in syms and "keccak_f1600" in syms,
            f"{tag}: the map's export list has {len(syms)} symbols in $E000-$FDFF")
    hits = banned_references(syms)
    t.check(not hits, f"{tag}: no source outside mlkem_link.s names one of them",
            str(hits))
    imps = map_importers(REPO / "build" / "c64-https.map")
    allowed = library_members()
    bad_imp = illegal_importers(syms, imps, allowed)
    t.check(not bad_imp and any(s in imps for s in syms),
            f"{tag}: the map's Imports list: only mlkem_link.o and the library's own "
            "members import a banned symbol", str(bad_imp))
    probe = {"mlkem_poly_ntt": {"boot.o"}}
    t.check(illegal_importers(syms, probe, allowed) == {"mlkem_poly_ntt": ["boot.o"]},
            f"{tag}: red: a foreign module importing a banned symbol is reported")
    spelled = 'jsr .ident(.concat("mlkem_", "keygen")) ; ";" in a string\n'
    t.check("src/zz.s" not in banned_references(syms, {"src/zz.s": spelled}),
            f"{tag}: (the source scan cannot see .ident(.concat(...)): the Imports "
            "check above is what catches it)")
    t.check(banned_references(syms, {"src/zz.s": "  jsr mlkem_poly_ntt\n"}) ==
            {"src/zz.s": ["mlkem_poly_ntt"]},
            f"{tag}: red: a direct jsr into the image is reported")
    t.check("src/zz.inc" in banned_references(syms, {"src/zz.inc": ".import mlkem_poly_ntt\n"}),
            f"{tag}: red: a reference in an .inc is reported")
    t.check("src/zz.s" in banned_references(syms, {"src/zz.s": "  jsr __LIB_MLKEM_CODE_RUN__\n"}),
            f"{tag}: red: a __LIB_MLKEM_* run-address reference is reported")
    t.check(set(syms) >= {"mlkem_keygen", "mlkem_decaps_seed", "mlkem_arith_init"},
            f"{tag}: red: the symbol set covers the entries, not a name regex")
    allowed = banned_references(syms, {"src/zz.s": "  jsr pq_mlkem_keygen\n  jsr pq_mlkem_decaps_seed\n  lda #<pq_mlkem_call\n"})
    t.check("src/zz.s" not in allowed,
            f"{tag}: the named wrappers are callable from anywhere")
    labels_txt = (REPO / "build" / "labels.txt").read_text()
    m = re.search(r"^al C:([0-9A-F]+) \.__LIB_MLKEM_MARK_LOAD__$", labels_txt, re.M)
    maddr = int(m.group(1), 16)
    t.check(not marker_collides(maddr),
            f"{tag}: the tail marker's load address ${maddr:04X} holds sqtab byte "
            f"${sqtab_byte_at(maddr):02X}, not the marker")
    t.check(marker_collides(0xBC67) and marker_collides(0xBD99)
            and not marker_collides(maddr),
            f"{tag}: red: the known collisions $BC67/$BD99 are reported")
    prg = REPO / "build" / "c64-https.prg"
    img = prg.read_bytes()
    import _prg_load as pl
    stage = pl.stage_from_labels(REPO / "build" / "labels.txt")
    try:
        pl.image_span(img, stage)
        ok_load = stage is not None
    except pl.PrgLoadError as exc:
        ok_load = False
    t.check(ok_load, f"{tag}: _prg_load accepts this PQ image (stage {stage})")
    off = 0xA000 - 0x0801 + 2
    t.check(img[off] != 0 and any(img[off:off + 0x1D00]),
            f"{tag}: the ML-KEM image is in the PRG at $A000 (first byte nonzero)")
    bad = prg_io_violation(img)
    t.check(bad is None, f"{tag}: the PRG does not load into $D000-$DFFF",
            str(bad))


# (label, file, old, new, expected ld65/ca65 text)
MUTANTS = [
    ("load image layout differs from the run layout", "cfg/c64-https-uci.cfg",
     "align = $40, align_load = $40, define = yes;", "align = $40, define = yes;",
     "the load image and the run image are laid out differently"),
    ("load image moved off the head of COLD_FILE", "cfg/c64-https-uci.cfg",
     "LIB_MLKEM_CODE:     load = COLD_FILE, run = MLKEM_CODE_RAM, type = ro,  optional = yes, define = yes;",
     "LIB_MLKEM_CODE:     load = COLD_FILE, run = MLKEM_CODE_RAM, type = ro,  optional = yes, define = yes, start = $A100;",
     None),
    ("COLD_FILE shrunk below the image", "cfg/c64-https-uci.cfg",
     "COLD_FILE:          start = $A000, size = $2000",
     "COLD_FILE:          start = $A000, size = $1000",
     "COLD_FILE no longer ends at $BFFF"),
    ("polys moved off $D000", "cfg/c64-https-uci.cfg",
     "MLKEM_POLY_RAM:     start = $D000, size = $1000",
     "MLKEM_POLY_RAM:     start = $D100, size = $0F00",
     "MLKEM_POLY_RAM is not at $D000"),
    ("polys area shrunk", "cfg/c64-https-uci.cfg",
     "MLKEM_POLY_RAM:     start = $D000, size = $1000",
     "MLKEM_POLY_RAM:     start = $D000, size = $1100",
     "MLKEM_POLY_RAM is not 4 KB"),
    ("code moved off $E000", "cfg/c64-https-uci.cfg",
     "MLKEM_CODE_RAM:     start = $E000, size = $1E00",
     "MLKEM_CODE_RAM:     start = $E200, size = $1C00",
     "MLKEM_CODE_RAM is not at $E000"),
    ("code area shrunk below the footprint", "cfg/c64-https-uci.cfg",
     "MLKEM_CODE_RAM:     start = $E000, size = $1E00",
     "MLKEM_CODE_RAM:     start = $E000, size = $1800",
     "MLKEM_CODE_RAM is not 7,680 B"),
    ("rest-BSS moved off X25519_TABLES", "cfg/c64-https-uci.cfg",
     "MLKEM_BSS_RAM:      start = $B100, size = $0B00",
     "MLKEM_BSS_RAM:      start = $B000, size = $0C00",
     "MLKEM_BSS_RAM must start on X25519_TABLES"),
    ("rest-BSS grown over the sqtab", "cfg/c64-https-uci.cfg",
     "MLKEM_BSS_RAM:      start = $B100, size = $0B00",
     "MLKEM_BSS_RAM:      start = $B100, size = $0D00",
     "MLKEM_BSS_RAM is not exactly [mul38_lo_tab, sqtab_lo)"),
    ("an empty area parked on the sqtab", "cfg/c64-https-uci.cfg",
     "UCI_BSS_REGION: start = $4000, size = $0000",
     "UCI_BSS_REGION: start = $BD00, size = $0000",
     "area UCI_BSS_REGION overlaps the sqtab window"),
    ("dk ring smaller than 2,400 B", "src/constants.inc",
     "TCP_RECV_BUF_SIZE       = 4096", "TCP_RECV_BUF_SIZE       = 2048",
     "the TCP ring is smaller than the 2,400 B dk it hosts"),
    ("dk size drifted", "src/constants.inc",
     "MLKEM_DK_SIZE           = 2400", "MLKEM_DK_SIZE           = 2401",
     "session_scrub: span at tcp_recv_buf is not 2400 bytes"),
    ("dk scratch moved off the ring", "src/constants.inc",
     "mlkem_dk_scratch        = tcp_recv_buf",
     "mlkem_dk_scratch        = tcp_recv_buf + $100",
     "the dk scratch moved off the TCP ring base"),
    ("ZP slot moved ($40 -> $30)", "tools/integration/build_mlkem.sh",
     "-D mlkem_zp_src=0x40", "-D mlkem_zp_src=0x30",
     "mlkem_zp_src moved off $40"),
    ("ZP mul block moved ($48 -> $50)", "tools/integration/build_mlkem.sh",
     "-D mlkem_zp_mul=0x48", "-D mlkem_zp_mul=0x50",
     "mlkem_zp_mul moved off $48"),
    ("scrub window span length", "src/session_scrub.s",
     "mul_dma_hi + 256,       2816", "mul_dma_hi + 256,       2815",
     "session_scrub: span at mul38_lo_tab is not 2815 bytes"),
    ("scrub poly span length", "src/session_scrub.s",
     "__LIB_MLKEM_POLY_BSS_RUN__ + __LIB_MLKEM_POLY_BSS_SIZE__, 4096",
     "__LIB_MLKEM_POLY_BSS_RUN__ + __LIB_MLKEM_POLY_BSS_SIZE__, 4095",
     "session_scrub: span at __LIB_MLKEM_POLY_BSS_RUN__ is not 4095 bytes"),
    ("scrub dk span length", "src/session_scrub.s",
     "tcp_recv_buf + MLKEM_DK_SIZE, 2400", "tcp_recv_buf + MLKEM_DK_SIZE, 2399",
     "session_scrub: span at tcp_recv_buf is not 2399 bytes"),
]

PQ_ARGS = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=1"]
COMB_ARGS = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1", "PQ_HYBRID=1"]
COMB_NOCOLD = COMB_ARGS + ["COLD_BANK=0"]


def link_ok(t, tag, args):
    subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
    rc, out = run_make(args)
    errs = [ln for ln in out.splitlines() if "rror" in ln and "ldwarning" not in ln]
    ok = t.check(rc == 0, f"{tag}: links", "\n".join(errs[-5:]) or out[-400:])
    if ok:
        warns = [ln for ln in out.splitlines() if ln.startswith("ld65: Warning")]
        t.check(not warns, f"{tag}: no ld65 warnings", "; ".join(warns))
        layout_checks(t, tag)
    return ok


def build_checks(t):
    print("\n[3] green controls")
    if not link_ok(t, "uci-onchip", PQ_ARGS):
        return
    link_ok(t, "uci-onchip TRUST_STORE=1", PQ_ARGS + ["TRUST_STORE=1", "TRUST_RELEASE=1"])
    link_ok(t, "uci-comb", COMB_ARGS)
    link_ok(t, "uci-comb TRUST_STORE=1", COMB_ARGS + ["TRUST_STORE=1", "TRUST_RELEASE=1"])
    link_ok(t, "uci-comb COLD_BANK=0", COMB_NOCOLD)

    print("\n[4] mutations: each must fail with its own assert")
    subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
    for label, f, old, new, expect in MUTANTS:
        path = REPO / f
        orig = path.read_text()
        if old not in orig:
            t.check(False, f"mutant {label!r}", f"anchor not found in {f}")
            continue
        try:
            path.write_text(orig.replace(old, new, 1))
            subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
            rc, out = run_make(PQ_ARGS)
        finally:
            path.write_text(orig)
        if expect is None:
            t.check(rc != 0, f"mutant {label!r} fails the build",
                    out.strip()[-300:])
        else:
            t.check(rc != 0 and expect in out,
                    f"mutant {label!r} fails with {expect!r}",
                    f"rc={rc} " + "\n".join(
                        ln for ln in out.splitlines() if "rror" in ln)[-400:])

    print("\n[4b] a probe module that reaches a banned symbol by .ident(.concat(...))")
    probe = REPO / "src" / "zz_probe.s"
    try:
        probe.write_text('.import .ident(.concat("mlkem_", "keygen"))\n.segment "CODE"\n        jsr .ident(.concat("mlkem_", "keygen"))\n')
        subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
        rc, out = run_make(PQ_ARGS)
        if t.check(rc == 0, "the probe links (the source scan cannot see it)", out[-300:]):
            syms = rom_shadowed_symbols(REPO / "build" / "c64-https.map")
            t.check("src/zz_probe.s" not in banned_references(syms, {"src/zz_probe.s": probe.read_text()}),
                    "the source scan misses .ident(.concat(...))")
            bad = illegal_importers(syms, map_importers(REPO / "build" / "c64-https.map"),
                                    library_members())
            t.check("zz_probe.o" in bad.get("mlkem_keygen", []),
                    "the Imports check reports zz_probe.o importing mlkem_keygen", str(bad))
    finally:
        probe.unlink(missing_ok=True)

    print("\n[5] the stale-checkout probe (libs/mlkem at v0.5.1)")
    sub = REPO / "libs" / "mlkem"
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=sub,
                          capture_output=True, text=True).stdout.strip()
    try:
        co = subprocess.run(["git", "checkout", "-q", "v0.5.1"], cwd=sub,
                            capture_output=True, text=True)
        if t.check(co.returncode == 0, "checked out libs/mlkem v0.5.1",
                   co.stderr.strip()):
            subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
            rc, out = run_make(PQ_ARGS)
            t.check(rc != 0 and "libs/mlkem checkout is unusable" in out
                    and "need c64-mlkem >= v0.6.0" in out,
                    "a v0.5.1 checkout fails the preflight by name",
                    out.strip()[-300:])
    finally:
        subprocess.run(["git", "checkout", "-q", head], cwd=sub,
                       capture_output=True)

    print("\n[6] restored: control relinks")
    link_ok(t, "uci-onchip (restored)", PQ_ARGS)


def main():
    t = Tally()
    static_checks(t)
    if "--static" not in sys.argv[1:]:
        if shutil.which("ld65") is None or shutil.which("ca65") is None:
            return cannot_run("cc65 not found", certifies="the PQ_HYBRID placement asserts")
        build_checks(t)
    print(f"\nRESULTS: {t.passed}/{t.passed + t.failed} passed, {t.failed} failed")
    return verdict(t.passed, t.failed, certifies="the PQ_HYBRID placement asserts")


if __name__ == "__main__":
    sys.exit(main())
