#!/usr/bin/env python3
"""Free bytes per memory region, measured from the link map (#193).

This is the ONE source for memory-margin figures. CLAUDE.md, the cfg
headers and the README used to restate per-profile byte counts by hand;
they drifted apart profile by profile, and every PR that moved a segment
then had to "correct" some of them. Nothing here is hand-maintained:
region bounds come from the MEMORY block of the cfg the build actually
linked (named by the `-C` in build/flags.stamp's LD65FLAGS), and
occupancy comes from build/c64-https.map's "Segment list".

For each file-backed region it reports:

  tail   bytes between the last used address and the region's end — the
         space the next byte appended to the region's last segment gets;
  hole   the largest gap BELOW the last used address (alignment padding,
         e.g. the gap under the page-aligned TABLES_BSS) — free, but only
         for a segment placed there explicitly.

Occupancy is by address, not by the cfg's `load =` names, so a region
that another region overlaps (ip65's SCRATCH_UNION inside
CRYPTO_COLD_SHADOW) counts the union's tenants as occupying it. A region
with no segments at all is reported as EMPTY to ld65, which is NOT
headroom: ip65's NET_BSS is the blob's own BSS and the UCI
OVERLAY_FILE_PAD holds the TCP ring by equate.

Usage:

    python3 tools/measure_margins.py              # the build in build/
    python3 tools/measure_margins.py --build      # clean-build every profile
    python3 tools/measure_margins.py --build --profile uci-comb
    python3 tools/measure_margins.py --json

`--build` runs `make clean && make <flags>` per profile in this checkout,
or in `--repo` (it overwrites that checkout's build/), keeps each profile's map/stamp/PRG under --out,
and prints the PRG sha256 beside each table so a figure is always tied to
the artifact it came from. Margins are per profile: never carry a number
from one profile to another.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# tools/uci/rig_https_wiki.py's default target: the longest one anything here
# builds, and so the one that finds the ip65 NET_CODE budget first.
WIKI = ("HTTPS_HOST=en.wikipedia.org",
        "HTTPS_PATH=/w/index.php?title=Commodore_64&action=raw")

# The five link profiles, plus the wikipedia target on both ip65 profiles:
# ip65's NET_CODE tail is a joint budget with HTTPS_TARGET_RODATA, so the
# default target's figure does not say whether a longer target links.
PROFILES = {
    "ip65":             ("BACKEND=ip65",),
    "ip65-onchip":      ("BACKEND=ip65", "USE_NISTCURVES_ONCHIP=1"),
    "uci":              ("BACKEND=uci",),
    "uci-onchip":       ("BACKEND=uci", "USE_NISTCURVES_ONCHIP=1"),
    "uci-comb":         ("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1"),
    "ip65-wiki":        ("BACKEND=ip65",) + WIKI,
    "ip65-onchip-wiki": ("BACKEND=ip65", "USE_NISTCURVES_ONCHIP=1") + WIKI,
}


class ParseError(ValueError):
    """An input did not have the shape this tool relies on."""


# ---------------------------------------------------------------------------
# Parsers (pure)
# ---------------------------------------------------------------------------
def _number(tok):
    tok = tok.strip()
    if re.fullmatch(r"\$[0-9A-Fa-f]+", tok):
        return int(tok[1:], 16)
    if re.fullmatch(r"0[xX][0-9A-Fa-f]+", tok):
        return int(tok, 16)
    if re.fullmatch(r"[0-9]+", tok):
        return int(tok)
    # An expression or a symbol: refuse rather than guess a bound.
    raise ParseError(f"cannot evaluate cfg value {tok!r}")


def parse_cfg_memory(text):
    """MEMORY areas of an ld65 cfg: [{name, start, size, end, file}] in order.

    `end` is inclusive. `file` is True for areas written to the output
    (`file = %O`), which are the ones a PRG byte can land in.
    """
    text = re.sub(r"#[^\n]*", "", text)
    m = re.search(r"\bMEMORY\s*\{(.*?)\}", text, re.S)
    if not m:
        raise ParseError("no MEMORY block in cfg")
    areas = []
    for entry in m.group(1).split(";"):
        entry = entry.strip()
        if not entry:
            continue
        name, sep, body = entry.partition(":")
        if not sep:
            raise ParseError(f"malformed MEMORY entry {entry!r}")
        attrs = {}
        for item in body.split(","):
            key, eq, val = item.partition("=")
            if eq:
                attrs[key.strip().lower()] = val.strip()
        if "start" not in attrs or "size" not in attrs:
            raise ParseError(f"MEMORY area {name.strip()} lacks start/size")
        start, size = _number(attrs["start"]), _number(attrs["size"])
        areas.append({
            "name": name.strip(),
            "start": start,
            "size": size,
            "end": start + size - 1,
            "file": attrs.get("file") == "%O",
        })
    if not areas:
        raise ParseError("empty MEMORY block in cfg")
    return areas


def parse_map_segments(text):
    """The map's "Segment list": [{name, start, end, size}], end inclusive."""
    m = re.search(r"^Segment list:\s*\n-+\s*\n(.*?)(?:\n\s*\n|\Z)", text,
                  re.S | re.M)
    if not m:
        raise ParseError("no 'Segment list:' section in map")
    segs = []
    for line in m.group(1).splitlines():
        cols = line.split()
        if not cols or cols[0] == "Name" or set(line.strip()) == {"-"}:
            continue
        if len(cols) != 5:
            raise ParseError(f"unexpected segment row {line!r}")
        name, start, end, size = cols[0], *(int(c, 16) for c in cols[1:4])
        if size and end - start + 1 != size:
            raise ParseError(f"segment {name}: start/end disagree with size")
        segs.append({"name": name, "start": start, "end": end, "size": size})
    if not segs:
        raise ParseError("'Segment list:' section has no rows")
    return segs


def cfg_from_stamp(text):
    """The cfg path in build/flags.stamp's LD65FLAGS `-C` argument."""
    m = re.search(r"^LD65FLAGS=(?:.*?\s)?-C\s+(\S+)", text, re.M)
    if not m:
        raise ParseError("no '-C <cfg>' in flags.stamp LD65FLAGS")
    return m.group(1)


# ---------------------------------------------------------------------------
# Measurement (pure)
# ---------------------------------------------------------------------------
def measure(areas, segments):
    """Per file-backed area: occupancy, tail free and largest interior hole.

    `overflow` is how far a segment that STARTS in the area runs past its
    end. ld65 writes the map even when a link fails on a memory-area
    overflow, so a map is not evidence of a good link: any non-zero
    overflow means the figures describe a failed link, not margins.
    """
    out = []
    for a in areas:
        if not a["file"] or a["size"] == 0 or a["name"] == "LOADADDR":
            continue
        overflow = max([s["end"] - a["end"] for s in segments
                        if s["size"] and a["start"] <= s["start"] <= a["end"]
                        and s["end"] > a["end"]], default=0)
        spans = sorted((max(s["start"], a["start"]), min(s["end"], a["end"]))
                       for s in segments
                       if s["size"] and s["start"] <= a["end"]
                       and s["end"] >= a["start"])
        row = {"region": a["name"], "start": a["start"], "end": a["end"],
               "size": a["size"], "overflow": overflow}
        if not spans:
            row.update(empty=True, last_used=None, tail=None, hole=None,
                       hole_at=None, used=0)
            out.append(row)
            continue
        merged = [list(spans[0])]
        for lo, hi in spans[1:]:
            if lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        gaps = [(merged[0][0] - a["start"], a["start"])]
        gaps += [(nxt[0] - cur[1] - 1, cur[1] + 1)
                 for cur, nxt in zip(merged, merged[1:])]
        hole, hole_at = max(gaps)
        last = merged[-1][1]
        row.update(empty=False, last_used=last, tail=a["end"] - last,
                   hole=hole, hole_at=hole_at if hole else None,
                   used=sum(hi - lo + 1 for lo, hi in merged))
        out.append(row)
    return out


def measure_files(map_path, cfg_path):
    return measure(parse_cfg_memory(Path(cfg_path).read_text()),
                   parse_map_segments(Path(map_path).read_text()))


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------
def format_rows(rows):
    lines = [f"  {'region':<24}{'extent':<15}{'last used':>10}"
             f"{'tail free':>11}{'largest hole':>20}"]
    for r in rows:
        extent = f"${r['start']:04X}-${r['end']:04X}"
        if r["empty"]:
            lines.append(f"  {r['region']:<24}{extent:<15}"
                         f"{'EMPTY to ld65 (not headroom)':>41}")
            continue
        if r["overflow"]:
            lines.append(f"  {r['region']:<24}{extent:<15}"
                         f"{'OVERFLOWS by %s B' % format(r['overflow'], ','):>41}")
            continue
        hole = (f"{r['hole']:,} B @ ${r['hole_at']:04X}" if r["hole"] else "-")
        lines.append(f"  {r['region']:<24}{extent:<15}"
                     f"{'$%04X' % r['last_used']:>10}"
                     f"{r['tail']:>9,} B{hole:>20}")
    return "\n".join(lines)


def format_matrix(results):
    """Tail free per region (rows) x profile (columns)."""
    names = list(results)
    regions = []
    for res in results.values():
        for r in res["rows"]:
            if not r["empty"] and r["region"] not in regions:
                regions.append(r["region"])
    width = max(len(n) for n in names) + 2
    lines = [f"  {'tail free (B)':<24}" + "".join(f"{n:>{width}}" for n in names)]
    for reg in regions:
        cells = []
        for n in names:
            hit = [r for r in results[n]["rows"] if r["region"] == reg]
            if not hit or hit[0]["empty"]:
                cells.append("-")
            elif hit[0]["overflow"]:
                cells.append(f"OVF+{hit[0]['overflow']:,}")
            else:
                cells.append(f"{hit[0]['tail']:,}")
        lines.append(f"  {reg:<24}" + "".join(f"{c:>{width}}" for c in cells))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Build driver
# ---------------------------------------------------------------------------
def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_build(build_dir, repo=REPO):
    """Measure the build in `build_dir` (map + flags.stamp + PRG)."""
    build_dir = Path(build_dir)
    for f in ("flags.stamp", "c64-https.map"):
        if not (build_dir / f).exists():
            raise ParseError(f"{build_dir / f} not found — build first "
                             "(or use --build)")
    cfg = cfg_from_stamp((build_dir / "flags.stamp").read_text())
    prg = build_dir / "c64-https.prg"
    return {
        "cfg": cfg,
        "prg_sha256": _sha256(prg) if prg.exists() else None,
        "rows": measure_files(build_dir / "c64-https.map", Path(repo) / cfg),
    }


def build_profile(name, out_dir, repo=REPO, make="make"):
    flags = PROFILES[name]
    subprocess.run([make, "-C", str(repo), "clean"], check=True,
                   stdout=subprocess.DEVNULL)
    proc = subprocess.run([make, "-C", str(repo), *flags],
                          capture_output=True, text=True)
    build = Path(repo) / "build"
    if proc.returncode != 0 or not (build / "c64-https.prg").exists():
        raise ParseError(f"{name}: build failed ({' '.join(flags)})\n"
                           + proc.stdout[-2000:] + proc.stderr[-2000:])
    dest = Path(out_dir) / name
    dest.mkdir(parents=True, exist_ok=True)
    for f in ("c64-https.map", "flags.stamp", "c64-https.prg"):
        shutil.copy2(build / f, dest / f)
    return read_build(dest, repo)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--build", action="store_true",
                    help="make clean && make each profile (overwrites build/)")
    ap.add_argument("--profile", action="append", choices=sorted(PROFILES),
                    help="with --build: only these profiles (repeatable)")
    ap.add_argument("--out", help="with --build: keep artifacts here "
                    "(default: a fresh temp dir)")
    ap.add_argument("--repo", default=str(REPO),
                    help="the checkout to build/measure (default: this one)")
    ap.add_argument("--build-dir",
                    help="without --build: the build to measure "
                    "(default: <repo>/build)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.build:
        out = args.out or tempfile.mkdtemp(prefix="c64-margins-")
        results = {}
        for name in args.profile or PROFILES:
            print(f"building {name} ...", file=sys.stderr)
            try:
                results[name] = build_profile(name, out, args.repo)
            except ParseError as exc:
                print(f"measure_margins: {exc}", file=sys.stderr)
                return 1
        print(f"artifacts: {out}", file=sys.stderr)
    else:
        if args.profile:
            ap.error("--profile needs --build")
        build_dir = args.build_dir or str(Path(args.repo) / "build")
        try:
            results = {"build/": read_build(build_dir, args.repo)}
        except ParseError as exc:
            print(f"measure_margins: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for name, res in results.items():
            print(f"{name}  ({res['cfg']}, PRG sha256 {res['prg_sha256']})")
            print(format_rows(res["rows"]))
            print()
        if len(results) > 1:
            print(format_matrix(results))
    bad = failed_links(results)
    for msg in bad:
        print(f"measure_margins: {msg}", file=sys.stderr)
    return 1 if bad else 0


def failed_links(results):
    """Reasons the measured builds are not good links (empty when all are)."""
    bad = []
    for name, res in results.items():
        if res["prg_sha256"] is None:
            bad.append(f"{name}: no PRG — the map is from a FAILED link, "
                       "so these figures are not margins")
        for r in res["rows"]:
            if r["overflow"]:
                bad.append(f"{name}: a segment overflows {r['region']} by "
                           f"{r['overflow']:,} B")
    return bad


if __name__ == "__main__":
    sys.exit(main())
