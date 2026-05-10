#!/usr/bin/env python3
"""Quick post-mortem analyzer for ecdsa_u64e bench trace.bin.

Usage:
  python3 tools/uci/_analyze_ecdsa_trace.py [trace_dir]

Reads `trace.bin` + `trace.bin.meta.json` from the given directory
(defaults to the newest dir under /tmp/ecdsa_debug/) and prints:
  - filter sanity (UCI / LOADER hits should be zero)
  - top-N PC hotspots, cross-referenced with build/labels.txt if present
  - histogram by high byte of address

trace.bin is a packed little-endian u32 stream where bits[31]=PHI2,
bits[15:0]=address. See meta.json for the full bit layout.
"""
from __future__ import annotations

import json
import struct
import sys
from collections import Counter
from pathlib import Path

from c64_test_harness import Labels


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = Path("/tmp/ecdsa_debug")


def _load_labels() -> dict[int, str]:
    """Return {addr: name} from build/labels.txt if present."""
    labels_file = REPO_ROOT / "build" / "labels.txt"
    if not labels_file.is_file():
        return {}
    out: dict[int, str] = {}
    for name, a in Labels.from_file(labels_file).items():
        # Prefer the first (public) label if multiple map to same addr
        out.setdefault(a, name)
    return out


def _pick_latest_dir(base: Path) -> Path | None:
    if not base.is_dir():
        return None
    cands = [d for d in base.iterdir() if d.is_dir() and
             (d / "trace.bin").is_file()]
    if not cands:
        return None
    cands.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return cands[0]


def _nearest_label(addr: int, labels: dict[int, str]) -> str:
    """Return 'name+offset' for the nearest label <= addr."""
    best_addr = -1
    for a in labels:
        if a <= addr and a > best_addr:
            best_addr = a
    if best_addr < 0:
        return ""
    delta = addr - best_addr
    return f"{labels[best_addr]}+{delta}"


def main() -> int:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else _pick_latest_dir(
        DEFAULT_BASE)
    if base is None:
        print(f"no trace.bin found under {DEFAULT_BASE}", file=sys.stderr)
        return 2
    trace_path = base / "trace.bin"
    meta_path = base / "trace.bin.meta.json"
    if not trace_path.is_file() or not meta_path.is_file():
        print(f"missing trace.bin or meta.json under {base}", file=sys.stderr)
        return 2

    meta = json.loads(meta_path.read_text())
    raw = trace_path.read_bytes()
    count = len(raw) // 4
    words = struct.unpack(f"<{count}I", raw)
    addrs = [w & 0xFFFF for w in words]

    labels = _load_labels()

    print(f"trace dir: {base}")
    print(f"cycles   : {count}")
    print(f"duration : {meta.get('duration_seconds', 0):.2f}s "
          f"(capture-side)")
    print(f"mhz      : {meta.get('speed_mhz', '?')}")
    print(f"vector   : {meta.get('vector', '?')}")
    print(f"filter   : {meta.get('filter', '?')}")

    uci_hits = sum(1 for a in addrs if 0xDF1B <= a <= 0xDF1F)
    low_hits = sum(1 for a in addrs if 0x0800 <= a <= 0x1FFF)
    print(f"\nUCI $DF1B-$DF1F hits: {uci_hits}")
    print(f"LOADER $0800-$1FFF  : {low_hits}")
    print(f"  (both should be 0 given the default capture filter)")

    top = Counter(addrs).most_common(20)
    print(f"\nTop 20 PC hotspots:")
    for a, c in top:
        near = _nearest_label(a, labels)
        print(f"  ${a:04X}  {c:>10d}  ({100*c/count:5.2f}%)  {near}")

    bins = Counter()
    for a in addrs:
        bins[a & 0xFF00] += 1
    print(f"\nHistogram by high byte (top 10):")
    for hi, c in sorted(bins.items(), key=lambda kv: -kv[1])[:10]:
        near = _nearest_label(hi, labels)
        print(f"  ${hi:04X}xx  {c:>10d}  {near}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
