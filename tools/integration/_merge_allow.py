#!/usr/bin/env python3
"""Merge allow/deny patterns into a .claude/settings.local.json file.

Usage:
    _merge_allow.py <settings.local.json> --allow PATTERN [...] [--deny PATTERN [...]]

Creates the file with a minimal skeleton if missing. Merges new patterns
into permissions.allow / permissions.deny, dedupes against existing entries,
preserves the order of existing entries, and appends new entries at the end.
Preserves any other top-level keys and any other keys under permissions.
Writes back with 2-space indent and a trailing newline.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def merge(existing: list, new: list) -> tuple[list, list]:
    """Return (merged_list, added_patterns). Preserves existing order."""
    seen = set(existing)
    added: list = []
    out = list(existing)
    for p in new:
        if p not in seen:
            out.append(p)
            added.append(p)
            seen.add(p)
    return out, added


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--allow", nargs="*", default=[])
    ap.add_argument("--deny", nargs="*", default=[])
    args = ap.parse_args()

    if args.path.exists():
        with args.path.open() as f:
            data = json.load(f)
    else:
        data = {"permissions": {"allow": [], "deny": []}}

    perms = data.setdefault("permissions", {})
    cur_allow = perms.get("allow", [])
    cur_deny = perms.get("deny", [])

    new_allow, added_allow = merge(cur_allow, args.allow)
    new_deny, added_deny = merge(cur_deny, args.deny)

    perms["allow"] = new_allow
    if args.deny or cur_deny:
        perms["deny"] = new_deny

    args.path.parent.mkdir(parents=True, exist_ok=True)
    with args.path.open("w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    # Report what was added for transparency.
    print(f"[{args.path}]")
    print(f"  allow: +{len(added_allow)} new / {len(new_allow)} total")
    for p in added_allow:
        print(f"    + {p}")
    print(f"  deny:  +{len(added_deny)} new / {len(new_deny)} total")
    for p in added_deny:
        print(f"    + {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
