#!/usr/bin/env python3
"""tools/check_upstream_pins.py — report submodule pin drift against upstream tags.

Answers one question for every submodule in ``.gitmodules``: *what release is
this pinned to, and what has upstream shipped since?*

Dependency-free (stdlib + ``git`` only), no network libraries, no API tokens,
no GitHub CLI. Exactly one ``git ls-remote --tags`` and one ``git ls-tree`` per
submodule. Safe to schedule. (That is the default mode; ``--worktree`` below
makes no network calls at all.)

Cost, measured rather than asserted (2026-08-13, 3 submodules, warm DNS):
**2.1 s wall-clock, 0.15 s of it CPU** — i.e. network-bound, and it scales
with submodule count, not repo size. Re-check with ``time
tools/check_upstream_pins.py``; the git-call count is verifiable by stubbing
``subprocess.run``. Stated concretely on purpose: this whole script exists
because of a claim nobody could execute, and a vague-but-true cost note is
one refactor away from a false one.

    tools/check_upstream_pins.py              # human-readable table
    tools/check_upstream_pins.py --json       # machine-readable
    tools/check_upstream_pins.py --strict     # exit 1 if any pin has drifted
    tools/check_upstream_pins.py --submodule libs/x25519
    tools/check_upstream_pins.py --worktree   # offline: checkout vs. gitlink

Why this exists rather than ``git submodule status``
----------------------------------------------------
``git submodule status`` renders its version via ``git describe`` **without**
``--tags``, which considers *annotated* tags only. A lightweight tag is
invisible to it. c64-x25519 tagged ``v0.6.0`` lightweight while ``v0.5.0`` and
``v0.7.0`` are annotated, so ``git submodule status`` renders the exactly-on-
``v0.6.0`` pin as ``v0.5.0-5-g95fdd70`` — which reads as "five commits past a
release" and is how a correct pin came to look like a documentation bug.

This script resolves tags through ``refs/tags/<name>^{}`` when the peeled ref
is present and the bare ref otherwise, so lightweight and annotated tags are
treated identically.

It also reads the pinned SHA out of the git tree (``git ls-tree HEAD <path>``)
rather than the working copy, so it is correct for a submodule that has never
been ``git submodule update --init``'d, and immune to a dirty local checkout.

The blind spot that buys, and ``--worktree``
--------------------------------------------
Reading the gitlink means the default report describes *what this repo pins*,
never *what is on disk*. Those diverge exactly when a submodule was not updated
after a pull — and that divergence is what a build actually trips over.

c64-https#124: a contributor's ``libs/nistcurves`` sat in the v0.5.0-v0.8.0
range under a master-era tree, so ``make BACKEND=uci`` died several minutes in
with ``zp_config.o exports nistcurves_zp_ptr2 = <absent>`` — an error naming a
knob they never touched. This script, run at that moment, would have reported
"v0.11.2, no drift" and been *correct about the pin* while the checkout that
broke the build went unmentioned.

``--worktree`` is the complementary check: for every submodule it compares the
checked-out ``HEAD`` against the gitlink and reports MATCH / MISMATCH /
NOT-CHECKED-OUT plus dirtiness. It is **offline** — no ``ls-remote``, so no
network — and exits 1 on any mismatch without needing ``--strict``, because an
out-of-sync checkout is a broken working tree rather than a policy call about
how current a pin should be.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Matches the common vX.Y.Z / X.Y.Z shapes; anything else sorts as non-semver
# and is reported but never treated as "latest".
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def _git(*args: str, cwd: str = REPO_ROOT) -> str:
    """Run git, return stdout stripped. Raises CalledProcessError on failure."""
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def parse_gitmodules(path: str) -> list[dict]:
    """Parse .gitmodules into [{name, path, url}] without a config library."""
    mods: list[dict] = []
    current: dict | None = None
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return mods

    for raw in lines:
        line = raw.strip()
        header = re.match(r'^\[submodule\s+"(.+)"\]$', line)
        if header:
            current = {"name": header.group(1), "path": None, "url": None}
            mods.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in ("path", "url"):
            current[key] = value.strip()

    return [m for m in mods if m["path"] and m["url"]]


def pinned_sha(sub_path: str, ref: str = "HEAD") -> str | None:
    """The gitlink SHA recorded in the tree — not the working copy."""
    try:
        out = _git("ls-tree", ref, "--", sub_path)
    except subprocess.CalledProcessError:
        return None
    # Format: "160000 commit <sha>\t<path>"
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "commit":
            return fields[2]
    return None


def remote_tags(url: str) -> dict[str, str]:
    """Map tag name -> commit SHA for every tag on the remote.

    Handles annotated and lightweight tags uniformly: ``git ls-remote --tags``
    emits ``refs/tags/<n>`` for every tag plus ``refs/tags/<n>^{}`` carrying the
    *dereferenced commit* for annotated ones. The peeled entry wins when both
    are present, so the value is always a commit SHA, never a tag-object SHA.
    """
    try:
        out = _git("ls-remote", "--tags", url)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"git ls-remote failed for {url}: {exc.stderr.strip()}") from exc

    bare: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        sha, ref = parts[0].strip(), parts[1].strip()
        if not ref.startswith("refs/tags/"):
            continue
        name = ref[len("refs/tags/"):]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            bare[name] = sha

    return {name: peeled.get(name, sha) for name, sha in bare.items()}


def semver_key(tag: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.match(tag)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def inspect(mod: dict, ref: str) -> dict:
    result = {
        "name": mod["name"],
        "path": mod["path"],
        "url": mod["url"],
        "pinned_sha": None,
        "pinned_tag": None,
        "latest_tag": None,
        "latest_sha": None,
        "releases_behind": None,
        "drifted": False,
        "error": None,
    }

    sha = pinned_sha(mod["path"], ref)
    if sha is None:
        result["error"] = f"no gitlink for {mod['path']} at {ref}"
        return result
    result["pinned_sha"] = sha

    try:
        tags = remote_tags(mod["url"])
    except RuntimeError as exc:
        result["error"] = str(exc)
        return result

    for name, tag_sha in sorted(tags.items()):
        if tag_sha == sha:
            result["pinned_tag"] = name
            break

    semver_tags = sorted(
        ((semver_key(n), n) for n in tags if semver_key(n)),
        key=lambda pair: pair[0],
    )
    if semver_tags:
        latest_key, latest_name = semver_tags[-1]
        result["latest_tag"] = latest_name
        result["latest_sha"] = tags[latest_name]
        result["drifted"] = tags[latest_name] != sha
        pinned_key = semver_key(result["pinned_tag"]) if result["pinned_tag"] else None
        if pinned_key is not None:
            result["releases_behind"] = sum(1 for k, _ in semver_tags if k > pinned_key)
        elif latest_key:
            result["releases_behind"] = None  # untagged pin: distance undefined

    return result


def inspect_worktree(mod: dict, ref: str) -> dict:
    """Compare a submodule's checked-out HEAD against the gitlink. Offline."""
    result = {
        "name": mod["name"],
        "path": mod["path"],
        "url": mod["url"],
        "pinned_sha": None,
        "checkout_sha": None,
        "checkout_describe": None,
        "dirty": False,
        "state": "unknown",
        "error": None,
    }

    result["pinned_sha"] = pinned_sha(mod["path"], ref)
    if result["pinned_sha"] is None:
        result["error"] = f"no gitlink for {mod['path']} at {ref}"
        result["state"] = "no-gitlink"
        return result

    abs_path = os.path.join(REPO_ROOT, mod["path"])

    # An un-`init`'d submodule leaves an EMPTY DIRECTORY behind, and `git -C`
    # inside one does not fail — it walks up and answers from the superproject.
    # Measured while writing this: a fresh clone with only libs/* initialised
    # reported ip65's checkout as 9114ff7 (this repo's own HEAD, described as
    # `v0.3.0-44-g9114ff7-dirty` against ip65's tags), i.e. a confident wrong
    # answer for the precise case the mode exists to catch. So the directory
    # must be confirmed to be its own worktree root before HEAD means anything.
    try:
        toplevel = _git("rev-parse", "--show-toplevel", cwd=abs_path)
    except (subprocess.CalledProcessError, OSError):
        result["state"] = "not-checked-out"
        return result
    if os.path.realpath(toplevel) != os.path.realpath(abs_path):
        result["state"] = "not-checked-out"
        return result

    try:
        result["checkout_sha"] = _git("rev-parse", "HEAD", cwd=abs_path)
    except (subprocess.CalledProcessError, OSError):
        result["state"] = "not-checked-out"
        return result

    # `--tags` is not optional here. Without it `git describe` sees annotated
    # tags only, which is the exact defect the header documents: c64-x25519's
    # lightweight v0.6.0 renders as `v0.5.0-5-g95fdd70`. This field is a human
    # label only — every verdict below is decided on the SHA.
    try:
        result["checkout_describe"] = _git(
            "describe", "--tags", "--always", "--dirty", cwd=abs_path
        )
    except (subprocess.CalledProcessError, OSError):
        result["checkout_describe"] = result["checkout_sha"][:12]

    try:
        result["dirty"] = bool(_git("status", "--porcelain", cwd=abs_path))
    except (subprocess.CalledProcessError, OSError):
        result["dirty"] = False

    result["state"] = (
        "match" if result["checkout_sha"] == result["pinned_sha"] else "mismatch"
    )
    return result


def render_worktree(rows: list[dict]) -> str:
    lines = []
    for row in rows:
        lines.append(f"{row['path']}")
        if row["error"]:
            lines.append(f"    ERROR: {row['error']}")
            continue
        lines.append(f"    pinned   {row['pinned_sha'][:12]}")
        if row["state"] == "not-checked-out":
            lines.append("    checkout (absent)             <-- NOT CHECKED OUT")
            continue
        marker = {"match": "  (in sync)", "mismatch": "  <-- MISMATCH"}[row["state"]]
        lines.append(
            f"    checkout {row['checkout_sha'][:12]}  "
            f"{row['checkout_describe']}{marker}"
        )
        if row["dirty"]:
            lines.append("             (working tree dirty)")
    if any(r["state"] in ("mismatch", "not-checked-out") for r in rows):
        lines.append("")
        lines.append("Fix with:  git submodule update --init --recursive")
    return "\n".join(lines)


def render(rows: list[dict]) -> str:
    lines = []
    for row in rows:
        lines.append(f"{row['path']}")
        if row["error"]:
            lines.append(f"    ERROR: {row['error']}")
            continue
        pin = row["pinned_tag"] or "(no tag points here)"
        lines.append(f"    pinned   {row['pinned_sha'][:12]}  {pin}")
        if row["latest_tag"]:
            marker = "  <-- DRIFT" if row["drifted"] else "  (current)"
            behind = row["releases_behind"]
            behind_txt = f", {behind} release(s) behind" if behind else ""
            lines.append(
                f"    upstream {row['latest_sha'][:12]}  {row['latest_tag']}"
                f"{marker}{behind_txt}"
            )
        else:
            lines.append("    upstream (no semver tags found)")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when any pin is behind the latest upstream semver tag",
    )
    ap.add_argument(
        "--ref",
        default="HEAD",
        help="git ref whose pins to inspect (default: HEAD)",
    )
    ap.add_argument(
        "--submodule",
        action="append",
        metavar="PATH",
        help="restrict to this submodule path (repeatable)",
    )
    ap.add_argument(
        "--worktree",
        action="store_true",
        help=(
            "offline: compare each submodule's checked-out HEAD against the "
            "gitlink instead of querying upstream tags; exit 1 on any mismatch"
        ),
    )
    args = ap.parse_args(argv)

    mods = parse_gitmodules(os.path.join(REPO_ROOT, ".gitmodules"))
    if args.submodule:
        wanted = set(args.submodule)
        mods = [m for m in mods if m["path"] in wanted]
    if not mods:
        print("no submodules to check", file=sys.stderr)
        return 2

    if args.worktree:
        rows = [inspect_worktree(m, args.ref) for m in mods]
        print(json.dumps(rows, indent=2) if args.json else render_worktree(rows))
        if any(r["error"] for r in rows):
            return 2
        # No --strict gate: a checkout that is not the pinned commit is a broken
        # working tree, not a judgement call about how current a pin should be.
        if any(r["state"] in ("mismatch", "not-checked-out") for r in rows):
            return 1
        return 0

    rows = [inspect(m, args.ref) for m in mods]

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(render(rows))

    if any(r["error"] for r in rows):
        return 2
    if args.strict and any(r["drifted"] for r in rows):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
