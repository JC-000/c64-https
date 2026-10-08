#!/usr/bin/env python3
"""Guard submodule pin coherence: checkout HEAD == gitlink.

``tools/check_upstream_pins.py`` exists solely to catch submodule drift,
and until now it was referenced by no test at all. This repo has no
``.github/`` and no CI, so every gate fires only when a human runs it —
and a gate nobody is reminded to run is how ``libs/nistcurves`` and
``libs/x25519`` each came to sit three releases behind.

What this pins, and what it deliberately does not
-------------------------------------------------
Only ``--worktree``: for each submodule, does the working tree's checked
-out HEAD match the commit the superproject records (the gitlink)? That
is offline, deterministic, and about **this** clone. A mismatch is
always a real local defect — a submodule left on a detached experiment,
a bisect not unwound, an interrupted ``git submodule update`` — and it is
exactly the state in which a build links code that no commit here
describes, so the PRG hash cannot be reproduced by anyone else.

``--strict`` is deliberately NOT wired in. It compares the pin against
the newest upstream *release*, so it goes red the moment any sibling
library tags a version — an event that is not a defect in this repo and
that this repo cannot fix by itself (a bump needs both backends to link
and the KATs to pass). A test that goes red for reasons outside the tree
trains people to ignore it, and an ignored red is worse than no test.
Pin currency is a decision, reviewed when a bump is being considered;
run ``python3 tools/check_upstream_pins.py --strict`` by hand for that.

Each contract sibling is pinned exactly ON a semver tag
------------------------------------------------------------
Every submodule except ``ip65`` (cc65's, which publishes no semver tags) is
a c64-lib-contract sibling, and its pin must be a commit some ``vX.Y.Z`` tag
points at -- annotated or lightweight (c64-x25519 tagged v0.6.0
lightweight). A pin between releases links code that no release describes,
so no release note, CHANGELOG entry or contract version applies to it, and
the CLAUDE.md pin checklist (CONTRACT_DEFINES, ABI_VERSION assert) has
nothing to be checked against. The tags are read from the submodule's own
clone, so this stays offline; a clone with no tags fails with the fetch to
run, rather than passing. No ``branch =`` line either: ``git submodule
update --remote`` would follow it to an untagged tip.

Pure Python, no VICE, no build, no network; runs in well under a second.
Runs under pytest, and standalone for anyone without pytest installed::

    python3 tools/test_pins.py
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHECKER = REPO / "tools" / "check_upstream_pins.py"

sys.path.insert(0, str(REPO / "tools"))
from check_upstream_pins import _SEMVER_RE, parse_gitmodules, pinned_sha  # noqa: E402

# Submodules that are not contract siblings and publish no semver tags.
NOT_A_SIBLING = {"ip65"}


def _is_own_checkout(sub_path):
    """True only if sub_path is the top of its OWN git work tree.

    An uninitialised submodule is an empty directory inside the
    superproject, and `git -C` there walks UP and answers for the
    superproject: its tags, not the submodule's. Reading those produced a
    confident false "no vX.Y.Z tag points at" for a pin that was fine.
    """
    out = subprocess.run(
        ["git", "-C", str(REPO / sub_path), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return False
    return Path(out.stdout.strip()).resolve() == (REPO / sub_path).resolve()


def _local_tags(sub_path):
    """tag name -> commit, from the submodule's own clone (annotated tags
    peeled through %(*objectname), lightweight ones taken as-is). None if
    sub_path is not its own checkout (see _is_own_checkout)."""
    if not _is_own_checkout(sub_path):
        return None
    out = subprocess.run(
        ["git", "-C", str(REPO / sub_path), "for-each-ref", "refs/tags",
         "--format=%(refname:short) %(objectname) %(*objectname)"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    tags = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            tags[parts[0]] = parts[2] if len(parts) == 3 else parts[1]
    return tags


def _run_worktree_check():
    return subprocess.run(
        [sys.executable, str(CHECKER), "--worktree"],
        cwd=str(REPO), capture_output=True, text=True,
    )


def test_checker_exists():
    """The script this suite delegates to must still be there.

    Without this the suite could pass vacuously the day someone renames
    or removes ``check_upstream_pins.py``: the subprocess would fail, and
    a reader skimming a traceback might file it as an environment
    problem rather than a missing gate.
    """
    assert CHECKER.is_file(), f"{CHECKER} is missing"


def test_submodule_checkouts_match_their_gitlinks():
    """``check_upstream_pins.py --worktree`` must exit 0."""
    result = _run_worktree_check()
    assert result.returncode == 0, (
        "submodule checkout(s) differ from the commit this repo pins.\n"
        "A build made here would link code no commit describes, so its "
        "PRG hash is not reproducible.\n"
        "Fix with: git submodule update --init --recursive\n\n"
        f"--- check_upstream_pins.py --worktree (exit "
        f"{result.returncode}) ---\n{result.stdout}{result.stderr}"
    )


def test_contract_siblings_are_pinned_on_a_semver_tag():
    """Each sibling's gitlink is a commit a vX.Y.Z tag points at."""
    mods = parse_gitmodules(str(REPO / ".gitmodules"))
    siblings = [m for m in mods if m["path"] not in NOT_A_SIBLING]
    assert siblings, "no contract siblings found in .gitmodules"
    problems = []
    for m in siblings:
        sha = pinned_sha(m["path"])
        tags = _local_tags(m["path"])
        if sha is None:
            problems.append(f"{m['path']}: no gitlink in HEAD")
            continue
        if tags is None:
            problems.append(
                f"{m['path']}: not initialised (not its own git checkout), so "
                f"its tags cannot be read. Run: git submodule update --init "
                f"{m['path']}")
            continue
        if not tags:
            problems.append(
                f"{m['path']}: the submodule clone has no tags. Run: "
                f"git -C {m['path']} fetch --tags")
            continue
        on = sorted(n for n, c in tags.items() if c == sha and _SEMVER_RE.match(n))
        if not on:
            problems.append(f"{m['path']}: pinned at {sha[:12]}, which no "
                            f"vX.Y.Z tag points at")
    assert not problems, "\n".join(problems)


def test_no_submodule_tracks_a_branch():
    """No `branch =` in .gitmodules: `update --remote` must not pick a tip."""
    # Read the file itself: parse_gitmodules keeps only path and url, so a
    # check through it could never see a branch line.
    tracking, section = [], None
    for raw in (REPO / ".gitmodules").read_text().splitlines():
        line = raw.strip()
        if line.startswith("[submodule"):
            section = line
        elif section and line.partition("=")[0].strip() == "branch":
            tracking.append(section)
    assert not tracking, (
        f"`branch =` set for {tracking}: `git submodule update --remote` would "
        "move these to an untagged branch tip")


def _main():
    passed = failures = 0
    for name, fn in sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    ):
        try:
            fn()
            passed += 1
            print(f"  ok   {name}")
        except AssertionError as e:
            failures += 1
            print(f"  FAIL {name}: {e}")
    print(f"\n{'PASSED' if failures == 0 else 'FAILED'}: {failures} failure(s)")
    from _skip_policy import verdict
    return verdict(passed, failures, certifies="the submodule pins")


if __name__ == "__main__":
    print("=== submodule pin coherence (checkout vs gitlink) ===")
    sys.exit(_main())
