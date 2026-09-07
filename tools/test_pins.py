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

Pure Python, no VICE, no build, no network; runs in well under a second.
Runs under pytest, and standalone for anyone without pytest installed::

    python3 tools/test_pins.py
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHECKER = REPO / "tools" / "check_upstream_pins.py"


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


def _main():
    failures = 0
    for name, fn in sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    ):
        try:
            fn()
            print(f"  ok   {name}")
        except AssertionError as e:
            failures += 1
            print(f"  FAIL {name}: {e}")
    print(f"\n{'PASSED' if failures == 0 else 'FAILED'}: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    print("=== submodule pin coherence (checkout vs gitlink) ===")
    sys.exit(_main())
