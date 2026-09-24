#!/usr/bin/env python3
"""test_x25519_pin.py — the libs/x25519 submodule pin must be the one we reviewed.

Pure Python. No build, no ca65, no ld65, no VICE, no hardware; it reads
``libs/x25519/src/lib_version.s`` out of the checked-out submodule and
compares two constants against the expectations recorded below. Runs in
milliseconds.

This is a TRIPWIRE, not a correctness proof
-------------------------------------------
It proves nothing about whether the sibling library still works, still
links, or still computes X25519 correctly. All it does is fail when the
submodule checkout stops being the version a human last reviewed, so that
the bump gets read by a person instead of riding in silently. If it is
green, the only thing you know is that nobody moved the pin since the
expectations below were written down.

Why a Python tripwire and not a link-time assert
------------------------------------------------
The obvious guard is the one the contract recommends and that every other
sibling gets — an import plus a deferred assert in a staged source::

    .import LIB_X25519_ABI_VERSION
    .assert LIB_X25519_ABI_VERSION = 4, lderror, "c64-x25519 ABI moved"

That is unreachable here, and not for the reason it first looks like.

The blocker is not that ``lib_version.s`` happens to be unstaged. It is
that the archive carrying it would only ever enter a link under ``make
USE_X25519_SIBLING=1``, and that configuration does not link, on either
backend, by design and by measurement (see the Known issues section of
CLAUDE.md). A guard that can only fire inside a build that never
completes is not a guard. Staging one more file would not change that,
so the whitelist is a choice here, not the constraint.

An assemble-time gate via ``.include`` --- pulling the submodule's
``lib_version.s``, which is pure equates and no code, into a source
that IS always assembled --- was considered and not pursued. No defect
is alleged against that route; the tripwire simply needs no build at
all and runs under ``pytest``, which nothing gated on
``USE_X25519_SIBLING=1`` can. If a later reader wants the gate at
assemble time instead, that is where to start.

So the sibling's version constants are, uniquely among this project's
submodules, outside the reach of any build that actually happens. That
is the gap this file covers, and it covers it in the only place left:
outside the toolchain entirely.

For the record, since the number carries the inertness argument
elsewhere: ``build_x25519.sh:269-279`` copies SIX upstream files, of
which THREE are assembled as translation units (``fe25519.s``,
``x25519.s``, ``x25519_init.s``). The other three — ``constants.s`` and
its two transitive includes ``zp_config.s`` / ``reu_config.s`` — exist
only so the ``.include "constants.s"`` at the top of each of those
three resolves; no ``.o`` is emitted from them. ``lib_version.s`` is in
neither set.

What it reads, and what it does not
-----------------------------------
It parses the two constants that carry meaning for a consumer:

  * ``LIB_X25519_VERSION_MINOR`` — the release the pin names. The library
    is in its 0.x series, so MINOR is where every release lands.
  * ``LIB_X25519_ABI_VERSION`` — c64-lib-contract §1/§7's monotonic
    generation counter for the exported surface. It is the load-bearing
    breakage gate while the library is pre-1.0, precisely because §7 lets
    breaking changes ride a MINOR bump there. It moved 3 -> 4 at
    v0.15.0.

It reads them from the submodule working tree, NOT from a constant baked
into this file and not from ``git ls-tree``, so an unexpected checkout —
including a dirty or manually moved one — is what fails.

PATCH is deliberately not asserted: a PATCH bump by definition carries no
API change, and pinning it would turn every upstream bugfix into a red
test with nothing for a reviewer to decide.

Known limitation: the parser is line-based and does not track ca65
conditional nesting, so it is blind to ``.if`` / ``.ifndef``. Were
upstream ever to move its version block inside a never-taken branch,
this would read the equates as live and pass. Accepted gap, not a
defect --- closing it means implementing enough of ca65's conditional
evaluation to be wrong in a subtler way. Every other failure mode in
this class was attacked and stays red: submodule absent, file missing
or renamed or empty, hex values, undecodable bytes, renamed constants,
the deprecated bare ``LIB_VERSION_MINOR`` alias, commented-out
constants, and duplicate definitions.

When this test goes red
-----------------------
Do not "fix" it by editing the expectations to match. Read what actually
changed upstream first, walk the migration log at the top of
``tools/integration/build_x25519.sh``, re-measure the staged per-source
segment sizes, and only then update ``EXPECTED_*`` here in the same
commit that moves the gitlink.

Runs under pytest, and standalone for anyone without pytest installed
(the repo declares no pytest dependency)::

    python3 tools/test_x25519_pin.py
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LIB_VERSION_S = REPO / "libs" / "x25519" / "src" / "lib_version.s"

# The reviewed pin. Bump these ONLY together with the gitlink, in the same
# commit, after reading what changed. See the module docstring.
EXPECTED_VERSION_MINOR = 16
EXPECTED_ABI_VERSION = 4

# Human-readable name of the reviewed pin, used only in failure messages.
EXPECTED_TAG = "v0.16.0"


def _parse_equates(text):
    """Every `NAME = <int>` equate in a ca65 source, as {name: int}.

    ca65 equates are `NAME = value` at the start of a line. Values here
    are small decimals; anything non-numeric (an alias to another symbol,
    an expression) is skipped rather than guessed at, which is why the
    deprecated bare `LIB_VERSION_MINOR = LIB_X25519_VERSION_MINOR` alias
    lower in the file does not shadow the real one.
    """
    found = {}
    for line in text.splitlines():
        line = line.split(";", 1)[0]          # strip ca65 comments
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\s*$", line)
        if m:
            found[m.group(1)] = int(m.group(2))
    return found


def _equates():
    assert LIB_VERSION_S.exists(), (
        f"{LIB_VERSION_S.relative_to(REPO)} is missing. The libs/x25519 "
        "submodule is not checked out — run `git submodule update --init "
        "--recursive`. This is a real failure, not a skip: an unchecked-out "
        "submodule is exactly the state in which a pin change is invisible."
    )
    return _parse_equates(LIB_VERSION_S.read_text())


def test_version_minor_is_the_reviewed_pin() -> None:
    """The submodule checkout must be the release a human signed off on."""
    eq = _equates()
    name = "LIB_X25519_VERSION_MINOR"
    assert name in eq, (
        f"{name} not found in {LIB_VERSION_S.relative_to(REPO)}. Upstream "
        "renamed or restructured its §1 version block; read the release "
        "notes before touching this test."
    )
    assert eq[name] == EXPECTED_VERSION_MINOR, (
        f"{name} is {eq[name]}, expected {EXPECTED_VERSION_MINOR} "
        f"({EXPECTED_TAG}). The libs/x25519 submodule checkout is not the "
        "reviewed pin. If you moved it deliberately, read what changed "
        "upstream and update EXPECTED_VERSION_MINOR in this file in the "
        "same commit as the gitlink — do not edit it to make this pass."
    )


def test_abi_version_is_the_reviewed_generation() -> None:
    """The contract §1/§7 export-surface generation counter must not have moved.

    This is the assertion that carries the weight. MINOR moves on every
    release including pure-documentation ones; ABI moves only when the
    exported symbol surface breaks, which is the change that could
    actually reach this consumer.
    """
    eq = _equates()
    name = "LIB_X25519_ABI_VERSION"
    assert name in eq, (
        f"{name} not found in {LIB_VERSION_S.relative_to(REPO)}. Upstream "
        "renamed or restructured its §1 version block; read the release "
        "notes before touching this test."
    )
    assert eq[name] == EXPECTED_ABI_VERSION, (
        f"{name} is {eq[name]}, expected {EXPECTED_ABI_VERSION}. The "
        "c64-lib-contract §1/§7 export-surface generation counter moved, "
        "which means an exported symbol was added, removed or renamed "
        "upstream. Audit the three staged sources (fe25519.s, x25519.s, "
        "x25519_init.s) and the BSS/RODATA heredocs in "
        "tools/integration/build_x25519.sh before updating "
        "EXPECTED_ABI_VERSION here."
    )


def _run():
    """Run every module-level test, printing a line each; (passed, failed)."""
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL {name}\n       {exc}")
        else:
            passed += 1
            print(f"  ok   {name}")
    return passed, failed


def run_tests(transport=None, labels=None, seed=None):
    """tools/run_all_tests.py entry point. Returns (passed, failed).

    All three arguments are the runner's uniform signature and all three
    are ignored: this suite needs no VICE transport, no linked labels and
    no RNG seed, because it reads a file on the host. They are accepted
    so the runner can dispatch it like every other suite.

    Dispatched from SUITE_ORDER rather than parked in UNDISPATCHED_SUITES
    deliberately. An UNDISPATCHED note explains the omission once; a
    SUITE_ORDER entry makes tools/test_runner_coverage.py enforce the
    wiring by AST from here on. Without either, this file is reachable
    only by a bare `pytest` --- which is the shape of #169, where suites
    nobody dispatched went unnoticed because nothing asserted they were.
    """
    print("=== libs/x25519 submodule pin ===")
    return _run()


def main() -> int:
    print("=== libs/x25519 submodule pin ===")
    passed, failed = _run()
    print(f"\n{'FAILED' if failed else 'PASSED'}: {failed} failure(s)")
    from _skip_policy import verdict
    return verdict(passed, failed, certifies="the libs/x25519 pin")


if __name__ == "__main__":
    sys.exit(main())
