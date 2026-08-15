#!/usr/bin/env python3
"""Guard the pytest collection boundary (issue #109).

Nothing here touches VICE, hardware or a build; it is pure AST inspection
and runs in milliseconds. It exists because the failure it prevents is
silent by construction: a file named ``test_*.py`` that pytest collects
zero tests from disappears into a green pass count, and a pure-logic
module that nobody adds to ``testpaths`` never runs at all.

Four invariants, checked in both directions:

1. No rig directory contains ``test_*.py``. Both ``tests/`` and
   ``tools/uci/`` hold manual live-rig scripts (``rig_*.py``); named the
   pytest way they would be walked, collected as zero, and reported as
   nothing. ``tests/`` was renamed by #111, ``tools/uci/`` by its
   follow-up.

2. ``pytest.ini``'s ``norecursedirs`` lists every rig directory. The
   rename is what holds from an arbitrary working directory; the config
   entry is what keeps a root-level run from descending there at all.
   Both halves are load-bearing, so both are pinned.

3. Every path in ``pytest.ini``'s ``testpaths`` exists.

4. ``testpaths`` is exactly the set of ``tools/test_*.py`` modules pytest
   can actually run — that is, modules with at least one module-level
   ``test_*`` function where every such function's parameters all have
   defaults. A parameter without a default is a fixture request, and this
   repo defines no fixtures, so such a module can only ever error.

Runs under pytest, and standalone for anyone without pytest installed
(the repo declares no pytest dependency)::

    python3 tools/test_pytest_boundary.py
"""

import ast
import configparser
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PYTEST_INI = REPO / "pytest.ini"

# Directories of manual live-rig scripts. Every file in each is a `main()`
# program needing hardware, sudo, or a network rig; none of them defines a
# single `def test_`, so pytest collects zero from all of them. They are
# named `rig_*.py` precisely so pytest never walks them looking.
#   tests/     — VICE / bridge rigs (issue #109, PR #111)
#   tools/uci/ — U64E + C64U hardware rigs (the #111 follow-up)
RIG_DIRS = ("tests", "tools/uci")


def _testpaths():
    """The `testpaths` entries from pytest.ini, as repo-relative strings."""
    parser = configparser.ConfigParser()
    parser.read(PYTEST_INI)
    raw = parser.get("pytest", "testpaths")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _is_function(node):
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))


def _module_level_test_functions(path_or_tree):
    """Module-level `def test_*` nodes."""
    tree = path_or_tree
    return [n for n in tree.body if _is_function(n) and n.name.startswith("test_")]


def _unittest_test_methods(tree):
    """`test_*` methods of unittest.TestCase subclasses.

    pytest collects these natively and never fixture-injects their
    arguments, so extra parameters (typically from `@mock.patch`) are not
    a fixture request.
    """
    found = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = []
        for b in node.bases:
            bases.append(b.attr if isinstance(b, ast.Attribute) else
                         getattr(b, "id", ""))
        if not any(b.endswith("TestCase") for b in bases):
            continue
        found += [n for n in node.body
                  if _is_function(n) and n.name.startswith("test_")]
    return found


def _requests_fixtures(fn):
    """True if `fn` has any parameter pytest would try to fill as a fixture.

    pytest ignores parameters that carry defaults, so only the
    non-defaulted positional/keyword-only ones count.
    """
    args = fn.args
    positional = args.posonlyargs + args.args
    n_defaulted = len(args.defaults)
    undefaulted = positional[:len(positional) - n_defaulted] if n_defaulted \
        else positional
    kwonly = [a for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is None]
    return bool(undefaulted or kwonly)


def _pytest_runnable_tools_modules():
    """tools/test_*.py modules pytest could run cleanly, repo-relative."""
    runnable = []
    for path in sorted((REPO / "tools").glob("test_*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        fns = _module_level_test_functions(tree)
        methods = _unittest_test_methods(tree)
        if not fns and not methods:
            continue                      # script-style; pytest sees nothing
        # A bare parameter on a plain module-level function is a fixture
        # request. Decorated ones (@mock.patch and friends) inject their
        # own arguments, so they are not decidable from the AST and are
        # left alone.
        if any(not fn.decorator_list and _requests_fixtures(fn) for fn in fns):
            continue                      # harness-driven; pytest can only error
        runnable.append(str(path.relative_to(REPO)))
    return runnable


def test_rig_dirs_hold_no_pytest_named_files() -> None:
    """A rig directory must not look collectable, because it is not."""
    stray = sorted(
        f"{d}/{p.name}"
        for d in RIG_DIRS
        for p in (REPO / d).glob("test_*.py")
    )
    assert stray == [], (
        f"rig directories contain pytest-named files {stray}, but every file "
        f"in {list(RIG_DIRS)} is a manual live-rig script. pytest would walk "
        "them, collect zero tests, and report nothing. Rename to rig_*.py — "
        "see tests/README.md, tools/uci/README.md and issue #109."
    )


def _norecursedirs():
    """The `norecursedirs` entries from pytest.ini, as a set of strings."""
    parser = configparser.ConfigParser()
    parser.read(PYTEST_INI)
    return set(parser.get("pytest", "norecursedirs").split())


def test_norecursedirs_covers_every_rig_dir() -> None:
    """The rename and the config entry are both load-bearing; pin both.

    The `rig_` prefix is what holds when pytest is invoked from an
    arbitrary working directory. `norecursedirs` is what stops a
    root-level run from descending into a rig directory at all — which
    still matters, because a rig directory may legitimately grow a
    non-rig helper, and because it documents the intent at the one place
    a reader looks.
    """
    missing = sorted(d for d in RIG_DIRS if d not in _norecursedirs())
    assert missing == [], (
        f"pytest.ini norecursedirs omits rig directories: {missing}. A bare "
        "`pytest` from the repo root would descend into them. Add them to "
        "norecursedirs — the rig_*.py naming alone is the other half of this "
        "boundary, not all of it."
    )


def test_every_testpath_exists() -> None:
    """A stale testpaths entry silently shrinks the default run."""
    missing = [p for p in _testpaths() if not (REPO / p).exists()]
    assert missing == [], (
        f"pytest.ini testpaths names paths that do not exist: {missing}. "
        "pytest would skip them without comment, so the default `pytest` run "
        "would quietly cover less than it claims."
    )


def test_testpaths_lists_every_runnable_tools_module() -> None:
    """A new pure-logic suite must not be invisible to a bare `pytest`."""
    listed = {p for p in _testpaths() if p.startswith("tools/")}
    runnable = set(_pytest_runnable_tools_modules())
    unlisted = sorted(runnable - listed)
    assert unlisted == [], (
        f"these tools/ modules are pytest-runnable but absent from "
        f"pytest.ini testpaths: {unlisted}. A bare `pytest` would never run "
        "them. Add them to testpaths."
    )


def test_testpaths_lists_nothing_pytest_cannot_run() -> None:
    """The inverse: a listed module must not error on missing fixtures."""
    listed = {p for p in _testpaths() if p.startswith("tools/")}
    runnable = set(_pytest_runnable_tools_modules())
    broken = sorted(listed - runnable)
    assert broken == [], (
        f"pytest.ini testpaths lists modules pytest cannot run cleanly: "
        f"{broken}. Their test functions take positional arguments supplied "
        "by tools/run_all_tests.py, not fixtures, so pytest reports "
        "'fixture not found' errors. Remove them from testpaths."
    )


def main() -> int:
    print("=== pytest collection boundary ===")
    failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL {name}\n       {exc}")
        else:
            print(f"  ok   {name}")
    print(f"\n{'FAILED' if failed else 'PASSED'}: {failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
