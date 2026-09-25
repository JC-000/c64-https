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

5. No suite or rig exits successfully from a prerequisite branch without
   going through ``tools/_skip_policy.py``, exits 0 on "nothing failed"
   without evidence that something ran, or spells a raw pytest skip
   (issue #178, part 2). See the section 5 comment for the rules and for
   what the shape guard cannot see.

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


# ---------------------------------------------------------------------------
# 5. The involuntary-skip rule (issue #178, part 2)
# ---------------------------------------------------------------------------
#
#     An involuntary skip is a failure; a voluntary skip is allowed but must
#     never be silent.
#
# tools/_skip_policy.py is the callable form of that rule. A helper on its
# own is just another convention to miss -- which is how #157 reintroduced
# the class one day after #158 swept it -- so this guard is what stops the
# wrong shape from being merged. It reads every suite, rig, the aggregate
# runner and the mutation harnesses by AST, finds each place a run can EXIT
# SUCCESSFULLY, and asks two questions of the conditions that lead there:
#
#   PREREQ   Is this success exit reached from a prerequisite branch -- a
#            condition that inspects the environment (os.environ, which(),
#            a path's existence, the platform, a helper whose NAME says
#            prereq/available/missing/supported/installed, an `except`
#            for ImportError / a skip / Unavailable) rather than a result? Then the exit code must BE a
#            _skip_policy call (`return cannot_run(...)`, `require(...)`),
#            never a literal. A bare `return 0`, `sys.exit(0)` or
#            pytest-test `return` there is the #158/#165/#177 shape -- and
#            so is calling cannot_run() for its printout and then returning
#            0 anyway, which is why a policy call elsewhere in the branch
#            earns no exemption. Nor does evidence (see VACUOUS) anywhere on
#            the path: `if total == 0: exit(2)` followed by `if not
#            which('ca65'): return 0` is the #165 partial-skip shape, and a
#            count that proves SOME checks ran says nothing about the ones
#            the prerequisite branch then skipped.
#
#   VACUOUS  Is this success exit justified ONLY by the absence of failures
#            (`0 if failed == 0 else 1`, `1 if failed else 0`, `if failed:
#            return 1` then `return 0`) with nothing, on any path to it,
#            showing that a check actually ran? Evidence is a positive test
#            on, or a fall-through past a zero test on, an identifier whose
#            underscore-separated words include one of EVIDENCE_WORDS
#            (`total`, `passed`, `executed`, `ran`, ...). Whole words, not
#            substrings: `transport` and `truncate` are not evidence, and
#            neither is a list of COLLECTED tests (`assert tests`), which
#            says nothing about how many passed. test_http.py's #178
#            verdict was this shape.
#
#   RAWSKIP  pytest.skip / skipif / importorskip / skipTest / unittest.skip,
#            `raise unittest.SkipTest`, or the same under an alias (`import
#            pytest as pt`, `from pytest import skip`) outside _skip_policy.
#            require() is the one sanctioned route, because it puts the
#            vacuity warning in the reason string -- the only channel -ra
#            keeps.
#
# KNOWN BLIND SPOTS -- stated rather than hidden. This is a shape guard: it
# proves the shapes above are absent, not that every suite is honest.
#   * an exit code held in a variable (`rc = 0 ... return rc`);
#   * a zero guard in a different block from the verdict it protects, or in
#     a helper the verdict calls;
#   * a helper that exits on its caller's behalf (`def done(): sys.exit(0)`
#     called from a prerequisite branch);
#   * a success condition that names a result it never counts (`0 if all_ok
#     else 1`, `if ok_body: return 0`) -- a verdict on an observation is
#     not this rule's business, so it is not flagged either way;
#   * evidence is WORD matching, so it is only as good as the names:
#     `total = len(TESTS)` counts COLLECTED tests but is treated as
#     evidence, as is any `passed`/`executed`/`ran`/`n_<check-noun>` that
#     does not count what it says; in the other direction a real count
#     with an unlisted name (`ok`, `nPassed` -- no camelCase split, on
#     purpose -- `stats["total"]`) is NOT evidence and reads as VACUOUS.
#     The veto list (dry, first, not, missing, retry, warn, timeout, ...)
#     is finite: a new decoy word gets through until it is added;
#   * bool-valued exits (`sys.exit(failed > 0)`, `return not failures`) and
#     tallies not named fail* (`errs`, `bad`): the verdict is not seen;
#   * a pytest body wrapped in a prerequisite `if` with no early return
#     (`if which('ca65'): <asserts>`) -- the test passes having run nothing;
#   * a prerequisite held in a local first (`have = which(...); if not
#     have: return 0`) -- the condition names only a local;
#   * skip spellings stored in a variable (`sk = pytest.skip`), decorator
#     aliases (`m = pytest.mark; @m.skipif`, `from unittest import skip`),
#     and a NON-call `pytest.mark.skip` in `pytestmark` (bare or in a
#     list); the call form `pytestmark = pytest.mark.skipif(...)` IS seen;
#   * `getattr(sys, "exit")(0)`, `exec`, and any dynamic spelling;
#   * exit functions other than main/_main that are only reached via
#     `sys.exit(fn())` in ANOTHER module;
#   * a prerequisite condition built from a name the helper-word list does
#     not know (`if not can_build(): return 0`).

SKIP_GUARD_GLOBS = ("tools/test_*.py", "tests/rig_*.py", "tools/uci/rig_*.py",
                    "tools/run_all_tests.py", "tools/mutate_*.py")

# The only module allowed to spell the raw pytest skip: it is the wrapper.
SKIP_GUARD_EXEMPT_MODULES = ("tools/_skip_policy.py",)

# _skip_policy's verbs. A name counts only when it is really the policy:
# imported from _skip_policy, spelled `_skip_policy.<verb>`, or a
# module-level wrapper whose own body calls one of those (the rigs'
# `_cannot_run`). A local `def cannot_run(): return 0` is not the policy.
POLICY_VERBS = frozenset({"cannot_run", "not_applicable", "require",
                          "verdict"})

# (path, function, kind, signature) -> why the shape is legitimate. The
# signature is the flagged statement plus its gating conditions (see
# _signature), so an entry exempts exactly ONE site: a new vacuous exit in
# the same function has a different signature, or makes the count exceed
# one, and is reported. Every entry must still match, or the guard fails.
SKIP_GUARD_ALLOWLIST = {
    # Offline self-checks of two hardware rigs. Each is straight-line: a
    # dozen-plus UNCONDITIONAL check() calls run before the verdict, so no
    # path reaches `return 0` without them. `failures` is a list the local
    # check() appends to, and nothing counts passes, so the shape reads as
    # VACUOUS to an AST that cannot see that every check is unconditional.
    # NOTHING RE-CHECKS THAT JUSTIFICATION: the signature pins the exit and
    # its gates, not the check() calls above it. Re-read the function when
    # touching it.
    ("tools/uci/rig_https_live.py", "_selfcheck", "VACUOUS",
     "return 0 <- not(failures)"):
        "straight-line: every check() above the verdict is unconditional",
    ("tools/uci/rig_https_wiki.py", "_selfcheck", "VACUOUS",
     "return 0 <- not(failures)"):
        "straight-line: every check() above the verdict is unconditional",
}

_RAW_SKIP_ATTRS = {"skip", "skipif", "importorskip", "skipTest",
                   "skipIf", "skipUnless"}
_RAW_SKIP_EXC = {"SkipTest", "Skipped"}
# Whole words of a helper's name that make its call a prerequisite probe.
_PREREQ_WORDS = {"prereq", "prereqs", "prerequisite", "prerequisites",
                 "available", "missing", "supported", "installed"}
_PREREQ_PREFIXES = ("have_", "has_", "skip_if")
_PATH_PROBES = {"exists", "is_file", "is_dir", "isfile", "isdir", "access"}
# An `except` for one of these IS a prerequisite branch: a missing module,
# a skip raised further down, or the suites' own "no usable build" error.
# `except VoluntarySkip: return 0` is a hand-rolled opt-out (found in two
# UCI suites on merging #238/#241).
_PREREQ_HANDLERS = {"ImportError", "ModuleNotFoundError", "VoluntarySkip",
                    "SkipTest", "Skipped", "Unavailable"}
# What makes an identifier a count of checks that RAN (see _countish).
# Deliberately narrow: a false "evidence" match silences VACUOUS, so every
# word here has to name executed checks on its own or as a compound.
#   * a word that says "executed" by itself: passed, executed, ran, ...
EVIDENCE_WORDS = {"passed", "passes", "executed", "ran", "succeeded",
                  "successes"}
#   * a count word joined to a check noun: pass_count, n_pass, run_count,
#     check_count, n_checks, vector_count. Neither half counts alone --
#     bare `count`, `pass` and `run` are too common (retry_count,
#     pass_phrase, dry_run).
_COUNT_WORDS = {"count", "n", "num"}
_CHECK_NOUNS = {"pass", "run", "runs", "check", "checks", "test", "tests",
                "case", "cases", "vector", "vectors", "assertion",
                "assertions"}
#   * `total` on its own, or `total_` + check nouns (total_tests).
# Any of these words anywhere in the identifier vetoes it.
_NON_EVIDENCE_WORDS = {"fail", "failed", "failure", "failures", "fails",
                       "err", "error", "errors", "skip", "skipped", "skips",
                       "dry", "first", "not", "missing", "retry", "retries",
                       "warn", "warning", "warnings", "timeout", "timeouts",
                       "out", "slow"}


class _Aliases:
    """How THIS module spells sys/os/pytest/unittest and their functions."""

    def __init__(self, tree=None):
        self.sys = {"sys"}
        self.os = {"os"}
        self.pytest = {"pytest"}
        self.unittest = {"unittest"}
        self.exit_funcs = {"exit", "quit"}      # builtins + `from sys import`
        self.skip_funcs = set()                 # `from pytest import skip`
        self.skip_excs = set(_RAW_SKIP_EXC)     # `from unittest import SkipTest`
        for node in ast.walk(tree) if tree is not None else ():
            if isinstance(node, ast.Import):
                for a in node.names:
                    root, bound = a.name.split(".")[0], a.asname or a.name
                    for mod, bucket in (("sys", self.sys), ("os", self.os),
                                        ("pytest", self.pytest),
                                        ("unittest", self.unittest)):
                        if root == mod:
                            bucket.add(bound.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                for a in node.names:
                    bound = a.asname or a.name
                    if root == "sys" and a.name == "exit":
                        self.exit_funcs.add(bound)
                    if root == "os" and a.name == "_exit":
                        self.exit_funcs.add(bound)
                    if root == "pytest" and a.name in _RAW_SKIP_ATTRS:
                        self.skip_funcs.add(bound)
                    if root in ("pytest", "_pytest", "unittest") and \
                            a.name in _RAW_SKIP_EXC:
                        self.skip_excs.add(bound)


_ALIASES = _Aliases()


def _call_name(call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _is_exit_call(node):
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name):
        return f.id in _ALIASES.exit_funcs
    if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)):
        return False
    return ((f.value.id in _ALIASES.sys and f.attr == "exit")
            or (f.value.id in _ALIASES.os and f.attr == "_exit"))


def _systemexit_arg(node):
    """(True, arg-or-None) if `node` is `raise SystemExit[(...)]`."""
    if not isinstance(node, ast.Raise) or node.exc is None:
        return False, None
    exc = node.exc
    if isinstance(exc, ast.Name) and exc.id == "SystemExit":
        return True, None                              # bare: code 0
    if isinstance(exc, ast.Call) and _call_name(exc) == "SystemExit":
        return True, exc.args[0] if exc.args else None
    return False, None


def _zero_names(tree):
    """Module-level names bound to 0, plus EXIT_PASS from _skip_policy."""
    names = set()
    for st in tree.body:
        if isinstance(st, ast.Assign):
            for tgt in st.targets:
                pairs = []
                if isinstance(tgt, ast.Name):
                    pairs = [(tgt, st.value)]
                elif isinstance(tgt, ast.Tuple) and isinstance(st.value, ast.Tuple):
                    pairs = list(zip(tgt.elts, st.value.elts))
                for t, v in pairs:
                    if (isinstance(t, ast.Name) and isinstance(v, ast.Constant)
                            and v.value == 0 and not isinstance(v.value, str)):
                        names.add(t.id)
        elif isinstance(st, ast.ImportFrom) and st.module == "_skip_policy":
            for alias in st.names:
                if alias.name == "EXIT_PASS":
                    names.add(alias.asname or alias.name)
    return names


def _exit_code_functions(tree):
    """Functions whose return value becomes the process exit code."""
    names = {"main", "_main"}
    for node in ast.walk(tree):
        arg = None
        if _is_exit_call(node) and node.args:
            arg = node.args[0]
        else:
            is_raise, raised = _systemexit_arg(node)
            if is_raise:
                arg = raised
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
            names.add(arg.func.id)
    return names


def _pytest_test_functions(tree):
    """Functions pytest would collect: module-level test_* and test_*
    methods of `class Test*` or of a TestCase subclass."""
    found = [n for n in tree.body if _is_function(n)
             and n.name.startswith("test_") and not _requests_fixtures(n)]
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        bases = [b.attr if isinstance(b, ast.Attribute) else
                 getattr(b, "id", "") for b in cls.bases]
        if not (cls.name.startswith("Test")
                or any(b.endswith("TestCase") for b in bases)):
            continue
        found += [n for n in cls.body
                  if _is_function(n) and n.name.startswith("test_")]
    return found


def _terminates(body):
    last = body[-1] if body else None
    return (isinstance(last, (ast.Return, ast.Raise))
            or (isinstance(last, ast.Expr) and _is_exit_call(last.value)))


def _zero_check_operand(test):
    """X if `test` asserts X is zero/empty (`X == 0`, `not X`, `X < 1`...)."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, op, right = test.left, test.ops[0], test.comparators[0]
        if isinstance(right, ast.Constant) and not isinstance(right.value, str):
            if ((isinstance(op, (ast.Eq, ast.LtE, ast.Is)) and right.value == 0)
                    or (isinstance(op, ast.Lt) and right.value == 1)):
                return left
        if isinstance(left, ast.Constant) and not isinstance(left.value, str):
            if isinstance(op, ast.Eq) and left.value == 0:
                return right
    return None


def _conjuncts(test):
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return [c for v in test.values for c in _conjuncts(v)]
    return [test]


def _disjuncts(test):
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return [c for v in test.values for c in _disjuncts(v)]
    return [test]


def _words(expr):
    """(lower-cased underscore words, from_subscript) of an identifier.

    Name, Attribute, or a string-keyed Subscript (`stats["executed"]`).
    NO camelCase split: it turns `byPass` into `by`+`pass`. Mixed-case
    names therefore stay one word and are not evidence (`nPassed`).
    """
    if isinstance(expr, ast.Call) and _call_name(expr) == "len" and expr.args:
        expr = expr.args[0]
    sub = False
    if isinstance(expr, ast.Name):
        ident = expr.id
    elif isinstance(expr, ast.Attribute):
        ident = expr.attr
    elif (isinstance(expr, ast.Subscript)
          and isinstance(expr.slice, ast.Constant)
          and isinstance(expr.slice.value, str)):
        ident, sub = expr.slice.value, True
    else:
        return None, False
    return {w for w in ident.lower().split("_") if w}, sub


def _countish(expr):
    """Does `expr` name a count of things that RAN (not failed, not skipped)?

    Whole-word match on EVIDENCE_WORDS. `passed + failed` counts, because
    one operand does. Without the evidence requirement, falling through
    `if not os.path.exists(PRG): exit(1)` -- a `not X` like any other --
    would certify a verdict that nothing ever counted.
    """
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _countish(expr.left) or _countish(expr.right)
    words, from_subscript = _words(expr)
    if not words or words & _NON_EVIDENCE_WORDS:
        return False
    if words & EVIDENCE_WORDS:
        return True
    if words & _COUNT_WORDS and words & _CHECK_NOUNS:
        return True
    # `total` alone or with check nouns -- but not as a dict key, where
    # stats["total"] is as likely bytes as checks.
    return (not from_subscript and "total" in words
            and words - {"total"} <= _CHECK_NOUNS)


def _failure_count(expr):
    """Does `expr` name a failure tally (`failed`, `failures`, `total_fail`)?

    VACUOUS is about verdicts built from the ABSENCE of failures. A rig
    that exits 0 on an observation (`if ok_body`, `if status == 200`) is
    judging a result, not counting, and is not this rule's business.
    """
    words, _ = _words(expr)
    return bool(words) and any(w.startswith("fail") for w in words)


def _positive_operand(test):
    """X if `test` asserts X is non-zero (`X > 0`, `X >= 1`, `0 < X`...)."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return None
    left, op, right = test.left, test.ops[0], test.comparators[0]
    if isinstance(right, ast.Constant) and not isinstance(right.value, str):
        if ((isinstance(op, (ast.Gt, ast.NotEq)) and right.value == 0)
                or (isinstance(op, ast.GtE) and right.value == 1)):
            return left
    if isinstance(left, ast.Constant) and not isinstance(left.value, str):
        if isinstance(op, ast.Lt) and left.value == 0:
            return right
    return None


def _classify(test, taken):
    """('evidence' | 'absence' | None) for one gating condition.

    `taken` is True when the site is reached because `test` held, False
    when it is reached because `test` failed.
    """
    if taken:
        parts = _conjuncts(test)
        if any(_countish(_positive_operand(p)) or _countish(p)
               for p in parts):
            return "evidence"      # `failed == 0 and total > 0`, `if passed`
        zeroed = [_zero_check_operand(p) for p in parts]
        if any(_failure_count(z) or _countish(z) for z in zeroed):
            return "absence"       # `0 if failed == 0`, `if executed == 0`
        return None
    # Reached because `test` was FALSE: every disjunct was false.
    parts = _disjuncts(test)
    if any(_countish(_zero_check_operand(p)) for p in parts):
        return "evidence"          # `if total == 0: exit(1)` fell through
    if any(_failure_count(p) or _failure_count(_positive_operand(p))
           for p in parts):
        return "absence"           # `if failed: exit(1)` fell through
    return None


def _is_prereq_test(test):
    """Does this condition inspect the environment rather than a result?"""
    for node in ast.walk(test):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            base, attr = node.value.id, node.attr
            if ((base in _ALIASES.os and attr in ("environ", "getenv"))
                    or (base in _ALIASES.sys and attr == "platform")
                    or base in ("shutil", "platform", "importlib")):
                return True
        if isinstance(node, ast.Call):
            name = _call_name(node).lower()
            if name in _PATH_PROBES or name in ("which", "getenv", "find_spec"):
                return True
            if (set(name.split("_")) & _PREREQ_WORDS
                    or name.startswith(_PREREQ_PREFIXES)):
                return True
    return False


def _policy_names(tree):
    """Callable names in `tree` that genuinely route through _skip_policy."""
    names = set()
    for st in tree.body:
        if isinstance(st, ast.ImportFrom) and st.module == "_skip_policy":
            names |= {a.asname or a.name for a in st.names
                      if a.name in POLICY_VERBS}

    def is_policy_call(node, known):
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        if isinstance(f, ast.Name):
            return f.id in known
        return (isinstance(f, ast.Attribute) and f.attr in POLICY_VERBS
                and isinstance(f.value, ast.Name)
                and f.value.id == "_skip_policy")

    # Module-level wrappers, to a fixed point (a wrapper of a wrapper).
    changed = True
    while changed:
        changed = False
        for st in tree.body:
            if (isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and st.name not in names
                    and any(is_policy_call(n, names) for n in ast.walk(st))):
                names.add(st.name)
                changed = True
    return names, is_policy_call


def _is_zero(node, zero_names):
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return node.value is None or (not isinstance(node.value, str)
                                      and node.value == 0)
    return isinstance(node, ast.Name) and node.id in zero_names


class _Site:
    """One way a run can exit successfully, with the conditions that lead there."""

    def __init__(self, node, func, conds, prereq_handler):
        self.node, self.func, self.conds = node, func, conds
        self.prereq_handler = prereq_handler


def _collect_sites(tree):
    """(success-exit sites, count of ALL exit statements) in `tree`.

    Gating conditions are (test, taken, enclosing) triples: the enclosing
    `if`s (taken = which arm) and an `IfExp` that selects the zero are
    ENCLOSING; a preceding sibling `if` whose body always exits (reaching
    past it means its test was false) and a preceding `assert` are not.
    Only enclosing conditions can make a site a prerequisite branch -- a
    verdict that follows `if not prg.exists(): return cannot_run(...)` is
    not itself on that branch -- but all of them count as evidence.
    """
    zero_names = _zero_names(tree)
    exit_fns = _exit_code_functions(tree)
    pytest_tests = set(_pytest_test_functions(tree))
    sites = []
    exits = [0]

    def value_sites(value, node, func, conds, handler):
        exits[0] += 1
        if isinstance(value, ast.IfExp):
            if _is_zero(value.body, zero_names):
                sites.append(_Site(node, func, conds + [(value.test, True, True)],
                                   handler))
            if _is_zero(value.orelse, zero_names):
                sites.append(_Site(node, func, conds + [(value.test, False, True)],
                                   handler))
        elif _is_zero(value, zero_names):
            sites.append(_Site(node, func, conds, handler))

    def visit_stmt(st, func, conds, handler):
        if isinstance(st, ast.Return):
            if func is not None and func.name in exit_fns:
                value_sites(st.value, st, func, conds, handler)
            elif func in pytest_tests and _is_zero(st.value, set()):
                exits[0] += 1
                sites.append(_Site(st, func, conds, handler))
        for node in ast.walk(st) if not isinstance(
                st, (ast.If, ast.For, ast.While, ast.With, ast.Try,
                     ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                     ast.AsyncFor, ast.AsyncWith)) else ():
            if _is_exit_call(node):
                value_sites(node.args[0] if node.args else None, node, func,
                            conds, handler)
            else:
                is_raise, raised = _systemexit_arg(node)
                if is_raise:
                    value_sites(raised, node, func, conds, handler)
        if isinstance(st, ast.If):
            visit_block(st.body, func, conds + [(st.test, True, True)], handler)
            visit_block(st.orelse, func, conds + [(st.test, False, True)], handler)
        elif isinstance(st, (ast.For, ast.AsyncFor, ast.While)):
            visit_block(st.body, func, conds, handler)
            visit_block(st.orelse, func, conds, handler)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            visit_block(st.body, func, conds, handler)
        elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            visit_block(st.body, func, conds, handler)
            for h in st.handlers:
                names = []
                for t in ([h.type] if not isinstance(h.type, ast.Tuple)
                          else h.type.elts):
                    if isinstance(t, (ast.Name, ast.Attribute)):
                        names.append(t.id if isinstance(t, ast.Name) else t.attr)
                is_prereq = any(n in _PREREQ_HANDLERS for n in names)
                visit_block(h.body, func, conds, handler or is_prereq)
            visit_block(st.orelse, func, conds, handler)
            visit_block(st.finalbody, func, conds, handler)
        elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            visit_block(st.body, st, [], False)
        elif isinstance(st, ast.ClassDef):
            visit_block(st.body, None, [], False)

    def visit_block(body, func, conds, handler):
        local = list(conds)
        for st in body:
            visit_stmt(st, func, local, handler)
            if isinstance(st, ast.If) and _terminates(st.body):
                local = local + [(st.test, False, False)]
            elif isinstance(st, ast.Assert):
                local = local + [(st.test, True, False)]

    visit_block(tree.body, None, [], False)
    return sites, exits[0]


def _raw_skip_target(node):
    """True if `node` (a call's func, or a bare decorator) is a raw skip."""
    if isinstance(node, ast.Name):
        return node.id in _ALIASES.skip_funcs
    if not (isinstance(node, ast.Attribute) and node.attr in _RAW_SKIP_ATTRS):
        return False
    base = node.value
    base_name = (base.id if isinstance(base, ast.Name) else
                 base.attr if isinstance(base, ast.Attribute) else "")
    return (base_name in _ALIASES.pytest or base_name in _ALIASES.unittest
            or base_name in ("mark", "self"))


def _raw_skip_raise(node):
    """`raise unittest.SkipTest(...)`, `raise SkipTest`, `raise
    pytest.skip.Exception(...)` and aliases."""
    if not isinstance(node, ast.Raise) or node.exc is None:
        return False
    exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
    if isinstance(exc, ast.Name):
        return exc.id in _ALIASES.skip_excs
    if isinstance(exc, ast.Attribute):
        if exc.attr in _RAW_SKIP_EXC:
            return True
        return exc.attr == "Exception" and _raw_skip_target(exc.value)
    return False


def _raw_skips(tree):
    """pytest/unittest skip spellings that bypass _skip_policy.require().

    CALLS (`pytest.skip(...)`, `self.skipTest(...)`), DECORATORS
    (`@pytest.mark.skipif(...)`, `@unittest.skip`) and RAISES (`raise
    unittest.SkipTest`). A bare attribute read such as `isinstance(exc,
    pytest.skip.Exception)` skips nothing.
    """
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _raw_skip_target(node.func):
            found.append(node)
        elif _raw_skip_raise(node):
            found.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call) and _raw_skip_target(dec):
                    found.append(dec)
    return found


def _enclosing_function(tree, lineno):
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= lineno <= end and (
                    best is None or node.lineno > best.lineno):
                best = node
    return best


def _signature(site):
    """Line-number-free identity of a site: the exit plus what gates it."""
    conds = []
    for test, taken, _ in site.conds:
        src = ast.unparse(test)
        conds.append(src if taken else f"not({src})")
    node = site.node
    head = ast.unparse(node).splitlines()[0] if not isinstance(
        node, ast.Raise) else "raise SystemExit"
    return f"{head} <- " + " & ".join(conds) if conds else head


def skip_policy_findings(source, rel):
    """(findings, stats) for one module's source. Pure; unit-testable.

    Each finding is (rel, lineno, function-name, kind, detail, signature).
    """
    global _ALIASES
    tree = ast.parse(source, filename=rel)
    saved, _ALIASES = _ALIASES, _Aliases(tree)
    try:
        return _findings(tree, rel)
    finally:
        _ALIASES = saved


def _findings(tree, rel):
    findings = []
    sites, n_exits = _collect_sites(tree)
    policy = _policy_names(tree)
    stats = {"exits": n_exits, "policy_calls": sum(
        1 for n in ast.walk(tree) if policy[1](n, policy[0]))}
    for s in sites:
        fname = s.func.name if s.func is not None else "<module>"
        where = (rel, s.node.lineno, fname)
        kinds = [_classify(t, taken) for t, taken, _ in s.conds]
        evidence = "evidence" in kinds
        prereq = s.prereq_handler or any(
            _is_prereq_test(t) for t, _, enclosing in s.conds if enclosing)
        if prereq:
            findings.append(where + ("PREREQ",
                                     "success exit on a prerequisite branch "
                                     "that does not go through _skip_policy",
                                     _signature(s)))
            continue
        if "absence" in kinds and not evidence:
            findings.append(where + ("VACUOUS",
                                     "exit 0 justified only by 'nothing "
                                     "failed'; nothing shows a check ran",
                                     _signature(s)))
    if rel not in SKIP_GUARD_EXEMPT_MODULES:
        for n in _raw_skips(tree):
            fn = _enclosing_function(tree, n.lineno)
            findings.append((rel, n.lineno, fn.name if fn else "<module>",
                             "RAWSKIP", "raw skip bypasses "
                             "_skip_policy.require()",
                             ast.unparse(n).splitlines()[0]))
    return findings, stats


def _skip_guard_scan():
    paths = sorted({p for g in SKIP_GUARD_GLOBS for p in REPO.glob(g)})
    findings, totals = [], {"files": 0, "exits": 0, "policy_calls": 0}
    for path in paths:
        rel = str(path.relative_to(REPO))
        f, stats = skip_policy_findings(path.read_text(), rel)
        findings += f
        totals["files"] += 1
        for k, v in stats.items():
            totals[k] += v
    return findings, totals


def _apply_allowlist(findings):
    """(live findings, allowlist keys that matched nothing)."""
    budget = {k: 1 for k in SKIP_GUARD_ALLOWLIST}
    live = []
    for f in findings:
        key = (f[0], f[2], f[3], f[5])
        if budget.get(key):
            budget[key] -= 1
        else:
            live.append(f)
    return live, sorted(k for k, left in budget.items() if left)


# Floors under what the scan must find. A matcher that silently matches
# nothing is the vacuous-green shape one level up (#178, #161). Each floor is
# on something migration to _skip_policy does NOT shrink -- files scanned,
# ALL exit statements (a `sys.exit(verdict(...))` still counts), and calls
# into the policy -- at about half its measured value.
#   measured at introduction: files 67, exits 403, policy_calls 172.
SKIP_GUARD_FLOORS = {"files": 33, "exits": 200, "policy_calls": 86}


def test_skip_guard_scan_is_not_vacuous() -> None:
    """The guard must fail loudly when its pattern finds nothing."""
    _, totals = _skip_guard_scan()
    low = {k: (totals[k], floor) for k, floor in SKIP_GUARD_FLOORS.items()
           if totals[k] < floor}
    assert not low, (
        f"the involuntary-skip guard scanned less than it should: {low} "
        "(found, floor). Either the globs stopped matching or the matcher "
        "stopped recognising exit sites -- and a guard that sees nothing "
        "passes everything."
    )


def test_no_involuntary_skip_bypasses_skip_policy() -> None:
    """#178 part 2: the wrong shape cannot be merged."""
    findings, _ = _skip_guard_scan()
    live, _ = _apply_allowlist(findings)
    assert live == [], (
        "success exits that bypass the involuntary-skip rule "
        "(tools/_skip_policy.py, issue #178):\n" + "\n".join(
            f"  {p}:{ln} in {fn}(): {kind} -- {detail}\n      [{sig}]"
            for p, ln, fn, kind, detail, sig in live)
        + "\nRoute a missing prerequisite through cannot_run()/require(), a "
        "configuration that is out of scope through not_applicable(), and "
        "a finished run's tallies through verdict()."
    )


def test_skip_guard_allowlist_has_no_stale_entries() -> None:
    """An exemption that matches nothing is a hole for the next edit."""
    findings, _ = _skip_guard_scan()
    _, stale = _apply_allowlist(findings)
    assert stale == [], f"SKIP_GUARD_ALLOWLIST entries match nothing: {stale}"


def test_skip_guard_allowlist_exempts_one_site_not_a_function() -> None:
    """A second vacuous exit in an allowlisted function is still reported."""
    path, func, kind, sig = next(iter(SKIP_GUARD_ALLOWLIST))
    fake = [(path, 10, func, kind, "", sig), (path, 20, func, kind, "", sig),
            (path, 30, func, kind, "", "return 0 <- not(other)")]
    live, _ = _apply_allowlist(fake)
    assert [f[1] for f in live] == [20, 30], live


# Shapes the guard must flag, and legitimate shapes it must not. These are
# the matcher's own mutation record: each BAD case is one real regression
# (the file it came from is named) or one spelling a review showed it
# missed; each GOOD case is one legitimate pattern the tree uses.
_GUARD_CASES_BAD = {
    # test_http.py:1048 before #178 part 2.
    "bare_verdict": (
        "import sys\ndef main():\n    failed = 0\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "inverted_verdict": (
        "def main():\n    failed = 0\n    return 1 if failed else 0\n",
        "VACUOUS"),
    "early_fail_then_zero": (
        "def main():\n    failed = 0\n    if failed:\n        return 1\n"
        "    return 0\n", "VACUOUS"),
    # test_transcript_large.py: the guard was in the print, not the exit.
    "guard_in_print_only": (
        "import sys\ndef main():\n    total = failed = 0\n"
        "    if failed == 0 and total > 0:\n        print('ok')\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    # run_all_tests.py before this PR.
    "aggregate_total_failed": (
        "import sys\ndef main():\n    total_failed = 0\n"
        "    sys.exit(0 if total_failed == 0 else 1)\n", "VACUOUS"),
    # _countish used to substring-match `ran`/`run`/`test`: `transport`.
    "substring_is_not_evidence": (
        "import sys\ndef main():\n    transport = failed = 0\n"
        "    if not transport:\n        sys.exit(1)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    # A list of COLLECTED tests says nothing about how many passed.
    "collected_list_is_not_evidence": (
        "def main():\n    tests = [1]\n    assert tests, 'none'\n"
        "    failed = 0\n    return 1 if failed else 0\n", "VACUOUS"),
    "sys_alias": (
        "import sys as s\ndef main():\n    failed = 0\n"
        "    s.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "from_sys_import_exit": (
        "from sys import exit as bye\ndef main():\n    failed = 0\n"
        "    bye(0 if failed == 0 else 1)\n", "VACUOUS"),
    # Review 3 (adv237 probe4): words that looked like evidence and are
    # not. Each was NOT flagged at be1f1ba.
    "evidence_word_count_not_run": (
        "import sys\ndef main():\n    count_not_run = failed = 0\n"
        "    if count_not_run == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_word_count_missing": (
        "import sys\ndef main():\n    count_missing = failed = 0\n"
        "    if count_missing == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_word_retry_count": (
        "import sys\ndef main():\n    retry_count = failed = 0\n"
        "    if retry_count == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_word_pass_phrase": (
        "import sys\ndef main():\n    pass_phrase = failed = 0\n"
        "    if pass_phrase == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_word_bypass": (
        "import sys\ndef main():\n    byPass = failed = 0\n"
        "    if byPass == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_word_first_run": (
        "import sys\ndef main():\n    first_run = failed = 0\n"
        "    if first_run == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_word_timeout_count": (
        "import sys\ndef main():\n    timeout_count = failed = 0\n"
        "    if timeout_count == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_word_total_bytes": (
        "import sys\ndef main():\n    total_bytes = failed = 0\n"
        "    if total_bytes == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_key_run": (
        "import sys\ndef main(stats):\n    failed = 0\n"
        "    if stats['run'] == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_key_count": (
        "import sys\ndef main(stats):\n    failed = 0\n"
        "    if stats['count'] == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_key_pass": (
        "import sys\ndef main(stats):\n    failed = 0\n"
        "    if stats['pass'] == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "evidence_key_total": (
        "import sys\ndef main(stats):\n    failed = 0\n"
        "    if stats['total'] == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n", "VACUOUS"),
    "dry_run_gate": (
        "import sys\ndef main(args):\n    failed = 0\n"
        "    if args.dry_run:\n"
        "        sys.exit(0 if failed == 0 else 1)\n    sys.exit(1)\n",
        "VACUOUS"),
    # tests/rig_phase*.py _skip() before #180.
    "prereq_return_0": (
        "import shutil\ndef main():\n    if shutil.which('ca65') is None:\n"
        "        print('SKIP: ca65')\n        return 0\n    return 1\n",
        "PREREQ"),
    # test_dns.py's hand-rolled opt-out.
    "env_opt_out_exit_0": (
        "import os, sys\nif os.environ.get('OPT') == '1':\n"
        "    print('EXPLICIT SKIP')\n    sys.exit(0)\n", "PREREQ"),
    "env_opt_out_bare_raise_systemexit": (
        "import os\nif os.environ.get('OPT') == '1':\n"
        "    raise SystemExit\n", "PREREQ"),
    "os_alias_environ": (
        "import os as o, sys\nif o.environ.get('OPT') == '1':\n"
        "    sys.exit(0)\n", "PREREQ"),
    # test_build_flags_stamp.py before #177: a pytest `return` is a pass.
    "pytest_bare_return": (
        "import shutil\ndef test_x():\n    if not shutil.which('ld65'):\n"
        "        print('SKIP')\n        return\n    assert True\n", "PREREQ"),
    "pytest_return_none": (
        "import shutil\ndef test_x():\n    if not shutil.which('ld65'):\n"
        "        return None\n    assert True\n", "PREREQ"),
    "pytest_method_in_test_class": (
        "import shutil\nclass TestX:\n    def test_x(self):\n"
        "        if not shutil.which('ld65'):\n            return\n"
        "        assert True\n", "PREREQ"),
    # Adversary probes (PR #237 review 2): earlier evidence on the path
    # used to launder a later prerequisite skip -- #165's partial skip.
    "prereq_after_total_guard": (
        "import sys, shutil\nTESTS=[1]\ndef main():\n    total = len(TESTS)\n"
        "    if total == 0:\n        sys.exit(2)\n"
        "    if not shutil.which('ca65'):\n        print('SKIP')\n"
        "        return 0\n    return 1\n", "PREREQ"),
    "prereq_after_assert_total": (
        "import shutil\ndef main():\n    total = 3\n    assert total > 0\n"
        "    if not shutil.which('ca65'):\n        return 0\n    return 1\n",
        "PREREQ"),
    "pytest_prereq_after_total": (
        "import shutil\ndef test_x():\n    total = 1\n    assert total\n"
        "    if not shutil.which('ld65'):\n        return\n    assert True\n",
        "PREREQ"),
    "prereq_with_run_arg": (
        "import shutil\ndef main(run=True):\n"
        "    if run and not shutil.which('x'):\n        return 0\n"
        "    return 1\n", "PREREQ"),
    # tools/test_uci_reply_valid_wait.py / test_uci_abort_recovery.py as
    # merged from #238 / #241: the first opt-out skip returned 0 outright.
    "voluntary_skip_handler_return_0": (
        "def main():\n    for t in TESTS:\n        try:\n            t()\n"
        "        except VoluntarySkip:\n            return 0\n    return 1\n",
        "PREREQ"),
    "import_error_exit_0": (
        "import sys\ntry:\n    import foo\nexcept ImportError:\n"
        "    sys.exit(0)\n", "PREREQ"),
    # A local look-alike is not the policy: it returns 0 like the bug did.
    "shadowed_policy": (
        "import shutil\ndef cannot_run(*a, **k):\n    return 0\n"
        "def main():\n    if shutil.which('ca65') is None:\n"
        "        cannot_run('x')\n        return 0\n    return 1\n",
        "PREREQ"),
    "raw_pytest_skip": (
        "import pytest\ndef test_x():\n    pytest.skip('no')\n", "RAWSKIP"),
    "raw_skipif": (
        "import pytest\n@pytest.mark.skipif(True, reason='x')\n"
        "def test_x():\n    pass\n", "RAWSKIP"),
    "pytest_alias_skip": (
        "import pytest as pt\ndef test_x():\n    pt.skip('no')\n", "RAWSKIP"),
    "from_pytest_import_skip": (
        "from pytest import skip\ndef test_x():\n    skip('no')\n", "RAWSKIP"),
    "raise_unittest_skiptest": (
        "import unittest\ndef test_x():\n"
        "    raise unittest.SkipTest('no')\n", "RAWSKIP"),
    "raise_from_unittest_skiptest": (
        "from unittest import SkipTest\ndef test_x():\n"
        "    raise SkipTest('no')\n", "RAWSKIP"),
}

_GUARD_CASES_GOOD = {
    "total_guard_before_verdict": (
        "import sys\ndef main():\n    total = failed = 0\n"
        "    if total == 0:\n        sys.exit(1)\n"
        "    sys.exit(0 if failed == 0 else 1)\n"),
    "positive_conjunct": (
        "import sys\ndef main():\n    passed = failed = 0\n"
        "    if failed == 0 and passed > 0:\n        sys.exit(0)\n"
        "    sys.exit(1)\n"),
    "zero_guard_via_policy": (
        "from _skip_policy import cannot_run\ndef main():\n"
        "    executed = failures = 0\n"
        "    if failures:\n        return 1\n"
        "    if executed == 0:\n        return cannot_run('x')\n"
        "    return 0\n"),
    "prereq_via_policy": (
        "import shutil\nfrom _skip_policy import cannot_run\ndef main():\n"
        "    if shutil.which('ca65') is None:\n"
        "        return cannot_run('no ca65', opt_out_env='C64_ALLOW_SKIP')\n"
        "    return 1\n"),
    "binop_total_guard": (
        "import sys\ndef main():\n    ran = failed = 0\n"
        "    if ran + failed == 0:\n        sys.exit(2)\n"
        "    return 1 if failed else 0\n"),
    "verdict_helper": (
        "import sys\nfrom _skip_policy import verdict\ndef main():\n"
        "    sys.exit(verdict(1, 0))\n"),
    "skip_exception_attribute": (
        "import pytest\ndef test_x():\n"
        "    assert isinstance(ValueError(), pytest.skip.Exception) is False\n"),
    "observation_verdict": (
        "def main():\n    ok_mem = ok_ret = True\n"
        "    if ok_mem and ok_ret:\n        return 0\n    return 1\n"),
    "helper_returning_zero_count": (
        "import os\ndef check_label(n):\n    if not os.path.exists(n):\n"
        "        return 0\n    return 1\n"),
    "pytest_return_after_assert": (
        "def test_x():\n    out = ''\n    if 'x' in out:\n"
        "        assert out\n        return\n    assert not out\n"),
    # Whole-word evidence, widened in review 2: `pass`/`count`, camelCase,
    # and a string-keyed subscript.
    "n_pass_evidence": (
        "import sys\ndef main():\n    n_pass = failed = 0\n"
        "    if n_pass == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n"),
    "compound_count_evidence": (
        "import sys\ndef main():\n    check_count = failed = 0\n"
        "    if check_count == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n"),
    "subscript_key_evidence": (
        "import sys\ndef main(stats):\n    failed = 0\n"
        "    if stats['executed'] == 0:\n        sys.exit(2)\n"
        "    sys.exit(0 if failed == 0 else 1)\n"),
    # `ready`/`already` are not prerequisite words.
    "ready_is_not_a_prereq_word": (
        "def main():\n    if already_ready():\n        return 0\n    return 1\n"),
    "non_test_class_method": (
        "import shutil\nclass Helper:\n    def test_x(self):\n"
        "        if not shutil.which('ld65'):\n            return\n"),
}


def test_skip_guard_flags_every_known_bad_shape() -> None:
    missed = []
    for name, (src, kind) in _GUARD_CASES_BAD.items():
        kinds = {f[3] for f in skip_policy_findings(src, f"<{name}>")[0]}
        if kind not in kinds:
            missed.append(f"{name}: wanted {kind}, got {sorted(kinds)}")
    assert missed == [], "guard missed known-bad shapes:\n  " + "\n  ".join(missed)


def test_skip_guard_passes_every_legitimate_shape() -> None:
    fired = []
    for name, src in _GUARD_CASES_GOOD.items():
        f = skip_policy_findings(src, f"<{name}>")[0]
        if f:
            fired.append(f"{name}: {[(x[1], x[3]) for x in f]}")
    assert fired == [], "guard fired on legitimate shapes:\n  " + "\n  ".join(fired)


def main() -> int:
    print("=== pytest collection boundary ===")
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
    print(f"\n{'FAILED' if failed else 'PASSED'}: {failed} failure(s)")
    from _skip_policy import verdict
    return verdict(passed, failed,
                   certifies="the pytest collection boundary and the skip-policy guard")


if __name__ == "__main__":
    sys.exit(main())
