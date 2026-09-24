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
# wrong shape from being merged. It reads every suite and rig by AST and
# finds each place a run can EXIT SUCCESSFULLY, then asks two questions of
# the conditions that lead there:
#
#   PREREQ   Is this success exit reached from a prerequisite branch -- a
#            condition that inspects the environment (os.environ, which(),
#            a path's existence, the platform, a *prereq*/*available*
#            helper, an ImportError handler) rather than a result? Then the
#            exit code must BE a _skip_policy call (`return cannot_run(...)`,
#            `return not_applicable(...)`, `require(...)`), never a literal.
#            A bare `return 0`, `sys.exit(0)` or pytest-test `return` there
#            is the #158/#165/#177 shape -- and so is calling cannot_run()
#            for its printout and then returning 0 anyway, which is why a
#            policy call elsewhere in the branch earns no exemption.
#
#   VACUOUS  Is this success exit justified ONLY by the absence of failures
#            (`0 if failed == 0 else 1`, `1 if failed else 0`, `if failed:
#            return 1` then `return 0`) with nothing, on any path to it,
#            showing that a check actually ran (`total > 0`, a preceding
#            `if total == 0: <exit non-zero>`)? Then zero checks exits 0.
#            That is test_http.py's #178 verdict.
#
# And, anywhere: a raw pytest.skip / skipif / importorskip / skipTest /
# unittest.skip outside _skip_policy is RAWSKIP. require() is the one
# sanctioned route, because it puts the vacuity warning in the reason
# string -- the only channel -ra keeps.
#
# What it cannot see, stated rather than hidden: an exit code held in a
# variable (`return rc`), a zero guard nested in a different block from the
# verdict it protects, a helper that exits on the caller's behalf, and any
# success condition that names a result it never checks (`0 if all_ok`).
# It is a shape guard. It proves the shapes it names are absent; it does
# not prove every suite is honest.

SKIP_GUARD_GLOBS = ("tools/test_*.py", "tests/rig_*.py", "tools/uci/rig_*.py")

# The only module allowed to spell the raw pytest skip: it is the wrapper.
SKIP_GUARD_EXEMPT_MODULES = ("tools/_skip_policy.py",)

# _skip_policy's verbs. A name counts only when it is really the policy:
# imported from _skip_policy, spelled `_skip_policy.<verb>`, or a
# module-level wrapper whose own body calls one of those (the rigs'
# `_cannot_run`). A local `def cannot_run(): return 0` is not the policy.
POLICY_VERBS = frozenset({"cannot_run", "not_applicable", "require",
                          "verdict"})

# (repo-relative path, function name, kind) -> why the shape is legitimate.
# Every entry must still match a finding, or the guard fails: a stale
# exemption is a hole waiting for the next edit to fall into.
SKIP_GUARD_ALLOWLIST = {
    # Offline self-checks of two hardware rigs. Each is straight-line: a
    # dozen-plus UNCONDITIONAL check() calls run before the verdict, so no
    # path reaches `return 0` without them. `failures` is a list the local
    # check() appends to, and nothing counts passes, so the shape reads as
    # VACUOUS to an AST that cannot see that every check is unconditional.
    ("tools/uci/rig_https_live.py", "_selfcheck", "VACUOUS"):
        "straight-line: every check() above the verdict is unconditional",
    ("tools/uci/rig_https_wiki.py", "_selfcheck", "VACUOUS"):
        "straight-line: every check() above the verdict is unconditional",
}

_EXIT_ATTRS = {("sys", "exit"), ("os", "_exit")}
_EXIT_NAMES = {"exit", "quit"}
_RAW_SKIP_ATTRS = {"skip", "skipif", "importorskip", "skipTest",
                   "skipIf", "skipUnless"}
_ENV_HELPER_WORDS = ("prereq", "available", "missing", "supported",
                     "ready", "have_", "has_", "skip_if", "installed")
_PATH_PROBES = {"exists", "is_file", "is_dir", "isfile", "isdir", "access"}


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
        return f.id in _EXIT_NAMES
    return (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
            and (f.value.id, f.attr) in _EXIT_ATTRS)


def _is_raise_systemexit(node):
    return (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
            and _call_name(node.exc) == "SystemExit")


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
        elif _is_raise_systemexit(node) and node.exc.args:
            arg = node.exc.args[0]
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
            names.add(arg.func.id)
    return names


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


_COUNT_WORDS = ("total", "pass", "executed", "ran", "run", "count", "check",
                "test", "case", "assert", "result", "vector", "n_", "num")


def _countish(expr):
    """Does `expr` name a count of things that RAN (not failed, not skipped)?

    Evidence has to be about how much executed. Without this, falling
    through `if not os.path.exists(PRG): exit(1)` -- a `not X` like any
    other -- would certify a verdict that nothing ever counted.
    """
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _countish(expr.left) or _countish(expr.right)  # passed + failed
    if isinstance(expr, ast.Call) and _call_name(expr) == "len" and expr.args:
        expr = expr.args[0]
    if isinstance(expr, ast.Name):
        ident = expr.id
    elif isinstance(expr, ast.Attribute):
        ident = expr.attr
    else:
        return False
    ident = ident.lower()
    if any(bad in ident for bad in ("fail", "err", "skip")):
        return False
    return any(w in ident for w in _COUNT_WORDS)


def _failure_count(expr):
    """Does `expr` name a failure tally (`failed`, `failures`, `total_fail`)?

    VACUOUS is about verdicts built from the ABSENCE of failures. A rig
    that exits 0 on an observation (`if ok_body`, `if status == 200`) is
    judging a result, not counting, and is not this rule's business.
    """
    if isinstance(expr, ast.Call) and _call_name(expr) == "len" and expr.args:
        expr = expr.args[0]
    if isinstance(expr, ast.Name):
        return "fail" in expr.id.lower()
    if isinstance(expr, ast.Attribute):
        return "fail" in expr.attr.lower()
    return False


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
            return "evidence"      # `failed == 0 and total > 0`, `assert tests`
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
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and (
                    (node.value.id == "os" and node.attr in ("environ", "getenv"))
                    or (node.value.id == "sys" and node.attr == "platform")
                    or node.value.id in ("shutil", "platform", "importlib")):
                return True
        if isinstance(node, ast.Call):
            name = _call_name(node).lower()
            if name in _PATH_PROBES or name in ("which", "getenv", "find_spec"):
                return True
            if any(w in name for w in _ENV_HELPER_WORDS):
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
    """Every success exit in `tree`, with its gating conditions.

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
    sites = []

    def pytest_test(func):
        return (func is not None and func.name.startswith("test_")
                and func in tree.body and not _requests_fixtures(func))

    def value_sites(value, node, func, conds, handler):
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
            elif pytest_test(func) and st.value is None:
                sites.append(_Site(st, func, conds, handler))
        for node in ast.walk(st) if not isinstance(
                st, (ast.If, ast.For, ast.While, ast.With, ast.Try,
                     ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                     ast.AsyncFor, ast.AsyncWith)) else ():
            if _is_exit_call(node):
                value_sites(node.args[0] if node.args else None, node, func,
                            conds, handler)
            elif isinstance(node, ast.Raise) and _is_raise_systemexit(node):
                args = node.exc.args
                value_sites(args[0] if args else None, node, func, conds,
                            handler)
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
                is_import = any(n in ("ImportError", "ModuleNotFoundError")
                                for n in names)
                visit_block(h.body, func, conds, handler or is_import)
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
    return sites


def _raw_skip_target(node):
    """True if `node` (a call's func, or a bare decorator) is a raw skip."""
    if not (isinstance(node, ast.Attribute) and node.attr in _RAW_SKIP_ATTRS):
        return False
    base = node.value
    base_name = (base.id if isinstance(base, ast.Name) else
                 base.attr if isinstance(base, ast.Attribute) else "")
    return base_name in ("pytest", "mark", "unittest", "self")


def _raw_skips(tree):
    """pytest/unittest skip spellings that bypass _skip_policy.require().

    CALLS (`pytest.skip(...)`, `self.skipTest(...)`) and DECORATORS
    (`@pytest.mark.skipif(...)`, `@unittest.skip`) only. A bare attribute
    read such as `isinstance(exc, pytest.skip.Exception)` skips nothing.
    """
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _raw_skip_target(node.func):
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


def skip_policy_findings(source, rel):
    """(findings, stats) for one module's source. Pure; unit-testable.

    Each finding is (rel, lineno, function-name, kind, detail).
    """
    tree = ast.parse(source, filename=rel)
    findings = []
    sites = _collect_sites(tree)
    policy = _policy_names(tree)
    stats = {"sites": len(sites), "policy_calls": 0, "vacuity_checked": 0}
    stats["policy_calls"] = sum(
        1 for n in ast.walk(tree) if policy[1](n, policy[0]))
    for s in sites:
        fname = s.func.name if s.func is not None else "<module>"
        where = (rel, s.node.lineno, fname)
        prereq = s.prereq_handler or any(
            _is_prereq_test(t) for t, _, enclosing in s.conds if enclosing)
        if prereq:
            findings.append(where + ("PREREQ",
                                     "success exit on a prerequisite branch "
                                     "that does not go through _skip_policy"))
            continue
        kinds = [_classify(t, taken) for t, taken, _ in s.conds]
        if "absence" in kinds or "evidence" in kinds:
            stats["vacuity_checked"] += 1
        if "absence" in kinds and "evidence" not in kinds:
            findings.append(where + ("VACUOUS",
                                     "exit 0 justified only by 'nothing "
                                     "failed'; nothing shows a check ran"))
    if rel not in SKIP_GUARD_EXEMPT_MODULES:
        for n in _raw_skips(tree):
            fn = _enclosing_function(tree, n.lineno)
            findings.append((rel, n.lineno, fn.name if fn else "<module>",
                             "RAWSKIP", "raw skip bypasses "
                             "_skip_policy.require()"))
    return findings, stats


def _skip_guard_scan():
    paths = sorted({p for g in SKIP_GUARD_GLOBS for p in REPO.glob(g)})
    findings, totals = [], {"files": 0, "sites": 0, "policy_calls": 0,
                            "vacuity_checked": 0}
    for path in paths:
        rel = str(path.relative_to(REPO))
        f, stats = skip_policy_findings(path.read_text(), rel)
        findings += f
        totals["files"] += 1
        for k, v in stats.items():
            totals[k] += v
    return findings, totals


# Floors under what the scan must find on this tree. A matcher that
# silently matches nothing is the vacuous-green shape one level up (#178,
# #161), so each count is pinned at roughly half its measured value: loose
# enough that ordinary churn does not trip it, tight enough that a broken
# glob or a matcher that stopped recognising `sys.exit` does.
#   measured after the #178 sweep: files 64, sites 32, vacuity_checked 15,
#   policy_calls 159. (Before it: sites 72, vacuity_checked 50 -- the sweep
#   turned 40 literal verdicts into verdict() calls, which are not sites.)
SKIP_GUARD_FLOORS = {"files": 32, "sites": 16, "vacuity_checked": 7,
                     "policy_calls": 80}


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
    live = [f for f in findings
            if (f[0], f[2], f[3]) not in SKIP_GUARD_ALLOWLIST]
    assert live == [], (
        "success exits that bypass the involuntary-skip rule "
        "(tools/_skip_policy.py, issue #178):\n" + "\n".join(
            f"  {p}:{ln} in {fn}(): {kind} -- {detail}"
            for p, ln, fn, kind, detail in live)
        + "\nRoute a missing prerequisite through cannot_run()/require(), a "
        "configuration that is out of scope through not_applicable(), and "
        "gate a failure-count verdict on something having run (e.g. "
        "`if total == 0: return cannot_run(...)`)."
    )


def test_skip_guard_allowlist_has_no_stale_entries() -> None:
    """An exemption that matches nothing is a hole for the next edit."""
    findings, _ = _skip_guard_scan()
    hit = {(p, fn, k) for p, _, fn, k, _ in findings}
    stale = sorted(k for k in SKIP_GUARD_ALLOWLIST if k not in hit)
    assert stale == [], f"SKIP_GUARD_ALLOWLIST entries match nothing: {stale}"


# Shapes the guard must flag, and legitimate shapes it must not. These are
# the matcher's own mutation record: each BAD case is one real regression
# (the file it came from is named), each GOOD case one legitimate pattern
# the tree uses today.
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
    # tests/rig_phase*.py _skip() before #180.
    "prereq_return_0": (
        "import shutil\ndef main():\n    if shutil.which('ca65') is None:\n"
        "        print('SKIP: ca65')\n        return 0\n    return 1\n",
        "PREREQ"),
    # test_dns.py's hand-rolled opt-out.
    "env_opt_out_exit_0": (
        "import os, sys\nif os.environ.get('OPT') == '1':\n"
        "    print('EXPLICIT SKIP')\n    sys.exit(0)\n", "PREREQ"),
    # test_build_flags_stamp.py before #177: a pytest `return` is a pass.
    "pytest_bare_return": (
        "import shutil\ndef test_x():\n    if not shutil.which('ld65'):\n"
        "        print('SKIP')\n        return\n    assert True\n", "PREREQ"),
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
    "assert_tests_nonempty": (
        "def main():\n    tests = [1]\n    assert tests, 'none'\n"
        "    failed = 0\n    return 1 if failed else 0\n"),
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
