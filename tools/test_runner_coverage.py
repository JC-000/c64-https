#!/usr/bin/env python3
"""Guard tools/run_all_tests.py's suite coverage (issue #169).

Nothing here touches VICE, hardware or a build; it is pure AST inspection
and runs in milliseconds. It is the sibling of
``tools/test_pytest_boundary.py``, which pins the *pytest* collection
boundary; this one pins the *aggregate runner's* dispatch list, for the
same reason: the failure it prevents is silent by construction.

``tools/run_all_tests.py`` dispatches a hardcoded list of suite names. A
new ``tools/test_*.py`` that defines a module-level ``run_tests()`` — the
runner's own interface — is therefore only ever run if somebody
remembers to wire it in. Nothing noticed when that drifted, and what it
drifted past was not incidental: the omitted suites were
``test_hs_sequence`` (issue #152, a working server-impersonation
exploit), ``test_ecdh_zero_check`` (#153), ``test_finished_verify`` (the
suite an audit demanded because the server-Finished path had no test at
all) and ``test_tls_deframer``. A runner that prints a confident TOTAL
over a list nobody maintains is worse than no runner, because the number
looks like coverage.

The invariant, in one line: **every ``tools/test_*.py`` that defines a
module-level ``run_tests()`` is either dispatched by the runner or named
on the runner's explicit, commented ``UNDISPATCHED_SUITES`` list.**

Five checks, and every one of them is written to fail loudly rather than
find nothing:

1. The runner still has the shape this guard reads — ``SUITE_ORDER``,
   ``UNDISPATCHED_SUITES``, and a ``run_test_suite`` whose body is an
   ``if name == "..."`` chain. If any of those is gone the guard says so
   and names what it could not find, instead of quietly matching zero
   arms and passing.
2. ``SUITE_ORDER`` and the dispatch arms are the same set of names, in
   both directions. A name with no arm never runs; an arm no name
   selects is dead code that reads as coverage.
3. An unrecognised suite name is a hard error in the runner, not a
   silent ``0/0``.
4. Every module with a ``run_tests()`` entry point is dispatched or
   excluded.
5. Exclusions are live (the module exists and really does define
   ``run_tests()``) and carry a real reason, so the list cannot rot into
   a blanket amnesty.

The anti-vacuity anchor is check 4's shape rather than a hardcoded
count: the set of modules named by the dispatch arms must be a *subset*
of the set discovered by scanning ``tools/``. If the scanner ever
stopped finding files, that subset relation breaks and the guard goes
red — a scan that finds nothing can no longer produce a pass. Counts are
deliberately absent; they are what rotted in the first place.

Runs under pytest, and standalone for anyone without pytest installed
(the repo declares no pytest dependency)::

    python3 tools/test_runner_coverage.py
"""

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
RUNNER = TOOLS / "run_all_tests.py"

# The runner's interface: a module-level `def run_tests(transport, labels, ...)`.
ENTRY_POINT = "run_tests"
# The function holding the `if name == "..."` dispatch chain.
DISPATCH_FN = "run_test_suite"
# Module-level constants the runner must keep for this guard to read it.
ORDER_CONST = "SUITE_ORDER"
EXCLUSION_CONST = "UNDISPATCHED_SUITES"
# An exclusion has to say *why*. A bare word is not a reason.
MIN_REASON_CHARS = 40


class GuardParseError(AssertionError):
    """The runner no longer has the shape this guard reads.

    Deliberately an AssertionError subclass so pytest and the standalone
    main() below both report it as a failure. A restructured runner must
    make this guard go red and be re-taught, never make it pass by
    matching nothing.
    """


def _is_function(node):
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))


def _runner_tree():
    if not RUNNER.exists():
        raise GuardParseError(
            f"{RUNNER.relative_to(REPO)} does not exist. This guard exists "
            "to pin that runner's suite list; if the runner was renamed or "
            "removed, re-point or retire the guard deliberately."
        )
    return ast.parse(RUNNER.read_text(), filename=str(RUNNER))


def _str_constants(node):
    """The str elements of a List/Tuple literal, or None if it is not one."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    out = []
    for elt in node.elts:
        if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
            return None
        out.append(elt.value)
    return out


def _module_level_assign(tree, name):
    """The value node of a module-level `name = <literal>`, or None."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if name in targets:
                return node.value
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                return node.value
    return None


def suite_order():
    """The runner's ordered suite names, from its `SUITE_ORDER` constant."""
    value = _module_level_assign(_runner_tree(), ORDER_CONST)
    if value is None:
        raise GuardParseError(
            f"{RUNNER.relative_to(REPO)} has no module-level "
            f"`{ORDER_CONST}`. That constant is the single source of truth "
            "for which suites the aggregate run covers, and this guard "
            "reads it by AST. If the runner now expresses its suite list "
            "some other way, teach this guard the new shape — do not let "
            "it match nothing (issue #169)."
        )
    names = _str_constants(value)
    if not names:
        raise GuardParseError(
            f"`{ORDER_CONST}` in {RUNNER.relative_to(REPO)} is not a "
            "non-empty list/tuple of string literals, so this guard cannot "
            "read the suite list statically. Keep it a plain literal."
        )
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise GuardParseError(
            f"`{ORDER_CONST}` repeats suite name(s) {dupes}; each suite "
            "runs once."
        )
    return names


def excluded_suites():
    """`UNDISPATCHED_SUITES` as {module_stem: reason}."""
    value = _module_level_assign(_runner_tree(), EXCLUSION_CONST)
    if value is None:
        raise GuardParseError(
            f"{RUNNER.relative_to(REPO)} has no module-level "
            f"`{EXCLUSION_CONST}`. A suite that is deliberately not "
            "dispatched must be named there with a reason; an empty dict "
            "is the correct value when there are none. Its absence is not "
            "read as 'no exclusions', because that would let a rename turn "
            "this guard into a rubber stamp."
        )
    if not isinstance(value, ast.Dict):
        raise GuardParseError(
            f"`{EXCLUSION_CONST}` in {RUNNER.relative_to(REPO)} is not a "
            "dict literal of {module: reason}; this guard reads it by AST."
        )
    out = {}
    for k, v in zip(value.keys, value.values):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
            raise GuardParseError(
                f"`{EXCLUSION_CONST}` has a non-string key; keys are "
                "tools/ module stems such as 'test_tls_deframer'."
            )
        if not (isinstance(v, ast.Constant) and isinstance(v.value, str)):
            raise GuardParseError(
                f"`{EXCLUSION_CONST}['{k.value}']` is not a string literal. "
                "Every exclusion states its reason inline, so a reader of "
                "the runner sees it without chasing a commit."
            )
        out[k.value] = v.value
    return out


def _dispatch_chain():
    """The `if name == "..."` If-nodes inside run_test_suite, in source order."""
    tree = _runner_tree()
    fn = next((n for n in tree.body
               if _is_function(n) and n.name == DISPATCH_FN), None)
    if fn is None:
        raise GuardParseError(
            f"{RUNNER.relative_to(REPO)} has no module-level "
            f"`def {DISPATCH_FN}(...)`. This guard reads the suite->module "
            "wiring out of that function's `if name == \"...\"` chain."
        )
    arms = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not (isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name) and test.left.id == "name"
                and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
                and len(test.comparators) == 1
                and isinstance(test.comparators[0], ast.Constant)
                and isinstance(test.comparators[0].value, str)):
            continue
        arms.append(node)
    if not arms:
        raise GuardParseError(
            f"found no `if name == \"...\"` arms in {DISPATCH_FN}(). Either "
            "the runner dispatches nothing (a real defect) or it no longer "
            "dispatches this way (teach the guard). Matching zero arms is "
            "never a pass."
        )
    return arms


def dispatched_modules():
    """{suite name: module stem} from run_test_suite's dispatch arms."""
    out = {}
    for arm in _dispatch_chain():
        suite = arm.test.comparators[0].value
        # Only this arm's own statements — never its `orelse`, which is
        # the next elif.
        modules = [
            stmt.module for stmt in arm.body
            if isinstance(stmt, ast.ImportFrom) and stmt.module
            and stmt.module.startswith("test_")
            and any(a.name == ENTRY_POINT for a in stmt.names)
        ]
        if len(modules) != 1:
            raise GuardParseError(
                f"dispatch arm `name == \"{suite}\"` in {DISPATCH_FN}() has "
                f"{len(modules)} `from test_* import {ENTRY_POINT}` "
                "statement(s); this guard expects exactly one, which is how "
                "it maps a suite name to the module that actually runs."
            )
        if suite in out:
            raise GuardParseError(
                f"suite name {suite!r} is tested by more than one dispatch "
                f"arm in {DISPATCH_FN}(); only the first can ever run."
            )
        out[suite] = modules[0]
    return out


def entry_point_modules():
    """tools/test_*.py module stems defining a module-level run_tests()."""
    found = []
    for path in sorted(TOOLS.glob("test_*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        if any(_is_function(n) and n.name == ENTRY_POINT for n in tree.body):
            found.append(path.stem)
    return found


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def test_runner_has_the_shape_this_guard_reads() -> None:
    """Every parse the other checks rely on, asserted up front by name.

    Each accessor raises GuardParseError naming what it could not find,
    so a restructured runner produces one legible failure here rather
    than four mysteriously-empty sets below.
    """
    suite_order()
    excluded_suites()
    dispatched_modules()
    assert entry_point_modules(), (
        f"scanned {TOOLS.relative_to(REPO)}/test_*.py and found no module "
        f"defining a module-level `{ENTRY_POINT}()`. The repo has many, so "
        "this is the guard's own scanner failing, not a clean tree."
    )


def test_suite_order_and_dispatch_arms_agree() -> None:
    """A name with no arm never runs; an arm no name selects is dead."""
    ordered = set(suite_order())
    armed = set(dispatched_modules())
    unarmed = sorted(ordered - armed)
    unreachable = sorted(armed - ordered)
    assert not unarmed, (
        f"{ORDER_CONST} names suites with no dispatch arm in "
        f"{DISPATCH_FN}(): {unarmed}. They would be scheduled, hit the "
        "chain's else, and error out. Add the arm."
    )
    assert not unreachable, (
        f"{DISPATCH_FN}() has dispatch arms no {ORDER_CONST} entry selects: "
        f"{unreachable}. Dead arms read as coverage and are not. Add them "
        f"to {ORDER_CONST} or delete them."
    )


def test_unknown_suite_name_is_an_error() -> None:
    """The chain must end in a raise, not fall through to 0 passed / 0 failed."""
    arms = _dispatch_chain()
    tail = arms[-1]
    for arm in arms:
        if not (len(arm.orelse) == 1 and isinstance(arm.orelse[0], ast.If)):
            tail = arm
            break
    raises = any(isinstance(n, ast.Raise) for n in ast.walk(ast.Module(
        body=list(tail.orelse), type_ignores=[])))
    assert tail.orelse and raises, (
        f"the `if name == ...` chain in {DISPATCH_FN}() has no final `else` "
        "that raises. A suite name with no arm would then return 0 passed / "
        "0 failed and be counted as a clean pass — the exact vacuous-green "
        "shape this guard exists to prevent."
    )


def _scheduled_modules():
    """Modules actually reachable from a run: an arm AND a SUITE_ORDER entry.

    Deliberately the intersection and not the arm set. An arm alone is not
    coverage — nothing schedules it — so counting it would let a suite be
    dropped from SUITE_ORDER while its orphaned arm kept this guard green.
    """
    arms = dispatched_modules()
    return {mod for suite, mod in arms.items() if suite in set(suite_order())}


def test_every_entry_point_module_is_dispatched_or_excluded() -> None:
    """The invariant. A new run_tests() suite must be wired or explained."""
    known = set(entry_point_modules())
    dispatched = _scheduled_modules()
    excluded = set(excluded_suites())

    # Anti-vacuity anchor, and it needs no magic number: everything the
    # runner dispatches must have been found by the scanner. If the scan
    # ever came back empty (or short), this fails instead of passing.
    unscanned = sorted(dispatched - known)
    assert not unscanned, (
        f"{DISPATCH_FN}() dispatches modules the tools/ scan did not find "
        f"defining `{ENTRY_POINT}()`: {unscanned}. Either those modules lost "
        "their entry point (the runner is broken) or this guard's scanner "
        "is. Both are failures; neither is a pass."
    )

    unlisted = sorted(known - dispatched - excluded)
    assert not unlisted, (
        f"these tools/ modules define `{ENTRY_POINT}()` — the aggregate "
        f"runner's own interface — but {RUNNER.name} neither dispatches "
        f"them nor lists them in {EXCLUSION_CONST}: {unlisted}. They are "
        "invisible to the aggregate TOTAL, which therefore overstates "
        f"coverage. Add each to {ORDER_CONST} with a dispatch arm, or to "
        f"{EXCLUSION_CONST} with a reason (issue #169)."
    )


def test_exclusions_are_live_and_explained() -> None:
    """An exclusion list that outlives its subjects is an amnesty."""
    known = set(entry_point_modules())
    dispatched = _scheduled_modules()
    excluded = excluded_suites()

    stale = sorted(m for m in excluded if m not in known)
    assert not stale, (
        f"{EXCLUSION_CONST} names module(s) that do not exist or no longer "
        f"define `{ENTRY_POINT}()`: {stale}. A stale exclusion silently "
        "widens the next time a module of that name appears. Remove them."
    )

    both = sorted(set(excluded) & dispatched)
    assert not both, (
        f"{EXCLUSION_CONST} names module(s) the runner also dispatches: "
        f"{both}. One of the two statements is a lie; pick one."
    )

    thin = sorted(m for m, why in excluded.items()
                  if len(why.strip()) < MIN_REASON_CHARS)
    assert not thin, (
        f"{EXCLUSION_CONST} entries {thin} give no real reason (under "
        f"{MIN_REASON_CHARS} characters). The point of the list is that a "
        "reader sees why a suite is out without chasing a commit."
    )


def main() -> int:
    print("=== run_all_tests.py suite coverage ===")
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
