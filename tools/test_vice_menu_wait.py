#!/usr/bin/env python3
"""Every VICE suite's boot-menu wait goes through ``_vice_helpers.menu_wait``.

A comb image runs the boot precompute before the menu, which outlasts the
suites' built-in waits under VICE. Before this, five suites read
``C64_INIT_TIMEOUT``, one read ``C64_INIT_WAIT`` (the name the rigs and
CLAUDE.md use) and the rest hardcoded 60-180 s, so no single setting could
run the set against a comb image: the rest failed "Main menu did not
appear" for a reason that looked like a regression.

Pure Python, no VICE, no build. Runs under pytest and standalone.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from _vice_helpers import menu_wait  # noqa: E402


def _suites():
    """Every tools/ script, not only the test_*.py suites: benches and
    diagnostics launch VICE and wait for the menu too."""
    return sorted(TOOLS.rglob("*.py"))


def _is_menu_wait(node, assigned):
    if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "menu_wait":
        return True
    return isinstance(node, ast.Name) and node.id in assigned


def hardcoded_menu_waits():
    """(file:line) of every wait_for_text(..., "Q=QUIT", ...) in tools/ whose
    timeout is not menu_wait(...) or a name bound from it."""
    bad = []
    for path in _suites():
        tree = ast.parse(path.read_text(), str(path))
        # module-level constants holding the menu needle count as the literal
        needles = {t.id for n in tree.body if isinstance(n, ast.Assign)
                   and isinstance(n.value, ast.Constant) and n.value.value == "Q=QUIT"
                   for t in n.targets if isinstance(t, ast.Name)}
        assigned = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign)
                    and isinstance(n.value, ast.Call)
                    and getattr(n.value.func, "id", None) == "menu_wait"
                    for t in n.targets if isinstance(t, ast.Name)}
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call)
                    and getattr(n.func, "id", None) == "wait_for_text"
                    and any((isinstance(a, ast.Constant) and a.value == "Q=QUIT")
                            or (isinstance(a, ast.Name) and a.id in needles)
                            for a in n.args)):
                continue
            timeout = next((k.value for k in n.keywords if k.arg == "timeout"),
                           None)
            if timeout is None or not _is_menu_wait(timeout, assigned):
                bad.append(f"{path.name}:{n.lineno}")
    return bad


def unvalidated_menu_waits():
    """Files with a menu wait that never validate the override before VICE
    starts (via default_vice_config or require_menu_wait_env): a bad value
    there would surface as a traceback from inside a live session."""
    bad = []
    for path in _suites():
        tree = ast.parse(path.read_text(), str(path))
        calls = {getattr(n.func, "id", None) for n in ast.walk(tree)
                 if isinstance(n, ast.Call)}
        if "menu_wait" in calls and path.name not in (
                "_vice_helpers.py", Path(__file__).name) and not (
                calls & {"default_vice_config", "require_menu_wait_env"}):
            bad.append(path.name)
    return bad


def test_every_menu_wait_is_validated_before_launch():
    bad = unvalidated_menu_waits()
    assert not bad, f"menu_wait used without a pre-launch check: {bad}"


def test_no_suite_hardcodes_its_menu_wait():
    bad = hardcoded_menu_waits()
    assert not bad, ("boot-menu waits not routed through "
                     f"_vice_helpers.menu_wait: {bad}")


def test_default_when_unset():
    assert menu_wait(120, env={}) == 120.0
    assert menu_wait(60, env={"C64_INIT_WAIT": ""}) == 60.0


def test_wait_and_alias_both_raise_it():
    assert menu_wait(120, env={"C64_INIT_WAIT": "900"}) == 900.0
    assert menu_wait(120, env={"C64_INIT_TIMEOUT": "900"}) == 900.0
    assert menu_wait(120, env={"C64_INIT_WAIT": "900",
                               "C64_INIT_TIMEOUT": "900.0"}) == 900.0


def _raises(env):
    try:
        menu_wait(120, env=env)
    except ValueError:
        return True
    return False


def test_bad_values_are_refused_not_ignored():
    assert _raises({"C64_INIT_WAIT": "ten minutes"})
    assert _raises({"C64_INIT_TIMEOUT": "0"})
    assert _raises({"C64_INIT_WAIT": "-5"})
    assert _raises({"C64_INIT_WAIT": "nan"})
    assert _raises({"C64_INIT_TIMEOUT": "inf"})
    assert _raises({"C64_INIT_WAIT": "600", "C64_INIT_TIMEOUT": "900"})


if __name__ == "__main__":
    from _skip_policy import verdict
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                passed += 1
                print(f"  ok   {name}")
            except AssertionError as exc:
                failed += 1
                print(f"  FAIL {name}: {exc}")
    sys.exit(verdict(passed, failed,
                     certifies="every VICE suite's boot-menu wait honours C64_INIT_WAIT"))
