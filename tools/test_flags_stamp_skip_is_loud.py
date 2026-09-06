#!/usr/bin/env python3
"""A missing cc65 must not turn tools/test_build_flags_stamp.py green (#177).

That module has eight tests, every one of which shells out to `make`. Each
used to open with

    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return

and a pytest test function that returns None without asserting is a **pass**.
The module is pinned in ``pytest.ini`` ``testpaths``, so on a machine without
cc65 — a CI container, most likely — bare ``pytest`` at the repo root reported

    .......                                                          [100%]
    7 passed in 0.01s

The ``SKIP:`` lines were not even visible: pytest captures stdout on a passing
test and discards it. ``0.01 s`` was the only tell. The standalone runner had
the same hole from the other side, printing ``PASSED: 0 failure(s)`` for a run
in which zero assertions executed.

This matters more than an ordinary silent skip because the invariant being
laundered is ``build/flags.stamp`` itself — what closes CLAUDE.md's two
documented silent-failure modes (a mixed link, and no link at all). If the
enforcement can evaporate on a ``PATH`` accident, the enforcement is a
convention again.

The rule, adopted in #158 and re-closed in PR #172: *an involuntary skip is a
failure; a voluntary skip is allowed but must never be silent.* A missing
toolchain is involuntary.

Method: re-run the suite in a subprocess whose ``PATH`` has had every directory
containing ca65 or ld65 removed — computed from the real ``PATH``, not a
hardcoded ``/usr/bin:/bin``, so it strips the toolchain wherever it is
installed and leaves ``make``/``sh``/``cmp`` alone. Both channels are checked,
because #177 documents the hole on both:

  * standalone — must exit 2 (COULD NOT RUN), not 0
  * pytest     — must not report the cases as passes

Nothing here builds anything: the subject process cannot assemble, which is
the entire point, so this file costs a few hundred milliseconds.

Runs under pytest, and standalone::

    python3 tools/test_flags_stamp_skip_is_loud.py

Exit codes: 0 pass, 1 fail. There is no skip path — this test needs no
toolchain, by construction.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SUBJECT = REPO / "tools" / "test_build_flags_stamp.py"

# The tools whose absence must be loud. Both are needed by every case in the
# subject module; either one missing means nothing can be verified.
TOOLCHAIN = ("ca65", "ld65")

EXIT_CANNOT_RUN = 2


def _path_without_toolchain():
    """A PATH with every directory that provides ca65 or ld65 removed.

    Computed rather than hardcoded: cc65 is under /opt/homebrew/bin here and
    /usr/local/bin or /usr/bin elsewhere, and a hardcoded "/usr/bin:/bin"
    would silently stop stripping anything on a machine that installs it
    there — the test would then pass for the wrong reason, which is the
    class of defect this file exists to catch.
    """
    entries = [e for e in os.environ.get("PATH", "").split(os.pathsep) if e]
    keep = []
    for entry in entries:
        if any((Path(entry) / tool).exists() for tool in TOOLCHAIN):
            continue
        keep.append(entry)
    return os.pathsep.join(keep)


def _env_without_toolchain():
    env = dict(os.environ)
    env["PATH"] = _path_without_toolchain()
    # The opt-out must not be inherited from the developer's shell, or this
    # test would measure the opt-out instead of the default.
    env.pop("C64_ALLOW_SKIP", None)
    return env


def _run(cmd, env):
    return subprocess.run(cmd, cwd=REPO, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def test_the_strip_actually_strips():
    """Guard the guard: prove the stripped PATH really has no toolchain.

    Without this, a PATH-stripping bug makes every assertion below run
    against a machine that CAN build, and they would all pass having tested
    nothing — the same vacuity, one level up.
    """
    stripped = _path_without_toolchain()
    for tool in TOOLCHAIN:
        assert shutil.which(tool, path=stripped) is None, (
            f"{tool} is still reachable on the stripped PATH ({stripped!r}); "
            "every assertion in this module would be vacuous"
        )


def test_standalone_run_without_toolchain_exits_cannot_run():
    """`python3 tools/test_build_flags_stamp.py` with no cc65: exit 2, not 0."""
    proc = _run([sys.executable, str(SUBJECT)], _env_without_toolchain())
    assert proc.returncode == EXIT_CANNOT_RUN, (
        "tools/test_build_flags_stamp.py with no ca65/ld65 on PATH exited "
        f"{proc.returncode}, expected {EXIT_CANNOT_RUN} (COULD NOT RUN). "
        "Exit 0 there is a run that executed zero assertions reporting "
        "itself as a pass; exit 1 would claim a check ran and failed.\n"
        f"--- output ---\n{proc.stdout}"
    )
    assert "COULD NOT RUN" in proc.stdout, (
        "the standalone run did not name its verdict:\n" + proc.stdout
    )
    assert "PASSED" not in proc.stdout, (
        "the standalone run printed PASSED having verified nothing:\n"
        + proc.stdout
    )


def test_pytest_run_without_toolchain_is_not_green():
    """`pytest tools/test_build_flags_stamp.py` with no cc65 must be red.

    A bare `return` from a pytest test is a pass, so this reported
    `7 passed in 0.01s` — and because the module is in pytest.ini
    `testpaths`, that green is what bare `pytest` at the repo root shows.
    """
    env = _env_without_toolchain()
    proc = _run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                 str(SUBJECT)], env)
    if "No module named pytest" in proc.stdout:
        # Not a skip: the standalone channel above already fails this
        # module's defect, and this repo declares no pytest dependency.
        # Assert the fallback rather than returning quietly.
        assert proc.returncode != 0
        return
    assert proc.returncode != 0, (
        "pytest on tools/test_build_flags_stamp.py with no ca65/ld65 exited "
        "0. Every case returned early without asserting, which pytest counts "
        "as a pass, and this module is pinned in pytest.ini testpaths — so "
        "bare `pytest` at the repo root goes green having verified nothing "
        "about the build-flag invariant.\n"
        f"--- output ---\n{proc.stdout}"
    )
    assert " passed" not in proc.stdout or "failed" in proc.stdout, (
        "pytest reported passes for cases that could not run:\n" + proc.stdout
    )


def test_opt_out_is_explicit_and_still_warns():
    """C64_ALLOW_SKIP=1 may buy exit 0 — never silence.

    The escape hatch exists so a CI lane with no cc65 can stay green *by
    saying so in its own configuration*, which is greppable. It suppresses
    the exit code, never the warning, and it must require exactly "1" — a
    bare-truthiness check would make C64_ALLOW_SKIP=0 turn the policy off.
    """
    env = _env_without_toolchain()
    env["C64_ALLOW_SKIP"] = "1"
    proc = _run([sys.executable, str(SUBJECT)], env)
    assert proc.returncode == 0, (
        "C64_ALLOW_SKIP=1 did not honour the opt-out:\n" + proc.stdout
    )
    assert "certifies NOTHING" in proc.stdout, (
        "the opt-out silenced the vacuity warning; it may only suppress the "
        "exit code:\n" + proc.stdout
    )

    env["C64_ALLOW_SKIP"] = "0"
    proc = _run([sys.executable, str(SUBJECT)], env)
    assert proc.returncode == EXIT_CANNOT_RUN, (
        "C64_ALLOW_SKIP=0 opened the escape hatch. Setting it to 0 is what "
        "someone does to CLOSE it; only the literal \"1\" may open it.\n"
        + proc.stdout
    )


def main() -> int:
    print("=== involuntary skip must be loud (#177) ===")
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:            # noqa: BLE001 — a crash is a fail
            failed += 1
            print(f"  FAIL {name}\n       {type(exc).__name__}: {exc}")
        else:
            print(f"  ok   {name}")
    assert tests, "no tests collected"
    print(f"\n{'FAILED' if failed else 'PASSED'}: {failed} failure(s) "
          f"({len(tests)} executed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
