#!/usr/bin/env python3
"""Tests for tools/_skip_policy.py -- the involuntary-skip rule itself (#178).

Pure logic: no VICE, no hardware, no build.  Runs under pytest from the repo
root (it is pinned in ``pytest.ini`` ``testpaths``) and standalone::

    python3 tools/test_skip_policy.py

The two things worth guarding here, both of which have a history:

  1. **The opt-out must require the literal "1".**  Bare truthiness makes
     ``C64_ALLOW_SKIP=0`` *enable* the escape hatch, so someone setting 0 to
     shut it off silently disables the whole policy instead.  Every other
     gate in this repo compares to "1"; the cases below pin that.

  2. **The two lanes must not collapse into each other.**  An involuntary
     skip returns 2 and a voluntary one returns 0; a change that makes
     everything fail is as wrong as the vacuous green it replaced.
"""

import io
import os
import subprocess
import sys
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _skip_policy import (  # noqa: E402
    EXIT_CANNOT_RUN,
    EXIT_FAIL,
    EXIT_PASS,
    SkipPolicyError,
    VoluntarySkip,
    cannot_run,
    not_applicable,
    reason_text,
    require,
)

ENV = "C64_TEST_SKIP_POLICY_OPT_OUT"


class _Env:
    """Set (or unset) ENV for the duration of a with-block."""

    def __init__(self, value):
        self.value = value
        self.saved = None

    def __enter__(self):
        self.saved = os.environ.get(ENV)
        if self.value is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = self.value
        return self

    def __exit__(self, *exc):
        if self.saved is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = self.saved
        return False


def _call(value, **kw):
    """cannot_run() with ENV set to `value`; returns (exit code, output)."""
    buf = io.StringIO()
    with _Env(value):
        rc = cannot_run(
            "a prerequisite is missing",
            executed=0,
            total=3,
            certifies="the thing under test",
            opt_out_env=ENV,
            out=buf,
            **kw,
        )
    return rc, buf.getvalue()


# ---------------------------------------------------------------------------
# 1. The opt-out is exactly "1", and nothing else.
# ---------------------------------------------------------------------------

def test_opt_out_unset_is_a_failure():
    rc, out = _call(None)
    assert rc == EXIT_CANNOT_RUN, rc
    assert "COULD NOT RUN" in out
    assert "opt-out honoured" not in out


def test_opt_out_one_is_honoured():
    rc, out = _call("1")
    assert rc == EXIT_PASS, rc
    assert "opt-out honoured" in out
    # The warning survives the opt-out: silencing the exit code must not
    # silence the vacuity notice.
    assert "certifies NOTHING" in out
    assert "NOT because anything passed" in out


def test_opt_out_zero_does_not_open_the_hatch():
    # The regression this file exists for: bare truthiness made "0" enable
    # the opt-out, so setting 0 to CLOSE it disabled the policy instead.
    rc, _ = _call("0")
    assert rc == EXIT_CANNOT_RUN, f"C64_ALLOW_SKIP=0 must not opt out (got {rc})"


def test_opt_out_false_does_not_open_the_hatch():
    rc, _ = _call("false")
    assert rc == EXIT_CANNOT_RUN, f"=false must not opt out (got {rc})"


def test_opt_out_empty_does_not_open_the_hatch():
    rc, _ = _call("")
    assert rc == EXIT_CANNOT_RUN, f"empty must not opt out (got {rc})"


def test_opt_out_tolerates_surrounding_whitespace():
    # A shell export can carry a stray space or a trailing newline (`export
    # C64_ALLOW_SKIP=$(...)` is the usual source of the latter); both are
    # still an explicit 1, and the newline is the case .strip() exists for.
    for value in (" 1 ", "1\n", "\t1", " 1\n"):
        rc, _ = _call(value)
        assert rc == EXIT_PASS, (repr(value), rc)


def test_opt_out_yes_and_true_are_not_one():
    for value in ("yes", "true", "TRUE", "on", "2", "11"):
        rc, _ = _call(value)
        assert rc == EXIT_CANNOT_RUN, f"={value} must not opt out (got {rc})"


def test_no_opt_out_env_means_no_escape_hatch_at_all():
    # The build-failure and contention sites pass opt_out_env=None.  Nothing
    # in the environment may rescue them.
    buf = io.StringIO()
    with _Env("1"):
        rc = cannot_run("the build is broken", executed=0, total=1,
                        certifies="anything", opt_out_env=None, out=buf)
    assert rc == EXIT_CANNOT_RUN, rc
    # Plain containment.  This used to .replace("opt-out honoured", "") first,
    # which deleted the exact phrase the assertion was looking for -- so it
    # could not fail for the defect it targets.
    out = buf.getvalue()
    assert "opt-out" not in out, out
    assert "COULD NOT RUN" in out


# ---------------------------------------------------------------------------
# 2. The two lanes stay distinct.
# ---------------------------------------------------------------------------

def test_not_applicable_is_a_pass_with_a_named_verdict():
    buf = io.StringIO()
    rc = not_applicable("UCI-only (backend=ip65)",
                        certifies="the dual-overlay dispatcher", out=buf)
    assert rc == EXIT_PASS, rc
    out = buf.getvalue()
    assert "NOT APPLICABLE" in out
    assert "certifies NOTHING" in out          # quiet, but never silent
    assert "COULD NOT RUN" not in out


def test_not_applicable_has_no_environment_switch():
    # A voluntary skip is decided by the code's own conditions, so no env
    # var may turn it into a failure or vice versa.
    for value in (None, "0", "1"):
        buf = io.StringIO()
        with _Env(value):
            rc = not_applicable("wrong backend", certifies="x", out=buf)
        assert rc == EXIT_PASS, (value, rc)


def test_the_two_exit_codes_are_distinct():
    # 2 must not collapse onto 1: "could not run" and "a check failed" are
    # different states and callers are documented to tell them apart.
    assert EXIT_CANNOT_RUN == 2
    assert EXIT_PASS == 0


# ---------------------------------------------------------------------------
# 3. The reason string carries its own warning (the pytest -ra channel).
# ---------------------------------------------------------------------------

def test_reason_text_is_self_contained():
    text = reason_text("ca65 not on PATH", executed=0, total=7,
                       certifies="the build-flag stamp", opt_out_env=ENV)
    # Under pytest -ra this string is the ONLY channel that survives, so
    # every part of the warning has to be inside it.
    assert "ca65 not on PATH" in text
    assert "0 of 7 checks executed" in text
    assert "certifies NOTHING about the build-flag stamp" in text
    assert ENV in text
    assert "\n" not in text, "must stay one line for the -ra summary"


def test_require_raises_when_the_prerequisite_is_missing():
    with _Env(None):
        try:
            require(False, "ca65 not on PATH", executed=0, total=7,
                    certifies="the build-flag stamp", opt_out_env=ENV)
        except SkipPolicyError as exc:
            assert "certifies NOTHING" in str(exc)
        else:
            raise AssertionError("require() did not raise")


def test_require_is_silent_when_the_prerequisite_holds():
    with _Env(None):
        require(True, "not reached", executed=1, total=1)


def test_require_still_raises_when_the_opt_out_is_zero():
    """=0 must FAIL, and must not be able to pass by SKIPPING either.

    The obvious spelling of this test -- `except SkipPolicyError: pass` --
    is vacuous against the exact defect it guards.  If _opted_out() ever
    reverts to bare truthiness, `bool("0")` is true, require() takes the
    opt-out branch, calls pytest.skip(), and pytest records this case as
    SKIPPED at exit 0.  The guard converts itself into a green skip under
    precisely the mutation it exists to catch -- the vacuous-skip shape
    #178 exists to kill, inside #178's own implementation.
    Measured: under that mutant this case was `1 skipped`, not a failure.

    So the catch is BaseException-wide.  pytest.outcomes.Skipped derives
    from BaseException, not Exception, which is what let it slip past.
    """
    with _Env("0"):
        try:
            require(False, "ca65 not on PATH", executed=0, total=7,
                    certifies="the build-flag stamp", opt_out_env=ENV)
        except SkipPolicyError:
            pass
        except BaseException as exc:  # noqa: BLE001 - a Skipped here IS the bug
            raise AssertionError(
                f"=0 must fail, not skip or otherwise escape: {exc!r}") from None
        else:
            raise AssertionError("=0 must not suppress the failure")


def test_require_does_not_hand_a_skip_to_a_non_pytest_runner():
    """The opt-out must stay catchable by whoever is actually driving.

    require() asks sys.modules, not `import pytest`: pytest being INSTALLED
    says nothing about pytest DRIVING, and pytest.skip() raises a
    BaseException that a standalone runner's `except Exception` cannot
    catch.  Before this was fixed, `C64_ALLOW_SKIP=1 python3
    tools/test_rig_skip_contract.py` died mid-suite at exit 1 with no
    summary and four runnable tests never run -- an opt-out that reports
    as "a check ran and failed".

    Simulated by hiding pytest from sys.modules for the duration; the real
    lane is any run of these modules as a script.
    """
    saved = sys.modules.pop("pytest", None)
    try:
        with _Env("1"):
            try:
                require(False, "ca65 not on PATH", executed=0, total=7,
                        certifies="the build-flag stamp", opt_out_env=ENV)
            except VoluntarySkip as exc:
                assert isinstance(exc, Exception), "must be catchable as Exception"
                assert "certifies NOTHING" in str(exc), str(exc)
            except BaseException as exc:  # noqa: BLE001
                raise AssertionError(
                    f"opt-out outside pytest must raise VoluntarySkip, got "
                    f"{exc!r}") from None
            else:
                raise AssertionError(
                    "opt-out must not RETURN outside pytest -- the caller would "
                    "run the body as if the prerequisite held")
    finally:
        if saved is not None:
            sys.modules["pytest"] = saved


def test_require_hands_a_skip_to_pytest_when_pytest_is_driving():
    """The other half: with pytest driving, it is still a pytest skip.

    Pinned so the sys.modules fix cannot be "simplified" into never
    skipping at all, which would make the documented escape hatch a lie.
    """
    was_loaded = "pytest" in sys.modules
    import pytest  # noqa: PLC0415 - this test is about pytest specifically

    try:
        with _Env("1"):
            try:
                require(False, "ca65 not on PATH", executed=0, total=7,
                        certifies="the build-flag stamp", opt_out_env=ENV)
            except VoluntarySkip as exc:
                raise AssertionError(
                    f"pytest is driving; the opt-out must be a pytest skip: "
                    f"{exc!r}") from None
            except BaseException as exc:  # noqa: BLE001
                assert type(exc).__name__ == "Skipped", repr(exc)
                assert isinstance(exc, pytest.skip.Exception), repr(exc)
            else:
                raise AssertionError("the opt-out must not RETURN under pytest")
    finally:
        # Do not leave pytest in sys.modules for a standalone run that did
        # not have it there: require() reads sys.modules, so this test would
        # otherwise change how every later test in the file behaves.
        if not was_loaded:
            sys.modules.pop("pytest", None)


# ---------------------------------------------------------------------------
# 4. The standalone runner honours the 0/1/2 contract.
#
# Driven as a SUBPROCESS, because the exit code is the whole contract and
# pytest never collects _standalone() at all.  The target is
# tools/test_rig_skip_contract.py rather than this module: it is the one with
# a genuine could-not-run lane (six tests need the sibling c64_test_harness
# checkout), and driving it from here cannot recurse -- that module has no
# spawner of its own.
# ---------------------------------------------------------------------------

_RIG_CONTRACT = os.path.join(_HERE, "test_rig_skip_contract.py")

# Run a script with c64_test_harness made unimportable, so the six
# https_e2e-dependent tests take the require() path.  A meta_path finder,
# not a PYTHONPATH trick: the sibling is pip-installed, so there is no path
# entry to remove.
_BLOCK_AND_RUN = textwrap.dedent("""
    import runpy, sys
    class _Block:
        def find_spec(self, name, path=None, target=None):
            if name == "c64_test_harness" or name.startswith("c64_test_harness."):
                raise ImportError("blocked by tools/test_skip_policy.py")
            return None
    sys.meta_path.insert(0, _Block())
    sys.argv = [sys.argv[1]]
    runpy.run_path(sys.argv[0], run_name="__main__")
""")


def _run_blocked(script, **env_over):
    env = dict(os.environ)
    for k, v in env_over.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    return subprocess.run([sys.executable, "-c", _BLOCK_AND_RUN, script],
                          capture_output=True, text=True, timeout=180,
                          cwd=os.path.dirname(_HERE), env=env)


def test_standalone_runner_returns_two_for_could_not_run():
    """"Could not run" must not be reported as 1, which means "a check failed".

    Nothing collects _standalone(), so this is the only thing standing
    between the 0/1/2 split and a future edit collapsing it back to
    `return 1 if failed else 0` -- in a PR whose thesis is that a helper
    with no call-site test is just another convention to miss.
    """
    proc = _run_blocked(_RIG_CONTRACT, C64_ALLOW_SKIP=None)
    out = proc.stdout + proc.stderr
    assert proc.returncode == EXIT_CANNOT_RUN, (
        f"a missing prerequisite must be {EXIT_CANNOT_RUN}, not "
        f"{proc.returncode}\n{out}")
    assert "CANNOT RUN" in out, out
    assert "COULD NOT RUN" in out, out          # the vacuity string survives
    assert "passed" in out, "the summary line must still be printed\n" + out


def test_standalone_runner_returns_zero_when_the_opt_out_is_honoured():
    """The opt-out lane, which is where defect D1 crashed the whole runner.

    Before the sys.modules fix this exact invocation died with an uncaught
    pytest Skipped: exit 1, no summary, and the four tests that did not need
    the sibling checkout never ran.
    """
    proc = _run_blocked(_RIG_CONTRACT, C64_ALLOW_SKIP="1")
    out = proc.stdout + proc.stderr
    assert proc.returncode == EXIT_PASS, (
        f"an honoured opt-out must be {EXIT_PASS}, got {proc.returncode}\n{out}")
    assert "Traceback" not in out, "the opt-out must not raise\n" + out
    assert "skipped by explicit opt-out" in out, out
    # The tests that did NOT need the sibling checkout must still have run.
    assert "PASS  test_macos_rig" in out, out


def _standalone() -> int:
    """Run every test_* in this module without pytest.

    Honours the module's own 0/1/2 contract rather than collapsing "could
    not run" onto 1: a SkipPolicyError is exactly the involuntary skip this
    policy calls a 2, and reporting it as 1 ("a check ran and failed") is
    the confusion the exit codes exist to prevent.
    """
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert tests, "FATAL: no tests found -- a matcher that matches nothing"
    failed = cannot = skipped = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except VoluntarySkip as exc:
            skipped += 1
            print(f"  SKIP  {name}: {exc}")
        except SkipPolicyError as exc:
            cannot += 1
            print(f"  CANNOT RUN  {name}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}: {exc!r}")
    passed = len(tests) - failed - cannot - skipped
    tail = ""
    if cannot:
        tail += f", {cannot} COULD NOT RUN"
    if skipped:
        tail += f", {skipped} skipped by explicit opt-out"
    print(f"\n{passed}/{len(tests)} passed{tail}")
    if failed:
        return EXIT_FAIL
    if cannot:
        return EXIT_CANNOT_RUN
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(_standalone())
