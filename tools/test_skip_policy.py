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
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _skip_policy import (  # noqa: E402
    EXIT_CANNOT_RUN,
    EXIT_PASS,
    SkipPolicyError,
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
    with _Env("0"):
        try:
            require(False, "ca65 not on PATH", executed=0, total=7,
                    certifies="the build-flag stamp", opt_out_env=ENV)
        except SkipPolicyError:
            pass
        else:
            raise AssertionError("=0 must not suppress the failure")


def _standalone() -> int:
    """Run every test_* in this module without pytest."""
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert tests, "FATAL: no tests found -- a matcher that matches nothing"
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_standalone())
