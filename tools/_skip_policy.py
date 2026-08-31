#!/usr/bin/env python3
"""_skip_policy.py -- the project's involuntary-skip rule, in one import.

    An involuntary skip is a failure; a voluntary skip is allowed but must
    never be silent.

This repo has closed that class three times (#158 audit commit `7497e48`,
re-found as #165, fixed again in PR #172) because the correct shape was a
convention rather than a callable.  This module is the callable.

Two lanes, and the whole point is that they are different calls:

  * ``cannot_run()`` -- INVOLUNTARY.  A prerequisite the caller asked for is
    missing: no toolchain, no PRG, a failed ``make``, no hardware, no
    fixture.  Nothing was verified, so the run must not read as success.
    Returns ``EXIT_CANNOT_RUN`` (2) -- deliberately distinct from 1 ("a
    check ran and failed") so a caller can tell "broken" from "unproven".

  * ``not_applicable()`` -- VOLUNTARY.  The caller chose a configuration
    this suite does not cover (the other backend, a diagnostic mode).  There
    is genuinely nothing to verify, so exit 0 is honest -- but it is printed
    as a named verdict with its scope spelled out, never as a bare line that
    a reader mistakes for a pass.

Exit-code contract for every caller wired to this module:

    0  PASS, or a declared NOT APPLICABLE, or an acknowledged opt-out
    1  a check ran and FAILED
    2  COULD NOT RUN -- prerequisites missing, nothing was verified

The opt-out
-----------
``cannot_run(..., opt_out_env="C64_ALLOW_SKIP")`` returns 0 when that
variable is set to exactly ``"1"`` -- not merely set, so ``=0`` and
``=false`` do NOT open the hatch.  It still prints the full block: the
opt-out suppresses the exit code, never the warning.  It exists so a CI lane
that legitimately has no hardware can stay green *by saying so in its own
configuration*, which is a decision someone made on purpose and can be
grepped for -- unlike a bare ``return 0`` buried in a prerequisite branch.

The pytest channel
------------------
Under pytest the skip *reason* is the only channel that survives: ``-ra``
(pinned in ``pytest.ini`` ``addopts``) prints that string and nothing else,
and module stdout is swallowed.  So ``reason_text()`` folds the vacuity
warning INTO the reason string rather than printing it alongside, and
``require()`` hands that same string to the failure/skip it raises.  Without
that, an exit-0 opt-out reads as a bare ``3 skipped`` and the warning is
gone.

Usage (script lane)::

    from _skip_policy import cannot_run, not_applicable

    if missing:
        return cannot_run(
            "missing prerequisites: " + "; ".join(missing),
            executed=0, total=TOTAL_CHECKS,
            certifies="the ip65 DHCP path in VICE",
            opt_out_env="C64_ALLOW_SKIP",
        )

    if backend != "uci":
        return not_applicable(
            f"dual-overlay smoke test is UCI-only (backend={backend})",
            certifies="the UCI dual-overlay swap dispatcher",
        )

Usage (pytest lane)::

    from _skip_policy import require

    def test_something():
        require(shutil.which("ca65") is not None,
                "ca65 not on PATH",
                executed=0, total=1,
                certifies="the build-flag stamp",
                opt_out_env="C64_ALLOW_SKIP")
        ...
"""

from __future__ import annotations

import os
import sys
from typing import Optional, TextIO

__all__ = [
    "EXIT_PASS",
    "EXIT_FAIL",
    "EXIT_CANNOT_RUN",
    "SkipPolicyError",
    "reason_text",
    "cannot_run",
    "not_applicable",
    "require",
]

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_CANNOT_RUN = 2


class SkipPolicyError(AssertionError):
    """Raised by require() when an involuntary skip must be a failure.

    Subclasses AssertionError so pytest renders it as a plain failure and so
    a caller that only catches AssertionError still catches it.
    """


def _opted_out(opt_out_env: Optional[str]) -> bool:
    """True only if `opt_out_env` names a variable whose value is exactly "1".

    Bare truthiness would make ``C64_ALLOW_SKIP=0`` and
    ``C64_ALLOW_SKIP=false`` ENABLE the opt-out -- someone setting 0 to shut
    the escape hatch would silently disable the whole policy.  Every other
    gate in this repo (``C64_SKIP_BUILD``, ``C64_SKIP_TEMP_GC``,
    ``C64_NET_TESTS_OPTIONAL``, ``VICE_HTTPS_OK_TO_RUN``) compares to the
    literal "1"; this one does too.  Surrounding whitespace is tolerated
    because a shell export can carry it; nothing else is.
    """
    if not opt_out_env:
        return False
    return os.environ.get(opt_out_env, "").strip() == "1"


def _coverage_clause(executed: Optional[int], total: Optional[int]) -> str:
    if executed is None or total is None:
        return "no checks executed"
    return f"{executed} of {total} checks executed"


def reason_text(
    reason: str,
    *,
    executed: Optional[int] = 0,
    total: Optional[int] = None,
    certifies: Optional[str] = None,
    opt_out_env: Optional[str] = None,
) -> str:
    """Build the one-string reason that carries its own vacuity warning.

    This is the string that must reach pytest's ``-ra`` line, where it is the
    only surviving channel.  It always states the coverage, and it always
    states what the run therefore certifies nothing about.
    """
    parts = [f"COULD NOT RUN: {reason}", _coverage_clause(executed, total)]
    subject = certifies or "the behaviour under test"
    parts.append(f"this run certifies NOTHING about {subject}")
    if opt_out_env:
        parts.append(f"set {opt_out_env}=1 to accept an unverified run")
    return " -- ".join(parts)


def _print_block(
    heading: str,
    reason: str,
    lines: "list[str]",
    out: Optional[TextIO] = None,
) -> None:
    stream = out if out is not None else sys.stdout
    bar = "=" * 60
    print(bar, file=stream)
    print(f"{heading}: {reason}", file=stream)
    for line in lines:
        print(f"  {line}", file=stream)
    print(bar, file=stream)
    try:
        stream.flush()
    except Exception:  # noqa: BLE001 - a closed/odd stream must not mask the verdict
        pass


def cannot_run(
    reason: str,
    *,
    executed: Optional[int] = 0,
    total: Optional[int] = None,
    certifies: Optional[str] = None,
    opt_out_env: Optional[str] = None,
    out: Optional[TextIO] = None,
) -> int:
    """An INVOLUNTARY skip.  Print the standard block, return 2 (or 0 if opted out).

    Returns ``EXIT_CANNOT_RUN`` so the caller can ``return cannot_run(...)``
    straight out of ``main()``.  Returns ``EXIT_PASS`` only when
    ``opt_out_env`` names a variable set to exactly "1" -- and even then the
    block is printed in full.
    """
    subject = certifies or "the behaviour under test"
    opted_out = _opted_out(opt_out_env)
    lines = [
        _coverage_clause(executed, total),
        f"this run certifies NOTHING about {subject}",
    ]
    if opted_out:
        lines.append(
            f"{opt_out_env}=1 is set -- exiting 0 by explicit opt-out, "
            "NOT because anything passed"
        )
        _print_block("COULD NOT RUN (opt-out honoured)", reason, lines, out)
        return EXIT_PASS
    if opt_out_env:
        lines.append(
            f"set {opt_out_env}=1 to accept an unverified run (exit 0 instead of "
            f"{EXIT_CANNOT_RUN})"
        )
    lines.append(f"exit {EXIT_CANNOT_RUN} = could not run (1 would mean a check failed)")
    _print_block("COULD NOT RUN", reason, lines, out)
    return EXIT_CANNOT_RUN


def not_applicable(
    reason: str,
    *,
    certifies: Optional[str] = None,
    out: Optional[TextIO] = None,
) -> int:
    """A VOLUNTARY skip.  Print a named verdict, return 0.

    Use this ONLY when the caller's own configuration puts the subject out of
    scope -- the other backend, a diagnostic mode -- so that there is nothing
    to verify and exit 0 is the honest answer.  If a prerequisite is missing,
    that is ``cannot_run()``, not this.
    """
    subject = certifies or "the behaviour under test"
    lines = [
        "0 of 0 checks executed -- there is nothing here to verify in this "
        "configuration",
        f"this run certifies NOTHING about {subject}",
        "exit 0 = not applicable (a prerequisite that is merely MISSING is "
        f"exit {EXIT_CANNOT_RUN}, not this)",
    ]
    _print_block("NOT APPLICABLE", reason, lines, out)
    return EXIT_PASS


def require(
    condition: object,
    reason: str,
    *,
    executed: Optional[int] = 0,
    total: Optional[int] = None,
    certifies: Optional[str] = None,
    opt_out_env: Optional[str] = None,
) -> None:
    """pytest-side ``cannot_run``: raise unless the prerequisite holds.

    On a false ``condition`` this raises :class:`SkipPolicyError` carrying the
    full ``reason_text()`` -- pytest records a FAILURE, and the reason string
    is self-contained because module stdout does not survive.

    If ``opt_out_env`` is set to exactly "1" it calls ``pytest.skip()``
    with the same self-contained string instead, so the ``-ra`` summary still
    carries the vacuity warning rather than a bare "skipped".
    """
    if condition:
        return
    text = reason_text(
        reason,
        executed=executed,
        total=total,
        certifies=certifies,
        opt_out_env=opt_out_env,
    )
    if _opted_out(opt_out_env):
        try:
            import pytest  # noqa: PLC0415 - optional, only needed on this branch
        except ImportError:
            # No pytest, so there is no skip to record -- and returning would
            # be the worst answer available: the caller would carry on into a
            # test body whose prerequisite is missing, which is the vacuous
            # pass this module exists to prevent.  Fail closed instead.
            raise SkipPolicyError(
                f"{text} [{opt_out_env}=1 is set, but pytest is not installed, "
                "so the skip cannot be recorded; failing closed rather than "
                "running the body as if the prerequisite held]")
        pytest.skip(f"{text} [{opt_out_env}=1 set]")
    raise SkipPolicyError(text)
