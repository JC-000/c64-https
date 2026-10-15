"""Make the boundary of a pytest run impossible to misread.

c64-https is an assembly project. Its real test suites drive VICE or real
Ultimate 64 hardware and are launched by `python3 tools/run_all_tests.py`
and by the manual rig scripts in `tests/` and `tools/uci/` — not by
pytest. Only a few
pure-logic host-side modules are pytest-runnable, and `pytest.ini` pins
`testpaths` to exactly those.

Without this file, `pytest` at the repo root prints a bare pass count that
reads like whole-project coverage. It is not. See issue #109.

This module deliberately contains no fixtures, no skips and no imports of
pytest: it must stay inert for anyone who does not have pytest installed,
and the repo declares no pytest dependency.
"""

from pathlib import Path

_BOUNDARY = [
    "c64-https: pytest runs ONLY the pure-logic host-side modules pinned in",
    "pytest.ini `testpaths`. It does NOT run the C64 suites (those need VICE:",
    "`python3 tools/run_all_tests.py`) and it does NOT run the live-rig",
    "scripts in tests/ (sudo + network rig) or tools/uci/ (real U64E/C64U",
    "hardware). A green run here says nothing about any of them.",
]

_EMPTY_RUN = [
    "pytest collected nothing from the paths you gave it.",
    "If that was `pytest tests/` or `pytest tools/uci/`: both hold manual",
    "live-rig scripts (rig_*.py, main() programs needing sudo + a network",
    "rig, or real U64E/C64U hardware), not pytest tests. See",
    "tests/README.md and tools/uci/README.md for how to run them.",
]


def pytest_report_header(config):
    """Printed in the header of every pytest invocation."""
    return _BOUNDARY


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Repeat the boundary immediately above the final pass/fail line.

    The header scrolls away on a long run; the summary line is the thing
    people actually read, so the caveat has to sit next to it.
    """
    write = terminalreporter.write_line
    terminalreporter.write_sep("=", "scope of this run")
    for line in _BOUNDARY:
        write(line)
    # pytest.ExitCode.NO_TESTS_COLLECTED == 5, spelled numerically so this
    # file never has to import pytest.
    if exitstatus == 5:
        write("")
        for line in _EMPTY_RUN:
            write(line)


# Six modules execute the shipped UCI bytes. Give them a fresh private UCI
# build (tools/_private_uci_build.py) so a bare pytest is green on any build/
# (#302). The build dir reaches them through C64_UCI_BUILD_DIR, which their
# PRG/LABELS read at use, so no import mode (default, append, importlib) can
# leave them on a stale build/. Unset under pytest they fail closed. A build
# that fails raises here, once per run, with make's error as the reason ->
# pytest ERROR on every selected test, never a skip (#178).
# C64_UCI_TESTS_OPTIONAL=1 turns that failure into a loud skip with the same
# reason; build/ is never used as a fallback.
_UCI_BYTES_FILES = {
    "test_uci_data_acc.py", "test_uci_timeout_recovery.py",
    "test_uci_reply_valid_wait.py", "test_uci_abort_recovery.py",
    "test_uci_resp_read_wait.py", "test_uci_dhcp_probe.py",
}


def pytest_runtest_setup(item):
    path = getattr(item, "path", None) or getattr(item, "fspath", None)
    if path is None or Path(str(path)).name not in _UCI_BYTES_FILES:
        return
    import os
    import sys
    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    import _private_uci_build as pub
    try:
        os.environ[pub.ENV] = str(pub.uci_build_dir())
    except pub.Unavailable as exc:
        os.environ.pop(pub.ENV, None)
        if os.environ.get("C64_UCI_TESTS_OPTIONAL") != "1":
            raise
        # Opt-out: a loud skip carrying make's error, never build/ (which is
        # not the working tree's build).
        from _skip_policy import require
        require(False, str(exc), executed=0, total=1,
                certifies="the UCI 6502 bytes of this working tree",
                opt_out_env="C64_UCI_TESTS_OPTIONAL")
