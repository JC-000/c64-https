"""Make the boundary of a pytest run impossible to misread.

c64-https is an assembly project. Its real test suites drive VICE or real
Ultimate 64 hardware and are launched by `python3 tools/run_all_tests.py`
and by the manual rig scripts in `tests/` — not by pytest. Only a few
pure-logic host-side modules are pytest-runnable, and `pytest.ini` pins
`testpaths` to exactly those.

Without this file, `pytest` at the repo root prints a bare pass count that
reads like whole-project coverage. It is not. See issue #109.

This module deliberately contains no fixtures, no skips and no imports of
pytest: it must stay inert for anyone who does not have pytest installed,
and the repo declares no pytest dependency.
"""

_BOUNDARY = [
    "c64-https: pytest runs ONLY the pure-logic host-side modules pinned in",
    "pytest.ini `testpaths`. It does NOT run the C64 suites (those need VICE:",
    "`python3 tools/run_all_tests.py`) and it does NOT run the live-rig",
    "scripts in tests/ (manual, sudo + network rig: see tests/README.md).",
    "A green run here says nothing about either.",
]

_EMPTY_RUN = [
    "pytest collected nothing from the paths you gave it.",
    "If that was `pytest tests/`: tests/ holds manual live-rig scripts",
    "(tests/rig_*.py, main() programs needing sudo and a network rig), not",
    "pytest tests. See tests/README.md for how to run them.",
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
