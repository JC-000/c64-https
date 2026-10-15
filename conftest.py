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


# Six modules execute the shipped UCI bytes. Point them at a fresh private
# UCI build (tools/_private_uci_build.py) so a bare pytest is green on any
# build/ (#302). A build that fails raises here, once, with make's error as the
# reason -> pytest ERROR on every selected test, never a skip (#178).
# C64_UCI_TESTS_OPTIONAL=1 (the modules' own opt-out) is the one exception:
# a failed private build then leaves their paths alone, and they announce the
# skip themselves.
_UCI_BYTES_MODULES = {
    "test_uci_data_acc", "test_uci_timeout_recovery",
    "test_uci_reply_valid_wait", "test_uci_abort_recovery",
    "test_uci_resp_read_wait", "test_uci_dhcp_probe",
}
_uci_retargeted = False


def pytest_runtest_setup(item):
    global _uci_retargeted
    mod = getattr(item, "module", None)
    if _uci_retargeted or mod is None or mod.__name__ not in _UCI_BYTES_MODULES:
        return
    import os
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    import _private_uci_build as pub
    import test_uci_data_acc
    import test_uci_timeout_recovery
    try:
        build = pub.uci_build_dir()
    except pub.Unavailable:
        if os.environ.get("C64_UCI_TESTS_OPTIONAL") == "1":
            return
        raise
    for m in (test_uci_data_acc, test_uci_timeout_recovery):
        m.PRG = build / "c64-https.prg"
        m.LABELS = build / "labels.txt"
    _uci_retargeted = True
