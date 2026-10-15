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


# Six modules execute the shipped UCI bytes. Point them at a UCI build that
# is not necessarily build/, so a bare pytest is green on an ip65 build too
# (#302). A build that cannot be produced raises here -> pytest ERROR, never
# a skip (#178). Lazy: only a run that selects one of them pays for it.
_UCI_BYTES_MODULES = {
    "test_uci_data_acc", "test_uci_timeout_recovery",
    "test_uci_reply_valid_wait", "test_uci_abort_recovery",
    "test_uci_resp_read_wait", "test_uci_dhcp_probe",
}
_uci_retargeted = False


def pytest_runtest_setup(item):
    global _uci_retargeted
    if _uci_retargeted or item.module.__name__ not in _UCI_BYTES_MODULES:
        return
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    import _private_uci_build as pub
    import test_uci_data_acc
    import test_uci_timeout_recovery
    try:
        build = pub.uci_build_dir()
    except pub.Unavailable as exc:
        # Each module's own Unavailable keeps the opt-out semantics
        # (C64_UCI_TESTS_OPTIONAL) -- leave its paths alone and say why.
        print(f"conftest: private UCI build unavailable: {exc}")
        return
    for mod in (test_uci_data_acc, test_uci_timeout_recovery):
        mod.PRG = build / "c64-https.prg"
        mod.LABELS = build / "labels.txt"
    _uci_retargeted = True
