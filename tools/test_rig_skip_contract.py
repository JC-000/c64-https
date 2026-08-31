#!/usr/bin/env python3
"""Pin the skip contract AT THE CALL SITES, not just in the helper (#178).

``tools/_skip_policy.py`` has its own tests.  This file tests the thing those
cannot: that the eleven wired call sites still *use* it, and still ask their
questions in the right order.

The gap this closes was the sharpest point of the #178 review.  The four
bridge rigs must ask ``platform_supported()`` BEFORE ``check_prerequisites()``:
on macOS the prerequisite list contains "ip not on PATH", which is not
installable there, so asking it first turns four Linux-only rigs into a
permanent red on this project's primary platform -- and the only remedy on
offer is the global opt-out, i.e. the policy gets switched off everywhere.
Swap those two lines back in a future edit and nothing else in the tree
notices.  That is #178's own thesis -- "a helper on its own is just another
convention to miss" -- turned on #178's own implementation.

Pure logic: no VICE, no hardware, no build, no network.  Every rig entry point
called here is called with a tripwire in place of the next step, so a test
that fails an ordering assertion fails loudly rather than starting a `make`.

Two deliberate limitations, stated rather than hidden:

  * ``tests/rig_vice_https_macos.py`` is NOT imported.  It imports
    ``c64_test_harness`` from a hard-coded sibling checkout at module level,
    which is a separate repo (``pip install -e ../c64-test-harness``), so
    importing it here would make this module error on any machine without
    that checkout.  Its two ordering contracts are pinned by source
    inspection instead -- weaker evidence, and labelled as such.
  * ``platform_supported()`` is a pure function of ``sys.platform``, so it is
    tested by patching exactly that one input.  That is the whole of its
    behaviour; there is nothing else to observe.
  * ``tools/https_e2e`` reaches the same sibling checkout transitively (its
    ``__init__`` re-exports from ``.vice_on_bridge``), so it is imported
    lazily inside the tests that need it, through ``require()``.  Without the
    checkout those six tests FAIL by name; the four source-inspection tests
    below still run.  A module-level import would instead have been a pytest
    COLLECTION ERROR on a fresh clone -- and ``pytest.ini`` says in as many
    words that a collection error must never be mistaken for a passing run.

KNOWN GAP, follow-up owed
-------------------------
The four ``test_macos_rig_*`` cases assert on SOURCE TEXT, so behavioural
mutants of ``tests/rig_vice_https_macos.py`` survive them -- reordering its
gates at runtime, or changing a verdict without changing the anchored text,
would not be caught.  Closing that needs the rig restructured to be
importable without the sibling harness, which is not a drive-by.  So: the
four bridge rigs are pinned BEHAVIOURALLY here; the macOS rig is pinned by
SHAPE only.
"""

import io
import os
import sys
from contextlib import redirect_stdout

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_TESTS = os.path.join(_REPO, "tests")
for _p in (_HERE, _TESTS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _skip_policy import require  # noqa: E402

# tools/https_e2e is NOT imported at module level.  Its __init__ re-exports
# from .vice_on_bridge, which imports c64_test_harness from a sibling
# checkout (`pip install -e ../c64-test-harness`) -- a separate repo.  This
# module is in pytest.ini testpaths, so a module-level import would make bare
# `pytest` on a fresh clone die with a COLLECTION ERROR, and pytest.ini's own
# comment says a collection error must never be mistaken for a passing run.
#
# It is also the exact hazard the docstring above cites as the reason not to
# import the macOS rig -- which the module-level import quietly voided.
#
# So it is loaded on first use and routed through require(): a missing
# sibling checkout is INVOLUNTARY, so the six tests that need it FAIL (exit 2
# semantics), loudly and by name, while the four source-inspection tests below
# still run and still pin what they pin.
_HTTPS_E2E = None
_HTTPS_E2E_ERROR = None

# The tests that cannot run without it, named so the failure says how much
# coverage is lost rather than just "import failed".
_NEEDS_HTTPS_E2E = 6


def _https_e2e():
    """Return the https_e2e package, or fail this test loudly (never collect-fail)."""
    global _HTTPS_E2E, _HTTPS_E2E_ERROR
    if _HTTPS_E2E is None and _HTTPS_E2E_ERROR is None:
        try:
            import https_e2e as mod
        except Exception as exc:  # noqa: BLE001 - a broken sibling can raise anything
            _HTTPS_E2E_ERROR = exc
        else:
            _HTTPS_E2E = mod
    require(
        _HTTPS_E2E is not None,
        f"tools/https_e2e could not be imported ({_HTTPS_E2E_ERROR!r}) -- it "
        "re-exports from .vice_on_bridge, which needs c64_test_harness from a "
        "sibling checkout: pip install -e ../c64-test-harness",
        executed=0,
        total=_NEEDS_HTTPS_E2E,
        certifies="the rigs' platform-before-prerequisites gate order",
        opt_out_env="C64_ALLOW_SKIP",
    )
    return _HTTPS_E2E

# The four Linux bridge rigs.  rig_phase3_https_1mhz is included even though
# it has two extra gates in front (an opt-in flag and a port check), because
# it is the one whose gate order was got wrong once already.
BRIDGE_RIGS = (
    "rig_phase1_dhcp",
    "rig_phase2_http",
    "rig_phase3_https",
    "rig_phase3_https_1mhz",
)

MACOS_RIG = os.path.join(_TESTS, "rig_vice_https_macos.py")


class Tripwire(AssertionError):
    """Raised when a rig reaches a step an ordering test must never reach."""


def _tripwire(name):
    def _fire(*_a, **_k):
        raise Tripwire(f"reached {name}() -- a gate let the run through")
    return _fire


class _FakeSocket:
    """Stands in for socket.socket in the 1 MHz rig's port-443 check.

    The bind succeeds, so the port check is not an environmental variable in
    an ordering test.  Whether 443 is free on the machine running the test
    says nothing about gate order.
    """

    def __init__(self, *_a, **_k):
        pass

    def bind(self, _addr):
        return None

    def close(self):
        return None


class _Patched:
    """Restore module attributes and environment after a with-block."""

    def __init__(self, mod, **kw):
        self.mod = mod
        self.kw = kw
        self.saved = {}
        self.env_saved = {}

    def env(self, **kw):
        for k, v in kw.items():
            self.env_saved[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __enter__(self):
        for name, value in self.kw.items():
            self.saved[name] = getattr(self.mod, name)
            setattr(self.mod, name, value)
        return self

    def __exit__(self, *exc):
        for name, value in self.saved.items():
            setattr(self.mod, name, value)
        for k, v in self.env_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


def _import_rig(name):
    import importlib
    return importlib.import_module(name)


def _run_main(mod, extra_tripwires=()):
    """Call mod.main() with output captured; returns (rc, output)."""
    saved = {}
    for attr in extra_tripwires:
        saved[attr] = getattr(mod, attr)
        setattr(mod, attr, _tripwire(attr))
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            rc = mod.main()
    finally:
        for attr, value in saved.items():
            setattr(mod, attr, value)
    return rc, buf.getvalue()


# ---------------------------------------------------------------------------
# The platform predicate.
# ---------------------------------------------------------------------------

def test_platform_supported_is_true_only_on_linux():
    _env = _https_e2e().env
    saved = _env.sys.platform
    try:
        for value in ("linux", "linux2"):
            _env.sys.platform = value
            assert _env.platform_supported() is True, value
        for value in ("darwin", "win32", "freebsd13", "cygwin"):
            _env.sys.platform = value
            assert _env.platform_supported() is False, value
    finally:
        _env.sys.platform = saved


def test_platform_supported_is_exported_from_the_package():
    # The rigs import it from the package, not from .env.
    mod = _https_e2e()
    assert mod.platform_supported is mod.env.platform_supported


# ---------------------------------------------------------------------------
# The ordering contract, behaviourally, on all four bridge rigs.
# ---------------------------------------------------------------------------

def test_bridge_rigs_ask_platform_before_prerequisites():
    """Wrong platform -> exit 0, and check_prerequisites() is never called.

    The tripwire is the whole point: if a future edit moves the prerequisite
    check back in front of the platform check, this raises instead of
    quietly returning 2.
    """
    pkg = _https_e2e()
    for name in BRIDGE_RIGS:
        mod = _import_rig(name)
        with _Patched(pkg, platform_supported=lambda: False,
                      check_prerequisites=_tripwire("check_prerequisites")):
            rc, out = _run_main(mod)
        assert rc == 0, f"{name}: wrong platform must be exit 0, got {rc}\n{out}"
        assert "NOT APPLICABLE" in out, f"{name}: no named verdict\n{out}"


def test_bridge_rigs_still_fail_when_the_platform_is_right():
    """Right platform + a missing prerequisite -> exit 2.

    The other half of the contract.  A fix for the macOS over-fail that also
    silenced the real coverage hole would pass the test above and fail this
    one.
    """
    pkg = _https_e2e()
    for name in BRIDGE_RIGS:
        mod = _import_rig(name)
        saved_socket = getattr(mod, "socket", None)
        if saved_socket is not None:
            # Only rig_phase3_https_1mhz binds a port before the prerequisite
            # check; neutralise it so gate ORDER is what this test measures.
            mod.socket = type("m", (), {"socket": _FakeSocket,
                                        "AF_INET": 0, "SOCK_STREAM": 0})
        try:
            with _Patched(pkg, platform_supported=lambda: True,
                          check_prerequisites=lambda: ["a tool is missing"]).env(
                    VICE_HTTPS_OK_TO_RUN="1", C64_ALLOW_SKIP=None):
                rc, out = _run_main(mod, extra_tripwires=("_ensure_built",))
        finally:
            if saved_socket is not None:
                mod.socket = saved_socket
        assert rc == 2, f"{name}: missing prereq on-platform must be 2, got {rc}\n{out}"
        assert "COULD NOT RUN" in out, f"{name}: no named verdict\n{out}"


def test_bridge_rigs_route_a_broken_build_to_two_without_an_opt_out():
    """A failed `make` is exit 2 even with C64_ALLOW_SKIP=1."""
    pkg = _https_e2e()
    for name in BRIDGE_RIGS:
        mod = _import_rig(name)
        saved_socket = getattr(mod, "socket", None)
        if saved_socket is not None:
            mod.socket = type("m", (), {"socket": _FakeSocket,
                                        "AF_INET": 0, "SOCK_STREAM": 0})
        saved_built = mod._ensure_built
        mod._ensure_built = lambda: False       # the build failed
        try:
            with _Patched(pkg, platform_supported=lambda: True,
                          check_prerequisites=lambda: []).env(
                    VICE_HTTPS_OK_TO_RUN="1", C64_ALLOW_SKIP="1"):
                rc, out = _run_main(mod)
        finally:
            mod._ensure_built = saved_built
            if saved_socket is not None:
                mod.socket = saved_socket
        assert rc == 2, f"{name}: broken build must be 2 even opted out, got {rc}\n{out}"


def test_the_opt_in_rig_treats_an_unset_flag_as_not_applicable():
    """VICE_HTTPS_OK_TO_RUN unset is the operator declining: exit 0."""
    mod = _import_rig("rig_phase3_https_1mhz")
    with _Patched(_https_e2e(), platform_supported=lambda: True,
                  check_prerequisites=_tripwire("check_prerequisites")).env(
            VICE_HTTPS_OK_TO_RUN=None):
        rc, out = _run_main(mod)
    assert rc == 0, f"unset opt-in flag must be exit 0, got {rc}\n{out}"
    assert "NOT APPLICABLE" in out, out
    assert "VICE_HTTPS_OK_TO_RUN" in out, out


# ---------------------------------------------------------------------------
# tests/rig_vice_https_macos.py -- source inspection only (see module docstring).
# ---------------------------------------------------------------------------

def _macos_source():
    with open(MACOS_RIG, "r", encoding="utf-8") as fh:
        return fh.read()


def _index_of(src, needle, label):
    i = src.find(needle)
    # A matcher that matches nothing is the same vacuous shape this whole
    # file is about, one level up: fail loudly rather than pass by absence.
    assert i >= 0, f"anchor not found in rig_vice_https_macos.py: {label} ({needle!r})"
    return i


def test_macos_rig_reports_problems_before_contention():
    """Contention on a rig that does not exist is the wrong headline.

    It is also not opt-out-able, so evaluating it first left a no-rig CI lane
    red with no recourse even when it correctly set C64_ALLOW_SKIP=1.
    """
    src = _macos_source()
    check = _index_of(src, "problems, contention = _rig_check()", "the _rig_check call")
    problems = _index_of(src[check:], "if problems:", "the problems branch")
    contention = _index_of(src[check:], "if contention:", "the contention branch")
    assert problems < contention, (
        "rig_vice_https_macos.py must test `problems` before `contention`")


def test_macos_rig_asks_platform_before_checking_the_rig():
    src = _macos_source()
    main_at = _index_of(src, "\ndef main() -> int:", "main()")
    body = src[main_at:]
    platform = _index_of(body, "_platform_supported()", "the platform gate")
    check = _index_of(body, "_rig_check()", "the _rig_check call")
    assert platform < check, (
        "rig_vice_https_macos.py must ask the platform question before "
        "inspecting the rig")


def test_macos_rig_contention_detector_is_not_a_bare_substring_match():
    """`pgrep -fl "ethernetioif feth0"` matched any process whose command
    line merely contained that text -- a grep, an editor, a driver script.
    A false positive is unrecoverable because contention has no opt-out.
    """
    src = _macos_source()
    assert '"-fl", "ethernetioif feth0"' not in src, (
        "the unanchored pgrep -fl substring match is back")
    _index_of(src, '"pgrep", "-x", "x64sc"', "the binary-name match")


def test_macos_rig_build_failure_exits_two():
    src = _macos_source()
    assert 'raise SystemExit("build failed")' not in src, (
        'SystemExit("build failed") exits 1, which makes a broken build '
        "indistinguishable from a real handshake failure")
    _index_of(src, "raise SystemExit(cannot_run(", "the build-failure verdict")


def _standalone() -> int:
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
