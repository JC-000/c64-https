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

import ast
import io
import os
import subprocess
import sys
from contextlib import redirect_stdout

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_TESTS = os.path.join(_REPO, "tests")
for _p in (_HERE, _TESTS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _skip_policy import (  # noqa: E402
    EXIT_CANNOT_RUN,
    EXIT_FAIL,
    EXIT_PASS,
    SkipPolicyError,
    VoluntarySkip,
    require,
)

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

P384_KAT = os.path.join(_HERE, "test_ecdsa_p384_kat.py")

# The one bridge rig whose voluntary skip really does cost coverage: the
# macOS rig drives the emulated-RR-Net path over TLS, so plaintext HTTP has
# no counterpart there.  Named here so the claim is asserted, not folklore.
PLAINTEXT_ONLY_RIG = os.path.join(_TESTS, "rig_phase2_http.py")


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


def test_the_interlock_flag_unset_is_contention_and_stays_exit_two():
    """VICE_HTTPS_OK_TO_RUN unset must NOT be laundered into a pass.

    This is the one gate where #178's own first draft got the taxonomy
    backwards: it read an unset flag as "the operator declined an opt-in
    rig" and returned 0, silently loosening the exit 2 this rig had on
    master.  Unset is the DEFAULT state, so it cannot tell a considered
    decline from a forgotten flag -- and the flag asserts "the UCI HTTPS
    listener has stopped", which is a contention claim.  Contention is the
    category with no opt-out at all.

    Pinned behaviourally, and pinned as NOT opt-out-able, so neither half
    can be quietly reverted.
    """
    mod = _import_rig("rig_phase3_https_1mhz")
    with _Patched(_https_e2e(), platform_supported=lambda: True,
                  check_prerequisites=_tripwire("check_prerequisites")).env(
            VICE_HTTPS_OK_TO_RUN=None):
        rc, out = _run_main(mod)
    assert rc == 2, f"unset interlock must be exit 2, got {rc}\n{out}"
    assert "COULD NOT RUN" in out, out
    assert "NOT APPLICABLE" not in out, out
    assert "VICE_HTTPS_OK_TO_RUN" in out, out

    # ...and no environment variable may rescue it, unlike the
    # missing-prerequisite lane three lines further down the rig.
    with _Patched(_https_e2e(), platform_supported=lambda: True,
                  check_prerequisites=_tripwire("check_prerequisites")).env(
            VICE_HTTPS_OK_TO_RUN=None, C64_ALLOW_SKIP="1"):
        rc, out = _run_main(mod)
    assert rc == 2, f"contention must not be opt-out-able, got {rc}\n{out}"


# ---------------------------------------------------------------------------
# tests/rig_vice_https_macos.py -- source inspection only (see module docstring).
# ---------------------------------------------------------------------------

def test_the_u64_gate_is_not_opt_out_able_because_it_precedes_the_vice_lane():
    """--u64 with no U64_HOST must be exit 2 even under C64_ALLOW_SKIP=1.

    This gate is the one place in this PR where honouring the opt-out would
    make an exit code WEAKER than master's, and the reason is scope rather
    than arithmetic.  On master, `--u64` with U64_HOST unset still ran the
    entire VICE lane and returned `0 if total_fail == 0 else 1`, so a failing
    emulator vector reported 1.  The gate added here fires BEFORE
    _build_prg() and before any VICE work, so an honoured opt-out returns 0
    with nothing run at all.

    C64_ALLOW_SKIP answers "this lane has no hardware" -- which is exactly
    the operator who would set it here -- yet it would silence the EMULATOR
    half, which needs no hardware.  The remedy costs nothing and needs no
    variable: set U64_HOST, or drop --u64.  Pinned as a subprocess because
    the exit CODE is the whole contract.

    Cheap by construction: the gate returns before the vector file check,
    before _build_prg(), and before VICE, and the module imports nothing but
    stdlib and _skip_policy -- so this runs in well under a second and
    touches no hardware.
    """
    env = dict(os.environ)
    env.pop("U64_HOST", None)
    env["C64_ALLOW_SKIP"] = "1"
    proc = subprocess.run([sys.executable, P384_KAT, "--u64"],
                          capture_output=True, text=True, cwd=_REPO, env=env,
                          timeout=120)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, (
        f"--u64 with no U64_HOST must be exit 2 even opted out, got "
        f"{proc.returncode}\n{out}")
    assert "COULD NOT RUN" in out, out
    # ...and it must not advertise a hatch it does not honour.
    assert "opt-out honoured" not in out, out


def test_phase2_does_not_claim_a_counterpart_it_does_not_have():
    """rig_phase2_http.py must not tell an operator its coverage is covered.

    The file used to contradict itself inside 40 lines: its module docstring
    said "tests/rig_vice_https_macos.py owns the coverage", while its own
    _COUNTERPART string -- the one that actually reaches the operator at
    runtime -- said that rig drives TLS, "so plaintext HTTP specifically has
    no macOS rig".  The docstring is what a reader hits first.

    This matters past tidiness: the voluntary-skip verdict is justified by
    "another rig owns the coverage, nothing is lost", and for this one rig
    that is false.  Exit 0 is still right (there is no remedy on macOS) but
    the reason has to be the true one, or the exit code quietly overstates
    what was verified -- the same defect class this module exists to catch.
    """
    with open(PLAINTEXT_ONLY_RIG, "r", encoding="utf-8") as fh:
        src = fh.read()

    # The runtime string is the anchor: assert it says what we think, so
    # this test cannot pass because the string was silently reworded.
    assert "no macOS rig" in src, (
        "rig_phase2_http.py must state that plaintext HTTP has no macOS "
        "counterpart; the anchor string is gone")

    doc = ast.get_docstring(ast.parse(src)) or ""
    assert doc, "rig_phase2_http.py lost its module docstring"
    assert "owns the coverage" not in doc, (
        "rig_phase2_http.py's docstring claims another rig owns its "
        "coverage, which its own _COUNTERPART denies:\n" + doc)


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
    """Run every test_* in this module without pytest.

    Honours the 0/1/2 contract of the module under test rather than
    collapsing "could not run" onto 1.  The six https_e2e tests raise
    SkipPolicyError when the sibling harness checkout is absent -- that is a
    coverage hole (exit 2), not a failed check (exit 1).
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
