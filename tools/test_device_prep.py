#!/usr/bin/env python3
"""Pin the UCI rigs' device prep: policy AND call sites (issues #187, #197, #212).

Nothing here touches VICE, hardware or a build. The ``Ultimate64Client`` and
the three harness writers are faked, so this is pure logic and runs in
milliseconds — the model is ``tools/test_reu_preflight.py``, and for the same
reason: the thing being guarded is a *hardware* prep whose failure mode is to
stop guarding, which no hardware run can observe.

Two independent halves, because two independent things went wrong.

1. **The policy** (``tools/uci/_device_prep.py``). One unreadable probe, two
   opposite correct answers:

   * REU unreadable -> **write anyway**. The write is the configuration the
     run needs; a wasted one costs a PUT. (#197 names this asymmetry as the
     correct one and asks for it to be preserved.)
   * Turbo unreadable -> **abort**, after one retry. The turbo write is
     itself the hazard (a redundant one glitches the UCI bridge and loses the
     next command: ``$88``), and skipping it silently runs the rig at the
     previous lane's clock. Neither degrade is safe, so the run stops where
     it costs seconds. ``C64_FORCE_TURBO_WRITE=1`` is the named override.

   The asymmetry is the whole design, so both directions are pinned. A
   uniform policy in *either* direction passes half of these and fails the
   other half.

2. **The call sites** (``tools/uci/rig_*.py``, ``bench_ecdsa_u64e.py``). A
   helper on its own is a convention to miss — the same argument
   ``tools/test_rig_skip_contract.py`` makes about the skip policy. #197's
   defect was precisely that four rigs *had* a guard and no setup, so these
   tests assert by AST that every crypto-path rig calls ``prepare_device``
   and calls it BEFORE ``preflight_reu``: prep is setup, the preflight is the
   backstop behind it, and that order is the fix.

Runs under pytest, and standalone for anyone without pytest installed::

    python3 tools/test_device_prep.py
"""

import ast
import importlib.util
import io
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UCI = REPO / "tools" / "uci"
PREP_PATH = UCI / "_device_prep.py"

# tools/uci/ is in pytest.ini's norecursedirs (it is a rig directory), so the
# module under test is loaded by path. It imports its sibling _reu_preflight
# by bare name, exactly as the rigs do, so tools/uci must be importable.
if str(UCI) not in sys.path:
    sys.path.insert(0, str(UCI))
_spec = importlib.util.spec_from_file_location("_device_prep_ut", PREP_PATH)
dp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dp)

CAT_U64 = dp.CAT_U64_SPECIFIC
CAT_CART = dp.CAT_CART

# Same labels fixtures as test_reu_preflight.py: no manifest equate and no
# on-chip row generator is the REU profile; the equate at 0 is on-chip.
LABELS_REU = "al 006000 .ecdsa_verify_256\nal 00A000 .tls_rec_buf\n"
LABELS_ONCHIP = "al 000000 .LIB_NISTCURVES_REU_BANKS_USED\nal 006000 .gen_mul_row\n"

#: A device at the factory default: 1 MHz, turbo off, no REU. This is the
#: ordinary state of a freshly power-cycled U64E, not a broken one — which is
#: the whole of #197.
DEFAULT_STATE = {
    f"{CAT_U64}/Turbo Control": "Off",
    f"{CAT_U64}/CPU Speed": " 1",
    f"{CAT_CART}/RAM Expansion Unit": "Disabled",
    f"{CAT_CART}/REU Size": "2 MB",
}

#: A device already prepared for a 48 MHz comb run.
READY_STATE = {
    f"{CAT_U64}/Turbo Control": "Manual",
    f"{CAT_U64}/CPU Speed": "48",
    f"{CAT_CART}/RAM Expansion Unit": "Enabled",
    f"{CAT_CART}/REU Size": "16 MB",
}


class _HarnessError(Exception):
    """Stands in for Ultimate64ProtocolError / Ultimate64Error."""


class FakeClient:
    """Minimal Ultimate64Client stand-in, driven by a list of states.

    :param states: one dict per read *pass* (``read_device_state`` reads all
        four items in one pass). The last entry is reused once exhausted, so
        a single-element list means "the device never changes". A value that
        is an Exception instance is raised for that item.
    """

    host = "10.0.0.1"

    def __init__(self, states):
        self.states = list(states)
        self.passes = 0
        self.reads = []

    def _state(self):
        idx = min(self.passes, len(self.states) - 1)
        return self.states[idx]

    def get_config_value(self, category, item):
        key = f"{category}/{item}"
        self.reads.append(key)
        state = self._state()
        # Count a pass each time the last item of the sweep is read.
        if (category, item) == dp.STATE_ITEMS[-1]:
            self.passes += 1
        value = state.get(key, _HarnessError(f"item {item!r} absent"))
        if isinstance(value, Exception):
            raise value
        return value


class Writers:
    """Records the two hazardous actions instead of performing them."""

    def __init__(self, reu_raises=None):
        self.turbo = []
        self.reu = []
        #: Exception the REU write raises, standing in for a device refusal.
        self.reu_raises = reu_raises

    def set_turbo(self, client, mhz):
        self.turbo.append(mhz)

    def set_reu(self, client, enabled, size=None):
        self.reu.append((enabled, size))
        if self.reu_raises is not None:
            raise self.reu_raises


def _speed_enum(mhz):
    """Stand-in for the harness's cpu_speed_enum (right-justified width 2)."""
    return f"{mhz:>2}"


def _run(client, *, labels=LABELS_REU, turbo_mhz=48, env=None,
         artifact_dir=None, reu_raises=None):
    """Call prepare_device with fake writers. Returns (report, writers, output)."""
    writers = Writers(reu_raises=reu_raises)
    buf = io.StringIO()
    saved = {}
    env = env or {}
    for key in (dp.SKIP_ENV, dp.FORCE_TURBO_WRITE_ENV, "TURBO_SETTLE",
                "REU_SETTLE", "TURBO_PROBE_RETRY_DELAY", dp.DEBUG_DIR_ENV):
        saved[key] = os.environ.get(key)
    # No real sleeps in a unit test.
    os.environ["TURBO_SETTLE"] = "0"
    os.environ["REU_SETTLE"] = "0"
    os.environ["TURBO_PROBE_RETRY_DELAY"] = "0"
    os.environ.pop(dp.SKIP_ENV, None)
    os.environ.pop(dp.FORCE_TURBO_WRITE_ENV, None)
    os.environ.pop(dp.DEBUG_DIR_ENV, None)
    os.environ.update(env)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            labels_path = Path(tmp) / "labels.txt"
            labels_path.write_text(labels)
            try:
                report = dp.prepare_device(
                    client, labels_path,
                    turbo_mhz=turbo_mhz,
                    stream=buf,
                    set_turbo=writers.set_turbo,
                    set_reu=writers.set_reu,
                    speed_enum=_speed_enum,
                    artifact_dir=artifact_dir,
                )
            except BaseException as exc:      # noqa: BLE001 — re-raised below
                exc.captured = buf.getvalue()
                exc.writers = writers
                raise
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return report, writers, buf.getvalue()


def _assert_raises_prep(client, what="", **kwargs):
    try:
        report, writers, out = _run(client, **kwargs)
    except dp.DevicePrepError as exc:
        return exc
    raise AssertionError(
        f"{what}: prepare_device returned {report!r} instead of raising "
        f"DevicePrepError. The turbo guard degraded instead of stopping — "
        f"turbo writes: {writers.turbo!r}. Output was:\n{out}"
    )


# ------------------------------------------------------- turbo: fail closed

def test_unreadable_turbo_aborts_and_writes_nothing() -> None:
    """#187: an unreadable turbo probe must abort, not write anyway.

    Both halves are asserted. Aborting while still having issued the write
    would be the same defect wearing an error message: the ``$88`` glitch is
    caused by the PUT, not by the exit code.
    """
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_U64}/CPU Speed"] = _HarnessError("no 'current' value")
    client = FakeClient([broken])
    exc = _assert_raises_prep(client, what="CPU Speed unreadable")
    assert "DEVICE PREP FAILED" in str(exc)
    assert exc.writers.turbo == [], (
        "prepare_device performed the turbo write it aborted over; the $88 "
        f"hazard is the write itself. writes: {exc.writers.turbo!r}"
    )
    assert dp.FORCE_TURBO_WRITE_ENV in str(exc), (
        f"the failure must name its override; got:\n{exc}"
    )
    assert "$88" in str(exc), (
        "the message must name the failure being avoided (issue #187 asks "
        f"for exactly this); got:\n{exc}"
    )


def test_unreadable_turbo_control_also_aborts() -> None:
    """Either half of the pair being unreadable is an unreadable pair."""
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_U64}/Turbo Control"] = _HarnessError("HTTP 500")
    exc = _assert_raises_prep(FakeClient([broken]), what="Turbo Control unreadable")
    assert exc.writers.turbo == []


def test_turbo_none_value_is_not_a_mismatch() -> None:
    """A ``None`` value must not be compared as if the item had answered.

    This is #187's mechanism verbatim: the old ``inner.get(...)`` descent
    made "absent" and "None" indistinguishable, and both landed on writing.
    """
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_U64}/CPU Speed"] = None
    exc = _assert_raises_prep(FakeClient([broken]), what="CPU Speed None")
    assert exc.writers.turbo == []


def test_turbo_probe_is_retried_once_before_aborting() -> None:
    """A single REST hiccup must not burn a device slot."""
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_U64}/CPU Speed"] = _HarnessError("transient")
    client = FakeClient([broken, DEFAULT_STATE])
    report, writers, out = _run(client)
    assert writers.turbo == [48], (
        f"the retry read cleanly and the write should have gone ahead: {out}"
    )
    assert "retry" in out, f"the retry must be visible in the log:\n{out}"


def test_force_override_restores_the_write_anyway_degrade() -> None:
    """The old behaviour stays reachable, deliberately and by name."""
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_U64}/CPU Speed"] = _HarnessError("nope")
    client = FakeClient([broken])
    report, writers, out = _run(client, env={dp.FORCE_TURBO_WRITE_ENV: "1"})
    assert writers.turbo == [48], f"override did not write: {out}"
    assert "$88" in out, (
        f"writing blind must say what risk is being accepted:\n{out}"
    )


# --------------------------------------------------------- turbo: normal path

def test_matching_turbo_skips_the_write() -> None:
    """The reason the probe exists: a redundant write is itself the hazard."""
    report, writers, out = _run(FakeClient([READY_STATE]))
    assert writers.turbo == [], f"redundant turbo write was issued:\n{out}"
    assert "turbo" in report["skipped_write"]


def test_mismatched_turbo_is_written() -> None:
    report, writers, out = _run(FakeClient([DEFAULT_STATE, READY_STATE]))
    assert writers.turbo == [48], f"turbo was not set: {out}"
    assert "turbo" in report["wrote"]


def test_turbo_none_makes_no_turbo_decision() -> None:
    """``turbo_mhz=None`` leaves the clock alone — no write, and no abort.

    A rig that does not manage the clock must not inherit a failure mode
    about it, even when the read is broken.
    """
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_U64}/CPU Speed"] = _HarnessError("unreadable")
    report, writers, out = _run(FakeClient([broken]), turbo_mhz=None)
    assert writers.turbo == []
    assert "turbo" not in report["wrote"]


# ---------------------------------------------------- REU: the other direction

def test_default_device_is_configured_not_refused() -> None:
    """#197: a factory-default device must be set up, not declined.

    ``RAM Expansion Unit: Disabled`` is the default state of a
    power-cycled device. Refusing it is the preflight doing its job and the
    rig failing to do its own.
    """
    report, writers, out = _run(FakeClient([DEFAULT_STATE, READY_STATE]))
    assert writers.reu == [(True, dp.REQUIRED_REU_SIZE)], (
        f"the REU was not configured for a REU-profile build:\n{out}"
    )
    assert "reu" in report["wrote"]


def test_unreadable_reu_writes_anyway() -> None:
    """The asymmetry with turbo, and it is deliberate.

    Here the write is the *safe* action: it is the configuration the run
    needs, and a wasted PUT costs nothing. #197 explicitly asks for this
    direction to survive being generalised.
    """
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_CART}/RAM Expansion Unit"] = _HarnessError("unreadable")
    report, writers, out = _run(FakeClient([broken, READY_STATE]))
    assert writers.reu == [(True, dp.REQUIRED_REU_SIZE)], (
        f"an unreadable REU probe must still configure the device:\n{out}"
    )
    assert "unreadable" in out


def test_ready_reu_skips_the_write() -> None:
    report, writers, out = _run(FakeClient([READY_STATE]))
    assert writers.reu == [], f"redundant REU write:\n{out}"
    assert "reu" in report["skipped_write"]


def test_wrong_size_is_rewritten() -> None:
    """Enabled is not enough: the wikipedia sink writes REU bank $10."""
    small = dict(READY_STATE)
    small[f"{CAT_CART}/REU Size"] = "2 MB"
    report, writers, out = _run(FakeClient([small, READY_STATE]))
    assert writers.reu == [(True, dp.REQUIRED_REU_SIZE)], out


def test_onchip_build_never_writes_the_reu() -> None:
    """Failing closed must not start blocking the REU-less configuration.

    Reads still happen (the before-state is the point of #212 and reads are
    not the hazard), but an on-chip image needs no REU and must never have
    one configured on its behalf.
    """
    report, writers, out = _run(FakeClient([DEFAULT_STATE]), labels=LABELS_ONCHIP)
    assert writers.reu == [], f"on-chip build had the REU configured:\n{out}"
    assert report["profile"] == "onchip"
    assert "no REU configuration needed" in out


# --------------------------------------------- the REU write can itself fail

def test_a_refused_reu_write_is_exit_4_with_a_ladder_not_a_traceback() -> None:
    """The degrade toward writing is only safe if the write cannot escape.

    This is not a corner: the condition that makes the probe unreadable is
    frequently the same condition that makes the write fail. With REST
    refusing, the harness's own Cartridge-preset probe also fails, returns
    the inconclusive `None`, and `set_reu` then INCLUDES a
    `Cartridge: "REU"` PUT that a C64 Ultimate rejects with HTTP 400 —
    while `set_config_items` catches nothing per item.

    Unwrapped, that escapes every call site (all five catch only
    DevicePrepError): master reported this device as exit 4 with the
    writemem-wedge ladder, and an escaping exception would have downgraded
    it to exit 1 and a raw traceback on the one path this project has a
    documented habit of misreading as firmware corruption.
    """
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_CART}/RAM Expansion Unit"] = _HarnessError("connection refused")
    exc = _assert_raises_prep(
        FakeClient([broken]), what="REU write refused",
        reu_raises=_HarnessError("HTTP 400: 'REU' is not a valid choice "
                                 "for Cartridge"),
    )
    text = str(exc)
    assert "DEVICE PREP FAILED" in text
    assert "HTTP 400" in text, f"the device's own words must survive:\n{text}"
    assert "firmware corruption" in text, (
        "the refused-write message must carry the diagnostic ladder, since "
        f"this is the ordinary shape of 'REST is refusing':\n{text}"
    )
    assert "no REU" not in text, (
        "this is a refused write, not a missing REU — it must not send the "
        f"operator to the settings menu for a fact not in evidence:\n{text}"
    )


def test_a_refused_reu_write_does_not_reach_the_turbo_write() -> None:
    """A device refusing config is not a device to keep writing to."""
    exc = _assert_raises_prep(
        FakeClient([DEFAULT_STATE]), what="REU refused, turbo pending",
        reu_raises=_HarnessError("HTTP 500"),
    )
    assert exc.writers.turbo == [], (
        f"turbo was written after the device refused a write: "
        f"{exc.writers.turbo!r}"
    )


# ------------------------------------------------------------- the record

def test_before_and_after_are_reported() -> None:
    """#212: a run's log must say which device state produced its result."""
    report, writers, out = _run(FakeClient([DEFAULT_STATE, READY_STATE]))
    assert "device state before" in out and "device state after" in out, out
    assert "'Disabled'" in out, (
        f"the before-state must show the values actually found:\n{out}"
    )
    assert report["before"][f"{CAT_CART}/RAM Expansion Unit"] == "Disabled"
    assert report["after"][f"{CAT_CART}/RAM Expansion Unit"] == "Enabled"


def test_unreadable_items_are_named_in_the_report() -> None:
    """An item that could not be read must say so, not read as a value."""
    broken = dict(DEFAULT_STATE)
    broken[f"{CAT_CART}/REU Size"] = _HarnessError("boom")
    report, writers, out = _run(FakeClient([broken, READY_STATE]))
    assert "unreadable" in out
    key = f"{CAT_CART}/REU Size" + dp.ERROR_SUFFIX
    assert key in report["before"], f"no error recorded: {report['before']!r}"


def test_state_is_written_to_the_artifact_dir() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        report, writers, out = _run(FakeClient([DEFAULT_STATE, READY_STATE]),
                                    artifact_dir=tmp)
        dest = Path(tmp) / "device_state.json"
        assert dest.exists(), f"no device_state.json written:\n{out}"
        saved = json.loads(dest.read_text())
        assert saved["before"][f"{CAT_CART}/RAM Expansion Unit"] == "Disabled"
        assert saved["wrote"] == report["wrote"]


def test_unwritable_artifact_dir_does_not_fail_the_run() -> None:
    """The record is a record, not a new way to lose a device slot."""
    with tempfile.TemporaryDirectory() as tmp:
        blocker = Path(tmp) / "blocked"
        blocker.write_text("not a directory")
        report, writers, out = _run(FakeClient([DEFAULT_STATE, READY_STATE]),
                                    artifact_dir=blocker)
        assert report["wrote"], out
        assert "could not record" in out, out


def test_skip_env_makes_no_device_call() -> None:
    """The documented bypass, and it must be total."""
    client = FakeClient([DEFAULT_STATE])
    report, writers, out = _run(client, env={dp.SKIP_ENV: "1"})
    assert client.reads == [], f"skipped prep still read config: {client.reads!r}"
    assert writers.turbo == [] and writers.reu == []
    assert report["skipped"] is True
    assert "preflight still runs" in out


def test_the_env_fallback_writes_when_no_artifact_dir_is_given() -> None:
    """The documented `$UCI_DEBUG_DIR` fallback must actually work.

    It was untested in both directions: the artifact test passed
    `artifact_dir` explicitly while `_run` popped the env var, so the
    fallback path this module and two docs advertise had never executed.
    """
    with tempfile.TemporaryDirectory() as tmp:
        report, writers, out = _run(FakeClient([DEFAULT_STATE, READY_STATE]),
                                    env={dp.DEBUG_DIR_ENV: tmp})
        assert (Path(tmp) / "device_state.json").exists(), (
            f"the {dp.DEBUG_DIR_ENV} fallback wrote nothing:\n{out}"
        )


def test_nothing_is_written_when_neither_is_given() -> None:
    """No dir, no file, no failure — and no silent claim that it was kept."""
    report, writers, out = _run(FakeClient([DEFAULT_STATE, READY_STATE]))
    assert "state recorded in" not in out, (
        f"prep claimed to record state with nowhere to put it:\n{out}"
    )


def test_the_two_skip_flags_parse_env_values_identically() -> None:
    """#5: `=false` must mean the same thing to both flags.

    They disagreed: `_reu_preflight` tested `!= "0"`, so
    `C64_SKIP_REU_PREFLIGHT=false` SKIPPED the guard, while
    `C64_SKIP_DEVICE_PREP=false` did not skip the prep — with the two
    documented on one line as though they behaved alike. Unified toward the
    stricter reading, which leaves the guard ON.
    """
    import importlib.util as _ilu
    _s = _ilu.spec_from_file_location("_reu_preflight_parity", UCI / "_reu_preflight.py")
    pf = _ilu.module_from_spec(_s)
    _s.loader.exec_module(pf)
    saved = {k: os.environ.get(k) for k in (dp.SKIP_ENV, pf.SKIP_ENV)}
    try:
        for value, expected in (("1", True), ("true", True), ("yes", True),
                                ("0", False), ("false", False), ("off", False),
                                ("no", False), ("", False)):
            os.environ[dp.SKIP_ENV] = value
            os.environ[pf.SKIP_ENV] = value
            got_prep = dp._env_true(dp.SKIP_ENV)
            got_flight = pf.env_flag_enabled(pf.SKIP_ENV)
            assert got_prep == got_flight == expected, (
                f"{value!r}: prep={got_prep}, preflight={got_flight}, "
                f"expected {expected}. Two flags on one documentation line "
                "must not parse differently."
            )
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_skipping_prep_warns_that_the_clock_is_unmanaged() -> None:
    """#3: SKIP_DEVICE_PREP is the dangerous hatch, and must say so.

    It skips the turbo write entirely, so the run proceeds at whatever clock
    the previous lane left — the exact outcome this module argues is worth
    aborting over. Saying only "the REU preflight still runs and still fails
    closed" is true and irrelevant to the clock.
    """
    report, writers, out = _run(FakeClient([DEFAULT_STATE]),
                                env={dp.SKIP_ENV: "1"})
    assert "clock" in out.lower(), (
        f"skipping prep must warn about the unmanaged clock:\n{out}"
    )
    assert "WARNING" in out, f"and it must read as a warning:\n{out}"


# ------------------------------------------------------------- call sites

#: Rigs that are exempt from the prep contract, and why. An entry here is a
#: statement that the gap is known and owned, not that it is harmless — each
#: one is asserted below to still lack prep, so a fixed rig fails this file
#: until its entry is removed. Same shape as `run_all_tests.UNDISPATCHED_SUITES`.
KNOWN_UNPREPPED = {
    "rig_https_banner.py": (
        "owned by another lane (the #210 work) and must not be edited from "
        "here; sequencing is with the coordinator. It is the rig whose "
        "documented failure IS #212's: it boots the PRG through the menu on "
        "a C64_INIT_WAIT of 75 s while printing 'comb boot precompute', "
        "writes no turbo and no REU, and a comb boot at 1 MHz needs ~36 min "
        "against that budget. `tests/rig_ip65_rrnet_hw.py` writes turbo at "
        "stock 1 MHz, so 'RR-Net run, then banner run' reaches it live."
    ),
}


def _crypto_path_rigs():
    """Discover the rigs this contract covers, rather than listing them.

    The rule: a module that boots the PRG on the device (``client.run_prg``)
    AND knows about the comb profile. Those two together are exactly the
    exposure — comb needs REU bank 2, and its boot precompute is ~45 s at
    48 MHz against ~36 min at 1 MHz, so such a rig depends on both the REU
    state and the clock whether or not it manages them.

    Discovery rather than an allowlist because an allowlist cannot find a
    sixth rig *at all*, and "a helper nothing calls is a convention, not a
    fix" cuts both ways: a contract that only checks the files it already
    knows about is one too.

    **Know what this does and does not catch.** It is a text match, so it
    finds a sixth rig written to the same shape as the existing five — and
    misses one that is not. A rig naming its client `u64` instead of
    `client`, or never using the word "comb", is not selected and the whole
    suite stays green; both were constructed and both pass 30/0. That is the
    **silent** direction, and `test_the_discovery_rule_finds_the_known_rigs`
    cannot see it either, because a module the rule misses never enters the
    set being compared.

    Over-selection is the loud direction: a helper containing
    `client.run_prg(` and the word "combines" produces two reds, one of them
    absurdly demanding that a *helper* call `prepare_device`. That is
    annoying and safe. If you hit it under time pressure, add an exemption
    to :data:`KNOWN_UNPREPPED` with a reason — do not weaken the rule, which
    would trade a loud false positive for a silent false negative.
    """
    found = []
    for path in sorted(UCI.glob("*.py")):
        text = path.read_text()
        if "client.run_prg(" in text and "comb" in text.lower():
            found.append(path)
    return found


def test_the_discovery_rule_finds_the_known_rigs() -> None:
    """The rule must not quietly narrow to nothing (or to everything)."""
    names = {p.name for p in _crypto_path_rigs()}
    expected = {"bench_ecdsa_u64e.py", "rig_https_bad_finished.py",
                "rig_https_live.py", "rig_https_local.py",
                "rig_https_wiki.py", "rig_https_banner.py"}
    assert names == expected, (
        f"the discovery rule now selects {sorted(names)}, not "
        f"{sorted(expected)}. If a rig was added or renamed that is fine — "
        "update this list deliberately. If the rule stopped matching, the "
        "contract below silently covers less than it claims."
    )


def _call_lines(tree, name):
    """Line numbers of every ``name(...)`` call in *tree*."""
    return sorted(
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == name
    )


def test_every_crypto_rig_prepares_before_it_checks() -> None:
    """#197: the preflight is the backstop, so something must come before it.

    Asserted at the call sites rather than only in the helper, on
    ``tools/test_rig_skip_contract.py``'s argument: a helper nothing calls is
    a convention, not a fix, and #197's defect was exactly four rigs holding
    a guard with no setup behind it.
    """
    for path in _crypto_path_rigs():
        tree = ast.parse(path.read_text(), filename=str(path))
        prep = _call_lines(tree, "prepare_device")
        flight = _call_lines(tree, "preflight_reu")
        if path.name in KNOWN_UNPREPPED:
            continue
        assert prep, (
            f"{path.name} boots the PRG and knows about the comb profile, "
            "but never calls prepare_device: it depends on the device's REU "
            "and clock state without configuring or recording either "
            "(issue #197). Wire it up, or add it to KNOWN_UNPREPPED with the "
            "reason and the owner."
        )
        assert flight, f"{path.name} lost its preflight_reu backstop"
        assert min(prep) < min(flight), (
            f"{path.name} calls preflight_reu (line {min(flight)}) before "
            f"prepare_device (line {min(prep)}). The preflight is the guard "
            "BEHIND the prep; in that order it refuses the device the prep "
            "was about to fix."
        )


def test_known_unprepped_entries_are_still_unprepped() -> None:
    """An exemption must expire on its own when the gap closes."""
    for name, reason in KNOWN_UNPREPPED.items():
        path = UCI / name
        assert path.exists(), f"KNOWN_UNPREPPED names a missing file: {name}"
        assert len(reason) > 80, f"{name}'s exemption needs a real reason"
        tree = ast.parse(path.read_text(), filename=str(path))
        assert not _call_lines(tree, "prepare_device"), (
            f"{name} now calls prepare_device — remove its KNOWN_UNPREPPED "
            "entry so the contract covers it for real."
        )


def test_every_prepping_rig_hands_over_its_run_artifact_dir() -> None:
    """#212's record must land WITH the run's artifacts, not in a base dir.

    Every rig writes its artifacts into a per-run timestamped directory; the
    env fallback inside `_write_artifact` resolves to the *base* directory
    the rigs derive that from, so a run relying on it would overwrite the
    previous run's record — and with `UCI_DEBUG_DIR` normally unset (each rig
    supplies its own Python-level default) it would write nothing at all.
    So every call site passes `artifact_dir` explicitly.
    """
    for path in _crypto_path_rigs():
        if path.name in KNOWN_UNPREPPED:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name)
                 and n.func.id == "prepare_device"]
        for call in calls:
            kwargs = {kw.arg for kw in call.keywords}
            assert "artifact_dir" in kwargs, (
                f"{path.name}:{call.lineno} calls prepare_device without "
                "artifact_dir, so the device-state record falls back to "
                "$UCI_DEBUG_DIR — normally unset, and when set it is the "
                "rig's BASE dir, which the next run overwrites."
            )


def test_no_rig_still_degrades_toward_the_turbo_write() -> None:
    """#187: the ``writing anyway`` degrade must be gone from every rig.

    The string is the anchor because it was the shared idiom across all four
    sites; the policy that replaced it lives in one module, tested above.
    """
    offenders = []
    for path in sorted(UCI.glob("*.py")):
        text = path.read_text()
        if "writing anyway" in text and path.name != "_device_prep.py":
            offenders.append(path.name)
    assert not offenders, (
        f"{offenders} still degrade toward the config write on a failed "
        "probe (issue #187). The write is the hazard the probe exists to "
        "avoid; an unreadable turbo state must abort, and an unreadable REU "
        "state is handled inside _device_prep.prepare_device."
    )


def test_rigs_do_not_hand_roll_the_turbo_probe() -> None:
    """One policy, one place. A second copy is a second thing to drift.

    The category-descent idiom (``cat.get(CAT_U64_SPECIFIC, cat)``) is what
    #187 documents as ambiguous, and it existed in four copies.
    """
    offenders = [
        path.name for path in sorted(UCI.glob("*.py"))
        if "get_config_category(CAT_U64_SPECIFIC)" in path.read_text()
    ]
    assert not offenders, (
        f"{offenders} still probe the turbo state inline. Route it through "
        "_device_prep.prepare_device so the failure policy has one home."
    )


def _main(tests=None) -> int:
    """Run the checks without pytest.

    Catches more than AssertionError for the same reason
    ``tools/test_reu_preflight.py`` does: the code under test converts read
    failures into its own exception type, so a regression can reach the
    runner wearing a DevicePrepError and abort the remaining tests.
    """
    if tests is None:
        tests = {name: obj for name, obj in sorted(globals().items())
                 if name.startswith("test_") and callable(obj)}
    failed = 0
    for name, fn in tests.items():
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
        except BaseException as exc:                  # noqa: BLE001
            failed += 1
            captured = getattr(exc, "captured", "")
            print(f"ERROR {name}: {exc.__class__.__name__}: {exc}"
                  + (f"\n--- captured ---\n{captured}" if captured else ""))
        else:
            print(f"ok   {name}")
    print(f"\n{len(tests) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
