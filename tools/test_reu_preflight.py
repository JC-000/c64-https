#!/usr/bin/env python3
"""Guard tools/uci/_reu_preflight.py against harness shape drift (issue #179).

Nothing here touches VICE, hardware or a build. The ``Ultimate64Client`` is
faked, so this is pure logic and runs in milliseconds — which is the point:
the thing being guarded is a *hardware* preflight whose only failure mode is
to stop guarding, and that is not observable from a hardware run.

Why this exists
---------------
``preflight_reu`` is the guard against issue #97: a REU-profile PRG on a
REU-less device derives the wrong X25519 secret, fails the first AEAD tag,
and spins ~44 minutes on a screen that reads as a lockup. It reads the
device's ``RAM Expansion Unit`` config item through ``c64-test-harness``.

That harness is installed **editable** from a sibling working tree, so a
merge there changes this repo's behaviour with no commit here. Harness
PR #226 (their issue #214) did exactly that: ``get_config_item`` stopped
returning the REST envelope ``{category: {item: ...}}`` and started
returning the item's own map, ``{"current": ..., "values": [...], ...}``.
Our unwrap found neither key, returned ``None``, printed a WARNING and
**continued unchecked**. The 44-minute guard was gone and the run went on.

So two invariants are pinned here, and they are independent:

1. **Shape tolerance.** Both the item map (harness >= #226) and the legacy
   envelope (harness < #226) must be read correctly, and
   ``get_config_value`` must be preferred when the harness offers it.
   Neither direction of the harness landing may break us.

2. **Fail closed.** A value that cannot be read is *not* a result. It must
   raise ``ReuPreflightError``, not print a warning — a warning line in the
   middle of a 45-minute run is not something anyone reads, and the whole
   value of the preflight is that it fires before the wait, not after.

Invariant 2 is why the on-chip and skip paths are pinned too: failing closed
must not start blocking the REU-less configuration we actively recommend.

Runs under pytest, and standalone for anyone without pytest installed
(the repo declares no pytest dependency)::

    python3 tools/test_reu_preflight.py
"""

import importlib.util
import io
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PREFLIGHT_PATH = REPO / "tools" / "uci" / "_reu_preflight.py"

# tools/uci/ is in pytest.ini's norecursedirs (it is a rig directory), so
# the module under test is loaded by path rather than imported by name.
_spec = importlib.util.spec_from_file_location("_reu_preflight_ut", PREFLIGHT_PATH)
pf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pf)

CAT = pf.CAT_CART
ITEM = pf.ITEM_REU_ENABLED

#: The ``RAM Expansion Unit`` enum as real firmware reports it — measured on
#: a U64E (unique_id 601A96) at fw 3.15, not invented. The third value is the
#: point: ``"GeoRAM Mode"`` is settable and is neither Enabled nor Disabled,
#: so a device can legitimately answer something this check must refuse
#: without that answer being an error, a disabled REU, or an unreadable read.
REU_VALUES = ["Disabled", "Enabled", "GeoRAM Mode"]

# A labels file with neither the manifest equate nor an on-chip row
# generator: detect_crypto_profile calls that the REU profile, which is the
# only profile that reads device config at all.
LABELS_REU = "al 006000 .ecdsa_verify_256\nal 00A000 .tls_rec_buf\n"
# LIB_NISTCURVES_REU_BANKS_USED = 0 — the manifest equate saying "no REU".
LABELS_ONCHIP = "al 000000 .LIB_NISTCURVES_REU_BANKS_USED\nal 006000 .gen_mul_row\n"


class _HarnessError(Exception):
    """Stands in for Ultimate64ProtocolError (raised for a missing item)."""


class FakeClient:
    """Minimal Ultimate64Client stand-in.

    :param item: what ``get_config_item`` returns, or an Exception instance
        to raise.
    :param value: what ``get_config_value`` returns, or an Exception to
        raise. ``_ABSENT`` means the method does not exist at all — a
        pre-#226 harness.
    """

    _ABSENT = object()

    def __init__(self, item=None, value=_ABSENT):
        self._item = item
        self._value = value
        self.calls = []
        if value is not FakeClient._ABSENT:
            self.get_config_value = self._get_config_value

    def get_config_item(self, category, item):
        self.calls.append(("get_config_item", category, item))
        if isinstance(self._item, Exception):
            raise self._item
        if callable(self._item):
            return self._item(category, item)
        return self._item

    def _get_config_value(self, category, item):
        self.calls.append(("get_config_value", category, item))
        if isinstance(self._value, Exception):
            raise self._value
        if callable(self._value):
            return self._value(category, item)
        return self._value


def _run(client, labels_text=LABELS_REU, skip_env=None):
    """Call preflight_reu against a temp labels file. Returns (result, output).

    Raises whatever preflight_reu raises, with the captured output attached
    to the exception as ``.captured`` so a failing assertion can show it.
    """
    prev = os.environ.get(pf.SKIP_ENV)
    if skip_env is None:
        os.environ.pop(pf.SKIP_ENV, None)
    else:
        os.environ[pf.SKIP_ENV] = skip_env
    buf = io.StringIO()
    with tempfile.TemporaryDirectory() as tmp:
        labels = Path(tmp) / "labels.txt"
        labels.write_text(labels_text)
        try:
            result = pf.preflight_reu(client, labels, stream=buf)
        except BaseException as exc:      # noqa: BLE001 — re-raised below
            exc.captured = buf.getvalue()
            raise
        finally:
            if prev is None:
                os.environ.pop(pf.SKIP_ENV, None)
            else:
                os.environ[pf.SKIP_ENV] = prev
    return result, buf.getvalue()


def _assert_raises_preflight(client, labels_text=LABELS_REU, what=""):
    """Assert ReuPreflightError, and return it. Fail-open is the bug."""
    try:
        result, out = _run(client, labels_text)
    except pf.ReuPreflightError as exc:
        return exc
    raise AssertionError(
        f"{what}: preflight_reu returned {result!r} instead of raising "
        f"ReuPreflightError. The REU guard failed OPEN — the run would "
        f"continue and spin ~44 min on a REU-less device (issue #97/#179). "
        f"Output was:\n{out}"
    )


# --------------------------------------------------------------- shape

def test_item_map_enabled_is_read() -> None:
    """The post-#226 item map must read as Enabled, with no warning."""
    client = FakeClient(item={"current": "Enabled",
                              "values": REU_VALUES,
                              "default": "Disabled"})
    result, out = _run(client)
    assert result == "reu", f"expected the REU profile, got {result!r}"
    assert "WARNING" not in out and "unchecked" not in out, (
        "preflight_reu did not understand the harness item map "
        "{'current': ...} and fell back to its warn-and-continue path:\n"
        f"{out}\n"
        "That is issue #179: the #97 guard is silently gone."
    )
    assert "OK" in out, f"expected a pass line, got:\n{out}"


def test_item_map_disabled_raises() -> None:
    """Disabled in the item map must still stop the run."""
    client = FakeClient(item={"current": "Disabled",
                              "values": REU_VALUES,
                              "default": "Disabled"})
    exc = _assert_raises_preflight(client, what="item map / Disabled")
    assert "REU PREFLIGHT FAILED" in str(exc)


def test_georam_mode_is_not_an_reu() -> None:
    """A third enum value must refuse, and it is not a hypothetical.

    Real firmware offers ``"GeoRAM Mode"`` alongside Enabled and Disabled.
    It is not an REU, so a REU-profile build must not run against it — and
    it is not an unreadable read either, so it earns the device-level
    message, not the "could not read" one.

    The code is already right, by comparing ``current`` *against*
    ``"enabled"`` rather than against ``"disabled"``. That is worth
    pinning precisely because it is right by construction and nothing
    forced it: the plausible alternative — refuse only what says
    "Disabled" — passes every other check in this file and lets GeoRAM
    Mode through as if an REU were present. Verified by mutation, not
    assumed.
    """
    client = FakeClient(item={"current": "GeoRAM Mode", "values": REU_VALUES})
    exc = _assert_raises_preflight(client, what="GeoRAM Mode")
    text = str(exc)
    assert "REU PREFLIGHT FAILED" in text
    assert "GeoRAM Mode" in text, (
        f"the observed value must appear in the message:\n{text}"
    )
    assert "could not read" not in text, (
        "GeoRAM Mode is a successful read of a value we must refuse, not "
        f"an unreadable one; it earns the device-level message:\n{text}"
    )


def test_legacy_envelope_still_read() -> None:
    """A pre-#226 harness must keep working — we must not break backwards."""
    client = FakeClient(item={CAT: {ITEM: "Enabled"}})
    result, out = _run(client)
    assert result == "reu"
    assert "WARNING" not in out, f"legacy REST envelope no longer read:\n{out}"


def test_legacy_nested_envelope_still_read() -> None:
    """The other pre-#226 device shape: envelope wrapping an item map."""
    client = FakeClient(item={CAT: {ITEM: {"current": "Disabled"}}})
    exc = _assert_raises_preflight(client, what="legacy nested / Disabled")
    assert "REU PREFLIGHT FAILED" in str(exc)


def test_get_config_value_is_preferred() -> None:
    """When the harness offers get_config_value, use it.

    It is the accessor that resolves the item the way the firmware does and
    raises rather than guessing. Reaching past it to get_config_item means
    re-implementing name resolution we do not own.
    """
    client = FakeClient(
        item=AssertionError("get_config_item must not be called when "
                            "get_config_value exists"),
        value="Enabled",
    )
    result, out = _run(client)
    assert result == "reu"
    assert ("get_config_value", CAT, ITEM) in client.calls, (
        f"get_config_value was never called; calls were {client.calls!r}"
    )
    assert "WARNING" not in out, out


# ---------------------------------------------------------- fail closed

def test_read_failure_fails_closed() -> None:
    """A raising harness (missing item, HTTP error) must fail the run."""
    client = FakeClient(item=_HarnessError("item 'RAM Expansion Unit' absent"))
    exc = _assert_raises_preflight(client, what="get_config_item raised")
    assert pf.SKIP_ENV in str(exc), (
        "the failure message must name the documented bypass "
        f"{pf.SKIP_ENV}=1; got:\n{exc}"
    )


def test_get_config_value_failure_fails_closed() -> None:
    """Same, through the new accessor."""
    client = FakeClient(value=_HarnessError("no 'current' value"))
    exc = _assert_raises_preflight(client, what="get_config_value raised")
    assert pf.SKIP_ENV in str(exc)


def test_unrecognised_shape_fails_closed() -> None:
    """A shape we cannot parse is not a result. It is a failure."""
    for shape in ({}, [], "Enabled", {CAT: {}}, {"values": ["Enabled"]}, None):
        client = FakeClient(item=shape)
        exc = _assert_raises_preflight(client, what=f"shape {shape!r}")
        assert pf.SKIP_ENV in str(exc)


# ------------------------------------------------- paths that must stay open

def test_onchip_build_makes_no_device_call() -> None:
    """Failing closed must not start blocking the REU-less configuration.

    The on-chip profile needs no REU, so the preflight must not read device
    config at all — a client that explodes on contact still passes.
    """
    client = FakeClient(item=AssertionError("no device call for an onchip build"),
                        value=AssertionError("no device call for an onchip build"))
    result, out = _run(client, LABELS_ONCHIP)
    assert result == "onchip", f"expected onchip, got {result!r}"
    assert client.calls == [], f"onchip build touched the device: {client.calls!r}"
    assert "no REU required" in out


def test_empty_current_is_unreadable_not_disabled() -> None:
    """An empty ``current`` is an inconclusive read, not a disabled REU.

    Both outcomes stop the run, so this is only about which of the two
    messages the operator gets — and they point at different machines. The
    "Disabled" text sends them to the device's settings menu; here the
    device said nothing intelligible, and nothing has been learned about
    whether the REU is there.
    """
    client = FakeClient(item={"current": "", "values": REU_VALUES})
    exc = _assert_raises_preflight(client, what="empty current")
    assert "could not read" in str(exc), (
        "an empty value was reported as a disabled REU. It is an "
        f"unreadable one — nothing was learned about the device:\n{exc}"
    )


def test_standalone_runner_reports_a_converted_exception() -> None:
    """The standalone runner must survive a non-AssertionError and go on.

    The house pattern (test_pytest_boundary.py, test_runner_coverage.py)
    catches only AssertionError, and for those two it is right: they are
    pure AST inspection and nothing else can be raised. It does not
    transfer here. The code under test deliberately converts *any*
    exception into ReuPreflightError, which is exactly how the fake
    client's "you must not call me" AssertionError comes back — so a
    regression in the on-chip guard reaches the runner wearing a
    ReuPreflightError, escapes the except, and aborts the run partway with
    the remaining tests unrun and a REU PREFLIGHT FAILED banner on screen
    that reads as "your device has no REU".

    Measured on a mutant with the on-chip early return removed: 6 ok
    lines, then a traceback, three tests never run.
    """
    ran = []

    def passing():
        ran.append("passing")

    def converted():
        ran.append("converted")
        try:
            raise AssertionError("no device call for an onchip build")
        except AssertionError as exc:
            raise pf.ReuPreflightError("REU PREFLIGHT FAILED\n...banner...") from exc

    buf = io.StringIO()
    stdout = sys.stdout
    sys.stdout = buf
    try:
        rc = _main(tests={"test_a_converted": converted,
                          "test_b_passing": passing})
    finally:
        sys.stdout = stdout
    out = buf.getvalue()

    assert ran == ["converted", "passing"], (
        f"the runner stopped at the first non-AssertionError; ran {ran!r}. "
        "Every later test is then silently unrun."
    )
    assert rc == 1, f"a raising test must fail the run; rc={rc}"
    assert "test_b_passing" in out, f"later tests were not reported:\n{out}"
    assert "no device call for an onchip build" in out, (
        "the runner reported the converted ReuPreflightError without the "
        f"AssertionError that caused it, which is the whole diagnosis:\n{out}"
    )


def test_skip_env_still_bypasses() -> None:
    """C64_SKIP_REU_PREFLIGHT=1 is the documented escape hatch."""
    client = FakeClient(item=AssertionError("skipped preflight must not call out"))
    result, _out = _run(client, LABELS_REU, skip_env="1")
    assert result == "skipped"
    assert client.calls == []


def _first_assertion_cause(exc):
    """The first AssertionError in *exc*'s cause/context chain, if any.

    The fake client signals "you must not have called me" by raising
    AssertionError. ``preflight_reu`` converts any exception into a
    ReuPreflightError whose banner is about a missing REU, so the sentence
    that actually diagnoses the regression is buried in ``__cause__``.
    Dig it back out and lead with it.
    """
    seen = set()
    cur = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, AssertionError):
            return cur
        cur = cur.__cause__ or cur.__context__
    return None


def _main(tests=None) -> int:
    """Run the checks without pytest. *tests* is a {name: callable} map.

    Unlike this repo's other standalone guards (test_pytest_boundary.py,
    test_runner_coverage.py), this one must catch more than AssertionError.
    Those two are pure AST inspection and can raise nothing else; the code
    under test *here* deliberately converts any exception into
    ReuPreflightError. Catching only AssertionError let a regression in the
    on-chip guard abort the whole run partway — measured on a mutant with
    the early return removed: six ok lines, a traceback, three tests never
    run, and a "REU PREFLIGHT FAILED" banner on screen that reads as a
    device problem rather than a test failure. An unrun test is not a
    passing one, so every case gets its own line either way.
    """
    if tests is None:
        tests = {n: f for n, f in globals().items()
                 if n.startswith("test_") and callable(f)}
    failures = 0
    for name, fn in sorted(tests.items()):
        try:
            fn()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
        except Exception as exc:      # noqa: BLE001 — a raise is a result
            failures += 1
            cause = _first_assertion_cause(exc)
            summary = str(exc).strip().splitlines()
            summary = summary[0] if summary else ""
            print(f"ERROR {name}: {type(exc).__name__}: {summary}")
            if cause is not None:
                print(f"       caused by AssertionError: {cause}")
        else:
            print(f"ok   {name}")
    print("FAILED" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_main())
