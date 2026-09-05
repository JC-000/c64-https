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
                              "values": ["Disabled", "Enabled"],
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
                              "values": ["Disabled", "Enabled"],
                              "default": "Disabled"})
    exc = _assert_raises_preflight(client, what="item map / Disabled")
    assert "REU PREFLIGHT FAILED" in str(exc)


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


def test_skip_env_still_bypasses() -> None:
    """C64_SKIP_REU_PREFLIGHT=1 is the documented escape hatch."""
    client = FakeClient(item=AssertionError("skipped preflight must not call out"))
    result, _out = _run(client, LABELS_REU, skip_env="1")
    assert result == "skipped"
    assert client.calls == []


def _main() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
        else:
            print(f"ok   {name}")
    print("FAILED" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_main())
