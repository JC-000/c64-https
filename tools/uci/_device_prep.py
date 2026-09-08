#!/usr/bin/env python3
"""tools/uci/_device_prep.py — reset-then-configure device prep for the UCI rigs.

Three defects, one shape (issues #197, #187, and the second half of #212).

Why this exists
---------------
Device configuration on an Ultimate is **runtime-only**: every re-flash
returns factory defaults, we never write flash, and a power cycle reverts
whatever the last lane left behind. So ``RAM Expansion Unit: Disabled`` and
``CPU Speed: 1`` are the *default*, not an anomaly, and the working pattern
is that a run **restores baseline and then sets what it needs** rather than
hoping the previous lane reverted its changes.

The rigs were doing neither half of that consistently:

* **#197 — read and refuse, never set.** ``preflight_reu`` is the #97
  backstop for a rig that forgot to prepare the device. Four of its five
  callers had nothing for it to back up: on a device at its factory default
  they exited 4 instead of enabling the REU and running. Observed on a U64E
  at fw 3.15 while validating PR #181.
* **#187 — the turbo probe degraded toward the risky action.** All four
  HTTPS rigs read ``CPU Speed`` / ``Turbo Control`` in order to *skip* a
  redundant write, because the write itself glitches the UCI bridge and
  loses the next pushed command (the documented second cause of
  ``UCI_ERR_NO_SOCKET`` / ``$88``). When the read failed they printed
  ``writing anyway`` — performing the exact action the probe exists to
  avoid, with an intermittent ``$88`` as the symptom and a project history
  of blaming that on firmware.
* **#212 (second half) — no run recorded the device state it ran against.**
  A peer lane left the device at 1 MHz with the REU disabled; the next comb
  run's boot precompute (~45 s at 48 MHz, ~36 min at 1 MHz) could not finish
  inside the rig's boot budget and failed in a way that reads exactly like a
  code defect. It was diagnosed only because a prep had printed its
  before-state.

The failure policy, and why it differs per item
-----------------------------------------------
Both directions of "degrade on an unreadable probe" are wrong somewhere, so
this module does not have one policy — it has one *question*: which way does
an unreadable read fall, and what does the fall cost?

* **REU: an unreadable probe writes anyway.** The write *is* the safe action
  (it is the configuration the run needs) and a wasted one costs a REST PUT.
  This is ``rig_https_wiki.py``'s ``ensure_reu_16mb`` shape, kept
  deliberately — #197 calls it out as the correct asymmetry.
* **Turbo: an unreadable probe ABORTS the run**, after one retry. Neither
  degrade is safe here. Writing anyway risks the ``$88`` the probe was added
  to avoid; skipping the write risks running the whole rig at whatever clock
  the last lane left, which invalidates every wall-clock number the run
  produces and is exactly #212's misdiagnosed comb-boot failure. A rig that
  cannot establish the device's clock cannot produce a trustworthy
  measurement either, so it stops where that costs seconds — with a named
  override, on the ``C64_SKIP_REU_PREFLIGHT`` model::

      C64_FORCE_TURBO_WRITE=1 <your command>

  reinstates the old write-anyway degrade for someone who has decided the
  ``$88`` risk is the one they want.

Nothing here resets a store. Baseline restoration is the harness's
``apply_factory_baseline()`` (opt-in with ``U64_BASELINE_ON_ENTRY=1``, run by
``create_manager(backend="u64")`` inside the DeviceLock); it refuses five
stores by design — the three network stores, ``SID Sockets Configuration``
(its reset cuts SID socket power while reporting clean) and ``Clock
Settings`` (its reset arms an RTC rollback). Neither REU store is in that
set, and this module PUTs only the four items it names below.

What it does NOT do
-------------------
It does not replace ``preflight_reu``. Prep is setup; the preflight stays
where it is, **after** prep, as the guard for the case where prep was
skipped, overridden, or did not take. Both are cheap.

An on-chip build makes **no REU call at all** — the point of that profile is
that it needs none, and a preparation step must not start blocking the
configuration we recommend to REU-less users.

Every device read goes through ``_reu_preflight._read_config_value``, so the
harness-shape tolerance argued in issue #179 (``get_config_value`` preferred,
both legacy envelope shapes still read) is shared rather than re-implemented
here: there is one place to audit against the sibling harness tree, not two.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

from _reu_preflight import (
    CAT_CART,
    ITEM_REU_ENABLED,
    ITEM_REU_SIZE,
    _read_config_value,
    detect_crypto_profile,
)

CAT_U64_SPECIFIC = "U64 Specific Settings"
ITEM_CPU_SPEED = "CPU Speed"
ITEM_TURBO_CONTROL = "Turbo Control"

#: The REU size every crypto-path rig is prepared with. 16 MB because the
#: wikipedia sink writes REU bank ``$10`` (beyond the flash-saved 512 KB) and
#: nothing on this path needs *less*; one size across the rigs also keeps the
#: device state they report comparable.
REQUIRED_REU_SIZE = "16 MB"

#: Deliberate override for the turbo fail-closed described above.
FORCE_TURBO_WRITE_ENV = "C64_FORCE_TURBO_WRITE"
#: Skips the whole prep. The REU preflight still runs, and still fails closed.
SKIP_ENV = "C64_SKIP_DEVICE_PREP"

#: Where the machine-readable record goes when set — the variable the HTTPS
#: rigs already use for their artifacts.
DEBUG_DIR_ENV = "UCI_DEBUG_DIR"

#: The only four config items this module reads or writes.
STATE_ITEMS: tuple[tuple[str, str], ...] = (
    (CAT_U64_SPECIFIC, ITEM_TURBO_CONTROL),
    (CAT_U64_SPECIFIC, ITEM_CPU_SPEED),
    (CAT_CART, ITEM_REU_ENABLED),
    (CAT_CART, ITEM_REU_SIZE),
)

#: Suffix under which a failed read's exception text is recorded alongside
#: the ``None`` value it produced.
ERROR_SUFFIX = "!error"


class DevicePrepError(RuntimeError):
    """Raised when the device cannot be brought to a state we can trust."""


def _env_true(name: str) -> bool:
    return os.environ.get(name, "0").strip().lower() not in (
        "0", "", "no", "false", "off",
    )


def read_device_state(client: Any) -> dict[str, str | None]:
    """Read the four items this module owns. Never raises.

    :returns: ``{"<Category>/<Item>": value}`` with ``None`` where the read
        failed or produced nothing usable, plus a ``"<key>!error"`` entry
        carrying the exception text for a read that raised. Errors are
        recorded rather than raised because the before-state is a *report*;
        every decision that depends on a value tests it for ``None`` itself,
        and the two decisions fall in opposite directions (see the module
        docstring).
    """
    state: dict[str, str | None] = {}
    for category, item in STATE_ITEMS:
        key = f"{category}/{item}"
        try:
            state[key] = _read_config_value(client, category, item)
        except Exception as exc:                     # noqa: BLE001 — reported
            state[key] = None
            state[key + ERROR_SUFFIX] = f"{exc.__class__.__name__}: {exc}"
    return state


def format_state(state: dict[str, str | None]) -> str:
    """One line naming every item, its value, and any read error."""
    parts = []
    for category, item in STATE_ITEMS:
        key = f"{category}/{item}"
        err = state.get(key + ERROR_SUFFIX)
        if err:
            parts.append(f"{item}=<unreadable: {err}>")
        else:
            parts.append(f"{item}={state.get(key)!r}")
    return ", ".join(parts)


def _turbo_matches(state: dict[str, str | None], want_speed: str) -> bool | None:
    """``True``/``False`` when both turbo items read; ``None`` when either did not.

    ``None`` is the whole point of this helper: an item that came back
    unreadable must not be compared as if it had answered, which is how the
    old ``inner.get(...)`` descent turned "absent" and "None" into the same
    thing (#187).
    """
    speed = state.get(f"{CAT_U64_SPECIFIC}/{ITEM_CPU_SPEED}")
    control = state.get(f"{CAT_U64_SPECIFIC}/{ITEM_TURBO_CONTROL}")
    if speed is None or control is None:
        return None
    return str(speed).strip() == want_speed.strip() and str(control) == "Manual"


def _reu_matches(state: dict[str, str | None], want_size: str) -> bool | None:
    """``True``/``False`` when both REU items read; ``None`` when either did not."""
    enabled = state.get(f"{CAT_CART}/{ITEM_REU_ENABLED}")
    size = state.get(f"{CAT_CART}/{ITEM_REU_SIZE}")
    if enabled is None or size is None:
        return None
    return str(enabled) == "Enabled" and str(size).strip() == want_size.strip()


def _turbo_failure_message(state: dict[str, str | None], mhz: int) -> str:
    """The abort text. Says what could not be read, why neither degrade is safe."""
    return (
        "\n"
        "DEVICE PREP FAILED — could not read the device's CPU Speed / Turbo "
        "Control,\n"
        "so this run cannot establish the clock it would be measuring at.\n"
        "\n"
        f"  wanted: {CAT_U64_SPECIFIC} / {ITEM_CPU_SPEED} = {mhz} MHz, "
        f"{ITEM_TURBO_CONTROL} = 'Manual'\n"
        f"  got   : {format_state(state)}\n"
        "\n"
        "This is not a warning, and it deliberately does NOT fall back to "
        "writing\n"
        "the setting anyway (issue #187). The turbo config WRITE is itself "
        "the\n"
        "hazard: even a redundant one glitches the UCI bridge and loses the "
        "next\n"
        "pushed command, surfacing as UCI_ERR_NO_SOCKET ($88) on the first\n"
        "TCP_CONNECT — the exact failure this probe was added to avoid. "
        "Skipping\n"
        "the write is no safer: the rig would then run at whatever clock the "
        "last\n"
        "lane left behind, which invalidates every wall-clock number it "
        "produces\n"
        "and is how a 1 MHz comb boot got misdiagnosed as a code defect "
        "(#212).\n"
        "\n"
        "Likely causes, most common first:\n"
        "\n"
        "  1. The device is unreachable, or REST is refusing. Check it with\n"
        "     tools/uci/boot_check.py before concluding anything. REST "
        "refusing\n"
        "     instantly while ping still answers is the writemem exhaustion "
        "wedge\n"
        "     (GideonZ/1541ultimate#686) — tools/uci/_temp_gc.py. Do NOT jump "
        "to\n"
        "     'firmware corruption'; that verdict has been reached wrongly "
        "and\n"
        "     repeatedly on this project.\n"
        "\n"
        "  2. c64-test-harness changed the shape of its config accessors. It "
        "is\n"
        "     installed editable from a sibling working tree, so a merge "
        "there\n"
        "     lands here with no commit on our side (issue #179). Check\n"
        "     Ultimate64Client.get_config_value against "
        "tools/uci/_reu_preflight.py.\n"
        "\n"
        "  3. The firmware does not expose these items under these names.\n"
        "\n"
        "To proceed by writing the setting blind, accepting the $88 risk:\n"
        "\n"
        f"       {FORCE_TURBO_WRITE_ENV}=1 <your command>\n"
        "\n"
        f"  Or skip prep entirely with {SKIP_ENV}=1 (the REU preflight still "
        "runs).\n"
    )


def prepare_device(
    client: Any,
    labels_path: Path | str,
    *,
    turbo_mhz: int | None = None,
    reu_size: str = REQUIRED_REU_SIZE,
    stream: Any = None,
    set_turbo: Callable[[Any, int], None] | None = None,
    set_reu: Callable[..., None] | None = None,
    speed_enum: Callable[[int], str] | None = None,
    artifact_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Bring the device to the state this build needs, and report both states.

    Call under the DeviceLock, after ``enable_uci``, and **before**
    ``preflight_reu`` — the preflight stays as the guard behind this.

    :param client: connected ``Ultimate64Client``.
    :param labels_path: ``build/labels.txt`` from the current link; decides
        whether the REU is needed at all (:func:`detect_crypto_profile`).
    :param turbo_mhz: CPU speed to boot at, or ``None`` to leave the clock
        alone entirely (no decision, so nothing to fail on).
    :param reu_size: ``REU Size`` enum to set when the REU is configured.
    :param stream: where progress goes (default ``sys.stdout``).
    :param set_turbo: injected for tests; defaults to the harness's
        ``set_turbo_mhz``.
    :param set_reu: injected for tests; defaults to the harness's ``set_reu``.
    :param speed_enum: injected for tests; defaults to the harness's
        ``cpu_speed_enum``.
    :param artifact_dir: where ``device_state.json`` is written; defaults to
        ``$UCI_DEBUG_DIR`` when set, else nothing is written.
    :returns: the report dict (the same content as ``device_state.json``).
    :raises DevicePrepError: the turbo state could not be read and
        ``C64_FORCE_TURBO_WRITE`` is not set. Never raised for the REU, which
        degrades toward writing what the run needs.
    """
    out = stream if stream is not None else sys.stdout
    profile, reason = detect_crypto_profile(labels_path)
    report: dict[str, Any] = {
        "host": getattr(client, "host", None),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "profile": profile,
        "profile_reason": reason,
        "wanted": {
            "turbo_mhz": turbo_mhz,
            "reu": None if profile == "onchip" else reu_size,
        },
        "wrote": [],
        "skipped_write": [],
        "skipped": False,
    }

    if _env_true(SKIP_ENV):
        print(f"device prep: skipped ({SKIP_ENV} set) — the REU preflight "
              "still runs and still fails closed", file=out, flush=True)
        report["skipped"] = True
        _write_artifact(report, artifact_dir, out)
        return report

    before = read_device_state(client)
    report["before"] = before
    print(f"device state before: {format_state(before)}", file=out, flush=True)

    # ---------------------------------------------------------------- REU
    # On-chip builds need no REU, so nothing is read, written or reported
    # about one. Anything else gets the configuration it needs, and an
    # unreadable probe degrades toward WRITING it (#197's asymmetry).
    if profile == "onchip":
        print(f"device prep: on-chip profile ({reason}) — no REU "
              "configuration needed", file=out, flush=True)
    else:
        match = _reu_matches(before, reu_size)
        if match is True:
            print(f"device prep: REU already (Enabled, {reu_size}) — "
                  "skipping config write", file=out, flush=True)
            report["skipped_write"].append("reu")
        else:
            if match is None:
                print("device prep: REU state unreadable — writing the "
                      "configuration this build needs anyway (here the write "
                      "is the safe direction)", file=out, flush=True)
            print(f"device prep: setting REU (Enabled, {reu_size}) — "
                  "runtime-only, REVERTS ON POWER CYCLE", file=out, flush=True)
            writer = set_reu if set_reu is not None else _harness_set_reu()
            writer(client, True, size=reu_size)
            report["wrote"].append("reu")
            time.sleep(float(os.environ.get("REU_SETTLE", "3.0")))

    # -------------------------------------------------------------- turbo
    if turbo_mhz is not None:
        enum = speed_enum if speed_enum is not None else _harness_speed_enum()
        want_speed = str(enum(turbo_mhz))
        match = _turbo_matches(before, want_speed)
        if match is None:
            # One retry: a single REST hiccup is not a reason to burn a
            # device slot, and a second failure is not a hiccup.
            time.sleep(float(os.environ.get("TURBO_PROBE_RETRY_DELAY", "1.0")))
            retry = read_device_state(client)
            report["turbo_retry"] = retry
            print(f"device prep: turbo probe retry: {format_state(retry)}",
                  file=out, flush=True)
            match = _turbo_matches(retry, want_speed)
            if match is not None:
                report["before"] = before = retry
        if match is None and not _env_true(FORCE_TURBO_WRITE_ENV):
            raise DevicePrepError(_turbo_failure_message(before, turbo_mhz))
        if match is True:
            print(f"device prep: turbo already {turbo_mhz} MHz (Manual) — "
                  "skipping config write (avoids the $88 bridge glitch)",
                  file=out, flush=True)
            report["skipped_write"].append("turbo")
        else:
            if match is None:
                print(f"device prep: turbo state unreadable and "
                      f"{FORCE_TURBO_WRITE_ENV} is set — writing blind, "
                      "accepting the $88 risk", file=out, flush=True)
            print(f"device prep: setting turbo to {turbo_mhz} MHz (Manual)",
                  file=out, flush=True)
            writer = set_turbo if set_turbo is not None else _harness_set_turbo()
            writer(client, turbo_mhz)
            report["wrote"].append("turbo")
            time.sleep(float(os.environ.get("TURBO_SETTLE", "3.0")))

    after = read_device_state(client)
    report["after"] = after
    print(f"device state after : {format_state(after)}", file=out, flush=True)
    if report["wrote"]:
        print(f"device prep: wrote {', '.join(report['wrote'])} — "
              "runtime-only, reverts on power cycle", file=out, flush=True)
    _write_artifact(report, artifact_dir, out)
    return report


def _write_artifact(report: dict[str, Any], artifact_dir, out) -> None:
    """Persist the record so a run's artifacts say which device state produced it.

    Best-effort by design (#212 asks for the record, not for a new way to
    fail): an unwritable directory costs a line of output, not the run.
    """
    target = artifact_dir if artifact_dir is not None else os.environ.get(DEBUG_DIR_ENV)
    if not target:
        return
    try:
        path = Path(target)
        path.mkdir(parents=True, exist_ok=True)
        dest = path / "device_state.json"
        dest.write_text(json.dumps(report, indent=2, default=str))
        print(f"device prep: state recorded in {dest}", file=out, flush=True)
    except Exception as exc:                          # noqa: BLE001
        print(f"device prep: (could not record device state: {exc})",
              file=out, flush=True)


# The three harness entry points, imported lazily so this module can be
# loaded (and unit-tested) without c64_test_harness installed, and so the
# tests can inject fakes without patching module globals.
def _harness_set_turbo():
    from c64_test_harness.backends.ultimate64_helpers import set_turbo_mhz
    return set_turbo_mhz


def _harness_set_reu():
    from c64_test_harness.backends.ultimate64_helpers import set_reu
    return set_reu


def _harness_speed_enum():
    from c64_test_harness.backends.ultimate64_helpers import cpu_speed_enum
    return cpu_speed_enum
