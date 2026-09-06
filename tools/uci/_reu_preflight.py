"""tools/uci/_reu_preflight.py — fail fast when a REU-profile PRG meets a REU-less device.

Why this exists (issue #97)
---------------------------
The default ``make BACKEND=uci`` image is the **REU profile**: both
``src/crypto/fe25519.s`` (X25519 field multiply) and the
``libs/nistcurves`` P-256 archive fetch their 8x8 multiply rows from REU
banks by DMA. On a machine with no REU — and the C64 Ultimate ships with
``RAM Expansion Unit: Disabled`` — that DMA **silently does nothing**. It
does not fault. The rows keep whatever ``src/boot.s::reu_mul_init`` left
behind, so every multiply returns a wrong-but-deterministic result.

The consequence is not a crash but a wrong ECDH shared secret, wrong
handshake keys, and an AEAD tag failure on the first encrypted record.
``src/tls13.s`` then spins 65,536 ``net_poll`` calls at ~40 ms each
looking for a record it can decrypt — about **44 minutes** of what
appears to be a lockup, with the screen frozen at ``... KEYS ENC1 RX``.

An outside contributor lost a working day to exactly that (issue #97),
including a wasted cold power cycle after we mis-matched the screen to
the unrelated device-wedge signature. The prerequisite was documented
nowhere on the UCI test path, and it is a prerequisite a program can
check in one REST call. So we check it.

What it does
------------
:func:`preflight_reu` is called under the DeviceLock the script already
holds, before the long run:

* Builds that do not need the REU (``USE_NISTCURVES_ONCHIP``) are let
  through untouched — **no REST call is made at all**, so there is no
  added latency and no new failure surface on the path we actively
  recommend to REU-less users.
* REU-profile builds read ``C64 and Cartridge Settings / RAM Expansion
  Unit``. Enabled: one line of output, carry on. Disabled: raise
  :class:`ReuPreflightError` immediately, naming both remedies.
* **Anything else is also a failure** — a read that raises, or a
  response shape this file cannot parse, raises
  :class:`ReuPreflightError` too (issue #179). It warned and continued
  until c64-test-harness PR #226 changed ``get_config_item``'s return
  shape under us, through the shared editable venv, and the guard went
  quietly missing on a live path. An unverified device is not a
  verified one. ``C64_SKIP_REU_PREFLIGHT=1`` is the way past it.

What it deliberately does NOT do
--------------------------------
**It never enables the REU for you.** #97 offered that as an option and
it is the wrong trade: the U64E is a queue-shared device across the
c64-* projects, REST config writes persist until the next power cycle,
and a test that silently reconfigures someone else's hardware turns a
legible error into a mystery two runs later on a different branch. A
clear refusal costs seconds; a silent reconfiguration costs trust.

Detection
---------
"Does this PRG need the REU?" is decided from ``build/labels.txt``,
which ld65 emits from the same link as ``build/c64-https.prg`` — every
script guarded here loads both from ``build/``, so the labels always
describe the image that is about to run.

Markers are checked as a **union**, not a conjunction, so renaming any
single one upstream does not silently reclassify an onchip build as
REU-profile (which would block the very configuration we recommend):

* ``LIB_NISTCURVES_REU_BANKS_USED == 0`` — the c64-lib-contract manifest
  equate. The library states its own REU claim; 3 under the REU profile,
  0 under ``FP_ONCHIP_MUL``. This is the semantically exact one.
* ``gen_mul_row`` — the sibling archive's on-chip row generator.
* ``fe_gen_mul_row`` — the in-tree ``fe25519.s`` counterpart (PR #69).
  This is the symbol that maps most directly to #97's failure, since
  X25519 is what breaks first.
* ``sqtab_reserved`` — ``src/data.s``'s onchip-only placeholder, present
  only when the sibling supplies ``sqtab_lo/hi`` as absolute equates.

Absence of every marker means "REU profile", which is the fail-closed
answer: the worst case of a bad detect is one clear error message with
an override, versus 44 minutes of silence.

Escape hatch: ``C64_SKIP_REU_PREFLIGHT=1`` skips the whole thing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

CAT_CART = "C64 and Cartridge Settings"
ITEM_REU_ENABLED = "RAM Expansion Unit"
ITEM_REU_SIZE = "REU Size"

#: Symbols/equates that appear in ``build/labels.txt`` only for a build
#: whose crypto generates multiply rows on the CPU. See module docstring.
_ONCHIP_SYMBOLS = ("gen_mul_row", "fe_gen_mul_row", "sqtab_reserved")

#: Manifest equate: REU banks the nistcurves archive claims. 0 == onchip.
_BANKS_EQUATE = "LIB_NISTCURVES_REU_BANKS_USED"

SKIP_ENV = "C64_SKIP_REU_PREFLIGHT"


class ReuPreflightError(RuntimeError):
    """Raised when a REU-profile PRG would run on a device with no REU."""


def _parse_labels(labels_path: Path) -> dict[str, int]:
    """Return ``{symbol: value}`` from an ld65/VICE label file.

    Accepts both the raw ca65 shape (``al 006000 .name``) and the
    VICE-rewritten shape the Makefile produces (``al C:6000 .name``).
    Leading ``.`` is stripped from the symbol. Unparseable lines are
    skipped rather than raising — this file is diagnostic input, and a
    single odd line must not take down a test run.
    """
    out: dict[str, int] = {}
    try:
        text = labels_path.read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[0] != "al":
            continue
        raw_addr = fields[1]
        if raw_addr.upper().startswith("C:"):
            raw_addr = raw_addr[2:]
        try:
            value = int(raw_addr, 16)
        except ValueError:
            continue
        out[fields[2].lstrip(".")] = value
    return out


def detect_crypto_profile(labels_path: Path | str) -> tuple[str, str]:
    """Classify the linked build as ``"onchip"`` or ``"reu"``.

    :param labels_path: path to ``build/labels.txt`` from the same link
        as the PRG about to be run.
    :returns: ``(profile, reason)`` where *profile* is ``"onchip"`` or
        ``"reu"`` and *reason* is a short human-readable justification
        suitable for printing.
    """
    labels = _parse_labels(Path(labels_path))
    if not labels:
        return ("reu", f"could not read {labels_path} — assuming REU profile")

    banks = labels.get(_BANKS_EQUATE)

    # The manifest equate is AUTHORITATIVE whenever it is present, and it
    # decides in BOTH directions. The on-chip symbols are a fallback for
    # when it is absent, not co-equal votes.
    #
    # This ordering is load-bearing, and getting it wrong shipped a real
    # hole. The comb profile (USE_NISTCURVES_ONCHIP_COMB) generates multiply
    # rows on the CPU — so `gen_mul_row`, `fe_gen_mul_row` and
    # `sqtab_reserved` are all present — while still claiming REU **bank 2**
    # for the 16 KB Lim-Lee anchor table: it links with
    # LIB_NISTCURVES_REU_BANKS_USED = $04, not 0. Under the previous
    # symbol-union-first ordering those three symbols outvoted the equate,
    # the comb build was classified "onchip", and the device REU check was
    # skipped entirely — printing "no REU required" for an image that does
    # not work without one. Measured on a real comb build, 2026-08-15.
    #
    # That is exactly the failure #97's preflight exists to prevent, and it
    # matters more now that comb is a shipped product whose whole premise is
    # REU-plus-turbo.
    if banks is not None:
        if banks == 0:
            return ("onchip", f"{_BANKS_EQUATE}=0")
        return ("reu", f"{_BANKS_EQUATE}=${banks:02X} — claims REU bank(s)")

    # No manifest equate: fall back to the symbol union. Union rather than
    # conjunction so renaming any single symbol upstream cannot silently
    # reclassify an onchip build as REU-profile and block the configuration
    # we recommend to REU-less users.
    found = [name for name in _ONCHIP_SYMBOLS if name in labels]
    if found:
        return ("onchip", "+".join(found) + f" (no {_BANKS_EQUATE})")

    # No manifest equate and no onchip symbol. Most likely a genuine
    # REU-profile build; possibly a library layout we do not know.
    # Fail closed — the check is skippable, 44 minutes of spin is not.
    return ("reu", f"no {_BANKS_EQUATE} and no on-chip row generator")


def _extract_config_value(resp: Any, category: str, item: str) -> str | None:
    """Dig a scalar out of a U64 config read, defensively.

    Three shapes have to be read, and which one arrives is decided by the
    *harness version installed in the shared editable venv*, not by
    anything in this repo (issue #179)::

        # c64-test-harness >= PR #226 — get_config_item returns the item map
        {"current": "Enabled", "values": ["Disabled", "Enabled"], ...}

        # < #226 — get_config_item returned the raw REST envelope, with the
        # item either a bare scalar or its own map, depending on firmware
        {"C64 and Cartridge Settings": {"RAM Expansion Unit": "Enabled"}}
        {"C64 and Cartridge Settings":
            {"RAM Expansion Unit": {"current": "Enabled", "presets": [...]}}}

    The item map is tested for first and is unambiguous: a REST envelope is
    keyed by category name, so a top-level ``"current"`` can only be an item
    map. Reading both means a harness bump in either direction cannot break
    this guard.

    Returns ``None`` on anything unrecognised rather than guessing — an
    inconclusive read must not be reported as "Disabled", nor as "Enabled".
    :func:`preflight_reu` turns that ``None`` into a failure; see the
    fail-closed note there.
    """
    if not isinstance(resp, dict):
        return None
    # Item map (harness >= #226). Checked before the category descent.
    if "current" in resp:
        value = resp["current"]
        return None if value is None else str(value)
    inner = resp.get(category, resp)
    if not isinstance(inner, dict):
        return None
    value = inner.get(item)
    if isinstance(value, dict):
        value = value.get("current")
    if value is None:
        return None
    return str(value)


def _read_config_value(client: Any, category: str, item: str) -> str | None:
    """Read one config item's live value, across harness versions.

    ``Ultimate64Client.get_config_value`` arrived with harness PR #226 and
    returns the item's ``current`` directly, resolving category and item
    names the way the firmware does and raising rather than guessing. Prefer
    it; fall back to ``get_config_item`` + :func:`_extract_config_value` on
    an older harness, which is also the path that reads the legacy envelope.

    Exceptions propagate: an unreadable value is the caller's problem to
    fail on, not something to paper over here.
    """
    getter = getattr(client, "get_config_value", None)
    if callable(getter):
        value = getter(category, item)
        return None if value is None else str(value)
    return _extract_config_value(
        client.get_config_item(category, item), category, item
    )


def preflight_reu(
    client: Any,
    labels_path: Path | str,
    *,
    stream: Any = None,
) -> str:
    """Assert the device can run this build; raise if it demonstrably cannot.

    Call under the DeviceLock, after ``enable_uci``, before the reset /
    ``run_prg`` that starts the long run.

    :param client: connected ``Ultimate64Client``.
    :param labels_path: ``build/labels.txt`` from the current link.
    :param stream: where to print progress (default ``sys.stdout``).
    :returns: the detected profile, ``"onchip"`` or ``"reu"``.
    :raises ReuPreflightError: on a REU-profile build, for any of three
        outcomes — the device reported the REU **Disabled**; the read
        **raised**; or the read returned nothing usable (an unrecognised
        response shape, or an empty value). The last two are failures and
        not warnings on purpose: see the fail-closed note in the body and
        in the module docstring. Never raised for an on-chip build, which
        makes no device call, nor when ``C64_SKIP_REU_PREFLIGHT`` is set.
    """
    out = stream if stream is not None else sys.stdout

    if os.environ.get(SKIP_ENV, "0") != "0":
        print(f"REU preflight: skipped ({SKIP_ENV} set)", file=out, flush=True)
        return "skipped"

    profile, reason = detect_crypto_profile(labels_path)
    if profile == "onchip":
        # No REST call: the onchip image needs no REU, so there is
        # nothing to check and nothing to slow down.
        print(
            f"REU preflight: build is the on-chip profile ({reason}) — "
            "no REU required, skipping device check",
            file=out,
            flush=True,
        )
        return profile

    # Fail CLOSED from here down (issue #179). This used to warn and carry
    # on, on the theory that the probe was advisory. It is not: it is the
    # only thing standing between a REU-less device and 44 minutes of what
    # looks like a lockup, and a WARNING line scrolling past at minute one
    # of a 45-minute run is not something anyone reads. An unreadable value
    # is an unverified device, and an unverified device is a failure with a
    # named override — which costs seconds — not a result.
    #
    # This is also what makes the guard survive the harness moving under it.
    # c64-test-harness is installed editable from a sibling working tree, so
    # its PR #226 changed get_config_item's return shape here with no commit
    # in this repo; the old code answered that by warning and continuing.
    # _read_config_value now reads both shapes, and if a future change
    # defeats it as well, the run stops instead of pretending.
    try:
        enabled = _read_config_value(client, CAT_CART, ITEM_REU_ENABLED)
    except Exception as exc:  # noqa: BLE001 — any read failure is a failure
        raise ReuPreflightError(
            _unreadable_message(
                f"{exc.__class__.__name__}: {exc}", reason
            )
        ) from exc

    if enabled is None or not enabled.strip():
        # Empty is grouped with unrecognised, not with "Disabled". An empty
        # enum value teaches us nothing about the device, and the two
        # messages send the operator to different machines — the Disabled
        # text sends them to the settings menu for a fact not in evidence.
        detail = (
            "the value came back empty"
            if enabled is not None else
            "the harness returned a shape this check does not "
            "recognise (no readable value in the response)"
        )
        raise ReuPreflightError(_unreadable_message(detail, reason))

    if enabled.strip().lower() != "enabled":
        raise ReuPreflightError(_failure_message(enabled, reason))

    # The size is decoration on the pass line, so it stays best-effort:
    # nothing is decided by it, and there is nothing to fail closed about.
    try:
        size = _read_config_value(client, CAT_CART, ITEM_REU_SIZE)
    except Exception:  # noqa: BLE001 — cosmetic only
        size = None
    size_note = f", {size}" if size else ""
    print(
        f"REU preflight: REU-profile build ({reason}); device REU "
        f"Enabled{size_note} — OK",
        file=out,
        flush=True,
    )
    return profile


def _unreadable_message(detail: str, reason: str) -> str:
    """Compose the failure text for a REU state we could not read at all.

    Distinct from :func:`_failure_message`, which reports a device that
    answered "Disabled". Here the device's answer is unknown, so the text
    must not accuse it of anything — it says what could not be read, why
    that is fatal rather than advisory, and how to proceed anyway.
    """
    return (
        "\n"
        "REU PREFLIGHT FAILED — could not read the device's REU setting, and "
        "this\n"
        "build needs an REU.\n"
        "\n"
        f"  wanted: {CAT_CART} / {ITEM_REU_ENABLED}\n"
        f"  got   : {detail}\n"
        f"  build : REU profile ({reason})\n"
        "\n"
        "This is not treated as a warning. A REU-profile image on a device "
        "with no\n"
        "REU does not fail — it derives the wrong X25519 secret and spins "
        "~44 min on\n"
        "a screen ending 'KEYS ENC1 RX' (issue #97). An unverified device is "
        "not a\n"
        "verified one, so the run stops here where it costs seconds.\n"
        "\n"
        "Likely causes, most common first:\n"
        "\n"
        "  1. The device is unreachable, or REST is refusing. Check it with\n"
        "     tools/uci/boot_check.py before concluding anything. If REST "
        "refuses\n"
        "     instantly while ping still answers, that is the writemem "
        "exhaustion\n"
        "     wedge (GideonZ/1541ultimate#686) — tools/uci/_temp_gc.py. Run "
        "the\n"
        "     diagnostic ladder; do NOT jump to 'firmware corruption', which "
        "is a\n"
        "     verdict this project has reached wrongly and repeatedly.\n"
        "\n"
        "  2. c64-test-harness changed the shape of its config accessors. "
        "This repo\n"
        "     imports it from a shared editable venv, so a merge in that "
        "repo lands\n"
        "     here immediately with no commit on our side (issue #179 was "
        "exactly\n"
        "     that: their PR #226 made get_config_item return the item map). "
        "Check\n"
        "     Ultimate64Client.get_config_value / get_config_item against\n"
        "     tools/uci/_reu_preflight.py, and file it in c64-test-harness "
        "first.\n"
        "\n"
        "  3. The firmware does not expose this config item under this name.\n"
        "\n"
        "To proceed without the check, having satisfied yourself the REU is "
        "there:\n"
        "\n"
        f"       {SKIP_ENV}=1 <your command>\n"
        "\n"
        "     Or build the on-chip profile, which needs no REU and skips "
        "this\n"
        "     check entirely:\n"
        "       make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1\n"
        "\n"
    )


def _failure_message(observed: str, reason: str) -> str:
    """Compose the actionable failure text. Both remedies, no jargon."""
    return (
        "\n"
        "REU PREFLIGHT FAILED — this build needs an REU and the device has "
        "none enabled.\n"
        "\n"
        f"  device: {CAT_CART} / {ITEM_REU_ENABLED} = {observed!r}\n"
        f"  build : REU profile ({reason})\n"
        "\n"
        "The REU-profile image fetches its multiply rows from REU banks by "
        "DMA. With\n"
        "no REU that DMA silently no-ops, X25519 derives the wrong shared "
        "secret, and\n"
        "the first encrypted record fails its AEAD tag. The client then "
        "spins ~44 min\n"
        "on a screen ending 'KEYS ENC1 RX' — which reads as a lockup. That "
        "is issue\n"
        "#97, and this check exists so you see it now instead of in 44 "
        "minutes.\n"
        "\n"
        "Fix it either way:\n"
        "\n"
        "  1. Enable the REU on the device:\n"
        "       Settings -> C64 and Cartridge Settings -> RAM Expansion Unit "
        "-> Enabled\n"
        "     (a C64 Ultimate ships with this Disabled; the setting reverts "
        "on power\n"
        "     cycle, so it may need redoing). This test will not set it for "
        "you: the\n"
        "     device is queue-shared and config writes persist.\n"
        "\n"
        "  2. Or build the on-chip profile, which needs no REU at all:\n"
        "       make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1\n"
        "     (it is also the faster profile above ~18 MHz). Prebuilt as\n"
        "     c64-https-uci-onchip.prg in the GitHub release.\n"
        "\n"
        f"  Override with {SKIP_ENV}=1 if you know better.\n"
    )
