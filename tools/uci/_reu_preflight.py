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
    if banks == 0:
        return ("onchip", f"{_BANKS_EQUATE}=0")

    found = [name for name in _ONCHIP_SYMBOLS if name in labels]
    if found:
        return ("onchip", "+".join(found))

    if banks is None:
        # No manifest equate and no onchip symbol. Most likely a genuine
        # REU-profile build; possibly a library layout we do not know.
        # Fail closed — the check is skippable, 44 minutes of spin is not.
        return ("reu", f"no {_BANKS_EQUATE} and no on-chip row generator")
    return ("reu", f"{_BANKS_EQUATE}={banks}")


def _extract_config_value(resp: Any, category: str, item: str) -> str | None:
    """Dig a scalar out of a U64 REST config response, defensively.

    Two shapes are live on the devices we test against::

        {"C64 and Cartridge Settings": {"RAM Expansion Unit": "Enabled"}}
        {"C64 and Cartridge Settings":
            {"RAM Expansion Unit": {"current": "Enabled", "presets": [...]}}}

    Returns ``None`` on anything unrecognised rather than guessing —
    an inconclusive read must not be reported as "Disabled".
    """
    if not isinstance(resp, dict):
        return None
    inner = resp.get(category, resp)
    if not isinstance(inner, dict):
        return None
    value = inner.get(item)
    if isinstance(value, dict):
        value = value.get("current")
    if value is None:
        return None
    return str(value)


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
    :raises ReuPreflightError: REU-profile build, REU reported Disabled.
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

    try:
        resp = client.get_config_item(CAT_CART, ITEM_REU_ENABLED)
        enabled = _extract_config_value(resp, CAT_CART, ITEM_REU_ENABLED)
    except Exception as exc:  # noqa: BLE001 — probe is advisory
        print(
            f"REU preflight: WARNING — could not read '{ITEM_REU_ENABLED}' "
            f"({exc.__class__.__name__}: {exc}); continuing unchecked",
            file=out,
            flush=True,
        )
        return profile

    if enabled is None:
        print(
            f"REU preflight: WARNING — '{ITEM_REU_ENABLED}' returned an "
            f"unrecognised shape ({resp!r}); continuing unchecked",
            file=out,
            flush=True,
        )
        return profile

    if enabled.strip().lower() != "enabled":
        raise ReuPreflightError(_failure_message(enabled, reason))

    size = None
    try:
        size = _extract_config_value(
            client.get_config_item(CAT_CART, ITEM_REU_SIZE),
            CAT_CART,
            ITEM_REU_SIZE,
        )
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
