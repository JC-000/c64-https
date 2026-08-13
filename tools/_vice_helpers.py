"""tools/_vice_helpers.py - shared VICE configuration helpers.

This module centralizes VICE launch defaults that every crypto-touching
test in c64-https must apply. The primary entry point is
:func:`default_vice_config`, which returns a
:class:`c64_test_harness.ViceConfig` with mandatory ``-reu`` /
``-reusize=512`` flags pre-applied.

See user memory ``vice_reu_required_for_p256`` and the project's
"VICE harness gotcha" note in ``CLAUDE.md`` for the canonical motivation.

Opt-in no-REU mode
------------------
Setting ``C64_VICE_NO_REU=1`` in the environment drops the REU flags, so
the packaging claim "the onchip PRG passes the ECDSA KAT without an REU"
has a runnable test instead of requiring a monkeypatched copy of the
script. It is deliberately opt-in and noisy: a no-REU run of a
*REU-profile* build does not error, it silently computes wrong answers
(a valid signature verifies as C=1). Only use it on
``USE_NISTCURVES_ONCHIP=1`` images.
"""

from __future__ import annotations

import os
import sys

from c64_test_harness import ViceConfig

#: Environment variable that opts a run out of the mandatory REU flags.
NO_REU_ENV = "C64_VICE_NO_REU"


def no_reu_requested(env: dict | None = None) -> bool:
    """Return True when the environment opts out of the REU flags.

    :param env: mapping to inspect (defaults to ``os.environ``).
    """
    src = os.environ if env is None else env
    return str(src.get(NO_REU_ENV, "")).strip().lower() in ("1", "true", "yes", "on")


def default_vice_config(
    *,
    extra_args: list[str] | None = None,
    **kwargs,
) -> ViceConfig:
    """Return a ``ViceConfig`` with mandatory ``-reu``/``-reusize=512`` pre-applied.

    Mandatory ``-reu`` / ``-reusize=512`` because sibling nistcurves'
    ``fp_mul`` reads multiply rows from REU banks 0/1; without REU enabled
    every ``fp_mul`` returns ``a*255*b mod p`` (the bank fetch silently
    no-ops and ``mul_dma_lo/hi`` at $BA00/$BB00 stays stuck at
    ``reu_mul_init``'s final-iteration residue, a=255). The same trap
    applies to any test that touches the X25519 sibling, the P-384 overlay
    images, or boot-time REU stashes.

    Any caller-supplied ``extra_args`` are **appended** to the mandatory
    REU flags rather than replacing them, so callers can pass other VICE
    options (e.g. ``-warp``, custom monitor flags) without losing the REU
    enablement.

    Setting ``C64_VICE_NO_REU=1`` omits the REU flags (and announces it on
    stderr). That mode exists to test the REU-less onchip profile — the
    shipped ``c64-https-uci-onchip.prg`` claims "no REU required", and this
    is how that claim is reproduced:

    .. code-block:: sh

        make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1
        C64_SKIP_BUILD=1 C64_VICE_NO_REU=1 \\
            python3 tools/test_ecdsa_kat_oracle.py

    On any other build the same invocation returns wrong answers without
    complaining, which is exactly why REU stays the default.

    Remaining keyword arguments are forwarded verbatim to ``ViceConfig``;
    typical callers pass ``prg_path``, ``warp``, ``ntsc``, ``sound`` etc.

    :param extra_args: optional VICE CLI flags appended after the REU
        flags. ``None`` and an empty list both leave the base flags
        untouched.
    :param kwargs: forwarded to :class:`c64_test_harness.ViceConfig`.
    :returns: a configured ``ViceConfig`` instance.
    """
    if no_reu_requested():
        print(
            f"[{NO_REU_ENV}] VICE launching WITHOUT -reu — valid only for "
            "USE_NISTCURVES_ONCHIP builds; any REU-profile image will "
            "silently compute wrong results.",
            file=sys.stderr,
            flush=True,
        )
        base_args: list[str] = []
    else:
        base_args = ["-reu", "-reusize", "512"]
    if extra_args:
        base_args = base_args + list(extra_args)
    return ViceConfig(extra_args=base_args, **kwargs)
