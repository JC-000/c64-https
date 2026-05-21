"""tools/_vice_helpers.py - shared VICE configuration helpers.

This module centralizes VICE launch defaults that every crypto-touching
test in c64-https must apply. The primary entry point is
:func:`default_vice_config`, which returns a
:class:`c64_test_harness.ViceConfig` with mandatory ``-reu`` /
``-reusize=512`` flags pre-applied.

See user memory ``vice_reu_required_for_p256`` and the project's
"VICE harness gotcha" note in ``CLAUDE.md`` for the canonical motivation.
"""

from __future__ import annotations

from c64_test_harness import ViceConfig


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

    Remaining keyword arguments are forwarded verbatim to ``ViceConfig``;
    typical callers pass ``prg_path``, ``warp``, ``ntsc``, ``sound`` etc.

    :param extra_args: optional VICE CLI flags appended after the REU
        flags. ``None`` and an empty list both leave the base flags
        untouched.
    :param kwargs: forwarded to :class:`c64_test_harness.ViceConfig`.
    :returns: a configured ``ViceConfig`` instance.
    """
    base_args = ["-reu", "-reusize", "512"]
    if extra_args:
        base_args = base_args + list(extra_args)
    return ViceConfig(extra_args=base_args, **kwargs)
