"""Shared MemoryPolicy / MemoryArbiter factory for the c64-https tools/uci/* scripts.

The c64-https build can lay out its memory map in several different ways
depending on the BACKEND (ip65 vs uci) and the USE_X25519_SIBLING flag.
Hand-coding scratch DMA addresses in each test script invites silent
collisions when the layout changes (see issue surfaced by PR #41:
ROUTINE_ADDR=$4200 clobbered X25519_RODATA under USE_X25519_SIBLING=1).

This module is the single source of truth for "where is c64-https
holding RAM under the current build?". It reads ``build/labels.txt``
(produced by ld65) and converts the per-region ``__<NAME>_START__`` /
``__<NAME>_LAST__`` linker-emitted markers into a
:class:`~c64_test_harness.MemoryPolicy`. The returned policy lists
every defined memory region as reserved; ``unknown_policy=WARN`` so
stray harness writes outside the recognised layout surface as
``UserWarning`` instead of silent passes (this is the migration
default — see follow-ups below).

Typical use in a ``tools/uci/*.py`` script (sibling import — the script
is executed directly so ``tools/uci/`` is on :data:`sys.path[0]`)::

    from _memory_policy import build_policy_and_arbiter

    policy, arbiter = build_policy_and_arbiter(LABELS_PATH, PRG_PATH)
    transport.memory_policy = policy
    routine_addr = arbiter.alloc(routine_len, name="trampoline")
    sentinel_addr = arbiter.alloc(16, name="sentinel")

The arbiter's allocations are NOT added to the policy by default —
i.e. ``transport.write_memory(routine_addr, ...)`` will not be
re-blocked by the policy on the second use. Call
``arbiter.policy_with_allocations()`` if you want each arbiter claim
to also become a reserved region (e.g. to catch a second piece of code
that bypasses the arbiter and writes to an arbiter-owned address).
"""

from __future__ import annotations

import re
from pathlib import Path

from c64_test_harness import (
    MemoryArbiter,
    MemoryPolicy,
    MemoryRegion,
    UnknownPolicy,
)
from c64_test_harness.verify import PrgFile


# Match the ld65 segment-boundary symbol shape:
#   al C:4200 .__CRYPTO_OVERLAY_START__
#   al C:5100 .__CRYPTO_OVERLAY_LAST__
#   al C:1E00 .__CRYPTO_OVERLAY_SIZE__
# We use ``START`` + ``SIZE`` to reserve the *declared* memory area
# (i.e. the full ``$4200-$5FFF`` rather than just $4200-$50FF). Reserving
# the declared area is the conservative choice: if a segment later
# grows into the trailing free range, the arbiter's prior allocation
# would silently collide. Reserving the whole declared area forces the
# arbiter to look for unused space *between* declared regions (e.g.
# $A000-$BFFF on UCI, $D000+ KERNAL ROM shadow, etc.).
#
# The CRYPTO_OVERLAY case is the deliberate exception: under
# USE_X25519_SIBLING=1 the X25519_RODATA + _BSS segments only fill the
# first $F00 bytes; the tail $5100-$5FFF is genuinely intended as
# harness scratch (the cfg comment says so explicitly). We re-add that
# tail as a safe_region in :func:`build_policy` so the arbiter can
# allocate there.
_SEGMENT_RX = re.compile(
    r"^al\s+(?:C:)?([0-9A-Fa-f]+)\s+\.__([A-Za-z0-9_]+)_(START|LAST|SIZE)__\s*$"
)

# Regions we never reserve, even if they appear in labels.txt. The
# arbiter and the policy need *some* unblocked range to allocate
# scratch from; the loader is the only memory region we declare as
# reserved-via-PRG separately.
_SKIP_REGIONS: frozenset[str] = frozenset({
    # Zero-page is below the arbiter's default window ($0200+) so
    # listing here is belt-and-suspenders.
    "ZP_CRYPTO",
    "ZP_WIDE",
    "ZP_IP65",
    "LOADADDR",
})


def _parse_segment_bounds(labels_path: Path) -> dict[str, tuple[int, int]]:
    """Pull ``__NAME_START__`` / ``__NAME_SIZE__`` pairs out of labels.txt.

    Returns a dict keyed by region name; values are half-open
    ``(start, end_exclusive)`` pairs covering the *declared* memory
    area (not just the used subset).

    Reserving the declared area is the conservative choice — segments
    can grow into their declared region at link time, so an arbiter
    allocation made today inside the tail of a declared region would
    silently collide tomorrow.

    Regions with no ``__NAME_SIZE__`` symbol, or with ``SIZE == 0``,
    are skipped (matches ip65's zero-sized CRYPTO_OVERLAY alias).
    """
    starts: dict[str, int] = {}
    sizes: dict[str, int] = {}
    with labels_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            m = _SEGMENT_RX.match(line)
            if not m:
                continue
            addr_hex, name, kind = m.groups()
            addr = int(addr_hex, 16)
            if kind == "START":
                starts[name] = addr
            elif kind == "SIZE":
                sizes[name] = addr
            # LAST is captured but unused — keeping the regex inclusive
            # of it for forward-compatibility / debug.
    bounds: dict[str, tuple[int, int]] = {}
    for name, start in starts.items():
        size = sizes.get(name)
        if not size:
            continue
        end = start + size
        if end > 0x10000:
            end = 0x10000
        if end <= start:
            continue
        bounds[name] = (start, end)
    return bounds


def build_policy(
    labels_path: str | Path,
    prg_path: str | Path,
    *,
    unknown: UnknownPolicy = UnknownPolicy.WARN,
    extra_reserved: tuple[MemoryRegion, ...] = (),
) -> MemoryPolicy:
    """Build a c64-https-aware :class:`MemoryPolicy`.

    Every defined memory region in ``labels_path`` becomes a reserved
    region. The PRG load image (``prg_path``) is also reserved via
    :meth:`MemoryPolicy.from_prg` — usually redundant with the
    ``LOADER`` / ``NET_CODE`` segment markers but it costs nothing and
    guards against builds where someone changes the segment names.

    ``unknown=WARN`` by default so writes outside any declared region
    surface as ``UserWarning`` without breaking the test. Tighten to
    ``UnknownPolicy.DENY`` once the call sites that surface warnings
    have been audited.

    ``extra_reserved`` is appended after the labels-derived regions,
    useful for declaring "this scratch range belongs to a sibling test
    process" or similar runtime-only constraints.
    """
    labels_path = Path(labels_path)
    prg_path = Path(prg_path)
    # ``prg_path`` is accepted so future callers can attach the
    # ``from_prg`` PRG-image reservation. We deliberately do NOT use
    # it here, because the c64-https PRG declares ``fill = yes`` on
    # several memory regions; the resulting PRG image spans
    # $0801-$BFFF as one contiguous load. That subsumes the gaps
    # where the arbiter would otherwise place harness scratch
    # (e.g. CRYPTO_OVERLAY's $5100-$5FFF tail when X25519 occupies
    # $4200-$50FF). The per-segment ``__<NAME>_START__`` /
    # ``__<NAME>_LAST__`` markers from labels.txt give us the actual
    # used ranges, which is exactly what we want.
    _ = prg_path  # acknowledged-but-unused; future-proofing

    bounds = _parse_segment_bounds(labels_path)
    used_ends = _parse_used_ends(labels_path)
    reserved: list[MemoryRegion] = []
    for name in sorted(bounds):
        if name in _SKIP_REGIONS:
            continue
        start, declared_end = bounds[name]
        # For CRYPTO_OVERLAY specifically, reserve only the *used*
        # portion so the unused tail is available as harness scratch.
        # The cfg comment on CRYPTO_OVERLAY explicitly designates the
        # tail as harness/overlay-test territory, and
        # tools/uci/test_https_local.py has used this tail in
        # production since PR #41.
        #
        # Other memory regions (UCI_BSS_REGION, TCP_BUF, etc.) reserve
        # the full declared area because their "unused" tail may
        # actually be written to at runtime (TCP_BUF holds
        # tcp_recv_buf, declared as a BSS segment so labels.txt's
        # used-end is $C000 even though the ring fills the full
        # $C000-$CFFF at runtime).
        if name == "CRYPTO_OVERLAY":
            used = used_ends.get(name, declared_end)
            reserve_end = max(min(used, declared_end), start)
            if reserve_end <= start:
                # Empty CRYPTO_OVERLAY (no overlay segments linked) —
                # nothing to reserve; the whole region becomes free.
                continue
            reserved.append(
                MemoryRegion(start, reserve_end, note=f"segment:{name}(used)")
            )
        else:
            reserved.append(
                MemoryRegion(start, declared_end, note=f"segment:{name}")
            )

    reserved.extend(extra_reserved)
    return MemoryPolicy(
        reserved_regions=tuple(reserved),
        unknown=unknown,
    )


def _parse_used_ends(labels_path: Path) -> dict[str, int]:
    """Return the half-open ``__<NAME>_LAST__`` value for every region."""
    ends: dict[str, int] = {}
    with labels_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            m = _SEGMENT_RX.match(line)
            if not m:
                continue
            addr_hex, name, kind = m.groups()
            if kind == "LAST":
                ends[name] = int(addr_hex, 16)
    return ends


def attach_arbiter_safe_regions(
    policy: MemoryPolicy,
    arbiter: MemoryArbiter,
) -> MemoryPolicy:
    """Promote every arbiter allocation to a ``safe_region`` in ``policy``.

    Use this AFTER all your ``arbiter.alloc(...)`` calls but BEFORE
    you assign the policy to ``transport.memory_policy``. Without it,
    every ``transport.write_memory(arbiter_alloced_addr, ...)`` call
    fires a ``UserWarning`` (because the address falls outside any
    declared safe_region while the policy's ``unknown`` setting is
    ``WARN``). Promoting the allocations silences that noise while
    still catching writes that *aren't* arbiter-blessed (zero-page,
    keyboard buffer, etc.).
    """
    out = policy
    for start, last_incl, name in arbiter.allocations:
        out = out.with_safe(
            MemoryRegion(start, last_incl + 1, note=f"arbiter:{name}")
        )
    return out


def build_arbiter(
    policy: MemoryPolicy,
    *,
    window: tuple[int, int] = (0x4000, 0x5FFF),
) -> MemoryArbiter:
    """Build a :class:`MemoryArbiter` scoped to the CRYPTO_OVERLAY range.

    The default window targets the $4000-$5FFF span — under ip65 most
    of this is filled by NET_BSS ($4000-$4F8B) + NET_BSS_TAIL
    ($4F8C-$5FFF), but under UCI the CRYPTO_OVERLAY's tail ($5100-$5FFF
    when USE_X25519_SIBLING=1, or all of $4200-$5FFF when not) is the
    natural home for harness scratch: it's RAM-backed, inside the
    LOADER/NET_CODE write-banked region, and not used by any code
    that the PRG ships with under normal operation.

    Pass ``window=(0xC000, 0xCFFF)`` to allocate inside the TCP_BUF
    range instead, but be aware that ``tcp_recv_buf`` lives there and
    is actively used by the TLS record path — collisions there will
    silently corrupt incoming records.
    """
    return MemoryArbiter(policy=policy, window=window)


def build_policy_and_arbiter(
    labels_path: str | Path,
    prg_path: str | Path,
    *,
    unknown: UnknownPolicy = UnknownPolicy.WARN,
    extra_reserved: tuple[MemoryRegion, ...] = (),
    window: tuple[int, int] = (0x4000, 0x5FFF),
) -> tuple[MemoryPolicy, MemoryArbiter]:
    """One-shot convenience: build the policy + an arbiter scoped to ``window``."""
    policy = build_policy(
        labels_path,
        prg_path,
        unknown=unknown,
        extra_reserved=extra_reserved,
    )
    arbiter = build_arbiter(policy, window=window)
    return policy, arbiter


def build_policy_and_arbiter_with_overlay_carveout(
    labels_path: str | Path,
    prg_path: str | Path,
    *,
    unknown: UnknownPolicy = UnknownPolicy.WARN,
    extra_reserved: tuple[MemoryRegion, ...] = (),
    min_scratch_bytes: int = 512,
) -> tuple[MemoryPolicy, MemoryArbiter]:
    """Build a policy + arbiter that carves harness scratch from NET_CODE's tail.

    Use this when ``CRYPTO_OVERLAY`` ($4200-$5FFF) is fully occupied by
    an overlay blob (e.g. ``OVERLAY_BLOB_SHA384`` under the P-384 build,
    or any future overlay that fills the whole region at PRG-load time
    AND is the active swap slot at runtime). In that case the default
    arbiter window ($4000-$5FFF) finds no free range and raises
    :class:`MemoryArbiterError`.
    Under the baseline P-256 / X25519-sibling P-256 builds the same
    problem appears any time the CRYPTO_OVERLAY tail that
    :func:`build_arbiter`'s default window relies on shrinks below the
    387 B of harness scratch the e2e tests need (trampoline + host /
    path strings + sentinels).
    The workaround mirrors the P-384 wrapper that lived inline in
    ``tools/uci/test_https_local_p384.py`` (factored out here so other
    test scripts can reuse it without re-copying the implementation):
    ``NET_CODE`` is declared $2000-$3FFF with ``fill = yes,
    fillval = $00``. The adapter + relocated TLS / crypto-aux code
    fills $2000-$3xxx (per ``build/labels.txt``'s ``__NET_CODE_LAST__``);
    the tail (rounded up to the next page from ``LAST``) through $3FFF
    is zero-fill in the PRG, never referenced by any production code,
    and stays RAM after boot. We:
      - round the NET_CODE used-end up to the next $100 boundary (cheap
        insurance against off-by-one with the very last code byte),
      - reject the carveout if it yields fewer than ``min_scratch_bytes``
        of free space (default 512 B, conservative ceiling for the
        387 B the current e2e tests need),
      - surgically rewrite the ``NET_CODE`` reservation in the
        labels-derived :class:`MemoryPolicy` to end at the carveout
        start (so the freed tail isn't blocked by the reserved-takes-
        precedence rule), and
      - scope the returned :class:`MemoryArbiter` to that tail.
    The CRYPTO_OVERLAY reservation is left intact — the overlay blob
    occupies it for real, and the arbiter has no business allocating
    there.
    :param labels_path: ``build/labels.txt`` from the current build.
    :param prg_path: PRG load image (currently unused — passed through
        to :func:`build_policy` for consistency).
    :param unknown: Passed through to :func:`build_policy`.
    :param extra_reserved: Passed through to :func:`build_policy`.
    :param min_scratch_bytes: Reject the carveout if NET_CODE's tail
        yields fewer than this many bytes of free space.
    :raises RuntimeError: When the NET_CODE tail is too small (build
        change pushed code into the would-be scratch range).
    """
    labels_path = Path(labels_path)
    bounds = _parse_segment_bounds(labels_path)
    used_ends = _parse_used_ends(labels_path)
    if "NET_CODE" not in bounds:
        raise RuntimeError(
            "labels.txt has no NET_CODE segment — cannot carve scratch tail"
        )
    netc_start, netc_decl_end = bounds["NET_CODE"]
    netc_used_end = used_ends.get("NET_CODE", netc_start)
    # Round up to next page so we don't trail right up to the last
    # instruction byte (cheap insurance against off-by-one).
    scratch_start = (netc_used_end + 0xFF) & ~0xFF
    scratch_end_excl = netc_decl_end
    free_bytes = scratch_end_excl - scratch_start
    if free_bytes < min_scratch_bytes:
        raise RuntimeError(
            f"NET_CODE tail scratch window too small for harness: "
            f"${scratch_start:04X}-${scratch_end_excl:04X} "
            f"({free_bytes} B, need >= {min_scratch_bytes} B). "
            f"NET_CODE used to ${netc_used_end:04X}, declared end "
            f"${netc_decl_end:04X}."
        )

    base = build_policy(
        labels_path,
        prg_path,
        unknown=unknown,
        extra_reserved=extra_reserved,
    )
    # Surgically trim the NET_CODE reservation to end at scratch_start
    # so the trailing free range is available to the arbiter.
    # ``reserved_regions`` is a tuple of frozen MemoryRegion dataclasses;
    # we rebuild a fresh tuple with NET_CODE shrunk.
    new_reserved: list[MemoryRegion] = []
    for r in base.reserved_regions:
        if r.start == netc_start and r.end == netc_decl_end:
            new_reserved.append(MemoryRegion(
                netc_start, scratch_start,
                note=f"{r.note}(overlay_carveout:trimmed)",
            ))
        else:
            new_reserved.append(r)
    policy = MemoryPolicy(
        reserved_regions=tuple(new_reserved),
        safe_regions=base.safe_regions,
        unknown=base.unknown,
    )
    arbiter = MemoryArbiter(
        policy=policy, window=(scratch_start, scratch_end_excl - 1),
    )
    print(
        f"NET_CODE-tail harness scratch: "
        f"${scratch_start:04X}-${scratch_end_excl - 1:04X} "
        f"({free_bytes} B free; NET_CODE used to ${netc_used_end:04X}, "
        f"declared end ${netc_decl_end:04X})"
    )
    return policy, arbiter


__all__ = [
    "build_policy",
    "build_arbiter",
    "build_policy_and_arbiter",
    "build_policy_and_arbiter_with_overlay_carveout",
    "attach_arbiter_safe_regions",
]
