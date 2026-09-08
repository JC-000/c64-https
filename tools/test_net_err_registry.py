#!/usr/bin/env python3
"""Guard the fleet's shared `net_last_error` number space (issue #184).

Pure logic: reads three source files off disk, parses them, compares. No
build, no VICE, no hardware, milliseconds. Runs under pytest (it is listed
in ``pytest.ini``'s ``testpaths``) and standalone::

    python3 tools/test_net_err_registry.py

WHY THIS EXISTS. The ip65 family ($40-$7F) and the UCI family ($80-$BF) are
one namespace each, shared by c64-https and c64-wireguard. c64-lib-contract
SPEC §13.2 used to hold the cross-repo allocation table; §13 was retired
wholesale at contract v1.0.0 and the registry moved to
``c64-wireguard/src/net_abi.inc``, which declares itself canonical for both
ranges. Two collisions have already happened in this fleet — $88, live for
four days, and wg#120's first commit minting $40-$44 over our $41-$45,
caught by a human reviewer. Until #184 nothing mechanical checked either
range in this repo.

WHAT IS CHECKED, AND WHERE THE OTHER HALF LIVES.
``src/net_err_registry_asserts.s`` is the link-time half: it fails the ca65
assemble of every profile, both backends, if a code it knows about lands on
a peer-owned value or a published value is reassigned. It costs no bytes.
Its blind spot is a code that never gets registered in it, and it cannot see
the peer repository at all. This suite covers exactly those two gaps:

  1-3. Structural, always run. Every error code defined in our two headers
       is in its family range, is registered in the asserts TU, and does not
       sit on a peer-owned value. (3) is the assembler's check repeated from
       the headers' side, which is the point: (2)+(3) together mean a new
       code cannot dodge the assembler by simply not being registered.
  4.   Snapshot integrity: the NET_ERR_PEER_* table in the asserts TU agrees
       with the prose lists in the two headers.
  5-7. Cross-repo drift, against the live peer registry. SKIPPED when no
       c64-wireguard checkout is found — pytest.ini sets ``addopts = -ra``,
       so the skip and its reason are printed on every run rather than
       vanishing into a green count. Point it at a checkout with
       ``C64_WIREGUARD_ROOT=/path/to/c64-wireguard``; the sibling default
       is ``../c64-wireguard`` relative to this repo, then
       ``~/Documents/c64-wireguard``.

WHAT IT DELIBERATELY DOES NOT DO. It never edits, and never asserts
anything about, the peer repository's own correctness. A code of ours that
their registry has claimed is reported as a finding for a human to take
cross-repo; this suite's job is to make it impossible to not notice.
"""

import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UCI_HEADER = REPO / "src" / "net" / "uci" / "uci_errors.inc"
IP65_HEADER = REPO / "src" / "net" / "ip65" / "ip65_errors.inc"
ASSERTS_TU = REPO / "src" / "net_err_registry_asserts.s"

IP65_FAMILY = (0x40, 0x7F)
UCI_FAMILY = (0x80, 0xBF)

# The one code we define that is a c64-wireguard allocation: mirrored here,
# reserved, never emitted, so the name is readable in our diagnostics. It is
# checked in the opposite direction from every other code (it must EQUAL
# theirs), and is excluded from the collision sweep by name, never by value.
MIRRORED = "UCI_ERR_LONG_READ"

# `NAME = $hh` where hh lands in either family range. Two hex digits only:
# a four-digit $DFxx is a register, not an error code, and the sub-$40
# values in these files ($00 = OK) are not allocatable.
_EQUATE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$([0-9A-Fa-f]{2})\s*(?:;.*)?$")

# `NET_ERR_PEER_NAME = $hh` in the asserts TU.
_PEER_RE = re.compile(r"^\s*(NET_ERR_PEER_[A-Za-z0-9_]+)\s*=\s*\$([0-9A-Fa-f]{2})\b")

# A registry row in c64-wireguard/src/net_abi.inc:
#   ;   $8E   UCI_ERR_CMD_UNKNOWN         OURS, minted here (PR #112)
_PEER_ROW_RE = re.compile(r"^;\s+\$([0-9A-Fa-f]{2})\s+([A-Z][A-Za-z0-9_]*)\s{2,}(.+?)\s*$")

# A comment row in one of our headers listing a peer allocation:
#   ;   $8C  UCI_ERR_SEND_TOO_LONG  theirs; ...
_OUR_COMMENT_ROW_RE = re.compile(r"^;\s+\$([0-9A-Fa-f]{2})\s+([A-Z][A-Za-z0-9_]*)\s+\S")


def _in(value, family):
    return family[0] <= value <= family[1]


def _read(path):
    return path.read_text(encoding="utf-8").splitlines()


def _our_codes():
    """{name: value} for every error code our two headers define."""
    codes = {}
    for path, family in ((UCI_HEADER, UCI_FAMILY), (IP65_HEADER, IP65_FAMILY)):
        for line in _read(path):
            m = _EQUATE_RE.match(line)
            if not m:
                continue
            name, value = m.group(1), int(m.group(2), 16)
            if not (_in(value, IP65_FAMILY) or _in(value, UCI_FAMILY)):
                continue
            assert name not in codes, f"{name} defined twice across the headers"
            codes[name] = (value, path, family)
    return codes


def _peer_snapshot():
    """{name: value} for the NET_ERR_PEER_* table in the asserts TU."""
    return {m.group(1): int(m.group(2), 16)
            for m in (_PEER_RE.match(l) for l in _read(ASSERTS_TU)) if m}


def _registered_names():
    """Names the asserts TU actually puts through a collision macro."""
    names = set()
    for line in _read(ASSERTS_TU):
        m = re.match(r"^NET_ERR_ASSERT_(?:IP65|UCI)\s+([A-Za-z0-9_]+)\s*,", line)
        if m:
            names.add(m.group(1))
    return names


def _wireguard_root():
    env = os.environ.get("C64_WIREGUARD_ROOT")
    candidates = [Path(env)] if env else [REPO.parent / "c64-wireguard",
                                          Path.home() / "Documents" / "c64-wireguard"]
    for c in candidates:
        if (c / "src" / "net_abi.inc").is_file():
            return c
    return None


def _peer_registry(root):
    """{value: (name, owner)} parsed from the peer's canonical table.

    owner is "c64-wireguard", "c64-https", or "other" (contract-generic
    rows such as $01). Only rows inside a family range are returned.
    """
    rows = {}
    for line in _read(root / "src" / "net_abi.inc"):
        m = _PEER_ROW_RE.match(line)
        if not m:
            continue
        value = int(m.group(1), 16)
        if not (_in(value, IP65_FAMILY) or _in(value, UCI_FAMILY)):
            continue
        origin = m.group(3)
        if "c64-https" in origin:
            owner = "c64-https"
        elif re.search(r"\bours\b", origin, re.IGNORECASE):
            owner = "c64-wireguard"
        else:
            owner = "other"
        rows[value] = (m.group(2), owner)
    return rows


# --------------------------------------------------------------------------
# 1-4: structural, no peer checkout needed.
# --------------------------------------------------------------------------

def test_every_code_is_in_its_family_range():
    for name, (value, path, family) in sorted(_our_codes().items()):
        assert _in(value, family), (
            f"{name} = ${value:02X} in {path.name} is outside its family range "
            f"${family[0]:02X}-${family[1]:02X} (#184)")


def test_every_code_is_registered_in_the_asserts_tu():
    """The assembler cannot check a code nobody registered with it."""
    registered = _registered_names() | {MIRRORED}
    missing = sorted(n for n in _our_codes() if n not in registered)
    assert not missing, (
        f"error codes defined in our headers but not registered in "
        f"{ASSERTS_TU.relative_to(REPO)}: {missing}. Add a "
        f"NET_ERR_ASSERT_IP65/NET_ERR_ASSERT_UCI line for each, or the "
        f"link-time collision guard silently does not cover them (#184).")


def test_no_code_of_ours_sits_on_a_peer_owned_value():
    peer = _peer_snapshot()
    by_value = {}
    for pname, pvalue in peer.items():
        by_value.setdefault(pvalue, []).append(pname)
    clashes = []
    for name, (value, _path, _family) in sorted(_our_codes().items()):
        if name == MIRRORED:
            continue
        if value in by_value:
            clashes.append(f"{name} = ${value:02X} == {by_value[value]}")
    assert not clashes, (
        "codes of ours land on c64-wireguard-owned values: "
        + "; ".join(clashes)
        + ". Allocate in c64-wireguard/src/net_abi.inc first (#184).")


def test_the_mirrored_code_tracks_the_peer_value():
    codes = _our_codes()
    peer = _peer_snapshot()
    assert MIRRORED in codes, f"{MIRRORED} vanished from uci_errors.inc"
    assert peer.get("NET_ERR_PEER_UCI_LONG_READ") == codes[MIRRORED][0], (
        f"{MIRRORED} must mirror c64-wireguard's $8A exactly; it is their "
        f"allocation, reserved and never emitted here (#184).")


def test_header_prose_lists_match_the_snapshot_table():
    """The comment lists #185 put in the headers must not drift from the
    NET_ERR_PEER_* equates the assembler actually checks."""
    snapshot = set(_peer_snapshot().values())
    ours = {v for v, _p, _f in _our_codes().values()}
    listed = set()
    for path in (UCI_HEADER, IP65_HEADER):
        for line in _read(path):
            m = _OUR_COMMENT_ROW_RE.match(line)
            if m:
                value = int(m.group(1), 16)
                if (_in(value, IP65_FAMILY) or _in(value, UCI_FAMILY)) \
                        and value not in ours:
                    listed.add(value)
    only_prose = sorted(listed - snapshot)
    only_table = sorted(snapshot - listed - ours)
    assert not only_prose and not only_table, (
        "the peer-owned codes named in the headers' comments and the "
        "NET_ERR_PEER_* table in net_err_registry_asserts.s disagree: "
        f"only in prose {[f'${v:02X}' for v in only_prose]}, "
        f"only in the table {[f'${v:02X}' for v in only_table]} (#184).")


# --------------------------------------------------------------------------
# 5-7: cross-repo drift. Needs a c64-wireguard checkout.
# --------------------------------------------------------------------------

def _require_peer():
    root = _wireguard_root()
    if root is None:
        try:
            import pytest
        except ImportError:
            return None
        pytest.skip(
            "no c64-wireguard checkout found, so the snapshot in "
            "src/net_err_registry_asserts.s is UNVERIFIED against the "
            "canonical registry. Set C64_WIREGUARD_ROOT=/path/to/c64-wireguard "
            "(or place it at ../c64-wireguard) to cover this (#184).")
    return root


def test_snapshot_matches_the_peer_registry():
    root = _require_peer()
    if root is None:
        print("SKIP: no c64-wireguard checkout")
        return
    registry = _peer_registry(root)
    theirs = {v for v, (_n, owner) in registry.items() if owner == "c64-wireguard"}
    snapshot = set(_peer_snapshot().values())
    missing = sorted(theirs - snapshot)
    stale = sorted(snapshot - theirs)
    assert not missing and not stale, (
        f"our NET_ERR_PEER_* snapshot has drifted from {root}/src/net_abi.inc: "
        f"they own but we do not list {[f'${v:02X}' for v in missing]}; "
        f"we list but they no longer own {[f'${v:02X}' for v in stale]}. "
        f"Update src/net_err_registry_asserts.s and both headers (#184).")


def test_no_code_of_ours_is_claimed_by_the_peer_registry():
    """The finding this whole ticket exists to make impossible to miss."""
    root = _require_peer()
    if root is None:
        print("SKIP: no c64-wireguard checkout")
        return
    registry = _peer_registry(root)
    bad = []
    for name, (value, _path, _family) in sorted(_our_codes().items()):
        if name == MIRRORED:
            continue
        row = registry.get(value)
        if row and row[1] == "c64-wireguard":
            bad.append(f"${value:02X} is ours as {name} and theirs as {row[0]}")
    assert not bad, (
        "LIVE CROSS-REPO COLLISION — " + "; ".join(bad)
        + f". Registry: {root}/src/net_abi.inc. Do not renumber unilaterally; "
        "a published value is never reassigned. Take this to the "
        "c64-wireguard lane (#184).")


def test_every_code_of_ours_appears_in_the_peer_registry():
    root = _require_peer()
    if root is None:
        print("SKIP: no c64-wireguard checkout")
        return
    registry = _peer_registry(root)
    unlisted = sorted(
        f"{name} = ${value:02X}"
        for name, (value, _p, _f) in _our_codes().items()
        if value not in registry)
    assert not unlisted, (
        f"codes we define that the canonical registry does not list: "
        f"{unlisted}. Allocate them in {root}/src/net_abi.inc — a code that "
        f"is not in the registry is a code the next lane will mint over "
        f"(#184).")


def main():
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}\n      {exc}")
    root = _wireguard_root()
    print(f"\npeer registry: {root or 'NOT FOUND (cross-repo checks skipped)'}")
    print(f"{'FAILED' if failures else 'OK'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
