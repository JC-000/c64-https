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

TWO HALVES. ``src/net_err_registry_asserts.s`` is the assemble-time half: it
fails ca65 on every profile, both backends, if a code it knows about lands
on a peer-owned value or a published value is reassigned, and it costs no
bytes. Its blind spot is a code that is never registered in it, and it
cannot see the peer repository at all. This suite covers exactly those two
gaps, and adds the intra-repo checks that reach beyond it.

=============================================================================
WHAT THIS GUARD DOES **NOT** COVER — read before trusting a green run
=============================================================================

**Only three declaration spellings are recognised**, because this is a text
parser and not ca65:

    NAME = $8C          recognised
    NAME = 140          recognised
    .define NAME $8C    recognised

An **expression-valued** equate is NOT recognised HERE:

    UCI_ERR_NEW = UCI_ERR_NO_SOCKET + 4      not seen by this suite

Evaluating that needs an assembler, not a regex, and a parser that silently
mis-evaluated one would be worse than one that visibly does not try. But
the assembler half is not so limited: ca65 evaluates whatever
NET_ERR_ASSERT_* is handed, so a REGISTERED expression-valued code fires
the collision assert exactly like a literal (measured). The residual gap is
therefore narrow: an expression-valued code that is also never registered
in the asserts TU escapes both halves, because the registration check that
would have caught it is the one in this file, and this file cannot see the
code. Write literals and the question does not arise — every existing code
in both headers is one.

**The assembler half covers only registered codes.** Check 2 below is what
makes that safe, by failing when a code in the headers has no
``NET_ERR_ASSERT_*`` line. The two halves are only jointly complete for the
spellings listed above.

**Inline immediates are invisible to both halves.** A `lda #$8C / sta
net_last_error` with no equate behind it is text neither guard looks at. No
such site exists today — every write goes through a named code — so this is
latent, not live. It is named here because a guard's silence about a shape
it cannot see is indistinguishable from a pass.

**Nothing here validates c64-wireguard.** A code of ours their registry has
claimed is reported as a finding for a human to take cross-repo. This suite
never edits, and never asserts the correctness of, the peer repository.

THE OTHER DIRECTION — this guard CAN go red on something that is not an
error code. It reads two headers that also hold ordinary constants, and a
value in $40-$BF is not by itself evidence of an allocation. `UCI_STATUS_MAX
= 16` is out of range today, but buffer sizes favour 64 and 128, which are
$40 and $80 — the first byte of each family. ERR_NAME_MARKER is the gate
that keeps such a constant out, and the comment on it says what the gate in
turn lets through. If this suite ever tells you to allocate something in
c64-wireguard's registry that is plainly not an error code, that is this
class, and the fix is the gate, not the constant.

=============================================================================

THE CROSS-REPO CHECKS NEED A PEER CHECKOUT, and a missing one is an
INVOLUNTARY skip under ``tools/_skip_policy.py``: the drift checks verify
nothing without it, so they FAIL rather than pass quietly (#158/#165/#178).
Point the suite at a checkout with ``C64_WIREGUARD_ROOT=/path``; the
defaults are ``../c64-wireguard`` then ``~/Documents/c64-wireguard``. A lane
that genuinely has no peer checkout opts out loudly with
``C64_NO_PEER_REGISTRY=1``, which still prints the full vacuity warning. The six
structural checks run either way.
"""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _skip_policy import VoluntarySkip, require  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
UCI_HEADER = REPO / "src" / "net" / "uci" / "uci_errors.inc"
IP65_HEADER = REPO / "src" / "net" / "ip65" / "ip65_errors.inc"
ASSERTS_TU = REPO / "src" / "net_err_registry_asserts.s"

IP65_FAMILY = (0x40, 0x7F)
UCI_FAMILY = (0x80, 0xBF)

TOTAL_CHECKS = 10
CERTIFIES = ("agreement between this repo's net_last_error allocations and "
             "c64-wireguard's canonical registry")

# The one code we define that is a c64-wireguard allocation: mirrored here,
# reserved, never emitted, so the name is readable in our diagnostics. It is
# checked in the opposite direction from every other code (it must EQUAL
# theirs), and is excluded from the collision sweep by name, never by value.
MIRRORED = "UCI_ERR_LONG_READ"

# The env var that opts out of the cross-repo checks. DELIBERATELY NOT the
# repo-wide C64_ALLOW_SKIP: that one also gates test_build_flags_stamp.py's
# "is ca65 on PATH" prerequisite, and someone exporting it in a shell
# profile or CI config to quiet THIS suite would silently quiet a genuinely
# missing toolchain too. One hatch, one door.
OPT_OUT_ENV = "C64_NO_PEER_REGISTRY"

# N2 -- the false-positive gate. Both headers name every error code with an
# `_ERR_` infix (UCI_ERR_*, NET_ERR_IP65_*) and every non-code constant
# without one (UCI_DATA_QUEUE_MAX, UCI_READ_CHUNK_MAX, UCI_STATUS_MAX,
# IP65_ERRORS_INC_INCLUDED). Without this gate an innocent, correctly
# written `UCI_HOST_BUF_MAX = 64` reads as an error code in the ip65 family
# and produces three red checks telling the author to allocate a buffer
# size in c64-wireguard's error registry. Buffer sizes favour exactly the
# values ($40, $80) that land in these ranges, so that is a when, not an if.
#
# WHAT THE GATE LETS THROUGH, stated plainly: a real error code named
# without `_ERR_` -- say `UCI_STATUS_FOO = $8C` -- is invisible to this
# suite. The assemble-time half still catches it the moment it is
# registered (NET_ERR_CLAIM_VALUE and the peer-collision asserts do not
# look at names at all).
#
# THE GATE DOES WIDEN A GAP, and it is worth being exact about which. A
# code that is BOTH non-`_ERR_`-named AND never registered is now invisible
# to both halves. That is a NEW class, not a restatement of an old one: an
# `_ERR_`-named unregistered code is caught here at every revision, and
# before the gate this suite caught the non-`_ERR_` unregistered case three
# ways (measured on the two commits either side of it -- 3 failures before,
# 0 after). The decision above still stands; the cost is one new blind
# spot, not zero.
ERR_NAME_MARKER = "_ERR_"

# snapshot name -> the peer's literal spelling, for rows whose name does not
# follow either convention _peer_snapshot_expected_name() derives. Empty
# today; every one of the nine current rows derives cleanly.
PEER_NAME_OVERRIDES = {}


class RegistryParseError(AssertionError):
    """A header is malformed in a way no individual check should own.

    AssertionError so pytest renders it as a plain failure and the
    standalone runner's handler catches it -- but a NAMED one, so it does
    not vanish under `python -O` the way the bare `assert` it replaced did.

    It is still raised from a helper, so it surfaces under EVERY test that
    calls `_our_codes()` and none of them owns the problem. That is not
    fixed; the message is self-identifying, which is why it is tolerable.
    """

# Declaration spellings we recognise. See the docstring's scope block: an
# expression-valued equate is deliberately out of scope.
#   NAME = $hh   |   NAME = ddd   |   .define NAME $hh / ddd
_EQUATE_RE = re.compile(
    r"^\s*(?:\.define\s+([A-Za-z_][A-Za-z0-9_]*)\s+|"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
    r"(?:\$([0-9A-Fa-f]{1,2})|([0-9]{1,3}))\s*(?:;.*)?$")

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
    """{name: (value, path, family)} for every error code our headers define."""
    codes = {}
    for path, family in ((UCI_HEADER, UCI_FAMILY), (IP65_HEADER, IP65_FAMILY)):
        for line in _read(path):
            m = _EQUATE_RE.match(line)
            if not m:
                continue
            name = m.group(1) or m.group(2)
            value = int(m.group(3), 16) if m.group(3) else int(m.group(4), 10)
            if not (_in(value, IP65_FAMILY) or _in(value, UCI_FAMILY)):
                continue
            if ERR_NAME_MARKER not in name:
                continue        # not an error code -- see N2 note above
            if name in codes:
                raise RegistryParseError(
                    f"{name} is defined in both headers; a net_last_error "
                    f"code has exactly one home (#184)")
            codes[name] = (value, path, family)
    return codes


def _peer_snapshot():
    """{name: value} for the NET_ERR_PEER_* table in the asserts TU."""
    return {m.group(1): int(m.group(2), 16)
            for m in (_PEER_RE.match(l) for l in _read(ASSERTS_TU)) if m}


def _peer_snapshot_expected_name(snapshot_name):
    """The peer's own spelling implied by a NET_ERR_PEER_* name.

    NET_ERR_PEER_UCI_SEND_TOO_LONG  -> UCI_ERR_SEND_TOO_LONG
    NET_ERR_PEER_IP65_UDP_LISTEN    -> NET_ERR_IP65_UDP_LISTEN

    The two rewrites fit all nine rows today. A future peer name fitting
    neither shape would otherwise force a contorted snapshot name or a
    spurious red, so PEER_NAME_OVERRIDES is the escape hatch: put the
    peer's literal spelling there and keep our name readable.
    """
    if snapshot_name in PEER_NAME_OVERRIDES:
        return PEER_NAME_OVERRIDES[snapshot_name]
    rest = snapshot_name[len("NET_ERR_PEER_"):]
    if rest.startswith("UCI_"):
        return "UCI_ERR_" + rest[len("UCI_"):]
    if rest.startswith("IP65_"):
        return "NET_ERR_IP65_" + rest[len("IP65_"):]
    return rest


def _registered_names():
    """Names the asserts TU actually puts through a collision macro."""
    names = set()
    for line in _read(ASSERTS_TU):
        m = re.match(r"^NET_ERR_ASSERT_(?:IP65|UCI)\s+([A-Za-z0-9_]+)\s*,", line)
        if m:
            names.add(m.group(1))
    return names


def _macro_peer_refs():
    """{'IP65': {peer names asserted}, 'UCI': {...}} from the macro bodies."""
    refs = {"IP65": set(), "UCI": set()}
    current = None
    for line in _read(ASSERTS_TU):
        m = re.match(r"^\s*\.macro\s+NET_ERR_ASSERT_(IP65|UCI)\b", line)
        if m:
            current = m.group(1)
            continue
        if re.match(r"^\s*\.endmacro\b", line):
            current = None
            continue
        if current:
            refs[current].update(re.findall(r"\bNET_ERR_PEER_[A-Za-z0-9_]+", line))
    return refs


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
# 1-6: structural. No peer checkout needed; these always run.
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


def test_our_codes_are_pairwise_distinct():
    """Two of our own names on one byte is the same defect, intra-repo.

    The assembler DOES catch this for any registered code, via
    NET_ERR_CLAIM_VALUE in src/net_err_registry_asserts.s -- a duplicate is
    a ca65 redefinition error and fails the build on all five profiles.
    (An earlier revision of this file claimed the assembler could not
    express it. That was wrong, and it foreclosed the better guard for a
    round.) What remains true, and is why this check stays: the literal
    pins give distinctness only among the codes that existed when they were
    written, and the peer-collision asserts never look at our own set, so
    NEITHER of those catches a new duplicate. And an UNREGISTERED duplicate
    reaches no macro at all, so the claim never runs -- that case is this
    check's alone.
    """
    by_value = {}
    for name, (value, _path, _family) in sorted(_our_codes().items()):
        by_value.setdefault(value, []).append(name)
    dupes = {f"${v:02X}": names for v, names in sorted(by_value.items())
             if len(names) > 1}
    assert not dupes, (
        f"one value, several names — our own allocations collide: {dupes}. "
        f"A published value is never reassigned, and it is never doubled up "
        f"either: net_last_error carries one byte and a post-mortem cannot "
        f"tell these apart (#184).")


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


def test_every_snapshot_entry_is_asserted_by_a_macro():
    """A NET_ERR_PEER_* equate with no .assert is a peer code nothing checks.

    The macro bodies are hand-written, so adding a row to the table without
    adding the matching assert line would leave the assembler half quietly
    not covering it.
    """
    snapshot = _peer_snapshot()
    refs = _macro_peer_refs()
    missing = []
    for name, value in sorted(snapshot.items(), key=lambda kv: kv[1]):
        family = "IP65" if _in(value, IP65_FAMILY) else "UCI"
        if name == "NET_ERR_PEER_UCI_LONG_READ":
            continue        # the mirror: asserted for equality outside the macro
        if name not in refs[family]:
            missing.append(f"{name} (${value:02X}) missing from "
                           f"NET_ERR_ASSERT_{family}")
    assert not missing, (
        "peer codes in the NET_ERR_PEER_* table that no macro asserts "
        "against: " + "; ".join(missing)
        + ". Add the .assert line, or the assembler does not actually check "
          "that value (#184).")


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
# 7-10: cross-repo drift. Needs a c64-wireguard checkout; a missing one is an
# involuntary skip, i.e. a failure, unless C64_NO_PEER_REGISTRY=1.
# --------------------------------------------------------------------------

def _require_peer():
    root = _wireguard_root()
    require(
        root is not None,
        "no c64-wireguard checkout found, so this repo's snapshot of the "
        "canonical net_last_error registry is UNVERIFIED. Set "
        "C64_WIREGUARD_ROOT=/path/to/c64-wireguard, or place it at "
        "../c64-wireguard",
        executed=6, total=TOTAL_CHECKS,
        certifies=CERTIFIES,
        opt_out_env=OPT_OUT_ENV,
    )
    return root


def test_snapshot_values_match_the_peer_registry():
    root = _require_peer()
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


def test_snapshot_names_match_the_peer_registry():
    """Values alone are not enough: a RENAME upstream leaves every value
    check green while our snapshot, our headers and our diagnostics all
    carry a name that no longer exists. That includes the $8A mirror, whose
    whole purpose is to carry their name."""
    root = _require_peer()
    registry = _peer_registry(root)
    wrong = []
    for name, value in sorted(_peer_snapshot().items(), key=lambda kv: kv[1]):
        row = registry.get(value)
        if row is None:
            continue                    # a value drift; the check above owns it
        expected = _peer_snapshot_expected_name(name)
        if row[0] != expected:
            wrong.append(f"${value:02X}: we call it {expected} "
                         f"(as {name}), they now call it {row[0]}")
    assert not wrong, (
        "c64-wireguard has RENAMED codes our snapshot mirrors: "
        + "; ".join(wrong)
        + f". Registry: {root}/src/net_abi.inc. Rename ours to match — the "
          "value is the contract, the name is how a post-mortem reads it "
          "(#184).")


def test_no_code_of_ours_is_claimed_by_the_peer_registry():
    """The finding this whole ticket exists to make impossible to miss."""
    root = _require_peer()
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
    """Standalone lane.

    `require()` raises SkipPolicyError (an AssertionError) on a missing
    peer checkout, so it lands in the FAIL bucket — an involuntary skip is
    a failure. With C64_NO_PEER_REGISTRY=1 it raises VoluntarySkip instead, which
    is a plain Exception and MUST be named before any broad handler; see
    _skip_policy.VoluntarySkip. Catching only AssertionError here is what
    let a pytest.skip() BaseException kill this runner mid-suite.
    """
    failures = skipped = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"PASS  {name}")
        except VoluntarySkip as exc:
            skipped += 1
            print(f"SKIP  {name}\n      {exc}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}\n      {exc}")
    root = _wireguard_root()
    print(f"\npeer registry: {root or 'NOT FOUND'}")
    if skipped:
        print(f"{skipped} check(s) skipped by explicit {OPT_OUT_ENV}=1 opt-out "
              f"— this run certifies NOTHING about {CERTIFIES}")
    print(f"{'FAILED' if failures else 'OK'} — {failures} failure(s), "
          f"{skipped} skipped")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
