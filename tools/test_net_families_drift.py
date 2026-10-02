#!/usr/bin/env python3
"""Guard the cross-repo copy of the `NET_FAMILY_*` bits against drift.

Pure logic: reads two source files off disk, parses them, compares. No
build, no VICE, no hardware, milliseconds. Runs under pytest (it is listed
in ``pytest.ini``'s ``testpaths``) and standalone::

    python3 tools/test_net_families_drift.py

WHY THIS EXISTS. ``src/net/net_families.inc`` holds the c64-lib-contract
SPEC §13.0 family bits. §13 was retired at contract v1.0.0, so there is no
upstream left to copy from, and c64-wireguard keeps an independent copy in
its own ``src/net/net_families.inc``. The bits are what a backend manifest
exports (``NET_BACKEND_FAMILIES``) and what a consumer asserts against, so
two repos disagreeing on one is a silent ABI split. Nothing checked that
the two copies agree; this suite is that check.

WHAT IT REQUIRES, both directions: the same set of ``NET_FAMILY_*`` names
on each side, each with the same value. A bit missing on either side, a
renamed bit (seen as one missing name plus one extra) and a changed value
each fail, naming the bit.

THE PARSER FAILS CLOSED. Every non-blank, non-comment line of both files
must be one of: the include guard (``.ifndef`` / guard ``= 1`` /
``.endif``) or a definition in one of the recognised spellings::

    NET_FAMILY_X = $0010      recognised (1-4 hex digits)
    NET_FAMILY_X = 16         recognised
    .define NET_FAMILY_X $10  recognised

Anything else -- an expression-valued bit (``NET_FAMILY_X =
NET_FAMILY_DNS << 1``), a typo'd name, a new directive -- is a FAILURE that
quotes the line, never a line silently skipped. A parser that drops a line
it cannot read reports a bit no check can see (the lesson of wg#169's
review). The cost is that a harmless new directive in either file turns
this red until the grammar here learns it; that is the intended direction.

THE CROSS-REPO CHECKS NEED A PEER CHECKOUT, located exactly as
``tools/test_net_err_registry.py`` locates it (``C64_WIREGUARD_ROOT``, then
``../c64-wireguard``, then ``~/Documents/c64-wireguard``; the shared helper
is imported, not copied). A missing checkout is an INVOLUNTARY skip under
``tools/_skip_policy.py`` and FAILS (#178). The loud opt-out is the same
variable the registry suite uses, ``C64_NO_PEER_REGISTRY=1`` -- one peer,
one hatch -- and it still prints the full vacuity warning. A checkout that
IS found but has no ``src/net/net_families.inc`` is not a skip: the peer
moved or deleted its copy, and that fails.

Nothing here validates or edits c64-wireguard; a disagreement is a finding
for a human to take cross-repo. Bits are append-only and never reused, so
the fix is never "renumber ours".
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _skip_policy import VoluntarySkip, require, verdict  # noqa: E402
from test_net_err_registry import OPT_OUT_ENV, _wireguard_root  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
OURS = REPO / "src" / "net" / "net_families.inc"
PEER_REL = Path("src") / "net" / "net_families.inc"

TOTAL_CHECKS = 5
CERTIFIES = ("agreement between this repo's NET_FAMILY_* bits and "
             "c64-wireguard's copy")

GUARD = "NET_FAMILIES_INC_INCLUDED"
NAME_PREFIX = "NET_FAMILY_"

_DEF_RE = re.compile(
    r"^(?:\.define\s+([A-Za-z_][A-Za-z0-9_]*)\s+|"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
    r"(?:\$([0-9A-Fa-f]{1,4})|([0-9]{1,5}))$")
_STRUCTURAL = (re.compile(rf"^\.ifndef\s+{GUARD}$"),
               re.compile(rf"^{GUARD}\s*=\s*1$"),
               re.compile(r"^\.endif$"))


class FamiliesParseError(AssertionError):
    """A families file holds a line the parser will not guess about."""


def parse_families(path):
    """{name: value} for every NET_FAMILY_* definition in `path`.

    Raises FamiliesParseError naming every line that is neither include
    guard nor a recognised NET_FAMILY_* definition, and every name defined
    twice. Never skips a line it does not understand.
    """
    bits, bad = {}, []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8")
                                 .splitlines(), 1):
        code = raw.split(";", 1)[0].strip()
        if not code or any(r.match(code) for r in _STRUCTURAL):
            continue
        m = _DEF_RE.match(code)
        name = m and (m.group(1) or m.group(2))
        if not m or not name.startswith(NAME_PREFIX):
            bad.append(f"{path}:{lineno}: {raw.strip()!r}")
            continue
        if name in bits:
            bad.append(f"{path}:{lineno}: {name} defined twice")
            continue
        bits[name] = int(m.group(3), 16) if m.group(3) else int(m.group(4))
    if bad:
        raise FamiliesParseError(
            "lines that are neither the include guard nor a recognised "
            "NET_FAMILY_* definition (NAME = $hhhh | NAME = ddd | .define "
            "NAME value; no expressions): " + "; ".join(bad))
    if not bits:
        raise FamiliesParseError(f"{path} defines no {NAME_PREFIX}* bits")
    return bits


def _fmt(bits):
    return ", ".join(f"{n}=${v:04X}" for n, v in sorted(bits.items()))


# --------------------------------------------------------------------------
# 1-2: structural, our copy only. No peer checkout needed; these always run.
# --------------------------------------------------------------------------

def test_our_families_file_parses():
    parse_families(OURS)


def test_our_bits_are_distinct_single_bits():
    bits = parse_families(OURS)
    not_single = [f"{n}=${v:04X}" for n, v in sorted(bits.items())
                  if v == 0 or v & (v - 1)]
    by_value = {}
    for n, v in sorted(bits.items()):
        by_value.setdefault(v, []).append(n)
    shared = {f"${v:04X}": ns for v, ns in by_value.items() if len(ns) > 1}
    assert not not_single and not shared, (
        f"{OURS}: family values must be distinct single bits; not a single "
        f"bit: {not_single}; one bit, several names: {shared}")


# --------------------------------------------------------------------------
# 3-5: cross-repo drift. Needs a c64-wireguard checkout; a missing one is an
# involuntary skip, i.e. a failure, unless C64_NO_PEER_REGISTRY=1.
# --------------------------------------------------------------------------

def _peer_file():
    root = _wireguard_root()
    require(
        root is not None,
        "no c64-wireguard checkout found, so this repo's NET_FAMILY_* bits "
        "are UNVERIFIED against the peer's copy. Set "
        "C64_WIREGUARD_ROOT=/path/to/c64-wireguard, or place it at "
        "../c64-wireguard",
        executed=2, total=TOTAL_CHECKS,
        certifies=CERTIFIES,
        opt_out_env=OPT_OUT_ENV,
    )
    path = root / PEER_REL
    if not path.is_file():
        raise FamiliesParseError(
            f"c64-wireguard checkout {root} has no {PEER_REL}: the peer "
            f"moved or deleted its copy of the family bits")
    return path


def test_peer_families_file_parses():
    parse_families(_peer_file())


def test_same_family_names_both_sides():
    peer = _peer_file()
    ours, theirs = parse_families(OURS), parse_families(peer)
    only_ours = sorted(set(ours) - set(theirs))
    only_theirs = sorted(set(theirs) - set(ours))
    assert not only_ours and not only_theirs, (
        f"NET_FAMILY_* names disagree (a rename shows as one of each): "
        f"only in {OURS}: {only_ours}; only in {peer}: {only_theirs}. "
        f"Bits are a cross-repo agreement -- take it to the c64-wireguard "
        f"lane, do not edit unilaterally.")


def test_same_family_values_both_sides():
    peer = _peer_file()
    ours, theirs = parse_families(OURS), parse_families(peer)
    wrong = [f"{n}: ours ${ours[n]:04X}, theirs ${theirs[n]:04X}"
             for n in sorted(set(ours) & set(theirs)) if ours[n] != theirs[n]]
    assert not wrong, (
        f"NET_FAMILY_* values disagree: {'; '.join(wrong)}. Ours: "
        f"{_fmt(ours)}. Theirs ({peer}): {_fmt(theirs)}. Bits are "
        f"append-only and never reused.")


def main():
    """Standalone lane; same shape as test_net_err_registry.main().

    VoluntarySkip (the opt-out) is a plain Exception and must be caught
    before AssertionError's bucket; SkipPolicyError (no checkout, no
    opt-out) is an AssertionError and lands in FAIL.
    """
    passed = failures = skipped = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            passed += 1
            print(f"PASS  {name}")
        except VoluntarySkip as exc:
            skipped += 1
            print(f"SKIP  {name}\n      {exc}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}\n      {exc}")
    root = _wireguard_root()
    print(f"\npeer checkout: {root or 'NOT FOUND'}")
    if skipped:
        print(f"{skipped} check(s) skipped by explicit {OPT_OUT_ENV}=1 opt-out "
              f"— this run certifies NOTHING about {CERTIFIES}")
    print(f"{'FAILED' if failures else 'OK'} — {failures} failure(s), "
          f"{skipped} skipped")
    return verdict(passed, failures, skipped=skipped,
                   opt_out_env=OPT_OUT_ENV, certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
