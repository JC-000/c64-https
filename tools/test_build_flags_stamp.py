#!/usr/bin/env python3
"""build/flags.stamp — a build-flag change must never survive as a mixed link.

The defect this pins, measured 2026-08-30 on a UCI onchip tree. The hashes
below are that day's tree, kept as the shape of the evidence; they are NOT
current — the default HTTPS_HOST changed afterwards, which moves every one
of them. The test recomputes its own oracle, so nothing here is load-bearing:

    make BACKEND=uci USE_NISTCURVES_ONCHIP=1                    # 1bb5fad9...
    make BACKEND=uci USE_NISTCURVES_ONCHIP=1 HTTPS_SNI=www.foo.invalid
                                                                # d1b63508...
    make clean && make ... HTTPS_SNI=www.foo.invalid                # a65fff60...

The middle line is the bug. `HTTPS_SNI=` feeds TWO consumers: the string
travels in the generated build/https_host.inc (content-compared at parse
time, issue #128, which invalidates boot.o), and a non-empty value ALSO
adds `-D HTTPS_SNI_OVERRIDE=1`, read by src/http.s. Nothing invalidated
http.o, so the image embedded the SNI string via boot.o while never
executing the override in http.o — behaviourally identical to not passing
the flag at all. It defeats every cheap check: the PRG hash changes, the
name greps out of the image, exit status is 0. Only a diff against a
properly cleaned build exposes it, and it cost a full false negative on
issue #141.

`make clean` after any flag change WAS the documented rule, but a rule
that lives only in prose is a rule that gets forgotten once.
build/flags.stamp makes it mechanical, and the docs now describe the
stamp instead of prescribing `make clean`: the whole
ca65/ld65 command line is written to a stamp file and content-compared
during Makefile PARSE, before make builds its file database, and any
change deletes the objects and the PRG. Absence, not a timestamp
comparison — macOS ships GNU Make 3.81, whose mtimes are 1-second
granular, so two builds in one second are indistinguishable by date.

Two properties are checked, in both directions, because either alone
would be satisfied by a Makefile that simply rebuilt everything always:

  * a flag change must produce exactly the `make clean` image, and
  * an unchanged flag set must rebuild nothing at all.

Isolation: every build runs in a throwaway symlink farm under $TMPDIR
(src/, cfg/, tools/, libs/ and the Makefile symlinked in; build/ private
to the farm), so the suite never touches the developer's build/ and can
be run mid-session. It shells out to `make`; each build is well under a
second because ca65 is fast and the tree is small.

Runs under pytest, and standalone::

    python3 tools/test_build_flags_stamp.py

Exit codes (standalone), per tools/_skip_policy.py::

    0  every case ran and passed
    1  a case ran and FAILED
    2  COULD NOT RUN -- ca65/ld65 absent, so nothing was verified

An absent toolchain is an INVOLUNTARY skip and must never read as a pass
(#177): this module is pinned in pytest.ini `testpaths`, so a silent skip
here is bare `pytest` at the repo root going green while asserting an
invariant it never checked. `C64_ALLOW_SKIP=1` is the deliberate opt-out
for a CI lane with no cc65; it still prints the warning.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _skip_policy import (   # noqa: E402
    EXIT_CANNOT_RUN, VoluntarySkip, cannot_run, require)

REPO = Path(__file__).resolve().parent.parent

# What every test here certifies, and therefore what a run that could not
# execute them certifies NOTHING about. Named once so the involuntary-skip
# block says the same thing on both channels.
CERTIFIES = ("build/flags.stamp — that a build-flag change invalidates the "
             "tree, and that an unchanged flag set does not")

# What a build reads. `libs` carries the sibling submodules the archive
# wrappers assemble from; `ip65`/`ip65-build` are symlinked for
# completeness but never assembled, because every case here is
# BACKEND=uci and an ip65 link would cost a blob build this suite has no
# use for. The BACKEND=ip65 case below never links.
#
# It used to say an ip65 link outside a real checkout root "is not to be
# trusted" because ca65 resolves `.incbin` against the current directory.
# That reason is retired (#116): the operand is a bare `ip65-c64.bin`
# resolved through `--bin-include-dir $(abspath ip65-build)`, which under
# this farm points at the symlinked `ip65-build`. Not linking ip65 here
# is a cost choice now, not a correctness one.
FARM_LINKS = ("src", "cfg", "tools", "libs", "ip65", "ip65-build", "Makefile")

# The reference profile for every case: UCI, onchip. Fastest to build, and
# the profile the 2026-08-30 incident was measured on.
UCI = ("BACKEND=uci", "USE_NISTCURVES_ONCHIP=1")
# The objects build/https_host.inc invalidates: the two that know the target
# strings (#128/#141) and cert_pin.o, which reads the pin bytes (#155).
TARGET_INC_GRAIN = {"build/boot.o", "build/http.o", "build/cert_pin.o"}

PRG = "build/c64-https.prg"
STAMP = "build/flags.stamp"

# Everything one link writes (LD65FLAGS' -o/-Ln/-m/--dbgfile). Issue #220:
# an invalidation that deletes only the PRG leaves the other three describing
# an image that no longer exists — and every margin figure in CLAUDE.md is
# read off the .map.
LINK_OUTPUTS = (PRG, "build/labels.txt", "build/c64-https.map",
                "build/c64-https.dbg")

# Goals that touch nothing under build/, and so must not invalidate it
# (#220). `clean` is exempt too but deletes build/ itself, so it proves
# nothing here.
MAINTENANCE_GOALS = ("ip65-libs", "ip65-blob")

# Invocations that must NOT mutate the tree. The bare short forms are the
# ones #174 reported; the COMBINED forms are what keep the guard from being
# "simplified" back into that bug.
#
# `make -n --no-print-directory` is the discriminating case, and it is the
# only one. GNU make 3.81 renders it as `MAKEFLAGS=[ --no-print-directory -n]`
# — the letters are LAST, and they carry a leading dash — so the two
# obvious-looking guards split exactly here:
#
#   $(firstword $(MAKEFLAGS))                    -> [--no-print-directory]
#       finds an `n` and a `t` in the long option's NAME. Right verdict here,
#       wrong reason; and on `make --no-print-directory` alone (no `-n`) the
#       same reasoning calls a REAL build a dry run, skips the invalidation,
#       and ships a mixed link. That is the direction
#       test_an_unrelated_option_does_not_suppress_invalidation pins.
#
#   $(filter-out -%,$(firstword $(MAKEFLAGS)))   -> []
#       drops the letters entirely because they are dash-prefixed, so a real
#       build runs and DELETES THE TREE. This is #174 verbatim, and without
#       the row below it passes every other test in this file — measured, by
#       mutating the Makefile to that form: 9/9 green while
#       `make -n --no-print-directory BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1`
#       left 0 objects and no PRG at exit 0.
#
# So the bare forms alone cannot tell a correct guard from a destructive one.
# Neither long option here is exotic: `--no-print-directory` contains both an
# `n` and a `t`, `--warn-undefined-variables` an `n`, and either can arrive
# from the environment, a parent make, or an IDE.
DRY_RUN_INVOCATIONS = (
    ("-n",),
    ("-q",),
    ("-t",),
    ("-npq",),                              # what shell completion runs
    ("-n", "--no-print-directory"),         # the discriminating case
    ("--no-print-directory", "-n"),         # same, option order swapped
    ("-t", "--no-print-directory"),
    ("-q", "--warn-undefined-variables"),
)

# The same question asked through the ENVIRONMENT under `-e`. GNU make 3.81
# then hands the makefile the environment's MAKEFLAGS TEXT verbatim, so a
# guard that scans $(MAKEFLAGS) for single-letter words sees `--dry-run`, finds
# no `n` word, and takes the REAL path: every object and the PRG deleted at
# exit 0. Each long spelling is its own row because each one is a separate
# way to miss; `--que` is an abbreviation make accepts. 4.x normalises
# MAKEFLAGS even under -e, so these rows are red on 3.81 only.
DRY_RUN_ENV_INVOCATIONS = (
    ({"MAKEFLAGS": "--dry-run"}, ("-e",)),
    ({"MAKEFLAGS": "--just-print"}, ("-e",)),
    ({"MAKEFLAGS": "--recon"}, ("-e",)),
    ({"MAKEFLAGS": "--question"}, ("-e",)),
    ({"MAKEFLAGS": "--que"}, ("-e",)),
    ({"MAKEFLAGS": "--touch"}, ("-e",)),
    ({"MAKEFLAGS": "--dry-run --no-print-directory"}, ("-e",)),
    ({"MAKEFLAGS": "-s --dry-run"}, ("-e",)),
)

# REAL builds that carry option text with an `n`, `q` or `t` in it, and so
# must still invalidate. `-I tools` is the 4.x trap: 4.x records it in
# MAKEFLAGS/MFLAGS as the word `-Itools`, whose `t` a dash-stripping scan
# reads as -t. The `-e` rows are the real-build side of the table above.
REAL_BUILD_INVOCATIONS = (
    ({}, ("--no-print-directory",)),
    ({}, ("--warn-undefined-variables",)),
    ({}, ("--silent",)),
    ({}, ("-I", "tools")),
    ({}, ("-e",)),
    ({"MAKEFLAGS": "--no-print-directory"}, ("-e",)),
    ({"MAKEFLAGS": "--warn-undefined-variables"}, ("-e",)),
)


def _toolchain_missing():
    for tool in ("ca65", "ld65"):
        if shutil.which(tool) is None:
            return tool
    return None


def _require_toolchain():
    """Fail loudly, on both channels, when cc65 is not installed (#177).

    Every test here shells out to `make`, so an absent ca65/ld65 means the
    body cannot run. This used to be four lines of `print("SKIP: ...")` and a
    bare `return` -- and a pytest test that returns None without asserting is
    a PASS, so `pytest tools/test_build_flags_stamp.py` on a machine without
    cc65 reported `7 passed in 0.01s`, the SKIP lines swallowed by pytest's
    stdout capture. This module is pinned in pytest.ini `testpaths`, so that
    is bare `pytest` at the repo root going green while asserting an
    invariant it never checked.

    `require()` raises instead, carrying the vacuity warning INSIDE the
    reason string, because under pytest `-ra` the reason is the only channel
    that survives. `C64_ALLOW_SKIP=1` is the deliberate opt-out for a CI lane
    with no toolchain: it downgrades to a real pytest skip and still prints
    the warning.
    """
    missing = _toolchain_missing()
    require(
        missing is None,
        f"{missing} not on PATH -- every case here shells out to `make`",
        executed=0,
        total=1,
        certifies=CERTIFIES,
        opt_out_env="C64_ALLOW_SKIP",
    )


class Farm:
    """A disposable tree whose build/ is private. src/cfg/tools/libs/ip65/
    ip65-build are symlinks into the real checkout, so the libs/ sub-make
    (libs/nistcurves/build/), `make ip65-libs` and `make ip65-blob`'s
    ca65/ld65 recipe write there."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="c64-flags-stamp-"))
        for name in FARM_LINKS:
            target = REPO / name
            if not target.exists():
                continue
            if name == "ip65-build":
                # A PRIVATE copy: the ip65 rules write and delete the blob
                # and its stamps here, and a symlink made a Farm test running
                # `make BACKEND=ip65 ...` delete the developer's real blob.
                shutil.copytree(target, self.dir / name, symlinks=True)
            else:
                os.symlink(target, self.dir / name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, *flags, dry_run=False, opts=(), env=None, check=True):
        cmd = ["make"] + (["-n"] if dry_run else []) + list(opts) + list(flags)
        proc = subprocess.run(cmd, cwd=self.dir, text=True,
                              env=dict(os.environ, **(env or {})),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if check:
            shown = " ".join(f"{k}={v}" for k, v in (env or {}).items())
            assert proc.returncode == 0, (
                f"`{shown} {' '.join(cmd)}` failed ({proc.returncode}):\n"
                f"{proc.stdout}"
            )
        return proc

    def path(self, rel):
        return self.dir / rel

    def exists(self, rel):
        return self.path(rel).exists()

    def sha(self, rel=PRG):
        return hashlib.sha256(self.path(rel).read_bytes()).hexdigest()

    def mtimes(self, suffix=".o"):
        out = {}
        for p in sorted(self.path("build").rglob("*" + suffix)):
            out[str(p.relative_to(self.dir))] = p.stat().st_mtime_ns
        return out


class X25519Farm(Farm):
    """A Farm whose libs/x25519 is a private COPY, so a test may edit it.

    Everything else under libs/ stays a symlink into the checkout. The copy
    carries no .git, so tools/integration/sibling_src_digest.sh takes its
    find(1) fallback here; the git path is what every real build exercises.
    """

    def __init__(self):
        super().__init__()
        os.unlink(self.dir / "libs")
        (self.dir / "libs").mkdir()
        for entry in (REPO / "libs").iterdir():
            if entry.name == "x25519":
                shutil.copytree(entry, self.dir / "libs" / "x25519",
                                ignore=shutil.ignore_patterns(".git"))
            else:
                os.symlink(entry, self.dir / "libs" / entry.name)

    def mutate_fe25519_add(self):
        """Carry-in 1 instead of 0: every fe25519_add result off by one."""
        src = self.path("libs/x25519/src/fe25519.s")
        text = src.read_text()
        head, sep, tail = text.partition(".proc fe25519_add")
        assert sep, "fe25519_add not found in libs/x25519/src/fe25519.s"
        body, loop, rest = tail.partition("@add_loop:")
        assert loop and body.count("        clc\n") == 1, (
            "fe25519_add's single carry-clear before @add_loop moved; "
            "re-aim this mutation")
        src.write_text(head + sep + body.replace("        clc\n",
                                                 "        sec\n") + loop + rest)


def test_sibling_source_edit_matches_a_clean_build():
    """A libs/x25519 source edit must reach the PRG without `make clean`.

    build/lib/x25519.a used to depend only on its wrapper and the flags
    stamp, so an edited sibling source -- which is what a submodule pin
    bump is -- left the old archive linked at exit 0 ("Nothing to be done").
    build/lib/x25519.src.stamp (a content digest, compared at parse time)
    is what deletes it now. The inverse is pinned too: an untouched tree
    must not rebuild the archive or relink.
    """
    _require_toolchain()
    with X25519Farm() as farm:
        farm.mutate_fe25519_add()
        farm.make()
        oracle = farm.sha()
    with X25519Farm() as farm:
        farm.make()
        before = farm.sha()
        archive = farm.path("build/lib/x25519.a").stat().st_mtime_ns
        prg = farm.path(PRG).stat().st_mtime_ns
        farm.make()
        assert farm.path("build/lib/x25519.a").stat().st_mtime_ns == archive, (
            "an unchanged libs/x25519 rebuilt build/lib/x25519.a")
        assert farm.path(PRG).stat().st_mtime_ns == prg, (
            "an unchanged libs/x25519 relinked the PRG")
        farm.mutate_fe25519_add()
        farm.make()
        after = farm.sha()

    assert before != oracle, (
        "the fe25519_add mutation does not change the PRG even from a clean "
        "tree -- this test's oracle is vacuous; re-aim the mutation")
    assert after == oracle, (
        "STALE SIBLING ARCHIVE: after editing libs/x25519/src/fe25519.s, "
        f"`make` produced\n  {after}\nbut a clean build of the edited tree "
        f"produces\n  {oracle}\n"
        + ("i.e. the OLD crypto is still linked. " if after == before else "")
        + "build/lib/x25519.src.stamp should have deleted build/lib/x25519.a "
        "at parse time.")


def _clean_build_sha(*flags):
    """The PRG a `make clean` build of these flags produces — the oracle."""
    with Farm() as farm:
        farm.make(*flags)
        return farm.sha()


def test_flag_change_without_clean_matches_a_clean_build():
    """The 2026-08-30 incident: HTTPS_SNI= on a tree built without it.

    `make clean` WAS the documented remedy, and it is absent here on
    purpose — the whole point is what happens when someone forgets it,
    which since #159 build/flags.stamp has to handle unaided.
    """
    _require_toolchain()
    oracle = _clean_build_sha(*UCI, "HTTPS_SNI=www.foo.invalid")
    with Farm() as farm:
        farm.make(*UCI)
        plain = farm.sha()
        farm.make(*UCI, "HTTPS_SNI=www.foo.invalid")
        dirty = farm.sha()

    assert plain != oracle, (
        "HTTPS_SNI=www.foo.invalid produced the same PRG as no SNI at all, even "
        "from a clean tree. The test's own oracle is vacuous — the flag has "
        "stopped doing anything, or the wrong flags are being passed."
    )
    assert dirty == oracle, (
        "MIXED LINK: adding HTTPS_SNI= without `make clean` produced\n"
        f"  {dirty}\nbut a clean build of the same flags produces\n"
        f"  {oracle}\n"
        "The SNI string rides build/https_host.inc (which invalidates "
        "boot.o) while `-D HTTPS_SNI_OVERRIDE=1` is read by src/http.s, "
        "which nothing invalidated. build/flags.stamp is what closes this."
    )


def test_profile_flip_without_clean_matches_a_clean_build():
    """A second flag, a different mechanism: comb changes the cfg too.

    USE_NISTCURVES_ONCHIP_COMB=1 adds `-D USE_NISTCURVES_COMB=1`, swaps
    the sibling archive, AND retargets $(CFG) to the -onchip cfg variant.
    Nothing in the old Makefile noticed any of the three.
    """
    _require_toolchain()
    comb = ("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1")
    oracle = _clean_build_sha(*comb)
    with Farm() as farm:
        farm.make(*UCI)
        onchip = farm.sha()
        farm.make(*comb)
        flipped = farm.sha()

    assert onchip != oracle, "comb and onchip images are identical — vacuous"
    assert flipped == oracle, (
        "MIXED LINK: USE_NISTCURVES_ONCHIP_COMB=1 without `make clean` "
        f"produced\n  {flipped}\nbut a clean build produces\n  {oracle}"
    )


def test_vic_blank_flip_without_clean_matches_a_clean_build():
    """A pure `-D` knob with no generated include anywhere near it."""
    _require_toolchain()
    noblank = UCI + ("VIC_BLANK=0",)
    oracle = _clean_build_sha(*noblank)
    with Farm() as farm:
        farm.make(*UCI)
        blanked = farm.sha()
        farm.make(*noblank)
        flipped = farm.sha()

    assert blanked != oracle, "VIC_BLANK=0 changed nothing — vacuous"
    assert flipped == oracle, (
        "MIXED LINK: VIC_BLANK=0 without `make clean` produced\n"
        f"  {flipped}\nbut a clean build produces\n  {oracle}"
    )


def test_backend_flip_removes_the_other_backends_prg():
    """The second documented failure mode: no link at all, exit 0.

    macOS GNU Make 3.81 compares mtimes at 1-second resolution, so a
    same-second backend flip could leave the OTHER backend's PRG on disk
    and exit 0 — and every rig loads that path by name. The invalidation
    happens during parse, so the stale PRG and objects are gone before
    make has even built its file database.

    This case deliberately does not LINK ip65 — a real ip65 link would
    drag in a blob build this suite has no use for. The goal is
    `build/flags.stamp`, which the parse-time block has already written
    by the time make looks at it, so the invocation is a REAL build (no
    `-n`) that assembles nothing and links nothing. It used to be spelled
    `make -n BACKEND=ip65`, which relied on a dry run mutating the tree —
    the defect fixed in #174.
    """
    _require_toolchain()
    with Farm() as farm:
        farm.make(*UCI)
        assert farm.exists(PRG)
        farm.make("BACKEND=ip65", STAMP, check=False)
        assert not farm.exists(PRG), (
            "a BACKEND flip left the UCI PRG in place. This invocation "
            "performs no link, so whatever `make BACKEND=ip65` did next, "
            "build/c64-https.prg was a UCI image that rigs load by path."
        )
        assert not farm.exists("build/tls13.o"), (
            "a BACKEND flip left UCI-flavoured objects in place; the next "
            "ip65 link would have reused them (mixed link)."
        )


def test_flags_invalidation_removes_every_link_output():
    """Issue #220: the .map / labels.txt / .dbg must go with the PRG.

    Every margin figure in CLAUDE.md is read off build/c64-https.map, and
    rigs read addresses out of build/labels.txt. Before #220 the flag-stamp
    invalidation deleted `$(ALL_OBJS) $(PRG)` only, so all three sidecars
    survived describing an image that no longer existed — and a stale map
    still parses fine. Same invocation as the backend-flip case: a real
    build that links nothing, so whatever exists afterwards is a survivor.
    """
    _require_toolchain()
    with Farm() as farm:
        farm.make(*UCI)
        missing = [p for p in LINK_OUTPUTS if not farm.exists(p)]
        assert not missing, f"the baseline link did not write {missing} — vacuous"
        farm.make("BACKEND=ip65", STAMP, check=False)
        stale = [p for p in LINK_OUTPUTS if farm.exists(p)]
        assert not stale, (
            f"a flag change deleted the objects but left {stale} behind. They "
            "describe a UCI image that no longer exists; the .map is what "
            "every CLAUDE.md margin figure is measured from."
        )


def test_https_host_invalidation_removes_every_link_output():
    """Issue #220, the second block: build/https_host.inc had the same gap.

    Its grain must stay #128's (boot.o + http.o, plus #155's cert_pin.o,
    which reads the pin bytes from the same header) — only the link outputs
    join it, and the rest of the objects must survive.
    """
    _require_toolchain()
    with Farm() as farm:
        farm.make(*UCI)
        before = farm.mtimes()
        missing = [p for p in LINK_OUTPUTS if not farm.exists(p)]
        assert not missing, f"the baseline link did not write {missing} — vacuous"
        # The goal is the generated include itself: already rewritten at
        # parse time, so this is a real invocation that links nothing.
        farm.make(*UCI, "HTTPS_HOST=en.wikipedia.org", "build/https_host.inc",
                  check=False)
        stale = [p for p in LINK_OUTPUTS if farm.exists(p)]
        assert not stale, (
            f"a target-string change deleted the PRG but left {stale} behind, "
            "describing the previous target's image."
        )
        lost = set(before) - set(farm.mtimes())
        assert lost == TARGET_INC_GRAIN, (
            "the https_host.inc invalidation grain changed; #128/#155 want "
            f"exactly {sorted(TARGET_INC_GRAIN)}, got {sorted(lost)}"
        )


def test_maintenance_goals_do_not_invalidate():
    """Issue #220: a goal that builds nothing under build/ must not clear it.

    The compare runs at parse time, before goal selection, so a flagless
    `make ip65-libs` or `make ip65-blob` after a UCI build used to rewrite
    the stamp to the ip65 defaults and delete every object and the PRG of a
    build it never touched. Skipping is exact, not a guess: nothing under
    build/ changes, so the stamp still describes the objects beside it —
    which the last step checks by requiring a real rebuild of the original
    flags to be a no-op.

    The goal's own exit status is not asserted: on a fresh clone without
    `make ip65-libs`, `ip65-blob` fails in the ip65 link, and the tree must
    survive that too.
    """
    _require_toolchain()
    # A NON-default target string, so the flagless goal also differs from
    # build/https_host.inc: without it, the https_host.inc block's skip goes
    # untested (reverting only that guard left this suite green).
    targeted = UCI + ("HTTPS_HOST=en.wikipedia.org",)
    for goal in MAINTENANCE_GOALS:
        with Farm() as farm:
            farm.make(*targeted)
            objs = farm.mtimes()
            prg_sha = farm.sha()
            stamp = farm.path(STAMP).read_text()
            sidecars = {p: farm.sha(p) for p in LINK_OUTPUTS}
            assert objs, "the baseline build produced no objects — vacuous"

            farm.make(goal, check=False)                # flagless, on purpose

            lost = sorted(set(objs) - set(farm.mtimes()))
            assert not lost, (
                f"`make {goal}` deleted {len(lost)} object(s), e.g. {lost[:3]}. "
                "It builds nothing under build/, so it has no business "
                "invalidating a build it never touched."
            )
            gone = [p for p in LINK_OUTPUTS if not farm.exists(p)]
            assert not gone, f"`make {goal}` deleted {gone}"
            assert {p: farm.sha(p) for p in LINK_OUTPUTS} == sidecars, (
                f"`make {goal}` rewrote a link output"
            )
            assert farm.sha() == prg_sha
            assert farm.path(STAMP).read_text() == stamp, (
                f"`make {goal}` rewrote {STAMP}; it would then describe a "
                "flag set whose objects were never built."
            )
            proc = farm.make(*targeted)
            assert farm.mtimes() == objs and farm.sha() == prg_sha, (
                f"after `make {goal}`, a real rebuild of the SAME flags "
                "re-assembled objects:\n" + proc.stdout
            )


def test_maintenance_goal_beside_a_real_goal_still_invalidates():
    """The exemption applies only when EVERY goal is a maintenance goal.

    `make ip65-libs <anything else>` may build under build/, so it must
    take the ordinary path — the safe direction for an unlisted goal.
    """
    _require_toolchain()
    with Farm() as farm:
        farm.make(*UCI)
        assert farm.exists(PRG)
        farm.make("BACKEND=ip65", "ip65-libs", STAMP, check=False)
        assert not farm.exists(PRG), (
            "`make ip65-libs build/flags.stamp` with changed flags skipped the "
            "invalidation: the exemption leaked past a non-maintenance goal."
        )
        assert not farm.exists("build/tls13.o")


def test_dry_run_options_do_not_touch_the_tree():
    """Issue #174: `make -n`, `-q` and `-t` are contractually side-effect-free.

    The stamp's compare/invalidate lives in a `$(shell …)` evaluated while
    make PARSES the makefile — before the dependency graph exists, and
    therefore before `-n` can suppress anything. `-n` suppresses *recipes*;
    it does not suppress `$(shell)`. So asking "what would this build?" with
    a flag set that differs from build/flags.stamp used to delete every
    object and the PRG, exit 0, and print nothing about it. One `make -n`
    destroyed a working tree during a supervised session on 2026-08-31.

    Two things must survive a dry run, and the second is the subtle one:

      * the objects and the PRG (the deletion), and
      * build/flags.stamp itself (the `mv`). A dry run that rewrites the
        stamp leaves it asserting a flag set that was never built, which
        makes a LATER real build skip an invalidation it needed — the exact
        mixed link this file exists to prevent.

    `-q` matters as much as `-n`, and `make -npq` (what shell completion runs
    to enumerate targets) is a third spelling — so a guard that tests only
    for `n` misses both. The COMBINED short+long invocations in
    DRY_RUN_INVOCATIONS matter for a different reason: they are the only
    rows that distinguish a correct guard from one that reads the letters
    out of a long option's name, and without them a plausible
    "simplification" of the Makefile restores #174 with this file fully
    green. See the comment on that table.
    """
    _require_toolchain()
    comb = ("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1")
    with Farm() as farm:
        farm.make(*UCI)
        prg_sha = farm.sha()
        objs = farm.mtimes()
        stamp = farm.path(STAMP).read_text()
        assert objs, "the baseline build produced no objects — vacuous"

        for env, opts in ([({}, o) for o in DRY_RUN_INVOCATIONS]
                          + list(DRY_RUN_ENV_INVOCATIONS)):
            shown = " ".join([f"{k}='{v}'" for k, v in env.items()]
                             + list(opts))
            farm.make(*comb, opts=list(opts), env=env, check=False)
            assert farm.exists(PRG), (
                f"`make {shown}` with a changed flag set DELETED {PRG}. A dry "
                "run must not mutate the tree: -n/-q/-t answer 'what would "
                "this do?' and are the idiom shell completion uses."
            )
            assert farm.sha() == prg_sha, (
                f"`make {shown}` rewrote {PRG}"
            )
            surviving = farm.mtimes()
            lost = sorted(set(objs) - set(surviving))
            assert not lost, (
                f"`make {shown}` with a changed flag set deleted "
                f"{len(lost)} object(s), e.g. {lost[:3]}"
            )
            assert farm.path(STAMP).read_text() == stamp, (
                f"`make {shown}` rewrote {STAMP} to a flag set that was never "
                "built. The next real build with the ORIGINAL flags would "
                "then see a matching stamp and skip the invalidation it "
                "needs — a mixed link produced by a dry run."
            )

        # And the tree is still genuinely usable: a real rebuild of the
        # baseline flags must be a no-op, not a full rebuild — with and
        # without `-e`, which the rows above route through.
        # Compared over the baseline's objects: `-t` creates (touches) any
        # object the comb flag set has and UCI does not (the cold bank's
        # cold_bank.o), which no UCI link reads and the next real comb
        # build's invalidation deletes. That is make's -t, not a rebuild.
        for opts in ((), ("-e",)):
            proc = farm.make(*UCI, opts=list(opts))
            after = farm.mtimes()
            assert {k: after.get(k) for k in objs} == objs, (
                f"after the dry runs, a real `make {' '.join(opts)}` of the "
                "SAME flags re-assembled objects:\n" + proc.stdout
            )
            assert farm.sha() == prg_sha


def test_an_unrelated_option_does_not_suppress_invalidation():
    """The other half of #174, and the one that bit: a REAL build must invalidate.

    The dry-run guard has to answer "is this -n/-q/-t?" and it has exactly
    two ways to be wrong. The destructive direction (a dry run that deletes)
    is what #174 reported and what the test above pins. THIS pins the
    dangerous direction: a real build misread as a dry run skips the
    invalidation, and the result is precisely the mixed link build/flags.stamp
    exists to prevent — same PRG size, different hash, exit 0, no diagnostic.

    The trap is that `$(firstword $(MAKEFLAGS))` is NOT reliably the
    single-letter option bundle. GNU make 3.81 puts long options in their own
    words, and the letters can land LAST and dash-prefixed:

        make                           MAKEFLAGS=[]
        make -n                        MAKEFLAGS=[n]
        make --no-print-directory      MAKEFLAGS=[ --no-print-directory]
        make -n --no-print-directory   MAKEFLAGS=[ --no-print-directory -n]

    `--no-print-directory` contains an `n` AND a `t`, and
    `--warn-undefined-variables` contains an `n` — so a guard that searches
    the first word classifies both as dry runs and lets a real build through
    with no invalidation. Neither option is exotic; either can also arrive
    from the environment, a parent make, or an IDE.

    Two probes, in increasing cost:

      * a real invocation with an extra option word must still delete the
        other backend's objects and PRG at parse time, and
      * a real profile flip with an extra option word must still produce
        exactly the `make clean` image — the end-to-end statement, and the
        one that catches a guard that merely warns without acting.
    """
    _require_toolchain()
    # Cheap probe: real build, links nothing (the goal is already up to
    # date once the parse-time block has written it), two common long
    # options plus one that shares no letters with n/q/t.
    for env, opts in REAL_BUILD_INVOCATIONS:
        opt = " ".join([f"{k}='{v}'" for k, v in env.items()] + list(opts))
        with Farm() as farm:
            farm.make(*UCI)
            assert farm.exists(PRG)
            farm.make("BACKEND=ip65", STAMP, opts=list(opts), env=env,
                      check=False)
            assert not farm.exists(PRG), (
                f"`make {opt} BACKEND=ip65` did NOT invalidate. It is a real "
                "build, not a dry run, so the parse-time block must have "
                "deleted the UCI PRG — every rig loads that path by name."
            )
            assert not farm.exists("build/tls13.o"), (
                f"`make {opt} BACKEND=ip65` left UCI-flavoured objects in "
                "place; the next ip65 link would reuse them (mixed link)."
            )

    # The end-to-end statement, on the option that carries both an `n` and
    # a `t`: the image a real build produces must not depend on whether an
    # unrelated option was typed.
    comb = ("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1")
    oracle = _clean_build_sha(*comb)
    with Farm() as farm:
        farm.make(*UCI)
        onchip = farm.sha()
        farm.make("--no-print-directory", *comb)
        flipped = farm.sha()
        # And through the environment under -e, back to onchip.
        farm.make(*UCI, opts=["-e"],
                  env={"MAKEFLAGS": "--no-print-directory"})
        assert farm.sha() == onchip, (
            "MIXED LINK: `MAKEFLAGS=--no-print-directory make -e` flipping "
            "comb -> onchip did not reproduce the onchip image."
        )
    assert onchip != oracle, "comb and onchip images are identical — vacuous"
    assert flipped == oracle, (
        "MIXED LINK: `make --no-print-directory` with changed flags produced\n"
        f"  {flipped}\nbut a clean build of the same flags produces\n"
        f"  {oracle}\n"
        "An unrelated long option was misread as -n/-q/-t, so the parse-time "
        "invalidation never ran and the link reused the previous profile's "
        "objects. Same size, different hash, exit 0 — the failure mode "
        "CLAUDE.md says only a sha256 catches."
    )


def test_hand_set_makeflags_is_refused_without_touching_the_tree():
    """A command-line MAKEFLAGS=/MFLAGS= is refused at parse time (#174).

    The guard reads $(MFLAGS), make's own record of its options. A
    command-line `MAKEFLAGS=--dry-run` IS a dry run — make decodes it after
    reading the makefiles, so no recipe runs — but at parse time MFLAGS
    does not show it yet, and a command-line `MFLAGS=` is text make never
    parsed. Either would let the guard take the wrong path, so the makefile
    refuses both before any stamp block runs. The refusal must itself be
    side-effect-free: exit non-zero, tree untouched.
    """
    _require_toolchain()
    comb = ("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1")
    with Farm() as farm:
        farm.make(*UCI)
        prg_sha = farm.sha()
        objs = farm.mtimes()
        for assign in ("MAKEFLAGS=--dry-run", "MAKEFLAGS=", "MFLAGS=",
                       "MFLAGS=-n"):
            for opts in ((), ("-n",)):
                proc = farm.make(*comb, assign, opts=list(opts), check=False)
                shown = " ".join(list(opts) + [assign])
                assert proc.returncode != 0, (
                    f"`make {shown}` was accepted; the dry-run guard cannot "
                    "see options passed that way:\n" + proc.stdout
                )
                assert "assigned by hand" in proc.stdout, proc.stdout
                assert farm.exists(PRG) and farm.sha() == prg_sha, (
                    f"`make {shown}` touched {PRG}"
                )
                assert farm.mtimes() == objs, (
                    f"`make {shown}` touched the objects"
                )


class CfgFarm(Farm):
    """A Farm whose cfg/ is a private COPY, so a test may edit a linker cfg."""

    def __init__(self):
        super().__init__()
        os.unlink(self.dir / "cfg")
        shutil.copytree(REPO / "cfg", self.dir / "cfg")

    def append_comment(self, rel):
        """A comment-only edit: the cfg's text changes, the link's bytes do not."""
        with open(self.path(rel), "a") as fh:
            fh.write("\n# edited by test_build_flags_stamp\n")


# Every cfg a build can select (Makefile: CFG, and the two variants it swaps
# in), each with the flags that select it. ip65 is left out for cost, as in
# FARM_LINKS: it needs the ip65 libs built first.
CFG_PROFILES = (
    ("cfg/c64-https-uci.cfg", ("BACKEND=uci",)),
    ("cfg/c64-https-uci.cfg", UCI),         # onchip alone keeps the base cfg
    ("cfg/c64-https-uci-onchip.cfg", UCI + ("USE_NISTCURVES_ONCHIP_COMB=1",
                                            "COLD_BANK=0")),
    ("cfg/c64-https-uci-onchip-cold.cfg", UCI + ("USE_NISTCURVES_ONCHIP_COMB=1",)),
    ("cfg/c64-https-uci-m3.cfg", ("BACKEND=uci-m3",)),
)


def test_cfg_edit_relinks_every_link_output():
    """Editing only the selected linker cfg must relink, without `make clean`.

    The PRG's prerequisites were objects and archives; the cfg reached the
    stamp only as the NAME in LD65FLAGS, so an edit to its contents left
    `make` at "Nothing to be done" and the old image, map, labels and dbg in
    place. The edit here is comment-only, so the relinked PRG must also be
    byte-identical. The inverse is pinned in the same case: an untouched cfg
    relinks nothing.
    """
    _require_toolchain()
    for cfg, flags in CFG_PROFILES:
        with CfgFarm() as farm:
            farm.make(*flags)
            before = farm.sha()
            old = {o: farm.path(o).stat().st_mtime_ns for o in LINK_OUTPUTS}
            proc = farm.make(*flags)
            assert "ld65 " not in proc.stdout, (
                f"{cfg}: an unchanged cfg relinked:\n" + proc.stdout)
            assert all(farm.path(o).stat().st_mtime_ns == old[o]
                       for o in LINK_OUTPUTS), f"{cfg}: unchanged cfg touched outputs"
            # No sleep, on purpose: a same-second edit is invisible to an
            # mtime prerequisite on make 3.81, so only a content stamp passes.
            farm.append_comment(cfg)
            proc = farm.make(*flags)
            assert "ld65 " in proc.stdout, (
                f"{cfg} edited, {flags}: make did not relink:\n" + proc.stdout)
            for o in LINK_OUTPUTS:
                assert farm.exists(o), f"{cfg}: {o} missing after relink"
                assert farm.path(o).stat().st_mtime_ns != old[o], (
                    f"{cfg}: {o} is stale after a cfg edit")
            assert farm.sha() == before, f"{cfg}: a comment edit moved the PRG"


def test_ip65_cfg_edit_changes_the_stamp_and_clears_outputs():
    """The ip65 cfg, without an ip65 link: the goal is build/flags.stamp."""
    _require_toolchain()
    with CfgFarm() as farm:
        farm.make(*UCI)
        farm.make("BACKEND=ip65", STAMP, check=False)
        line = lambda: [l for l in farm.path(STAMP).read_text().splitlines()
                        if l.startswith("CFG_SHA256=")]
        before = line()
        assert len(before) == 1 and len(before[0]) > len("CFG_SHA256=") + 8, (
            "flags.stamp has no CFG_SHA256 line")
        for o in LINK_OUTPUTS:
            farm.path(o).write_text("planted")
        farm.append_comment("cfg/c64-https-ip65.cfg")
        farm.make("BACKEND=ip65", STAMP, check=False)
        assert line() != before, "ip65 cfg edit did not move CFG_SHA256"
        for o in LINK_OUTPUTS:
            assert not farm.exists(o), f"{o} survived an ip65 cfg edit"


BLOB = "ip65-build/ip65-c64.bin"
BLOB_STAMP = "ip65-build/ip65-c64.stamp"
IP65_LIBS = ("ip65/ip65/ip65_tcp.lib", "ip65/drivers/ip65_c64.lib")
IP65 = ("BACKEND=ip65", "USE_NISTCURVES_ONCHIP=1")


class Ip65Farm(Farm):
    """A Farm with PRIVATE copies of ip65/ and ip65-build/, so a test may
    touch a lib or edit the blob's cfg without disturbing the checkout.
    Libs come from the checkout when built there, else from `make ip65-libs`
    run inside the copy."""

    def __init__(self, state="as-is"):
        """state: "as-is" keeps whatever the checkout's ip65-build/ holds;
        "blob-no-stamps" and "no-blob-no-stamps" model a fresh clone and a
        pre-#309 tree, so no case may depend on checkout state."""
        super().__init__()
        d = self.dir / "ip65-build"
        if state != "as-is":
            for p in d.glob("*.stamp"):
                p.unlink()
        if state == "no-blob-no-stamps":
            (d / "ip65-c64.bin").unlink(missing_ok=True)
        os.unlink(self.dir / "ip65")
        shutil.copytree(REPO / "ip65", self.dir / "ip65", symlinks=True)
        if not all(self.exists(r) for r in IP65_LIBS):
            self.make("ip65-libs", check=False)
        assert all(self.exists(r) for r in IP65_LIBS), "ip65 libs would not build"

    def blob_build(self, **kw):
        return self.make("BACKEND=ip65", "ip65-blob", **kw)

    def blob_mtime(self):
        return self.path(BLOB).stat().st_mtime_ns

    def edit_same_second(self, rel, text):
        """Append to an input, then pin its mtime to the blob's: only a
        CONTENT check can see the edit."""
        blob_ns = self.blob_mtime()
        with open(self.path(rel), "a") as fh:
            fh.write(text)
        os.utime(self.path(rel), ns=(blob_ns, blob_ns))


def test_ip65_blob_tracks_its_libs_cfg_and_stub():
    """#309: the blob's ld65 line links two archives and a cfg; none of them
    was a prerequisite (or, for the cfg, tracked by anything but mtime)."""
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.blob_build()
        good = farm.sha(BLOB)
        assert farm.exists(BLOB_STAMP)

        # unchanged: nothing runs
        old = farm.blob_mtime()
        proc = farm.blob_build()
        assert "ld65 " not in proc.stdout and farm.blob_mtime() == old, (
            "an unchanged blob relinked:\n" + proc.stdout)

        # each lib, touched (content unchanged): the mtime prerequisite
        for lib in IP65_LIBS:
            orig = farm.path(lib).stat().st_mtime_ns
            newer = farm.blob_mtime() + 2_000_000_000   # unambiguously newer
            os.utime(farm.path(lib), ns=(newer, newer))
            proc = farm.blob_build()
            assert "ld65 " in proc.stdout, f"touching {lib} did not relink the blob"
            assert farm.sha(BLOB) == good
            # put it back in the past, or every later step relinks on the
            # lib's future mtime and the cases below prove nothing
            os.utime(farm.path(lib), ns=(orig, orig))

        # same-second content edits of the cfg and of the stub
        for rel, text in (("ip65-build/ip65.cfg", "\n# same-second edit\n"),
                          ("ip65-build/ip65_stub.s", "\n; same-second edit\n")):
            farm.edit_same_second(rel, text)
            proc = farm.blob_build()
            assert "ld65 " in proc.stdout, (
                f"a same-second edit of {rel} did not relink the blob:\n"
                + proc.stdout)
            assert farm.sha(BLOB) == good, "a comment edit moved the blob"

        # a stale blob must take the PRG with it, with no clean
        farm.make(*IP65)
        prg = farm.sha()
        out = {o: farm.path(o).stat().st_mtime_ns for o in LINK_OUTPUTS}
        farm.edit_same_second("ip65-build/ip65.cfg", "\n# again\n")
        proc = farm.make(*IP65)
        assert "ld65 " in proc.stdout and farm.sha() == prg
        assert all(farm.path(o).stat().st_mtime_ns != out[o] for o in LINK_OUTPUTS), (
            "a rebuilt blob left a stale link output")


def test_ip65_blob_dry_run_writes_nothing():
    """#174: -n/-q/-t on a stale blob compare and report, and mutate nothing."""
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.blob_build()
        farm.edit_same_second("ip65-build/ip65.cfg", "\n# stale\n")

        def snap():
            return {str(p.relative_to(farm.dir)): (p.stat().st_mtime_ns,
                                                   p.read_bytes())
                    for p in farm.path("ip65-build").rglob("*") if p.is_file()}
        before = snap()
        for opt in ("-n", "-q", "-t"):
            proc = farm.make("BACKEND=ip65", "ip65-blob", opts=(opt,), check=False)
            assert snap() == before, f"`make {opt} ip65-blob` mutated ip65-build/"
        proc = farm.make("BACKEND=ip65", "ip65-blob", opts=("-n",))
        assert "DRY RUN" in proc.stdout and BLOB_STAMP in proc.stdout, (
            "a dry run on a stale blob did not report it:\n" + proc.stdout)


def test_ip65_blob_missing_lib_fails_by_name():
    """A fresh clone without `make ip65-libs` fails loudly, naming the file
    and the fix, before any link is attempted."""
    _require_toolchain()
    with Ip65Farm() as farm:
        for lib in IP65_LIBS:
            farm.path(lib).rename(farm.path(lib + ".held"))
            proc = farm.blob_build(check=False)
            assert proc.returncode != 0, f"missing {lib} did not fail the build"
            assert lib in proc.stdout and "make ip65-libs" in proc.stdout, (
                f"missing {lib}: failure does not name it and the fix:\n"
                + proc.stdout)
            assert "ld65" not in proc.stdout, "got as far as the link"
            farm.path(lib + ".held").rename(farm.path(lib))


def test_uci_build_does_not_need_the_ip65_tree():
    """BACKEND=uci neither reads nor requires ip65/ or ip65-build/."""
    _require_toolchain()
    with Farm() as farm:
        for name in ("ip65",):
            os.unlink(farm.dir / name)
        shutil.rmtree(farm.dir / "ip65-build")
        farm.make(*UCI)
        assert farm.exists(PRG)
        assert not farm.exists("ip65-build")
        # the ip65 block must not run for another backend at all: if it did,
        # its stamp could never be written here and every build would
        # invalidate the link outputs
        proc = farm.make(*UCI)
        assert "ld65 " not in proc.stdout, (
            "a second UCI build relinked: the ip65 blob block ran:\n" + proc.stdout)


def _write_text_keep_mtime(path, text):
    ns = path.stat().st_mtime_ns
    path.write_text(text)
    os.utime(path, ns=(ns, ns))


def test_ip65_blob_lib_content_change_with_restored_mtime_relinks():
    """The content digest must cover the libs, not just their mtimes."""
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.blob_build()
        lib = farm.path(IP65_LIBS[0])
        ns = lib.stat().st_mtime_ns
        with open(lib, "ab") as fh:
            fh.write(b"\0")
        os.utime(lib, ns=(ns, ns))
        proc = farm.blob_build(check=False)
        assert "ld65 " in proc.stdout, (
            "a lib's content changed (mtime restored) and the blob did not "
            "relink:\n" + proc.stdout)


def test_ip65_blob_toolchain_change_relinks():
    """TOOLCHAIN_ID is part of the blob digest (ca65 is not a prerequisite)."""
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.blob_build()
        other = farm.dir / "ca65-other"
        shutil.copy(shutil.which("ca65"), other)
        proc = farm.make("BACKEND=ip65", "ip65-blob", f"CA65={other}")
        assert "ld65 " in proc.stdout, (
            "a different assembler left the blob alone:\n" + proc.stdout)
        # the command-line form: 3.81's $(shell) does not see it in its
        # environment, so the digest must read the make variable
        proc = farm.make("BACKEND=ip65", "ip65-blob", f"CA65={other}",
                         f"LD65_LIB={farm.dir / 'nolib2'}")
        assert "ld65 " in proc.stdout, (
            "a command-line LD65_LIB was not seen:\n" + proc.stdout)
        # ld65's search-path environment can swap c64.lib without moving
        # TOOLCHAIN_ID; it rides in the digest
        proc = farm.make("BACKEND=ip65", "ip65-blob", f"CA65={other}",
                         env={"LD65_LIB": str(farm.dir / "nolib")})
        assert "ld65 " in proc.stdout, (
            "LD65_LIB changed and the blob was left alone:\n" + proc.stdout)


def test_ip65_blob_content_change_moves_the_prg():
    """A changed stub must reach the PRG even when the object looks fresh.

    The object's mtime is pushed into the future, so only the parse-time
    deletion of build/net/ip65/ip65_blob.o can make the PRG pick it up.
    """
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.make(*IP65)
        prg = farm.sha()
        obj = farm.path("build/net/ip65/ip65_blob.o")
        fut = obj.stat().st_mtime_ns + 60_000_000_000
        os.utime(obj, ns=(fut, fut))
        stub = farm.path("ip65-build/ip65_stub.s")
        orig = stub.read_text()
        assert orig.count("  rts     ; no standalone entry point") == 1
        _write_text_keep_mtime(stub, orig.replace(
            "  rts     ; no standalone entry point",
            "  nop     ; no standalone entry point"))
        farm.make(*IP65)
        assert farm.sha() != prg, "a changed blob did not reach the PRG"
        fut = farm.path("build/net/ip65/ip65_blob.o").stat().st_mtime_ns + 60_000_000_000
        os.utime(farm.path("build/net/ip65/ip65_blob.o"), ns=(fut, fut))
        _write_text_keep_mtime(stub, orig)
        farm.make(*IP65)
        assert farm.sha() == prg, "restoring the stub did not restore the PRG"


def _check_first_flip(farm):
    """The FIRST same-second flip after a build must reach the PRG (no
    warm-up parse), and restoring the byte must restore the PRG."""
    farm.make(*IP65)
    prg = farm.sha()
    blob = farm.path(BLOB)
    data = blob.read_bytes()
    ns = blob.stat().st_mtime_ns
    for new in (bytes([data[100] ^ 0xFF]), bytes([data[100]])):
        blob.write_bytes(data[:100] + new + data[101:])
        os.utime(blob, ns=(ns, ns))
        farm.make(*IP65)
        if new == bytes([data[100]]):
            assert farm.sha() == prg, "restoring the byte did not restore the PRG"
        else:
            assert farm.sha() != prg, "a flipped blob byte left a stale PRG"


def test_ip65_blob_byte_flip_reaches_the_prg():
    """The documented provenance test: flip one byte of the blob, same second
    (mtime restored). blob -> ip65_blob.o is an mtime edge; the blob's own
    content stamp, written by the blob rule, must close it."""
    _require_toolchain()
    with Ip65Farm("no-blob-no-stamps") as farm:
        _check_first_flip(farm)


def test_ip65_deleted_blob_after_a_flip_recovers_the_prg():
    """flip -> delete the blob -> rebuild: the regenerated (good) blob must
    take the flipped PRG with it, even when the object and PRG look newer
    than the new blob (same second on make 3.81)."""
    _require_toolchain()
    with Ip65Farm("no-blob-no-stamps") as farm:
        farm.make(*IP65)
        good = farm.sha()
        blob = farm.path(BLOB)
        data, ns = blob.read_bytes(), blob.stat().st_mtime_ns
        blob.write_bytes(data[:100] + bytes([data[100] ^ 0xFF]) + data[101:])
        os.utime(blob, ns=(ns, ns))
        farm.make(*IP65)
        assert farm.sha() != good
        blob.unlink()
        for rel in ("build/net/ip65/ip65_blob.o", PRG):
            p = farm.path(rel)
            fut = p.stat().st_mtime_ns + 60_000_000_000
            os.utime(p, ns=(fut, fut))
        farm.make(*IP65)
        assert farm.sha() == good, "a deleted blob left the flipped PRG permanent"


def test_ip65_cases_do_not_depend_on_checkout_state():
    """A fresh clone (no blob, no stamps) and a pre-stamp tree (blob, no
    stamps) must behave exactly like the checkout the suite runs in."""
    _require_toolchain()
    for state in ("no-blob-no-stamps", "blob-no-stamps"):
        with Ip65Farm(state) as farm:
            _check_first_flip(farm)
        with Ip65Farm(state) as farm:
            _check_skip_goals(farm)


def test_ip65_parse_after_a_build_invalidates_nothing():
    """Exactly one invalidation per input change: the parse right after a
    build (input change, or a stampless tree) deletes nothing."""
    _require_toolchain()
    for state in ("as-is", "blob-no-stamps"):
        with Ip65Farm(state) as farm:
            farm.make(*IP65)
            farm.edit_same_second("ip65-build/ip65.cfg", "\n# once\n")
            farm.make(*IP65)
            before = {o: farm.path(o).stat().st_mtime_ns for o in LINK_OUTPUTS}
            blob_ns = farm.blob_mtime()
            proc = farm.make(*IP65)
            assert "ld65 " not in proc.stdout and "ca65 " not in proc.stdout, (
                f"{state}: a parse after a build invalidated again:\n" + proc.stdout)
            assert farm.blob_mtime() == blob_ns
            assert before == {o: farm.path(o).stat().st_mtime_ns for o in LINK_OUTPUTS}
            # a stamp lost after a build is recorded, not treated as a change
            farm.path("ip65-build/ip65-c64-bin.stamp").unlink()
            proc = farm.make(*IP65)
            assert "ld65 " not in proc.stdout and "ca65 " not in proc.stdout, (
                f"{state}: an absent bin stamp invalidated:\n" + proc.stdout)
            assert farm.exists("ip65-build/ip65-c64-bin.stamp")


def test_ip65_maintenance_goal_keeps_the_prg():
    """#220 for ip65: `make BACKEND=ip65 ip65-blob` after a blob-input change
    rebuilds the blob and deletes only the blob and its object."""
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.make(*IP65)
        farm.edit_same_second("ip65-build/ip65.cfg", "\n# maintenance\n")
        farm.make("BACKEND=ip65", "ip65-blob")
        gone = [o for o in LINK_OUTPUTS if not farm.exists(o)]
        assert not gone, f"a maintenance goal deleted {gone}"


def _check_skip_goals(farm):
    for goal in ("clean", "ip65-libs"):
        farm.blob_build()
        farm.edit_same_second("ip65-build/ip65.cfg", "\n# skip %s\n" % goal)
        stamps = {p: farm.path(p).read_bytes()
                  for p in (BLOB_STAMP, "ip65-build/ip65-c64-bin.stamp")}
        farm.make("BACKEND=ip65", goal)
        assert farm.exists(BLOB), f"`make {goal}` deleted the blob"
        for p, b in stamps.items():
            assert farm.path(p).read_bytes() == b, f"`make {goal}` rewrote {p}"


def test_ip65_skip_goals_do_not_run_the_blob_block():
    """`clean` and `ip65-libs` must not compare, write or delete (#220)."""
    _require_toolchain()
    for _ in range(2):
        with Ip65Farm() as farm:
            _check_skip_goals(farm)


def test_ip65_blob_dry_run_message_matches_the_real_branch():
    """The -n warning must say what the real branch would delete."""
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.make(*IP65)
        farm.edit_same_second("ip65-build/ip65.cfg", "\n# dry\n")

        def line(*goals):
            out = farm.make(*goals, opts=("-n",)).stdout
            return [l for l in out.splitlines()
                    if "would delete ip65-build/ip65-c64.bin" in l]
        maint = line("BACKEND=ip65", "ip65-blob")
        assert maint and "ip65_blob.o" in maint[0] and PRG not in maint[0], maint
        real = line(*IP65)
        assert real and "ip65_blob.o" in real[0] and PRG in real[0], real

        # the blob-bytes stamp has its own warning
        farm.blob_build()
        farm.make(*IP65)
        blob = farm.path(BLOB)
        data, ns = blob.read_bytes(), blob.stat().st_mtime_ns
        blob.write_bytes(data[:100] + bytes([data[100] ^ 0xFF]) + data[101:])
        os.utime(blob, ns=(ns, ns))
        out = farm.make(*IP65, opts=("-n",)).stdout
        assert "differs from ip65-build/ip65-c64-bin.stamp" in out, out


def test_ip65_dry_run_t_on_a_libless_tree_creates_no_libs():
    """`make -t` must not turn a missing lib into an empty file (a file
    target with no recipe): it fails by name, creates nothing, and a later
    `make ip65-libs` + build still works."""
    _require_toolchain()
    with Ip65Farm() as farm:
        farm.blob_build()
        for lib in IP65_LIBS:
            farm.path(lib).unlink()
        for goal in (("ip65-blob",), (BLOB,)):
            proc = farm.make("BACKEND=ip65", *goal, opts=("-t",), check=False)
            assert proc.returncode != 0, "`make -t` with missing libs succeeded"
            assert "make ip65-libs" in proc.stdout
            for lib in IP65_LIBS:
                assert not farm.exists(lib), f"`make -t` created {lib}"
        farm.make("ip65-libs")
        farm.blob_build()
        assert all(farm.exists(r) for r in IP65_LIBS)


def test_unchanged_flags_rebuild_nothing():
    """The inverse property: the stamp must not make every build a rebuild."""
    _require_toolchain()
    with Farm() as farm:
        farm.make(*UCI)
        before_objs = farm.mtimes()
        before_prg = farm.path(PRG).stat().st_mtime_ns
        proc = farm.make(*UCI)
        assert farm.mtimes() == before_objs, (
            "a no-op rebuild re-assembled objects:\n" + proc.stdout
        )
        assert farm.path(PRG).stat().st_mtime_ns == before_prg, (
            "a no-op rebuild re-linked the PRG:\n" + proc.stdout
        )
        assert "ca65 " not in proc.stdout and "ld65 " not in proc.stdout, (
            "a no-op rebuild ran the toolchain:\n" + proc.stdout
        )


class SrcFarm(Farm):
    """A Farm whose src/ is a private COPY, so a test may edit an .inc."""

    def __init__(self):
        super().__init__()
        os.unlink(self.dir / "src")
        shutil.copytree(REPO / "src", self.dir / "src")

    def edit_inc(self, rel, old, new):
        """Edit one .inc at least a second after the last build.

        GNU Make 3.81 (macOS) compares mtimes to the second, so an edit, or
        the objects it rebuilds, in the same second as the previous build
        and link would read as not newer. A person's edit lands later; the
        wait says so. Same-second edits are make's caveat, not this fix's.
        """
        time.sleep(1.1)
        inc = self.path(rel)
        text = inc.read_text()
        assert text.count(old) == 1, f"{old!r} not found once in {rel}"
        inc.write_text(text.replace(old, new))

    def includers(self, name):
        """Objects built here whose source names *name* in an .include."""
        out = set()
        for obj in self.mtimes():
            src = (self.path("src") / Path(obj).relative_to("build")).with_suffix(".s")
            if not src.exists():
                continue                # an archive's staging object
            for line in src.read_text().splitlines():
                code = line.split(";", 1)[0]
                if ".include" in code and f'"{name}"' in code:
                    out.add(obj)
        return out


def test_inc_edit_rebuilds_its_includers_and_matches_a_clean_build():
    """An .inc edit must reach the PRG without `make clean`.

    build/%.o used to depend on its .s alone, so editing an .inc left every
    object that includes it stale and `make` relinked nothing: a plausible
    PRG, exit 0, the OLD constant inside. ca65's --create-dep files
    (build/%.d, -included by the Makefile) are what carry the edge now.
    Pinned at the grain too: exactly the includers rebuild, nothing else.
    """
    _require_toolchain()
    inc = "src/net/uci/uci_regs.inc"
    old, new = "UCI_FENCE_INNER = 217", "UCI_FENCE_INNER = 216"
    with SrcFarm() as farm:
        farm.edit_inc(inc, old, new)
        farm.make(*UCI)
        oracle = farm.sha()
    with SrcFarm() as farm:
        farm.make(*UCI)
        before_sha = farm.sha()
        before = farm.mtimes()
        expect = farm.includers("uci_regs.inc")
        farm.edit_inc(inc, old, new)
        proc = farm.make(*UCI)
        after = farm.mtimes()
        after_sha = farm.sha()

    rebuilt = {k for k in after if after[k] != before.get(k)}
    assert before_sha != oracle, (
        "the uci_regs.inc edit does not change the PRG even from a clean "
        "tree -- this test's oracle is vacuous; re-aim the edit")
    assert expect, "no object includes uci_regs.inc -- re-aim the edit"
    assert rebuilt == expect, (
        f"editing {inc} rebuilt {sorted(rebuilt)}, expected exactly its "
        f"includers {sorted(expect)}:\n{proc.stdout}")
    assert after_sha == oracle, (
        f"STALE OBJECTS: after editing {inc}, `make` produced\n  {after_sha}"
        f"\nbut a clean build of the edited tree produces\n  {oracle}\n"
        + ("i.e. nothing was rebuilt. " if after_sha == before_sha else "")
        + "build/%.d should name the .inc as a prerequisite.")


def test_https_host_change_is_still_incremental():
    """Issue #128's ergonomic must survive: no clean, and no full rebuild.

    HTTPS_HOST / HTTPS_PATH are deliberately NOT in the stamp — they reach
    ca65 through build/https_host.inc, which is content-compared with a
    finer grain (boot.o + http.o, not the whole tree). Certificate pinning
    (#155) is about to depend on that staying cheap.
    """
    _require_toolchain()
    retarget = UCI + ("HTTPS_HOST=en.wikipedia.org",)
    oracle = _clean_build_sha(*retarget)
    with Farm() as farm:
        farm.make(*UCI)
        before = farm.mtimes()
        farm.make(*retarget)
        assert farm.sha() == oracle, (
            "HTTPS_HOST= without `make clean` no longer matches a clean "
            "build — issue #128's exemption has regressed."
        )
        after = farm.mtimes()
        rebuilt = {k for k in after if after[k] != before.get(k)}
        assert rebuilt, "nothing rebuilt at all for a new HTTPS_HOST"
        unexpected = rebuilt - TARGET_INC_GRAIN
        assert not unexpected, (
            f"HTTPS_HOST= now forces a wider rebuild than {sorted(TARGET_INC_GRAIN)}: "
            f"{sorted(unexpected)}. The target strings must stay out of "
            "build/flags.stamp, or #128's no-clean ergonomic costs a full "
            "rebuild every time (and #155's pin values will too)."
        )


def test_pin_change_is_incremental():
    """#155: re-pinning after a key rotation must not need `make clean`.

    The pin's presence moves CA65FLAGS (-D HTTPS_PIN_SPKI=1, stamped), but a
    NEW VALUE travels only in build/https_host.inc. So pin A -> pin B must
    rebuild within the target-include grain and land on exactly the PRG a
    clean pin-B build produces — the check that the new bytes, not the old
    ones, are in the image.
    """
    _require_toolchain()
    pin_a = "HTTPS_PIN_SPKI_SHA256=" + "a5" * 32
    pin_b = "HTTPS_PIN_SPKI_SHA256=" + "5a" * 32
    oracle = _clean_build_sha(*UCI, pin_b)
    with Farm() as farm:
        farm.make(*UCI, pin_a)
        sha_a = farm.sha()
        before = farm.mtimes()
        farm.make(*UCI, pin_b)
        assert farm.sha() == oracle, (
            "a pin change without `make clean` does not match a clean build — "
            "the old pin is still in the image"
        )
        assert sha_a != oracle, "pin A and pin B built the same PRG — vacuous"
        after = farm.mtimes()
        rebuilt = {k for k in after if after[k] != before.get(k)}
        assert "build/cert_pin.o" in rebuilt, "cert_pin.o was not rebuilt"
        unexpected = rebuilt - TARGET_INC_GRAIN
        assert not unexpected, (
            f"a pin change rebuilt more than {sorted(TARGET_INC_GRAIN)}: "
            f"{sorted(unexpected)}"
        )


def test_stamp_records_the_whole_command_line():
    """The stamp must be readable evidence, not an opaque digest.

    A hash would work mechanically, but the file's second job is
    answering "what was this PRG built with?" at a glance, which is the
    question the incident started from.
    """
    _require_toolchain()
    with Farm() as farm:
        farm.make(*UCI)
        text = farm.path(STAMP).read_text()
        farm.make("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1")
        comb_text = farm.path(STAMP).read_text()
        farm.make("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1", "COLD_BANK=0")
        resident_text = farm.path(STAMP).read_text()
    for expected in ("BACKEND=uci",
                     "-D USE_NISTCURVES_ONCHIP=1",
                     "-D X509_VERIFY_NAME=1",           # backend-derived
                     "-I src/net/uci",                  # backend-derived
                     "-C cfg/c64-https-uci.cfg",        # the ld65 config
                     "nistcurves-p256-onchip.a"):       # the archive choice
        assert expected in text, (
            f"build/flags.stamp does not record {expected!r}:\n{text}"
        )
    # The cfg is a derived input, not a knob anyone types: comb retargets
    # $(CFG) to the -onchip-cold variant (the cold-code bank), COLD_BANK=0
    # back to -onchip, and that swap must show up too.
    assert ("-C cfg/c64-https-uci-onchip-cold.cfg" in comb_text
            and "-D COLD_BANK=1" in comb_text), (
        f"build/flags.stamp does not record the comb cfg:\n{comb_text}"
    )
    assert ("-C cfg/c64-https-uci-onchip.cfg" in resident_text
            and "COLD_BANK" not in resident_text), (
        f"build/flags.stamp does not record COLD_BANK=0's cfg:\n{resident_text}"
    )


LOCALES = ("C", "en_US.UTF-8", "cs_CZ.UTF-8")

CERTIFIES_LOCALE = "whether the PRG's bytes depend on the build locale (#301)"
CERTIFIES_STALE_ORDER = ("whether a tree linked in another object order is "
                         "rebuilt (#301)")


def _wildcard_orders(farm, pattern):
    """`$(wildcard pattern)` as the make in use returns it, per locale."""
    probe = farm.path("probe.mk")
    probe.write_text(f"all:\n\t@echo $(wildcard {pattern})\n")
    orders = {}
    for loc in LOCALES:
        proc = subprocess.run(
            ["make", "-f", str(probe)], cwd=farm.dir, text=True,
            env=dict(os.environ, LC_ALL=loc),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert proc.returncode == 0, proc.stdout
        orders[loc] = proc.stdout.split()
    return orders


def test_prg_is_independent_of_the_build_locale():
    """The PRG must not depend on LANG/LC_ALL (#301).

    GNU make 3.81 returns `$(wildcard)` hits in the locale's collation order
    and the wildcard lists are the ld65 object order. Unsorted, each of the
    three wildcard-built products had three PRG hashes (C, en_US, cs_CZ).
    `$(sort)` is byte order, so link order -- and the bytes -- are locale-free.

    Each sorted list is pinned only if some locale pair really reorders it,
    so the probe checks that per list and refuses a vacuous comparison:
      * src/*.s        en_US ignores the underscore (tls_record_io before
                       tls13); C does not.
      * src/crypto/*.s cs_CZ sorts "ch" after "h" (chacha20 after hmac_drbg);
                       C and en_US AGREE here, so two locales are not enough.
      * src/crypto/shared/*.s  no locale tried reorders it (crypto_init,
                       mul_tables), so its `$(sort)` is defensive and NOT
                       pinned by this test.
    """
    _require_toolchain()
    with Farm() as farm:
        for pattern in ("src/*.s", "src/crypto/*.s"):
            orders = _wildcard_orders(farm, pattern)
            assert len({tuple(sorted(o)) for o in orders.values()}) == 1, (
                f"{pattern}: locales disagree on the file SET: {orders}")
            if len({tuple(o) for o in orders.values()}) == 1:
                require(False,
                        f"no locale in {LOCALES} reorders $(wildcard "
                        f"{pattern}) under this make; the cross-locale "
                        "comparison would be vacuous for that list",
                        executed=0, total=1, certifies=CERTIFIES_LOCALE,
                        opt_out_env="C64_ALLOW_SKIP")
    shas = {}
    for loc in LOCALES:
        with Farm() as farm:
            farm.make(*UCI, env={"LC_ALL": loc})
            shas[loc] = farm.sha()
    assert len(set(shas.values())) == 1, (
        f"PRG depends on the build locale: {shas}")


def test_stale_link_order_is_rebuilt_to_the_clean_hash():
    """A tree linked in another object order must relink, not stay stale (#301).

    The object list is a link input that was in neither flags.stamp nor any
    prerequisite, so a build/ left by an unsorted Makefile answered "Nothing
    to be done" and kept the old PRG. The stale tree here is built by a
    private copy of the Makefile with the TOP_SRCS `$(sort)` removed, under a
    locale that reorders it, then rebuilt with the real Makefile.
    """
    _require_toolchain()
    loc = {"LC_ALL": "en_US.UTF-8"}
    with Farm() as clean:
        clean.make(*UCI, env=loc)
        oracle = clean.sha()
    with Farm() as farm:
        real = REPO / "Makefile"
        text = real.read_text()
        old = "TOP_SRCS    := $(sort $(wildcard src/*.s))"
        assert old in text, "TOP_SRCS line moved; re-aim this test"
        os.unlink(farm.path("Makefile"))
        farm.path("Makefile").write_text(
            text.replace(old, "TOP_SRCS    := $(wildcard src/*.s)"))
        farm.make(*UCI, env=loc)
        stale = farm.sha()
        os.unlink(farm.path("Makefile"))
        os.symlink(real, farm.path("Makefile"))
        farm.make(*UCI, env=loc)
        if stale == oracle:
            require(False,
                    "this make/locale does not reorder $(wildcard src/*.s); "
                    "the stale tree is not actually stale, so a relink to the "
                    "clean hash would prove nothing",
                    executed=0, total=1, certifies=CERTIFIES_STALE_ORDER,
                    opt_out_env="C64_ALLOW_SKIP")
        assert farm.sha() == oracle, (
            "a changed object order did not invalidate the tree: PRG "
            f"{farm.sha()} != clean build {oracle}")


def _ip65_build_snapshot():
    d = REPO / "ip65-build"
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(d.iterdir()) if p.is_file()} if d.is_dir() else {}


_REAL_IP65_BUILD_AT_IMPORT = _ip65_build_snapshot()


def test_zz_real_ip65_build_is_untouched_by_the_suite():
    """Every Farm owns a private ip65-build/; the checkout's must be exactly
    as this module found it (the blob was once deleted by a Farm test).
    Named zz so the standalone runner, which sorts, runs it last."""
    assert _ip65_build_snapshot() == _REAL_IP65_BUILD_AT_IMPORT, (
        "the suite changed the real ip65-build/")


def main() -> int:
    print("=== build/flags.stamp ===")
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]

    # The toolchain check is hoisted out of the loop on purpose. Per-test it
    # would report eight identical failures for one missing binary, and the
    # standalone lane wants the "could not run" EXIT CODE (2), which is a
    # thing only a process has -- `require()`'s AssertionError is the right
    # answer for pytest, where the unit of reporting is the test.
    missing = _toolchain_missing()
    if missing:
        return cannot_run(
            f"{missing} not on PATH -- every case here shells out to `make`",
            executed=0,
            total=len(tests),
            certifies=CERTIFIES,
            opt_out_env="C64_ALLOW_SKIP",
        )

    failed = 0
    ran = 0
    skipped = 0
    for name, fn in tests:
        try:
            fn()
        except VoluntarySkip as exc:        # named before Exception
            skipped += 1
            print(f"  SKIP {name}\n       {exc}")
            continue
        except Exception as exc:            # noqa: BLE001 - a crash is a fail
            failed += 1
            print(f"  FAIL {name}\n       {type(exc).__name__}: {exc}")
        else:
            ran += 1
            print(f"  ok   {name}")

    # A run that executed nothing must never print PASSED. Asserted rather
    # than assumed, because the version of this file that #177 reports did
    # print "PASSED: 0 failure(s)" for a run in which zero assertions ran.
    if ran + failed == 0:
        return cannot_run(
            "no test functions were collected from this module",
            executed=0, total=0, certifies=CERTIFIES,
        )

    print(f"\n{'FAILED' if failed else 'PASSED'}: {failed} failure(s) "
          f"({ran}/{len(tests)} executed"
          + (f", {skipped} skipped via C64_ALLOW_SKIP" if skipped else "")
          + ")")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
