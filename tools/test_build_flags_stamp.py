#!/usr/bin/env python3
"""build/flags.stamp — a build-flag change must never survive as a mixed link.

The defect this pins, measured 2026-08-30 on a UCI onchip tree:

    make BACKEND=uci USE_NISTCURVES_ONCHIP=1                    # 1bb5fad9...
    make BACKEND=uci USE_NISTCURVES_ONCHIP=1 HTTPS_SNI=www.foo.bar
                                                                # d1b63508...
    make clean && make ... HTTPS_SNI=www.foo.bar                # a65fff60...

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

`make clean` after any flag change is the documented rule (CLAUDE.md,
"Build"), but a rule that lives only in prose is a rule that gets
forgotten once. build/flags.stamp makes it mechanical: the whole
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
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# What a build reads. `libs` carries the sibling submodules the archive
# wrappers assemble from; `ip65`/`ip65-build` are symlinked for
# completeness but never assembled, because every case here is
# BACKEND=uci — ca65 resolves `.incbin` against the current directory, so
# an ip65 link from anywhere but a real checkout root is not to be
# trusted (CLAUDE.md, "Build"). The BACKEND=ip65 case below never links.
FARM_LINKS = ("src", "cfg", "tools", "libs", "ip65", "ip65-build", "Makefile")

# The reference profile for every case: UCI, onchip. Fastest to build, and
# the profile the 2026-08-30 incident was measured on.
UCI = ("BACKEND=uci", "USE_NISTCURVES_ONCHIP=1")

PRG = "build/c64-https.prg"
STAMP = "build/flags.stamp"


def _toolchain_missing():
    for tool in ("ca65", "ld65"):
        if shutil.which(tool) is None:
            return tool
    return None


class Farm:
    """A disposable tree that builds the repo without writing to it."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="c64-flags-stamp-"))
        for name in FARM_LINKS:
            target = REPO / name
            if target.exists():
                os.symlink(target, self.dir / name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, *flags, dry_run=False, check=True):
        cmd = ["make"] + (["-n"] if dry_run else []) + list(flags)
        proc = subprocess.run(cmd, cwd=self.dir, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if check:
            assert proc.returncode == 0, (
                f"`{' '.join(cmd)}` failed ({proc.returncode}):\n{proc.stdout}"
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


def _clean_build_sha(*flags):
    """The PRG a `make clean` build of these flags produces — the oracle."""
    with Farm() as farm:
        farm.make(*flags)
        return farm.sha()


def test_flag_change_without_clean_matches_a_clean_build():
    """The 2026-08-30 incident: HTTPS_SNI= on a tree built without it.

    `make clean` is the documented remedy and it is absent here on
    purpose — the whole point is what happens when someone forgets it.
    """
    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return
    oracle = _clean_build_sha(*UCI, "HTTPS_SNI=www.foo.bar")
    with Farm() as farm:
        farm.make(*UCI)
        plain = farm.sha()
        farm.make(*UCI, "HTTPS_SNI=www.foo.bar")
        dirty = farm.sha()

    assert plain != oracle, (
        "HTTPS_SNI=www.foo.bar produced the same PRG as no SNI at all, even "
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
    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return
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
    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return
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
    happens during parse, so it is visible here with `make -n`: no recipe
    runs, yet the stale PRG and objects must already be gone.

    This case deliberately does not LINK ip65: ca65 resolves `.incbin`
    against the current directory, so an ip65 build outside a real
    checkout root is untrustworthy (CLAUDE.md, "Build").
    """
    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return
    with Farm() as farm:
        farm.make(*UCI)
        assert farm.exists(PRG)
        farm.make("BACKEND=ip65", dry_run=True, check=False)
        assert not farm.exists(PRG), (
            "a BACKEND flip left the UCI PRG in place. A dry run performs no "
            "link, so whatever `make BACKEND=ip65` did next, "
            "build/c64-https.prg was a UCI image that rigs load by path."
        )
        assert not farm.exists("build/tls13.o"), (
            "a BACKEND flip left UCI-flavoured objects in place; the next "
            "ip65 link would have reused them (mixed link)."
        )


def test_unchanged_flags_rebuild_nothing():
    """The inverse property: the stamp must not make every build a rebuild."""
    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return
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


def test_https_host_change_is_still_incremental():
    """Issue #128's ergonomic must survive: no clean, and no full rebuild.

    HTTPS_HOST / HTTPS_PATH are deliberately NOT in the stamp — they reach
    ca65 through build/https_host.inc, which is content-compared with a
    finer grain (boot.o + http.o, not the whole tree). Certificate pinning
    (#155) is about to depend on that staying cheap.
    """
    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return
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
        unexpected = rebuilt - {"build/boot.o", "build/http.o"}
        assert not unexpected, (
            f"HTTPS_HOST= now forces a wider rebuild than boot.o/http.o: "
            f"{sorted(unexpected)}. The target strings must stay out of "
            "build/flags.stamp, or #128's no-clean ergonomic costs a full "
            "rebuild every time (and #155's pin values will too)."
        )


def test_stamp_records_the_whole_command_line():
    """The stamp must be readable evidence, not an opaque digest.

    A hash would work mechanically, but the file's second job is
    answering "what was this PRG built with?" at a glance, which is the
    question the incident started from.
    """
    missing = _toolchain_missing()
    if missing:
        print(f"SKIP: {missing} not on PATH")
        return
    with Farm() as farm:
        farm.make(*UCI)
        text = farm.path(STAMP).read_text()
        farm.make("BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1")
        comb_text = farm.path(STAMP).read_text()
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
    # $(CFG) to the -onchip variant, and that swap must show up too.
    assert "-C cfg/c64-https-uci-onchip.cfg" in comb_text, (
        f"build/flags.stamp does not record the comb cfg:\n{comb_text}"
    )


def main() -> int:
    print("=== build/flags.stamp ===")
    failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except Exception as exc:            # noqa: BLE001 — a crash is a fail
            failed += 1
            print(f"  FAIL {name}\n       {type(exc).__name__}: {exc}")
        else:
            print(f"  ok   {name}")
    print(f"\n{'FAILED' if failed else 'PASSED'}: {failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
