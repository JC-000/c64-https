#!/usr/bin/env python3
"""test_package_verify.py — regression tests for the release gate's verdict.

No VICE, no builds, no hardware: this exercises the pure logic in
tools/package/verify_release.py that decides whether a run may call itself
verified. Runs in milliseconds.

WHY THIS FILE EXISTS. The gate shipped with a bug where it could pass having
checked nothing: both disk checks iterated `dist/*.d64`, so an empty dist/
produced zero records, zero failures, and the cheerful verdict "0/0 checks
passed / RELEASE ARTIFACTS VERIFIED" with exit 0. A green light over a release
containing no disks at all.

The durable fix has two halves, and both are pinned here:

  * iterate over what MUST exist (derived from the build record), not over
    what happens to be on disk — an empty iteration is then a failed check
    rather than a check nobody ran (test_expected_images_*);
  * never let an empty or partial run reach a reassuring verdict
    (test_verdict_*).

The SKIP_* case is the one to watch: it is where the pressure to just say
VERIFIED will come back, because it is the invocation people actually use
while iterating. It must stay exit 0 (so it remains usable) while never
producing the word VERIFIED.

Usage:  python3 tools/test_package_verify.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "package"))

import verify_release as vr  # noqa: E402

PASSED = 0
FAILED = 0


def check(name: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  [PASS] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}\n         got  {got!r}\n         want {want!r}")


def verdict(results, missing=0, skipped=()):
    """Return (exit_code, joined text) for a set of recorded checks."""
    code, lines = vr.summarize(list(results), missing, list(skipped))
    return code, "\n".join(lines)


OK = ("some check", True, "")
BAD = ("some check", False, "boom")


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def test_verdict_empty_run_is_a_failure() -> None:
    """The original bug, pinned: zero checks must never read as success."""
    print("\n-- an empty run is a failure, not a pass --")
    code, text = verdict([])
    check("exit code is 1", code, 1)
    check("says NOTHING WAS VERIFIED", "NOTHING WAS VERIFIED" in text, True)
    check("never says VERIFIED alone", "RELEASE ARTIFACTS VERIFIED" in text, False)


def test_verdict_empty_run_not_rescued_by_skips() -> None:
    """Skipping every section must not launder an empty run into PARTIAL.

    This is the ordering that matters most: the skip branch is friendlier and
    exits 0, so if it were checked first, `SKIP_REBUILD=1 SKIP_VICE=1
    SKIP_LISTENER=1` on an empty dist/ would report a cheerful partial pass —
    which is exactly the shape of the original bug wearing a different hat.
    """
    print("\n-- an empty run stays a failure even when everything was skipped --")
    code, text = verdict([], skipped=["reproducibility", "VICE boots", "listener"])
    check("exit code is 1", code, 1)
    check("says NOTHING WAS VERIFIED", "NOTHING WAS VERIFIED" in text, True)
    check("does not claim PARTIAL VERIFICATION",
          "PARTIAL VERIFICATION" in text, False)


def test_verdict_clean_full_run() -> None:
    print("\n-- a complete, all-passing run is the only VERIFIED --")
    code, text = verdict([OK, OK, OK])
    check("exit code is 0", code, 0)
    check("says RELEASE ARTIFACTS VERIFIED",
          "RELEASE ARTIFACTS VERIFIED" in text, True)


def test_verdict_skips_never_say_verified() -> None:
    """Case D. Usable (exit 0), but never the word VERIFIED."""
    print("\n-- a skipped section downgrades the verdict but stays usable --")
    code, text = verdict([OK, OK], skipped=["VICE boots"])
    check("exit code is 0 (SKIP_* stays usable)", code, 0)
    check("says PARTIAL VERIFICATION", "PARTIAL VERIFICATION" in text, True)
    check("does NOT say RELEASE ARTIFACTS VERIFIED",
          "RELEASE ARTIFACTS VERIFIED" in text, False)
    check("names what was skipped", "VICE boots" in text, True)
    check("says it is not a release gate", "Not a release gate" in text, True)


def test_verdict_failures_win() -> None:
    print("\n-- a failed check fails the run --")
    code, text = verdict([OK, BAD])
    check("exit code is 1", code, 1)
    check("lists the failure", "some check" in text, True)
    check("does not say VERIFIED", "RELEASE ARTIFACTS VERIFIED" in text, False)


def test_verdict_missing_variants_block() -> None:
    print("\n-- present artifacts verifying does not excuse a missing variant --")
    code, text = verdict([OK, OK], missing=2)
    check("exit code is 1", code, 1)
    check("says RELEASE INCOMPLETE", "RELEASE INCOMPLETE" in text, True)
    check("does not say VERIFIED", "RELEASE ARTIFACTS VERIFIED" in text, False)


def test_verdict_failure_outranks_missing() -> None:
    print("\n-- a real failure is reported ahead of the missing-variant note --")
    code, text = verdict([BAD], missing=1)
    check("exit code is 1", code, 1)
    check("reports the failure", "FAILED:" in text, True)


# ---------------------------------------------------------------------------
# Coverage derivation — iterate over what MUST exist
# ---------------------------------------------------------------------------

def test_expected_images_from_build_record() -> None:
    print("\n-- expected disk images come from the build record --")
    variants = [
        {"key": "uci-reu", "prg": "a.prg", "result": "OK", "backend": "uci"},
        {"key": "uci-onchip", "prg": "b.prg", "result": "OK", "backend": "uci"},
        {"key": "ip65-reu", "prg": "c.prg", "result": "OK", "backend": "ip65"},
        {"key": "ip65-onchip", "prg": "d.prg", "result": "OK", "backend": "ip65"},
    ]
    names = sorted(p.name for p in vr.expected_d64_images(variants))
    # One disk per variant and nothing else. The per-backend combo images were
    # retired when the UCI lineup reached three variants (3 x 248 blocks does
    # not fit a .d64's 664), so a combo disk would have had to silently omit a
    # product. This test previously pinned the combo contract and is what
    # caught the change — keep it pinning the CURRENT one.
    check("one disk per variant, no combo images", names, [
        "c64-https-ip65-onchip.d64",
        "c64-https-ip65-reu.d64",
        "c64-https-uci-onchip.d64",
        "c64-https-uci-reu.d64",
    ])


def test_expected_images_skip_failed_variants() -> None:
    """A variant that did not build must not be expected to have a disk."""
    print("\n-- a variant that failed to build is not expected on disk --")
    variants = [
        {"key": "uci-reu", "prg": "a.prg", "result": "OK", "backend": "uci"},
        {"key": "uci-onchip", "prg": "b.prg", "result": "FAILED", "backend": "uci"},
    ]
    names = sorted(p.name for p in vr.expected_d64_images(variants))
    check("only the built variant's disk", names,
          ["c64-https-uci-reu.d64"])


def test_expected_images_empty_when_nothing_built() -> None:
    """Empty here is what makes the disk checks record an explicit failure."""
    print("\n-- nothing built means nothing expected (checks then fail loudly) --")
    variants = [{"key": "uci-reu", "prg": "a.prg", "result": "FAILED",
                 "backend": "uci"}]
    check("no images expected", vr.expected_d64_images(variants), [])


def test_expected_images_tolerate_old_build_info() -> None:
    """backend= was added late; a build-info without it must not crash.

    The derivation no longer READS backend= (combo disks are gone), so this is
    now purely a no-crash guard on old records rather than a check that the
    backend is inferred correctly.
    """
    print("\n-- a build record predating backend= still derives correctly --")
    variants = [{"key": "ip65-onchip", "prg": "d.prg", "result": "OK"}]
    names = sorted(p.name for p in vr.expected_d64_images(variants))
    check("no crash without backend=", names,
          ["c64-https-ip65-onchip.d64"])


# ---------------------------------------------------------------------------
# build-info parsing
# ---------------------------------------------------------------------------

# Sample build-info lines. Defaulted rather than passed in, so that pytest
# can run this module too: a parameter without a default is a fixture
# request, and there is no `tmp_lines` fixture (issue #109).
SAMPLE_BUILD_INFO = [
    "variant=uci-onchip prg=x.prg args=BACKEND=uci USE_NISTCURVES_ONCHIP=1"
    " result=OK bytes=62977 sha256=abc123 backend=uci",
    "variant=ip65-onchip prg=y.prg args=BACKEND=ip65 result=FAILED"
    " log=build-ip65-onchip.log",
]


def test_parse_build_info_records(tmp_lines: list[str] = None) -> None:
    if tmp_lines is None:
        tmp_lines = SAMPLE_BUILD_INFO
    print("\n-- build-info records parse, including args with spaces --")
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "build-info.txt"
        path.write_text("\n".join(tmp_lines) + "\n")
        saved = vr.BUILD_INFO
        vr.BUILD_INFO = path
        try:
            recs = vr.parse_build_info()
        finally:
            vr.BUILD_INFO = saved
    check("two records", len(recs), 2)
    check("OK record result", recs[0]["result"], "OK")
    check("multi-word args survive", recs[0]["args"],
          "BACKEND=uci USE_NISTCURVES_ONCHIP=1")
    check("sha captured", recs[0]["sha256"], "abc123")
    check("backend captured", recs[0]["backend"], "uci")
    check("FAILED record result", recs[1]["result"], "FAILED")


# ---------------------------------------------------------------------------
# #288: the boot gate loads under true drive emulation, and every dist PRG
# stays off the I/O page
# ---------------------------------------------------------------------------

def test_boot_gate_drive_setup() -> None:
    print("\n-- boot gate: TDE flags, and the resources read back --")
    check("TDE on, traps off, autostart leaves TDE alone",
          set(vr.TDE_ARGS) >= {"-drive8truedrive", "+trapdevice8",
                               "+autostart-handle-tde"}, True)
    check("no trap-load flag", set(vr.TDE_ARGS) & {"+drive8truedrive",
                                                   "-trapdevice8"}, set())
    import inspect
    src = inspect.getsource(vr.check_d64_boots)
    check("the gate launches with TDE_ARGS", "extra_args=list(TDE_ARGS)" in src, True)
    check("the gate reads the resources back",
          "tde_resource_problems(inst.transport.resource_get)" in src, True)
    good = dict(vr.TDE_RESOURCES)
    check("held resources pass", vr.tde_resource_problems(good.__getitem__), [])
    trap = {"Drive8TrueEmulation": 0, "TrapDevice8": 1,
            "AutostartHandleTrueDriveEmulation": 0}
    check("the old trap setup fails",
          len(vr.tde_resource_problems(trap.__getitem__)), 2)
    handled = dict(good, AutostartHandleTrueDriveEmulation=1)
    check("autostart disabling TDE fails",
          len(vr.tde_resource_problems(handled.__getitem__)), 1)

    def boom(name):
        raise RuntimeError("monitor gone")
    check("an unreadable resource fails",
          len(vr.tde_resource_problems(boom)), len(vr.TDE_RESOURCES))


def test_prg_range_check() -> None:
    print("\n-- dist PRGs: load range off the I/O page --")
    import tempfile
    def prg(last):
        return bytes([0x01, 0x08]) + bytes(last - 0x0801 + 1)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "old.prg").write_bytes(prg(0xDFFF))
        (d / "new.prg").write_bytes(prg(0xBFFF))
        saved_dist, saved_results = vr.DIST, list(vr.results)
        vr.DIST, vr.results[:] = d, []
        try:
            vr.check_prg_ranges([{"prg": "old.prg", "result": "OK"},
                                 {"prg": "new.prg", "result": "OK"},
                                 {"prg": "gone.prg", "result": "FAILED"}])
            got = [(n, ok) for n, ok, _ in vr.results]
            vr.results[:] = []
            vr.check_prg_ranges([])
            empty = [(n, ok) for n, ok, _ in vr.results]
        finally:
            vr.DIST = saved_dist
            vr.results[:] = saved_results
    check("a $DFFF image fails, a $BFFF one passes, unbuilt skipped", got,
          [("old.prg load range", False), ("new.prg load range", True)])
    check("nothing to check is a failure", empty,
          [("dist PRGs to range-check", False)])


def main() -> int:
    print("=== release-gate verdict regression tests ===")
    test_verdict_empty_run_is_a_failure()
    test_verdict_empty_run_not_rescued_by_skips()
    test_verdict_clean_full_run()
    test_verdict_skips_never_say_verified()
    test_verdict_failures_win()
    test_verdict_missing_variants_block()
    test_verdict_failure_outranks_missing()
    test_expected_images_from_build_record()
    test_expected_images_skip_failed_variants()
    test_expected_images_empty_when_nothing_built()
    test_expected_images_tolerate_old_build_info()
    test_parse_build_info_records(SAMPLE_BUILD_INFO)
    test_boot_gate_drive_setup()
    test_prg_range_check()
    print(f"\n{'=' * 60}")
    print(f"{PASSED} passed, {FAILED} failed")
    from _skip_policy import verdict
    return verdict(PASSED, FAILED, certifies="the release-gate verdict")


if __name__ == "__main__":
    sys.exit(main())
