#!/usr/bin/env python3
"""check_ip65_build_exports.py -- does build/labels.txt carry the symbols the
RR-Net hardware rig reads (`ip65_hw_checks.DIAG_SYMBOLS`)?

This was `test_the_build_exports_every_symbol_the_rig_reads` in
`test_ip65_hw_checks_unit.py` until #302: it needs a BACKEND=ip65 build in
build/, while six pytest modules need a BACKEND=uci one, so no single build
made a bare `pytest` green. It lives here, outside pytest's testpaths, and
`tools/run_all_tests.py` runs it on its ip65 build.

    python3 tools/check_ip65_build_exports.py     # after `make BACKEND=ip65 ...`

Exit 0 pass, 1 a symbol is missing, 2 COULD NOT RUN (no build, or a UCI one;
#178 -- never a silent pass). `C64_ALLOW_NO_BUILD=1` is the loud opt-out.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import ip65_hw_checks as hw  # noqa: E402
from _skip_policy import cannot_run, verdict  # noqa: E402

OPT_OUT_ENV = "C64_ALLOW_NO_BUILD"
CERTIFIES = "whether the build exports the symbols the hardware rig reads"


def check(build_dir: Path = REPO / "build") -> int:
    """0 pass / 1 fail / 2 could not run, for the labels.txt in build_dir."""
    return run(build_dir)[0]


def run(build_dir: Path = REPO / "build"):
    """(exit code, executed). executed is False when nothing was verified,
    which includes a 0 returned by the C64_ALLOW_NO_BUILD opt-out (#178)."""
    labels_path = build_dir / "labels.txt"
    if not labels_path.exists():
        return (cannot_run(
            f"{labels_path} is absent -- build first "
            "(`make BACKEND=ip65 USE_NISTCURVES_ONCHIP=1`)",
            executed=0, total=1, certifies=CERTIFIES,
            opt_out_env=OPT_OUT_ENV), False)
    # A UCI build lacks the ip65 adapter's symbols by design: that is "did
    # not run", not "missing export". Decided from flags.stamp, only on
    # positive evidence -- an unreadable stamp falls through to the real check.
    backend = None
    stamp = build_dir / "flags.stamp"
    if stamp.exists():
        for line in stamp.read_text().splitlines():
            if line.startswith("BACKEND="):
                backend = line.split("=", 1)[1].strip()
    if backend not in (None, "ip65"):
        return (cannot_run(
            f"build/ holds a BACKEND={backend} build, not an ip65 one -- "
            "rebuild (`make BACKEND=ip65 USE_NISTCURVES_ONCHIP=1`)",
            executed=0, total=1, certifies=CERTIFIES, opt_out_env=OPT_OUT_ENV), False)
    labels = {}
    for line in labels_path.read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "al" and parts[2].startswith("."):
            labels[parts[2][1:]] = int(parts[1].split(":")[-1], 16)
    v = hw.resolve_symbols(labels, hw.DIAG_SYMBOLS)
    if not v.ok:
        print(f"FAIL: {v.reason}")
    return verdict(int(v.ok), int(not v.ok), certifies=CERTIFIES), True


if __name__ == "__main__":
    sys.exit(check())
