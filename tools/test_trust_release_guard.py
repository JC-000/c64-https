#!/usr/bin/env python3
"""test_trust_release_guard.py — a release never carries the TEST-ONLY bundle key.

#155 phase 2, L3 (DECISIONS 10): the tree's trust-bundle key
(tools/trust_bundle_TEST_ONLY_pubkey.inc) has its private half committed, so
anyone can sign a bundle an image built with it accepts. `make package`
must refuse it. Two independent layers, each checked here:

  Makefile  TRUST_RELEASE=1 + TRUST_BUNDLE=1 with the test key's 64 `$XX`
            tokens is a parse-time $(error) — even if the .inc claims
            TRUST_BUNDLE_KEY_IS_TEST_ONLY = 0;
  link      that check is textual, so the link also runs
            tools/check_release_key.py over the ASSEMBLED PRG (the test key
            derived from its PEM) — pinned here by the recipe it prints and
            by the script's verdict on synthetic images;
  source    src/net/uci/trust_bundle.s `.assert`s the flag under
            -D TRUST_RELEASE (ca65 run directly, the Makefile bypassed).

and the wiring: every UCI product's args as tools/package/build_prgs.sh
builds them (variant_make_args in _common.sh) carry TRUST_RELEASE=1, so
turning the bundle on in a package line with the test key fails the
build. Controls: a dev build (no TRUST_RELEASE) with the test key, and a
release with a throwaway non-test key, both go through.

No build and no VICE: `make -n` (which, since #174, evaluates the Makefile
and writes nothing) and one ca65 run. Seconds.

Exit 0 pass, 1 fail, 2 could not run.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from _skip_policy import cannot_run, verdict    # noqa: E402

REPO = HERE.parent
TEST_INC = REPO / "tools" / "trust_bundle_TEST_ONLY_pubkey.inc"
CERTIFIES = "the release guard against the TEST-ONLY bundle key (#155, L3)"
UCI_BUNDLE = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "TRUST_STORE=1", "TRUST_BUNDLE=1"]

PASSED = 0
FAILED: list[str] = []


def check(ok, what):
    global PASSED
    if ok:
        PASSED += 1
    else:
        FAILED.append(what)
        print(f"  FAIL: {what}")


def make_n(*args):
    p = subprocess.run(["make", "-n", *args], cwd=REPO, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def package_args():
    """{key: args} exactly as build_prgs.sh builds each product."""
    script = ('PROJECT_ROOT="$1"; . "$1/tools/package/_common.sh"; '
              'for l in "${PACKAGE_VARIANTS[@]}"; do '
              'printf "%s|%s\\n" "$(variant_field "$l" 1)" "$(variant_make_args "$l")"; done')
    out = subprocess.run(["bash", "-c", script, "_", str(REPO)], capture_output=True,
                         text=True, check=True).stdout
    return dict(line.split("|", 1) for line in out.splitlines() if line)


def other_key_inc(tmp: Path) -> Path:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    pem = tmp / "throwaway.pem"
    pem.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    inc = tmp / "throwaway.inc"
    subprocess.run([sys.executable, str(HERE / "trust_bundle.py"), "inc", "--key", str(pem),
                    "--floor", "1", "-o", str(inc)], check=True, capture_output=True)
    return inc


def main():
    if not shutil.which("make") or not shutil.which("ca65"):
        return cannot_run("make / ca65 not on PATH", certifies=CERTIFIES)
    tmp = Path(tempfile.mkdtemp(prefix="trust-release-"))
    try:
        # --- the packaging wiring -------------------------------------------
        prods = package_args()
        uci = {k: a for k, a in prods.items() if "BACKEND=uci" in a.split()}
        check(len(uci) >= 2, f"expected the UCI products, got {sorted(prods)}")
        for key, args in prods.items():
            check("TRUST_RELEASE=1" in args.split(), f"{key}: built without TRUST_RELEASE=1")
            check("TRUST_BUNDLE=1" not in args.split(),
                  f"{key}: the bundle is in a package before a production key exists")
        for key in ("uci-onchip", "uci-comb"):
            check("TRUST_STORE=1" in prods.get(key, "").split(),
                  f"{key}: TRUST_STORE=1 is not on (DECISIONS 11, Q1)")
        for key, args in uci.items():           # the bundle switched on
            rc, out = make_n(*args.split(), "TRUST_BUNDLE=1")
            check(rc != 0 and "TEST-ONLY" in out,
                  f"{key} + TRUST_BUNDLE=1 with the test key: make -n exit {rc}")

        # --- Makefile layer ---------------------------------------------------
        rc, out = make_n(*UCI_BUNDLE, "TRUST_RELEASE=1")
        check(rc != 0 and "TEST-ONLY" in out, f"release + test key: exit {rc}")
        relabelled = tmp / "relabelled.inc"
        text = TEST_INC.read_text()
        relabelled.write_text(re.sub(r"TRUST_BUNDLE_KEY_IS_TEST_ONLY = 1",
                                     "TRUST_BUNDLE_KEY_IS_TEST_ONLY = 0", text))
        check("IS_TEST_ONLY = 0" in relabelled.read_text(), "could not relabel the test key")
        rc, out = make_n(*UCI_BUNDLE, "TRUST_RELEASE=1", f"TRUST_BUNDLE_KEY_INC={relabelled}")
        check(rc != 0 and "TEST-ONLY" in out,
              f"release + the test key's bytes relabelled not-test-only: exit {rc}")
        other = other_key_inc(tmp)
        rc, out = make_n(*UCI_BUNDLE, "TRUST_RELEASE=1", f"TRUST_BUNDLE_KEY_INC={other}")
        check(rc == 0, f"release + a non-test key was refused (exit {rc}):\n{out[-400:]}")
        rc, out = make_n(*UCI_BUNDLE)
        check(rc == 0, f"a dev build with the test key was refused (exit {rc})")
        rc, out = make_n(*UCI_BUNDLE, "TRUST_RELEASE=2")
        check(rc != 0, "TRUST_RELEASE=2 accepted")

        # --- assembled-byte layer (adv-269 #1) --------------------------------
        # The parse-time guard reads `$XX` tokens; an .inc that spells a byte
        # in decimal and pads the count with a commented `$00` gets past it.
        crafted = tmp / "crafted.inc"
        t = TEST_INC.read_text().replace("TRUST_BUNDLE_KEY_IS_TEST_ONLY = 1",
                                         "TRUST_BUNDLE_KEY_IS_TEST_ONLY = 0")
        t = t.replace("        .byte $EA, $30,", "        .byte 234, $30,", 1)
        t = t.replace("        ; Qy, big-endian", "        ; Qy, big-endian ; $00")
        crafted.write_text(t)
        rc, out = make_n(*UCI_BUNDLE, "TRUST_RELEASE=1", f"TRUST_BUNDLE_KEY_INC={crafted}")
        check(rc == 0 and "check_release_key.py" in out,
              f"crafted .inc: the textual guard passes it (exit {rc}), so the link "
              "must run the assembled-byte check -- it is not in the recipe")
        rc, out = make_n(*UCI_BUNDLE, f"TRUST_BUNDLE_KEY_INC={other}")
        check(rc == 0 and "check_release_key.py" not in out,
              "a dev build runs the release key check")
        sys.path.insert(0, str(HERE))
        import trust_bundle as tb       # noqa: PLC0415
        key = tb.pubkey_xy(tb.load_private_key(tb.TEST_KEY_PATH).public_key())
        for name, body, want in (("test key inside", bytes(5901) + key + bytes(99), 1),
                                 ("no test key", bytes(6000) + key[:63] + bytes(9), 0)):
            prg = tmp / f"{name.replace(' ', '_')}.prg"
            prg.write_bytes(b"\x01\x08" + body)
            p = subprocess.run([sys.executable, str(HERE / "check_release_key.py"), str(prg)],
                               capture_output=True, text=True)
            check(p.returncode == want, f"check_release_key.py, {name}: exit {p.returncode}")

        # --- source layer (Makefile bypassed) --------------------------------
        def assemble(inc: Path, release: bool):
            d = tmp / ("inc-" + inc.stem + ("-rel" if release else ""))
            d.mkdir()
            shutil.copy(inc, d / "trust_key.inc")
            cmd = ["ca65", "-I", "src", "-I", "src/net", "-I", "src/net/uci", "-I", str(d),
                   "-D", "TRUST_STORE=1", "-D", "TRUST_BUNDLE=1", "-D", "BACKEND_UCI=1",
                   "src/net/uci/trust_bundle.s", "-o", str(d / "tb.o")]
            if release:
                cmd[1:1] = ["-D", "TRUST_RELEASE=1"]
            p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
            return p.returncode, p.stdout + p.stderr
        rc, out = assemble(TEST_INC, True)
        check(rc != 0 and "TEST-ONLY" in out, f"ca65 -D TRUST_RELEASE + test key: exit {rc} {out}")
        rc, out = assemble(other, True)
        check(rc == 0, f"ca65 -D TRUST_RELEASE + non-test key: exit {rc} {out}")
        rc, out = assemble(TEST_INC, False)
        check(rc == 0, f"ca65 dev + test key: exit {rc} {out}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{PASSED} checks passed, {len(FAILED)} failed")
    return verdict(PASSED, len(FAILED), certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
