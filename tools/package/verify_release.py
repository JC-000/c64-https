#!/usr/bin/env python3
"""tools/package/verify_release.py — acceptance gate for the release artifacts.

Run after `make package`. Measures three things and prints the evidence; it
does not assert anything it has not just observed.

  1. REPRODUCIBILITY. Rebuilds every PRG variant a second time from clean and
     compares **PRG** sha256 against dist/build-info.txt. Object hashes are
     deliberately not compared: ca65 stamps wall-clock time into every .o
     header, so nobody can reproduce their own object hash twice. ld65 does
     not propagate that field, which is exactly what makes the PRG comparable.

  2. DISK IMAGES. Extracts each .d64's contents with c1541 and byte-compares
     them to the dist PRGs, then boots every image in VICE and asserts the
     banner. ip65 images will print NETWORK INIT FAILED without a network —
     that is expected and is NOT part of the pass criteria; the banner is.

  3. LISTENER. Runs the built single-file listener's own --selftest from a
     clean temp directory with no venv, which mints a cert and drives the
     server with a Python ssl client.

Environment:
  SKIP_REBUILD=1   skip check 1 (it costs four full builds)
  SKIP_VICE=1      skip the VICE boots (keeps the c1541 byte-compare)
  SKIP_LISTENER=1  skip check 3
  VICE_BOOT_TIMEOUT  seconds to wait for the menu (default 180)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DIST = REPO_ROOT / "dist"
BUILD_INFO = DIST / "build-info.txt"
BUILT_PRG = REPO_ROOT / "build" / "c64-https.prg"

sys.path.insert(0, str(REPO_ROOT / "tools"))

COMMON_BANNER = "C64-HTTPS CLIENT V0.1"
MENU_MARKER = "Q=QUIT"
# src/net/ip65/net_banner.s and src/net/uci/net.s respectively.
BACKEND_BANNERS = {"uci": "UCI NETWORKING", "ip65": "RR-NET (CS8900A) ETHERNET"}

results: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return ok


def sha256_of(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_build_info() -> list[dict]:
    """Return the per-variant records build_prgs.sh left behind."""
    if not BUILD_INFO.is_file():
        sys.exit(f"ERROR: {BUILD_INFO} missing — run `make package` first.")
    variants = []
    for line in BUILD_INFO.read_text().splitlines():
        if not line.startswith("variant="):
            continue
        rec: dict = {}
        # args= holds spaces, so peel the fixed keys off either end.
        head, _, rest = line.partition(" prg=")
        rec["key"] = head[len("variant="):]
        prg, _, rest = rest.partition(" args=")
        rec["prg"] = prg
        args, _, rest = rest.partition(" result=")
        rec["args"] = args
        # rest is "<result> [bytes=N sha256=H]" — the result value is bare.
        fields = rest.split()
        rec["result"] = fields[0] if fields else ""
        for kv in fields[1:]:
            k, _, v = kv.partition("=")
            rec[k] = v
        variants.append(rec)
    return variants


# ---------------------------------------------------------------------------
# 1. PRG reproducibility
# ---------------------------------------------------------------------------

def check_reproducible(variants: list[dict]) -> None:
    print("\n=== 1. PRG byte-reproducibility (second build from clean) ===")
    for rec in variants:
        if rec.get("result") != "OK":
            record(f"{rec['key']} rebuild", False, "first build had already failed")
            continue
        subprocess.run(["make", "clean"], cwd=REPO_ROOT, check=True,
                       stdout=subprocess.DEVNULL)
        proc = subprocess.run(["make"] + rec["args"].split(), cwd=REPO_ROOT,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            record(f"{rec['key']} rebuild", False,
                   f"make failed: {proc.stderr.strip().splitlines()[-1:]}")
            continue
        again = sha256_of(BUILT_PRG)
        record(f"{rec['key']} reproduces",
               again == rec["sha256"],
               f"{again[:16]}… vs {rec['sha256'][:16]}…")


# ---------------------------------------------------------------------------
# 2. Disk images
# ---------------------------------------------------------------------------

def d64_images() -> list[Path]:
    return sorted(DIST.glob("*.d64"))


def check_d64_contents(variants: list[dict]) -> None:
    """Read each PRG back out of each disk and byte-compare it."""
    print("\n=== 2a. D64 contents (c1541 read-back, byte-compare) ===")
    c1541 = os.environ.get("C1541", "c1541")
    if not shutil.which(c1541):
        record("c1541 available", False, "not on PATH")
        return
    by_prg = {r["prg"]: r for r in variants}
    for image in d64_images():
        listing = subprocess.run([c1541, "-attach", str(image), "-list"],
                                 capture_output=True, text=True).stdout
        names = [ln.split('"')[1] for ln in listing.splitlines()
                 if ln.count('"') >= 2 and " prg " in ln.lower()]
        if not names:
            record(f"{image.name} has files", False, "no PRG entries in directory")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            ok = True
            detail = []
            for name in names:
                out = Path(tmp) / f"{name}.prg"
                subprocess.run([c1541, "-attach", str(image),
                                "-read", f"{name},p", str(out)],
                               capture_output=True, text=True)
                if not out.is_file():
                    ok = False
                    detail.append(f"{name}: unreadable")
                    continue
                # Match it against whichever dist PRG has the same bytes.
                got = sha256_of(out)
                match = [p for p, r in by_prg.items()
                         if r.get("sha256") == got]
                if match:
                    detail.append(f"{name} == {match[0]}")
                else:
                    ok = False
                    detail.append(f"{name}: {got[:12]}… matches no dist PRG")
            record(f"{image.name} carries the built PRGs", ok, "; ".join(detail))


def check_d64_boots() -> None:
    """Autostart every disk image in VICE and assert the boot banner.

    Two flags are load-bearing, and both were found the hard way:

      -trapdevice8 +drive8truedrive — use the KERNAL load traps instead of
        true drive emulation. Under TDE the ~250-block serial load of a 63 KB
        PRG does not finish inside any budget worth waiting for, and the
        symptom (a screen frozen on LOADING) reads as a corrupt image rather
        than a slow one. The image's contents are byte-compared separately in
        2a, so nothing is lost by loading it fast.

    The pass criterion is the BANNER, not the menu. Two reasons, both
    measured. The ip65 images print NETWORK INIT FAILED with no network
    attached, which is expected and says nothing about the image. And the menu
    is not reachable in a test-shaped budget: boot's table init runs at
    emulated 1 MHz because VICE 3.10 has no usable warp, and a 900 s probe on
    c64-https-uci-reu.d64 saw the banner at 6.0 s and never reached Q=QUIT.
    Whether the menu appeared is reported as extra information, never as the
    verdict.
    """
    print("\n=== 2b. D64 boots to the banner in VICE ===")
    try:
        from c64_test_harness import ViceInstanceManager
        from c64_test_harness.screen import ScreenGrid
        from _vice_helpers import default_vice_config
    except Exception as exc:                                # noqa: BLE001
        record("c64_test_harness importable", False, f"{type(exc).__name__}: {exc}")
        return
    timeout = float(os.environ.get("VICE_BOOT_TIMEOUT", "240"))
    import time
    for image in d64_images():
        # Backend is in the filename by construction (see _common.sh); the
        # per-backend disks autostart their first file, which is that
        # backend's REU profile.
        backend = "uci" if "-uci" in image.name else "ip65"
        expected = BACKEND_BANNERS[backend]
        foreign_banners = {k: v for k, v in BACKEND_BANNERS.items()
                           if k != backend}
        # -autostart on a .d64 loads and runs the first program on the disk.
        config = default_vice_config(prg_path=str(image), warp=True,
                                     ntsc=True, sound=False,
                                     extra_args=["-trapdevice8",
                                                 "+drive8truedrive"])
        seen: dict[str, float] = {}
        needles = [COMMON_BANNER, expected, MENU_MARKER] + list(foreign_banners.values())
        try:
            with ViceInstanceManager(config=config) as mgr:
                inst = mgr.acquire()
                start = time.monotonic()
                while time.monotonic() - start < timeout:
                    time.sleep(5.0)
                    try:
                        inst.transport.resume()
                        text = ScreenGrid.from_transport(
                            inst.transport).continuous_text().upper()
                    except Exception:                       # noqa: BLE001
                        continue
                    for needle in needles:
                        if needle in text and needle not in seen:
                            seen[needle] = time.monotonic() - start
                    # Stop as soon as the verdict is decided. The banner is
                    # printed in one pass, so a foreign backend line cannot
                    # appear after the expected one; waiting on for the menu
                    # would add minutes of emulated table-init per image
                    # without changing the answer.
                    if COMMON_BANNER in seen and expected in seen:
                        break
                    if MENU_MARKER in seen:
                        break
                mgr.release(inst)
        except Exception as exc:                            # noqa: BLE001
            record(f"{image.name} boots", False, f"{type(exc).__name__}: {exc}")
            continue
        foreign = [v for v in foreign_banners.values() if v in seen]
        ok = COMMON_BANNER in seen and expected in seen and not foreign
        detail = ", ".join(f"{n!r} at {t:.0f}s" for n, t in sorted(
            seen.items(), key=lambda kv: kv[1]))
        if not detail:
            detail = f"nothing recognisable on screen within {timeout:.0f}s"
        if foreign:
            detail += f"; UNEXPECTED foreign banner {foreign}"
        record(f"{image.name} boots to the banner", ok, detail)


# ---------------------------------------------------------------------------
# 3. Listener
# ---------------------------------------------------------------------------

def check_listener() -> None:
    print("\n=== 3. Single-file listener selftest (clean temp dir, no venv) ===")
    bundle = DIST / "c64-https-listener.py"
    if not bundle.is_file():
        record("listener bundle present", False, f"{bundle} missing")
        return
    import ssl
    if not getattr(ssl, "HAS_TLSv1_3", False):
        record("listener selftest", False,
               f"this interpreter has no TLS 1.3 ({ssl.OPENSSL_VERSION}); "
               "re-run with PACKAGE_PYTHON=<a python built on OpenSSL 1.1.1+>")
        return
    with tempfile.TemporaryDirectory(prefix="c64-listener-verify-") as tmp:
        proc = subprocess.run([sys.executable, str(bundle), "--selftest"],
                              cwd=tmp, capture_output=True, text=True)
        for ln in proc.stdout.splitlines():
            print(f"      {ln}")
        record("listener selftest", proc.returncode == 0,
               f"exit {proc.returncode}")
        # The bundle must not have left anything behind in the working dir.
        leftovers = sorted(p.name for p in Path(tmp).iterdir())
        record("selftest leaves no droppings", not leftovers,
               f"found {leftovers}" if leftovers else "clean")


def main() -> int:
    variants = parse_build_info()
    print(f"Verifying {len(variants)} PRG variants and "
          f"{len(d64_images())} disk images in {DIST}")

    if os.environ.get("SKIP_REBUILD") != "1":
        check_reproducible(variants)
    else:
        print("\n=== 1. PRG reproducibility SKIPPED (SKIP_REBUILD=1) ===")

    check_d64_contents(variants)
    if os.environ.get("SKIP_VICE") != "1":
        check_d64_boots()
    else:
        print("\n=== 2b. VICE boots SKIPPED (SKIP_VICE=1) ===")

    if os.environ.get("SKIP_LISTENER") != "1":
        check_listener()
    else:
        print("\n=== 3. Listener SKIPPED (SKIP_LISTENER=1) ===")

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{'=' * 60}")
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("FAILED:")
        for name in failed:
            print(f"  - {name}")
        return 1
    print("RELEASE ARTIFACTS VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
