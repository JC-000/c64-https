#!/usr/bin/env python3
"""test_p384_symbols.py -- Phase 3 dual-overlay swap dispatcher smoke test.

Phase 3 (this rewrite) replaced the legacy single-image overlay flow
(crypto_swap_to_p384, overlay-p384.bin, harness-side staging) with a
build-time embedded dual-overlay flow:

  - The build produces TWO .bin images:
      build/lib/overlay-p384-sha384.bin   (REU bank 6, $60000)
      build/lib/overlay-p384-curve.bin    (REU bank 7, $70000)
  - `make BACKEND=uci` `.incbin`s both blobs into the PRG
    (src/crypto/shared/p384_overlay_blobs.s) and grows the PRG from
    47105 B -> 62977 B (+15872 B, the two 7,680 B blobs plus the 8 KB
    of zeros ld65 emits across the $C000-$DFFF gap so the under-KERNAL
    OVERLAY_BLOB_CURVE_RAM region at $E000 lands at the right RAM
    address after KERNAL LOAD).
  - At boot, src/boot.s calls reu_p384_overlay_init which STASHes the
    embedded blobs from $4200 (sha384) and $E000 (curve) into REU
    banks 6 and 7 in two ~8 ms DMA windows.
  - The TLS path (Phase 4a will implement) calls
    crypto_swap_to_p384_sha384 to hash the transcript, then
    crypto_swap_to_p384_curve to verify the ECDSA-P384 signature.
    Each swap is a single REU->C64 DMA into the live CRYPTO_OVERLAY
    slot at $4200; idempotent if `current_overlay` already matches.

This script smoke-tests the dispatcher in isolation:

  1. Verify both .bin files exist (rebuild if missing) and report sizes.
  2. Verify build/labels.txt exposes all four swap entry points and
     the current_overlay state byte.
  3. Boot the PRG in VICE -reu and wait for the menu banner.
  4. Read current_overlay -- expected OV_NONE (= 0) right after boot.
  5. JSR crypto_swap_to_p384_sha384.  Confirm current_overlay == 4
     (OV_P384_SHA384) and the first 16 B at $4200 match the sha384 .bin.
  6. JSR crypto_swap_to_p384_curve.  Confirm current_overlay == 5
     (OV_P384_CURVE) and the first 16 B at $4200 match the curve .bin.
  7. JSR crypto_swap_to_p384_sha384 again.  Confirm idempotent +
     direction-reversal: current_overlay == 4 and $4200 reverts to
     the sha384 image.
  8. JSR crypto_swap_to_x25519_sibling.  Confirm current_overlay == 1
     (OV_X25519_SIBLING).  This entry is a state-only marker today
     (Phase 3 deferred actual REU restoration of X25519 rodata to a
     follow-up phase), so the live slot bytes do NOT change -- we
     only assert the state byte updates.
  9. JSR crypto_swap_none.  Confirm current_overlay == 0.

Exits 0 on PASS, 1 on FAIL or environmental error.

VICE harness gotcha: the PRG's boot path executes nistcurves P-256
fp_mul, which fetches 8x8 multiply rows from REU banks 0/1.  Without
`-reu`, those banks don't exist and the boot crashes.  We launch
VICE with `extra_args=["-reu", "-reusize", "512"]` per the documented
project gotcha (CLAUDE.md "VICE harness gotcha", and the
vice_reu_required_for_p256 user memory note).

Usage:
    BACKEND=uci /Users/someone/.local/share/c64-test-harness/venv/bin/python3 \
        tools/test_p384_symbols.py [--verbose]

Under BACKEND=ip65 the script exits 0 with a skip message -- the
embedded-blobs path is UCI-only (ip65 has no main-RAM headroom for the
extra 15 KB; see cfg/c64-https-ip65.cfg's Phase 3 comment block).
"""

import os
import subprocess
import sys

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
SHA_BIN_PATH = os.path.join(PROJECT_ROOT, "build", "lib", "overlay-p384-sha384.bin")
CURVE_BIN_PATH = os.path.join(PROJECT_ROOT, "build", "lib", "overlay-p384-curve.bin")

VERBOSE = False

# ID constants kept in sync with src/crypto/shared/crypto_swap.s.
OV_NONE = 0
OV_X25519_SIBLING = 1
OV_P384_SHA384 = 4
OV_P384_CURVE = 5

# Live overlay slot start under UCI (cfg's CRYPTO_OVERLAY = $4200).
CRYPTO_OVERLAY_START = 0x4200
OVERLAY_BLOB_BYTES = 0x1E00  # 7,680 B per blob


# -----------------------------------------------------------------------------
# Label loader (VICE format: "al C:XXXX .name").
# -----------------------------------------------------------------------------

def load_labels(path: str) -> dict:
    """Return a dict mapping label name -> int address."""
    result: dict[str, int] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 3 or parts[0] != "al":
                continue
            addr_field = parts[1]
            if addr_field.startswith("C:"):
                addr = int(addr_field[2:], 16)
            else:
                addr = int(addr_field, 16)
            name = parts[2].lstrip(".")
            result[name] = addr
    return result


# -----------------------------------------------------------------------------
# Test harness wrapper.
# -----------------------------------------------------------------------------

def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    args = sys.argv[1:]
    if "--verbose" in args:
        VERBOSE = True

    backend = os.environ.get("BACKEND", "uci")
    print(f"=== test_p384_symbols.py (BACKEND={backend}) ===")

    # Phase 3 dual-overlay embed is UCI-only -- ip65 has no main-RAM
    # headroom for the extra 15 KB after the existing layout.  Under
    # ip65 the OVERLAY_BLOB_* segments are empty and the boot DMA is
    # a no-op, so there is nothing meaningful to test.  Skip cleanly.
    if backend != "uci":
        print(f"  SKIP: dual-overlay smoke test is UCI-only (backend={backend})")
        return 0

    if os.environ.get("C64_SKIP_BUILD") != "1":
        subprocess.run(["make", "clean", f"BACKEND={backend}"],
                       capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make", f"BACKEND={backend}"],
                                capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return 1
    else:
        print("  C64_SKIP_BUILD=1 -- reusing existing build artifacts")

    # Sanity-check on-disk artifacts.
    for path in (PRG_PATH, LABELS_PATH, SHA_BIN_PATH, CURVE_BIN_PATH):
        if not os.path.exists(path):
            print(f"FATAL: required artifact missing: {path}")
            return 1

    sha_image = open(SHA_BIN_PATH, "rb").read()
    curve_image = open(CURVE_BIN_PATH, "rb").read()
    print(f"  overlay-p384-sha384.bin: {len(sha_image)} B "
          f"(expected {OVERLAY_BLOB_BYTES})")
    print(f"  overlay-p384-curve.bin:  {len(curve_image)} B "
          f"(expected {OVERLAY_BLOB_BYTES})")
    if len(sha_image) != OVERLAY_BLOB_BYTES or len(curve_image) != OVERLAY_BLOB_BYTES:
        print("FATAL: overlay .bin sizes do not match OVERLAY_BLOB_BYTES")
        return 1

    prg_size = os.path.getsize(PRG_PATH)
    print(f"  c64-https.prg:           {prg_size} B "
          f"(pre-Phase-3 baseline: 47105 B)")

    labels = load_labels(LABELS_PATH)

    required_symbols = [
        "crypto_swap_to_x25519_sibling",
        "crypto_swap_to_p384_sha384",
        "crypto_swap_to_p384_curve",
        "crypto_swap_none",
        "current_overlay",
        "reu_p384_overlay_init",
    ]
    missing = [s for s in required_symbols if s not in labels]
    if missing:
        print(f"FATAL: required symbols missing from build/labels.txt: {missing}")
        return 1
    print(f"  Labels loaded: {len(required_symbols)} swap-dispatcher symbols verified")
    if VERBOSE:
        for s in required_symbols:
            print(f"    {s:32s} = ${labels[s]:04X}")

    try:
        from c64_test_harness import (
            ViceConfig, ViceInstanceManager,
            read_bytes, jsr, wait_for_text,
        )
    except ImportError:
        print("FATAL: c64-test-harness package not installed")
        return 1

    # VICE harness gotcha: the boot path runs nistcurves P-256 fp_mul
    # which DMAs 8x8 multiply rows from REU banks 0/1.  Without `-reu`
    # the banks don't exist and the boot path silently no-ops the
    # DMA, leading to wrong-result symptoms (and in our case, also
    # leaves the Phase 3 reu_p384_overlay_init STASH a no-op so the
    # subsequent crypto_swap_to_p384_* DMAs would deliver zeros).
    # ALWAYS pass `-reu` for any test that touches REU under VICE.
    extra_args = ["-reu", "-reusize", "512"]
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=extra_args)
    print(f"  VICE config: extra_args={extra_args!r}")

    print("\n=== Starting VICE ===")

    passed = failed = 0

    def check(label: str, condition: bool, fail_detail: str = "") -> None:
        nonlocal passed, failed
        if condition:
            print(f"  PASS {label}")
            passed += 1
        else:
            print(f"  FAIL {label}")
            if fail_detail:
                print(f"       {fail_detail}")
            failed += 1

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        grid = wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False)
        if grid is None:
            print("FATAL: program menu did not appear within 120 s")
            mgr.release(inst)
            return 1

        ov_addr = labels["current_overlay"]
        sha_entry = labels["crypto_swap_to_p384_sha384"]
        curve_entry = labels["crypto_swap_to_p384_curve"]
        x25519_entry = labels["crypto_swap_to_x25519_sibling"]
        none_entry = labels["crypto_swap_none"]

        # By the time the menu has rendered, src/boot.s has already run
        # reu_p384_overlay_init -- so REU banks 6 and 7 should hold the
        # two overlay images.  Note that $4200 at this point holds the
        # CURVE blob, not the SHA blob: boot's stash 2 CPU-copies the
        # curve bytes from $E000-$FDFF into $4200 (the now-free SHA
        # staging slot) before issuing the STASH-to-bank-7 DMA, so the
        # final state of $4200 is the curve image.  The first
        # crypto_swap_to_p384_sha384 call below will DMA the SHA bytes
        # back from REU bank 6, restoring the slot to SHA content.
        # The harness can't easily read RAM under KERNAL ROM via the
        # binary monitor (bank=0 = CPU-banked and $01 is $36 with
        # KERNAL on), so we skip $E000 verification here -- the
        # round-trip via crypto_swap_to_p384_curve below is the actual
        # correctness check on REU bank 7's contents.
        if VERBOSE:
            stage_4200 = bytes(read_bytes(transport, 0x4200, 16))
            print(f"    STAGE post-boot $4200:               {stage_4200.hex()}")
            print(f"    STAGE expected curve +$00 (post-cpy): {curve_image[:16].hex()}")

        # --- Test 1: boot leaves current_overlay = OV_NONE ---
        # boot.s zero-initialises SHADOW_BSS (which CRYPTO_BSS lives
        # under) and reu_p384_overlay_init does NOT touch the state
        # byte, so the first read after boot must be 0.
        ov = read_bytes(transport, ov_addr, 1)[0]
        check("boot leaves current_overlay = OV_NONE",
              ov == OV_NONE,
              f"got 0x{ov:02X}, expected 0x{OV_NONE:02X}")

        # --- Test 2: jsr crypto_swap_to_p384_sha384 ---
        # First swap should DMA from REU bank 6 into $4200 and update
        # current_overlay = OV_P384_SHA384.
        jsr(transport, sha_entry, timeout=30.0)
        ov = read_bytes(transport, ov_addr, 1)[0]
        check("crypto_swap_to_p384_sha384 sets current_overlay = OV_P384_SHA384",
              ov == OV_P384_SHA384,
              f"got 0x{ov:02X}, expected 0x{OV_P384_SHA384:02X}")

        live = bytes(read_bytes(transport, CRYPTO_OVERLAY_START, 16))
        if VERBOSE:
            print(f"    live @ ${CRYPTO_OVERLAY_START:04X}: {live.hex()}")
            print(f"    sha image +$00:                    {sha_image[:16].hex()}")
        check("$4200 holds the sha384 blob bytes after first swap",
              live == sha_image[:16],
              f"got {live.hex()}, expected {sha_image[:16].hex()}")

        # --- Test 3: jsr crypto_swap_to_p384_curve ---
        # Second swap should DMA from REU bank 7 into $4200 and update
        # current_overlay = OV_P384_CURVE.
        jsr(transport, curve_entry, timeout=30.0)
        ov = read_bytes(transport, ov_addr, 1)[0]
        check("crypto_swap_to_p384_curve sets current_overlay = OV_P384_CURVE",
              ov == OV_P384_CURVE,
              f"got 0x{ov:02X}, expected 0x{OV_P384_CURVE:02X}")

        live = bytes(read_bytes(transport, CRYPTO_OVERLAY_START, 16))
        if VERBOSE:
            print(f"    live @ ${CRYPTO_OVERLAY_START:04X}: {live.hex()}")
            print(f"    curve image +$00:                  {curve_image[:16].hex()}")
        check("$4200 holds the curve blob bytes after curve swap",
              live == curve_image[:16],
              f"got {live.hex()}, expected {curve_image[:16].hex()}")

        # --- Test 4: jsr crypto_swap_to_p384_sha384 again (round-trip) ---
        # Direction reversal -- previous state was OV_P384_CURVE, so
        # this must DMA again (not short-circuit).  current_overlay
        # back to OV_P384_SHA384 and bytes back to the sha384 image.
        jsr(transport, sha_entry, timeout=30.0)
        ov = read_bytes(transport, ov_addr, 1)[0]
        check("round-trip back to sha384 sets current_overlay = OV_P384_SHA384",
              ov == OV_P384_SHA384,
              f"got 0x{ov:02X}, expected 0x{OV_P384_SHA384:02X}")
        live = bytes(read_bytes(transport, CRYPTO_OVERLAY_START, 16))
        check("$4200 reverts to sha384 blob bytes after round-trip",
              live == sha_image[:16],
              f"got {live.hex()}, expected {sha_image[:16].hex()}")

        # --- Test 5: jsr crypto_swap_to_p384_sha384 idempotent (no-op) ---
        # State already OV_P384_SHA384 -- should single-byte cmp + rts.
        # Bytes at $4200 must remain the sha384 image (no DMA, but
        # would be the same bytes anyway).
        jsr(transport, sha_entry, timeout=5.0)
        ov = read_bytes(transport, ov_addr, 1)[0]
        check("idempotent re-swap to sha384 leaves state unchanged",
              ov == OV_P384_SHA384,
              f"got 0x{ov:02X}, expected 0x{OV_P384_SHA384:02X}")

        # --- Test 6: jsr crypto_swap_to_x25519_sibling (state-only marker) ---
        # Phase 3 leaves this as a state-only marker (no DMA -- there
        # is no boot-time REU stash for X25519 sibling rodata).  So we
        # only check the state byte; the live slot bytes at $4200 are
        # whatever the previous swap left there.
        jsr(transport, x25519_entry, timeout=5.0)
        ov = read_bytes(transport, ov_addr, 1)[0]
        check("crypto_swap_to_x25519_sibling sets current_overlay = OV_X25519_SIBLING",
              ov == OV_X25519_SIBLING,
              f"got 0x{ov:02X}, expected 0x{OV_X25519_SIBLING:02X}")

        # --- Test 7: jsr crypto_swap_none ---
        jsr(transport, none_entry, timeout=5.0)
        ov = read_bytes(transport, ov_addr, 1)[0]
        check("crypto_swap_none sets current_overlay = OV_NONE",
              ov == OV_NONE,
              f"got 0x{ov:02X}, expected 0x{OV_NONE:02X}")

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
