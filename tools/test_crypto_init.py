#!/usr/bin/env python3
"""Boot-only regression test for crypto_init (Phase E).

Verifies that one-shot boot-time crypto init wired up by
`src/crypto/shared/crypto_init.s` populated its expected artifacts:

  1. Shared sqtab seeded at sqtab_lo / sqtab_hi (c64-x25519 sibling's
     1 KB quarter-square table at $7800/$7A00; n in 0..511,
     sqtab[n] = floor(n*n / 4)).
  2. x25519 REU mul-row stash — for each multiplier `a` in 0..255,
     the library stores one full 256-byte row of (a*b) & $FF at
     REU offset a*512 and (a*b) >> 8 at REU offset a*512+256.
     We pull back row 42 via a harness-injected REU DMA trampoline
     and spot-check a handful of entries.
  3. Overlay swap integrity — after boot, `current_overlay == 1`
     (OV_X25519) because crypto_init leaves the x25519 image live
     in CRYPTO_OVERLAY. Idempotently re-calling crypto_swap_to_x25519
     must not corrupt the live slot. First and last 32 bytes of
     $4200..$5FFF must match the PRG-embedded overlay image.

Narrowed from the original plan: ccp (Poly1305 Shoup) + nist-curves
(P-256 / P-384) precompute samples were dropped — those integrations
were deferred (Profile A ccp too large; P-256 blocked on upstream
variable-base scalar-mult; P-384 is external-image-only, not linked).

Under BACKEND=ip65, the sibling libraries are not linked and
crypto_init is a thin dispatcher that only calls the stub
mul_tables_init. The test skips cleanly (exit 0).

Usage:
    BACKEND=uci  python3 tools/test_crypto_init.py [--verbose]
    BACKEND=ip65 python3 tools/test_crypto_init.py    # SKIP + exit 0
"""

import os
import random
import subprocess
import sys
import time
from pathlib import Path

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# -----------------------------------------------------------------------------
# Python reference implementations.
# -----------------------------------------------------------------------------

def compute_sqtab_reference() -> tuple[list[int], list[int]]:
    """Shared 1 KB quarter-square table.

    The c64-x25519 sibling's mul_8x8 builds sqtab[n] = floor(n*n / 4)
    for n in 0..511 — two 512-byte pages labelled sqtab_lo / sqtab_hi.

    Returns (lo, hi) where lo[n] = sqtab[n] & 0xFF, hi[n] = sqtab[n] >> 8.
    """
    lo = [(n * n // 4) & 0xFF for n in range(512)]
    hi = [(n * n // 4) >> 8 for n in range(512)]
    return lo, hi


def compute_x25519_row_reference(a: int) -> tuple[list[int], list[int]]:
    """x25519_init.s reu_mul_init row layout.

    For multiplier `a`, `reu_mul_init` computes a*b for every b in 0..255
    via mul_8x8 and stashes 256 lo bytes then 256 hi bytes at REU offset
    a*512. The row contents are just truncated a*b — no quarter-square
    sign tricks leak out because mul_8x8 packs (a*b) into
    (poly_prod_lo, poly_prod_hi).
    """
    lo = [(a * b) & 0xFF for b in range(256)]
    hi = [(a * b) >> 8 for b in range(256)]
    return lo, hi


# -----------------------------------------------------------------------------
# REU DMA trampoline (reused from test_p384_symbols.py).
# -----------------------------------------------------------------------------

# Trampoline lives in the cassette buffer; jsr()'s own scratch is at
# $0334-$0338, so $0340+ is safe. Params block at $0380+ (past the
# 55-byte trampoline).
DMA_TRAMPOLINE_ADDR = 0x0340
DMA_PARAMS_ADDR     = 0x0380

# Layout at DMA_PARAMS_ADDR (7 bytes):
#   +0  c64_dst_lo
#   +1  c64_dst_hi
#   +2  reu_src_lo
#   +3  reu_src_hi
#   +4  reu_src_bank
#   +5  length_lo
#   +6  length_hi
# REU command byte is literal in the trampoline (this one is FETCH = $91).
DMA_TRAMPOLINE_REU_TO_C64 = bytes([
    0x78,                                      # SEI
    0xAD, 0x80, 0x03,  0x8D, 0x02, 0xDF,       # $DF02 = [$0380] c64 lo
    0xAD, 0x81, 0x03,  0x8D, 0x03, 0xDF,       # $DF03 = [$0381] c64 hi
    0xAD, 0x82, 0x03,  0x8D, 0x04, 0xDF,       # $DF04 = [$0382] reu lo
    0xAD, 0x83, 0x03,  0x8D, 0x05, 0xDF,       # $DF05 = [$0383] reu hi
    0xAD, 0x84, 0x03,  0x8D, 0x06, 0xDF,       # $DF06 = [$0384] reu bank
    0xAD, 0x85, 0x03,  0x8D, 0x07, 0xDF,       # $DF07 = [$0385] len lo
    0xAD, 0x86, 0x03,  0x8D, 0x08, 0xDF,       # $DF08 = [$0386] len hi
    0xA9, 0x00,        0x8D, 0x0A, 0xDF,       # $DF0A = 0 (autoinc both)
    0xA9, 0x91,        0x8D, 0x01, 0xDF,       # $DF01 = $91 REU->C64
    0x58, 0x60,                                # CLI; RTS
])


def dma_reu_to_c64(transport, c64_dst: int, reu_src: int, length: int) -> None:
    """Fire a REU -> C64 DMA via the injected trampoline."""
    assert 1 <= length <= 0xFFFF
    params = bytes([
        c64_dst & 0xFF, (c64_dst >> 8) & 0xFF,
        reu_src & 0xFF, (reu_src >> 8) & 0xFF,
        (reu_src >> 16) & 0xFF,
        length & 0xFF, (length >> 8) & 0xFF,
    ])
    write_bytes(transport, DMA_PARAMS_ADDR, params)
    jsr(transport, DMA_TRAMPOLINE_ADDR, timeout=10.0)


# -----------------------------------------------------------------------------
# Test checks.
# -----------------------------------------------------------------------------

def check_sqtab(transport, labels, rng) -> tuple[int, int]:
    """Check 1: sample 8 indices from sqtab_lo / sqtab_hi."""
    print("\n--- Check 1: sqtab_lo / sqtab_hi sample ---")
    passed = failed = 0
    ref_lo, ref_hi = compute_sqtab_reference()

    sqtab_lo_addr = labels["sqtab_lo"]
    sqtab_hi_addr = labels["sqtab_hi"]

    # sqtab is 512 entries (0..511). Sample 8 indices reproducibly.
    indices = rng.sample(range(512), 8)
    for n in indices:
        got_lo = read_bytes(transport, sqtab_lo_addr + n, 1)[0]
        got_hi = read_bytes(transport, sqtab_hi_addr + n, 1)[0]
        exp_lo = ref_lo[n]
        exp_hi = ref_hi[n]
        if got_lo == exp_lo and got_hi == exp_hi:
            passed += 1
            if VERBOSE:
                print(f"  PASS sqtab[{n}] = ({got_hi:02X}{got_lo:02X})")
        else:
            failed += 1
            print(f"  FAIL sqtab[{n}]: got ({got_hi:02X}{got_lo:02X}), "
                  f"want ({exp_hi:02X}{exp_lo:02X})")

    if failed == 0:
        print(f"  PASS: sqtab sample OK (8/8 indices, lo+hi)")
    return passed, failed


def check_x25519_reu_mul_row(transport, labels) -> tuple[int, int]:
    """Check 2: fetch row 42 from the REU mul-row stash and spot-check."""
    print("\n--- Check 2: x25519 REU mul-row stash (row 42) ---")
    passed = failed = 0

    # Inject the REU->C64 DMA trampoline.
    write_bytes(transport, DMA_TRAMPOLINE_ADDR, DMA_TRAMPOLINE_REU_TO_C64)

    # Row 42 lives at REU bank 0, offset 42*512 = $5400 (fits in reu_lo/hi).
    row_a = 42
    reu_offset = row_a * 512  # 21504 = $5400
    assert reu_offset == 0x5400

    # Stage the 512-byte row into C64 RAM at $C000 (TCP_BUF, free — no net).
    row_scratch = 0xC000
    dma_reu_to_c64(transport, row_scratch, reu_offset, 512)

    row = read_bytes(transport, row_scratch, 512)
    exp_lo, exp_hi = compute_x25519_row_reference(row_a)

    # Spot-check 8 entries spread across the row.
    for b in (0, 1, 17, 64, 100, 128, 200, 255):
        got_lo = row[b]
        got_hi = row[256 + b]
        if got_lo == exp_lo[b] and got_hi == exp_hi[b]:
            passed += 1
            if VERBOSE:
                print(f"  PASS row[42][{b:3d}] = {row_a}*{b} "
                      f"= {(row_a*b):5d} (lo={got_lo:02X} hi={got_hi:02X})")
        else:
            failed += 1
            print(f"  FAIL row[42][{b}]: got lo={got_lo:02X} hi={got_hi:02X}, "
                  f"want lo={exp_lo[b]:02X} hi={exp_hi[b]:02X}")

    if failed == 0:
        print(f"  PASS: x25519 REU mul-row stash OK (row 42, 8 entries)")
    return passed, failed


def check_overlay_swap(transport, labels) -> tuple[int, int]:
    """Check 3: overlay swap integrity.

    After crypto_init, current_overlay must be 1 (OV_X25519) and the
    live slot at $4200..$5FFF must hold the x25519 overlay image.
    Also re-run crypto_swap_to_x25519 (idempotent fast path) to prove
    the swap can be called without corruption even when already live.
    """
    print("\n--- Check 3: overlay swap integrity ---")
    passed = failed = 0

    # Sub-check 3a: current_overlay == OV_X25519 (1).
    current_addr = labels["current_overlay"]
    current = read_bytes(transport, current_addr, 1)[0]
    if current == 1:
        passed += 1
        print(f"  PASS: current_overlay = 1 (OV_X25519)")
    else:
        failed += 1
        print(f"  FAIL: current_overlay = {current}, want 1 (OV_X25519)")

    # Sub-check 3b: idempotent swap returns with current_overlay unchanged.
    jsr(transport, labels["crypto_swap_to_x25519"], timeout=5.0)
    current2 = read_bytes(transport, current_addr, 1)[0]
    if current2 == 1:
        passed += 1
        print(f"  PASS: idempotent crypto_swap_to_x25519 (no change)")
    else:
        failed += 1
        print(f"  FAIL: idempotent swap changed current_overlay: {current2}")

    # Sub-check 3c: first / last 32 bytes of live slot match the PRG
    # overlay image.
    overlay_start = labels.get("__CRYPTO_OVERLAY_START__")
    overlay_fileoffs = labels.get("__CRYPTO_OVERLAY_FILEOFFS__")
    overlay_size = labels.get("__CRYPTO_OVERLAY_SIZE__")
    if (overlay_start is None or overlay_fileoffs is None
            or overlay_size is None):
        print("  SKIP-sub: CRYPTO_OVERLAY linker define labels not exported")
        return passed, failed

    prg = Path(PRG_PATH).read_bytes()
    # __CRYPTO_OVERLAY_FILEOFFS__ is the raw PRG file byte offset (the
    # 2-byte load-address header is already accounted for).
    exp_first = prg[overlay_fileoffs : overlay_fileoffs + 32]
    exp_last = prg[overlay_fileoffs + overlay_size - 32 :
                   overlay_fileoffs + overlay_size]
    got_first = bytes(read_bytes(transport, overlay_start, 32))
    got_last = bytes(read_bytes(transport, overlay_start + overlay_size - 32,
                                32))

    if got_first == exp_first:
        passed += 1
        if VERBOSE:
            print(f"  PASS: overlay first 32 B @ ${overlay_start:04X}: "
                  f"{got_first.hex()}")
        else:
            print(f"  PASS: overlay first 32 B match at ${overlay_start:04X}")
    else:
        failed += 1
        print(f"  FAIL: overlay first 32 B mismatch at ${overlay_start:04X}")
        print(f"    exp: {exp_first.hex()}")
        print(f"    got: {got_first.hex()}")

    if got_last == exp_last:
        passed += 1
        tail_addr = overlay_start + overlay_size - 32
        if VERBOSE:
            print(f"  PASS: overlay last 32 B @ ${tail_addr:04X}: "
                  f"{got_last.hex()}")
        else:
            print(f"  PASS: overlay last 32 B match at ${tail_addr:04X}")
    else:
        failed += 1
        tail_addr = overlay_start + overlay_size - 32
        print(f"  FAIL: overlay last 32 B mismatch at ${tail_addr:04X}")
        print(f"    exp: {exp_last.hex()}")
        print(f"    got: {got_last.hex()}")

    return passed, failed


# -----------------------------------------------------------------------------
# Main.
# -----------------------------------------------------------------------------

def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    args = sys.argv[1:]
    if "--verbose" in args:
        VERBOSE = True

    backend = os.environ.get("BACKEND", "uci")
    print(f"=== test_crypto_init.py (BACKEND={backend}) ===")

    # Skip cleanly under any non-UCI backend — the sibling libraries
    # (c64-x25519, c64-nist-curves) are not linked and the symbols the
    # test depends on (sqtab_lo/hi, x25519_reu_mul_init, the REU stash,
    # the overlay image) do not exist in that build.
    if backend != "uci":
        print(f"  SKIP: Phase E test is UCI-only (no sibling libs under "
              f"BACKEND={backend})")
        return 0

    # Build if needed.
    make_args = [f"BACKEND={backend}"]
    if os.environ.get("C64_SKIP_BUILD") != "1":
        subprocess.run(["make", "clean"] + make_args,
                       capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"] + make_args, capture_output=True,
                                text=True, cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return 1
    else:
        print("  C64_SKIP_BUILD=1 — reusing existing build artifacts")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found after build")
        return 1
    print(f"  Build OK: {PRG_PATH}")

    labels = Labels.from_file(LABELS_PATH)

    required = [
        "crypto_init", "crypto_swap_to_x25519",
        "sqtab_lo", "sqtab_hi",
        "x25519_scalarmult", "x25519_sqtab_init", "x25519_reu_mul_init",
        "current_overlay",
    ]
    missing = [s for s in required if labels.address(s) is None]
    if missing:
        print(f"  SKIP: missing labels (expected under UCI): {missing}")
        return 0
    print(f"  Labels loaded: {len(required)} required symbols verified")

    # Pull in the optional CRYPTO_OVERLAY linker defines for sub-check 3c.
    label_dict = {name: labels.address(name) for name in required}
    for opt in ("__CRYPTO_OVERLAY_START__", "__CRYPTO_OVERLAY_FILEOFFS__",
                "__CRYPTO_OVERLAY_SIZE__"):
        addr = labels.address(opt)
        if addr is not None:
            label_dict[opt] = addr

    # Launch VICE with REU Profile B (512 KB) as x25519 needs it.
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    print("\n=== Starting VICE ===")

    t_start = time.monotonic()
    passed = failed = 0
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        # Wait for the main menu — reaching this point proves boot.s ran
        # to main_loop, which means crypto_init + sqtab_init +
        # reu_mul_init + crypto_overlay_stash_x25519 all completed.
        # main_loop pauses on getin, so the CPU is idle and all crypto
        # BSS / REU state is quiescent.
        grid = wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False)
        if grid is None:
            print("FATAL: Program menu did not appear within 120 s")
            mgr.release(inst)
            return 1
        print("  VICE ready (reached main_loop, crypto_init complete)")

        # Idle trampoline — jsr() returns leave us sitting on this loop.
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        rng = random.Random(0x5151)

        p, f = check_sqtab(transport, label_dict, rng)
        passed += p; failed += f

        p, f = check_x25519_reu_mul_row(transport, label_dict)
        passed += p; failed += f

        p, f = check_overlay_swap(transport, label_dict)
        passed += p; failed += f

        mgr.release(inst)

    elapsed = time.monotonic() - t_start
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed "
          f"({elapsed:.1f}s)")
    print(f"{'='*60}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
