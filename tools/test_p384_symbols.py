#!/usr/bin/env python3
"""test_p384_symbols.py -- P-384 primitive smoke test (c64-nist-curves sibling).

Phase C.3b design: P-384 is smoke-test-only — the production PRG does NOT
link the P-384 archive (the Makefile USE_NISTCURVES_P384 gate is commented
out intentionally). Instead we ship the P-384 overlay as a separate
`build/lib/overlay-p384.bin` (8 KB raw image) + `build/labels-p384.txt`
(addresses of the primitives + DATA buffers), and THIS script loads them
into REU at harness time:

  1. Build main PRG (BACKEND=uci) -- same size as without P-384.
  2. Build overlay-p384.bin + labels-p384.txt via
     `bash tools/integration/build_nistcurves_p384_bin.sh`.
  3. Boot VICE and wait for the main menu.
  4. Stage the 8 KB image into C64 RAM at $2000 (clobbers the UCI adapter,
     which is fine — no networking used in this test).
  5. DMA-copy $2000..$3FFF into REU bank 2 offset $4100 (REU_OVERLAY_P384)
     via a tiny injected trampoline at $0340.
  6. Call `crypto_swap_to_p384` — REU→$4200 DMA inside the PRG. The live
     overlay slot now holds P-384 code.
  7. Exercise ec_point_double_384 / ec_point_add_384 /
     ec_jacobian_to_affine_384 against NIST P-384 generator vectors,
     comparing affine outputs to a Python reference.

Endian: c64-nist-curves stores field elements LITTLE-ENDIAN (byte 0 = LSB,
48 bytes per coordinate). Python `cryptography` gives integers; we
convert in-script with `int_to_le48`.

P-384 DATA buffers (ec384_p1, fp384_wide, ec384_affine_x, ...) live at
$C000+ in this standalone link (inside TCP_BUF). TCP_BUF is unused at
test time (no networking), so we can safely use it as P-384 scratch.

Usage:
    BACKEND=uci python3 tools/test_p384_symbols.py [--verbose]

Under BACKEND=ip65 (or any other backend where nistcurves-p384.a is not
built), the script exits 0 with a skip message — the overlay image is
built only under UCI via the integration script.

Known issue (Phase C.3b investigation):
    fp_mul_384 works correctly after the harness's REU-reg restore step
    (2*3=6 smoke-verified), but fp_sqr_384 hangs when invoked on any
    nonzero input in this standalone link configuration. Consequently
    ec_point_double_384 (which calls ec_sqrp_384 -> fp_mod_sqr_384 ->
    fp_sqr_384) times out on Test 1. The root cause has not been
    identified yet; most likely candidates:
      - Subtle interaction between the PRG's x25519 sibling leaving
        REU registers in a state fp_sqr_384 doesn't re-program (fp_sqr's
        inline DMA writes only $DF05/$DF06/$DF01, relying on other REU
        regs being pre-set to the mul-row FETCH config).
      - A local BSS symbol in fp384_raw.s (fp384_sqr_pairs, mul_src2_buf_384)
        resolving to an address that collides with something else in the
        standalone-link RESIDENT placement at $C000-$CFFF. This has been
        checked against the linker map and addresses look clean, but some
        interaction with TCP_BUF scratch used for overlay staging hasn't
        been fully ruled out.
    The test infrastructure (overlay upload, crypto_swap_to_p384, REU-reg
    restore, ZP/fp_src wiring, output readback) is verified working
    end-to-end by the fp_mul_384 path.
"""

import os
import subprocess
import sys

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
P384_LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels-p384.txt")
P384_IMAGE_PATH = os.path.join(PROJECT_ROOT, "build", "lib", "overlay-p384.bin")

VERBOSE = False

# P-384 curve parameters (NIST FIPS 186-4).
P_384 = 2**384 - 2**128 - 2**96 + 2**32 - 1
A_384 = -3 % P_384
B_384 = int(
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
    "c656398d8a2ed19d2a85c8edd3ec2aef",
    16,
)
GX_384 = int(
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
    "5502f25dbf55296c3a545e3872760ab7",
    16,
)
GY_384 = int(
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
    "0a60b1ce1d7e819d7a431d7c90ea0e5f",
    16,
)

# REU bank/offset used by the overlay store. Kept in sync with
# src/crypto/shared/reu_layout.inc.
REU_OVERLAY_P384 = 0x24100   # 24-bit REU address = bank 2, offset $4100.

# Harness staging area. The 8 KB image is uploaded to REU in two 4 KB
# halves so we can stage each half in TCP_BUF ($C000-$CFFF, free because
# networking is off). We can't stage at $2000 even though it's
# big enough — the UCI cfg puts LOADER_OVERFLOW (containing
# crypto_swap_to_p384 itself!) in NET_CODE at $2000-$3FFF, and clobbering
# that would crash the next jsr(crypto_swap_to_p384).
C64_STAGE_ADDR = 0xC000
C64_STAGE_SIZE = 0x1000      # 4 KB per chunk.
OVERLAY_SIZE = 0x2000        # 8 KB.

# Address we inject the DMA trampoline at. Inside the cassette buffer,
# safely past the jsr() scratch at $0334-$0338. The trampoline is 55 B
# so it occupies $0340-$0377 (ASCII).
DMA_TRAMPOLINE_ADDR = 0x0340


# -----------------------------------------------------------------------------
# Byte-order helpers.
# -----------------------------------------------------------------------------

def int_to_le48(v: int) -> bytes:
    """Convert an integer to 48-byte little-endian representation."""
    return (v % P_384).to_bytes(48, "little")


def le48_to_int(b: bytes) -> int:
    """Convert 48-byte little-endian bytes to integer."""
    return int.from_bytes(b, "little")


# -----------------------------------------------------------------------------
# Python reference implementations (affine + Jacobian point arithmetic over
# P-384).
# -----------------------------------------------------------------------------

def fe_add(a: int, b: int) -> int:
    return (a + b) % P_384

def fe_sub(a: int, b: int) -> int:
    return (a - b) % P_384

def fe_mul(a: int, b: int) -> int:
    return (a * b) % P_384

def fe_inv(a: int) -> int:
    return pow(a, P_384 - 2, P_384)


def point_double_affine(px: int, py: int) -> tuple[int, int]:
    """Double an affine point on y^2 = x^3 - 3x + b over F_P384."""
    lam = fe_mul(3 * fe_sub(fe_mul(px, px), 1), fe_inv(2 * py % P_384))
    rx = fe_sub(fe_mul(lam, lam), 2 * px % P_384)
    ry = fe_sub(fe_mul(lam, fe_sub(px, rx)), py)
    return rx % P_384, ry % P_384


def point_add_affine(px: int, py: int, qx: int, qy: int) -> tuple[int, int]:
    """Affine addition of two distinct points on P-384."""
    if (px, py) == (qx, qy):
        return point_double_affine(px, py)
    lam = fe_mul(fe_sub(qy, py), fe_inv(fe_sub(qx, px)))
    rx = fe_sub(fe_sub(fe_mul(lam, lam), px), qx)
    ry = fe_sub(fe_mul(lam, fe_sub(px, rx)), py)
    return rx % P_384, ry % P_384


def scalar_mul_affine(k: int, px: int, py: int) -> tuple[int, int]:
    """Double-and-add scalar mult: k*(px,py) on P-384."""
    rx, ry = None, None
    cx, cy = px, py
    for bit in range(k.bit_length()):
        if (k >> bit) & 1:
            if rx is None:
                rx, ry = cx, cy
            else:
                rx, ry = point_add_affine(rx, ry, cx, cy)
        cx, cy = point_double_affine(cx, cy)
    return rx, ry


# -----------------------------------------------------------------------------
# Label loader that merges build/labels.txt + build/labels-p384.txt.
# -----------------------------------------------------------------------------

def load_merged_labels():
    """Return a dict mapping label name -> int address.

    Parses the main PRG labels file plus the P-384 overlay labels file.
    Later wins on conflicts (not expected — P-384 symbols only appear
    in the overlay labels file).
    """
    result: dict[str, int] = {}
    for path in (LABELS_PATH, P384_LABELS_PATH):
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                # Format: al C:XXXX .name
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
# DMA trampoline / REU helpers.
# -----------------------------------------------------------------------------

# DMA-trampoline approach: the harness writes 7 parameter bytes into a
# staging area in C64 RAM (at DMA_PARAMS_ADDR), then calls the trampoline
# which loads them into REU registers $DF02-$DF08, sets $DF0A=0, and fires
# a $90 (C64->REU) to $DF01. This avoids relying on monitor-side
# memory_write() reaching the REU I/O registers (which would stomp on
# REU's internal state machine and may or may not actually store).
#
# Staging layout at DMA_PARAMS_ADDR (7 bytes):
#   +0  c64_src_lo
#   +1  c64_src_hi
#   +2  reu_dst_lo
#   +3  reu_dst_hi
#   +4  reu_dst_bank
#   +5  length_lo
#   +6  length_hi
# MUST be past the 55-byte trampoline at $0340 (ends at $0377).
DMA_PARAMS_ADDR = 0x0380

# Assembled 6502 — loads 7 params from DMA_PARAMS_ADDR ($0380) into
# $DF02-$DF08, writes $00 to $DF0A, then $90 to $DF01, then RTS.
# 55 bytes total, fits at $0340-$0376 without colliding with the
# DMA_PARAMS_ADDR staging block at $0380+.
DMA_TRAMPOLINE_C64_TO_REU = bytes([
    0x78,                                      # SEI
    0xAD, 0x80, 0x03,  0x8D, 0x02, 0xDF,       # $DF02 = [$0380]
    0xAD, 0x81, 0x03,  0x8D, 0x03, 0xDF,       # $DF03 = [$0381]
    0xAD, 0x82, 0x03,  0x8D, 0x04, 0xDF,       # $DF04 = [$0382]
    0xAD, 0x83, 0x03,  0x8D, 0x05, 0xDF,       # $DF05 = [$0383]
    0xAD, 0x84, 0x03,  0x8D, 0x06, 0xDF,       # $DF06 = [$0384]
    0xAD, 0x85, 0x03,  0x8D, 0x07, 0xDF,       # $DF07 = [$0385]
    0xAD, 0x86, 0x03,  0x8D, 0x08, 0xDF,       # $DF08 = [$0386]
    0xA9, 0x00,        0x8D, 0x0A, 0xDF,       # $DF0A = 0
    0xA9, 0x90,        0x8D, 0x01, 0xDF,       # $DF01 = $90 (C64->REU)
    0x58, 0x60,                                # CLI; RTS
])


def program_and_dma_c64_to_reu(transport, write_bytes_fn, jsr_fn,
                                c64_src: int, reu_dst: int, length: int):
    """Stage DMA params in RAM and fire the trampoline.

    *length* must fit in 16 bits ($DF07/$DF08). The trampoline covers
    the $DF0A address control (both autoincrement) and the $DF01 command
    byte ($90 = immediate C64->REU).
    """
    assert 1 <= length <= 0xFFFF, f"length {length} out of range"
    params = bytes([
        c64_src & 0xFF, (c64_src >> 8) & 0xFF,           # src lo/hi
        reu_dst & 0xFF, (reu_dst >> 8) & 0xFF,           # dst lo/hi
        (reu_dst >> 16) & 0xFF,                          # dst bank
        length & 0xFF, (length >> 8) & 0xFF,             # len lo/hi
    ])
    write_bytes_fn(transport, DMA_PARAMS_ADDR, params)
    jsr_fn(transport, DMA_TRAMPOLINE_ADDR, timeout=5.0)


# -----------------------------------------------------------------------------
# Test harness wrapper.
# -----------------------------------------------------------------------------

def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    args = sys.argv[1:]
    if "--verbose" in args:
        VERBOSE = True

    backend = os.environ.get("BACKEND", "ip65")
    make_args = [f"BACKEND={backend}"]
    print(f"=== test_p384_symbols.py (BACKEND={backend}) ===")

    # P-384 sibling integration is UCI-only. The ip65 cfg does not build
    # the archive and the labels table would not contain the symbols even
    # if stale artifacts were on disk. Exit cleanly under ip65.
    if backend != "uci":
        print(f"  SKIP: P-384 smoke test is UCI-only (backend={backend})")
        return 0

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

    # The overlay image + labels are only produced under UCI. ip65 does
    # not attempt the nistcurves-p384 archive build (sibling archive
    # script is gated in the main Makefile under BACKEND=uci).
    if not os.path.exists(P384_IMAGE_PATH):
        if backend != "uci":
            print(f"  SKIP: P-384 overlay image not built under BACKEND={backend}")
            print(f"  (missing: {P384_IMAGE_PATH})")
            return 0
        # Try to build the overlay image now under UCI.
        print(f"  Building P-384 overlay image + labels...")
        result = subprocess.run(
            ["bash", "tools/integration/build_nistcurves_p384_bin.sh"],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
        )
        if result.returncode != 0:
            print(f"FATAL: P-384 overlay build failed:\n{result.stdout}\n{result.stderr}")
            return 1
    if not os.path.exists(P384_LABELS_PATH):
        print(f"FATAL: {P384_LABELS_PATH} not found")
        return 1

    try:
        from c64_test_harness import (
            ViceConfig, ViceInstanceManager,
            read_bytes, write_bytes, jsr, wait_for_text,
        )
    except ImportError:
        print("FATAL: c64-test-harness package not installed")
        return 1

    labels = load_merged_labels()

    required = [
        "ec_point_double_384",
        "ec_point_add_384",
        "ec_jacobian_to_affine_384",
        "ec384_p1",
        "ec384_p2",
        "ec384_p3",
        "ec384_affine_x",
        "ec384_affine_y",
        "crypto_swap_to_p384",
    ]
    missing = [n for n in required if n not in labels]
    if missing:
        if backend != "uci":
            print(f"  SKIP: P-384 symbols not available under BACKEND={backend}")
            print(f"  (missing labels: {', '.join(missing)})")
            return 0
        print(f"FATAL: P-384 symbols missing from labels: {missing}")
        return 1

    print(f"  Labels loaded: {len(required)} P-384 symbols verified")

    # Read the overlay image.
    with open(P384_IMAGE_PATH, "rb") as fh:
        image = fh.read()
    if len(image) != OVERLAY_SIZE:
        print(f"FATAL: overlay image size {len(image)} != {OVERLAY_SIZE}")
        return 1
    print(f"  P-384 overlay image: {len(image)} bytes from {P384_IMAGE_PATH}")

    # Launch VICE with REU Profile B (512 KB) so both overlays fit.
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    print("\n=== Starting VICE ===")

    passed = failed = 0
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Program menu did not appear")
            return 1

        # Safety: CPU-idle trampoline at $0339 (unused by jsr / dma scratch).
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Inject the DMA trampoline.
        write_bytes(transport, DMA_TRAMPOLINE_ADDR, DMA_TRAMPOLINE_C64_TO_REU)

        # Stage the 8 KB image into REU in two 4 KB halves via TCP_BUF.
        # TCP_BUF ($C000-$CFFF) is free because networking is off. Doing
        # it in halves avoids clobbering LOADER_OVERFLOW in NET_CODE
        # ($2000-$3FFF) where crypto_swap_to_p384 lives.
        for chunk_i in range(0, OVERLAY_SIZE, C64_STAGE_SIZE):
            half = image[chunk_i:chunk_i + C64_STAGE_SIZE]
            reu_dst = REU_OVERLAY_P384 + chunk_i
            if VERBOSE:
                print(f"  Staging half +${chunk_i:04X} (len={len(half)}) at "
                      f"${C64_STAGE_ADDR:04X} -> REU ${reu_dst:06X}")
            write_bytes(transport, C64_STAGE_ADDR, half)
            program_and_dma_c64_to_reu(
                transport, write_bytes, jsr,
                C64_STAGE_ADDR, reu_dst, len(half),
            )
        print(f"  DMA C64 -> REU ${REU_OVERLAY_P384:06X} ({OVERLAY_SIZE} B)")

        # Verify: round-trip the first 16 B back from REU via an inverse DMA.
        # Writes REU bank 2 offset $4100 -> C64 $CF00 using a one-shot
        # trampoline, then reads $CF00.
        pullback = bytes([
            0x78,
            0xA9, 0x00, 0x8D, 0x02, 0xDF,   # c64 lo = $00
            0xA9, 0xCF, 0x8D, 0x03, 0xDF,   # c64 hi = $CF
            0xA9, 0x00, 0x8D, 0x04, 0xDF,   # reu lo = $00
            0xA9, 0x41, 0x8D, 0x05, 0xDF,   # reu hi = $41
            0xA9, 0x02, 0x8D, 0x06, 0xDF,   # reu bank = 2
            0xA9, 0x10, 0x8D, 0x07, 0xDF,   # len lo = 16
            0xA9, 0x00, 0x8D, 0x08, 0xDF,   # len hi = 0
            0xA9, 0x00, 0x8D, 0x0A, 0xDF,   # addr_ctrl = 0
            0xA9, 0x91, 0x8D, 0x01, 0xDF,   # cmd = $91 REU->C64
            0x58, 0x60,
        ])
        write_bytes(transport, DMA_TRAMPOLINE_ADDR, pullback)
        jsr(transport, DMA_TRAMPOLINE_ADDR, timeout=10.0)
        reu_readback = read_bytes(transport, 0xCF00, 16)
        if VERBOSE:
            print(f"    REU+$4100 readback : {reu_readback.hex()}")
            print(f"    image +$0000      : {image[:16].hex()}")
        if bytes(reu_readback) != image[:16]:
            print("FATAL: REU did not receive the overlay image cleanly")
            print(f"    got      {bytes(reu_readback).hex()}")
            print(f"    expected {image[:16].hex()}")
            mgr.release(inst)
            return 1

        # Restore the forward-DMA trampoline for subsequent calls if any.
        write_bytes(transport, DMA_TRAMPOLINE_ADDR, DMA_TRAMPOLINE_C64_TO_REU)

        # Swap P-384 overlay into the live CRYPTO_OVERLAY slot.
        if "current_overlay" in labels:
            pre = read_bytes(transport, labels["current_overlay"], 1)
            if VERBOSE:
                print(f"    current_overlay before swap = 0x{pre[0]:02x}")
        print("  Swapping CRYPTO_OVERLAY -> P-384 image")
        jsr(transport, labels["crypto_swap_to_p384"], timeout=30.0)
        if "current_overlay" in labels and VERBOSE:
            post = read_bytes(transport, labels["current_overlay"], 1)
            print(f"    current_overlay after swap  = 0x{post[0]:02x}")

        # Restore REU registers to the "mul-row FETCH config" that the
        # x25519 sibling's `reu_fetch_mul_row` expects at rest:
        #   $DF02/$DF03 = mul_dma_lo ($6600)
        #   $DF04       = 0          (reu_lo; reu_hi patched per call)
        #   $DF07/$DF08 = 512        (row length)
        #   $DF0A       = 0          (autoincrement both)
        # fp_mul_384 / fp_sqr_384 only overwrite $DF05 (reu_hi), $DF06
        # (bank), and $DF01 (command) inside `reu_fetch_mul_row`.
        # MUST happen AFTER crypto_swap_to_p384 — that DMA also writes
        # $DF02-$DF08 and would clobber our setup if we restored first.
        MUL_DMA_LO = 0x6600
        restore = bytes([
            MUL_DMA_LO & 0xFF, (MUL_DMA_LO >> 8) & 0xFF,  # $DF02, $DF03
            0x00,                                          # $DF04 reu_lo
        ])
        write_bytes(transport, 0xDF02, restore)
        write_bytes(transport, 0xDF07, bytes([0x00, 0x02]))  # len = 512
        write_bytes(transport, 0xDF0A, bytes([0x00]))         # autoincrement

        # Sanity check: first 16 bytes at $4200 must match the overlay
        # image. If they don't, the REU DMA didn't round-trip and every
        # subsequent jsr() will hang (the overlay slot still holds
        # x25519 code, not P-384).
        live = read_bytes(transport, 0x4200, 16)
        if VERBOSE:
            print(f"    live @ $4200: {live.hex()}")
            print(f"    image @ +$00: {image[:16].hex()}")
        if bytes(live) != image[:16]:
            print(f"FATAL: overlay DMA mismatch at $4200")
            print(f"    got      {bytes(live).hex()}")
            print(f"    expected {image[:16].hex()}")
            mgr.release(inst)
            return 1

        # Zero the P-384 DATA region at $C000-$C636 so uninitialised buffers
        # don't carry residue between tests.
        write_bytes(transport, 0xC000, bytes(0x640))

        # --- Test 1: ec_point_double_384(G) -> 2G ---
        print("\n--- Test 1: ec_point_double_384(G) ---")
        # Load G into ec384_p1 as Jacobian (X=Gx, Y=Gy, Z=1).
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        jsr(transport, labels["ec_point_double_384"], timeout=600.0)
        # Output lands in ec384_p3 (Jacobian). Convert to affine via the
        # library's own ec_jacobian_to_affine_384 for comparison.
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=600.0)
        got_x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        got_y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        exp_x, exp_y = point_double_affine(GX_384, GY_384)
        if got_x == exp_x and got_y == exp_y:
            print("  PASS 2G affine matches Python reference")
            passed += 1
        else:
            failed += 1
            print("  FAIL 2G mismatch")
            print(f"    exp_x = {exp_x:#098x}")
            print(f"    got_x = {got_x:#098x}")
            print(f"    exp_y = {exp_y:#098x}")
            print(f"    got_y = {got_y:#098x}")

        # --- Test 2: ec_point_add_384(G, 2G) -> 3G ---
        # ABI: ec_p1 (Jacobian) + ec_p2 (affine) -> ec_p3 (Jacobian).
        print("\n--- Test 2: ec_point_add_384(G, 2G) ---")
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        write_bytes(transport, labels["ec384_p2"],       int_to_le48(exp_x))
        write_bytes(transport, labels["ec384_p2"] + 48,  int_to_le48(exp_y))
        jsr(transport, labels["ec_point_add_384"], timeout=600.0)
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=600.0)
        got_x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        got_y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        exp_x3, exp_y3 = scalar_mul_affine(3, GX_384, GY_384)
        if got_x == exp_x3 and got_y == exp_y3:
            print("  PASS 3G affine matches Python reference")
            passed += 1
        else:
            failed += 1
            print("  FAIL 3G mismatch")
            print(f"    exp_x = {exp_x3:#098x}")
            print(f"    got_x = {got_x:#098x}")

        # --- Test 3: iterated double+add to 17G ---
        print("\n--- Test 3: iterated doubling -> 16G -> 17G ---")
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        for _ in range(4):
            jsr(transport, labels["ec_point_double_384"], timeout=600.0)
            p3_bytes = read_bytes(transport, labels["ec384_p3"], 144)
            write_bytes(transport, labels["ec384_p1"], p3_bytes)
        # Now p1 = 16G (Jacobian). Convert to affine to get 16G coordinates.
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=600.0)
        aff16x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        aff16y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        # Reload p1 = 16G (Jacobian) and p2 = G (affine), add.
        write_bytes(transport, labels["ec384_p1"], p3_bytes)
        write_bytes(transport, labels["ec384_p2"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p2"] + 48,  int_to_le48(GY_384))
        jsr(transport, labels["ec_point_add_384"], timeout=600.0)
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=600.0)
        got_x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        got_y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        exp_x17, exp_y17 = scalar_mul_affine(17, GX_384, GY_384)
        if got_x == exp_x17 and got_y == exp_y17:
            print("  PASS 17G affine matches Python reference")
            passed += 1
        else:
            failed += 1
            print("  FAIL 17G mismatch")
            print(f"    16G aff = ({aff16x:#098x}, {aff16y:#098x})")
            print(f"    exp_x = {exp_x17:#098x}")
            print(f"    got_x = {got_x:#098x}")
            print(f"    exp_y = {exp_y17:#098x}")
            print(f"    got_y = {got_y:#098x}")

        # --- Test 4: ec_jacobian_to_affine with non-trivial Z ---
        print("\n--- Test 4: ec_jacobian_to_affine_384 (Z != 1) ---")
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        jsr(transport, labels["ec_point_double_384"], timeout=600.0)
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=600.0)
        got_x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        got_y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        if got_x == exp_x and got_y == exp_y:
            print("  PASS jacobian_to_affine_384 matches 2G affine")
            passed += 1
        else:
            failed += 1
            print("  FAIL jacobian_to_affine_384 mismatch")

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
