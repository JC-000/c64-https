#!/usr/bin/env python3
"""test_p384_symbols.py -- P-384 primitive smoke test (c64-nist-curves sibling).

Exercises the three variable-base P-384 point operations against Python
`cryptography` reference values computed from the NIST P-384 generator:

    1. ec_point_double_384(G)      -> 2G
    2. ec_point_add_384(G, 2G)     -> 3G
    3. Iterated doubling + adding  -> 17G
    4. ec_jacobian_to_affine_384   -> affine coordinates of a test point

Endian:
  - c64-nist-curves stores field elements LITTLE-ENDIAN (byte 0 = LSB),
    48 bytes per coordinate.
  - Python `cryptography` gives BE integer forms; we convert in-script.

Usage:
    BACKEND=uci python3 tools/test_p384_symbols.py [--verbose]

Skipping:
  - Under BACKEND=ip65, `ec_point_double_384` will not be in labels.txt
    (the archive is only linked under UCI). The script exits 0 with a
    skip message on that path.

Phase C.3 status:
  The nistcurves-p384.a archive is built and the force-link stub is in
  place, but the actual USE_NISTCURVES_P384 Makefile gate is commented
  out pending a cfg-level fix for the CRYPTO_OVERLAY region (ld65
  currently stacks OVERLAY_X25519 + OVERLAY_P384 sequentially instead
  of overlaying them — see the comment above those Makefile lines).
  Once the cfg is extended to stage one overlay outside the live slot,
  uncomment the gate and this script will find the P-384 symbols.
"""

import os
import subprocess
import sys

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

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

    # Parse labels.txt and check for the P-384 symbols.
    try:
        from c64_test_harness import (
            Labels, ViceConfig, ViceInstanceManager,
            read_bytes, write_bytes, jsr, wait_for_text,
        )
    except ImportError:
        print("FATAL: c64-test-harness package not installed")
        return 1

    labels = Labels.from_file(LABELS_PATH)

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
        "crypto_swap_to_x25519",  # to restore x25519 state after test
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        if backend != "uci":
            print(f"  SKIP: P-384 sibling not linked under BACKEND={backend}")
            print(f"  (missing labels: {', '.join(missing)})")
            return 0
        print(f"FATAL: P-384 symbols missing from labels.txt: {missing}")
        print("  The nistcurves-p384.a archive may not be linked; check the")
        print("  USE_NISTCURVES_P384 Makefile gate and the CRYPTO_OVERLAY")
        print("  cfg (ld65 must be able to place OVERLAY_P384 alongside")
        print("  OVERLAY_X25519 — see Phase C.3 cfg notes).")
        return 1

    print(f"  Labels loaded: {len(required)} P-384 symbols verified")

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

        # Safety: CPU-idle trampoline at $0339.
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Swap in the P-384 overlay.
        print("  Swapping CRYPTO_OVERLAY -> P-384 image")
        jsr(transport, labels["crypto_swap_to_p384"], timeout=30.0)

        # --- Test 1: ec_point_double_384(G) -> 2G ---
        print("\n--- Test 1: ec_point_double_384(G) ---")
        # Load G into ec384_p1 as Jacobian (X=Gx, Y=Gy, Z=1).
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        jsr(transport, labels["ec_point_double_384"], timeout=60.0)
        # Output lands in ec384_p3 (Jacobian). Convert to affine via the
        # library's own ec_jacobian_to_affine_384 for comparison.
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=60.0)
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
        # This test follows the c64-nist-curves ABI: ec_p1 + ec_p2 -> ec_p3
        # where ec_p2 must be in AFFINE form (X, Y; Z ignored).
        print("\n--- Test 2: ec_point_add_384(G, 2G) ---")
        # ec384_p1 = G (Jacobian)
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        # ec384_p2 = 2G (affine)
        write_bytes(transport, labels["ec384_p2"],       int_to_le48(exp_x))
        write_bytes(transport, labels["ec384_p2"] + 48,  int_to_le48(exp_y))
        jsr(transport, labels["ec_point_add_384"], timeout=60.0)
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=60.0)
        got_x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        got_y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        exp_x3, exp_y3 = scalar_mul_affine(3, GX_384, GY_384)
        if got_x == exp_x3 and got_y == exp_y3:
            print("  PASS 3G affine matches Python reference")
            passed += 1
        else:
            failed += 1
            print("  FAIL 3G mismatch")

        # --- Test 3: iterated double+add to 17G ---
        # 17G via double (2G, 4G, 8G, 16G) then add G.
        print("\n--- Test 3: iterated doubling -> 16G -> 17G ---")
        # Start with G in ec384_p1 and iterate double 4 times.
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        for _ in range(4):
            jsr(transport, labels["ec_point_double_384"], timeout=60.0)
            # Copy ec384_p3 back into ec384_p1 for next iteration.
            p3_bytes = read_bytes(transport, labels["ec384_p3"], 144)
            write_bytes(transport, labels["ec384_p1"], p3_bytes)
        # Now p1 = 16G. Convert to affine, then add G.
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=60.0)
        aff16x = read_bytes(transport, labels["ec384_affine_x"], 48)
        aff16y = read_bytes(transport, labels["ec384_affine_y"], 48)
        # ec384_p1 = 16G (Jacobian from ec384_p3, still there)
        write_bytes(transport, labels["ec384_p1"], p3_bytes)
        # ec384_p2 = G (affine)
        write_bytes(transport, labels["ec384_p2"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p2"] + 48,  int_to_le48(GY_384))
        jsr(transport, labels["ec_point_add_384"], timeout=60.0)
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=60.0)
        got_x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        got_y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        exp_x17, exp_y17 = scalar_mul_affine(17, GX_384, GY_384)
        if got_x == exp_x17 and got_y == exp_y17:
            print("  PASS 17G affine matches Python reference")
            passed += 1
        else:
            failed += 1
            print("  FAIL 17G mismatch")
            print(f"    exp_x = {exp_x17:#098x}")
            print(f"    got_x = {got_x:#098x}")

        # --- Test 4: ec_jacobian_to_affine with non-trivial Z ---
        # Feed the 2G-Jacobian result from test 1 back through; independent
        # verification that the conversion handles Z != 1 correctly.
        print("\n--- Test 4: ec_jacobian_to_affine_384 (Z != 1) ---")
        write_bytes(transport, labels["ec384_p1"],       int_to_le48(GX_384))
        write_bytes(transport, labels["ec384_p1"] + 48,  int_to_le48(GY_384))
        write_bytes(transport, labels["ec384_p1"] + 96,  int_to_le48(1))
        jsr(transport, labels["ec_point_double_384"], timeout=60.0)
        # Do NOT overwrite ec384_p3 — jacobian_to_affine reads from it.
        jsr(transport, labels["ec_jacobian_to_affine_384"], timeout=60.0)
        got_x = le48_to_int(read_bytes(transport, labels["ec384_affine_x"], 48))
        got_y = le48_to_int(read_bytes(transport, labels["ec384_affine_y"], 48))
        if got_x == exp_x and got_y == exp_y:
            print("  PASS jacobian_to_affine_384 matches 2G affine")
            passed += 1
        else:
            failed += 1
            print("  FAIL jacobian_to_affine_384 mismatch")

        # Restore x25519 overlay so subsequent tests (if any) aren't
        # left with P-384 resident.
        jsr(transport, labels["crypto_swap_to_x25519"], timeout=30.0)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
