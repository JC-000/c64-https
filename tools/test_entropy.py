#!/usr/bin/env python3
"""test_entropy.py - Entropy/DRBG initialization test suite for c64-https.

Tests that entropy_init configures SID/CIA hardware correctly, that
drbg_init_entropy collects non-zero seed data, and that DRBG output
is non-degenerate (non-zero, non-repeating).

Usage:
    python3 tools/test_entropy.py [--verbose] [--seed <int>]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import os
import subprocess
import sys
from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    set_breakpoint,
    delete_breakpoint,
    goto,
    wait_for_pc,
    wait_for_text,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Scratch area for trampolines (C64 cassette buffer)
SCRATCH_ADDR = 0x0334

REQUIRED_LABELS = [
    "entropy_init",
    "drbg_init_entropy",
    "drbg_random_byte",
    "drbg_fill_bytes",
    "drbg_seed",
    "drbg_output",
    "drbg_buf_idx",
    "input_buffer",
]

VERBOSE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def jsr_with_a(transport, addr, a_value, timeout=120.0):
    """Call a subroutine with the A register set to a_value.

    Builds a trampoline at SCRATCH_ADDR:
        LDA #a_value   ; $A9, a_value   (2 bytes)
        JSR addr       ; $20, lo, hi    (3 bytes)
        NOP            ;                (1 byte) <- breakpoint
        NOP            ;                (1 byte)

    Breakpoint at SCRATCH_ADDR + 5, then goto SCRATCH_ADDR.
    """
    lo = addr & 0xFF
    hi = (addr >> 8) & 0xFF
    trampoline = bytes([0xA9, a_value, 0x20, lo, hi, 0xEA, 0xEA])
    write_bytes(transport, SCRATCH_ADDR, trampoline)
    bp_addr = SCRATCH_ADDR + 5
    bp_id = set_breakpoint(transport, bp_addr)
    try:
        goto(transport, SCRATCH_ADDR)
        wait_for_pc(transport, bp_addr, timeout=timeout)
    finally:
        delete_breakpoint(transport, bp_id)


def jsr_fill_bytes(transport, labels, dest_addr, count):
    """Call drbg_fill_bytes with zp_ptr ($FB-$FC) = dest_addr, A = count.

    Sets up the zero-page pointer, then uses a trampoline to call
    drbg_fill_bytes with the byte count in the A register.
    """
    # Set up zp_ptr ($FB-$FC) with destination address (little-endian)
    write_bytes(transport, 0xFB, bytes([dest_addr & 0xFF, (dest_addr >> 8) & 0xFF]))
    # Call drbg_fill_bytes with A = count
    jsr_with_a(transport, labels["drbg_fill_bytes"], count)


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_sid_noise_waveform(transport):
    """Test 1: SID voice 3 configured for noise waveform.

    After boot, $D412 (SID voice 3 control register) should have bit 7 set,
    indicating the noise waveform is selected for entropy collection.
    """
    print("\n--- Test 1: SID voice 3 noise waveform ---")

    sid_ctrl = read_bytes(transport, 0xD412, 1)
    if sid_ctrl[0] & 0x80 == 0x80:
        print(f"  PASS: SID voice 3 control = ${sid_ctrl[0]:02X} (bit 7 set, noise mode)")
        return True
    else:
        print(f"  FAIL: SID voice 3 control = ${sid_ctrl[0]:02X} (bit 7 not set)")
        return False


def test_cia1_timer_running(transport):
    """Test 2: CIA1 Timer A is running.

    After boot, $DC0E (CIA1 control register A) should have bit 0 set,
    indicating Timer A is started for entropy sampling.
    """
    print("\n--- Test 2: CIA1 Timer A running ---")

    cia_cra = read_bytes(transport, 0xDC0E, 1)
    if cia_cra[0] & 0x01 == 0x01:
        print(f"  PASS: CIA1 CRA = ${cia_cra[0]:02X} (bit 0 set, timer running)")
        return True
    else:
        print(f"  FAIL: CIA1 CRA = ${cia_cra[0]:02X} (bit 0 not set)")
        return False


def test_drbg_seed_nonzero(transport, labels):
    """Test 3: DRBG seed is not all zeros.

    After boot, drbg_init_entropy should have collected 32 bytes of
    SID/CIA entropy. The seed must not be all zeros.
    """
    print("\n--- Test 3: DRBG seed not all zeros ---")

    seed = read_bytes(transport, labels["drbg_seed"], 32)
    if any(b != 0 for b in seed):
        nonzero = sum(1 for b in seed if b != 0)
        print(f"  PASS: drbg_seed has {nonzero}/32 non-zero bytes")
        if VERBOSE:
            print(f"    Seed: {seed.hex()}")
        return True
    else:
        print(f"  FAIL: drbg_seed is all zeros (no entropy collected)")
        return False


def test_drbg_fill_nonzero(transport, labels):
    """Test 4: drbg_fill_bytes produces non-zero output.

    Call drbg_fill_bytes to fill input_buffer with 32 bytes, then
    verify the output is not all zeros.
    """
    print("\n--- Test 4: DRBG fill produces non-zero output ---")

    dest = labels["input_buffer"]

    # Clear destination first to ensure we detect actual output
    write_bytes(transport, dest, b'\x00' * 32)

    try:
        jsr_fill_bytes(transport, labels, dest, 32)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    output = read_bytes(transport, dest, 32)

    if any(b != 0 for b in output):
        nonzero = sum(1 for b in output if b != 0)
        print(f"  PASS: DRBG output has {nonzero}/32 non-zero bytes")
        if VERBOSE:
            print(f"    Output: {output.hex()}")
        return True
    else:
        print(f"  FAIL: DRBG output is all zeros")
        return False


def test_drbg_fill_differs(transport, labels):
    """Test 5: Two consecutive fills produce different output.

    Call drbg_fill_bytes twice with 32 bytes each. The two outputs
    should differ (DRBG state advances after each generate).
    """
    print("\n--- Test 5: Two fills produce different output ---")

    dest = labels["input_buffer"]

    try:
        # First fill
        jsr_fill_bytes(transport, labels, dest, 32)
        output1 = read_bytes(transport, dest, 32)

        # Second fill
        jsr_fill_bytes(transport, labels, dest, 32)
        output2 = read_bytes(transport, dest, 32)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if output1 != output2:
        print(f"  PASS: Two fills differ")
        if VERBOSE:
            print(f"    Fill 1: {output1.hex()}")
            print(f"    Fill 2: {output2.hex()}")
        return True
    else:
        print(f"  FAIL: Two fills produced identical output")
        print(f"    Output: {output1.hex()}")
        return False


def test_drbg_random_byte_varies(transport, labels):
    """Test 6: drbg_random_byte produces varying values.

    Call drbg_fill_bytes with length=1 ten times to a scratch byte,
    collecting each result. Verify at least 2 unique values.
    """
    print("\n--- Test 6: Random byte produces varying values ---")

    dest = labels["input_buffer"]
    values = []

    try:
        for i in range(10):
            # Use drbg_fill_bytes with count=1 to get one random byte
            jsr_fill_bytes(transport, labels, dest, 1)
            result = read_bytes(transport, dest, 1)
            values.append(result[0])
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    unique = len(set(values))
    if unique >= 2:
        print(f"  PASS: {unique} unique values in 10 random bytes: {[f'${v:02X}' for v in values]}")
        return True
    else:
        print(f"  FAIL: Only {unique} unique value(s) in 10 random bytes: {[f'${v:02X}' for v in values]}")
        return False


def test_reseed_differs(transport, labels, original_seed):
    """Test 7: Re-initialization produces a different seed.

    Call drbg_init_entropy again and verify the new seed differs
    from the original seed captured at boot time (new entropy collected).
    """
    print("\n--- Test 7: Re-seed produces different seed ---")

    try:
        jsr(transport, labels["drbg_init_entropy"], timeout=60.0)
    except Exception as e:
        print(f"  FAIL: jsr(drbg_init_entropy) raised {e}")
        return False

    new_seed = read_bytes(transport, labels["drbg_seed"], 32)

    if new_seed != original_seed:
        # Count differing bytes
        diff_count = sum(1 for a, b in zip(new_seed, original_seed) if a != b)
        print(f"  PASS: New seed differs from original ({diff_count}/32 bytes changed)")
        if VERBOSE:
            print(f"    Original: {original_seed.hex()}")
            print(f"    New:      {new_seed.hex()}")
        return True
    else:
        print(f"  FAIL: New seed is identical to original")
        print(f"    Seed: {new_seed.hex()}")
        return False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels):
    """Run all entropy/DRBG tests. Returns (passed, failed)."""
    passed = 0
    failed = 0

    def tally(ok):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1

    # Test 1: SID voice 3 noise waveform
    tally(test_sid_noise_waveform(transport))

    # Test 2: CIA1 Timer A running
    tally(test_cia1_timer_running(transport))

    # Test 3: DRBG seed not all zeros — save for test 7
    original_seed = read_bytes(transport, labels["drbg_seed"], 32)
    seed_ok = any(b != 0 for b in original_seed)
    nonzero = sum(1 for b in original_seed if b != 0)
    print(f"\n--- Test 3: DRBG seed not all zeros ---")
    if seed_ok:
        print(f"  PASS: drbg_seed has {nonzero}/32 non-zero bytes")
        if VERBOSE:
            print(f"    Seed: {original_seed.hex()}")
    else:
        print(f"  FAIL: drbg_seed is all zeros (no entropy collected)")
    tally(seed_ok)

    # Test 4: DRBG fill produces non-zero output
    tally(test_drbg_fill_nonzero(transport, labels))

    # Test 5: Two fills produce different output
    tally(test_drbg_fill_differs(transport, labels))

    # Test 6: Random byte varies
    tally(test_drbg_random_byte_varies(transport, labels))

    # Test 7: Re-seed produces different seed
    tally(test_reseed_differs(transport, labels, original_seed))

    return passed, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global VERBOSE

    os.chdir(PROJECT_ROOT)

    if "--verbose" in sys.argv:
        VERBOSE = True

    # Parse --seed <value> for deterministic VICE runs
    # NOTE: ViceConfig should natively support a `seed` parameter so callers
    # don't have to smuggle it through extra_args.  File a feature request
    # against c64-test-harness for v0.5.0.
    vice_seed = None
    if "--seed" in sys.argv:
        idx = sys.argv.index("--seed")
        if idx + 1 < len(sys.argv):
            vice_seed = sys.argv[idx + 1]

    # Build
    print("=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Build failed:\n{result.stderr}")
        sys.exit(1)
    print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    for name in REQUIRED_LABELS:
        if labels.address(name) is None:
            print(f"FATAL: required label '{name}' not found")
            sys.exit(1)
    print(f"  Labels loaded, drbg_seed at ${labels['drbg_seed']:04X}")

    # Start VICE
    print("\n=== Starting VICE ===")
    extra = ["-seed", vice_seed] if vice_seed else []
    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
        extra_args=extra,
    )

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        # Wait for main menu
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready (DRBG already seeded at startup)")

        # Run tests
        print(f"\n=== Entropy/DRBG Tests (7 total) ===")
        passed, failed = run_tests(transport, labels)

        mgr.release(inst)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] Entropy/DRBG: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] Entropy/DRBG: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
