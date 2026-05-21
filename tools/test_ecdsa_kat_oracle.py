#!/usr/bin/env python3
"""test_ecdsa_kat_oracle.py - Library-side KAT oracle for ECDSA P-256 verify.

Runs additional known-VALID P-256/SHA-256 signature vectors against the
C64's `ecdsa_verify` routine (the c64-https dispatcher over the
libs/nistcurves sibling). Mirrors the structure of
`tools/test_x509.py` group 3 subtest [3c] (call `setup_ecdsa_verify(...)`,
then `jsr_with_carry(... labels["ecdsa_verify"] ...)`, assert C=0) but
exercises 3 additional vectors so we can distinguish a primitive bug
from a [3c]-specific test-setup bug:

  - [3e] CAVP SigVer P-256/SHA-256 valid #1 (Result = P record)
  - [3f] CAVP SigVer P-256/SHA-256 valid #2
  - [3g] CAVP SigVer P-256/SHA-256 valid #3

Vectors are extracted verbatim from
`libs/nistcurves/tools/vectors/nist_p256_sigver.rsp` (NIST CAVP SigVer,
P-256/SHA-256 section), specifically the records flagged `Result = P`.
For each vector the hash is `SHA-256(Msg)`; r/s/Qx/Qy are taken straight
from the .rsp file in big-endian wire order, matching the BE struct ABI
of the sibling's `ecdsa_verify_256`.

Usage:
    python3 tools/test_ecdsa_kat_oracle.py [--verbose]

Honours `C64_SKIP_BUILD=1` for the same reason `test_x509.py` does.
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    goto,
    wait_for_text,
)

from _vice_helpers import default_vice_config

# ---------------------------------------------------------------------------
# Constants (mirrors tools/test_x509.py)
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

CARRY_TRAMPOLINE = 0x033C
CARRY_RESULT_ADDR = 0x0352
CARRY_FLAG_ADDR = 0x0353

CURVE_P256 = 0

ECDSA_LABELS = [
    "ecdsa_verify",
    "ecdsa_curve_id",
    "ecdsa_hash",
    "ecdsa_sig_r", "ecdsa_sig_s",
    "ecdsa_pubkey_x", "ecdsa_pubkey_y",
    "sqtab_init",
]


# ---------------------------------------------------------------------------
# Hardcoded P-256 known-VALID KAT vectors (CAVP SigVer, Result = P records)
# ---------------------------------------------------------------------------

KAT_VECTORS = [
    # CAVP SigVer P-256/SHA-256 valid record #1
    dict(
        tag="CAVP SigVer P-256/SHA-256 valid #1",
        hash=bytes.fromhex(
            "d1b8ef21eb4182ee270638061063a3f3"
            "c16c114e33937f69fb232cc833965a94"),
        r=bytes.fromhex(
            "bf96b99aa49c705c910be33142017c64"
            "2ff540c76349b9dab72f981fd9347f4f"),
        s=bytes.fromhex(
            "17c55095819089c2e03b9cd415abdf12"
            "444e323075d98f31920b9e0f57ec871c"),
        qx=bytes.fromhex(
            "e424dc61d4bb3cb7ef4344a7f8957a0c"
            "5134e16f7a67c074f82e6e12f49abf3c"),
        qy=bytes.fromhex(
            "970eed7aa2bc48651545949de1dddaf0"
            "127e5965ac85d1243d6f60e7dfaee927"),
    ),
    # CAVP SigVer P-256/SHA-256 valid record #2
    dict(
        tag="CAVP SigVer P-256/SHA-256 valid #2",
        hash=bytes.fromhex(
            "b9336a8d1f3e8ede001d19f41320bc76"
            "72d772a3d2cb0e435fff3c27d6804a2c"),
        r=bytes.fromhex(
            "1d75830cd36f4c9aa181b2c4221e87f1"
            "76b7f05b7c87824e82e396c88315c407"),
        s=bytes.fromhex(
            "cb2acb01dac96efc53a32d4a0d85d0c2"
            "e48955214783ecf50a4f0414a319c05a"),
        qx=bytes.fromhex(
            "e0fc6a6f50e1c57475673ee54e3a57f9"
            "a49f3328e743bf52f335e3eeaa3d2864"),
        qy=bytes.fromhex(
            "7f59d689c91e463607d9194d99faf316"
            "e25432870816dde63f5d4b373f12f22a"),
    ),
    # CAVP SigVer P-256/SHA-256 valid record #3
    dict(
        tag="CAVP SigVer P-256/SHA-256 valid #3",
        hash=bytes.fromhex(
            "41007876926a20f821d72d9c6f2c9dae"
            "6c03954123ea6e6939d7e6e669438891"),
        r=bytes.fromhex(
            "06108e525f845d0155bf60193222b321"
            "9c98e3d49424c2fb2a0987f825c17959"),
        s=bytes.fromhex(
            "62b5cdd591e5b507e560167ba8f6f7cd"
            "a74673eb315680cb89ccbc4eec477dce"),
        qx=bytes.fromhex(
            "2d98ea01f754d34bbc3003df5050200a"
            "bf445ec728556d7ed7d5c54c55552b6d"),
        qy=bytes.fromhex(
            "9b52672742d637a32add056dfd6d8792"
            "f2a33c2e69dafabea09b960bc61e230a"),
    ),
]

SUBTEST_LABELS = ["3e", "3f", "3g"]


# ---------------------------------------------------------------------------
# jsr_with_carry: copied verbatim from tools/test_x509.py
# ---------------------------------------------------------------------------

def jsr_with_carry(transport, addr, timeout=2400.0, poll_interval=30.0):
    lo = addr & 0xFF
    hi = (addr >> 8) & 0xFF
    result_lo = CARRY_RESULT_ADDR & 0xFF
    result_hi = (CARRY_RESULT_ADDR >> 8) & 0xFF
    flag_lo = CARRY_FLAG_ADDR & 0xFF
    flag_hi = (CARRY_FLAG_ADDR >> 8) & 0xFF
    loop_addr = CARRY_TRAMPOLINE + 19
    trampoline = bytes([
        0xA9, 0x00,
        0x8D, flag_lo, flag_hi,
        0x20, lo, hi,
        0xA9, 0x00,
        0x2A,
        0x8D, result_lo, result_hi,
        0xA9, 0xFF,
        0x8D, flag_lo, flag_hi,
        0x4C, loop_addr & 0xFF, loop_addr >> 8,
    ])
    write_bytes(transport, CARRY_TRAMPOLINE, trampoline)
    write_bytes(transport, CARRY_FLAG_ADDR, bytes([0x00]))
    goto(transport, CARRY_TRAMPOLINE)

    deadline = time.monotonic() + timeout
    while True:
        time.sleep(poll_interval)
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"jsr_with_carry(${addr:04X}) timed out after {timeout:.0f}s")
        try:
            flag = read_bytes(transport, CARRY_FLAG_ADDR, 1)
            if flag[0] == 0xFF:
                break
            transport.resume()
        except Exception:
            continue

    return read_bytes(transport, CARRY_RESULT_ADDR, 1)[0]


def setup_ecdsa_verify(transport, labels, msg_hash, r_bytes, s_bytes,
                       qx, qy, curve_id=CURVE_P256):
    write_bytes(transport, labels["ecdsa_curve_id"], bytes([curve_id]))
    write_bytes(transport, labels["ecdsa_hash"], msg_hash)
    write_bytes(transport, labels["ecdsa_sig_r"], r_bytes)
    write_bytes(transport, labels["ecdsa_sig_s"], s_bytes)
    write_bytes(transport, labels["ecdsa_pubkey_x"], qx)
    write_bytes(transport, labels["ecdsa_pubkey_y"], qy)


def check_labels(labels, label_list):
    for name in label_list:
        if labels.address(name) is None:
            print(f"  SKIP: label '{name}' not found")
            return False
    return True


def run_kat_oracle(transport, labels):
    passed = 0
    failed = 0

    if not check_labels(labels, ECDSA_LABELS):
        return 0, 0

    for idx, vec in enumerate(KAT_VECTORS):
        sub = SUBTEST_LABELS[idx]
        tag = vec["tag"]
        print(f"\n  [{sub}] ECDSA verify: {tag} (expected C=0)")
        if VERBOSE:
            print(f"       hash = {vec['hash'][:8].hex()}... r = {vec['r'][:8].hex()}...")
            print(f"       s    = {vec['s'][:8].hex()}... Qx = {vec['qx'][:8].hex()}... Qy = {vec['qy'][:8].hex()}...")
        setup_ecdsa_verify(transport, labels, vec["hash"], vec["r"], vec["s"],
                           vec["qx"], vec["qy"], CURVE_P256)
        c64_hash = read_bytes(transport, labels["ecdsa_hash"], 32)
        c64_r    = read_bytes(transport, labels["ecdsa_sig_r"], 32)
        c64_s    = read_bytes(transport, labels["ecdsa_sig_s"], 32)
        c64_qx   = read_bytes(transport, labels["ecdsa_pubkey_x"], 32)
        c64_qy   = read_bytes(transport, labels["ecdsa_pubkey_y"], 32)
        c64_cid  = read_bytes(transport, labels["ecdsa_curve_id"], 1)[0]
        if VERBOSE:
            print(f"       readback: hash={c64_hash[:4].hex()}...{c64_hash[-4:].hex()} "
                  f"r={c64_r[:4].hex()}...{c64_r[-4:].hex()} "
                  f"s={c64_s[:4].hex()}...{c64_s[-4:].hex()} "
                  f"Qx={c64_qx[:4].hex()}...{c64_qx[-4:].hex()} "
                  f"Qy={c64_qy[:4].hex()}...{c64_qy[-4:].hex()} cid={c64_cid}")
        all_match = (c64_hash == vec["hash"] and c64_r == vec["r"]
                     and c64_s == vec["s"] and c64_qx == vec["qx"]
                     and c64_qy == vec["qy"] and c64_cid == CURVE_P256)
        if not all_match:
            failed += 1
            print(f"       FAIL: input staging mismatch (read-back diverges from intent)")
            continue

        try:
            t0 = time.time()
            carry = jsr_with_carry(transport, labels["ecdsa_verify"],
                                   timeout=2400.0, poll_interval=30.0)
            elapsed = time.time() - t0
            if carry == 0:
                passed += 1
                print(f"       PASS: ecdsa_verify returned C=0 (valid) [{elapsed:.0f}s]")
            else:
                failed += 1
                print(f"       FAIL: ecdsa_verify returned C=1 (invalid) [{elapsed:.0f}s]")
                print(f"         hash:  {c64_hash.hex()}")
                print(f"         r:     {c64_r.hex()}")
                print(f"         s:     {c64_s.hex()}")
                print(f"         Qx:    {c64_qx.hex()}")
                print(f"         Qy:    {c64_qy.hex()}")
        except Exception as e:
            failed += 1
            print(f"       FAIL: {e}")

    return passed, failed


def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    args = sys.argv[1:]
    if "--verbose" in args:
        VERBOSE = True

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building ===")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)
        print(f"  Build OK: {PRG_PATH}")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)

    if not check_labels(labels, ECDSA_LABELS):
        print("\nFATAL: ECDSA verify labels missing; nothing to test.")
        sys.exit(1)

    print(f"\n  Labels loaded from {LABELS_PATH}")
    print(f"  Vectors to run: {len(KAT_VECTORS)} (CAVP SigVer P-256/SHA-256 valid)")
    print(f"  Per-vector wallclock budget: 2400 s (VICE warp; typical ~5-16 min)")

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"\n=== Starting VICE ===")
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready")

        print(f"\n=== Initialising sqtab (quarter-square multiply tables) ===")
        try:
            jsr(transport, labels["sqtab_init"], timeout=60.0)
            print("  sqtab_init OK")
        except Exception as e:
            print(f"  sqtab_init FAILED: {e}")
            sys.exit(1)

        print(f"\n=== ECDSA P-256 KAT oracle ({len(KAT_VECTORS)} valid vectors) ===")
        passed, failed = run_kat_oracle(transport, labels)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
