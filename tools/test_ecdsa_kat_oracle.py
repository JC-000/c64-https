#!/usr/bin/env python3
"""test_ecdsa_kat_oracle.py - Library-side KAT oracle for ECDSA P-256 verify.

Runs CAVP P-256/SHA-256 signature vectors against the C64's `ecdsa_verify`
routine (the c64-https dispatcher over the libs/nistcurves sibling). Mirrors
the structure of `tools/test_x509.py` group 3 subtest [3c] (call
`setup_ecdsa_verify(...)`, then `jsr_with_carry(... labels["ecdsa_verify"] ...)`,
assert the carry) but exercises additional vectors so we can distinguish a
primitive bug from a [3c]-specific test-setup bug:

  - [3e] CAVP SigVer P-256/SHA-256 valid   #1  (Result = P) -> expect C=0
  - [3f] CAVP SigVer P-256/SHA-256 valid   #2  (Result = P) -> expect C=0
  - [3g] CAVP SigVer P-256/SHA-256 valid   #3  (Result = P) -> expect C=0
  - [3h] CAVP SigVer P-256/SHA-256 invalid #1  (Result = F, S changed)   -> C=1
  - [3i] CAVP SigVer P-256/SHA-256 invalid #2  (Result = F, R changed)   -> C=1
  - [3j] CAVP SigVer P-256/SHA-256 invalid #3  (Result = F, Msg changed) -> C=1

Negative vectors (audit finding F7)
-----------------------------------
This oracle originally ran three vectors, all valid, all expecting C=0.
That cannot distinguish a working verifier from one that reports "valid"
unconditionally: against an `ecdsa_verify` stubbed to `clc; rts` it happily
reported 3/3. An oracle with no negative case does not test verification,
it tests that the routine returns.

The three `Result = F` records above close that. They are genuine CAVP
records, not signatures manufactured by mutating a valid one and not
anything produced by running this implementation.

Every `Result = F` record in the file has Q on the curve and r, s in
[1, n-1] (checked host-side, see below), so none of them can be rejected by
a cheap range or point-validity gate — each one forces the full verify math
and compares the recovered R.x against r. One record per CAVP modification
class is included: 3 (S changed), 2 (R changed), 1 (Message changed).

Provenance
----------
Vectors are extracted verbatim from
`libs/nistcurves/tools/vectors/nist_p256_sigver.rsp` (NIST CAVP SigVer,
P-256/SHA-256 section). For each vector the hash is `SHA-256(Msg)`;
r/s/Qx/Qy are taken straight from the .rsp file in big-endian wire order,
matching the BE struct ABI of the sibling's `ecdsa_verify_256`.

Every vector below — positive and negative — was independently confirmed
host-side against OpenSSL via the `cryptography` package before being added
here: all 15 records in the .rsp agreed with their Result column, with Q on
curve and r, s in range. The `expect_carry` field encodes the .rsp Result
column (P -> 0, F -> 1), never an observed C64 result.

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
# Hardcoded P-256 KAT vectors (CAVP SigVer, both Result = P and Result = F)
#
# `expect_carry` mirrors the .rsp Result column: P (valid) -> C=0,
# F (invalid) -> C=1. See the module docstring for provenance and for why
# the negative records are load-bearing (audit finding F7).
# ---------------------------------------------------------------------------

KAT_VECTORS = [
    # --- Result = P (valid) --------------------------------------------
    # CAVP SigVer P-256/SHA-256 valid record #1
    dict(
        tag="CAVP SigVer P-256/SHA-256 valid #1",
        expect_carry=0,
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
        expect_carry=0,
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
        expect_carry=0,
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

    # --- Result = F (invalid) ------------------------------------------
    # These are what make this file an oracle rather than a smoke test:
    # a verify that answers "valid" unconditionally passes every vector
    # above and fails every vector below. Q is on the curve and r, s are in
    # [1, n-1] for all three, so none is rejectable by a cheap gate.
    #
    # CAVP SigVer P-256/SHA-256 invalid record, "Result = F (3 - S changed)"
    dict(
        tag="CAVP SigVer P-256/SHA-256 invalid #1 (F: S changed)",
        expect_carry=1,
        hash=bytes.fromhex(
            "a82c31412f537135d1c418bd7136fb5f"
            "de9426e70c70e7c2fb11f02f30fdeae2"),
        r=bytes.fromhex(
            "d19ff48b324915576416097d2544f7cb"
            "df8768b1454ad20e0baac50e211f23b0"),
        s=bytes.fromhex(
            "a3e81e59311cdfff2d4784949f7a2cb5"
            "0ba6c3a91fa54710568e61aca3e847c6"),
        qx=bytes.fromhex(
            "87f8f2b218f49845f6f10eec38771362"
            "69f5c1a54736dbdf69f89940cad41555"),
        qy=bytes.fromhex(
            "e15f369036f49842fac7a86c8a2b0557"
            "609776814448b8f5e84aa9f4395205e9"),
    ),
    # CAVP SigVer P-256/SHA-256 invalid record, "Result = F (2 - R changed)"
    dict(
        tag="CAVP SigVer P-256/SHA-256 invalid #2 (F: R changed)",
        expect_carry=1,
        hash=bytes.fromhex(
            "5984eab8854d0a9aa5f0c70f96deeb51"
            "0e5f9ff8c51befcdc3c41bac53577f22"),
        r=bytes.fromhex(
            "dc23d130c6117fb5751201455e99f36f"
            "59aba1a6a21cf2d0e7481a97451d6693"),
        s=bytes.fromhex(
            "d6ce7708c18dbf35d4f8aa7240922dc6"
            "823f2e7058cbc1484fcad1599db5018c"),
        qx=bytes.fromhex(
            "5cf02a00d205bdfee2016f7421807fc3"
            "8ae69e6b7ccd064ee689fc1a94a9f7d2"),
        qy=bytes.fromhex(
            "ec530ce3cc5c9d1af463f264d685afe2"
            "b4db4b5828d7e61b748930f3ce622a85"),
    ),
    # CAVP SigVer P-256/SHA-256 invalid record, "Result = F (1 - Message changed)"
    dict(
        tag="CAVP SigVer P-256/SHA-256 invalid #3 (F: Message changed)",
        expect_carry=1,
        hash=bytes.fromhex(
            "d80e9933e86769731ec16ff31e682153"
            "1bcf07fcbad9e2ac16ec9e6cb343a870"),
        r=bytes.fromhex(
            "288f7a1cd391842cce21f00e6f15471c"
            "04dc182fe4b14d92dc18910879799790"),
        s=bytes.fromhex(
            "247b3c4e89a3bcadfea73c7bfd361def"
            "43715fa382b8c3edf4ae15d6e55e9979"),
        qx=bytes.fromhex(
            "69b7667056e1e11d6caf6e45643f8b21"
            "e7a4bebda463c7fdbc13bc98efbd0214"),
        qy=bytes.fromhex(
            "d3f9b12eb46c7c6fda0da3fc85bc1fd8"
            "31557f9abc902a3be3cb3e8be7d1aa2f"),
    ),
]

SUBTEST_LABELS = ["3e", "3f", "3g", "3h", "3i", "3j"]


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
        want = vec["expect_carry"]
        want_word = "valid" if want == 0 else "INVALID"
        print(f"\n  [{sub}] ECDSA verify: {tag} (expected C={want}, {want_word})")
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
            got_word = "valid" if carry == 0 else "invalid"
            if carry == want:
                passed += 1
                print(f"       PASS: ecdsa_verify returned C={carry} "
                      f"({got_word}) [{elapsed:.0f}s]")
            else:
                failed += 1
                print(f"       FAIL: ecdsa_verify returned C={carry} ({got_word}), "
                      f"expected C={want} ({want_word}) [{elapsed:.0f}s]")
                if want == 1:
                    print("         A CAVP Result=F vector was accepted. The "
                          "verifier is reporting")
                    print("         signatures valid that NIST says are not.")
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

    n_pos = sum(1 for v in KAT_VECTORS if v["expect_carry"] == 0)
    n_neg = sum(1 for v in KAT_VECTORS if v["expect_carry"] == 1)

    # Structural guard against audit finding F7 regressing: an oracle made up
    # entirely of valid signatures cannot fail against a verifier that always
    # answers "valid", so it is not an oracle.
    if n_neg == 0:
        print("\nFATAL: KAT_VECTORS contains no Result=F (expect_carry=1) vector.")
        print("       An all-positive vector set passes against a verify stubbed")
        print("       to 'clc; rts' and therefore proves nothing. See F7.")
        sys.exit(1)

    print(f"\n  Labels loaded from {LABELS_PATH}")
    print(f"  Vectors to run: {len(KAT_VECTORS)} CAVP SigVer P-256/SHA-256 "
          f"({n_pos} valid / {n_neg} invalid)")
    print(f"  Per-vector wallclock budget: 2400 s (VICE warp; typical ~5-16 min)")

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"\n=== Starting VICE ===")
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        # Comb-profile boots run ec_precompute_256 (256 point mults) before
        # the menu — minutes of VICE time even under warp. Overridable.
        _menu_to = float(os.environ.get("C64_INIT_TIMEOUT", "60"))
        grid = wait_for_text(transport, "Q=QUIT", timeout=_menu_to, verbose=False)
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

        print(f"\n=== ECDSA P-256 KAT oracle "
              f"({n_pos} valid + {n_neg} invalid vectors) ===")
        passed, failed = run_kat_oracle(transport, labels)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if total != len(KAT_VECTORS):
        # Every declared vector must produce a verdict; a vector that silently
        # dropped out is the same class of defect as F3's skipped group.
        print(f"\n  [-] ECDSA KAT oracle: only {total} of "
              f"{len(KAT_VECTORS)} declared vectors produced a verdict")
        sys.exit(1)
    if failed == 0:
        print(f"\n  [+] ECDSA KAT oracle: ALL {total} VECTORS PASSED "
              f"({n_pos} valid accepted, {n_neg} invalid rejected)")
    else:
        print(f"\n  [-] ECDSA KAT oracle: {failed} VECTOR(S) FAILED")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
