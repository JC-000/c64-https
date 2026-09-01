#!/usr/bin/env python3
"""Run all c64-https test suites in parallel using ViceInstanceManager.

Usage:
    python3 tools/run_all_tests.py [--workers N] [--seed S] [--skip-slow]
"""

import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PRG_PATH = os.path.join("build", "c64-https.prg")
LABELS_PATH = os.path.join("build", "labels.txt")

# Import each test module's run function
sys.path.insert(0, "tools")


# The suites this runner covers, in launch order, and the single source of
# truth for that set: main() schedules exactly these and run_test_suite()
# must carry an arm for each. Ordering is a scheduling hint, not policy —
# x509 is by far the slowest (~5 min for the ECDSA verify) so it goes first,
# and entropy uses manual breakpoints sensitive to CPU state so it wants an
# early, fresh worker. The rest fill in around them.
#
# tools/test_runner_coverage.py asserts by AST that this list, plus
# UNDISPATCHED_SUITES below, accounts for every tools/test_*.py defining a
# module-level run_tests() — the interface this runner dispatches through.
# Adding a suite and forgetting to wire it here is a test failure, not a
# silently smaller TOTAL (issue #169).
SUITE_ORDER = (
    "x509",
    "entropy",
    "net",
    "sha256",
    "crypto",
    "hkdf",
    "keyschedule",
    "http",
    "tls_record",
    "tls_handshake",
    "x25519",
    "finished_verify",
    "ecdh_zero_check",
    "hs_sequence",
)

# Suites that define run_tests() but are deliberately NOT dispatched here,
# as {module: why}. Anything absent from both this and SUITE_ORDER fails
# tools/test_runner_coverage.py.
UNDISPATCHED_SUITES = {
    "test_tls_deframer": (
        "does not speak this runner's interface: run_tests() takes "
        "(transport, labels, cert_der, pubkey_xy, wiki_leaf) and returns a "
        "4-tuple (plumb_pass, plumb_fail, defr_pass, defr_fail), not "
        "(passed, failed). It also needs minted cert fixtures and a "
        "BACKEND=uci build -- its deframer scenarios are an acceptance gate "
        "that xfails by design on the ip65 build this runner produces, so "
        "folding it into the TOTAL would report expected xfails as "
        "regressions. Run it directly: python3 tools/test_tls_deframer.py"
    ),
}


def build():
    print("=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Build FAILED:\n{result.stderr}")
        sys.exit(1)
    print("  Build OK")
    return Labels.from_file(LABELS_PATH)


def run_test_suite(name, transport, labels, seed):
    """Run a single test suite, return (name, passed, failed, duration)."""
    # Ensure CPU is running before each suite (previous suite leaves it paused
    # after jsr() returns at a breakpoint)
    transport.resume()
    start = time.time()
    passed = failed = 0

    try:
        if name == "net":
            from test_net import run_tests as net_run
            passed, failed = net_run(transport, labels)

        elif name == "sha256":
            from test_sha256 import run_tests as sha256_run
            passed, failed = sha256_run(transport, labels, iterations=5)

        elif name == "crypto":
            from test_crypto import run_tests as crypto_run
            passed, failed = crypto_run(transport, labels, seed=seed)

        elif name == "hkdf":
            from test_hkdf import run_tests as hkdf_run
            passed, failed = hkdf_run(transport, labels)

        elif name == "tls_record":
            from test_tls_record import run_tests as record_run
            passed, failed = record_run(transport, labels, seed=seed)

        elif name == "tls_handshake":
            from test_tls_handshake import run_tests as handshake_run
            passed, failed = handshake_run(transport, labels, seed=seed)

        elif name == "keyschedule":
            from test_keyschedule_steps import run_tests as ks_run
            passed, failed = ks_run(transport, labels)

        elif name == "entropy":
            from test_entropy import run_tests as entropy_run
            passed, failed = entropy_run(transport, labels)

        elif name == "http":
            from test_http import run_tests as http_run
            passed, failed = http_run(transport, labels)

        elif name == "x509":
            from test_x509 import run_tests as x509_run
            passed, failed = x509_run(transport, labels)

        elif name == "finished_verify":
            # Known off-profile result, found while wiring this in and NOT
            # caused by it: on a BACKEND=uci build the two `positive` cases
            # fail while all 16 rejects pass. tls_verify_finished compares
            # against (tls_hs_ptr)+4 and skips tls_hs_ptr_reset under
            # TLS_STREAM_DEFRAME (src/tls_keyschedule.s), because the
            # deframer is meant to have set the pointer; this suite drives
            # the routine over DMA with no deframer in the loop, so the
            # comparison reads a stale pointer. The computed verify_data is
            # byte-correct, so it is the rig's contract with the streaming
            # build that is broken, not the crypto. Measured both ways at
            # this commit: 18/18 on ip65, 16/18 on uci -- and build() below
            # produces the ip65 (non-streaming) PRG, so dispatching it here
            # is safe. Tracked under issue #161, whose first item is the
            # same tls_hs_ptr defect seen from the other side (the 16
            # negatives passing vacuously on UCI).
            from test_finished_verify import run_tests as finished_run
            passed, failed = finished_run(transport, labels)

        elif name == "ecdh_zero_check":
            from test_ecdh_zero_check import run_tests as ecdh_zero_run
            passed, failed = ecdh_zero_run(transport, labels)

        elif name == "hs_sequence":
            # Needs a TLS_STREAM_DEFRAME build; main() drops it from the
            # schedule (as an accounted SKIP) when tls_deframe_pump is
            # absent, so reaching here means the label exists.
            from test_hs_sequence import run_tests as hs_sequence_run
            passed, failed = hs_sequence_run(transport, labels)

        elif name == "x25519":
            from test_x25519 import run_tests as x25519_run
            # run_tests also reports groups it skipped. This caller never
            # sets test_x25519.FAST, so the RFC 7748 scalarmult vectors
            # always run here (+~33 s) and the list is empty; assert it
            # rather than dropping it, so a future gate cannot silently
            # remove coverage from the aggregate verdict.
            passed, failed, x25519_skipped = x25519_run(
                transport, labels, seed=seed)
            if x25519_skipped:
                raise AssertionError(
                    "x25519 suite skipped groups in the aggregate run: "
                    + ", ".join(x25519_skipped))

        else:
            # Never fall through. Without this, a SUITE_ORDER name with no
            # arm returns 0 passed / 0 failed and lands in the summary as a
            # clean PASS that ran nothing.
            raise ValueError(
                f"no dispatch arm for suite {name!r}; add one here or "
                "remove it from SUITE_ORDER")

    except Exception as e:
        import traceback
        print(f"  [{name}] EXCEPTION: {e}")
        traceback.print_exc()
        failed += 1

    duration = time.time() - start
    return name, passed, failed, duration


def main():
    workers = 4
    seed = random.randint(0, 2**32 - 1)
    skip_slow = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--workers":
            workers = int(args[i + 1])
            i += 2
        elif args[i] == "--seed":
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--skip-slow":
            skip_slow = True
            i += 1
        else:
            i += 1

    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    labels = build()

    suites = list(SUITE_ORDER)

    # Suites deliberately not run this session, as (name, reason). --skip-slow
    # used to drop x509 by simply never adding it to the list, so the aggregate
    # printed a TOTAL and exited 0 with no trace that the entire X.509/ECDSA
    # suite had not run. That is audit finding F3's shape one level up: the
    # skipped assertions left the denominator instead of being accounted for.
    # An explicit operator flag is a legitimate reason to skip; it is not a
    # licence to report an unqualified clean pass.
    skipped_suites = []
    if skip_slow:
        suites.remove("x509")
        skipped_suites.append(
            ("x509", "--skip-slow (X.509 DER parsing + ECDSA P-256 verify)"))

    # The handshake-sequence gate (#152) drives tls_deframe_pump, which only
    # exists under TLS_STREAM_DEFRAME -- ON for BACKEND=uci, compiled out for
    # the ip65 build() produces by default. Reported as an accounted SKIP
    # rather than dropped silently: the ip65 arm carries the same gate inline
    # in tls_recv_encrypted, and it is genuinely uncovered by this run.
    # Cover it with `BACKEND=uci python3 tools/run_all_tests.py`, which
    # build()'s bare `make` picks up from the environment (Makefile: BACKEND ?=).
    if labels.address("tls_deframe_pump") is None:
        suites.remove("hs_sequence")
        skipped_suites.append((
            "hs_sequence",
            "tls_deframe_pump absent -- not a TLS_STREAM_DEFRAME build "
            "(rerun with BACKEND=uci)"))

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    num_instances = min(workers, len(suites))

    print(f"\n=== Launching {len(suites)} suites across "
          f"{num_instances} concurrent VICE instances ===")

    def run_suite_in_own_instance(mgr, suite_name):
        """Acquire a fresh VICE instance, run one suite, release."""
        inst = mgr.acquire()
        try:
            grid = wait_for_text(inst.transport, "Q=QUIT", timeout=120.0,
                                 verbose=False)
            if grid is None:
                return suite_name, 0, 1, 0.0
            # Safety loop: JMP $0339 prevents crash when BASIC ROM banked out
            write_bytes(inst.transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

            return run_test_suite(suite_name, inst.transport, labels, seed)
        finally:
            mgr.release(inst)

    results = []

    with ViceInstanceManager(config=config) as mgr:
        with ThreadPoolExecutor(max_workers=num_instances) as pool:
            futures = {
                pool.submit(run_suite_in_own_instance, mgr, suite): suite
                for suite in suites
            }

            for fut in as_completed(futures):
                name, passed, failed, duration = fut.result()
                status = "PASS" if failed == 0 else "FAIL"
                results.append((name, passed, failed, duration))
                print(f"  [{status}] {name}: {passed}/{passed+failed} "
                      f"({duration:.1f}s)")

    # Summary
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    total_tests = total_passed + total_failed

    skipped_note = ""
    if skipped_suites:
        skipped_note = (f" -- {len(skipped_suites)} suite(s) SKIPPED: "
                        + ", ".join(n for n, _ in skipped_suites))

    print(f"\n{'='*60}")
    print(f"TOTAL: {total_passed}/{total_tests} passed, "
          f"{total_failed} failed{skipped_note}")
    for name, passed, failed, duration in sorted(results):
        status = "OK" if failed == 0 else "FAIL"
        print(f"  {status:4s} {name:20s} {passed:3d}/{passed+failed:3d} "
              f"({duration:.1f}s)")
    for name, reason in skipped_suites:
        print(f"  SKIP {name:20s}   ---   did not run: {reason}")
    if skipped_suites:
        print("\n  WARNING: the suite(s) above did not run. This aggregate "
              "result does not")
        print("           certify them, and their assertions are absent from "
              "the TOTAL.")
    print(f"{'='*60}")

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
