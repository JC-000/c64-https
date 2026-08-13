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

    # x509 is by far the slowest (~5 min for ECDSA verify), so start it first.
    # Entropy uses manual breakpoints sensitive to CPU state, so start it early
    # on a fresh worker. Remaining fast suites fill in around them.
    suites = ["entropy", "net", "sha256", "crypto", "hkdf",
              "keyschedule", "http", "tls_record", "tls_handshake",
              "x25519"]
    if not skip_slow:
        suites.insert(0, "x509")

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

    print(f"\n{'='*60}")
    print(f"TOTAL: {total_passed}/{total_tests} passed, "
          f"{total_failed} failed")
    for name, passed, failed, duration in sorted(results):
        status = "OK" if failed == 0 else "FAIL"
        print(f"  {status:4s} {name:20s} {passed:3d}/{passed+failed:3d} "
              f"({duration:.1f}s)")
    print(f"{'='*60}")

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
