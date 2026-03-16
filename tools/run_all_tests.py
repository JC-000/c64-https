#!/usr/bin/env python3
"""Run all c64-https test suites in parallel using ViceInstanceManager.

Usage:
    python3 tools/run_all_tests.py [--workers N]
"""

import os
import subprocess
import sys
import time

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, ViceTransport,
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


def run_test_suite(name, transport, labels, port, pid):
    """Run a single test suite, return (name, passed, failed, duration)."""
    start = time.time()
    passed = failed = 0

    try:
        if name == "net":
            from test_net import test_build_integrity, test_ip65_jump_table
            from test_net import test_zp_save_restore, test_recv_ring_buffer
            from test_net import test_ip65_init_without_hardware

            p, f = test_build_integrity(labels)
            passed += p; failed += f
            p, f = test_ip65_jump_table(transport)
            passed += p; failed += f
            p, f = test_zp_save_restore(transport, labels)
            passed += p; failed += f
            p, f = test_recv_ring_buffer(transport, labels)
            passed += p; failed += f
            p, f = test_ip65_init_without_hardware(transport, labels)
            passed += p; failed += f

        elif name == "sha256":
            from test_sha256 import run_tests as sha256_run
            passed, failed = sha256_run(transport, labels, iterations=5)

        elif name == "crypto":
            from test_crypto import (test_sqtab_init, test_chacha20_block_rfc,
                test_chacha20_encrypt_rfc, test_poly1305_mac_rfc,
                test_aead_encrypt_rfc, test_aead_decrypt_roundtrip,
                test_aead_random)
            import random
            rng = random.Random(42)
            for fn in [test_sqtab_init, test_chacha20_block_rfc,
                       test_chacha20_encrypt_rfc, test_poly1305_mac_rfc,
                       test_aead_encrypt_rfc]:
                p, f = fn(transport, labels)
                passed += p; failed += f
            p, f = test_aead_decrypt_roundtrip(transport, labels, rng)
            passed += p; failed += f
            p, f = test_aead_random(transport, labels, rng)
            passed += p; failed += f

        elif name == "hkdf":
            from test_hkdf import run_tests as hkdf_run
            passed, failed = hkdf_run(transport, labels)

        elif name == "tls_record":
            from test_tls_record import run_tests as record_run
            passed, failed = record_run(transport, labels, seed=42)

    except Exception as e:
        print(f"  [{name}] EXCEPTION: {e}")
        failed += 1

    duration = time.time() - start
    return name, passed, failed, duration


def main():
    workers = 3
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--workers":
            workers = int(sys.argv[i + 2])

    labels = build()

    suites = ["net", "sha256", "crypto", "hkdf", "tls_record"]

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    print(f"\n=== Starting {workers} VICE instances (staggered 100ms) ===")

    with ViceInstanceManager(
        config=config,
        port_range_start=6510,
        port_range_end=6510 + workers + 5,
    ) as mgr:
        instances = []
        for i in range(min(workers, len(suites))):
            inst = mgr.acquire()
            print(f"  Worker {i}: VICE PID={inst.pid}, port={inst.port}")
            instances.append(inst)
            if i < workers - 1:
                time.sleep(0.1)  # 100ms stagger per PATTERNS.md

        # Wait for all instances to boot
        for i, inst in enumerate(instances):
            grid = wait_for_text(inst.transport, "Q=QUIT", timeout=60.0)
            if grid is None:
                print(f"  Worker {i}: FATAL - menu did not appear")
                sys.exit(1)
            print(f"  Worker {i}: ready")

        # Each suite gets its own worker — suites run in parallel
        # If more suites than workers, extra suites wait for a free worker
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def worker_fn(suite_name, inst):
            return run_test_suite(suite_name, inst.transport, labels,
                                 inst.port, inst.pid)

        results = []
        print(f"\n=== Running {len(suites)} test suites across "
              f"{len(instances)} workers ===\n")

        # Map suites to workers 1:1 (first batch), then reuse freed workers
        with ThreadPoolExecutor(max_workers=len(instances)) as pool:
            futures = {}
            inst_queue = list(instances)
            pending_suites = list(suites)
            active = {}

            # Submit up to N suites (one per worker)
            while pending_suites and inst_queue:
                suite = pending_suites.pop(0)
                inst = inst_queue.pop(0)
                fut = pool.submit(worker_fn, suite, inst)
                futures[fut] = suite
                active[fut] = inst

            for fut in as_completed(futures):
                name, passed, failed, duration = fut.result()
                status = "PASS" if failed == 0 else "FAIL"
                results.append((name, passed, failed, duration))
                print(f"  [{status}] {name}: {passed}/{passed+failed} "
                      f"({duration:.1f}s)")

                # Return this worker's instance and submit next suite
                freed_inst = active.pop(fut)
                if pending_suites:
                    suite = pending_suites.pop(0)
                    new_fut = pool.submit(worker_fn, suite, freed_inst)
                    futures[new_fut] = suite
                    active[new_fut] = freed_inst

        # Release instances
        for inst in instances:
            mgr.release(inst)

    # Summary
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    total_tests = total_passed + total_failed

    print(f"\n{'='*60}")
    print(f"TOTAL: {total_passed}/{total_tests} passed, "
          f"{total_failed} failed")
    for name, passed, failed, duration in sorted(results):
        status = "OK" if failed == 0 else "FAIL"
        print(f"  {status:4s} {name:15s} {passed:3d}/{passed+failed:3d} "
              f"({duration:.1f}s)")
    print(f"{'='*60}")

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
