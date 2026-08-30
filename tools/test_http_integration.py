#!/usr/bin/env python3
"""test_http_integration.py -- End-to-end HTTP integration test for c64-https.

Exercises the C64's http_get_plain routine over real networking via the TAP
interface.  The network architecture is:

    VICE (C64, 10.0.65.2) <--tap-c64 L2--> Host (10.0.65.1)
                                             |-- dnsmasq (DHCP + DNS)
                                             |-- HTTP server :80

Prerequisites:
    - tap-c64 interface exists and is configured (10.0.65.1)
    - x64sc (VICE) is on PATH
    - dnsmasq is on PATH

Usage:
    python3 tools/test_http_integration.py
"""

import os
import shutil
import subprocess
import sys
import time

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# ---------------------------------------------------------------------------
# Skip checks
# ---------------------------------------------------------------------------

def check_prerequisites():
    """Return True if all prerequisites are met, else print skip and return False."""
    if not os.path.exists("/sys/class/net/tap-c64"):
        print("SKIP: tap-c64 interface not found")
        return False
    if shutil.which("x64sc") is None:
        print("SKIP: x64sc not on PATH")
        return False
    if shutil.which("dnsmasq") is None:
        print("SKIP: dnsmasq not on PATH")
        return False
    if shutil.which("sudo") is None:
        print("SKIP: sudo not on PATH")
        return False
    return True


# ---------------------------------------------------------------------------
# dnsmasq helper
# ---------------------------------------------------------------------------

def start_dnsmasq():
    """Start dnsmasq providing DHCP and DNS on tap-c64. Returns Popen."""
    cmd = [
        "sudo", "dnsmasq",
        "--no-daemon",
        "--interface=tap-c64",
        "--bind-interfaces",
        "--listen-address=10.0.65.1",
        "--dhcp-range=10.0.65.2,10.0.65.10,255.255.255.0,5m",
        "--address=/c64test.local/10.0.65.1",
        "--dhcp-option=6,10.0.65.1",
        "--log-queries",
        "--no-resolv",
    ]
    print(f"  dnsmasq cmd: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Give it a moment to bind
    time.sleep(0.5)
    if proc.poll() is not None:
        _, stderr = proc.communicate()
        raise RuntimeError(f"dnsmasq failed to start: {stderr.decode()}")
    print(f"  dnsmasq PID={proc.pid}")
    return proc


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    if not check_prerequisites():
        # An involuntary skip is a failure: none of the five end-to-end HTTP
        # assertions ran, so exiting 0 would report a working HTTP path on a
        # host that has no TAP rig at all. Exit 2 ("could not run") to keep
        # that distinct from 1 ("tests failed").
        #
        # C64_NET_TESTS_OPTIONAL=1 is the explicit, deliberate skip — the
        # other half of the audit rule (7497e48): explicit skips are allowed,
        # but never silent.
        if os.environ.get("C64_NET_TESTS_OPTIONAL") == "1":
            print("EXPLICIT SKIP (C64_NET_TESTS_OPTIONAL=1): "
                  "test_http_integration.py did NOT run.\n  0 of 5 HTTP "
                  "assertions executed; this exit 0 certifies nothing about "
                  "the HTTP path.")
            sys.exit(0)
        print("CANNOT RUN: test_http_integration.py needs the TAP network "
              "rig (tap-c64 + x64sc + dnsmasq).\n"
              "  0 of 5 HTTP assertions executed — this run certifies "
              "nothing.\n"
              "  Set C64_NET_TESTS_OPTIONAL=1 to make skipping it a "
              "deliberate, exit-0 choice.", file=sys.stderr)
        sys.exit(2)

    # Late imports -- only needed if prerequisites are met
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_server import TestHTTPServer
    from c64_test_harness import (
        Labels, ViceConfig, ViceInstanceManager,
        read_bytes, write_bytes, jsr, wait_for_text,
    )

    passed = 0
    failed = 0
    dnsmasq_proc = None
    server = None
    mgr = None
    inst = None

    try:
        # ---- 1. Build --------------------------------------------------------
        print("\n=== Building ===")
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"  Build failed:\n{result.stderr}")
            sys.exit(1)
        print("  Build OK")

        labels = Labels.from_file(LABELS_PATH)
        print(f"  Labels loaded, {len(labels)} symbols")

        # Verify key labels exist
        required_labels = [
            "http_get_plain", "http_host_ptr", "http_host_len",
            "http_path_ptr", "http_path_len", "http_port",
            "http_parse_state", "http_line_idx", "http_hdr_match",
            "http_resp_len", "http_resp_buf", "http_status",
        ]
        for name in required_labels:
            if labels.address(name) is None:
                print(f"  FATAL: required label '{name}' not found")
                sys.exit(1)

        # ---- 2. Start dnsmasq ------------------------------------------------
        print("\n=== Starting dnsmasq ===")
        dnsmasq_proc = start_dnsmasq()

        # ---- 3. Start HTTP test server ---------------------------------------
        print("\n=== Starting HTTP test server ===")
        server = TestHTTPServer(host="10.0.65.1", port=8080)
        server.start()
        print("  HTTP server listening on 10.0.65.1:8080")

        # ---- 4. Launch VICE --------------------------------------------------
        print("\n=== Starting VICE ===")
        config = ViceConfig(
            prg_path=PRG_PATH,
            warp=False,  # warp causes timing issues with ethernet
            ntsc=True,
            sound=False,
            ethernet=True,
            ethernet_mode="rrnet",
            ethernet_driver="tuntap",
            ethernet_interface="tap-c64",
        )

        mgr = ViceInstanceManager(config=config)
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        # ---- 5. Wait for boot menu ------------------------------------------
        print("\n=== Waiting for boot menu ===")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("  FATAL: Program menu did not appear")
            failed += 1
            raise RuntimeError("Boot menu timeout")
        print("  Boot menu appeared")

        # ---- 6. Network init (DHCP) -----------------------------------------
        print("\n=== Network init (pressing I for init) ===")
        transport.resume()  # CPU paused after wait_for_text screen read
        transport.inject_keys([0x49])  # 'I'

        grid = wait_for_text(transport, "DHCP OK", timeout=60.0, verbose=False)
        if grid is None:
            print("  FAIL: DHCP did not complete within 60 seconds")
            # Dump dnsmasq stderr for debugging
            if dnsmasq_proc:
                dnsmasq_proc.terminate()
                _, stderr = dnsmasq_proc.communicate(timeout=5)
                print(f"  dnsmasq stderr:\n{stderr.decode()}")
                dnsmasq_proc = None
            failed += 1
            raise RuntimeError("DHCP timeout")
        print("  DHCP OK")
        passed += 1

        # ---- 7. Set up HTTP parameters in C64 memory -------------------------
        print("\n=== Setting up HTTP parameters ===")

        # Write hostname to scratch RAM at $C000
        hostname = b"c64test.local\x00"
        write_bytes(transport, 0xC000, hostname)
        write_bytes(transport, labels.address("http_host_ptr"), [0x00, 0xC0])
        write_bytes(transport, labels.address("http_host_len"), [13])

        # Write path to $C080
        path = b"/\x00"
        write_bytes(transport, 0xC080, path)
        write_bytes(transport, labels.address("http_path_ptr"), [0x80, 0xC0])
        write_bytes(transport, labels.address("http_path_len"), [1])

        # Set port to 8080 (little-endian 16-bit: 0x1F90)
        write_bytes(transport, labels.address("http_port"), [0x90, 0x1F])

        # Initialize parser state
        write_bytes(transport, labels.address("http_parse_state"), [0])
        write_bytes(transport, labels.address("http_line_idx"), [0])
        write_bytes(transport, labels.address("http_hdr_match"), [0])
        write_bytes(transport, labels.address("http_resp_len"), [0, 0])

        print("  Parameters written to C64 memory")

        # ---- 8. Call http_get_plain ------------------------------------------
        print("\n=== Calling http_get_plain ===")
        http_get_plain = labels.address("http_get_plain")
        print(f"  http_get_plain @ ${http_get_plain:04X}")

        try:
            jsr(transport, http_get_plain, timeout=60.0)
            print("  http_get_plain returned")
        except TimeoutError:
            print("  FAIL: http_get_plain timed out after 60 seconds")
            failed += 1
            raise RuntimeError("http_get_plain timeout")

        # ---- 9. Read results -------------------------------------------------
        print("\n=== Checking results ===")

        # Check http_status (2 bytes, little-endian)
        status_bytes = read_bytes(transport, labels.address("http_status"), 2)
        status = status_bytes[0] | (status_bytes[1] << 8)
        if status == 200:
            print(f"  PASS: http_status = {status}")
            passed += 1
        else:
            print(f"  FAIL: http_status = {status}, expected 200 "
                  f"(bytes: ${status_bytes[0]:02X} ${status_bytes[1]:02X})")
            failed += 1

        # Check http_resp_len (2 bytes, little-endian)
        resp_len_bytes = read_bytes(transport, labels.address("http_resp_len"), 2)
        resp_len = resp_len_bytes[0] | (resp_len_bytes[1] << 8)
        if resp_len == 9:
            print(f"  PASS: http_resp_len = {resp_len}")
            passed += 1
        else:
            print(f"  FAIL: http_resp_len = {resp_len}, expected 9")
            failed += 1

        # Check response body
        resp_body = read_bytes(transport, labels.address("http_resp_buf"), resp_len)
        if resp_body == b"HELLO C64":
            print(f"  PASS: response body = 'HELLO C64'")
            passed += 1
        else:
            print(f"  FAIL: response body = {resp_body!r}, expected b'HELLO C64'")
            failed += 1

        # ---- 10. Verify server received a well-formed request ----------------
        print("\n=== Checking server-side request log ===")
        if len(server.requests) >= 1:
            req = server.requests[0]
            if req["method"] == "GET" and req["path"] == "/":
                print(f"  PASS: server received GET / "
                      f"(Host: {req['headers'].get('Host', '<missing>')})")
                passed += 1
            else:
                print(f"  FAIL: server received {req['method']} {req['path']}, "
                      f"expected GET /")
                failed += 1
        else:
            print(f"  FAIL: server received 0 requests, expected >= 1")
            failed += 1

    except RuntimeError as e:
        print(f"\n  Test aborted: {e}")
    except Exception as e:
        print(f"\n  Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
    finally:
        # ---- Teardown --------------------------------------------------------
        print("\n=== Teardown ===")

        if mgr is not None:
            try:
                if inst is not None:
                    mgr.release(inst)
                mgr.shutdown()
                print("  VICE released")
            except Exception as e:
                print(f"  VICE cleanup error: {e}")

        if server is not None:
            try:
                server.stop()
                print("  HTTP server stopped")
            except Exception as e:
                print(f"  HTTP server cleanup error: {e}")

        if dnsmasq_proc is not None:
            try:
                dnsmasq_proc.terminate()
                try:
                    _, stderr = dnsmasq_proc.communicate(timeout=5)
                    print(f"  dnsmasq stopped (exit={dnsmasq_proc.returncode})")
                    if failed > 0:
                        print(f"  dnsmasq stderr:\n{stderr.decode()}")
                except subprocess.TimeoutExpired:
                    dnsmasq_proc.kill()
                    dnsmasq_proc.wait()
                    print("  dnsmasq killed (did not terminate cleanly)")
            except Exception as e:
                print(f"  dnsmasq cleanup error: {e}")

    # ---- Summary -------------------------------------------------------------
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
