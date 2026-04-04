#!/usr/bin/env python3
"""test_dns.py -- DNS resolution tests for c64-https.

Tests the net_dns_resolve routine over real networking via the TAP interface.

Prerequisites:
    - tap-c64 interface exists and is configured (10.0.65.1)
    - x64sc (VICE) is on PATH
    - dnsmasq is on PATH

Usage:
    python3 tools/test_dns.py
"""

import os
import subprocess
import sys

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from net_test_env import NetworkTestEnv, skip_if_no_network

# ip65_dns_ip_addr: 4 bytes storing the resolved IP address
IP65_DNS_IP_ADDR = 0x4073

# Scratch RAM locations
HOSTNAME_ADDR = 0xC000
TRAMPOLINE_ADDR = 0xC100
CARRY_RESULT_ADDR = 0xC0F0


# ---------------------------------------------------------------------------
# DNS resolve helper
# ---------------------------------------------------------------------------

def build_dns_trampoline(hostname_lo, hostname_hi, dns_resolve_addr):
    """Build a 6502 trampoline that calls net_dns_resolve and stores
    the carry result (0=success, 1=failure) at CARRY_RESULT_ADDR.

    Layout at TRAMPOLINE_ADDR ($C100):
        LDA #hostname_lo
        LDX #hostname_hi
        JSR net_dns_resolve
        LDA #$00           ; assume success (carry clear)
        BCC +2             ; skip next instruction if carry clear
        LDA #$01           ; failure (carry set)
        STA $C0F0          ; store result
        RTS
    """
    dns_lo = dns_resolve_addr & 0xFF
    dns_hi = (dns_resolve_addr >> 8) & 0xFF
    result_lo = CARRY_RESULT_ADDR & 0xFF
    result_hi = (CARRY_RESULT_ADDR >> 8) & 0xFF
    return bytes([
        0xA9, hostname_lo,          # LDA #hostname_lo
        0xA2, hostname_hi,          # LDX #hostname_hi
        0x20, dns_lo, dns_hi,       # JSR net_dns_resolve
        0xA9, 0x00,                 # LDA #$00 (success)
        0x90, 0x02,                 # BCC +2 (branch if carry clear = success)
        0xA9, 0x01,                 # LDA #$01 (failure)
        0x8D, result_lo, result_hi, # STA CARRY_RESULT_ADDR
        0x60,                       # RTS
    ])


def do_dns_resolve(transport, write_bytes, read_bytes, jsr_fn,
                   hostname_str, dns_resolve_addr):
    """Write hostname to scratch RAM, build trampoline, call it, return
    (carry_result, ip_bytes).

    carry_result: 0 = success (carry clear), 1 = failure (carry set)
    ip_bytes: 4-byte list from ip65_dns_ip_addr
    """
    # Write null-terminated hostname to scratch RAM
    hostname = hostname_str.encode("ascii") + b"\x00"
    write_bytes(transport, HOSTNAME_ADDR, hostname)

    # Clear carry result location
    write_bytes(transport, CARRY_RESULT_ADDR, [0xFF])

    hostname_lo = HOSTNAME_ADDR & 0xFF
    hostname_hi = (HOSTNAME_ADDR >> 8) & 0xFF

    trampoline = build_dns_trampoline(hostname_lo, hostname_hi, dns_resolve_addr)
    write_bytes(transport, TRAMPOLINE_ADDR, trampoline)

    # Execute the trampoline
    jsr_fn(transport, TRAMPOLINE_ADDR, timeout=30.0)

    # Read carry result
    carry_bytes = read_bytes(transport, CARRY_RESULT_ADDR, 1)
    carry_result = carry_bytes[0]

    # Read resolved IP (4 bytes)
    ip_bytes = read_bytes(transport, IP65_DNS_IP_ADDR, 4)

    return carry_result, ip_bytes


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    if skip_if_no_network():
        sys.exit(0)

    # Late imports -- only needed if prerequisites are met
    from c64_test_harness import (
        Labels, ViceConfig, ViceInstanceManager,
        read_bytes, write_bytes, jsr, wait_for_text,
    )

    passed = 0
    failed = 0
    mgr = None
    inst = None

    with NetworkTestEnv(
        dns_records={"c64test.local": "10.0.65.1", "second.local": "10.0.65.1"},
        setup_tap=False,
    ) as env:
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

            # ---- Test: test_dns_labels -------------------------------------------
            print("\n=== test_dns_labels ===")
            dns_resolve_addr = labels.address("net_dns_resolve")
            if dns_resolve_addr is not None:
                print(f"  PASS: net_dns_resolve found @ ${dns_resolve_addr:04X}")
                passed += 1
            else:
                print("  FAIL: net_dns_resolve label not found")
                failed += 1
                raise RuntimeError("Required label net_dns_resolve not found")

            # ---- 2. Launch VICE --------------------------------------------------
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

            # ---- 3. Wait for boot menu ------------------------------------------
            print("\n=== Waiting for boot menu ===")
            grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
            if grid is None:
                print("  FATAL: Program menu did not appear")
                failed += 1
                raise RuntimeError("Boot menu timeout")
            print("  Boot menu appeared")

            # ---- 4. Network init (DHCP) -----------------------------------------
            print("\n=== Network init (pressing I for init) ===")
            transport.resume()  # CPU paused after wait_for_text screen read
            transport.inject_keys([0x49])  # 'I'

            grid = wait_for_text(transport, "DHCP OK", timeout=60.0, verbose=False)
            if grid is None:
                print("  FAIL: DHCP did not complete within 60 seconds")
                failed += 1
                raise RuntimeError("DHCP timeout")
            print("  DHCP OK")

            # ---- Test: test_dns_resolve_known_host -------------------------------
            print("\n=== test_dns_resolve_known_host ===")
            carry, ip = do_dns_resolve(
                transport, write_bytes, read_bytes, jsr,
                "c64test.local", dns_resolve_addr,
            )
            expected_ip = [10, 0, 65, 1]
            if carry == 0 and list(ip) == expected_ip:
                print(f"  PASS: resolved c64test.local -> {'.'.join(str(b) for b in ip)}"
                      f", carry=0")
                passed += 1
            else:
                print(f"  FAIL: c64test.local -> {list(ip)}, carry={carry}"
                      f" (expected {expected_ip}, carry=0)")
                failed += 1

            # ---- Test: test_dns_resolve_second_host ------------------------------
            print("\n=== test_dns_resolve_second_host ===")
            carry, ip = do_dns_resolve(
                transport, write_bytes, read_bytes, jsr,
                "second.local", dns_resolve_addr,
            )
            if carry == 0 and list(ip) == expected_ip:
                print(f"  PASS: resolved second.local -> {'.'.join(str(b) for b in ip)}"
                      f", carry=0")
                passed += 1
            else:
                print(f"  FAIL: second.local -> {list(ip)}, carry={carry}"
                      f" (expected {expected_ip}, carry=0)")
                failed += 1

            # ---- Test: test_dns_resolve_unknown_host -----------------------------
            print("\n=== test_dns_resolve_unknown_host ===")
            carry, ip = do_dns_resolve(
                transport, write_bytes, read_bytes, jsr,
                "nonexistent.invalid", dns_resolve_addr,
            )
            if carry == 1:
                print(f"  PASS: nonexistent.invalid -> carry=1 (failure, as expected)")
                passed += 1
            else:
                print(f"  FAIL: nonexistent.invalid -> carry={carry}, ip={list(ip)}"
                      f" (expected carry=1)")
                failed += 1

        except RuntimeError as e:
            print(f"\n  Test aborted: {e}")
        except Exception as e:
            print(f"\n  Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        finally:
            # ---- Teardown (VICE only -- dnsmasq handled by NetworkTestEnv) -------
            print("\n=== Teardown ===")

            if mgr is not None:
                try:
                    if inst is not None:
                        mgr.release(inst)
                    mgr.shutdown()
                    print("  VICE released")
                except Exception as e:
                    print(f"  VICE cleanup error: {e}")

    # ---- Summary -------------------------------------------------------------
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
