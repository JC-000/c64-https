#!/usr/bin/env python3
"""Diagnostic: test jsr_with_carry trampoline pattern via harness."""
import time, sys, os
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, goto, jsr, wait_for_text,
)

import subprocess
subprocess.run(["make", "clean"], capture_output=True)
result = subprocess.run(["make"], capture_output=True, text=True)
if result.returncode != 0:
    print(f"Build failed:\n{result.stderr}")
    sys.exit(1)
print("Build OK", flush=True)

PRG = "build/c64-https.prg"
LABELS = "build/labels.txt"
config = ViceConfig(prg_path=PRG, warp=True, ntsc=True, sound=False)
labels = Labels.from_file(LABELS)

CARRY_TRAMPOLINE = 0x033C
CARRY_RESULT_ADDR = 0x0352
CARRY_FLAG_ADDR = 0x0353

def jsr_with_carry_diag(transport, addr, timeout=60.0, poll_interval=0.5):
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
    print(f"  Trampoline ({len(trampoline)} bytes): {trampoline.hex()}", flush=True)

    write_bytes(transport, CARRY_TRAMPOLINE, trampoline)
    write_bytes(transport, CARRY_FLAG_ADDR, bytes([0x00]))

    # Verify write
    readback = read_bytes(transport, CARRY_TRAMPOLINE, len(trampoline))
    if readback != trampoline:
        print(f"  ERROR: trampoline readback mismatch!", flush=True)
        print(f"    wrote: {trampoline.hex()}", flush=True)
        print(f"    read:  {readback.hex()}", flush=True)
        return -1

    flag_before = read_bytes(transport, CARRY_FLAG_ADDR, 1)
    print(f"  Flag before goto: {flag_before[0]:02X}", flush=True)

    goto(transport, CARRY_TRAMPOLINE)

    deadline = time.monotonic() + timeout
    i = 0
    while True:
        time.sleep(poll_interval)
        if time.monotonic() >= deadline:
            print(f"  TIMEOUT after {timeout:.0f}s", flush=True)
            return -1
        flag = read_bytes(transport, CARRY_FLAG_ADDR, 1)
        print(f"  poll {i}: flag={flag[0]:02X}", flush=True)
        if flag[0] == 0xFF:
            result = read_bytes(transport, CARRY_RESULT_ADDR, 1)
            print(f"  Done! carry={result[0]}", flush=True)
            return result[0]
        # Binary monitor: resume CPU after memory read paused it
        t.resume()
        i += 1


with ViceInstanceManager(config=config) as mgr:
    inst = mgr.acquire()
    t = inst.transport
    print(f"VICE PID={inst.pid}, port={inst.port}", flush=True)

    grid = wait_for_text(t, "Q=QUIT", timeout=180.0, verbose=False)
    if grid is None:
        print("FATAL: menu not found")
        sys.exit(1)
    print("Menu ready", flush=True)

    # Test 1: sqtab_init (should succeed, carry irrelevant)
    addr = labels["sqtab_init"]
    print(f"\n=== Test 1: sqtab_init (${addr:04X}) ===", flush=True)
    result = jsr_with_carry_diag(t, addr, timeout=60.0)
    print(f"Result: {result}", flush=True)

    # Test 2: simple RTS (SEC; RTS should give carry=1)
    # Write SEC; RTS at $0380
    print(f"\n=== Test 2: SEC; RTS at $0380 ===", flush=True)
    write_bytes(t, 0x0380, bytes([0x38, 0x60]))  # SEC; RTS
    result = jsr_with_carry_diag(t, 0x0380, timeout=10.0)
    print(f"Result: {result} (expected 1)", flush=True)

    # Test 3: CLC; RTS should give carry=0
    print(f"\n=== Test 3: CLC; RTS at $0380 ===", flush=True)
    write_bytes(t, 0x0380, bytes([0x18, 0x60]))  # CLC; RTS
    result = jsr_with_carry_diag(t, 0x0380, timeout=10.0)
    print(f"Result: {result} (expected 0)", flush=True)

    mgr.release(inst)

print("\nDone.", flush=True)
