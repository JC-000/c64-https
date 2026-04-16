#!/usr/bin/env python3
"""
Phase 1b boot check for the UCI backend.

Uploads build/c64-https.prg (assumed to have been built with
`make BACKEND=uci`) to the U64E at 192.168.1.81, waits for the PRG
to boot, reads screen RAM at $0400 (40x25 = 1000 bytes), decodes the
Commodore screen-code bytes to ASCII, and prints the non-empty lines.

Pass criterion: screen contains printable text (not a uniform field
of spaces or garbage). This only verifies the PRG loads and runs on
real hardware — no UCI commands are exercised.

Usage:
    python3 tools/uci/boot_check.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64_client import Ultimate64Client

HOST = "192.168.1.81"
PRG_PATH = Path(__file__).resolve().parents[2] / "build" / "c64-https.prg"


# Commodore screen-code -> ASCII (uppercase/graphics mode, codes $00-$3F
# cover the visible uppercase charset we care about for the banner).
def screen_code_to_ascii(b: int) -> str:
    b &= 0x7F  # mask off reverse-video bit
    if b == 0x00:
        return "@"
    if 0x01 <= b <= 0x1A:
        return chr(ord("a") + (b - 0x01))  # $01..$1A -> a..z
    if 0x1B <= b <= 0x1F:
        return "[\\]^_"[b - 0x1B]
    if b == 0x20:
        return " "
    if 0x21 <= b <= 0x3F:
        # $21..$3F maps to ASCII $21..$3F (punctuation + digits)
        return chr(b)
    return "."  # non-printable / graphics


def decode_screen(mem: bytes) -> list[str]:
    lines: list[str] = []
    for row in range(25):
        start = row * 40
        end = start + 40
        text = "".join(screen_code_to_ascii(b) for b in mem[start:end])
        lines.append(text.rstrip())
    return lines


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        print("Run: make BACKEND=uci clean && make BACKEND=uci", file=sys.stderr)
        return 2

    prg = PRG_PATH.read_bytes()
    print(f"Loaded {len(prg)} bytes from {PRG_PATH}")

    lock = DeviceLock(HOST)
    if not lock.acquire(timeout=60.0):
        print(f"ERROR: could not acquire DeviceLock({HOST})", file=sys.stderr)
        return 3
    print(f"Acquired DeviceLock({HOST})")

    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)  # let KERNAL boot

        print("run_prg(PRG)...")
        client.run_prg(prg)
        time.sleep(3.0)  # let the PRG boot, draw its banner

        print("Reading screen RAM at $0400 (1000 bytes)...")
        mem = client.read_mem(0x0400, 1000)
        if len(mem) != 1000:
            print(
                f"WARNING: read_mem returned {len(mem)} bytes, expected 1000",
                file=sys.stderr,
            )

        lines = decode_screen(mem)
        print("\n--- screen RAM decoded (non-empty lines) ---")
        any_text = False
        for i, line in enumerate(lines):
            if line.strip():
                any_text = True
                print(f"{i:02d}: {line}")
        print("--- end screen ---\n")

        # Sanity: non-uniform bytes, and contains at least one printable letter
        unique = len(set(mem))
        has_text = any(
            (0x01 <= (b & 0x7F) <= 0x1A) or (0x21 <= (b & 0x7F) <= 0x3F)
            for b in mem
        )
        print(f"Unique screen bytes: {unique}")
        print(f"Contains printable text: {has_text}")
        if not any_text:
            print("FAIL: screen RAM decoded to nothing printable", file=sys.stderr)
            return 1
        if unique < 3:
            print(
                f"FAIL: screen looks uniform ({unique} unique bytes)",
                file=sys.stderr,
            )
            return 1
        print("PASS: PRG booted and drew a banner")
        return 0

    finally:
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    raise SystemExit(main())
