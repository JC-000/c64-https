#!/usr/bin/env python3
"""
Phase 2 boot + IP-readback check for the UCI backend.

Builds (assumed already built — or run via `make BACKEND=uci` first),
enables UCI firmware mode on the U64E, resets, uploads the PRG, waits
for boot, then:

  1. Decodes screen RAM at $0400 and prints the non-empty lines so we can
     visually confirm the new backend-aware banner (no "rr-net" string).
  2. Reads net_local_ip (4 bytes) via DMA, using the address from
     build/labels.txt. Asserts the four-byte value is non-zero and that
     the first octet is a plausible private-IP prefix (10 / 172 / 192).
  3. Also reads and prints net_last_error for diagnostics.

UCI firmware mode is enabled via enable_uci() before the reset and
disabled in the finally block. Without enable_uci the $DF1D identifier
register does not respond with $C9, so net_init would return the
UCI_ERR_NOT_PRESENT code and net_dhcp_acquire would never execute.

Usage:
    python3 tools/uci/phase2_check.py

Environment:
    U64_HOST  — U64E address (default 192.168.1.81)
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from c64_test_harness import Labels
from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import enable_uci, disable_uci

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO_ROOT = Path(__file__).resolve().parents[2]
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"


# Commodore screen-code -> ASCII (uppercase/graphics mode).
def screen_code_to_ascii(b: int) -> str:
    b &= 0x7F  # mask off reverse-video bit
    if b == 0x00:
        return "@"
    if 0x01 <= b <= 0x1A:
        return chr(ord("a") + (b - 0x01))
    if 0x1B <= b <= 0x1F:
        return "[\\]^_"[b - 0x1B]
    if b == 0x20:
        return " "
    if 0x21 <= b <= 0x3F:
        return chr(b)
    return "."


def decode_screen(mem: bytes) -> list[str]:
    lines: list[str] = []
    for row in range(25):
        start = row * 40
        end = start + 40
        text = "".join(screen_code_to_ascii(b) for b in mem[start:end])
        lines.append(text.rstrip())
    return lines


def load_label(name: str) -> int:
    """Look up a VICE-format label from build/labels.txt.

    Entries look like: `al C:BC4B .net_local_ip` — the `.name` token
    is unambiguous across backend cfgs.
    """
    labels = Labels.from_file(LABELS_PATH)
    if name not in labels:
        raise KeyError(f"label {name!r} not found in {LABELS_PATH}")
    return labels[name]


def is_plausible_private(ip: tuple[int, int, int, int]) -> bool:
    o1, o2, _o3, _o4 = ip
    if o1 == 10:
        return True
    if o1 == 172 and 16 <= o2 <= 31:
        return True
    if o1 == 192 and o2 == 168:
        return True
    return False


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        print("Run: make BACKEND=uci clean && make BACKEND=uci", file=sys.stderr)
        return 2
    if not LABELS_PATH.is_file():
        print(f"ERROR: labels.txt not found at {LABELS_PATH}", file=sys.stderr)
        return 2

    try:
        net_local_ip_addr = load_label("net_local_ip")
        net_last_error_addr = load_label("net_last_error")
    except KeyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"net_local_ip   @ ${net_local_ip_addr:04X}")
    print(f"net_last_error @ ${net_last_error_addr:04X}")

    prg = PRG_PATH.read_bytes()
    print(f"Loaded {len(prg)} bytes from {PRG_PATH}")

    lock = DeviceLock(HOST)
    if not lock.acquire(timeout=60.0):
        print(f"ERROR: could not acquire DeviceLock({HOST})", file=sys.stderr)
        return 3
    print(f"Acquired DeviceLock({HOST})")

    client: Ultimate64Client | None = None
    uci_enabled = False
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        transport = Ultimate64Transport(host=HOST, timeout=15.0, client=client)

        print("Enabling UCI (Command Interface)...")
        enable_uci(client)
        uci_enabled = True

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)  # let KERNAL boot

        print("run_prg(PRG)...")
        client.run_prg(prg)
        # Let the PRG run entropy_init, drbg_init_entropy, sqtab_init,
        # reu_mul_init (~128 KB REU stash — empirically ~15-18 s on the
        # U64E), and our new auto-init (net_init + GET_IPADDR).
        time.sleep(22.0)

        print("Reading screen RAM at $0400 (1000 bytes)...")
        mem = client.read_mem(0x0400, 1000)
        if len(mem) != 1000:
            print(
                f"WARNING: read_mem returned {len(mem)} bytes, expected 1000",
                file=sys.stderr,
            )

        lines = decode_screen(mem)
        print("\n--- screen RAM decoded (non-empty lines) ---")
        for i, line in enumerate(lines):
            if line.strip():
                print(f"{i:02d}: {line}")
        print("--- end screen ---\n")

        decoded_text = " ".join(line for line in lines if line.strip()).lower()
        if "rr-net" in decoded_text or "cs8900" in decoded_text:
            print("FAIL: banner still mentions rr-net / cs8900a", file=sys.stderr)
            return 1
        if "ultimate" not in decoded_text and "uci" not in decoded_text:
            print(
                "FAIL: banner does not mention ultimate/uci",
                file=sys.stderr,
            )
            return 1

        print("Reading net_last_error via DMA...")
        err_byte = transport.read_memory(net_last_error_addr, 1)[0]
        print(f"  net_last_error = ${err_byte:02X}")

        print("Reading net_local_ip (4 bytes) via DMA...")
        ip_bytes = bytes(transport.read_memory(net_local_ip_addr, 4))
        if len(ip_bytes) != 4:
            print(
                f"FAIL: net_local_ip read returned {len(ip_bytes)} bytes",
                file=sys.stderr,
            )
            return 1

        ip_tuple = (ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
        dotted = ".".join(str(b) for b in ip_tuple)
        print(f"  net_local_ip   = {dotted}  (raw {ip_bytes.hex()})")

        if ip_bytes == b"\x00\x00\x00\x00":
            print(
                "FAIL: net_local_ip is all zero — GET_IPADDR did not populate it",
                file=sys.stderr,
            )
            if err_byte:
                print(
                    f"       net_last_error = ${err_byte:02X} "
                    f"($81=NOT_PRESENT, $82=CMD_FAILED, $83=NO_IP)",
                    file=sys.stderr,
                )
            return 1
        if not is_plausible_private(ip_tuple):
            print(
                f"FAIL: {dotted} is not a plausible private-range address",
                file=sys.stderr,
            )
            return 1

        print()
        print(f"PASS: UCI backend booted, banner updated, IP = {dotted}")
        return 0

    finally:
        if uci_enabled and client is not None:
            print("Disabling UCI...")
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    raise SystemExit(main())
