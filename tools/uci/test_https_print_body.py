#!/usr/bin/env python3
"""
Issue #28 verification harness: runs the standard HTTPS GET flow but the
injected 6502 stub also calls `print_resp_body` after `http_get`, so the
decrypted response body actually lands on the C64 screen. Then dumps
screen RAM ($0400-$07E7) and scans for the expected 21-byte screen-code
sequence corresponding to "HELLO FROM TLS SERVER".

Reads all environment variables the same way as test_https_local.py
(U64_HOST, TURBO_MHZ, HTTPS_PORT, ACCEPT_TIMEOUT, SENTINEL_POLL_TIMEOUT,
UCI_DEBUG_DIR, etc.).

Exit code 0 = PASS: body buffer correct AND expected screen-code
sequence found. Exit 1 = FAIL.
"""
from __future__ import annotations

import importlib.util
import os
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

# Reuse the existing harness's helpers by importing the module as-is.
# We'll override a narrow slice: the stub-building function `_build_http_routine`.
from tools.uci import test_https_local as base

from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    set_turbo_mhz,
    set_debug_stream_mode,
    DEBUG_MODE_6510,
)
from c64_test_harness.uci_network import enable_uci, disable_uci
from c64_test_harness.keyboard import send_text


SCREEN_RAM = 0x0400
SCREEN_LEN = 1000

# H E L L O   F R O M   T L S   S E R V E R
EXPECTED_SC = bytes([
    0x08, 0x05, 0x0C, 0x0C, 0x0F, 0x20,
    0x06, 0x12, 0x0F, 0x0D, 0x20,
    0x14, 0x0C, 0x13, 0x20,
    0x13, 0x05, 0x12, 0x16, 0x05, 0x12,
])


def _build_routine(labels, port):
    """Same as base._build_http_routine but adds a jsr to print_resp_body
    after http_get, so the body actually renders to screen RAM."""
    code = bytearray()

    def emit(*bs):
        code.extend(bs)

    def emit_lda_imm(v):
        emit(0xA9, v & 0xFF)

    def emit_sta_abs(addr):
        emit(0x8D, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_lda_abs(addr):
        emit(0xAD, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jsr(addr):
        emit(0x20, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jmp(addr):
        emit(0x4C, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_progress(step):
        emit_lda_imm(step)
        emit_sta_abs(base.PROGRESS_ADDR)

    http_get         = labels["http_get"]
    http_host_ptr    = labels["http_host_ptr"]
    http_host_len    = labels["http_host_len"]
    http_path_ptr    = labels["http_path_ptr"]
    http_path_len    = labels["http_path_len"]
    http_port        = labels["http_port"]
    net_init         = labels["net_init"]
    tcp_recv_head    = labels["tcp_recv_head"]
    tcp_recv_tail    = labels["tcp_recv_tail"]
    print_resp_body  = labels["print_resp_body"]

    emit_lda_abs(0x0001)
    emit(0x29, 0xFE)
    emit_sta_abs(0x0001)

    emit_lda_imm(0x00)
    emit_sta_abs(base.SENTINEL_ADDR)
    emit_sta_abs(base.PROGRESS_ADDR)
    emit_sta_abs(base.CARRY_FLAG_ADDR)

    emit_progress(0x01)
    emit_jsr(net_init)

    emit_lda_imm(0x00)
    emit_sta_abs(tcp_recv_head)
    emit_sta_abs(tcp_recv_head + 1)
    emit_sta_abs(tcp_recv_tail)
    emit_sta_abs(tcp_recv_tail + 1)

    emit_progress(0x02)

    emit_lda_imm(base.HOST_STR_ADDR & 0xFF)
    emit_sta_abs(http_host_ptr)
    emit_lda_imm((base.HOST_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_host_ptr + 1)

    host_len_patch_offset = len(code) + 1
    emit_lda_imm(0x00)
    emit_sta_abs(http_host_len)

    emit_lda_imm(base.PATH_STR_ADDR & 0xFF)
    emit_sta_abs(http_path_ptr)
    emit_lda_imm((base.PATH_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_path_ptr + 1)

    emit_lda_imm(1)
    emit_sta_abs(http_path_len)

    emit_lda_imm(port & 0xFF)
    emit_sta_abs(http_port)
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(http_port + 1)

    emit_progress(0x03)
    emit_jsr(http_get)

    emit(0x08)
    emit(0x68)
    emit_sta_abs(base.CARRY_FLAG_ADDR)

    emit_progress(0x04)

    # NEW: render body on screen so we can observe rendering correctness.
    emit_jsr(print_resp_body)

    emit_lda_imm(base.SENTINEL_VALUE)
    emit_sta_abs(base.SENTINEL_ADDR)

    emit_progress(0x05)

    park = base.ROUTINE_ADDR + len(code)
    emit_jmp(park)

    return bytes(code), host_len_patch_offset


def _scan_screen(data, needle):
    """Return (offset, row, col) or None."""
    idx = data.find(needle)
    if idx < 0:
        return None
    return (idx, idx // 40, idx % 40)


def main():
    # Monkey-patch the stub builder, then delegate to the normal main().
    base._build_http_routine = _build_routine

    # We also want to force a screen dump + scan at the end regardless of
    # the base test's pass/fail heuristic. Approach: wrap base.main() and
    # after it finishes, re-acquire the device lock to DMA screen RAM.
    # But base.main() already disables UCI, which clears the lock.
    # Simpler: add a post-hook into the _run_test flow via a thin wrapper.
    # The base test prints screen RAM already — so we just extend it by
    # patching _decode_screen_ram OR by reading transport once more.
    #
    # Observation: by the time base.main() returns, the screen is still
    # whatever the stub left. But the U64E session ended. To capture the
    # screen we need a DMA read DURING the run. The cleanest hook is to
    # patch _decode_screen_ram to also do the scan.

    original_decode = base._decode_screen_ram
    found = {"sc_bytes": None, "hit": None, "screen": None}

    def decode_and_scan(data):
        text = original_decode(data)
        found["screen"] = text
        found["sc_bytes"] = data
        hit = _scan_screen(data, EXPECTED_SC)
        found["hit"] = hit
        return text

    base._decode_screen_ram = decode_and_scan

    rc = base.main()

    print()
    print("=" * 60)
    print("ISSUE #28 SCREEN-CODE VERIFICATION")
    print("=" * 60)
    if found["sc_bytes"] is None:
        print("FAIL: never got a screen dump")
        return 1
    hit = found["hit"]
    if hit is None:
        print("FAIL: expected 21-byte screen-code sequence NOT found in $0400-$07E7")
        print("      (bytes 08 05 0C 0C 0F 20 06 12 0F 0D 20 14 0C 13 20 13 05 12 16 05 12)")
        # Show first 200 bytes of screen RAM in hex for diagnostics.
        data = found["sc_bytes"]
        print()
        print("screen RAM $0400-$04C7 (first 200 bytes), hex:")
        for i in range(0, 200, 40):
            row = data[i:i + 40]
            print("  {:02d}: {}".format(i // 40, row.hex()))
        return 1
    offset, row, col = hit
    print(f"PASS: expected screen-code sequence found at offset +{offset:04X}"
          f" (row {row}, col {col})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
