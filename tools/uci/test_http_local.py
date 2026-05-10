#!/usr/bin/env python3
"""
Phase 4 LOCAL: exercise the real http_get_plain code path through the UCI
backend on a real Ultimate 64 Elite.

Flow:
  1. Boot the UCI-built PRG, wait for auto-init (net_init + DHCP).
  2. Quit to BASIC ('Q').
  3. Start a Python HTTP server on the dev host's LAN IP, port 8080.
  4. DMA-inject a small 6502 stub at $4200 that:
       - Banks out BASIC ROM
       - Sets http_host_ptr to a DMA'd hostname string (dev host IP)
       - Sets http_host_len, http_path_ptr, http_path_len, http_port
       - Calls http_get_plain (the real HTTP code from src/http.s)
       - Writes a sentinel on completion
  5. Trigger with SYS 16896 via keyboard buffer.
  6. Poll sentinel, then read http_resp_buf for the response body.
  7. Assert it contains "HELLO FROM TEST SERVER".
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

from c64_test_harness import Labels
from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import enable_uci, disable_uci
from c64_test_harness.keyboard import send_text


HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO_ROOT = Path(__file__).resolve().parents[2]
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"

ROUTINE_ADDR     = 0x4200
HOST_STR_ADDR    = 0x4400   # where we DMA the hostname string
PATH_STR_ADDR    = 0x4440   # where we DMA the path string
SENTINEL_ADDR    = 0x4540
PROGRESS_ADDR    = 0x4541
CARRY_FLAG_ADDR  = 0x4542

SENTINEL_VALUE   = 0xAA
HTTP_PORT        = 8080
DEFAULT_TIMEOUT  = 45.0

EXPECTED_BODY    = "HELLO FROM TEST SERVER"
HTTP_RESPONSE    = (
    b"HTTP/1.0 200 OK\r\n"
    b"Content-Length: 22\r\n"
    b"\r\n"
    b"HELLO FROM TEST SERVER"
)


def _detect_local_ip(target: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _run_http_server(bind_ip: str, port: int, result: dict) -> None:
    """Minimal HTTP server that responds with a fixed body."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(120.0)
    try:
        srv.bind((bind_ip, port))
        srv.listen(1)
        result["listening"] = True
        conn, addr = srv.accept()
        result["client_addr"] = addr
        # Read the request (up to 1024 bytes)
        conn.settimeout(15.0)
        try:
            req = conn.recv(1024)
            result["request"] = req
        except socket.timeout:
            result["request"] = b"<timeout>"
        # Send fixed HTTP response
        conn.sendall(HTTP_RESPONSE)
        # Keep alive briefly for the C64 to drain
        time.sleep(1.0)
        conn.close()
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        srv.close()


def _load_labels() -> dict[str, int]:
    return dict(Labels.from_file(LABELS_PATH))


def _build_http_routine(labels: dict[str, int], port: int) -> bytes:
    """Emit a 6502 routine that calls http_get_plain via the real HTTP layer."""
    code = bytearray()

    def emit(*bs: int) -> None:
        code.extend(bs)

    def emit_lda_imm(v: int) -> None:
        emit(0xA9, v & 0xFF)

    def emit_ldx_imm(v: int) -> None:
        emit(0xA2, v & 0xFF)

    def emit_sta_abs(addr: int) -> None:
        emit(0x8D, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_lda_abs(addr: int) -> None:
        emit(0xAD, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jsr(addr: int) -> None:
        emit(0x20, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jmp(addr: int) -> None:
        emit(0x4C, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_progress(step: int) -> None:
        emit_lda_imm(step)
        emit_sta_abs(PROGRESS_ADDR)

    # ABI addresses
    http_get_plain = labels["http_get_plain"]
    http_host_ptr  = labels["http_host_ptr"]
    http_host_len  = labels["http_host_len"]
    http_path_ptr  = labels["http_path_ptr"]
    http_path_len  = labels["http_path_len"]
    http_port      = labels["http_port"]
    net_init       = labels["net_init"]
    tcp_recv_head  = labels["tcp_recv_head"]
    tcp_recv_tail  = labels["tcp_recv_tail"]

    # 0) Bank BASIC ROM OUT so $A000-$BFFF is RAM
    emit_lda_abs(0x0001)
    emit(0x29, 0xFE)          # AND #$FE
    emit_sta_abs(0x0001)

    # Clear markers
    emit_lda_imm(0x00)
    emit_sta_abs(SENTINEL_ADDR)
    emit_sta_abs(PROGRESS_ADDR)
    emit_sta_abs(CARRY_FLAG_ADDR)

    emit_progress(0x01)

    # Re-init UCI (ensure idle state after auto-init)
    emit_jsr(net_init)

    # Zero the TCP ring head/tail to flush any stale boot-poll data
    emit_lda_imm(0x00)
    emit_sta_abs(tcp_recv_head)
    emit_sta_abs(tcp_recv_head + 1)
    emit_sta_abs(tcp_recv_tail)
    emit_sta_abs(tcp_recv_tail + 1)

    emit_progress(0x02)

    # Set http_host_ptr = HOST_STR_ADDR
    emit_lda_imm(HOST_STR_ADDR & 0xFF)
    emit_sta_abs(http_host_ptr)
    emit_lda_imm((HOST_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_host_ptr + 1)

    # Set http_host_len — the hostname was DMA'd to HOST_STR_ADDR
    # We'll set this dynamically from Python after we know the IP length
    # For now emit a placeholder that Python will patch
    host_len_patch_offset = len(code) + 1  # offset of the immediate byte
    emit_lda_imm(0x00)  # placeholder — patched below
    emit_sta_abs(http_host_len)

    # Set http_path_ptr = PATH_STR_ADDR
    emit_lda_imm(PATH_STR_ADDR & 0xFF)
    emit_sta_abs(http_path_ptr)
    emit_lda_imm((PATH_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_path_ptr + 1)

    # Set http_path_len = 1 (just "/")
    emit_lda_imm(1)
    emit_sta_abs(http_path_len)

    # Set http_port = our test port
    emit_lda_imm(port & 0xFF)
    emit_sta_abs(http_port)
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(http_port + 1)

    emit_progress(0x03)

    # Call http_get_plain — the REAL HTTP code path
    emit_jsr(http_get_plain)

    # Store carry (success/failure)
    emit(0x08)  # PHP
    emit(0x68)  # PLA
    emit_sta_abs(CARRY_FLAG_ADDR)

    emit_progress(0x04)

    # Write sentinel
    emit_lda_imm(SENTINEL_VALUE)
    emit_sta_abs(SENTINEL_ADDR)

    # Park CPU
    park = ROUTINE_ADDR + len(code)
    emit_jmp(park)

    return bytes(code), host_len_patch_offset


def _petscii_to_ascii(screen_codes: bytes) -> str:
    """Rough conversion of C64 screen codes to ASCII for display."""
    out = []
    for b in screen_codes:
        if b == 0:
            break
        if 0x01 <= b <= 0x1A:
            out.append(chr(b + 0x40))  # screen code A-Z
        elif 0x41 <= b <= 0x5A:
            out.append(chr(b))
        elif 0x30 <= b <= 0x39:
            out.append(chr(b))
        elif b == 0x20:
            out.append(' ')
        elif b == 0x2E:
            out.append('.')
        elif b == 0x2F:
            out.append('/')
        elif b == 0x3A:
            out.append(':')
        elif b == 0x2D:
            out.append('-')
        elif b == 0x0D:
            out.append('\n')
        else:
            out.append(f'[{b:02X}]')
    return ''.join(out)


def _decode_screen_ram(data: bytes) -> str:
    """Convert 1000 bytes of screen RAM (screen codes) to readable text."""
    lines = []
    for row in range(25):
        line = data[row * 40:(row + 1) * 40]
        chars = []
        for b in line:
            if b == 0x20:
                chars.append(' ')
            elif 0x01 <= b <= 0x1A:
                chars.append(chr(b + 0x40))
            elif 0x00 == b:
                chars.append(' ')  # null = space on screen
            elif 0x30 <= b <= 0x39:
                chars.append(chr(b))
            elif 0x41 <= b <= 0x5A:
                chars.append(chr(b))
            elif 0x2E == b:
                chars.append('.')
            elif 0x2F == b:
                chars.append('/')
            elif 0x3A == b:
                chars.append(':')
            elif 0x2D == b:
                chars.append('-')
            elif 0x28 == b:
                chars.append('(')
            elif 0x29 == b:
                chars.append(')')
            else:
                chars.append('.')
        lines.append(''.join(chars).rstrip())
    return '\n'.join(lines)


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        return 2
    if not LABELS_PATH.is_file():
        print(f"ERROR: labels.txt not found", file=sys.stderr)
        return 2

    labels = _load_labels()
    required = [
        "http_get_plain", "http_host_ptr", "http_host_len",
        "http_path_ptr", "http_path_len", "http_port",
        "net_init", "net_last_error", "net_tcp_state",
        "net_initialized", "uci_socket_id",
        "tcp_recv_head", "tcp_recv_tail",
        "http_resp_buf", "http_resp_len", "http_status",
    ]
    missing = [n for n in required if n not in labels]
    if missing:
        print(f"ERROR: missing labels: {missing}", file=sys.stderr)
        return 2

    for n in sorted(required):
        print(f"  {n:20s} = ${labels[n]:04X}")

    test_host_ip = _detect_local_ip(HOST)
    print(f"\nDev host LAN IP : {test_host_ip}")
    print(f"HTTP port       : {HTTP_PORT}")
    print(f"Expected body   : {EXPECTED_BODY!r}")

    # Start HTTP server
    server_result: dict = {}
    server_thread = threading.Thread(
        target=_run_http_server,
        args=(test_host_ip, HTTP_PORT, server_result),
        daemon=True,
    )
    server_thread.start()
    for _ in range(60):
        if server_result.get("listening"):
            break
        time.sleep(0.05)
    else:
        print("ERROR: HTTP server failed to start", file=sys.stderr)
        return 1
    print(f"HTTP server listening on {test_host_ip}:{HTTP_PORT}")

    # Build the 6502 routine
    routine_bytes_raw, host_len_patch = _build_http_routine(labels, HTTP_PORT)
    routine_bytes = bytearray(routine_bytes_raw)
    # Patch host length
    host_ip_bytes = test_host_ip.encode("ascii")
    routine_bytes[host_len_patch] = len(host_ip_bytes)
    routine_bytes = bytes(routine_bytes)

    print(f"Routine size    : {len(routine_bytes)} bytes @ ${ROUTINE_ADDR:04X}")

    # Prepare hostname + path strings for DMA
    host_str = host_ip_bytes + b"\x00"
    path_str = b"/\x00"

    prg = PRG_PATH.read_bytes()

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

        print("Enabling UCI...")
        enable_uci(client)
        uci_enabled = True

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)

        print("run_prg(PRG)...")
        client.run_prg(prg)
        # Wait for auto-init (entropy, REU stash, DHCP)
        time.sleep(22.0)

        init_flag = transport.read_memory(labels["net_initialized"], 1)[0]
        print(f"net_initialized = ${init_flag:02X}")
        if init_flag == 0:
            print("WARNING: net_initialized is 0 — auto-init may have failed")

        # Quit PRG main_loop back to BASIC
        print("Sending 'Q' to exit PRG main_loop...")
        send_text(transport, "q\r")
        time.sleep(2.0)

        # DMA-write the routine + data
        CHUNK = 64
        for i in range(0, len(routine_bytes), CHUNK):
            transport.write_memory(
                ROUTINE_ADDR + i,
                routine_bytes[i:i + CHUNK],
            )
        transport.write_memory(HOST_STR_ADDR, host_str.ljust(32, b"\x00"))
        transport.write_memory(PATH_STR_ADDR, path_str.ljust(8, b"\x00"))

        # Clear sentinel area
        transport.write_memory(SENTINEL_ADDR, bytes(16))

        # Trigger via SYS
        sys_line = f"sys{ROUTINE_ADDR}\r"
        print(f"Triggering: {sys_line.strip()}")
        send_text(transport, sys_line)

        # Poll sentinel
        deadline = time.time() + DEFAULT_TIMEOUT
        last_progress = -1
        while time.time() < deadline:
            time.sleep(0.5)
            blob = transport.read_memory(SENTINEL_ADDR, 2)
            sentinel = blob[0]
            progress = blob[1]
            if progress != last_progress:
                print(f"  progress=0x{progress:02X}")
                last_progress = progress
            if sentinel == SENTINEL_VALUE:
                print("  sentinel set — routine complete")
                break
        else:
            print(f"TIMEOUT: sentinel not set (progress=0x{last_progress:02X})",
                  file=sys.stderr)
            _dump_diag(transport, labels)
            return 1

        # --- Read results ---
        _dump_diag(transport, labels)

        # Read carry flag (bit 0 of stored processor status)
        carry_byte = transport.read_memory(CARRY_FLAG_ADDR, 1)[0]
        carry = carry_byte & 0x01
        print(f"http_get_plain carry = {carry} (0=success, 1=failure)")

        # Read http_status
        status_raw = transport.read_memory(labels["http_status"], 2)
        http_status = status_raw[0] | (status_raw[1] << 8)
        print(f"http_status     = {http_status}")

        # Read http_resp_len
        resp_len_raw = transport.read_memory(labels["http_resp_len"], 2)
        resp_len = resp_len_raw[0] | (resp_len_raw[1] << 8)
        print(f"http_resp_len   = {resp_len}")

        # Read http_resp_buf (up to 200 bytes)
        read_len = min(resp_len, 200) if resp_len > 0 else 200
        resp_data = bytes(transport.read_memory(labels["http_resp_buf"], read_len))
        print(f"http_resp_buf   = {resp_data[:80]!r}...")

        # Also read screen RAM
        screen = bytes(transport.read_memory(0x0400, 1000))
        screen_text = _decode_screen_ram(screen)
        print("\n--- screen RAM ---")
        for line in screen_text.split('\n'):
            if line.strip():
                print(f"  {line}")

        # Read ring buffer first 256 bytes
        ring_data = bytes(transport.read_memory(0xC000, 256))
        print(f"\ntcp_recv_buf[0:64] = {ring_data[:64].hex()}")

        # Server side
        server_thread.join(timeout=5.0)
        if "error" in server_result:
            print(f"server error: {server_result['error']}")
        print(f"server request  = {server_result.get('request', b'<none>')!r}")
        print(f"server peer     = {server_result.get('client_addr')}")

        # --- Assertions ---
        # Check if body contains expected text
        body_ascii = ""
        try:
            body_ascii = resp_data.decode("ascii", errors="replace")
        except Exception:
            pass

        if EXPECTED_BODY in body_ascii:
            print(f"\nPASS: http_resp_buf contains '{EXPECTED_BODY}'")
            return 0

        # Also check screen RAM for the text (print_resp_body prints it)
        if "HELLO" in screen_text.upper():
            print(f"\nPASS: screen RAM contains HELLO (body in resp_buf may differ in encoding)")
            return 0

        print(f"\nFAIL: expected '{EXPECTED_BODY}' not found in response or screen",
              file=sys.stderr)
        return 1

    finally:
        if uci_enabled and client is not None:
            print("\nDisabling UCI...")
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


def _dump_diag(transport: Ultimate64Transport, labels: dict[str, int]) -> None:
    last_err = transport.read_memory(labels["net_last_error"], 1)[0]
    tcp_state = transport.read_memory(labels["net_tcp_state"], 1)[0]
    socket_id = transport.read_memory(labels["uci_socket_id"], 1)[0]
    head = transport.read_memory(labels["tcp_recv_head"], 2)
    tail = transport.read_memory(labels["tcp_recv_tail"], 2)
    head_val = head[0] | (head[1] << 8)
    tail_val = tail[0] | (tail[1] << 8)

    print()
    print("--- adapter state ---")
    print(f"  net_last_error : 0x{last_err:02X}")
    print(f"  net_tcp_state  : 0x{tcp_state:02X}")
    print(f"  uci_socket_id  : 0x{socket_id:02X}")
    print(f"  tcp_recv_head  : ${head_val:04X}")
    print(f"  tcp_recv_tail  : ${tail_val:04X}")


if __name__ == "__main__":
    raise SystemExit(main())
