#!/usr/bin/env python3
"""
Phase 3: end-to-end TCP echo test for the UCI backend.

Boots the UCI-built PRG on the real Ultimate 64 Elite, then:
  1. Quits the PRG's main_loop back to BASIC (keyboard 'Q').
  2. DMA-injects a 6502 test routine at $4200 that exercises the
     adapter's ABI:  net_dns_resolve → net_tcp_connect → net_tcp_send
     → poll loop of net_poll + net_recv_byte drain → net_tcp_close.
  3. Starts a local TCP echo server on this host's LAN IP.
  4. Triggers the routine with SYS 16896 via the keyboard buffer.
  5. Polls a sentinel byte, then DMA-reads the drained echo bytes.
  6. Asserts the echoed payload matches b"HELLO UCI".

Design notes
------------
* The injected routine runs with BASIC ROM banked out ($01 &= $FE)
  so it can read/write the shadow-BSS fields net_send_len, net_tcp_state,
  and net_last_error at $BC5x directly.
* net_tcp_connect A/X calling convention = port_lo/port_hi (matches
  src/http.s).  net_dns_resolve A/X = pointer to null-terminated host.
* net_dns_resolve under UCI just memcpys into uci_host_buf; the U64E
  firmware does the real DNS inside TCP_CONNECT.  We stage a dotted-quad
  string ("192.168.X.Y\0") which U64E treats as a literal IP.
* Injection address $4200 is in the NET_BSS region ($4000-$5FFF)
  reserved to UCI_BSS; the UCI BSS allocation ends at $4120, so $4200
  onward is free RAM at boot (zero-filled by the PRG load image).
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

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
HOST_BUF_ADDR    = 0x4400   # mirrors uci_host_buf — routine will also
                            # stage via net_dns_resolve so the adapter
                            # canonicalizes the copy itself.
TEST_STRING_ADDR = 0x4440
RESULT_BUF_ADDR  = 0x4500
SENTINEL_ADDR    = 0x4540
PROGRESS_ADDR    = 0x4541
CONNECT_CARRY_ADDR = 0x4542
SEND_CARRY_ADDR    = 0x4543
RESULT_LEN_ADDR    = 0x4544
POLL_COUNT_ADDR    = 0x4545
RECV_BYTES_ADDR    = 0x4500

SENTINEL_VALUE = 0x42
ECHO_PORT      = 7777
TEST_STRING    = b"HELLO UCI"
DEFAULT_TIMEOUT = 40.0


def _detect_local_ip(target: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _run_echo_server(bind_ip: str, port: int, result: dict) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(60.0)
    try:
        srv.bind((bind_ip, port))
        srv.listen(1)
        result["listening"] = True
        conn, addr = srv.accept()
        result["client_addr"] = addr
        data = b""
        # Read up to 256 bytes then echo back — the C64 routine only
        # sends TEST_STRING, but we give ourselves slack.
        conn.settimeout(10.0)
        try:
            chunk = conn.recv(256)
            data += chunk
        except socket.timeout:
            pass
        result["received"] = data
        conn.sendall(data)
        # Keep connection alive briefly so the C64 has time to drain.
        time.sleep(0.2)
        conn.close()
    except Exception as exc:  # pragma: no cover — surfaces via result dict
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        srv.close()


def _load_labels() -> dict[str, int]:
    labels: dict[str, int] = {}
    for line in LABELS_PATH.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "al" and parts[2].startswith("."):
            name = parts[2][1:]
            _, hex_addr = parts[1].split(":", 1)
            labels[name] = int(hex_addr, 16)
    return labels


def _build_test_routine(labels: dict[str, int], host_ip: str, port: int) -> bytes:
    """Emit a 6502 routine that drives the UCI adapter ABI end-to-end.

    The routine assumes:
      * BASIC ROM currently banked in (we bank it out immediately).
      * The test string has been DMA-written to TEST_STRING_ADDR.
      * uci_host_buf has been DMA-written with the host IP + null.
    """
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
    net_init          = labels["net_init"]
    net_dhcp_acquire  = labels["net_dhcp_acquire"]
    net_dns_resolve   = labels["net_dns_resolve"]
    net_tcp_connect   = labels["net_tcp_connect"]
    net_tcp_send      = labels["net_tcp_send"]
    net_tcp_close     = labels["net_tcp_close"]
    net_poll          = labels["net_poll"]
    net_recv_byte     = labels["net_recv_byte"]
    net_send_len      = labels["net_send_len"]
    uci_host_buf      = labels["uci_host_buf"]

    # --- 0) Bank BASIC ROM OUT so $A000-$BFFF is RAM (net_send_len etc.) ---
    emit_lda_abs(0x0001)
    emit(0x29, 0xFE)          # AND #$FE — clear bit 0
    emit_sta_abs(0x0001)

    # Clear result markers
    emit_lda_imm(0x00)
    emit_sta_abs(PROGRESS_ADDR)
    emit_sta_abs(SENTINEL_ADDR)
    emit_sta_abs(CONNECT_CARRY_ADDR)
    emit_sta_abs(SEND_CARRY_ADDR)
    emit_sta_abs(RESULT_LEN_ADDR)
    emit_sta_abs(POLL_COUNT_ADDR)

    emit_progress(0x01)

    # Re-init UCI to make sure the PRG's auto-init left it idle
    emit_jsr(net_init)
    emit_progress(0x02)

    # --- 1) DNS resolve (stage hostname) ---
    emit_lda_imm(HOST_BUF_ADDR & 0xFF)
    emit_ldx_imm((HOST_BUF_ADDR >> 8) & 0xFF)
    emit_jsr(net_dns_resolve)
    emit_progress(0x03)

    # --- 2) TCP connect: AX = port_lo/port_hi ---
    emit_lda_imm(port & 0xFF)
    emit_ldx_imm((port >> 8) & 0xFF)
    emit_jsr(net_tcp_connect)
    # Store carry into flag byte:
    # After JSR, Carry is in processor P register. Use PHP/PLA trick.
    emit(0x08)                # PHP
    emit(0x68)                # PLA
    emit_sta_abs(CONNECT_CARRY_ADDR)
    emit_progress(0x04)

    # --- 3) set net_send_len = len(TEST_STRING) ---
    emit_lda_imm(len(TEST_STRING))
    emit_sta_abs(net_send_len + 0)
    emit_lda_imm(0x00)
    emit_sta_abs(net_send_len + 1)

    # --- 4) TCP send: AX = ptr to TEST_STRING ---
    emit_lda_imm(TEST_STRING_ADDR & 0xFF)
    emit_ldx_imm((TEST_STRING_ADDR >> 8) & 0xFF)
    emit_jsr(net_tcp_send)
    emit(0x08)
    emit(0x68)
    emit_sta_abs(SEND_CARRY_ADDR)
    emit_progress(0x05)

    # --- 5) Poll + drain loop.
    #
    # Structure:
    #   poll_top:   JSR net_poll
    #   drain_top:  JSR net_recv_byte
    #               BCS drain_end              ; C=1 means ring empty
    #               LDY RESULT_LEN_ADDR
    #               STA RESULT_BUF_ADDR,Y      ; (via zero-page not avail — use SMC)
    #               INC RESULT_LEN_ADDR
    #               JMP drain_top
    #   drain_end:  LDA RESULT_LEN_ADDR
    #               CMP #<len(TEST_STRING)
    #               BCS poll_out               ; enough bytes, finish
    #               delay ~16 ms
    #               DEC retry_counter
    #               BEQ poll_out               ; out of budget
    #               JMP poll_top
    #   poll_out:
    #
    # We don't have a free Y across the drain (net_recv_byte clobbers it).
    # Use RESULT_LEN_ADDR itself as the byte-count; TAY just before the
    # STA abs,Y and reload A from a stash slot.
    retry_counter = 0x4546
    stash_byte    = 0x4547

    emit_lda_imm(200)                 # 200 * 16 ms ≈ 3.2 s budget
    emit_sta_abs(retry_counter)

    poll_top = ROUTINE_ADDR + len(code)
    emit_jsr(net_poll)

    drain_top = ROUTINE_ADDR + len(code)
    emit_jsr(net_recv_byte)
    # BCS drain_end — forward branch, patched after we know the offset.
    bcs_end_pos = len(code)
    emit(0xB0, 0x00)

    emit_sta_abs(stash_byte)          # park the byte
    emit_lda_abs(RESULT_LEN_ADDR)
    emit(0xA8)                        # TAY
    emit_lda_abs(stash_byte)
    emit(0x99, RESULT_BUF_ADDR & 0xFF, (RESULT_BUF_ADDR >> 8) & 0xFF)  # STA abs,Y
    emit(0xEE, RESULT_LEN_ADDR & 0xFF, (RESULT_LEN_ADDR >> 8) & 0xFF)  # INC len
    emit_jmp(drain_top)

    drain_end = len(code)
    code[bcs_end_pos + 1] = (drain_end - (bcs_end_pos + 2)) & 0xFF

    # If len >= len(TEST_STRING), exit to close.
    emit_lda_abs(RESULT_LEN_ADDR)
    emit(0xC9, len(TEST_STRING))      # CMP #9
    bcs_out_pos = len(code)
    emit(0xB0, 0x00)                  # BCS poll_out — patched below

    # Delay ~16 ms: LDX #$FF / LDY #$20 / inner: DEX / BNE -3 / DEY / BNE inner
    emit_ldx_imm(0xFF)
    emit(0xA0, 0x20)
    delay_inner = ROUTINE_ADDR + len(code)
    emit(0xCA)                        # DEX
    emit(0xD0, 0xFD)                  # BNE inner
    emit(0x88)                        # DEY
    back = (delay_inner - (ROUTINE_ADDR + len(code) + 2)) & 0xFF
    emit(0xD0, back)

    # DEC retry; if 0 give up
    emit(0xCE, retry_counter & 0xFF, (retry_counter >> 8) & 0xFF)
    emit(0xF0, 0x03)                  # BEQ +3 (skip JMP)
    emit_jmp(poll_top)

    # poll_out:
    poll_out = len(code)
    code[bcs_out_pos + 1] = (poll_out - (bcs_out_pos + 2)) & 0xFF

    emit_progress(0x06)

    # --- 6) close socket ---
    emit_jsr(net_tcp_close)
    emit_progress(0x07)

    # --- 7) sentinel ---
    emit_lda_imm(SENTINEL_VALUE)
    emit_sta_abs(SENTINEL_ADDR)

    # Park CPU
    park_addr = ROUTINE_ADDR + len(code)
    emit_jmp(park_addr)

    return bytes(code)


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        print("Run: make BACKEND=uci clean && make BACKEND=uci", file=sys.stderr)
        return 2
    if not LABELS_PATH.is_file():
        print(f"ERROR: labels.txt not found at {LABELS_PATH}", file=sys.stderr)
        return 2

    labels = _load_labels()
    required = [
        "net_init", "net_dhcp_acquire", "net_dns_resolve",
        "net_tcp_connect", "net_tcp_send", "net_tcp_close",
        "net_poll", "net_recv_byte",
        "net_send_len", "net_tcp_state", "net_last_error",
        "uci_host_buf",
    ]
    missing = [n for n in required if n not in labels]
    if missing:
        print(f"ERROR: missing labels: {missing}", file=sys.stderr)
        return 2

    for n in required:
        print(f"  {n:18s} = ${labels[n]:04X}")

    test_host_ip = _detect_local_ip(HOST)
    print(f"Dev host LAN IP : {test_host_ip}")
    print(f"Echo port       : {ECHO_PORT}")
    print(f"Test string     : {TEST_STRING!r}")

    server_result: dict = {}
    server_thread = threading.Thread(
        target=_run_echo_server,
        args=(test_host_ip, ECHO_PORT, server_result),
        daemon=True,
    )
    server_thread.start()

    # Wait for server to be listening
    for _ in range(60):
        if server_result.get("listening"):
            break
        time.sleep(0.05)
    else:
        print("ERROR: Echo server failed to start", file=sys.stderr)
        return 1
    print(f"Echo server listening on {test_host_ip}:{ECHO_PORT}")

    routine_bytes = _build_test_routine(labels, test_host_ip, ECHO_PORT)
    print(f"Routine size    : {len(routine_bytes)} bytes @ ${ROUTINE_ADDR:04X}")

    host_bytes = (test_host_ip.encode("ascii") + b"\x00").ljust(32, b"\x00")

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

        print("Enabling UCI (Command Interface)...")
        enable_uci(client)
        uci_enabled = True

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)

        print("run_prg(PRG)...")
        client.run_prg(prg)
        # Let the PRG complete its auto-init: entropy, REU stash, DHCP.
        # Empirically this has been ~18-22 s on the U64E.
        time.sleep(22.0)

        # Sanity-check main_loop state via net_initialized flag.
        init_flag = transport.read_memory(labels["net_initialized"], 1)[0]
        print(f"net_initialized = ${init_flag:02X}")
        tcp_state = transport.read_memory(labels["net_tcp_state"], 1)[0]
        print(f"net_tcp_state   = ${tcp_state:02X}")

        # --- Step 1: Quit PRG main_loop back to BASIC ("Q") ---
        # The Q handler re-enables BASIC ROM and RTS's to BASIC.
        print("Sending 'Q' to exit PRG main_loop...")
        send_text(transport, "q\r")
        time.sleep(2.0)  # BASIC READY. prompt returns

        # --- Step 2: DMA-write test routine + data areas ---
        # Chunk into 64-byte pieces to stay under the 128 B firmware PUT limit.
        CHUNK = 64
        for i in range(0, len(routine_bytes), CHUNK):
            transport.write_memory(
                ROUTINE_ADDR + i,
                routine_bytes[i:i + CHUNK],
            )
        transport.write_memory(HOST_BUF_ADDR, host_bytes)
        transport.write_memory(TEST_STRING_ADDR, TEST_STRING)

        # Also pre-populate uci_host_buf directly — net_dns_resolve in the
        # routine copies from HOST_BUF_ADDR into uci_host_buf, but we DMA
        # the string into both locations for belt-and-braces determinism.
        transport.write_memory(labels["uci_host_buf"], host_bytes)

        # Clear result area (sentinel + collected bytes)
        transport.write_memory(RESULT_BUF_ADDR, bytes(0x80))

        # --- Step 3: trigger via SYS (BASIC ROM currently enabled) ---
        sys_line = f"sys{ROUTINE_ADDR}\r"
        print(f"Triggering: {sys_line.strip()}")
        send_text(transport, sys_line)

        # --- Step 4: poll sentinel ---
        deadline = time.time() + DEFAULT_TIMEOUT
        last_progress = -1
        sentinel = 0
        while time.time() < deadline:
            time.sleep(0.25)
            # Read [SENTINEL, PROGRESS] as a 2-byte block; SENTINEL_ADDR
            # is $4540 and PROGRESS_ADDR = $4541.
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
            print(f"TIMEOUT: sentinel not set (last progress=0x{last_progress:02X})",
                  file=sys.stderr)
            _dump_state(transport, labels)
            return 1

        # --- Step 5: read results ---
        _dump_state(transport, labels)

        result_len = transport.read_memory(RESULT_LEN_ADDR, 1)[0]
        print(f"result_len      = {result_len}")
        if result_len == 0:
            print("FAIL: no bytes drained into ring", file=sys.stderr)
            return 1

        drained = bytes(transport.read_memory(RESULT_BUF_ADDR, min(result_len, 64)))
        print(f"drained bytes   = {drained.hex()}  ({drained!r})")

        # Wait for echo server thread
        server_thread.join(timeout=5.0)
        if "error" in server_result:
            print(f"echo server error: {server_result['error']}", file=sys.stderr)
        print(f"server recv     = {server_result.get('received')!r}")
        print(f"server peer     = {server_result.get('client_addr')}")

        if drained[:len(TEST_STRING)] == TEST_STRING:
            print()
            print("PASS: echo roundtrip matches")
            return 0
        else:
            print()
            print(f"FAIL: expected {TEST_STRING!r}, got {drained!r}", file=sys.stderr)
            return 1

    finally:
        if uci_enabled and client is not None:
            print("Disabling UCI...")
            try:
                disable_uci(client)
            except Exception as exc:  # pragma: no cover
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


def _dump_state(transport: Ultimate64Transport, labels: dict[str, int]) -> None:
    last_err = transport.read_memory(labels["net_last_error"], 1)[0]
    tcp_state = transport.read_memory(labels["net_tcp_state"], 1)[0]
    send_len = transport.read_memory(labels["net_send_len"], 2)
    head = transport.read_memory(labels["tcp_recv_head"], 2)
    tail = transport.read_memory(labels["tcp_recv_tail"], 2)
    prog = transport.read_memory(PROGRESS_ADDR, 1)[0]
    conn_c = transport.read_memory(CONNECT_CARRY_ADDR, 1)[0]
    send_c = transport.read_memory(SEND_CARRY_ADDR, 1)[0]
    result_len = transport.read_memory(RESULT_LEN_ADDR, 1)[0]
    socket_id = transport.read_memory(labels["uci_socket_id"], 1)[0]

    print()
    print("--- adapter state ---")
    print(f"  progress       : 0x{prog:02X}")
    print(f"  connect P-flag : 0x{conn_c:02X}  (bit0 = Carry at return)")
    print(f"  send P-flag    : 0x{send_c:02X}")
    print(f"  socket_id      : 0x{socket_id:02X}")
    print(f"  net_last_error : 0x{last_err:02X}")
    print(f"  net_tcp_state  : 0x{tcp_state:02X}")
    print(f"  net_send_len   : {send_len[0] | (send_len[1] << 8)}")
    print(f"  tcp_recv_head  : ${head[0] | (head[1] << 8):04X}")
    print(f"  tcp_recv_tail  : ${tail[0] | (tail[1] << 8):04X}")
    print(f"  result_len     : {result_len}")


if __name__ == "__main__":
    raise SystemExit(main())
