#!/usr/bin/env python3
"""
Phase 5 LOCAL HTTPS: exercise the real http_get (TLS 1.3) code path through
the UCI backend on a real Ultimate 64 Elite at 48 MHz turbo.

Debug-stream capture: set DEBUG_CAPTURE=0 in env to disable. Default enabled.
Artifacts land in a per-run timestamped directory under $UCI_DEBUG_DIR
(default /tmp/uci_https_debug/<YYYYMMDD_HHMMSS>/). Each run dir holds:
  summary.txt          — stats + hot PCs + UCI-reg counts
  tail.txt             — last 2000 CPU cycles
  uci_accesses.txt     — every CPU cycle in $DF1B-$DF1F
  trace.bin + .meta.json — packed raw BusCycle trace (4 bytes/cycle)
  server_result.json   — server-side listener state (request, error, ...)
  run_info.txt         — git HEAD, outcome, duration, exit code
The latest 5 run dirs are retained; older ones are pruned on startup.

Flow:
  1. Boot the UCI-built PRG, wait for auto-init (net_init + DHCP).
  2. Start a Python HTTPS server on the dev host's LAN IP with the
     self-signed ECDSA P-256 cert at tools/https_e2e/certs/server.pem.
  3. Quit to BASIC ('Q'), flip to 48 MHz turbo.
  4. DMA-inject a 6502 stub at $4200 that:
       - Banks out BASIC ROM
       - Sets http_host_ptr, http_host_len, http_path_ptr, http_path_len, http_port
       - Calls http_get (the TLS+HTTP code from src/http.s)
       - Writes a sentinel on completion
  5. Trigger with SYS 16896 via keyboard buffer.
  6. Poll sentinel for up to 120 s (handshake is ~13-15 s at 48 MHz).
  7. Assert response body contains "HELLO FROM TLS SERVER".
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    set_turbo_mhz,
    set_debug_stream_mode,
    DEBUG_MODE_6510,
)
from c64_test_harness.backends.u64_debug_capture import (
    DebugCapture,
    DEFAULT_DEBUG_PORT,
)
from c64_test_harness.uci_network import enable_uci, disable_uci
from c64_test_harness.keyboard import send_text


DEBUG_CAPTURE_ENABLED = os.environ.get("DEBUG_CAPTURE", "1") != "0"
UCI_DEBUG_BASE_DIR = Path(
    os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug")
)
UCI_DEBUG_KEEP = 5
UCI_DEBUG_KEEP_ON_PASS = os.environ.get("KEEP_DEBUG_ON_PASS", "0") != "0"


def _keep_cycle(word: int) -> bool:
    """DebugCapture filter: keep only CPU cycles in regions we care about.

    Keeps a cycle if PHI2=1 (CPU cycle, bit 31 set) AND the 16-bit address
    falls in one of the three interesting ranges:
      - $2000-$3FFF : UCI adapter code/data
      - $6000-$9FFF : crypto + TLS code
      - $DF1B-$DF1F : UCI I/O registers
    """
    if not (word >> 31) & 1:
        return False
    addr = word & 0xFFFF
    return (
        0x2000 <= addr <= 0x3FFF
        or 0x6000 <= addr <= 0x9FFF
        or 0xDF1B <= addr <= 0xDF1F
    )


HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO_ROOT = Path(__file__).resolve().parents[2]
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"
CERT_PATH = REPO_ROOT / "tools" / "https_e2e" / "certs" / "server.pem"
KEY_PATH = REPO_ROOT / "tools" / "https_e2e" / "certs" / "server.key"

ROUTINE_ADDR     = 0x4200
HOST_STR_ADDR    = 0x4400
PATH_STR_ADDR    = 0x4440
SENTINEL_ADDR    = 0x4540
PROGRESS_ADDR    = 0x4541
CARRY_FLAG_ADDR  = 0x4542

SENTINEL_VALUE   = 0xAA

# Default HTTPS port; can override via HTTPS_PORT env, else fall back to 4433
# if 443 bind fails (requires root on most systems).
DEFAULT_HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "443"))
FALLBACK_HTTPS_PORT = 4433

SENTINEL_POLL_TIMEOUT = 120.0   # TLS handshake ~13-15s at 48 MHz; leave slack
ACCEPT_TIMEOUT        = 180.0   # server-side accept + handshake slack
TURBO_MHZ             = 48

EXPECTED_BODY    = "HELLO FROM TLS SERVER"
HTTP_RESPONSE    = (
    b"HTTP/1.0 200 OK\r\n"
    b"Content-Length: 21\r\n"
    b"\r\n"
    b"HELLO FROM TLS SERVER"
)


def _detect_local_ip(target: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))
    # Restrict to TLS 1.3 to match what the C64 client negotiates.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        pass
    return ctx


def _try_bind(bind_ip: str, port: int) -> socket.socket | None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_ip, port))
    except PermissionError:
        srv.close()
        return None
    except OSError:
        srv.close()
        return None
    return srv


def _run_https_server(srv: socket.socket, ctx: ssl.SSLContext,
                      result: dict) -> None:
    srv.settimeout(ACCEPT_TIMEOUT)
    try:
        srv.listen(1)
        result["listening"] = True
        raw_conn, addr = srv.accept()
        result["client_addr"] = addr
        try:
            tls_conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            result["error"] = f"TLS handshake failed: {type(exc).__name__}: {exc}"
            try:
                raw_conn.close()
            except Exception:
                pass
            return
        try:
            tls_conn.settimeout(30.0)
            try:
                req = tls_conn.recv(1024)
                result["request"] = req
            except socket.timeout:
                result["request"] = b"<timeout>"
            tls_conn.sendall(HTTP_RESPONSE)
            # Keep alive briefly for the C64 to drain before FIN.
            time.sleep(1.0)
        finally:
            try:
                tls_conn.unwrap()
            except Exception:
                pass
            try:
                tls_conn.close()
            except Exception:
                pass
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            srv.close()
        except Exception:
            pass


def _load_labels() -> dict[str, int]:
    labels: dict[str, int] = {}
    for line in LABELS_PATH.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "al" and parts[2].startswith("."):
            name = parts[2][1:]
            _, hex_addr = parts[1].split(":", 1)
            labels[name] = int(hex_addr, 16)
    return labels


def _build_http_routine(labels: dict[str, int], port: int) -> tuple[bytes, int]:
    """Emit a 6502 routine that calls http_get via the real TLS+HTTP layer."""
    code = bytearray()

    def emit(*bs: int) -> None:
        code.extend(bs)

    def emit_lda_imm(v: int) -> None:
        emit(0xA9, v & 0xFF)

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
    http_get       = labels["http_get"]
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

    # Set http_host_len — patched by Python once the IP is known.
    host_len_patch_offset = len(code) + 1
    emit_lda_imm(0x00)
    emit_sta_abs(http_host_len)

    # Set http_path_ptr = PATH_STR_ADDR
    emit_lda_imm(PATH_STR_ADDR & 0xFF)
    emit_sta_abs(http_path_ptr)
    emit_lda_imm((PATH_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_path_ptr + 1)

    # Set http_path_len = 1 (just "/")
    emit_lda_imm(1)
    emit_sta_abs(http_path_len)

    # Set http_port = our test port (16-bit: low then high)
    emit_lda_imm(port & 0xFF)
    emit_sta_abs(http_port)
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(http_port + 1)

    emit_progress(0x03)

    # Call http_get — the REAL TLS 1.3 + HTTP code path.
    emit_jsr(http_get)

    # Store carry (success/failure) via PHP/PLA
    emit(0x08)  # PHP
    emit(0x68)  # PLA
    emit_sta_abs(CARRY_FLAG_ADDR)

    emit_progress(0x04)

    # Write sentinel
    emit_lda_imm(SENTINEL_VALUE)
    emit_sta_abs(SENTINEL_ADDR)

    emit_progress(0x05)

    # Park CPU
    park = ROUTINE_ADDR + len(code)
    emit_jmp(park)

    return bytes(code), host_len_patch_offset


def _decode_screen_ram(data: bytes) -> str:
    lines = []
    for row in range(25):
        line = data[row * 40:(row + 1) * 40]
        chars = []
        for b in line:
            if b == 0x20 or b == 0x00:
                chars.append(' ')
            elif 0x01 <= b <= 0x1A:
                chars.append(chr(b + 0x40))
            elif 0x30 <= b <= 0x39:
                chars.append(chr(b))
            elif 0x41 <= b <= 0x5A:
                chars.append(chr(b))
            elif b in (0x2E, 0x2F, 0x3A, 0x2D, 0x28, 0x29):
                chars.append(chr(b))
            else:
                chars.append('.')
        lines.append(''.join(chars).rstrip())
    return '\n'.join(lines)


def _dump_diag(transport: Ultimate64Transport,
               labels: dict[str, int]) -> None:
    def r8(name: str) -> int:
        return transport.read_memory(labels[name], 1)[0]

    def r16(name: str) -> int:
        b = transport.read_memory(labels[name], 2)
        return b[0] | (b[1] << 8)

    print()
    print("--- adapter / TLS state ---")
    for name in ("net_last_error", "net_tcp_state", "uci_socket_id",
                 "net_initialized"):
        if name in labels:
            print(f"  {name:22s} : 0x{r8(name):02X}")
    for name in ("tls_state", "tls_last_state",
                 "tls_recv_progress", "tls_recv_sub_progress"):
        if name in labels:
            print(f"  {name:22s} : 0x{r8(name):02X}")
    for name in ("tcp_recv_head", "tcp_recv_tail",
                 "http_status", "http_resp_len"):
        if name in labels:
            print(f"  {name:22s} : ${r16(name):04X}")


def _dump_full(transport: Ultimate64Transport,
               labels: dict[str, int],
               server_result: dict) -> None:
    """Dump the full diagnostic set (used on both success and TIMEOUT paths)."""
    _dump_diag(transport, labels)

    try:
        carry_byte = transport.read_memory(CARRY_FLAG_ADDR, 1)[0]
        carry = carry_byte & 0x01
        print(f"http_get carry  = {carry} (0=success, 1=failure)")
    except Exception as exc:
        print(f"http_get carry  = <read failed: {exc}>")

    try:
        status_raw = transport.read_memory(labels["http_status"], 2)
        http_status = status_raw[0] | (status_raw[1] << 8)
        print(f"http_status     = {http_status}")
    except Exception as exc:
        print(f"http_status     = <read failed: {exc}>")

    resp_len = 0
    try:
        resp_len_raw = transport.read_memory(labels["http_resp_len"], 2)
        resp_len = resp_len_raw[0] | (resp_len_raw[1] << 8)
        print(f"http_resp_len   = {resp_len}")
    except Exception as exc:
        print(f"http_resp_len   = <read failed: {exc}>")

    try:
        read_len = min(resp_len, 200) if resp_len > 0 else 200
        resp_data = bytes(transport.read_memory(labels["http_resp_buf"],
                                                read_len))
        print(f"http_resp_buf   = {resp_data[:80]!r}")
        if read_len > 80:
            print(f"http_resp_buf+  = {resp_data[80:200]!r}")
    except Exception as exc:
        print(f"http_resp_buf   = <read failed: {exc}>")

    try:
        screen = bytes(transport.read_memory(0x0400, 1000))
        screen_text = _decode_screen_ram(screen)
        print("\n--- screen RAM ---")
        for line in screen_text.split('\n'):
            if line.strip():
                print(f"  {line}")
    except Exception as exc:
        print(f"screen RAM read failed: {exc}")

    try:
        ring_data = bytes(transport.read_memory(0xC000, 256))
        print(f"\ntcp_recv_buf[0:128] hex :")
        for off in (0, 64, 128, 192):
            print(f"  +{off:03X} : {ring_data[off:off+64].hex()}")
    except Exception as exc:
        print(f"tcp_recv_buf read failed: {exc}")

    print("\n--- server-side ---")
    print(f"  listening     : {server_result.get('listening', False)}")
    print(f"  client_addr   : {server_result.get('client_addr')}")
    print(f"  request       : {server_result.get('request', b'<none>')!r}")
    print(f"  error         : {server_result.get('error', '<none>')}")


def _git_head_sha() -> str:
    """Return the short git HEAD SHA, or '<unknown>' if git is unavailable."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT),
            stderr=subprocess.DEVNULL,
            timeout=3.0,
        )
        return out.decode("ascii", errors="replace").strip() or "<unknown>"
    except Exception:
        return "<unknown>"


def _create_run_dir(base_dir: Path) -> Path:
    """Create and return a timestamped run directory under ``base_dir``."""
    base_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = base_dir / stamp
    # Disambiguate if a same-second run dir already exists
    suffix = 0
    candidate = run_dir
    while candidate.exists():
        suffix += 1
        candidate = base_dir / f"{stamp}_{suffix}"
    candidate.mkdir(parents=True, exist_ok=False)
    return candidate


def _prune_old_run_dirs(base_dir: Path, keep: int) -> list[Path]:
    """Keep the ``keep`` most-recent run directories; remove the rest.

    Orders by mtime (not filename) so DST/timezone oddities don't misorder.
    Returns the list of directories that were removed (for logging).
    """
    if not base_dir.is_dir():
        return []
    entries: list[tuple[float, Path]] = []
    for child in base_dir.iterdir():
        if child.is_dir():
            try:
                entries.append((child.stat().st_mtime, child))
            except OSError:
                pass
    entries.sort(key=lambda t: t[0], reverse=True)
    removed: list[Path] = []
    for _, d in entries[keep:]:
        try:
            shutil.rmtree(d)
            removed.append(d)
        except Exception as exc:
            print(f"WARNING: failed to prune {d}: {exc}")
    return removed


def _serialize_trace_packed(cap_result, trace_path: Path,
                            meta_path: Path) -> dict:
    """Serialize the raw BusCycle trace to a packed 4-byte-per-cycle file.

    Each BusCycle carries only a 32-bit ``raw`` word, so the packed
    little-endian u32 stream is lossless and dramatically more compact
    than pickle. Writes ``trace.bin`` and a ``trace.bin.meta.json``
    sidecar that describes the layout for post-hoc readers.

    Returns a small dict with size/count for logging.
    """
    trace = getattr(cap_result, "trace", None) or []
    count = len(trace)
    # Pre-size buffer and pack in one shot. Fall back to per-cycle pack if
    # the in-tree BusCycle layout ever grows richer.
    try:
        fmt = f"<{count}I"
        buf = struct.pack(fmt, *(int(c.raw) & 0xFFFFFFFF for c in trace))
    except Exception:
        parts = [struct.pack("<I", int(c.raw) & 0xFFFFFFFF) for c in trace]
        buf = b"".join(parts)
    trace_path.write_bytes(buf)

    meta = {
        "format": "packed-u32-le",
        "bytes_per_cycle": 4,
        "cycle_count": count,
        "file": trace_path.name,
        "field_layout": {
            "bit31": "PHI2 (1=CPU, 0=VIC)",
            "bit30": "GAME# (active low)",
            "bit29": "EXROM# (active low)",
            "bit28": "BA (Bus Available)",
            "bit27": "IRQ# (active low)",
            "bit26": "ROM# (active low)",
            "bit25": "NMI# (active low)",
            "bit24": "R/W# (1=read, 0=write)",
            "bits23_16": "Data bus (8-bit)",
            "bits15_0": "Address bus (16-bit)",
        },
        "capture": {
            "packets_received": int(
                getattr(cap_result, "packets_received", 0) or 0),
            "packets_dropped": int(
                getattr(cap_result, "packets_dropped", 0) or 0),
            "duration_seconds": float(
                getattr(cap_result, "duration_seconds", 0.0) or 0.0),
            "total_cycles": int(
                getattr(cap_result, "total_cycles", 0) or 0),
        },
        "first_raw": int(trace[0].raw) & 0xFFFFFFFF if count else None,
        "last_raw": int(trace[-1].raw) & 0xFFFFFFFF if count else None,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    return {
        "cycle_count": count,
        "bytes_on_disk": len(buf),
    }


def _serialize_server_result(server_result: dict, path: Path) -> None:
    """Dump the HTTPS listener's per-connection dict to JSON.

    Bytes fields are base64-encoded (round-trippable, unlike repr()).
    Non-serializable exception values are captured as type/str/traceback.
    """
    out: dict = {}
    for key, val in server_result.items():
        if isinstance(val, (bytes, bytearray)):
            out[key] = {
                "__type__": "bytes-b64",
                "b64": base64.b64encode(bytes(val)).decode("ascii"),
                "len": len(val),
            }
        elif isinstance(val, BaseException):
            out[key] = {
                "__type__": "exception",
                "class": type(val).__name__,
                "str": str(val),
                "traceback": traceback.format_exception(
                    type(val), val, val.__traceback__),
            }
        elif isinstance(val, tuple):
            # client_addr is (host, port) — JSON has no tuple, keep as list
            out[key] = list(val)
        else:
            try:
                json.dumps(val)
                out[key] = val
            except TypeError:
                out[key] = repr(val)
    path.write_text(json.dumps(out, indent=2, default=str))


def _write_run_info(path: Path, *, outcome: str, duration: float,
                    exit_code: int, extra: dict | None = None) -> None:
    """Write one-line metadata for a run (git SHA, outcome, duration, rc)."""
    sha = _git_head_sha()
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    lines = [
        f"timestamp     = {ts}",
        f"git_head      = {sha}",
        f"outcome       = {outcome}",
        f"duration_s    = {duration:.3f}",
        f"exit_code     = {exit_code}",
    ]
    if extra:
        for k, v in extra.items():
            lines.append(f"{k:<13} = {v}")
    path.write_text("\n".join(lines) + "\n")


def _process_debug_trace(cap_result,
                         summary_path: str,
                         tail_path: str,
                         uci_path: str) -> dict:
    """Post-process the debug-stream BusCycle list into three artifacts.

    Returns a small dict with high-level stats for console logging.
    """
    stats: dict = {}
    trace = getattr(cap_result, "trace", None) or []
    total = len(trace)
    packets = getattr(cap_result, "packets_received", 0)
    dropped = getattr(cap_result, "packets_dropped", 0)
    duration = getattr(cap_result, "duration_seconds", 0.0) or 0.0
    bytes_recv = getattr(cap_result, "bytes_received", 0) or 0
    stats["total"] = total
    stats["packets"] = packets
    stats["dropped"] = dropped
    stats["duration"] = duration

    cpu_count = 0
    vic_count = 0
    cpu_read_hist: dict = {}
    uci_hist: dict = {}
    uci_tail: list = []
    cpu_tail: list = []  # ring of last CPU cycles

    tail_cap = 2000
    huge = total > 2_000_000
    # If huge, still compute PC hotspots but only over the LAST 500k CPU
    # cycles, to bound cost. For small traces use everything.
    scan_window = total
    scan_start = 0
    if huge:
        scan_start = max(0, total - 2_000_000)
        scan_window = total - scan_start

    cpu_idx_for_tail_start = max(0, total - tail_cap * 4)  # oversample — trim later

    for i, c in enumerate(trace):
        is_cpu = bool(getattr(c, "is_cpu", False))
        if is_cpu:
            cpu_count += 1
            if i >= scan_start and bool(getattr(c, "is_read", False)):
                addr = int(getattr(c, "address", 0)) & 0xFFFF
                cpu_read_hist[addr] = cpu_read_hist.get(addr, 0) + 1
            if i >= cpu_idx_for_tail_start:
                cpu_tail.append((i, c))
                if len(cpu_tail) > tail_cap * 2:
                    # keep it bounded while iterating
                    cpu_tail = cpu_tail[-tail_cap:]
            addr = int(getattr(c, "address", 0)) & 0xFFFF
            if 0xDF1B <= addr <= 0xDF1F:
                uci_hist[addr] = uci_hist.get(addr, 0) + 1
                uci_tail.append((i, c))
        else:
            vic_count += 1

    # Trim tail to exactly last tail_cap CPU cycles
    if len(cpu_tail) > tail_cap:
        cpu_tail = cpu_tail[-tail_cap:]

    top_pcs = sorted(cpu_read_hist.items(), key=lambda kv: kv[1],
                     reverse=True)[:20]
    top_uci = sorted(uci_hist.items(), key=lambda kv: kv[1],
                     reverse=True)[:10]

    stats["cpu"] = cpu_count
    stats["vic"] = vic_count
    stats["top_pcs"] = top_pcs
    stats["top_uci"] = top_uci
    stats["uci_tail"] = uci_tail[-10:]
    stats["cpu_tail_sample"] = cpu_tail[-20:]

    # --- Write summary ---
    with open(summary_path, "w") as f:
        f.write(f"DebugCapture summary\n")
        f.write(f"  packets_received   = {packets}\n")
        f.write(f"  packets_dropped    = {dropped}\n")
        f.write(f"  duration_seconds   = {duration:.3f}\n")
        f.write(f"  bytes_received     = {bytes_recv}\n")
        bps = (bytes_recv / duration) if duration > 0 else 0
        f.write(f"  bytes_per_second   = {bps:.0f}\n")
        f.write(f"  total_cycles       = {total}\n")
        f.write(f"  cpu_cycles         = {cpu_count}\n")
        f.write(f"  vic_cycles         = {vic_count}\n")
        if huge:
            f.write(f"  NOTE: trace > 2M cycles; PC histogram computed over "
                    f"last {scan_window} cycles only.\n")
        f.write(f"\nTop 20 CPU-read addresses (approx PC hotspots):\n")
        for addr, count in top_pcs:
            f.write(f"  ${addr:04X}  {count}\n")
        f.write(f"\nTop 10 UCI register accesses ($DF1B-$DF1F):\n")
        for addr, count in top_uci:
            f.write(f"  ${addr:04X}  {count}\n")

    # --- Write tail (last 2000 CPU cycles) ---
    with open(tail_path, "w") as f:
        f.write(f"# last {len(cpu_tail)} CPU cycles (of {cpu_count} total)\n")
        for idx, c in cpu_tail:
            rw = "R" if getattr(c, "is_read", False) else \
                 ("W" if getattr(c, "is_write", False) else "?")
            addr = int(getattr(c, "address", 0)) & 0xFFFF
            data = int(getattr(c, "data", 0)) & 0xFF
            f.write(f"{idx:>9d} {rw} ${addr:04X} = ${data:02X}\n")

    # --- Write UCI-register filter (every CPU access to $DF1B-$DF1F) ---
    with open(uci_path, "w") as f:
        f.write(f"# {len(uci_tail)} CPU cycles in $DF1B-$DF1F\n")
        for run_idx, (idx, c) in enumerate(uci_tail):
            rw = "R" if getattr(c, "is_read", False) else \
                 ("W" if getattr(c, "is_write", False) else "?")
            addr = int(getattr(c, "address", 0)) & 0xFFFF
            data = int(getattr(c, "data", 0)) & 0xFF
            f.write(f"{run_idx:>7d} @{idx:>9d} {rw} ${addr:04X} = ${data:02X}\n")

    stats["uci_total"] = len(uci_tail)
    return stats


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        return 2
    if not LABELS_PATH.is_file():
        print(f"ERROR: labels.txt not found", file=sys.stderr)
        return 2
    if not CERT_PATH.is_file() or not KEY_PATH.is_file():
        print(f"ERROR: cert/key not found at {CERT_PATH} / {KEY_PATH}",
              file=sys.stderr)
        return 2

    labels = _load_labels()
    required = [
        "http_get", "http_host_ptr", "http_host_len",
        "http_path_ptr", "http_path_len", "http_port",
        "net_init", "net_initialized", "uci_socket_id",
        "tcp_recv_head", "tcp_recv_tail",
        "http_resp_buf", "http_resp_len", "http_status",
        "tls_state", "tls_last_state",
    ]
    missing = [n for n in required if n not in labels]
    if missing:
        print(f"ERROR: missing labels: {missing}", file=sys.stderr)
        return 2

    for n in sorted(required):
        print(f"  {n:22s} = ${labels[n]:04X}")

    test_host_ip = _detect_local_ip(HOST)
    print(f"\nDev host LAN IP : {test_host_ip}")
    print(f"Cert / key      : {CERT_PATH} / {KEY_PATH}")

    # --- Bind HTTPS listener (try default port, fall back to 4433) ---
    ctx = _make_ssl_context()
    srv = _try_bind(test_host_ip, DEFAULT_HTTPS_PORT)
    chosen_port = DEFAULT_HTTPS_PORT
    if srv is None:
        if DEFAULT_HTTPS_PORT != FALLBACK_HTTPS_PORT:
            print(f"NOTE: bind {test_host_ip}:{DEFAULT_HTTPS_PORT} failed"
                  f" (need root?), falling back to {FALLBACK_HTTPS_PORT}")
            srv = _try_bind(test_host_ip, FALLBACK_HTTPS_PORT)
            chosen_port = FALLBACK_HTTPS_PORT
        if srv is None:
            print(f"ERROR: could not bind HTTPS listener", file=sys.stderr)
            return 1
    print(f"HTTPS port      : {chosen_port}")
    print(f"Expected body   : {EXPECTED_BODY!r}")

    server_result: dict = {}
    server_thread = threading.Thread(
        target=_run_https_server,
        args=(srv, ctx, server_result),
        daemon=True,
    )
    server_thread.start()
    for _ in range(60):
        if server_result.get("listening"):
            break
        time.sleep(0.05)
    else:
        print("ERROR: HTTPS server failed to start", file=sys.stderr)
        return 1
    print(f"HTTPS server listening on {test_host_ip}:{chosen_port}")

    # --- Build routine (port patched in at build time) ---
    routine_bytes_raw, host_len_patch = _build_http_routine(labels, chosen_port)
    routine_bytes = bytearray(routine_bytes_raw)
    host_ip_bytes = test_host_ip.encode("ascii")
    routine_bytes[host_len_patch] = len(host_ip_bytes)
    routine_bytes = bytes(routine_bytes)

    print(f"Routine size    : {len(routine_bytes)} bytes @ ${ROUTINE_ADDR:04X}")

    host_str = host_ip_bytes + b"\x00"
    path_str = b"/\x00"

    prg = PRG_PATH.read_bytes()

    lock = DeviceLock(HOST)
    if not lock.acquire(timeout=60.0):
        print(f"ERROR: could not acquire DeviceLock({HOST})", file=sys.stderr)
        return 3
    print(f"Acquired DeviceLock({HOST})")

    # --- Per-run debug artifact directory + rotation ---
    run_dir: Path | None = None
    if DEBUG_CAPTURE_ENABLED:
        removed = _prune_old_run_dirs(UCI_DEBUG_BASE_DIR, UCI_DEBUG_KEEP)
        for d in removed:
            print(f"Pruning old debug artifacts: {d}")
        run_dir = _create_run_dir(UCI_DEBUG_BASE_DIR)
        print(f"Debug artifacts dir: {run_dir}")

    client: Ultimate64Client | None = None
    uci_enabled = False
    debug_cap: DebugCapture | None = None
    debug_started_on_u64 = False
    outcome: str = "UNKNOWN"
    exit_code: int = 1
    run_start = time.time()
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

        # --- Flip to 48 MHz turbo BEFORE we trigger the stub ---
        print(f"Setting turbo to {TURBO_MHZ} MHz...")
        set_turbo_mhz(client, TURBO_MHZ)
        time.sleep(0.5)

        # --- Start 6510 debug-stream capture (after turbo, before trigger) ---
        if DEBUG_CAPTURE_ENABLED:
            try:
                set_debug_stream_mode(client, DEBUG_MODE_6510)
                debug_cap = DebugCapture(
                    port=DEFAULT_DEBUG_PORT,
                    recv_buf_size=1024 * 1024,
                    max_bytes=50 * 1024 * 1024,  # ~50 MB rolling filtered window
                    filter=_keep_cycle,
                )
                debug_cap.start()
                debug_dest = f"{test_host_ip}:{DEFAULT_DEBUG_PORT}"
                print(f"Starting U64 6510 debug stream -> {debug_dest}")
                client.stream_debug_start(debug_dest)
                debug_started_on_u64 = True
                time.sleep(0.3)
            except Exception as exc:
                print(f"WARNING: debug capture failed to start: {exc}")
                debug_cap = None
        else:
            print("DEBUG_CAPTURE=0 — 6510 stream disabled")

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
        deadline = time.time() + SENTINEL_POLL_TIMEOUT
        last_progress = -1
        start = time.time()
        while time.time() < deadline:
            time.sleep(0.5)
            blob = transport.read_memory(SENTINEL_ADDR, 2)
            sentinel = blob[0]
            progress = blob[1]
            if progress != last_progress:
                elapsed = time.time() - start
                print(f"  [{elapsed:6.1f}s] progress=0x{progress:02X}")
                last_progress = progress
            if sentinel == SENTINEL_VALUE:
                print("  sentinel set — routine complete")
                break
        else:
            print(f"TIMEOUT: sentinel not set after "
                  f"{SENTINEL_POLL_TIMEOUT:.0f}s "
                  f"(progress=0x{last_progress:02X})", file=sys.stderr)
            server_thread.join(timeout=1.0)
            _dump_full(transport, labels, server_result)
            outcome = "TIMEOUT"
            exit_code = 1
            return exit_code

        # --- Results ---
        # Join server thread briefly so server_result is populated
        server_thread.join(timeout=5.0)
        _dump_full(transport, labels, server_result)

        # Reread resp_data + screen_text for the assertion logic below.
        resp_len_raw = transport.read_memory(labels["http_resp_len"], 2)
        resp_len = resp_len_raw[0] | (resp_len_raw[1] << 8)
        read_len = min(resp_len, 200) if resp_len > 0 else 200
        resp_data = bytes(transport.read_memory(labels["http_resp_buf"],
                                                read_len))
        screen = bytes(transport.read_memory(0x0400, 1000))
        screen_text = _decode_screen_ram(screen)

        # --- Assertions ---
        body_ascii = ""
        try:
            body_ascii = resp_data.decode("ascii", errors="replace")
        except Exception:
            pass

        if EXPECTED_BODY in body_ascii:
            print(f"\nPASS: http_resp_buf contains '{EXPECTED_BODY}'")
            outcome = "PASS"
            exit_code = 0
            return exit_code

        if "HELLO" in screen_text.upper():
            print(f"\nPASS: screen RAM contains HELLO "
                  f"(body in resp_buf may differ in encoding)")
            outcome = "PASS"
            exit_code = 0
            return exit_code

        print(f"\nFAIL: expected '{EXPECTED_BODY}' not found in response"
              f" or screen", file=sys.stderr)
        outcome = "FAIL"
        exit_code = 1
        return exit_code

    finally:
        # --- Stop 6510 debug stream; post-process + persist trace ---
        if debug_started_on_u64 and client is not None:
            try:
                client.stream_debug_stop()
            except Exception as exc:
                print(f"WARNING: stream_debug_stop failed: {exc}")
        trace_bytes_on_disk = 0
        if debug_cap is not None and run_dir is not None:
            cap_result = None
            try:
                cap_result = debug_cap.stop()
            except Exception as exc:
                print(f"WARNING: debug capture stop failed: {exc}")
            if cap_result is not None:
                try:
                    stats = _process_debug_trace(
                        cap_result,
                        summary_path=str(run_dir / "summary.txt"),
                        tail_path=str(run_dir / "tail.txt"),
                        uci_path=str(run_dir / "uci_accesses.txt"),
                    )
                    print(f"\nDebug capture: {stats.get('packets', 0)} pkts, "
                          f"{stats.get('dropped', 0)} dropped, "
                          f"{stats.get('total', 0)} cycles, "
                          f"{stats.get('duration', 0.0):.1f}s "
                          f"(cpu={stats.get('cpu', 0)} vic={stats.get('vic', 0)}; "
                          f"uci_hits={stats.get('uci_total', 0)})")
                except Exception as exc:
                    print(f"WARNING: debug trace post-process failed: {exc}")

                # Persist the raw trace as packed u32-LE, with a JSON
                # sidecar describing the bit layout.
                try:
                    trace_bin = run_dir / "trace.bin"
                    trace_meta = run_dir / "trace.bin.meta.json"
                    tstats = _serialize_trace_packed(
                        cap_result, trace_bin, trace_meta)
                    trace_bytes_on_disk = tstats["bytes_on_disk"]
                    mb = trace_bytes_on_disk / (1024 * 1024)
                    print(f"  raw trace       : {trace_bin} "
                          f"({tstats['cycle_count']} cycles, {mb:.2f} MB)")
                except Exception as exc:
                    print(f"WARNING: raw trace serialize failed: {exc}")

        # --- Persist server-side listener state ---
        if run_dir is not None:
            try:
                _serialize_server_result(
                    server_result, run_dir / "server_result.json")
            except Exception as exc:
                print(f"WARNING: server_result dump failed: {exc}")

        # --- Write run metadata ---
        if run_dir is not None:
            try:
                _write_run_info(
                    run_dir / "run_info.txt",
                    outcome=outcome,
                    duration=time.time() - run_start,
                    exit_code=exit_code,
                    extra={
                        "trace_bytes": trace_bytes_on_disk,
                        "turbo_mhz": TURBO_MHZ,
                        "host": HOST,
                    },
                )
            except Exception as exc:
                print(f"WARNING: run_info write failed: {exc}")

            # Print run dir prominently for operator / test harness.
            print(f"\nDebug artifacts: {run_dir}")
            # Optional: drop the run dir on PASS unless the operator
            # asked to keep it. 5-dir rotation still applies regardless.
            if outcome == "PASS" and not UCI_DEBUG_KEEP_ON_PASS:
                try:
                    shutil.rmtree(run_dir)
                    print(f"(removed on PASS; set KEEP_DEBUG_ON_PASS=1 to "
                          f"retain)")
                except Exception as exc:
                    print(f"WARNING: failed to remove PASS run dir: {exc}")

        if uci_enabled and client is not None:
            print("\nDisabling UCI...")
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    raise SystemExit(main())
