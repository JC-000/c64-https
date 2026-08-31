#!/usr/bin/env python3
"""Phase 3 e2e test: boot c64-https.prg, do DHCP, then HTTPS GET.

This test extends Phase 2 by pressing 'G' after DHCP succeeds, which
triggers an HTTPS GET to www.foo.invalid (resolved via dnsmasq to the
host bridge IP 10.0.65.1). A Python HTTPS server (TLS 1.3, self-signed
P-256 ECDSA cert, CN=www.foo.invalid) on 10.0.65.1:443 serves a known
response body.

The C64 X25519 keygen is slow (~3.6 min at normal speed), so the TLS
phase gets a generous 5-minute timeout. Total test runtime is typically
6-8 minutes.

Run:
    sudo PYTHONPATH=tools python3 tests/rig_phase3_https.py

Exit codes:
    0 -- PASS
    0 -- SKIP (clearly printed)
    1 -- FAIL
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TOOLS = os.path.join(_REPO_ROOT, "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

PRG_PATH = os.path.join(_REPO_ROOT, "build", "c64-https.prg")

# Screen needles (from src/boot.asm string labels).
MENU_NEEDLE = "Q=QUIT"
DHCP_OK_NEEDLE = "DHCP OK"
# Primary success indicator: the C64 prints this after the whole HTTPS
# exchange completes.
SUCCESS_NEEDLE = "CONNECTION CLOSED"
# Failure needles (any one of these means the C64 bailed out).
FAIL_NEEDLES = (
    "DNS RESOLVE FAILED",
    "TCP CONNECT FAILED",
    "TLS HANDSHAKE FAILED",
    "TLS SEND FAILED",
)
# Progress needles we use to report how far we got on failure.
# Ordered roughly by expected appearance; _last_progress_seen picks the
# one with the latest rfind index on screen.
PROGRESS_NEEDLES = (
    "HTTPS GET",
    "DNS OK",
    "TCP CONNECTED",
    "CH",
    "SH",
    "KEYS",
    "ENC1",
    "RX",
    "GOT",
    "DEC",
    "PROC",
    "EE",
    "CERT",
    "CV",
    "FIN",
    "CFIN",
    "TLS HANDSHAKE OK",
    "REQUEST SENT",
    "CONNECTION CLOSED",
)
# Response body served by our test HTTPS server.
RESPONSE_BODY = "TLS13 OK FROM C64 TEST"

MENU_TIMEOUT = 90.0
DHCP_TIMEOUT = 90.0
# TLS handshake dominates: X25519 keygen ~3.6 min PLUS X25519 shared secret
# ~3.6 min PLUS HKDF (many HMAC-SHA256) ~2 min PLUS ECDSA P-256 verify ~2 min.
# Budget 30 minutes total to cover full handshake + app data round-trip.
HTTPS_TIMEOUT = 1800.0


def _skip(reason: str) -> int:
    print(f"SKIP: {reason}")
    return 0


def _ensure_built() -> bool:
    if os.path.isfile(PRG_PATH):
        return True
    print("[build] c64-https.prg missing, running make...")
    r = subprocess.run(["make"], cwd=_REPO_ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  make failed (exit {r.returncode}):\n{r.stderr}")
        return False
    return os.path.isfile(PRG_PATH)


def _last_progress_seen(upper_screen: str) -> str:
    """Return the latest progress marker seen on screen, or '(none)'."""
    last = "(none)"
    last_idx = -1
    for needle in PROGRESS_NEEDLES:
        idx = upper_screen.rfind(needle)
        if idx > last_idx:
            last_idx = idx
            last = needle
    return last


_LABELS_CACHE = None

def _label_addr(name: str):
    """Look up a label address in build/labels.txt; return int or None."""
    global _LABELS_CACHE
    if _LABELS_CACHE is None:
        _LABELS_CACHE = {}
        try:
            with open("/home/someone/c64-https/build/labels.txt") as f:
                for line in f:
                    # format: "al C:xxxx .name"
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == "al":
                        addr_s = parts[1].split(":")[-1]
                        lbl = parts[2].lstrip(".")
                        try:
                            _LABELS_CACHE[lbl] = int(addr_s, 16)
                        except ValueError:
                            pass
        except Exception:
            pass
    return _LABELS_CACHE.get(name)


def _dump_diagnostics(transport=None) -> None:
    """Print dnsmasq log and host-side connectivity checks for post-mortem."""
    diag_log_path = "/tmp/c64-https-phase3-diag.log"
    try:
        diag_log = open(diag_log_path, "a", buffering=1)  # line-buffered
        _ts = time.strftime("%Y-%m-%d %H:%M:%S")
        diag_log.write(f"\n=== diagnostic dump at {_ts} ===\n")
        diag_log.flush()
    except Exception:
        diag_log = None

    def _emit(line: str) -> None:
        print(line, flush=True)
        if diag_log is not None:
            try:
                diag_log.write(line + "\n")
                diag_log.flush()
            except Exception:
                pass

    dnsmasq_log = "/tmp/c64-https-dnsmasq.log"
    if os.path.isfile(dnsmasq_log):
        _emit(f"\n--- tail of {dnsmasq_log} ---")
        with open(dnsmasq_log, "rb") as f:
            data = f.read()[-4000:]
        _emit(data.decode("utf-8", errors="replace"))

    # Host-side DNS check
    try:
        r = subprocess.run(
            ["dig", "+short", "@10.0.65.1", "www.foo.invalid"],
            capture_output=True, text=True, timeout=5,
        )
        _emit(f"\n  dig @10.0.65.1 www.foo.invalid -> {r.stdout.strip()}")
    except Exception as e:
        _emit(f"  dig check failed: {e}")

    # Host-side HTTPS check (self-signed, so disable verification).
    try:
        import ssl as _ssl
        import urllib.request
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        resp = urllib.request.urlopen(
            "https://10.0.65.1:443/", timeout=3, context=ctx
        )
        _emit(f"  HTTPS from host: {resp.status} {resp.read()[:100]}")
    except Exception as e:
        _emit(f"  HTTPS from host failed: {e}")

    # ip65 error code from C64 memory
    if transport is not None:
        # Force-load labels so the PC/stack lookups below have data.
        _label_addr("tls_state")
        # CPU registers -- PC tells us where the 6502 is currently stuck.
        try:
            transport.resume()
            regs = transport.read_registers()
            pc = regs.get("PC", 0)
            sp = regs.get("SP", 0)
            a = regs.get("A", 0)
            x = regs.get("X", 0)
            y = regs.get("Y", 0)
            _emit(f"  CPU PC=${pc:04X}  SP=${sp:02X}  A=${a:02X} X=${x:02X} Y=${y:02X}")
            # Find nearest label <= PC
            nearest_name = None
            nearest_addr = -1
            for name, addr in _LABELS_CACHE.items() if _LABELS_CACHE else []:
                if addr <= pc and addr > nearest_addr:
                    nearest_addr = addr
                    nearest_name = name
            if nearest_name is not None:
                _emit(f"  nearest label <= PC: {nearest_name} @ ${nearest_addr:04X} (PC+${pc-nearest_addr:X})")
        except Exception as e:
            _emit(f"  read_registers failed: {e}")

        # Top of stack: return address chain from JSRs.
        # 6502 SP indexes into $0100-$01FF; stack grows downward.
        # Bytes ABOVE current SP (i.e. $0100+SP+1 .. $01FF) are live.
        try:
            transport.resume()
            stack = transport.read_memory(0x01F0, 16)
            _emit(f"  stack $01F0-$01FF = {' '.join(f'{b:02X}' for b in stack)}")
            # Parse as little-endian return-address pairs (each JSR pushes hi, lo
            # where the saved addr = actual_return - 1).
            _emit("  possible return-address pairs (addr+1 = instruction after JSR):")
            for i in range(0, 16, 2):
                lo = stack[i]
                hi = stack[i + 1]
                ret = ((hi << 8) | lo) + 1
                # Find nearest label <= ret
                near_n = None
                near_a = -1
                for name, addr in _LABELS_CACHE.items() if _LABELS_CACHE else []:
                    if addr <= ret and addr > near_a:
                        near_a = addr
                        near_n = name
                tag = f"{near_n}+${ret-near_a:X}" if near_n else "?"
                _emit(f"    $01{0xF0+i:02X}: lo=${lo:02X} hi=${hi:02X} -> ${ret:04X} ({tag})")
        except Exception as e:
            _emit(f"  stack read failed: {e}")

        try:
            transport.resume()
            err_addr = _label_addr("ip65_error") or 0x4CEA
            err_data = transport.read_memory(err_addr, 1)
            _emit(f"  ip65_error @ ${err_addr:04X} = 0x{err_data[0]:02X}")
        except Exception as e:
            _emit(f"  ip65_error read failed: {e}")

        state_names = {
            0x00: "IDLE", 0x01: "CLIENT_HELLO", 0x02: "SERVER_HELLO",
            0x03: "ENCRYPTED_EXT", 0x04: "CERTIFICATE", 0x05: "CERT_VERIFY",
            0x06: "FINISHED", 0x07: "CONNECTED", 0xFF: "ERROR",
        }

        # TLS state machine progress (set before each step; $FF on error)
        try:
            transport.resume()
            ts_addr = _label_addr("tls_state")
            if ts_addr is not None:
                tls_state = transport.read_memory(ts_addr, 1)[0]
                name = state_names.get(tls_state, "UNKNOWN")
                _emit(f"  tls_state @ ${ts_addr:04X} = ${tls_state:02X} ({name})")
            else:
                _emit("  tls_state: label missing")
        except Exception as e:
            _emit(f"  tls_state read failed: {e}")

        # Last attempted TLS state (preserved before error handler overwrote tls_state)
        try:
            transport.resume()
            tls_addr = _label_addr("tls_last_state")
            if tls_addr is not None:
                last = transport.read_memory(tls_addr, 1)[0]
                last_name = state_names.get(last, "UNKNOWN")
                _emit(f"  tls_last_state @ ${tls_addr:04X} = ${last:02X} ({last_name})")
            else:
                _emit("  tls_last_state: label missing")
        except Exception as e:
            _emit(f"  tls_last_state read failed: {e}")

        # Most recent TLS record buffer head
        try:
            transport.resume()
            buf_addr = _label_addr("tls_rec_buf")
            if buf_addr is not None:
                rec = transport.read_memory(buf_addr, 256)
                _emit(f"  tls_rec_buf @ ${buf_addr:04X} = ({len(rec)} bytes)")
                for i in range(0, len(rec), 16):
                    line = rec[i:i+16]
                    hex_part = " ".join(f"{b:02X}" for b in line)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
                    _emit(f"    +${i:02X}  {hex_part:<47}  {ascii_part}")
            else:
                _emit("  tls_rec_buf: label missing")
        except Exception as e:
            _emit(f"  tls_rec_buf read failed: {e}")

        # Raw ip65 TCP receive ring — what ip65 actually delivered
        try:
            transport.resume()
            ring_addr = _label_addr("tcp_recv_buf")
            if ring_addr is not None:
                ring = transport.read_memory(ring_addr, 256)
                _emit(f"  tcp_recv_buf @ ${ring_addr:04X} = ({len(ring)} bytes)")
                for i in range(0, len(ring), 16):
                    line = ring[i:i+16]
                    hex_part = " ".join(f"{b:02X}" for b in line)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
                    _emit(f"    +${i:02X}  {hex_part:<47}  {ascii_part}")
            else:
                _emit("  tcp_recv_buf: label missing")
        except Exception as e:
            _emit(f"  tcp_recv_buf read failed: {e}")

        # Parser input: tls_hs_buf (stable copy made during record reception)
        try:
            transport.resume()
            hs_addr = _label_addr("tls_hs_buf")
            if hs_addr is not None:
                hs = transport.read_memory(hs_addr, 128)
                _emit(f"  tls_hs_buf @ ${hs_addr:04X} = ({len(hs)} bytes)")
                for i in range(0, len(hs), 16):
                    line = hs[i:i+16]
                    hex_part = " ".join(f"{b:02X}" for b in line)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
                    _emit(f"    +${i:02X}  {hex_part:<47}  {ascii_part}")
            else:
                _emit("  tls_hs_buf: label missing")
        except Exception as e:
            _emit(f"  tls_hs_buf read failed: {e}")

        # tls_rec_header raw 5-byte buffer (state-machine target)
        try:
            transport.resume()
            hdr_addr = _label_addr("tls_rec_header")
            if hdr_addr is not None:
                hdr = transport.read_memory(hdr_addr, 5)
                _emit(f"  tls_rec_header @ ${hdr_addr:04X} = {' '.join(f'{b:02X}' for b in hdr)}")
            else:
                _emit("  tls_rec_header: label missing")
        except Exception as e:
            _emit(f"  tls_rec_header read failed: {e}")

        # tls_recv_state and tls_recv_count (16-bit) — dynamic addrs
        try:
            transport.resume()
            rs_addr = _label_addr("tls_recv_state")
            rc_addr = _label_addr("tls_recv_count")
            if rs_addr is not None:
                rs_v = transport.read_memory(rs_addr, 1)[0]
                _emit(f"  tls_recv_state @ ${rs_addr:04X} = ${rs_v:02X}")
            if rc_addr is not None:
                rc_b = transport.read_memory(rc_addr, 2)
                _emit(f"  tls_recv_count @ ${rc_addr:04X} = ${rc_b[1]:02X}{rc_b[0]:02X}")
        except Exception as e:
            _emit(f"  tls_recv_state read failed: {e}")

        # Single-byte diagnostic labels (dynamic; skip silently if missing)
        for lbl_name in ("tls_hs_len", "tls_rec_len", "tls_rec_type"):
            addr = _label_addr(lbl_name)
            if addr is None:
                continue
            try:
                transport.resume()
                # 16-bit for *_len, 8-bit for type
                n = 1 if lbl_name == "tls_rec_type" else 2
                b = transport.read_memory(addr, n)
                if n == 1:
                    _emit(f"  {lbl_name} @ ${addr:04X} = ${b[0]:02X}")
                else:
                    _emit(f"  {lbl_name} @ ${addr:04X} = ${b[1]:02X}{b[0]:02X}")
            except Exception:
                pass

        # tls_recv_progress — granular progress within tls_recv_server_hello
        # $01=entered $02=record-recv ok $03=ct-handshake ok $04=copied to hs_buf $05=parse ok
        try:
            transport.resume()
            prog_addr = _label_addr("tls_recv_progress")
            if prog_addr is not None:
                pv = transport.read_memory(prog_addr, 1)[0]
                _emit(f"  tls_recv_progress @ ${prog_addr:04X} = ${pv:02X}")
        except Exception as e:
            _emit(f"  tls_recv_progress read failed: {e}")

        # tls_recv_sub_progress — granular progress within tls_record_recv_and_decrypt
        sub_state_names = {
            0x00: "never-entered",
            0x01: "entered tls_record_recv_and_decrypt",
            0x02: "reading record header (state 0)",
            0x03: "header bytes received, parsing",
            0x04: "record type/version validated",
            0x05: "record length parsed, entering state 1",
            0x06: "reading record body (state 1)",
            0x07: "record body complete",
            0x08: "about to decrypt",
            0x09: "decrypt succeeded",
            0x0A: "returning success",
        }
        try:
            transport.resume()
            sub_addr = _label_addr("tls_recv_sub_progress")
            if sub_addr is not None:
                sv = transport.read_memory(sub_addr, 1)[0]
                name = sub_state_names.get(sv, "UNKNOWN")
                _emit(f"  tls_recv_sub_progress @ ${sub_addr:04X} = ${sv:02X} ({name})")
        except Exception as e:
            _emit(f"  tls_recv_sub_progress read failed: {e}")

        # tls_recv_poll_count — how many times @sh_wait looped
        try:
            transport.resume()
            pc_addr = _label_addr("tls_recv_poll_count")
            if pc_addr is not None:
                pcb = transport.read_memory(pc_addr, 2)
                pc = pcb[0] | (pcb[1] << 8)
                _emit(f"  tls_recv_poll_count @ ${pc_addr:04X} = {pc} (${pcb[1]:02X}{pcb[0]:02X})")
        except Exception as e:
            _emit(f"  tls_recv_poll_count read failed: {e}")

        # TCP receive ring buffer head/tail — tells us if ip65 wrote data
        # that TLS never drained. Both are 16-bit little-endian words.
        try:
            transport.resume()
            head_addr = _label_addr("tcp_recv_head")
            tail_addr = _label_addr("tcp_recv_tail")
            ovf_addr = _label_addr("tcp_recv_overflow")
            if head_addr is not None and tail_addr is not None:
                hb = transport.read_memory(head_addr, 2)
                tb = transport.read_memory(tail_addr, 2)
                head = hb[0] | (hb[1] << 8)
                tail = tb[0] | (tb[1] << 8)
                avail = (tail - head) & 0xFFFF
                _emit(f"  tcp_recv_head @ ${head_addr:04X} = ${head:04X}")
                _emit(f"  tcp_recv_tail @ ${tail_addr:04X} = ${tail:04X}")
                _emit(f"  tcp ring available = {avail} bytes")
                if ovf_addr is not None:
                    ov = transport.read_memory(ovf_addr, 1)[0]
                    _emit(f"  tcp_recv_overflow @ ${ovf_addr:04X} = ${ov:02X}")
                if avail > 0:
                    # dump first 48 bytes of ring starting at head (mod 4096)
                    buf_addr = _label_addr("tcp_recv_buf")
                    if buf_addr is not None:
                        ring = transport.read_memory(buf_addr, 4096)
                        n = min(avail, 48)
                        line_hex = " ".join(f"{ring[(head + i) & 0xFFF]:02X}" for i in range(n))
                        _emit(f"  ring[head..head+{n}] = {line_hex}")
        except Exception as e:
            _emit(f"  tcp ring read failed: {e}")

    if diag_log is not None:
        try:
            diag_log.close()
        except Exception:
            pass


def main() -> int:
    from https_e2e import (
        BridgeEnv,
        check_prerequisites,
        launch_vice_on_bridge,
        shutdown_vice,
        press_key,
        wait_for_screen_text,
        get_screen_text,
        start_https_listener,
        stop_https_listener,
    )

    missing = check_prerequisites()
    if missing:
        return _skip("missing prerequisites: " + "; ".join(missing))

    if not _ensure_built():
        return _skip("c64-https.prg could not be built")

    handle = None
    listener = None
    try:
        with BridgeEnv() as env:
            try:
                # --- Start HTTPS listener on bridge IP ---
                print(f"\n=== Starting HTTPS listener on {env.bridge_ip}:443 ===")
                listener = start_https_listener(
                    host=env.bridge_ip,
                    port=443,
                    response_body=RESPONSE_BODY,
                )
                print(f"  listener ready on {listener.host}:{listener.port}")
                print(f"  cert: {listener.cert_path}")

                # --- Launch VICE ---
                print(f"\n=== Launching VICE on {env.tap0} with {PRG_PATH} ===")
                handle = launch_vice_on_bridge(
                    prg_path=PRG_PATH,
                    tap=env.tap0,
                    ready_timeout=90.0,
                )
                transport = handle.transport

                # --- Wait for boot menu ---
                print(f"\n=== Waiting for boot menu ({MENU_NEEDLE!r}) ===")
                try:
                    wait_for_screen_text(transport, MENU_NEEDLE, timeout=MENU_TIMEOUT)
                except TimeoutError as e:
                    print(f"FAIL: boot menu did not appear\n{e}")
                    return 1
                print("  boot menu OK")

                # --- DHCP init ---
                print("\n=== Pressing 'I' for DHCP init ===")
                press_key(transport, "I")

                print(f"\n=== Waiting up to {DHCP_TIMEOUT:.0f}s for {DHCP_OK_NEEDLE!r} ===")
                try:
                    wait_for_screen_text(transport, DHCP_OK_NEEDLE, timeout=DHCP_TIMEOUT)
                except TimeoutError as e:
                    print(f"FAIL: DHCP did not complete\n{e}")
                    _dump_diagnostics(transport)
                    return 1
                print("  DHCP OK")

                # --- HTTPS GET ---
                print("\n=== Pressing 'G' for HTTPS GET ===")
                press_key(transport, "G")

                print(f"\n=== Waiting up to {HTTPS_TIMEOUT:.0f}s for HTTPS completion ===")
                print("  (TLS handshake is slow: X25519 keygen ~3.6 min + handshake)")
                # After pressing G, the C64 prints a success sequence
                # culminating in "CONNECTION CLOSED", or one of the
                # FAIL_NEEDLES on failure. Poll screen text and break
                # on either.
                deadline = time.monotonic() + HTTPS_TIMEOUT
                final = ""
                https_started = False
                result = None  # "pass" | "fail"
                fail_reason = ""
                last_progress = "(none)"
                last_log_progress = "(none)"
                next_heartbeat = time.monotonic() + 30.0

                while time.monotonic() < deadline:
                    try:
                        transport.resume()
                    except Exception:
                        pass
                    time.sleep(3.0)
                    try:
                        final = get_screen_text(transport)
                    except Exception:
                        continue

                    upper = final.upper()

                    # Check if the HTTPS GET banner appeared.
                    idx_get = upper.find("HTTPS GET")
                    if idx_get < 0:
                        continue
                    if not https_started:
                        print("  HTTPS GET initiated")
                        https_started = True

                    after_get = upper[idx_get:]
                    last_progress = _last_progress_seen(after_get)

                    # Heartbeat log so the test shows forward motion.
                    if time.monotonic() >= next_heartbeat:
                        remaining = int(deadline - time.monotonic())
                        # Sample ip65/TCP ring and net_poll counters so we
                        # can tell "slow progress" from "dead stuck".
                        hb_head = hb_tail = hb_pin = hb_pout = None
                        try:
                            transport.resume()
                            head_addr = _label_addr("tcp_recv_head")
                            tail_addr = _label_addr("tcp_recv_tail")
                            pin_addr = _label_addr("net_poll_entry_count")
                            pout_addr = _label_addr("net_poll_return_count")
                            if head_addr is not None:
                                b = transport.read_memory(head_addr, 2)
                                hb_head = b[0] | (b[1] << 8)
                            if tail_addr is not None:
                                b = transport.read_memory(tail_addr, 2)
                                hb_tail = b[0] | (b[1] << 8)
                            if pin_addr is not None:
                                b = transport.read_memory(pin_addr, 2)
                                hb_pin = b[0] | (b[1] << 8)
                            if pout_addr is not None:
                                b = transport.read_memory(pout_addr, 2)
                                hb_pout = b[0] | (b[1] << 8)
                        except Exception as _hb_exc:
                            print(f"    (heartbeat sample failed: {_hb_exc})")
                        hb_extra = (
                            f" head=${hb_head:04X}" if hb_head is not None else ""
                        ) + (
                            f" tail=${hb_tail:04X}" if hb_tail is not None else ""
                        ) + (
                            f" poll_in={hb_pin}" if hb_pin is not None else ""
                        ) + (
                            f" poll_out={hb_pout}" if hb_pout is not None else ""
                        )
                        print(f"  [heartbeat] last seen: {last_progress}  ({remaining}s left){hb_extra}")
                        # Also dump the 10 lines from idx_get onward so we
                        # can see fine-grained markers like ENC1/RX/GOT.
                        tail_lines = final[idx_get:].splitlines()[:12]
                        for tl in tail_lines:
                            tl_stripped = tl.rstrip()
                            if tl_stripped:
                                print(f"    | {tl_stripped}")
                        next_heartbeat = time.monotonic() + 30.0
                    elif last_progress != last_log_progress:
                        print(f"  progress: {last_progress}")
                        last_log_progress = last_progress

                    # Short-circuit on any failure message.
                    failed = False
                    for needle in FAIL_NEEDLES:
                        if needle in after_get:
                            fail_reason = needle
                            failed = True
                            break
                    if failed:
                        result = "fail"
                        break

                    # Primary success marker.
                    if SUCCESS_NEEDLE in after_get:
                        result = "pass"
                        break

                if result == "fail" or result != "pass":
                    if result == "fail":
                        reason = f"HTTPS GET reported {fail_reason}"
                    else:
                        reason = f"HTTPS GET did not complete within {HTTPS_TIMEOUT:.0f}s"
                    print(f"FAIL: {reason}")
                    try:
                        final = get_screen_text(transport)
                    except Exception:
                        pass
                    last_progress = _last_progress_seen(final.upper())
                    print(f"  last progress marker seen: {last_progress}")
                    print(f"\n--- final screen ---\n{final}")
                    _dump_diagnostics(transport)
                    return 1

                print("\n=== PASS: HTTPS CONNECTION CLOSED seen on screen ===")
                snippet = "\n".join(final.splitlines()[:25])
                print(f"--- final screen (first 25 lines) ---\n{snippet}")
                print(f"  last progress marker seen: "
                      f"{_last_progress_seen(final.upper())}")

                # Check for response body on screen (not a hard failure
                # -- print_resp_body only writes up to 200 bytes and it
                # may scroll).
                body_upper = RESPONSE_BODY.upper()
                if body_upper in final.upper():
                    print(f"  response body verified: {RESPONSE_BODY!r}")
                else:
                    print(f"  (response body not found on screen, may have scrolled)")

                return 0
            finally:
                if listener is not None:
                    try:
                        stop_https_listener(listener)
                    except Exception as e:
                        print(f"  stop_https_listener: {e}")
                    listener = None
                if handle is not None:
                    try:
                        shutdown_vice(handle)
                    except Exception as e:
                        print(f"  shutdown_vice: {e}")
                    handle = None
    except Exception as e:
        print(f"FAIL: unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
