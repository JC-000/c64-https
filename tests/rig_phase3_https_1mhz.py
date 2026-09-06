#!/usr/bin/env python3
"""Phase 3 e2e HTTPS test — 1 MHz, WARP-off reproduction of the UCI run.

This is the VICE/ip65 companion to the UCI e2e run on real U64E hardware:
it exercises the exact same ClientHello->...->Application-Data flow but on
the ip65/RR-Net backend at stock 1 MHz with VICE WARP disabled, so the
wall-clock is dominated by ECDSA-P256 CertificateVerify (~85 s on U64E at
48 MHz; at 1 MHz VICE the whole handshake is expected to take roughly
2-3 hours end-to-end). The upstream ip65 bug described in CLAUDE.md's
"End-to-End Bridge Tests" section and in the `project_phase3_handoff`
memory note may cause a stall partway through; ``_dump_diagnostics``
samples the TLS state machine, tcp ring head/tail, net_poll counters,
and key TLS labels (client/server random, ECDHE pub/priv, shared secret)
so an observer can tell "ip65 starved the TLS layer" apart from "TLS
layer stuck on its own". This test MUST NOT be started while the UCI
HTTPS listener on ports 443/4433 is active on this host — the bridge
listener here binds 10.0.65.1:443 and would race host-side sockets.
Gated by the ``VICE_HTTPS_OK_TO_RUN=1`` environment variable.

Run (after the UCI test has fully stopped):
    sudo env VICE_HTTPS_OK_TO_RUN=1 PYTHONPATH=tools python3 tests/rig_phase3_https_1mhz.py

Exit codes (tools/_skip_policy.py, issue #178):
    0 -- PASS
    0 -- NOT APPLICABLE, as a named verdict rather than a bare skip: this
         rig is Linux-only, and on any other host
         tests/rig_vice_https_macos.py owns the coverage.
    1 -- FAIL (a check ran and failed)
    2 -- COULD NOT RUN (a prerequisite is missing ON LINUX, the build is
         broken, or the rig is interlocked -- VICE_HTTPS_OK_TO_RUN unset,
         or port 443 held by another run.  Nothing was verified).  Set
         C64_ALLOW_SKIP=1 to accept a prerequisite-missing run as exit 0;
         a FAILED BUILD and CONTENTION are never opted out of, and the
         pre-flight gate is contention.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TOOLS = os.path.join(_REPO_ROOT, "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

# needs _TOOLS on sys.path, hence the placement below the block above
from _skip_policy import cannot_run, not_applicable  # noqa: E402

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

# 1 MHz no-WARP timeouts. These are order-of-magnitude larger than the
# WARP-on variant because at stock speed ECDSA-P256 verify alone already
# dwarfs the whole handshake budget of the fast variant.
READY_TIMEOUT = 180.0
MENU_TIMEOUT = 180.0
DHCP_TIMEOUT = 180.0
HTTPS_TIMEOUT = 9000.0
ACCEPT_TIMEOUT = 9000.0
POST_HANDSHAKE_TIMEOUT = 9000.0
HEARTBEAT_INTERVAL = 120.0

# Per-heartbeat screen snapshot output directory.
SCREEN_SNAP_DIR = "/tmp/c64-https-phase3-1mhz-screens"
SCREEN_SNAP_KEEP = 30


_CERTIFIES = "the TLS 1.3 handshake + GET at honest 1 MHz over emulated RR-Net"


def _cannot_run(reason: str, *, opt_out: bool = True) -> int:
    """An involuntary skip is a FAILURE -- nothing was verified (issue #178).

    `opt_out=False` for a broken build: a failed `make` is never laundered
    into a pass, not even by C64_ALLOW_SKIP.
    """
    return cannot_run(
        reason,
        executed=0,
        total=1,
        certifies=_CERTIFIES,
        opt_out_env="C64_ALLOW_SKIP" if opt_out else None,
    )


_COUNTERPART = (
    "tests/rig_vice_https_macos.py owns this coverage on macOS (E2E_NO_WARP=1 for the 1 MHz variant)"
)


def _wrong_platform() -> int:
    """A VOLUNTARY skip: this host can never run this rig (issue #178).

    The load-bearing question is what the remedy is.  "install iproute2" is
    an involuntary skip and stays exit 2 -- but on a non-Linux host there is
    no remedy at all, and another rig owns the coverage, so nothing is lost
    and exit 2 would be a red nobody can ever clear.
    """
    return not_applicable(
        f"this rig is Linux-only (br-c64 bridge + netfilter + /proc/net/udp); "
        f"this host is {sys.platform} -- {_COUNTERPART}",
        certifies=_CERTIFIES,
    )


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


def _save_heartbeat_screen(transport) -> None:
    """Read the 1000 bytes of text screen RAM and save under SCREEN_SNAP_DIR.

    Keeps the last SCREEN_SNAP_KEEP snapshots by sorted filename (ISO time
    stamps sort lexicographically). Silent on failure -- heartbeat must not
    crash the poll loop.
    """
    try:
        os.makedirs(SCREEN_SNAP_DIR, exist_ok=True)
    except Exception as e:
        print(f"    (screen snap mkdir failed: {e})")
        return
    try:
        transport.resume()
        data = transport.read_memory(0x0400, 1000)
    except Exception as e:
        print(f"    (screen snap read failed: {e})")
        return
    ts = time.strftime("%Y%m%dT%H%M%S")
    path = os.path.join(SCREEN_SNAP_DIR, f"heartbeat_{ts}.bin")
    try:
        with open(path, "wb") as f:
            f.write(bytes(data))
    except Exception as e:
        print(f"    (screen snap write failed: {e})")
        return
    # Rotate -- keep only the most recent SCREEN_SNAP_KEEP files.
    try:
        entries = sorted(
            p for p in os.listdir(SCREEN_SNAP_DIR)
            if p.startswith("heartbeat_") and p.endswith(".bin")
        )
        excess = len(entries) - SCREEN_SNAP_KEEP
        for old in entries[:max(0, excess)]:
            try:
                os.remove(os.path.join(SCREEN_SNAP_DIR, old))
            except Exception:
                pass
    except Exception:
        pass


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

        # Extended TLS key-material snapshot (1 MHz variant). These labels
        # survived the tls_hs_buf elimination; any that didn't are skipped
        # silently so the dump stays useful across refactors.
        _extended_tls_labels = (
            ("tls_ecdhe_privkey", 32),
            ("tls_ecdhe_pubkey", 32),
            ("tls_server_pubkey", 32),
            ("tls_shared_secret", 32),
            ("tls_client_random", 32),
            ("tls_server_random", 32),
        )
        for lbl_name, nbytes in _extended_tls_labels:
            addr = _label_addr(lbl_name)
            if addr is None:
                continue
            try:
                transport.resume()
                buf = transport.read_memory(addr, nbytes)
                _emit(f"  {lbl_name} @ ${addr:04X} = ({len(buf)} bytes)")
                for i in range(0, len(buf), 16):
                    line = buf[i:i+16]
                    hex_part = " ".join(f"{b:02X}" for b in line)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
                    _emit(f"    +${i:02X}  {hex_part:<47}  {ascii_part}")
            except Exception as e:
                _emit(f"  {lbl_name} read failed: {e}")

    if diag_log is not None:
        try:
            diag_log.close()
        except Exception:
            pass


def main() -> int:
    # This import is inert (module-level constants and defs only), so it can
    # precede the pre-flight gate, whose real constraint is that it run
    # before BridgeEnv mutates host netfilter via sudo.
    from https_e2e import (
        BridgeEnv,
        check_prerequisites,
        platform_supported,
        launch_vice_on_bridge,
        shutdown_vice,
        press_key,
        wait_for_screen_text,
        get_screen_text,
        start_https_listener,
        stop_https_listener,
    )

    # Platform FIRST: check_prerequisites() cannot answer this, because the
    # same string ("ip not on PATH") means "installable" on Linux and "wrong
    # OS" everywhere else (issue #178).  Ahead of the gates below so that a
    # host which can never run this rig is never told to opt in, and never
    # trips the port check.
    if not platform_supported():
        return _wrong_platform()

    # --- Pre-flight gate (must run BEFORE BridgeEnv, which mutates host
    # netfilter via sudo). Refuses if the UCI HTTPS listener is still up.
    #
    # This flag is a CONTENTION INTERLOCK, not a taste setting, so an unset
    # flag stays exit 2 exactly as it was before #178 -- the verdict is now
    # a named block instead of a bare print, and that is the whole change.
    #
    # An earlier draft called it "the operator declining an opt-in rig" and
    # routed it to not_applicable() (exit 0).  That was wrong in this repo's
    # own terms.  UNSET IS THE DEFAULT STATE: it cannot distinguish "I
    # considered this and declined" from "I forgot", so exit 0 hands a green
    # run to someone who verified nothing -- the class #178 exists to close,
    # committed by #178's own implementation.  What the flag actually
    # asserts is "the UCI HTTPS listener has fully stopped", which is a
    # contention claim, and contention is the one category this policy gives
    # no opt-out at all -- see the port-443 check immediately below, which is
    # the same interlock measured directly rather than asserted.
    if os.environ.get("VICE_HTTPS_OK_TO_RUN") != "1":
        return _cannot_run(
            "VICE_HTTPS_OK_TO_RUN is not set -- this rig is interlocked because\n"
            "    it collides with the UCI HTTPS listener (which binds 443/4433\n"
            "    on the LAN interface); the U64E test may still be running.\n"
            "    To run it, wait for that to finish, then:\n"
            "      sudo env VICE_HTTPS_OK_TO_RUN=1 PYTHONPATH=tools \\\n"
            "          python3 tests/rig_phase3_https_1mhz.py",
            opt_out=False,
        )

    # A held port is CONTENTION, the third category: the rig exists, someone
    # else has it.  Exit 2 like any could-not-run, but deliberately NOT
    # opt-out-able -- a lane that silences contention goes green exactly when
    # it collides, and unlike a missing tool it clears on its own.  Same
    # decision as tests/rig_vice_https_macos.py's feth0 check.
    for port in (443,):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0", port))
        except OSError as e:
            return _cannot_run(
                f"port {port} is held by another process (the UCI test?): {e}"
                f"\n    fix: wait for the other run to finish",
                opt_out=False,
            )
        finally:
            s.close()

    missing = check_prerequisites()
    if missing:
        return _cannot_run("missing prerequisites: " + "; ".join(missing))

    if not _ensure_built():
        return _cannot_run("c64-https.prg could not be built -- `make` "
                           "failed; this is a broken build, not a "
                           "missing prerequisite", opt_out=False)

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
                # launch_vice_on_bridge hard-codes warp=False in ViceConfig
                # (see tools/https_e2e/vice_on_bridge.py — "load-bearing:
                # warp breaks DHCP"). We still assert below to catch any
                # future drift that would invalidate the 1 MHz timing.
                handle = launch_vice_on_bridge(
                    prg_path=PRG_PATH,
                    tap=env.tap0,
                    ready_timeout=READY_TIMEOUT,
                )
                transport = handle.transport
                # Verify WARP is actually off — 1 MHz timing assumption
                # is load-bearing for every downstream timeout constant.
                # WARP is hard-coded False in tools/https_e2e/vice_on_bridge.py ViceConfig;
                # can't query it here (would need text_monitor_port on the transport).

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
                next_heartbeat = time.monotonic() + HEARTBEAT_INTERVAL

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
                        # Save a raw screen snapshot to disk so a long run
                        # produces a post-mortem trail even if stdout is
                        # lost.
                        _save_heartbeat_screen(transport)
                        next_heartbeat = time.monotonic() + HEARTBEAT_INTERVAL
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
