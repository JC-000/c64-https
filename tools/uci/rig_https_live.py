#!/usr/bin/env python3
"""W5 LIVE HTTPS: full TLS 1.3 handshake + GET against a REAL public server
through the UCI backend on a real U64E / C64 Ultimate.

This is the live-server counterpart of ``rig_https_local.py``: there is no
inline listener, no repo cert, and no server-side evidence — the target is a
third-party host on the open internet, so **pass criteria come from C64-side
state only**: the sentinel fires, ``http_get`` returns C=0 (the TLS 1.3
handshake completed and the response parsed), and ``http_status`` equals the
expected status (200 — both sprint targets return 200 at ``/``).

Targets (2026-08-21 re-probe, ``tools/probe_server_tls.py``, 2 runs each):

    target             max record  silence tolerance   leaf     flight
    github.com              529 B     90 s (2/2)      1010 B   11 recs
    browserleaks.com        529 B     45 s (2/2)       952 B   12 recs
    en.wikipedia.org        529 B   ~120 s (2/2)      1636 B   14 recs

en.wikipedia.org's leaf (1636 B) fits the UCI ``cert_buf`` since it grew
to 2048 B (``cert_buf_size`` in labels.txt — the rig reads it from there);
on an old 1536 B build the rig warns loudly when wikipedia is selected but
does not refuse, since that run exercises the W2 "certificate too large"
error path.

How the target reaches the C64: this rig programs ``http_host_ptr`` /
``http_host_len`` over DMA and calls ``http_get``, whose prologue copies the
hostname into ``tls_hostname`` for SNI (src/http.s:95-111) and resolves it
via UCI firmware DNS — so any hostname works with today's PRG, unmodified.
The PRG's *menu-driven* 'G' path is a different story: its host is baked in
(``www.foo.invalid``, src/boot.s) until W3's ``make HTTPS_HOST=<host>`` /
``HTTPS_HOST_LEN`` build defines land. This rig does not depend on W3.

Environment variables:
  U64_HOST              — device IP (default 192.168.1.81)
  HTTPS_TARGET          — hostname to dial (default github.com)
  HTTPS_TARGET_PORT     — TCP port (default 443)
  EXPECT_STATUS         — expected http_status (default 200)
  TURBO_MHZ             — C64 CPU MHz (default 48); timeouts auto-scale
                          by 48/TURBO_MHZ exactly like rig_https_local
  C64_INIT_WAIT         — boot/auto-init wait seconds. Default is derived
                          from build/labels.txt: 75 for a comb build (the
                          ec_precompute_256 boot pass is ~45 s at 48 MHz —
                          the local rig's 22 s default would poll a machine
                          still precomputing), 22 otherwise.
  SENTINEL_POLL_TIMEOUT — C64-side completion budget (default 300 * scale)
  PHASE_TIMING          — default **1** here (opt-in in the local rig): a
                          live run is a milestone and the W0 phase table is
                          half its value. Set 0 to disable.
  PHASE_POLL            — phase-poll interval seconds (default 0.5)
  UCI_DEBUG_DIR         — artifact base dir (default /tmp/uci_https_live_debug)
  KEEP_DEBUG_ON_PASS    — default **1** here (0 in the local rig): live-run
                          artifacts (phase table, TLS snapshot) are the
                          deliverable, keep them even on PASS.
  TURBO_SETTLE          — settle after a real turbo config write (default 3.0)
  C64_SKIP_REU_PREFLIGHT— skip the REU preflight (see _reu_preflight.py)

Hardware conventions honored (see CLAUDE.md "UCI rig scripts"):
  * turbo is set BEFORE reset/run_prg, with the read-skip-write pattern
    (a mid-session or even redundant config write drops the next UCI
    command — UCI_ERR_NO_SOCKET on the first TCP_CONNECT);
  * ``preflight_reu()`` runs under the DeviceLock right after enable_uci
    (the comb build claims REU bank 2 — LIB_NISTCURVES_REU_BANKS_USED=$04 —
    so a device with the REU disabled must be refused before the run);
  * every DMA address comes from ``build_policy_and_arbiter_with_overlay_
    carveout()`` — nothing is hardcoded;
  * the filename is ``rig_*.py`` so pytest never collects it.

Deliberately NOT carried over from rig_https_local: the 6510 bus-stream
DebugCapture. Live failures are expected to be protocol/timing-shaped
(server RST during a crypto stall, cert too large), which the phase table,
``tls_state_dump.json``, ``ring.bin`` and the screen dump diagnose; run
rig_https_local for bus-level post-mortems.

Offline structural check (no hardware, no DeviceLock):
  ./rig_https_live.py --selfcheck
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    set_turbo_mhz,
    runner_health_check,
    Ultimate64RunnerStuckError,
    CAT_U64_SPECIFIC,
    cpu_speed_enum,
)
from c64_test_harness.uci_network import enable_uci, disable_uci
from c64_test_harness.keyboard import send_text
from c64_test_harness.labels import Labels

from _memory_policy import build_policy_and_arbiter_with_overlay_carveout
from _reu_preflight import ReuPreflightError, preflight_reu
from _temp_gc import gc_temp

# Pure helpers shared with the local rig (all side-effect free; importing
# the module only evaluates env defaults, it drives no hardware).
from rig_https_local import (
    _create_run_dir,
    _current_phase,
    _decode_screen_ram,
    _dump_diag,
    _dump_ring,
    _dump_tls_state_snapshot,
    _format_phase_log,
    _prune_old_run_dirs,
    _write_run_info,
)

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO_ROOT = Path(__file__).resolve().parents[2]
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"

HTTPS_TARGET = os.environ.get("HTTPS_TARGET", "github.com")
HTTPS_TARGET_PORT = int(os.environ.get("HTTPS_TARGET_PORT", "443"))
EXPECT_STATUS = int(os.environ.get("EXPECT_STATUS", "200"))

TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_TIMEOUT_SCALE = max(1.0, 48.0 / float(TURBO_MHZ))
SENTINEL_POLL_TIMEOUT = float(
    os.environ.get("SENTINEL_POLL_TIMEOUT", str(300.0 * _TIMEOUT_SCALE))
)

SENTINEL_VALUE = 0xC4

UCI_DEBUG_BASE_DIR = Path(
    os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_live_debug")
)
UCI_DEBUG_KEEP = 5
# Live-run divergence from the local rig: artifacts are kept on PASS by
# default — the phase table IS the milestone record.
UCI_DEBUG_KEEP_ON_PASS = os.environ.get("KEEP_DEBUG_ON_PASS", "1") != "0"

# 2026-08-21 re-probe values; see the module docstring table. Used only to
# print margin context and to warn — never to gate a run.
_KNOWN_TARGETS: dict[str, dict] = {
    "github.com":       {"tolerance_s": 90,  "leaf_b": 1010, "records": 11},
    "browserleaks.com": {"tolerance_s": 45,  "leaf_b": 952,  "records": 12},
    "en.wikipedia.org": {"tolerance_s": 120, "leaf_b": 1636, "records": 14},
}
# cert_buf capacity fallback, used only when labels.txt predates the
# `cert_buf_size` export (src/exports.s). Current builds carry the real
# value in labels.txt: 2048 UCI / 1536 ip65 (Wikipedia growth) — always
# prefer the label over this constant.
CERT_BUF_FALLBACK_BYTES = 1536

# Comb marker: manifest equate bit for REU bank 2 (Lim-Lee anchor table).
_BANKS_EQUATE = "LIB_NISTCURVES_REU_BANKS_USED"
_COMB_BANK_MASK = 0x04


def _load_labels() -> dict[str, int]:
    return dict(Labels.from_file(LABELS_PATH))


def default_init_wait(labels: dict[str, int]) -> float:
    """Boot-wait default for the *linked* build.

    A comb build runs ``ec_precompute_256`` at boot (~45 s at 48 MHz), so
    the local rig's 22 s default would start driving a machine that is
    still precomputing. Detection is a union, mirroring _reu_preflight's
    philosophy: the manifest equate's bank-2 bit OR the precompute symbol —
    renaming either upstream cannot silently misclassify.
    """
    banks = labels.get(_BANKS_EQUATE)
    if banks is not None and (banks & _COMB_BANK_MASK):
        return 75.0
    if any(name.startswith("ec_precompute") for name in labels):
        return 75.0
    return 22.0


def build_live_routine(labels: dict[str, int], *,
                       routine_addr: int,
                       host_str_addr: int,
                       path_str_addr: int,
                       sentinel_addr: int,
                       progress_addr: int,
                       carry_flag_addr: int,
                       host_len: int,
                       port: int) -> bytes:
    """Emit the 6502 trampoline that calls http_get for a live hostname.

    Identical in shape to rig_https_local's routine, but parameterised
    (no module-global addresses) and with the host length baked in — the
    hostname is known up front, so there is no patch offset.
    """
    if not (1 <= host_len <= 63):
        raise ValueError(f"host_len {host_len} out of range 1..63 "
                         "(tls_hostname copy guards at 63)")
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

    def emit_progress(step: int) -> None:
        emit_lda_imm(step)
        emit_sta_abs(progress_addr)

    http_get      = labels["http_get"]
    http_host_ptr = labels["http_host_ptr"]
    http_host_len = labels["http_host_len"]
    http_path_ptr = labels["http_path_ptr"]
    http_path_len = labels["http_path_len"]
    http_port     = labels["http_port"]
    net_init      = labels["net_init"]
    tcp_recv_head = labels["tcp_recv_head"]
    tcp_recv_tail = labels["tcp_recv_tail"]

    # 0) Bank BASIC ROM OUT so $A000-$BFFF is RAM
    emit_lda_abs(0x0001)
    emit(0x29, 0xFE)          # AND #$FE
    emit_sta_abs(0x0001)

    # Clear markers
    emit_lda_imm(0x00)
    emit_sta_abs(sentinel_addr)
    emit_sta_abs(progress_addr)
    emit_sta_abs(carry_flag_addr)

    emit_progress(0x01)

    # Re-init UCI (ensure idle state after auto-init)
    emit_jsr(net_init)

    # Zero the TCP ring head/tail to flush stale boot-poll data
    emit_lda_imm(0x00)
    emit_sta_abs(tcp_recv_head)
    emit_sta_abs(tcp_recv_head + 1)
    emit_sta_abs(tcp_recv_tail)
    emit_sta_abs(tcp_recv_tail + 1)

    emit_progress(0x02)

    # http_host_ptr = host_str_addr; http_host_len = host_len
    emit_lda_imm(host_str_addr & 0xFF)
    emit_sta_abs(http_host_ptr)
    emit_lda_imm((host_str_addr >> 8) & 0xFF)
    emit_sta_abs(http_host_ptr + 1)
    emit_lda_imm(host_len)
    emit_sta_abs(http_host_len)

    # http_path_ptr = path_str_addr; http_path_len = 1 ("/")
    emit_lda_imm(path_str_addr & 0xFF)
    emit_sta_abs(http_path_ptr)
    emit_lda_imm((path_str_addr >> 8) & 0xFF)
    emit_sta_abs(http_path_ptr + 1)
    emit_lda_imm(1)
    emit_sta_abs(http_path_len)

    # http_port (16-bit LE)
    emit_lda_imm(port & 0xFF)
    emit_sta_abs(http_port)
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(http_port + 1)

    emit_progress(0x03)

    # Call http_get — the REAL TLS 1.3 + HTTP code path.
    emit_jsr(http_get)

    # Store carry (0=success, 1=failure) via PHP/PLA
    emit(0x08)  # PHP
    emit(0x68)  # PLA
    emit_sta_abs(carry_flag_addr)

    emit_progress(0x04)

    # Write sentinel
    emit_lda_imm(SENTINEL_VALUE)
    emit_sta_abs(sentinel_addr)

    emit_progress(0x05)

    # Park CPU
    park = routine_addr + len(code)
    emit(0x4C, park & 0xFF, (park >> 8) & 0xFF)   # JMP park

    return bytes(code)


def _print_target_context(target: str, port: int,
                          cert_buf_b: int = CERT_BUF_FALLBACK_BYTES) -> None:
    info = _KNOWN_TARGETS.get(target)
    print(f"\nLive target     : {target}:{port}")
    if info is None:
        print("  (not in the probed target table — no tolerance/leaf data; "
              "run tools/probe_server_tls.py against it first)")
        return
    print(f"  silence tolerance : ~{info['tolerance_s']} s "
          f"(2026-08-21 probe; live servers change — re-probe before "
          f"trusting)")
    print(f"  leaf cert         : {info['leaf_b']} B "
          f"(cert_buf = {cert_buf_b} B)")
    print(f"  server flight     : ~{info['records']} records, all <= 529 B")
    if info["leaf_b"] > cert_buf_b:
        print(f"  *** WARNING: leaf exceeds cert_buf by "
              f"{info['leaf_b'] - cert_buf_b} B — expect the client to "
              f"abort at Certificate (this exercises the W2 'certificate "
              f"too large' path; it cannot PASS on this build)")


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        print("Run: make BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1",
              file=sys.stderr)
        return 2
    if not LABELS_PATH.is_file():
        print("ERROR: labels.txt not found", file=sys.stderr)
        print("Run: make BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1",
              file=sys.stderr)
        return 2

    labels = _load_labels()
    required = [
        "http_get", "http_host_ptr", "http_host_len",
        "http_path_ptr", "http_path_len", "http_port",
        "net_init", "net_initialized", "uci_socket_id",
        "net_last_error", "net_tcp_state",
        "tcp_recv_head", "tcp_recv_tail",
        "uci_req_len", "uci_read_hdr",      # #140: SOCKET_READ request vs claim
        "http_resp_buf", "http_resp_len", "http_status",
        "tls_state", "tls_last_state",
    ]
    missing = [n for n in required if n not in labels]
    if missing:
        print(f"ERROR: missing labels: {missing}", file=sys.stderr)
        return 2
    for n in sorted(required):
        print(f"  {n:22s} = ${labels[n]:04X}")

    init_wait = float(os.environ.get("C64_INIT_WAIT",
                                     str(default_init_wait(labels))))

    # DMA addresses from the arbiter — never hardcoded. Same carveout the
    # local rig uses (the comb build's overlay landings fill CRYPTO_OVERLAY;
    # the NET_CODE zero-fill tail is the safe scratch region).
    memory_policy, arbiter = build_policy_and_arbiter_with_overlay_carveout(
        LABELS_PATH, PRG_PATH,
    )
    routine_addr    = arbiter.alloc(256, name="trampoline")
    host_str_addr   = arbiter.alloc(64,  name="host_str")
    path_str_addr   = arbiter.alloc(64,  name="path_str")
    sentinel_addr   = arbiter.alloc(1,   name="sentinel")
    progress_addr   = arbiter.alloc(1,   name="progress")
    carry_flag_addr = arbiter.alloc(1,   name="carry_flag")
    print(f"\nMemoryPolicy reserved {len(memory_policy.reserved_regions)}"
          f" region(s); arbiter allocations:")
    for base, last, note in arbiter.allocations:
        print(f"  ${base:04X}-${last:04X}  {note}")

    _print_target_context(HTTPS_TARGET, HTTPS_TARGET_PORT,
                          labels.get("cert_buf_size",
                                     CERT_BUF_FALLBACK_BYTES))

    host_bytes = HTTPS_TARGET.encode("ascii")
    routine_bytes = build_live_routine(
        labels,
        routine_addr=routine_addr,
        host_str_addr=host_str_addr,
        path_str_addr=path_str_addr,
        sentinel_addr=sentinel_addr,
        progress_addr=progress_addr,
        carry_flag_addr=carry_flag_addr,
        host_len=len(host_bytes),
        port=HTTPS_TARGET_PORT,
    )
    print(f"Routine size    : {len(routine_bytes)} bytes @ ${routine_addr:04X}")
    print(f"C64_INIT_WAIT   : {init_wait:.0f} s "
          f"(x{_TIMEOUT_SCALE:.0f} timeout scale at {TURBO_MHZ} MHz)")

    host_str = host_bytes + b"\x00"
    path_str = b"/\x00"
    prg = PRG_PATH.read_bytes()

    lock = DeviceLock(HOST)
    try:
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 2
    info = lock.read_info()
    print(f"Acquired DeviceLock({HOST}); holder info: {info!r}")

    removed = _prune_old_run_dirs(UCI_DEBUG_BASE_DIR, UCI_DEBUG_KEEP)
    for d in removed:
        print(f"Pruning old debug artifacts: {d}")
    run_dir = _create_run_dir(UCI_DEBUG_BASE_DIR)
    print(f"Debug artifacts dir: {run_dir}")

    client: Ultimate64Client | None = None
    uci_enabled = False
    outcome = "UNKNOWN"
    exit_code = 1
    run_start = time.time()
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        transport = Ultimate64Transport(host=HOST, timeout=15.0, client=client)
        transport.memory_policy = memory_policy

        print("Enabling UCI...")
        enable_uci(client)
        uci_enabled = True

        # Userspace /Temp GC (fw <= 3.14d leaks one attachment per REST
        # body; ~15 runs wedge REST + the UCI bridge together). Mirrors
        # the GideonZ/1541ultimate#686 cleanup until a released firmware
        # carries it. Best-effort; C64_SKIP_TEMP_GC=1 bypasses.
        gc_temp(HOST)

        # Wedged-runner pre-detect (see rig_https_local for the rationale).
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            print(f"[fatal] runner wedged at {HOST}: {exc}", file=sys.stderr)
            print("[fatal] supervisor: investigate / authorize recover()",
                  file=sys.stderr)
            return 3

        # REU preflight (issue #97) — under the DeviceLock, right after
        # enable_uci, before anything long-running. The comb build claims
        # REU bank 2, so this is not optional for the sprint's own PRG.
        try:
            preflight_reu(client, LABELS_PATH)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4

        # --- Set turbo BEFORE reset/run_prg, skipping a redundant write ---
        # (the config WRITE itself glitches the UCI bridge and drops the
        # next TCP_CONNECT — see rig_https_local's comment block; the shape
        # of the REST response is also documented there).
        try:
            cat = client.get_config_category(CAT_U64_SPECIFIC)
            inner = cat.get(CAT_U64_SPECIFIC, cat)
            cur_speed = inner.get("CPU Speed")
            cur_turbo = inner.get("Turbo Control")
        except Exception as exc:                      # probe is best-effort
            print(f"  (turbo state probe failed: {exc}; writing anyway)")
            cur_speed = cur_turbo = None

        want_speed = str(cpu_speed_enum(TURBO_MHZ))
        if str(cur_speed) == want_speed and cur_turbo == "Manual":
            print(f"Turbo already {TURBO_MHZ} MHz (Manual) — skipping "
                  "config write")
        else:
            print(f"Setting turbo to {TURBO_MHZ} MHz "
                  f"(from {cur_turbo}/{cur_speed})...")
            set_turbo_mhz(client, TURBO_MHZ)
            time.sleep(float(os.environ.get("TURBO_SETTLE", "3.0")))

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)

        print("run_prg(PRG)...")
        client.run_prg(prg)
        print(f"Waiting {init_wait * _TIMEOUT_SCALE:.0f} s for auto-init "
              "(entropy, REU init, comb precompute, DHCP)...")
        time.sleep(init_wait * _TIMEOUT_SCALE)

        init_flag = transport.read_memory(labels["net_initialized"], 1)[0]
        print(f"net_initialized = ${init_flag:02X}")
        if init_flag == 0:
            print("WARNING: net_initialized is 0 — auto-init may have failed")

        # Quit PRG main_loop back to BASIC
        print("Sending 'Q' to exit PRG main_loop...")
        send_text(transport, "q\r")
        time.sleep(2.0 * _TIMEOUT_SCALE)

        # DMA-write the routine + data
        CHUNK = 64
        for i in range(0, len(routine_bytes), CHUNK):
            transport.write_memory(routine_addr + i,
                                   routine_bytes[i:i + CHUNK])
        transport.write_memory(host_str_addr, host_str.ljust(64, b"\x00"))
        transport.write_memory(path_str_addr, path_str.ljust(8, b"\x00"))
        transport.write_memory(sentinel_addr, bytes(16))

        # Trigger via SYS
        sys_line = f"sys{routine_addr}\r"
        print(f"Triggering: {sys_line.strip()}")
        send_text(transport, sys_line)

        # --- Poll sentinel, with phase timing (default ON for live runs) ---
        deadline = time.time() + SENTINEL_POLL_TIMEOUT
        last_progress = -1
        start = time.time()
        phase_timing = os.environ.get("PHASE_TIMING", "1") == "1"
        phase_poll = float(os.environ.get("PHASE_POLL", "0.5"))
        phase_log: list[tuple[str, float]] = []
        cur_phase = None
        sentinel_seen = False
        while time.time() < deadline:
            time.sleep(phase_poll if phase_timing else 0.5)
            blob = transport.read_memory(sentinel_addr, 2)
            sentinel = blob[0]
            progress = blob[1]
            if progress != last_progress:
                elapsed = time.time() - start
                print(f"  [{elapsed:6.1f}s] progress=0x{progress:02X}")
                last_progress = progress
            if phase_timing:
                scr = _decode_screen_ram(
                    bytes(transport.read_memory(0x0400, 1000)))
                phase = _current_phase(scr)
                if cur_phase is None:
                    cur_phase = phase
                elif phase != cur_phase:
                    cur_phase = phase
                    phase_log.append((phase, time.time() - start))
                    print(f"  phase +{phase_log[-1][1]:7.1f}s  {phase}")
            if sentinel == SENTINEL_VALUE:
                print("  sentinel set — routine complete")
                sentinel_seen = True
                break

        if phase_timing:
            table = _format_phase_log(phase_log)
            print("\n=== Phase timing (live) ===")
            print(table)
            try:
                (run_dir / "phase_timing.txt").write_text(
                    f"target={HTTPS_TARGET}:{HTTPS_TARGET_PORT} "
                    f"turbo={TURBO_MHZ}MHz poll={phase_poll}s\n\n{table}\n")
            except Exception as exc:      # diagnostics must never fail the run
                print(f"  (could not write phase_timing.txt: {exc})")

        # --- Diagnostics (both outcomes) ---
        _dump_diag(transport, labels)
        try:
            _dump_ring(transport, labels, run_dir)
            _dump_tls_state_snapshot(transport, labels, run_dir)
            print(f"  snapshots -> {run_dir}")
        except Exception as exc:
            print(f"WARNING: snapshot dump failed: {exc}")

        carry = transport.read_memory(carry_flag_addr, 1)[0] & 0x01
        status_raw = transport.read_memory(labels["http_status"], 2)
        http_status = status_raw[0] | (status_raw[1] << 8)
        resp_len_raw = transport.read_memory(labels["http_resp_len"], 2)
        resp_len = resp_len_raw[0] | (resp_len_raw[1] << 8)
        read_len = min(resp_len, 200) if resp_len > 0 else 200
        resp_data = bytes(transport.read_memory(labels["http_resp_buf"],
                                                read_len))
        screen = bytes(transport.read_memory(0x0400, 1000))
        screen_text = _decode_screen_ram(screen)

        print(f"\nhttp_get carry  = {carry} (0=success, 1=failure)")
        print(f"http_status     = {http_status}")
        print(f"http_resp_len   = {resp_len}")
        print(f"http_resp_buf   = {resp_data[:100]!r}")
        print("\n--- screen RAM ---")
        for line in screen_text.split("\n"):
            if line.strip():
                print(f"  {line}")
        try:
            (run_dir / "screen.txt").write_text(screen_text + "\n")
        except Exception:
            pass

        # --- Pass criteria: C64-side state ONLY ---
        problems: list[str] = []
        if not sentinel_seen:
            problems.append(
                f"sentinel not set within {SENTINEL_POLL_TIMEOUT:.0f}s "
                f"(progress=0x{last_progress:02X})")
        else:
            if carry != 0:
                problems.append(
                    "http_get returned C=1 — TLS handshake or HTTP exchange "
                    "failed (see tls_state_dump.json)")
            if http_status != EXPECT_STATUS:
                problems.append(
                    f"http_status is {http_status}, expected {EXPECT_STATUS}")

        if problems:
            print(f"\nFAIL against {HTTPS_TARGET}:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            outcome = "TIMEOUT" if not sentinel_seen else "FAIL"
            exit_code = 1
            return exit_code

        print(f"\nPASS: TLS 1.3 handshake completed against {HTTPS_TARGET} "
              f"and http_status={http_status}")
        outcome = "PASS"
        exit_code = 0
        return exit_code

    finally:
        try:
            _write_run_info(
                run_dir / "run_info.txt",
                outcome=outcome,
                duration=time.time() - run_start,
                exit_code=exit_code,
                extra={
                    "target": f"{HTTPS_TARGET}:{HTTPS_TARGET_PORT}",
                    "turbo_mhz": TURBO_MHZ,
                    "host": HOST,
                },
            )
        except Exception as exc:
            print(f"WARNING: run_info write failed: {exc}")
        print(f"\nDebug artifacts: {run_dir}")
        if outcome == "PASS" and not UCI_DEBUG_KEEP_ON_PASS:
            import shutil
            try:
                shutil.rmtree(run_dir)
                print("(removed on PASS; KEEP_DEBUG_ON_PASS=1 to retain)")
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


# ---------------------------------------------------------------------------
# Offline structural self-check — no hardware, no DeviceLock, no REST.
# ---------------------------------------------------------------------------

def _selfcheck() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        status = "ok" if cond else "FAIL"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
        if not cond:
            failures.append(name)

    print("rig_https_live selfcheck (offline)")

    # 1) env handling
    check("HTTPS_TARGET default/env",
          HTTPS_TARGET == os.environ.get("HTTPS_TARGET", "github.com"))
    check("port parses as int", isinstance(HTTPS_TARGET_PORT, int))
    check("timeout scale >= 1", _TIMEOUT_SCALE >= 1.0,
          f"TURBO_MHZ={TURBO_MHZ} -> x{_TIMEOUT_SCALE:g}")

    # 2) init-wait derivation
    check("comb via banks equate ($04) -> 75",
          default_init_wait({_BANKS_EQUATE: 0x04}) == 75.0)
    check("comb via ec_precompute_256 symbol -> 75",
          default_init_wait({"ec_precompute_256": 0x8000}) == 75.0)
    check("onchip (banks=0, no symbol) -> 22",
          default_init_wait({_BANKS_EQUATE: 0}) == 22.0)
    check("reu profile (banks=$03) -> 22",
          default_init_wait({_BANKS_EQUATE: 0x03}) == 22.0)

    # 3) trampoline structure against synthetic labels
    fake_labels = {
        "http_get": 0x6123, "http_host_ptr": 0xA801, "http_host_len": 0xA803,
        "http_path_ptr": 0xA804, "http_path_len": 0xA806,
        "http_port": 0xA807, "net_init": 0x2001,
        "tcp_recv_head": 0xA810, "tcp_recv_tail": 0xA812,
    }
    addrs = dict(routine_addr=0x3C00, host_str_addr=0x3D00,
                 path_str_addr=0x3D40, sentinel_addr=0x3D80,
                 progress_addr=0x3D81, carry_flag_addr=0x3D82)
    host = "github.com"
    code = build_live_routine(fake_labels, **addrs,
                              host_len=len(host), port=443)
    check("banks ROM out first",
          code[:8] == bytes([0xAD, 0x01, 0x00, 0x29, 0xFE, 0x8D, 0x01, 0x00]))
    jsr_http_get = bytes([0x20, 0x23, 0x61])
    check("JSR http_get present", jsr_http_get in code)
    check("PHP/PLA carry latch after http_get",
          code[code.index(jsr_http_get) + 3:
               code.index(jsr_http_get) + 5] == b"\x08\x68")
    check("host_len baked in",
          bytes([0xA9, len(host), 0x8D, 0x03, 0xA8]) in code)
    check("port 443 stored LE",
          bytes([0xA9, 443 & 0xFF, 0x8D, 0x07, 0xA8, 0xA9, 443 >> 8]) in code)
    check("sentinel value written",
          bytes([0xA9, SENTINEL_VALUE]) in code)
    # The park JMP targets its own address (spin in place), which is the
    # routine base plus the code length *before* the 3-byte JMP itself.
    park = addrs["routine_addr"] + len(code) - 3
    check("parks with JMP self",
          code[-3:] == bytes([0x4C, park & 0xFF, (park >> 8) & 0xFF]))
    check("routine fits its 256 B slot", len(code) <= 256,
          f"{len(code)} bytes")

    # 4) host-length guard
    try:
        build_live_routine(fake_labels, **addrs, host_len=64, port=443)
        check("host_len > 63 rejected", False)
    except ValueError:
        check("host_len > 63 rejected", True)

    # 5) real build, if one exists (structural only — no hardware)
    if LABELS_PATH.is_file():
        labels = _load_labels()
        have = [n for n in ("http_get", "http_host_ptr", "net_init")
                if n in labels]
        check("real labels.txt loads", len(have) == 3,
              f"{LABELS_PATH}")
        print(f"  (real build init wait would default to "
              f"{default_init_wait(labels):.0f} s)")
    else:
        print(f"  (no {LABELS_PATH} — real-build check skipped)")

    if failures:
        print(f"\nSELFCHECK FAIL: {len(failures)} check(s): {failures}")
        return 1
    print("\nSELFCHECK PASS")
    return 0


if __name__ == "__main__":
    if "--selfcheck" in sys.argv[1:]:
        raise SystemExit(_selfcheck())
    raise SystemExit(main())
