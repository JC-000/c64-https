#!/usr/bin/env python3
"""Wikipedia-article stretch goal: GET ~122 KB of wikitext from
en.wikipedia.org into the REU at $10:0000, then hand the machine to the
human with the on-screen viewer live.

Build the PRG this rig expects with EXACTLY:

    make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1 \\
        HTTPS_HOST=en.wikipedia.org \\
        'HTTPS_PATH=/w/index.php?title=Commodore_64&action=raw' \\
        HTTPS_BODY_TO_REU=1

Contract with the 6502 lanes (exports expected in build/labels.txt):
  http_body_total   3 bytes LE — de-chunked body bytes sunk so far; the
                    rig's progress signal AND the size it verifies
  http_body_sink    body-sink entry (presence proves the right build)
  http_status       16-bit LE HTTP status
  http_resp_buf     holds the FIRST 512 body bytes after completion
  viewer_enter      on-screen viewer; the trampoline JSRs it on success

Recon (2026-08-21, tools/probe_server_tls.py + header-faithful host
fetch — re-run both before trusting):
  * en.wikipedia.org still honors max_fragment_length: 529 B max record
    (fits TLS_REC_BUF_MAX 548), 14-record / 4,659 B server flight,
    ~120 s silence tolerance, ECDSA-P256 leaf 1636 B DER (<= the 2048 B
    cert_buf the certbuf lane sized for).
  * action=raw responds **Transfer-Encoding: chunked** (NO
    Content-Length): 4 data chunks of 26,931-32,768 B, body 125,235 B,
    `text/x-wiki`, byte-stable across back-to-back requests. The
    body-sink must ride the W4 chunked path; chunk sizes fit the
    16-bit http_chunk_rem.
  * **A request without a User-Agent header gets HTTP 403** ("Please
    set a user-agent...m robot policy"). src/http.s's http_build_get
    sends only Host + Connection — the HTTP lane must add a UA header
    or every run ends 403.

Environment variables:
  U64_HOST          — device IP (default 192.168.1.81)
  WIKI_HOST         — hostname the trampoline dials (default
                      en.wikipedia.org; must match the build's
                      HTTPS_HOST for the banner/menu path but the
                      trampoline programs it either way)
  WIKI_PATH         — path (default /w/index.php?title=Commodore_64&
                      action=raw). Tip: pin a revision with &oldid=N
                      for a byte-exact compare that cannot drift.
  WIKI_TIMEOUT      — sentinel budget seconds (default 600; the fetch
                      is ~250+ TLS records after a ~35 s handshake)
  WIKI_REF_UA       — User-Agent for the HOST-side reference fetch
                      (Wikipedia requires one; default identifies this
                      project per their robot policy)
  EXPECT_STATUS     — expected http_status (default 200)
  TURBO_MHZ         — C64 CPU MHz (default 48); budgets scale by 48/MHz
  C64_INIT_WAIT     — boot wait; auto-detected 75 s for a comb build
  REU_SETTLE / TURBO_SETTLE — post-config-write settle (default 3.0 s;
                      config writes glitch the next UCI command)
  PHASE_TIMING      — screen-scrape phase table (default 0 here: the
                      run is long and body progress is the signal)
  UCI_DEBUG_DIR     — artifact dir (default /tmp/uci_https_wiki_debug)
  C64_SKIP_TEMP_GC / C64_SKIP_REU_PREFLIGHT — bypass those steps
  WIKI_SELFCHECK_OFFLINE — set 1 to skip the live reference fetch in
                      --selfcheck

Hardware conventions honored (CLAUDE.md "UCI rig scripts"):
  * REU forced to (Enabled, 16 MB) BEFORE reset — the article lands at
    REU bank 16, past the flash-saved 512 KB default. Read first,
    write only on mismatch (any config write can drop the next UCI
    command), settle after a real write. The write is runtime-only and
    REVERTS ON POWER CYCLE — the rig prints exactly what it changed.
  * preflight_reu() kept as well: it checks presence/enabled against
    the build profile, not size.
  * turbo set BEFORE reset with the read-skip-write pattern;
  * /Temp GC after enable_uci (fw <= 3.14d writemem leak);
  * every DMA address from build_policy_and_arbiter_with_overlay_
    carveout() — nothing hardcoded;
  * DEBUG_CAPTURE (6510 bus stream) is NOT wired here at all — OFF;
  * progress is read-only DMA at ~1-2 Hz (reads are wedge-safe;
    writemem is the leaky side), progress PRINTS at most every 10 s;
  * rig_*.py name keeps pytest collection out.

On PASS the machine is NOT reset and UCI is left enabled: the viewer
is live on the real screen for the human. CAVEAT (DeviceLock module
docs): the lock is a queued flock — the moment this rig releases it,
any waiting harness job acquires the device and will typically reset
it. The viewer session lasts only until the next queued job; hold off
launching other device work while playing with it.

Offline structural check (no hardware, no DeviceLock):
  ./rig_https_wiki.py --selfcheck
"""
from __future__ import annotations

import os
import socket
import ssl
import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    CAT_U64_SPECIFIC,
    Ultimate64RunnerStuckError,
    cpu_speed_enum,
    get_reu_config,
    runner_health_check,
    set_reu,
    set_turbo_mhz,
)
from c64_test_harness.keyboard import send_text
from c64_test_harness.labels import Labels
from c64_test_harness.uci_network import disable_uci, enable_uci

from _memory_policy import build_policy_and_arbiter_with_overlay_carveout
from _reu_preflight import ReuPreflightError, preflight_reu
from _temp_gc import gc_temp

# Pure helpers shared with the local/live rigs (side-effect free imports).
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
from rig_https_live import SENTINEL_VALUE, default_init_wait

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO_ROOT = Path(__file__).resolve().parents[2]
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"

WIKI_HOST = os.environ.get("WIKI_HOST", "en.wikipedia.org")
WIKI_PATH = os.environ.get(
    "WIKI_PATH", "/w/index.php?title=Commodore_64&action=raw")
WIKI_PORT = int(os.environ.get("WIKI_PORT", "443"))
EXPECT_STATUS = int(os.environ.get("EXPECT_STATUS", "200"))
# Wikipedia's robot policy 403s UA-less clients; the reference fetch
# must send one (the C64 side's UA is baked by the HTTP lane).
WIKI_REF_UA = os.environ.get(
    "WIKI_REF_UA",
    "c64-https-rig/0.1 (host-side reference fetch; "
    "https://github.com/JC-000/c64-https)")

TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_TIMEOUT_SCALE = max(1.0, 48.0 / float(TURBO_MHZ))
WIKI_TIMEOUT = float(os.environ.get("WIKI_TIMEOUT", "600")) * _TIMEOUT_SCALE

REQUIRED_REU_SIZE = "16 MB"          # article sink base is REU bank $10
RESP_PREFIX_BYTES = 512              # contract: first 512 body bytes
PROGRESS_PRINT_INTERVAL = 10.0       # print at most every 10 s
POLL_INTERVAL = 1.0                  # readmem cadence (reads are safe)

UCI_DEBUG_BASE_DIR = Path(
    os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_wiki_debug"))
UCI_DEBUG_KEEP = 5

# Labels the wiki-contract build must export, on top of the live-rig set.
CONTRACT_LABELS = [
    "http_body_total", "http_body_sink", "viewer_enter",
]
BASE_LABELS = [
    "http_get", "http_host_ptr", "http_host_len",
    "http_path_ptr", "http_path_len", "http_port",
    "net_init", "net_initialized",
    "net_last_error", "net_tcp_state",
    "tcp_recv_head", "tcp_recv_tail",
    "http_resp_buf", "http_resp_len", "http_status",
    "tls_state", "tls_last_state",
]


def _load_labels() -> dict[str, int]:
    return dict(Labels.from_file(LABELS_PATH))


# --------------------------------------------------------------------------- #
# 6502 trampoline                                                             #
# --------------------------------------------------------------------------- #

def build_wiki_routine(labels: dict[str, int], *,
                       routine_addr: int,
                       host_str_addr: int,
                       path_str_addr: int,
                       sentinel_addr: int,
                       progress_addr: int,
                       carry_flag_addr: int,
                       host_len: int,
                       path_len: int,
                       port: int) -> bytes:
    """Trampoline: http_get for the wiki target, then viewer on success.

    Same shape as rig_https_live's routine with two differences: the
    path length is parameterised (the article path is 42 chars, not
    "/"), and after latching carry + writing the sentinel it JSRs
    ``viewer_enter`` when http_get returned C=0 — leaving the viewer
    live on screen — and parks otherwise.
    """
    if not (1 <= host_len <= 63):
        raise ValueError(f"host_len {host_len} out of range 1..63 "
                         "(tls_hostname copy guards at 63)")
    if not (1 <= path_len <= 128):
        # http_req_buf is 256 B total for "GET <path> HTTP/1.1" + Host +
        # UA + Connection; 128 keeps comfortable margin.
        raise ValueError(f"path_len {path_len} out of range 1..128 "
                         "(http_req_buf is 256 B for the whole request)")
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
    viewer_enter  = labels["viewer_enter"]

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

    # http_host_ptr/len
    emit_lda_imm(host_str_addr & 0xFF)
    emit_sta_abs(http_host_ptr)
    emit_lda_imm((host_str_addr >> 8) & 0xFF)
    emit_sta_abs(http_host_ptr + 1)
    emit_lda_imm(host_len)
    emit_sta_abs(http_host_len)

    # http_path_ptr/len — real article path, length baked in
    emit_lda_imm(path_str_addr & 0xFF)
    emit_sta_abs(http_path_ptr)
    emit_lda_imm((path_str_addr >> 8) & 0xFF)
    emit_sta_abs(http_path_ptr + 1)
    emit_lda_imm(path_len)
    emit_sta_abs(http_path_len)

    # http_port (16-bit LE)
    emit_lda_imm(port & 0xFF)
    emit_sta_abs(http_port)
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(http_port + 1)

    emit_progress(0x03)

    # The REAL TLS 1.3 + HTTP + body-sink code path.
    emit_jsr(http_get)

    # Latch carry (0=success, 1=failure) via PHP/PLA
    emit(0x08)  # PHP
    emit(0x68)  # PLA
    emit_sta_abs(carry_flag_addr)

    emit_progress(0x04)

    # Sentinel FIRST so the rig sees completion promptly, then hand the
    # screen to the human iff http_get succeeded (carry bit 0 clear).
    emit_lda_imm(SENTINEL_VALUE)
    emit_sta_abs(sentinel_addr)

    emit_lda_abs(carry_flag_addr)
    emit(0x29, 0x01)          # AND #$01 — carry is bit 0 of pushed P
    emit(0xD0, 0x03)          # BNE +3 (skip the JSR on failure)
    emit_jsr(viewer_enter)    # normally never returns while human plays

    # Park CPU (also the BNE target)
    park = routine_addr + len(code)
    emit(0x4C, park & 0xFF, (park >> 8) & 0xFF)   # JMP park

    return bytes(code)


# --------------------------------------------------------------------------- #
# Host-side reference fetch (stdlib ssl only)                                 #
# --------------------------------------------------------------------------- #

def fetch_reference(host: str, path: str, port: int = 443, *,
                    user_agent: str = WIKI_REF_UA,
                    timeout: float = 30.0) -> dict:
    """GET the same URL the C64 fetched, with C64-faithful headers plus a
    User-Agent (Wikipedia 403s without one). Returns
    {status, framing, body, content_length} — body is de-chunked.
    """
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    raw = socket.create_connection((host, port), timeout=timeout)
    s = ctx.wrap_socket(raw, server_hostname=host)
    try:
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {user_agent}\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode("ascii"))
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()

    hdr_end = buf.find(b"\r\n\r\n")
    if hdr_end < 0:
        raise RuntimeError("reference fetch: no header terminator in reply")
    header_lines = buf[:hdr_end].decode("latin-1").split("\r\n")
    status = int(header_lines[0].split(" ", 2)[1])
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = buf[hdr_end + 4:]

    framing = "close-delimited"
    if "chunked" in headers.get("transfer-encoding", "").lower():
        framing = "chunked"
        body = _dechunk(body)
    elif "content-length" in headers:
        framing = "content-length"
        body = body[:int(headers["content-length"])]
    return {
        "status": status,
        "framing": framing,
        "content_length": headers.get("content-length"),
        "content_type": headers.get("content-type"),
        "body": body,
    }


def _dechunk(raw: bytes) -> bytes:
    out, off = bytearray(), 0
    while True:
        i = raw.find(b"\r\n", off)
        if i < 0:
            break                      # truncated tail — return what we have
        try:
            n = int(raw[off:i].split(b";")[0], 16)
        except ValueError:
            break
        if n == 0:
            break
        out += raw[i + 2:i + 2 + n]
        off = i + 2 + n + 2
    return bytes(out)


# --------------------------------------------------------------------------- #
# Verification                                                                #
# --------------------------------------------------------------------------- #

def verify_against_reference(c64_status: int, body_total: int,
                             prefix: bytes, ref: dict | None,
                             expect_status: int = EXPECT_STATUS,
                             ) -> tuple[str, list[str], list[str]]:
    """Pass criteria. Returns (verdict, problems, warnings); verdict is
    PASS / WARN (pass with size drift) / FAIL.

    * http_status must equal expect_status — else FAIL.
    * reference unavailable — FAIL (an unverified pass is not a pass);
      the viewer is still left live, rerun the rig to verify.
    * body_total == reference size AND 512-byte prefix matches — PASS.
    * sizes differ but prefix matches byte-exactly — WARN, not FAIL
      (action=raw revisions change between fetches); both sizes are
      reported.
    * prefix mismatch — FAIL regardless of sizes.
    """
    problems: list[str] = []
    warnings: list[str] = []
    if c64_status != expect_status:
        problems.append(f"http_status is {c64_status}, expected "
                        f"{expect_status}"
                        + (" — note: Wikipedia 403s UA-less requests; is "
                           "the HTTP lane's User-Agent header in the build?"
                           if c64_status == 403 else ""))
        return ("FAIL", problems, warnings)
    if ref is None:
        problems.append("host-side reference fetch failed — body cannot be "
                        "verified (C64-side status was correct; viewer left "
                        "live; re-run to verify)")
        return ("FAIL", problems, warnings)

    ref_body = ref["body"]
    n = min(RESP_PREFIX_BYTES, body_total, len(ref_body), len(prefix))
    prefix_ok = n > 0 and prefix[:n] == ref_body[:n]
    size_ok = body_total == len(ref_body)

    if size_ok and prefix_ok:
        return ("PASS", problems, warnings)
    if prefix_ok:
        warnings.append(
            f"size drift: C64 http_body_total={body_total} vs reference "
            f"{len(ref_body)} bytes, but first {n} body bytes match "
            "byte-exactly (action=raw revision may have changed between "
            "fetches) — WARN, not FAIL")
        return ("WARN", problems, warnings)
    problems.append(
        f"body prefix mismatch in first {n} bytes "
        f"(C64 total {body_total}, reference {len(ref_body)}); "
        "the sink prefix in http_resp_buf does not match the article")
    return ("FAIL", problems, warnings)


# --------------------------------------------------------------------------- #
# Device REU config (16 MB, before reset, read-skip-write)                    #
# --------------------------------------------------------------------------- #

def ensure_reu_16mb(client: Ultimate64Client) -> None:
    """Force (Enabled, 16 MB) — the sink writes REU bank $10, beyond the
    flash-saved 512 KB. Runtime-only; reverts on power cycle."""
    try:
        enabled, size = get_reu_config(client)
    except Exception as exc:                 # probe best-effort, then write
        print(f"  (REU state probe failed: {exc}; writing anyway)")
        enabled, size = False, "?"
    if enabled and size == REQUIRED_REU_SIZE:
        print(f"REU already (Enabled, {REQUIRED_REU_SIZE}) — "
              "skipping config write")
        return
    print(f"REU config was (enabled={enabled}, size={size!r}); writing "
          f"(Enabled, {REQUIRED_REU_SIZE}) — runtime-only, REVERTS ON "
          "POWER CYCLE")
    set_reu(client, True, size=REQUIRED_REU_SIZE)
    time.sleep(float(os.environ.get("REU_SETTLE", "3.0")))


# --------------------------------------------------------------------------- #
# Main hardware run                                                           #
# --------------------------------------------------------------------------- #

def main() -> int:
    if not PRG_PATH.is_file() or not LABELS_PATH.is_file():
        print(f"ERROR: build artifacts missing under {PRG_PATH.parent}",
              file=sys.stderr)
        print("Build with:\n  make clean && make BACKEND=uci "
              "USE_NISTCURVES_ONCHIP_COMB=1 HTTPS_HOST=en.wikipedia.org "
              "'HTTPS_PATH=/w/index.php?title=Commodore_64&action=raw' "
              "HTTPS_BODY_TO_REU=1", file=sys.stderr)
        return 2

    labels = _load_labels()
    required = BASE_LABELS + CONTRACT_LABELS
    missing = [n for n in required if n not in labels]
    if missing:
        print(f"ERROR: missing labels: {missing}", file=sys.stderr)
        if set(missing) & set(CONTRACT_LABELS):
            print("This PRG predates the wiki contract (HTTPS_BODY_TO_REU "
                  "body sink + viewer). Rebuild with the line in this "
                  "file's header.", file=sys.stderr)
        return 2
    for n in sorted(required):
        print(f"  {n:22s} = ${labels[n]:04X}")

    init_wait = float(os.environ.get("C64_INIT_WAIT",
                                     str(default_init_wait(labels))))

    memory_policy, arbiter = build_policy_and_arbiter_with_overlay_carveout(
        LABELS_PATH, PRG_PATH,
    )
    routine_addr  = arbiter.alloc(256, name="trampoline")
    host_str_addr = arbiter.alloc(64,  name="host_str")
    path_str_addr = arbiter.alloc(128, name="path_str")
    marker_base   = arbiter.alloc(16,  name="markers")
    sentinel_addr, progress_addr, carry_flag_addr = (
        marker_base, marker_base + 1, marker_base + 2)
    print(f"\nMemoryPolicy reserved {len(memory_policy.reserved_regions)}"
          f" region(s); arbiter allocations:")
    for base, last, note in arbiter.allocations:
        print(f"  ${base:04X}-${last:04X}  {note}")

    host_bytes = WIKI_HOST.encode("ascii")
    path_bytes = WIKI_PATH.encode("ascii")
    routine_bytes = build_wiki_routine(
        labels,
        routine_addr=routine_addr,
        host_str_addr=host_str_addr,
        path_str_addr=path_str_addr,
        sentinel_addr=sentinel_addr,
        progress_addr=progress_addr,
        carry_flag_addr=carry_flag_addr,
        host_len=len(host_bytes),
        path_len=len(path_bytes),
        port=WIKI_PORT,
    )
    print(f"\nTarget          : https://{WIKI_HOST}{WIKI_PATH}")
    print(f"Routine size    : {len(routine_bytes)} bytes @ ${routine_addr:04X}")
    print(f"C64_INIT_WAIT   : {init_wait:.0f} s; sentinel budget "
          f"{WIKI_TIMEOUT:.0f} s (x{_TIMEOUT_SCALE:.0f} at {TURBO_MHZ} MHz)")

    prg = PRG_PATH.read_bytes()

    lock = DeviceLock(HOST)
    try:
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 2
    print(f"Acquired DeviceLock({HOST}); holder info: {lock.read_info()!r}")

    removed = _prune_old_run_dirs(UCI_DEBUG_BASE_DIR, UCI_DEBUG_KEEP)
    for d in removed:
        print(f"Pruning old debug artifacts: {d}")
    run_dir = _create_run_dir(UCI_DEBUG_BASE_DIR)
    print(f"Debug artifacts dir: {run_dir}")

    client: Ultimate64Client | None = None
    uci_enabled = False
    outcome = "UNKNOWN"
    exit_code = 1
    viewer_live = False
    run_start = time.time()
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        transport = Ultimate64Transport(host=HOST, timeout=15.0, client=client)
        transport.memory_policy = memory_policy

        print("Enabling UCI...")
        enable_uci(client)
        uci_enabled = True

        # Userspace /Temp GC (fw <= 3.14d writemem attachment leak).
        gc_temp(HOST)

        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            print(f"[fatal] runner wedged at {HOST}: {exc}", file=sys.stderr)
            print("[fatal] supervisor: investigate / authorize recover()",
                  file=sys.stderr)
            return 3

        # REU to (Enabled, 16 MB) — required, see header. Before reset,
        # like every config write in this rig.
        ensure_reu_16mb(client)

        # Presence/profile preflight kept too (issue #97 pattern).
        try:
            preflight_reu(client, LABELS_PATH)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4

        # Turbo BEFORE reset, read-skip-write (rig_https_live pattern).
        try:
            cat = client.get_config_category(CAT_U64_SPECIFIC)
            inner = cat.get(CAT_U64_SPECIFIC, cat)
            cur_speed = inner.get("CPU Speed")
            cur_turbo = inner.get("Turbo Control")
        except Exception as exc:
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

        print("Sending 'Q' to exit PRG main_loop...")
        send_text(transport, "q\r")
        time.sleep(2.0 * _TIMEOUT_SCALE)

        # DMA-write routine + data
        CHUNK = 64
        for i in range(0, len(routine_bytes), CHUNK):
            transport.write_memory(routine_addr + i,
                                   routine_bytes[i:i + CHUNK])
        transport.write_memory(host_str_addr,
                               (host_bytes + b"\x00").ljust(64, b"\x00"))
        transport.write_memory(path_str_addr,
                               (path_bytes + b"\x00").ljust(128, b"\x00"))
        transport.write_memory(marker_base, bytes(16))

        # Arm the REU body sink explicitly. The HTTPS_BODY_TO_REU build
        # sets http_body_sink=1 in do_https_get (the menu 'G' path), but
        # this trampoline JSRs http_get directly and never crosses it —
        # without this poke the body would not be sunk (lane E contract:
        # poking the exported flag by DMA before http_get is supported).
        transport.write_memory(labels["http_body_sink"], b"\x01")
        print("Armed http_body_sink=1 (trampoline bypasses do_https_get)")

        sys_line = f"sys{routine_addr}\r"
        print(f"Triggering: {sys_line.strip()}")
        send_text(transport, sys_line)

        # --- Poll sentinel + body progress ------------------------------- #
        body_total_addr = labels["http_body_total"]
        deadline = time.time() + WIKI_TIMEOUT
        start = time.time()
        last_progress = -1
        last_print = 0.0
        last_body_total = 0
        sentinel_seen = False
        phase_timing = os.environ.get("PHASE_TIMING", "0") == "1"
        phase_log: list[tuple[str, float]] = []
        cur_phase = None
        while time.time() < deadline:
            time.sleep(POLL_INTERVAL)
            blob = transport.read_memory(sentinel_addr, 2)
            sentinel, progress = blob[0], blob[1]
            bt = transport.read_memory(body_total_addr, 3)
            body_total = bt[0] | (bt[1] << 8) | (bt[2] << 16)
            now = time.time()
            if progress != last_progress:
                print(f"  [{now - start:6.1f}s] progress=0x{progress:02X}")
                last_progress = progress
                last_print = now
            elif now - last_print >= PROGRESS_PRINT_INTERVAL:
                rate = ((body_total - last_body_total)
                        / max(now - last_print, 1e-9))
                print(f"  [{now - start:6.1f}s] http_body_total="
                      f"{body_total:,} B ({rate:,.0f} B/s)")
                last_print = now
                last_body_total = body_total
            if phase_timing:
                scr = _decode_screen_ram(
                    bytes(transport.read_memory(0x0400, 1000)))
                phase = _current_phase(scr)
                if cur_phase is None:
                    cur_phase = phase
                elif phase != cur_phase:
                    cur_phase = phase
                    phase_log.append((phase, now - start))
                    print(f"  phase +{phase_log[-1][1]:7.1f}s  {phase}")
            if sentinel == SENTINEL_VALUE:
                print(f"  sentinel set after {now - start:.1f}s — "
                      "routine complete")
                sentinel_seen = True
                break

        if phase_timing and phase_log:
            table = _format_phase_log(phase_log)
            print("\n=== Phase timing ===")
            print(table)
            try:
                (run_dir / "phase_timing.txt").write_text(table + "\n")
            except Exception as exc:
                print(f"  (could not write phase_timing.txt: {exc})")

        # --- Read results (all DMA reads — safe even with viewer live) --- #
        carry = transport.read_memory(carry_flag_addr, 1)[0] & 0x01
        status_raw = transport.read_memory(labels["http_status"], 2)
        http_status = status_raw[0] | (status_raw[1] << 8)
        bt = transport.read_memory(body_total_addr, 3)
        body_total = bt[0] | (bt[1] << 8) | (bt[2] << 16)
        prefix = bytes(transport.read_memory(labels["http_resp_buf"],
                                             RESP_PREFIX_BYTES))
        print(f"\nhttp_get carry  = {carry} (0=success, 1=failure)")
        print(f"http_status     = {http_status}")
        print(f"http_body_total = {body_total:,} bytes")
        print(f"prefix          = {prefix[:80]!r}")

        try:
            _dump_diag(transport, labels)
            _dump_ring(transport, labels, run_dir)
            _dump_tls_state_snapshot(transport, labels, run_dir)
            (run_dir / "resp_prefix.bin").write_bytes(prefix)
            print(f"  snapshots -> {run_dir}")
        except Exception as exc:
            print(f"WARNING: snapshot dump failed: {exc}")

        if not sentinel_seen:
            print(f"\nFAIL: sentinel not set within {WIKI_TIMEOUT:.0f}s "
                  f"(progress=0x{last_progress:02X}, "
                  f"http_body_total={body_total:,})", file=sys.stderr)
            outcome = "TIMEOUT"
            return 1
        if carry != 0:
            print("\nFAIL: http_get returned C=1 — TLS handshake or HTTP "
                  "exchange failed (see tls_state_dump.json)",
                  file=sys.stderr)
            outcome = "FAIL"
            return 1

        # --- Host-side reference fetch + comparison ---------------------- #
        ref = None
        for attempt in (1, 2):
            try:
                print(f"\nReference fetch (attempt {attempt}): "
                      f"https://{WIKI_HOST}{WIKI_PATH}")
                ref = fetch_reference(WIKI_HOST, WIKI_PATH, WIKI_PORT)
                print(f"  status={ref['status']} framing={ref['framing']} "
                      f"body={len(ref['body']):,} B "
                      f"type={ref['content_type']}")
                (run_dir / "reference_body.bin").write_bytes(ref["body"])
                break
            except Exception as exc:
                print(f"  reference fetch failed: {exc}")
                ref = None
        if ref is not None and ref["status"] != EXPECT_STATUS:
            print(f"  WARNING: reference status {ref['status']} != "
                  f"{EXPECT_STATUS}; treating reference as unusable")
            ref = None

        verdict, problems, warnings = verify_against_reference(
            http_status, body_total, prefix, ref)
        for w in warnings:
            print(f"\nWARN: {w}")
        if verdict == "FAIL":
            print(f"\nFAIL against {WIKI_HOST}:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            outcome = "FAIL"
            return 1

        outcome = verdict            # PASS or WARN
        exit_code = 0
        viewer_live = True
        print(f"\n{verdict}: {body_total:,} article bytes sunk to REU "
              f"$10:0000, http_status={http_status}, prefix verified "
              f"against the live article.")
        print("\nviewer live on device; scroll with CRSR/SPACE/F1/HOME, "
              "Q to quit")
        print("NOTE: the machine is NOT reset and UCI stays enabled. The "
              "DeviceLock is released on exit — any queued harness job "
              "will grab the device and reset it, ending the viewer "
              "session. Hold other device work while playing.")
        return 0

    finally:
        try:
            _write_run_info(
                run_dir / "run_info.txt",
                outcome=outcome,
                duration=time.time() - run_start,
                exit_code=exit_code,
                extra={
                    "target": f"{WIKI_HOST}{WIKI_PATH}",
                    "turbo_mhz": TURBO_MHZ,
                    "host": HOST,
                    "viewer_live": viewer_live,
                },
            )
        except Exception as exc:
            print(f"WARNING: run_info write failed: {exc}")
        print(f"\nDebug artifacts: {run_dir}")

        if viewer_live:
            # Leave the machine exactly as-is for the human.
            pass
        elif uci_enabled and client is not None:
            print("\nDisabling UCI...")
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


# --------------------------------------------------------------------------- #
# Offline structural self-check — no hardware, no DeviceLock                  #
# --------------------------------------------------------------------------- #

def _selfcheck() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        status = "ok" if cond else "FAIL"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
        if not cond:
            failures.append(name)

    print("rig_https_wiki selfcheck (offline unless noted)")

    # 1) env handling
    check("WIKI_HOST default/env",
          WIKI_HOST == os.environ.get("WIKI_HOST", "en.wikipedia.org"))
    check("WIKI_PATH default has action=raw",
          "action=raw" in os.environ.get("WIKI_PATH", WIKI_PATH))
    check("timeout scale >= 1", _TIMEOUT_SCALE >= 1.0,
          f"TURBO_MHZ={TURBO_MHZ} -> x{_TIMEOUT_SCALE:g}")
    check("sentinel budget scaled", WIKI_TIMEOUT >= 600.0 or
          "WIKI_TIMEOUT" in os.environ, f"{WIKI_TIMEOUT:.0f}s")

    # 2) trampoline structure against synthetic labels
    fake_labels = {
        "http_get": 0x6123, "http_host_ptr": 0xA801, "http_host_len": 0xA803,
        "http_path_ptr": 0xA804, "http_path_len": 0xA806,
        "http_port": 0xA807, "net_init": 0x2001,
        "tcp_recv_head": 0xA810, "tcp_recv_tail": 0xA812,
        "viewer_enter": 0x7C40,
    }
    addrs = dict(routine_addr=0x3C00, host_str_addr=0x3D00,
                 path_str_addr=0x3D40, sentinel_addr=0x3DC0,
                 progress_addr=0x3DC1, carry_flag_addr=0x3DC2)
    path = "/w/index.php?title=Commodore_64&action=raw"
    code = build_wiki_routine(fake_labels, **addrs,
                              host_len=len("en.wikipedia.org"),
                              path_len=len(path), port=443)
    check("banks ROM out first",
          code[:8] == bytes([0xAD, 0x01, 0x00, 0x29, 0xFE, 0x8D, 0x01, 0x00]))
    jsr_http_get = bytes([0x20, 0x23, 0x61])
    check("JSR http_get present", jsr_http_get in code)
    check("PHP/PLA carry latch after http_get",
          code[code.index(jsr_http_get) + 3:
               code.index(jsr_http_get) + 5] == b"\x08\x68")
    check("path_len baked in",
          bytes([0xA9, len(path), 0x8D, 0x06, 0xA8]) in code)
    check("port 443 stored LE",
          bytes([0xA9, 443 & 0xFF, 0x8D, 0x07, 0xA8, 0xA9, 443 >> 8]) in code)
    check("sentinel value written",
          bytes([0xA9, SENTINEL_VALUE]) in code)
    # Conditional viewer entry: LDA carry / AND #1 / BNE +3 / JSR viewer
    cond = bytes([0xAD, 0xC2, 0x3D, 0x29, 0x01, 0xD0, 0x03,
                  0x20, 0x40, 0x7C])
    check("carry-gated JSR viewer_enter", cond in code)
    check("viewer JSR after sentinel write",
          code.index(cond) > code.index(bytes([0xA9, SENTINEL_VALUE])))
    park = addrs["routine_addr"] + len(code) - 3
    check("parks with JMP self (also the BNE target)",
          code[-3:] == bytes([0x4C, park & 0xFF, (park >> 8) & 0xFF]))
    check("BNE target is the park JMP",
          code.index(cond) + len(cond) == len(code) - 3)
    check("routine fits its 256 B slot", len(code) <= 256,
          f"{len(code)} bytes")

    # 3) guards
    for kwargs, name in (
        (dict(host_len=64, path_len=1), "host_len > 63 rejected"),
        (dict(host_len=10, path_len=129), "path_len > 128 rejected"),
        (dict(host_len=10, path_len=0), "path_len 0 rejected"),
    ):
        try:
            build_wiki_routine(fake_labels, **addrs, port=443, **kwargs)
            check(name, False)
        except ValueError:
            check(name, True)

    # 4) verification logic (synthetic)
    ref = {"status": 200, "framing": "chunked", "content_length": None,
           "content_type": "text/x-wiki", "body": b"A" * 1000}
    v, p, w = verify_against_reference(200, 1000, b"A" * 512, ref, 200)
    check("exact match -> PASS", v == "PASS" and not p and not w)
    v, p, w = verify_against_reference(200, 998, b"A" * 512, ref, 200)
    check("size drift + prefix match -> WARN", v == "WARN" and w and not p)
    v, p, w = verify_against_reference(200, 1000, b"B" * 512, ref, 200)
    check("prefix mismatch -> FAIL", v == "FAIL")
    v, p, w = verify_against_reference(403, 126, b"A" * 126, ref, 200)
    check("403 -> FAIL with UA hint", v == "FAIL" and "User-Agent" in p[0])
    v, p, w = verify_against_reference(200, 1000, b"A" * 512, None, 200)
    check("no reference -> FAIL (unverified is not a pass)", v == "FAIL")

    # 5) de-chunker
    raw = b"5\r\nHELLO\r\n6;ext=1\r\n WORLD\r\n0\r\n\r\n"
    check("de-chunker strips framing", _dechunk(raw) == b"HELLO WORLD")

    # 6) live reference fetch (real Wikipedia; skippable)
    if os.environ.get("WIKI_SELFCHECK_OFFLINE", "0") == "1":
        print("  (WIKI_SELFCHECK_OFFLINE=1 — live reference fetch skipped)")
    else:
        try:
            ref = fetch_reference(WIKI_HOST, WIKI_PATH, WIKI_PORT)
            check("live reference fetch returns 200",
                  ref["status"] == 200,
                  f"framing={ref['framing']} body={len(ref['body']):,} B")
            check("live body non-trivial", len(ref["body"]) > 50_000,
                  "article should be ~125 KB of wikitext")
        except Exception as exc:
            check("live reference fetch", False, f"{exc}")

    # 7) local build, if present (informational for contract labels)
    if LABELS_PATH.is_file():
        labels = _load_labels()
        base_missing = [n for n in BASE_LABELS if n not in labels]
        check("base labels present in local build", not base_missing,
              f"missing: {base_missing}" if base_missing else str(LABELS_PATH))
        contract_missing = [n for n in CONTRACT_LABELS if n not in labels]
        if contract_missing:
            print(f"  (info) contract labels not in local build yet "
                  f"(6502 lanes pending): {contract_missing}")
        else:
            print("  (info) local build carries the full wiki contract")
            print(f"  (info) init wait would default to "
                  f"{default_init_wait(labels):.0f} s")
    else:
        print(f"  (no {LABELS_PATH} — local-build check skipped)")

    if failures:
        print(f"\nSELFCHECK FAIL: {len(failures)} check(s): {failures}")
        return 1
    print("\nSELFCHECK PASS")
    return 0


if __name__ == "__main__":
    if "--selfcheck" in sys.argv[1:]:
        raise SystemExit(_selfcheck())
    raise SystemExit(main())
