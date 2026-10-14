#!/usr/bin/env python3
"""BACKEND=uci-m3 hardware checks the banner rig cannot make.

`rig_https_banner.py` already runs an M3 build end to end (typed target,
HTTP status, completeness by the body's own framing). This rig adds the two
verdicts that need more than one image or a failure:

  refuse HOST CODE   The firmware must REFUSE the Open (e.g. 94 for a name
                     mismatch, 93 for an untrusted chain), and the client
                     must surface it: "TLS HANDSHAKE FAILED" plus the
                     firmware's own status line on screen, nothing sent,
                     the handle not held (m3_owned = 0), net_last_error
                     $8D UCI_ERR_OPEN_REFUSED.
  ab HOST PATH PRG_B LABELS_B
                     A/B oracle: the same URL through this build (A, the
                     M3 PRG in build/) and through B (a 6510-TLS UCI PRG).
                     Both must be HTTP 200 with the same body length; the
                     CRC-32 of the bytes both keep in http_resp_buf (the
                     whole body when it is <= 512 B, else its first 512 B)
                     must match.
  timed SCHEDULE NAME=DIR [NAME=DIR ...]
                     Timed A/B of M3 builds (each DIR holds c64-https.prg,
                     labels.txt and flags.stamp of a `make BACKEND=uci-m3
                     HTTPS_BODY_TO_REU=1` link), e.g. M3_READ_FENCE=1 vs the
                     default. SCHEDULE is PAGE:NAMES[,PAGE:NAMES], e.g.
                     small:FSSFFS,large:FSSFFS (ABBA order); PAGE is small
                     (en.wikipedia.org /robots.txt) or large (/wiki/
                     Commodore_64). Per attempt: reset, verified load, 'I',
                     then the clock starts at 'G' and stops when the REU
                     viewer opens (the whole body sunk); 'Q' closes; the
                     body is read back out of REU $10:0000 and compared with
                     a host fetch made just before (curl, the client's UA).
                     A dynamic page that differs only in per-render metadata
                     lines is reported as such, never as equal. An M3_TRACE
                     build's per-net_poll records are read before 'Q' and
                     summarised. TURBO_OFF=1 runs with turbo off (1 MHz).
                     One JSON line per attempt to $UCI_DEBUG_DIR/<run>/
                     timed.jsonl. Exit 1 if any attempt is not complete.

Both drive the MENU the way an operator does ('I', 'G', the typed target),
take the harness DeviceLock, set 48 MHz and the REU through
_device_prep.prepare_device, verify the PRG load (#199), and let every fetch
reach "CONNECTION CLOSED" before the lock is released: a reset over a live
firmware socket poisons the lease (CLAUDE.md "Device gotchas").

    U64_HOST=10.43.23.81 tools/uci/rig_https_m3.py refuse wrong.host.badssl.com 94
    U64_HOST=10.43.23.81 tools/uci/rig_https_m3.py ab en.wikipedia.org / B.prg B.labels
    U64_HOST=10.43.23.81 tools/uci/rig_https_m3.py timed small:FSSF F=bf S=bs

Exit: 0 pass, 1 fail, 2 fatal, 3 DeviceLock timeout, 4 device prep / load.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import zlib
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import disable_uci, enable_uci

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _device_lock_helper import LockTimeoutConfigError, acquire_device_lock  # noqa: E402
from _device_prep import DevicePrepError, prepare_device  # noqa: E402
from _prg_load import PrgLoadError, load_verified_and_run  # noqa: E402
from _reu_preflight import (  # noqa: E402
    ReuPreflightError, detect_crypto_profile, preflight_reu)
from boot_check import decode_screen, screen_text  # noqa: E402
from _petscii_keys import push_keys, target_keys  # noqa: E402
from _rig_lifecycle import guard_socket_teardown  # noqa: E402
from rig_https_local import _create_run_dir  # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO = Path(__file__).resolve().parents[2]
PRG_A = REPO / "build" / "c64-https.prg"
LABELS_A = REPO / "build" / "labels.txt"
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
TURBO_OFF = os.environ.get("TURBO_OFF") == "1"   # timed: prep, then turbo off
INIT_WAIT = float(os.environ.get("C64_INIT_WAIT", "120"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "900"))
RUN_DIR = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug"))


UCI_ERR_OPEN_REFUSED = 0x8D     # c64-wireguard's code, mirrored (uci_errors.inc)


class Fail(Exception):
    pass


def labels(path: Path) -> dict[str, int]:
    out = {}
    for line in path.read_text().splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == "al" and p[2].startswith("."):
            out[p[2][1:]] = int(p[1].split(":")[-1], 16)
    return out


def screen(client) -> tuple[list[str], str]:
    lines = decode_screen(bytes(client.read_mem(0x0400, 1000)))
    return lines, screen_text(lines)


def wait_for(client, markers, budget: float):
    """Return the first of `markers` on screen, or None after `budget` s."""
    end = time.monotonic() + budget
    while True:
        lines, text = screen(client)
        for m in markers:
            if m in text:
                return m, lines
        if time.monotonic() > end:
            return None, lines
        time.sleep(1.0)


def wait_after(client, anchor, markers, budget: float):
    """Like wait_for, but only counts text after the LAST `anchor` on the
    screen: an earlier step's lines (CONNECTION CLOSED, DHCP OK) are still
    there. Nothing counts until `anchor` is on screen, so the caller must
    know it will be (or wait_for it first). `markers` are regular
    expressions; the one that matched is returned."""
    end = time.monotonic() + budget
    while True:
        lines, text = screen(client)
        tail = text[text.rfind(anchor):] if anchor in text else ""
        for m in markers:
            if re.search(m, tail):
                return m, lines
        if time.monotonic() > end:
            return None, lines
        time.sleep(1.0)


#: The end of do_net_init: the whole address is printed (then CR, RTS).
DHCP_DONE = r"DHCP OK - IP: \d+\.\d+\.\d+\.\d+"


def press_init(client) -> None:
    """'I', then wait for THAT init's verdict.

    The boot runs the same init before it prints the menu, so "DHCP OK" is
    already on screen when 'I' is pressed; waiting for it returned at once
    and let 'G' land while the re-init was still running. Only text after
    the menu line belongs to this 'I'. The menu is on screen when 'I' is
    pressed (the caller waited for it), with a blank row under it, so at
    row 22 at the lowest; a successful re-init prints four rows, so the
    menu is still there when DHCP OK is. (A failure long enough to scroll
    it off ends in a timeout: still a FAIL.) The address is matched while
    it may still be printing, so the screen must then read the same twice.
    """
    client.send_text("I", finish_with_return=False)
    m, lines = wait_after(client, "Q=QUIT", [DHCP_DONE, "FAILED"], 120)
    if m != DHCP_DONE:
        dump(lines, "init")
        raise Fail("network init: %s" % m)
    for _ in range(10):
        time.sleep(1.0)
        again, _text = screen(client)
        if again == lines:
            return
        lines = again
    dump(lines, "init")
    raise Fail("the screen kept changing after DHCP OK")


def dump(lines, title):
    print(f"--- {title} ---")
    for i, line in enumerate(lines):
        if line.strip():
            print(f"{i:02d}: {line}")
    print("--- end ---")


def le(client, addr, n):
    return int.from_bytes(bytes(client.read_mem(addr, n)), "little")


def run_fetch(client, prg_path: Path, host: str, path: str):
    """Boot `prg_path`, 'I', 'G', type the target; wait for the end.

    Returns (the screen marker that ended it, the final screen lines).
    """
    client.reset()
    time.sleep(2.5)
    load_verified_and_run(client, prg_path.read_bytes())
    m, lines = wait_for(client, ["Q=QUIT"], INIT_WAIT)
    if not m:
        dump(lines, "boot")
        raise Fail("menu never appeared")
    press_init(client)
    client.send_text("G", finish_with_return=False)
    push_keys(client, target_keys(f"{host}\r{path}\r"))
    m, lines = wait_for(client, ENDS, FETCH_TIMEOUT)
    if m == "TLS HANDSHAKE FAILED":
        time.sleep(2.0)                     # let the status line print
        lines, _ = screen(client)
    return m, lines


#: The screen lines that end a fetch. The first two leave no socket open:
#: "CONNECTION CLOSED" follows net_tcp_close, and a refused Open holds none.
ENDS = ["CONNECTION CLOSED", "TLS HANDSHAKE FAILED", "NOT RESPONDING",
        "INVALID TARGET"]
SETTLED = ("CONNECTION CLOSED", "TLS HANDSHAKE FAILED", "INVALID TARGET")


def body_facts(client, lab):
    status = le(client, lab["http_status"], 2)
    total = le(client, lab["http_body_total"], 3)
    rlen = le(client, lab["http_resp_len"], 2)
    keep = bytes(client.read_mem(lab["http_resp_buf"], min(rlen, 512)))
    return status, total, keep


def verdict_refuse(client, lab, host, code, m, lines) -> None:
    dump(lines, "final screen")
    if m != "TLS HANDSHAKE FAILED":
        raise Fail("expected the Open to be refused; screen ended with %r" % m)
    n = bytes(client.read_mem(lab["m3_status_len"], 1))[0]
    line = bytes(client.read_mem(lab["m3_status"], n)).decode("ascii", "replace")
    owned = bytes(client.read_mem(lab["m3_owned"], 1))[0]
    err = bytes(client.read_mem(lab["net_last_error"], 1))[0]
    print(f"  firmware status line: {line!r}")
    print(f"  m3_owned={owned}  net_last_error=${err:02X}")
    if err != UCI_ERR_OPEN_REFUSED:
        raise Fail(f"net_last_error ${err:02X}, expected $8D UCI_ERR_OPEN_REFUSED")
    shown = bool(line) and any(line[:20].upper() in ln.upper() for ln in lines)
    if not line.startswith(code + ","):
        raise Fail(f"refused with {line!r}, expected code {code}")
    if not shown:
        raise Fail("the refusal's status line is not on the screen")
    if owned:
        raise Fail("a handle is held after a refused Open")
    if "REQUEST SENT" in screen_text(lines):
        raise Fail("a request was sent over a refused connection")
    print(f"PASS: the engine refused {host} with {code} and the client said so")


def verdict_ab(rows) -> None:
    (_, sa, ta, ka, ca, _), (_, sb, tb, kb, cb, _) = rows
    if sa != 200 or sb != 200:
        raise Fail(f"HTTP status A={sa} B={sb}")
    if ta != tb:
        raise Fail(f"body length A={ta:,} B={tb:,}")
    if (ka, ca) != (kb, cb):
        raise Fail(f"kept bytes differ: A {ka} B / {ca:08X}, B {kb} B / {cb:08X}")
    whole = "the whole body" if ka == ta else f"the first {ka} B"
    print(f"PASS: same status, same length ({ta:,} B), same CRC-32 over {whole}")


# --- timed ------------------------------------------------------------------

PAGES = {"small": ("en.wikipedia.org", "/robots.txt"),
         "large": ("en.wikipedia.org", "/wiki/Commodore_64")}
PAGE_BUDGET = {"small": 900.0, "large": 3600.0}
UA = "c64-https/0.1"                    # src/http.s's User-Agent
#: The REU viewer's status line: OOOOOO/TTTTTT (decode_screen lowercases).
VIEWER = re.compile(r"^\s*[0-9a-f]{6}/[0-9a-f]{6}", re.I)
REU_BODY = 0x100000                     # HTTPS_BODY_TO_REU's region
#: After a reset (BASIC idle, no program), REU -> C64 staging for readback.
STAGE = 0x0800
STAGE_LEN = 0x8000
#: MediaWiki per-render values. A difference counts as metadata only if one
#: of these keys is in the 120 bytes before it, on the same line.
RENDER_KEYS = re.compile(
    rb"wgRequestId|wgBackendResponseTime|wgHostname|wgPageParseReport|"
    rb"cputime|walltime|timestamp|\"ttl\"|transientcontent|cachereport|"
    rb"limitreport|timingprofile|ppvisitednodes|postexpandincludesize|"
    rb"Parsed by|Cached time|Cache expiry|CPU time usage|Real time usage|"
    rb"Saved in parser cache|Render ID|Transclusion expansion time report|"
    rb"Rendering was triggered")
TOKEN = re.compile(rb"\w+|\W")


def host_reference(host: str, path: str) -> bytes | None:
    r = subprocess.run(["curl", "-s", "--http1.1", "-A", UA, "--max-time",
                        "60", f"https://{host}{path}"], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def reu_read(client, off: int, n: int) -> bytes:
    """REU [off, off+n) through STAGE, a chunk at a time (C64 reset first)."""
    out = bytearray()
    for o in range(0, n, STAGE_LEN):
        k = min(STAGE_LEN, n - o)
        a = off + o
        client.write_mem(0xDF02, bytes([STAGE & 0xFF, STAGE >> 8, a & 0xFF,
                                        (a >> 8) & 0xFF, (a >> 16) & 0xFF,
                                        k & 0xFF, (k >> 8) & 0xFF, 0, 0]))
        client.write_mem(0xDF01, bytes([0x91]))     # execute, REU -> C64
        time.sleep(0.05)
        out += bytes(client.read_mem(STAGE, k))
    return bytes(out)


#: MediaWiki's parser reports: HTML comments re-written on every render.
REPORT_COMMENT = re.compile(rb"<!--(?:(?!-->).)*?(?:NewPP limit report|"
                            rb"Transclusion expansion time report|"
                            rb"Saved in parser cache|cache key).*?-->", re.S)


def report_spans(body: bytes) -> list[tuple[int, int]]:
    """REPORT_COMMENT matches, plus the "wgPageParseReport":{...} object
    (braces matched; its JSON holds no brace inside a string here)."""
    spans = [(m.start(), m.end()) for m in REPORT_COMMENT.finditer(body)]
    for m in re.finditer(rb'"wgPageParseReport":\{', body):
        depth, i = 0, m.end() - 1
        while i < len(body):
            depth += {123: 1, 125: -1}.get(body[i], 0)
            i += 1
            if depth == 0:
                break
        spans.append((m.start(), i))
    return spans


def body_oracle(body: bytes, ref: bytes | None) -> tuple[str, dict]:
    """("equal" | "metadata-only" | "DIFFERENT" | "no-reference", facts).

    "metadata-only": a line diff, then a token diff inside each changed
    line; every changed token run either has a RENDER_KEYS key within the
    120 bytes before it on its line, or lies inside a parser report
    (report_spans); and no line was added or dropped on its own.
    That is two renders of one revision, not a short or damaged body."""
    facts = {"sha256": hashlib.sha256(body).hexdigest(),
             "crc32": f"{zlib.crc32(body) & 0xFFFFFFFF:08X}", "len": len(body)}
    if ref is None:
        return "no-reference", facts
    facts.update(ref_len=len(ref), ref_sha256=hashlib.sha256(ref).hexdigest())
    if body == ref:
        return "equal", facts
    spans = report_spans(body)
    a, b = body.split(b"\n"), ref.split(b"\n")
    starts = [0]
    for ln in a:
        starts.append(starts[-1] + len(ln) + 1)
    runs, unexplained = 0, []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
            None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if tag != "replace" or i2 - i1 != j2 - j1:
            unexplained.append(f"lines {i1}-{i2} vs {j1}-{j2}: {tag}")
            continue
        for li, (la, lb) in enumerate(zip(a[i1:i2], b[j1:j2]), i1):
            ta, tb = TOKEN.findall(la), TOKEN.findall(lb)
            pos = [0]
            for t in ta:
                pos.append(pos[-1] + len(t))
            for t2, k1, k2, _, _ in difflib.SequenceMatcher(
                    None, ta, tb, autojunk=False).get_opcodes():
                if t2 == "equal":
                    continue
                runs += 1
                at = pos[k1]
                absolute = starts[li] + at
                if RENDER_KEYS.search(la[max(0, at - 120):at]):
                    continue
                if any(lo <= absolute < hi for lo, hi in spans):
                    continue
                unexplained.append(la[max(0, at - 60):at + 60].decode("latin-1"))
    facts.update(diff_runs=runs, unexplained=len(unexplained),
                 first_unexplained=unexplained[:3])
    return ("metadata-only" if runs and not unexplained else "DIFFERENT"), facts


def read_trace(client, lab) -> dict | None:
    """An M3_TRACE build's records (src/net/uci-m3/m3.inc, "Timing trace")."""
    if "m3_tr_count" not in lab:
        return None
    unit = 10227                        # M3_UNIT_CYCLES
    n = le(client, lab["m3_tr_n"], 2)
    raw = bytes(client.read_mem(0x6000, n * 12)) if n else b""

    def ticks(b, o):
        dtb = b[o] | b[o + 1] << 8
        dta = b[o + 2] | b[o + 3] << 8
        return dtb * unit + (dta - 0x10000 if dta & 0x8000 else dta)
    recs = []
    for i in range(n):
        r = raw[12 * i:12 * i + 12]
        recs.append({"rtt": ticks(r, 0) if any(r[0:4]) else None,
                     "total": ticks(r, 4), "bytes": r[8] | r[9] << 8,
                     "result": r[10], "post": r[11]})
    return {"count": le(client, lab["m3_tr_count"], 2), "kept": n,
            "pushes": le(client, lab["m3_tr_pushes"], 2),
            "bit3": le(client, lab["m3_tr_bit3"], 2),
            "or": bytes(client.read_mem(lab["m3_tr_or"], 1))[0],
            "records": recs}


def _dist(xs):
    xs = sorted(xs)
    if not xs:
        return None
    return {"n": len(xs), "min": xs[0], "median": xs[len(xs) // 2],
            "max": xs[-1]}


def summarise_trace(tr: dict) -> dict:
    """CIA ticks are PHI2 cycles at the real bus clock (~1.0227 MHz NTSC):
    ms = ticks / 1022.7. Distributions over READs that returned data, over
    idle READs, and per byte."""
    ms = lambda t: round(t / 1022.7, 3)     # noqa: E731
    data = [r for r in tr["records"] if r["result"] == 0 and r["rtt"] is not None]
    idle = [r for r in tr["records"] if r["result"] == 1 and r["rtt"] is not None]
    return {
        "net_poll_calls": tr["count"], "records_kept": tr["kept"],
        "pushes": tr["pushes"], "pushes_with_bit3": tr["bit3"],
        "post_push_status_or": f"${tr['or']:02X}",
        "post_push_status_values": sorted({f"${r['post']:02X}" for r in tr["records"] if r["rtt"] is not None}),
        "data_reads": len(data), "idle_reads": len(idle),
        "data_rtt_ms": _dist([ms(r["rtt"]) for r in data]),
        "data_total_ms": _dist([ms(r["total"]) for r in data]),
        "idle_rtt_ms": _dist([ms(r["rtt"]) for r in idle]),
        "bytes_per_data_read": _dist([r["bytes"] for r in data]),
        "full_893_reads": sum(1 for r in data if r["bytes"] == 893),
    }


def timed_attempt(client, name, bdir: Path, page: str, run_dir: Path) -> dict:
    lab = labels(bdir / "labels.txt")
    host, path = PAGES[page]
    rec = {"arm": name, "dir": str(bdir), "page": page, "host": host,
           "path": path, "start": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "prg_sha256": hashlib.sha256((bdir / "c64-https.prg").read_bytes()).hexdigest()}
    ref = host_reference(host, path)
    client.reset()
    time.sleep(2.5)
    load_verified_and_run(client, (bdir / "c64-https.prg").read_bytes())
    m, lines = wait_for(client, ["Q=QUIT"], INIT_WAIT)
    if not m:
        dump(lines, "boot")
        raise Fail(f"{name}: menu never appeared")
    press_init(client)
    t0 = time.monotonic()
    client.send_text("G", finish_with_return=False)
    push_keys(client, target_keys(f"{host}\r{path}\r"))
    t_hs = None
    end = t0 + PAGE_BUDGET[page]
    while True:
        lines, text = screen(client)
        now = time.monotonic()
        if t_hs is None and "TLS HANDSHAKE OK" in text:
            t_hs = now
        if VIEWER.match(lines[0]):
            outcome = "VIEWER"
            break
        hit = [e for e in ENDS + ["BODY INCOMPLETE"] if e in text]
        if hit:
            outcome = hit[0]
            break
        if now > end:
            outcome = "TIMEOUT"
            break
        time.sleep(0.5)
    rec.update(outcome=outcome, t_body=round(time.monotonic() - t0, 2),
               t_handshake=round(t_hs - t0, 2) if t_hs else None)
    rec["http_status"] = le(client, lab["http_status"], 2)
    rec["body_total"] = le(client, lab["http_body_total"], 3)
    rec["net_last_error"] = f"${bytes(client.read_mem(lab['net_last_error'], 1))[0]:02X}"
    tr = read_trace(client, lab)
    if tr is not None:
        (run_dir / f"trace-{name}-{page}-{rec['start']}.json").write_text(json.dumps(tr))
        rec["trace"] = summarise_trace(tr)
    rec["screen_at_end"] = [x for x in lines if x.strip()]
    if outcome != "VIEWER":
        dump(lines, f"{name} final screen")
        rec["verdict"] = f"INCOMPLETE: {outcome}"
        if outcome not in SETTLED:
            guard_socket_teardown(client.read_mem, lab["net_tcp_state"],
                                  nudge=lambda: client.send_text("Q", finish_with_return=False))
        return rec
    client.send_text("Q", finish_with_return=False)
    m, lines = wait_for(client, ["CONNECTION CLOSED"], 60)
    if not m:
        dump(lines, f"{name} after Q")
        guard_socket_teardown(client.read_mem, lab["net_tcp_state"])
        raise Fail(f"{name}: no CONNECTION CLOSED after Q")
    client.reset()                      # the socket is closed: safe
    time.sleep(3.0)
    body = reu_read(client, REU_BODY, rec["body_total"]) if rec["body_total"] else b""
    (run_dir / f"body-{name}-{page}-{rec['start']}.bin").write_bytes(body)
    if ref is not None:
        (run_dir / f"ref-{page}-{rec['start']}.bin").write_bytes(ref)
    oracle, facts = body_oracle(body, ref)
    rec.update(oracle=oracle, body=facts)
    ok = rec["http_status"] == 200 and oracle in ("equal", "metadata-only")
    rec["verdict"] = "PASS" if ok else "FAIL"
    return rec


def run_timed(client, sched, arms, run_dir: Path) -> int:
    out = run_dir / "timed.jsonl"
    bad = 0
    for page, name in sched:
        print(f"=== {name} {page} {time.strftime('%H:%M:%S')}", flush=True)
        try:
            rec = timed_attempt(client, name, arms[name], page, run_dir)
        except BaseException:
            # #234: never leave this attempt's socket live behind the lock.
            lab = labels(arms[name] / "labels.txt")
            guard_socket_teardown(client.read_mem, lab["net_tcp_state"])
            raise
        rec["turbo_mhz"] = 1 if TURBO_OFF else TURBO_MHZ
        with out.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        short = {k: rec.get(k) for k in ("arm", "page", "verdict", "oracle",
                 "t_handshake", "t_body", "http_status", "body_total",
                 "net_last_error")}
        print("  " + json.dumps(short), flush=True)
        if "trace" in rec:
            print("  trace: " + json.dumps(rec["trace"]), flush=True)
        if rec["verdict"] != "PASS":
            bad += 1
            if rec["verdict"].startswith("INCOMPLETE"):
                print("stopping: an incomplete fetch leaves the device state unknown")
                break
    print(f"results: {out}")
    return 1 if bad else 0


def parse_timed(argv):
    sched = [(page, n) for item in argv[2].split(",")
             for page, names in [item.split(":")] for n in names]
    arms = {}
    for a in argv[3:]:
        n, d = a.split("=", 1)
        arms[n] = Path(d)
    for page, n in sched:
        if page not in PAGES or n not in arms:
            raise ValueError(f"schedule names {page}:{n}, not a page/arm")
    for n, d in arms.items():
        lab = labels(d / "labels.txt")
        if "m3_wedged" not in lab or "http_sink_full" not in lab:
            raise ValueError(f"{d} is not a BACKEND=uci-m3 HTTPS_BODY_TO_REU=1 build")
    return sched, arms


def main(argv) -> int:
    timed = len(argv) >= 4 and argv[1] == "timed"
    if timed:
        try:
            sched, arms = parse_timed(argv)
        except (ValueError, OSError) as exc:
            print(f"[fatal] {exc}", file=sys.stderr)
            return 2
        prep_labels = next(iter(arms.values())) / "labels.txt"
    elif (len(argv) < 2 or argv[1] not in ("refuse", "ab")
            or len(argv) != {"refuse": 4, "ab": 6}[argv[1]]):
        print(__doc__)
        return 2
    else:
        prep_labels = LABELS_A
    if not timed and (not PRG_A.is_file() or "m3_wedged" not in labels(LABELS_A)):
        print("[fatal] build/ is not a BACKEND=uci-m3 build", file=sys.stderr)
        return 2
    if timed:
        runs = []
    elif argv[1] == "refuse":
        host, path = argv[2], "/"
        runs = [("A (uci-m3)", PRG_A, LABELS_A)]
    else:
        host, path = argv[2], argv[3]
        runs = [("A (uci-m3)", PRG_A, LABELS_A),
                ("B (6510 TLS)", Path(argv[4]), Path(argv[5]))]
        # The device is prepared for A, which needs no REU (prep turns it
        # off), so B must need none either: a REU-profile or comb B would
        # spin. Refused rather than prepared twice.
        b_profile, why = detect_crypto_profile(argv[5])
        if b_profile != "onchip":
            print(f"[fatal] B must be an on-chip build (no REU); {argv[5]} "
                  f"is {b_profile!r} ({why})", file=sys.stderr)
            return 2
    lock = DeviceLock(HOST)
    try:
        acquire_device_lock(lock)
    except LockTimeoutConfigError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 3
    client = None
    fetch_in_flight = False
    tcp_addr = None
    try:
        client = Ultimate64Client(host=HOST, timeout=20.0)
        info = client.get_info()
        print(f"device: {info.get('product')} fw {info.get('firmware_version')} "
              f"git {info.get('git_commit_hash')} fpga {info.get('fpga_version')} "
              f"core {info.get('core_version')}")
        want_git = os.environ.get("M3_EXPECT_GIT")
        if want_git and info.get("git_commit_hash") != want_git:
            print(f"[fatal] firmware git {info.get('git_commit_hash')}, "
                  f"expected {want_git} (M3_EXPECT_GIT): not benching",
                  file=sys.stderr)
            return 2
        enable_uci(client)
        run_dir = _create_run_dir(RUN_DIR)
        print(f"run dir: {run_dir} (device_state.json)")
        try:
            prepare_device(client, prep_labels, turbo_mhz=TURBO_MHZ,
                           artifact_dir=run_dir)
        except DevicePrepError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        if timed and TURBO_OFF:                 # stock 1 MHz: turbo off
            from c64_test_harness.backends.ultimate64_helpers import set_turbo_mhz
            set_turbo_mhz(client, None)
            time.sleep(3.0)
            print("turbo: " + str(client.get_config_value(
                "U64 Specific Settings", "Turbo Control")))
        try:
            preflight_reu(client, prep_labels)  # the backstop behind the prep
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        if timed:
            (run_dir / "device_info.json").write_text(json.dumps(info))
            try:
                return run_timed(client, sched, arms, run_dir)
            except PrgLoadError as exc:
                print(f"[fatal] {exc}", file=sys.stderr)
                return 4
            except Fail as exc:
                print(f"FAIL: {exc}", file=sys.stderr)
                return 1
        rows = []
        try:
            for name, prg, lab_path in runs:
                lab = labels(lab_path)
                tcp_addr = lab["net_tcp_state"]
                t0 = time.monotonic()
                fetch_in_flight = True          # #234: a socket may be live
                m, lines = run_fetch(client, prg, host, path)
                if m in SETTLED:
                    fetch_in_flight = False
                took = time.monotonic() - t0
                if argv[1] == "refuse":
                    verdict_refuse(client, lab, host, argv[3], m, lines)
                    continue
                if m != "CONNECTION CLOSED":
                    dump(lines, f"{name} final screen")
                    raise Fail(f"{name}: fetch ended with {m!r}")
                status, total, keep = body_facts(client, lab)
                crc = zlib.crc32(keep) & 0xFFFFFFFF
                rows.append((name, status, total, len(keep), crc, took))
                print(f"  {name}: {prg.name}, HTTP {status}, body {total:,} B, "
                      f"CRC-32 of the first {len(keep)} B = {crc:08X}, {took:.0f} s")
            if rows:
                verdict_ab(rows)
        except PrgLoadError as exc:
            print(f"[fatal] {exc}", file=sys.stderr)
            return 4
        except Fail as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        return 0
    finally:
        if fetch_in_flight and client is not None:
            guard_socket_teardown(client.read_mem, tcp_addr)
        if client is not None:
            try:
                disable_uci(client)
            except Exception as exc:            # noqa: BLE001
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
