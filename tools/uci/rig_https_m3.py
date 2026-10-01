#!/usr/bin/env python3
"""BACKEND=uci-m3 hardware checks the banner rig cannot make.

`rig_https_banner.py` already runs an M3 build end to end (typed target,
HTTP status, completeness by the body's own framing). This rig adds the two
verdicts that need more than one image or a failure:

  refuse HOST CODE   The firmware must REFUSE the Open (e.g. 94 for a name
                     mismatch, 93 for an untrusted chain), and the client
                     must surface it: "TLS HANDSHAKE FAILED" plus the
                     firmware's own status line on screen, nothing sent,
                     the handle not held (m3_owned = 0).
  ab HOST PATH PRG_B LABELS_B
                     A/B oracle: the same URL through this build (A, the
                     M3 PRG in build/) and through B (a 6510-TLS UCI PRG).
                     Both must be HTTP 200 with the same body length; the
                     CRC-32 of the bytes both keep in http_resp_buf (the
                     whole body when it is <= 512 B, else its first 512 B)
                     must match.

Both drive the MENU the way an operator does ('I', 'G', the typed target),
take the harness DeviceLock, set 48 MHz and the REU through
_device_prep.prepare_device, verify the PRG load (#199), and let every fetch
reach "CONNECTION CLOSED" before the lock is released: a reset over a live
firmware socket poisons the lease (CLAUDE.md "Device gotchas").

    U64_HOST=10.43.23.81 tools/uci/rig_https_m3.py refuse wrong.host.badssl.com 94
    U64_HOST=10.43.23.81 tools/uci/rig_https_m3.py ab en.wikipedia.org / B.prg B.labels

Exit: 0 pass, 1 fail, 2 fatal, 3 DeviceLock timeout, 4 device prep / load.
"""
from __future__ import annotations

import os
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
from _reu_preflight import ReuPreflightError, preflight_reu  # noqa: E402
from boot_check import decode_screen, screen_text  # noqa: E402
from _petscii_keys import push_keys, target_keys  # noqa: E402
from _rig_lifecycle import guard_socket_teardown  # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO = Path(__file__).resolve().parents[2]
PRG_A = REPO / "build" / "c64-https.prg"
LABELS_A = REPO / "build" / "labels.txt"
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
INIT_WAIT = float(os.environ.get("C64_INIT_WAIT", "120"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "900"))
RUN_DIR = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug"))


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
    client.send_text("I", finish_with_return=False)
    m, lines = wait_for(client, ["DHCP OK", "FAILED"], 120)
    if m != "DHCP OK":
        dump(lines, "init")
        raise Fail("network init: %s" % m)
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
    print(f"  firmware status line: {line!r}")
    print(f"  m3_owned={owned}")
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


def main(argv) -> int:
    if len(argv) < 2 or argv[1] not in ("refuse", "ab"):
        print(__doc__)
        return 2
    if not PRG_A.is_file() or "m3_wedged" not in labels(LABELS_A):
        print("[fatal] build/ is not a BACKEND=uci-m3 build", file=sys.stderr)
        return 2
    if argv[1] == "refuse":
        host, path = argv[2], "/"
        runs = [("A (uci-m3)", PRG_A, LABELS_A)]
    else:
        host, path = argv[2], argv[3]
        runs = [("A (uci-m3)", PRG_A, LABELS_A),
                ("B (6510 TLS)", Path(argv[4]), Path(argv[5]))]
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
              f"git {info.get('git_commit_hash')} core {info.get('core_version')}")
        enable_uci(client)
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        try:
            prepare_device(client, LABELS_A, turbo_mhz=TURBO_MHZ,
                           artifact_dir=RUN_DIR)
        except DevicePrepError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        try:
            preflight_reu(client, LABELS_A)     # the backstop behind the prep
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4
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
