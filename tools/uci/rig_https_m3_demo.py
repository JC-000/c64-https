#!/usr/bin/env python3
"""The M3 demo disk, the way a user runs it: from the drive, not by DMA.

`make package-m3-demo` writes dist/m3-demo/c64-https-uci-m3-demo.d64. This
rig mounts THAT image on the Ultimate's drive A (device 8), types
LOAD"*",8,1 and RUN, and then drives the menu:

  1. 'I', then 'G' with RETURN, RETURN: the built-in default target
     (en.wikipedia.org /wiki/Commodore_64). It must end HTTP 200 with the
     body complete by its own framing (tools/http_body_checks.py).
  1b. 'G' with github.com /robots.txt: HTTP 200, complete (timed too).
  2. 'G' with a name the certificate does not carry (NEGATIVE_HOST, a
     nip.io name for a Wikipedia address): it must end "TLS HANDSHAKE
     FAILED" with the firmware's "94,..." line on screen, no handle held,
     net_last_error $8D UCI_ERR_OPEN_REFUSED.

The PRG on the disk must be the one build/labels.txt describes: the rig
reads the PRG back out of the .d64 with c1541 and refuses to run if it
differs from build/c64-https.prg (run it right after `make
package-m3-demo`, which leaves that build in build/).

Drive A's state is read first and restored at the end: our image removed
(and its /Temp upload deleted), the old image re-mounted by path when it had
one, the drive switched back off when it was off, and the result compared
with what was read. Device prep, the REU preflight, the DeviceLock, the
init wait and the refusal verdict are rig_https_m3.py's.

    U64_HOST=10.43.23.81 tools/uci/rig_https_m3_demo.py [path/to.d64]

C1541 overrides the c1541 binary, as in `make package-m3-demo`.

Exit: 0 pass, 1 fail, 2 fatal, 3 DeviceLock timeout, 4 device prep.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from ftplib import FTP, error_perm
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import disable_uci, enable_uci

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _device_lock_helper import LockTimeoutConfigError, acquire_device_lock  # noqa: E402
from _device_prep import DevicePrepError, prepare_device  # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu  # noqa: E402
from _rig_lifecycle import guard_socket_teardown  # noqa: E402
from _petscii_keys import push_keys, target_keys  # noqa: E402
from http_body_checks import (  # noqa: E402
    SYMBOLS, check_body_complete, check_http_status, decode_body_state)
from rig_https_m3 import (  # noqa: E402
    SETTLED, Fail, dump, labels, press_init, screen, verdict_refuse,
    wait_after, wait_for)

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO = Path(__file__).resolve().parents[2]
D64 = REPO / "dist" / "m3-demo" / "c64-https-uci-m3-demo.d64"
DISK_FILE = "c64-https-m3"
PRG = REPO / "build" / "c64-https.prg"
LABELS = REPO / "build" / "labels.txt"
SECOND_HOST, SECOND_PATH = "github.com", "/robots.txt"
NEGATIVE_HOST = os.environ.get("NEGATIVE_HOST", "208-80-153-224.nip.io")
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "900"))
RUN_DIR = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug"))
C1541 = os.environ.get("C1541", "c1541")
DRIVE_FIELDS = ("enabled", "image_path", "image_file")


def disk_prg(d64: Path) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "prg"
        subprocess.run([C1541, "-attach", str(d64), "-read", DISK_FILE,
                        str(out)], check=True, capture_output=True)
        return out.read_bytes()


def since(lines, anchor):
    """The rows from the last one holding `anchor` on (all rows if none)."""
    rows = [i for i, ln in enumerate(lines) if anchor in ln.upper()]
    return lines[rows[-1]:] if rows else lines


def body_state(client, lab):
    raw = {n: bytes(client.read_mem(lab[n], w)) for n, w in SYMBOLS.items()}
    return decode_body_state(raw)


def drive_a(client) -> dict:
    info = client.list_drives()
    for d in info.get("drives", []):
        if "a" in d:
            return d["a"]
    return {}


def delete_temp_upload(ours: dict, before: dict) -> None:
    """Delete the /Temp file our mount uploaded, unless it was there before."""
    path, name = ours.get("image_path", ""), ours.get("image_file", "")
    if not name or path.rstrip("/") != "/Temp" or (
            before.get("image_path"), before.get("image_file")) == (path, name):
        return
    try:
        with FTP(HOST, timeout=10.0) as ftp:
            ftp.login()
            ftp.cwd("/Temp")
            ftp.delete(name)
        print(f"  deleted /Temp/{name}")
    except (OSError, error_perm) as exc:
        print(f"WARNING: /Temp/{name} not deleted: {exc}")


def restore_drive_a(client, before: dict, ours: dict) -> None:
    client.unmount_disk("a")
    delete_temp_upload(ours, before)
    path, file = before.get("image_path"), before.get("image_file")
    if path and file:
        client.mount_disk_path("a", f"{path.rstrip('/')}/{file}")
    if not before.get("enabled", True):
        client.drive_off("a")
    after = drive_a(client)
    diff = {k: (before.get(k), after.get(k)) for k in DRIVE_FIELDS
            if before.get(k) != after.get(k)}
    if diff:
        print(f"WARNING: drive A not as found (before, after): {diff}")
    else:
        print(f"drive A restored: {after}")


def main() -> int:
    d64 = Path(sys.argv[1]) if len(sys.argv) > 1 else D64
    if not d64.is_file():
        print(f"[fatal] no {d64}: run `make package-m3-demo` first", file=sys.stderr)
        return 2
    try:
        on_disk = disk_prg(d64)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"[fatal] c1541 could not read {DISK_FILE} from {d64}: {exc}",
              file=sys.stderr)
        return 2
    if not PRG.is_file() or on_disk != PRG.read_bytes():
        print("[fatal] the PRG on the disk is not build/c64-https.prg, so "
              "build/labels.txt does not describe it", file=sys.stderr)
        return 2
    lab = labels(LABELS)
    if "m3_wedged" not in lab:
        print("[fatal] build/ is not a BACKEND=uci-m3 build", file=sys.stderr)
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
    before = {}
    ours = {}
    mounted = False
    try:
        client = Ultimate64Client(host=HOST, timeout=30.0)
        info = client.get_info()
        print(f"device: {info.get('product')} fw {info.get('firmware_version')} "
              f"git {info.get('git_commit_hash')} core {info.get('core_version')}")
        enable_uci(client)
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        try:
            prepare_device(client, LABELS, turbo_mhz=TURBO_MHZ,
                           artifact_dir=RUN_DIR)
        except DevicePrepError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        try:
            preflight_reu(client, LABELS)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        try:
            from _temp_gc import gc_temp
            print(f"/Temp GC: removed {gc_temp(HOST)} stale file(s)")
        except Exception as exc:                # noqa: BLE001
            print(f"WARNING: /Temp GC skipped: {exc}")

        before = drive_a(client)
        print(f"drive A before: {before}")
        if not before.get("enabled", True):
            client.drive_on("a")
        client.mount_disk("a", d64.read_bytes(), "d64", mode="readonly")
        mounted = True
        ours = drive_a(client)
        print(f"drive A now: {ours}")

        try:
            client.reset()
            time.sleep(3.0)
            m, lines = wait_for(client, ["READY."], 30)
            if not m:
                dump(lines, "after reset")
                raise Fail("no READY. after reset")
            client.send_text('LOAD"*",8,1')
            m, lines = wait_for(client, ["LOADING"], 60)
            if not m:
                dump(lines, "load")
                raise Fail("the drive never started LOADING")
            time.sleep(1.0)
            end = time.monotonic() + 180
            while time.monotonic() < end:
                lines, text = screen(client)
                if text.count("READY.") >= 2:
                    break
                time.sleep(1.0)
            else:
                dump(lines, "load")
                raise Fail("LOAD never finished")
            print("  loaded from drive 8; typing RUN")
            client.send_text("RUN")
            m, lines = wait_for(client, ["Q=QUIT"], 120)
            if not m:
                dump(lines, "run")
                raise Fail("the menu never appeared after RUN")
            press_init(client)

            # --- 1. the default target ----------------------------------
            t0 = time.monotonic()
            fetch_in_flight = True          # #234: a socket may be live
            client.send_text("G", finish_with_return=False)
            push_keys(client, target_keys("\r\r"))
            m, lines = wait_for(client, ["CONNECTION CLOSED", "TLS HANDSHAKE FAILED",
                                         "NOT RESPONDING"], FETCH_TIMEOUT)
            took = time.monotonic() - t0
            if m in SETTLED:
                fetch_in_flight = False
            dump(lines, "default fetch")
            if m != "CONNECTION CLOSED":
                raise Fail(f"default fetch ended with {m!r}")
            state = body_state(client, lab)
            status, body = check_http_status(state), check_body_complete(state)
            print(f"  {state.summary()}")
            print(f"  HTTP status   : {status.reason}")
            print(f"  body complete : {body.reason}")
            print(f"  default fetch : {took:.0f} s from 'G' to CONNECTION CLOSED"
                  " (1 s screen polling)")
            if not (status.ok and body.ok):
                raise Fail("the default fetch is not HTTP 200 + complete")

            # --- 1b. a second positive, the README's second URL ----------
            t0 = time.monotonic()
            fetch_in_flight = True
            client.send_text("G", finish_with_return=False)
            push_keys(client, target_keys(f"{SECOND_HOST}\r{SECOND_PATH}\r"))
            m, lines = wait_after(client, "HTTPS GET " + SECOND_HOST.upper(),
                                  ["CONNECTION CLOSED", "TLS HANDSHAKE FAILED",
                                   "NOT RESPONDING"], FETCH_TIMEOUT)
            took = time.monotonic() - t0
            if m in SETTLED:
                fetch_in_flight = False
            if m != "CONNECTION CLOSED":
                dump(lines, "second fetch")
                raise Fail(f"{SECOND_HOST}{SECOND_PATH} ended with {m!r}")
            state = body_state(client, lab)
            status, body = check_http_status(state), check_body_complete(state)
            print(f"  {SECOND_HOST}{SECOND_PATH}: {status.reason}; {body.reason}; "
                  f"{took:.0f} s")
            if not (status.ok and body.ok):
                raise Fail(f"{SECOND_HOST}{SECOND_PATH} is not HTTP 200 + complete")

            # --- 2. the negative ----------------------------------------
            fetch_in_flight = True
            client.send_text("G", finish_with_return=False)
            push_keys(client, target_keys(f"{NEGATIVE_HOST}\r/\r"))
            banner = "HTTPS GET " + NEGATIVE_HOST.upper()
            m, lines = wait_after(client, banner,
                                  ["TLS HANDSHAKE FAILED", "CONNECTION CLOSED",
                                   "NOT RESPONDING"], 300)
            if m in SETTLED:
                fetch_in_flight = False
            time.sleep(2.0)                 # let the status line print
            lines, _ = screen(client)
            # Only this fetch's rows: the default fetch's REQUEST SENT is
            # still on screen, and verdict_refuse rejects one.
            verdict_refuse(client, lab, NEGATIVE_HOST, "94", m,
                           since(lines, banner))
            client.send_text("Q", finish_with_return=False)
            print("PASS: the demo disk LOADs from drive 8, fetches the default "
                  "target complete, and shows the name-mismatch refusal")
            return 0
        except Fail as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
    finally:
        if fetch_in_flight and client is not None:
            guard_socket_teardown(client.read_mem, lab.get("net_tcp_state"))
        if client is not None:
            if mounted:
                try:
                    restore_drive_a(client, before, ours)
                except Exception as exc:        # noqa: BLE001
                    print(f"WARNING: drive A not restored: {exc}")
            try:
                disable_uci(client)
            except Exception as exc:            # noqa: BLE001
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    sys.exit(main())
