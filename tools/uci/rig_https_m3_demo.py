#!/usr/bin/env python3
"""The M3 demo disk, the way a user runs it: from the drive, not by DMA.

`make package-m3-demo` writes dist/m3-demo/c64-https-uci-m3-demo.d64. This
rig mounts THAT image on the Ultimate's drive A (device 8), types
LOAD"*",8,1 and RUN, and then drives the menu:

  1. 'I', then 'G' with RETURN, RETURN: the built-in default target
     (en.wikipedia.org /wiki/Commodore_64). It must end HTTP 200 with the
     body complete by its own framing (tools/http_body_checks.py).
  2. 'G' with a name the certificate does not carry (NEGATIVE_HOST, a
     nip.io name for a Wikipedia address): it must end "TLS HANDSHAKE
     FAILED" with the firmware's "94,..." line on screen, no handle held,
     net_last_error $8D UCI_ERR_OPEN_REFUSED.

The PRG on the disk must be the one build/labels.txt describes: the rig
reads the PRG back out of the .d64 with c1541 and refuses to run if it
differs from build/c64-https.prg (run it right after `make
package-m3-demo`, which leaves that build in build/).

Drive A's state is read first and restored at the end (its image re-mounted
by path when it had one). Device prep, the REU preflight, the DeviceLock and
the #234 socket guard are the same as every other fetch rig's.

    U64_HOST=10.43.23.81 tools/uci/rig_https_m3_demo.py [path/to.d64]

Exit: 0 pass, 1 fail, 2 fatal, 3 DeviceLock timeout, 4 device prep.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
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
from boot_check import decode_screen, screen_text  # noqa: E402
from http_body_checks import (  # noqa: E402
    SYMBOLS, check_body_complete, check_http_status, decode_body_state)

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO = Path(__file__).resolve().parents[2]
D64 = REPO / "dist" / "m3-demo" / "c64-https-uci-m3-demo.d64"
DISK_FILE = "c64-https-m3"
PRG = REPO / "build" / "c64-https.prg"
LABELS = REPO / "build" / "labels.txt"
NEGATIVE_HOST = os.environ.get("NEGATIVE_HOST", "208-80-153-224.nip.io")
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "900"))
RUN_DIR = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug"))
UCI_ERR_OPEN_REFUSED = 0x8D


class Fail(Exception):
    pass


def labels() -> dict[str, int]:
    out = {}
    for line in LABELS.read_text().splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == "al" and p[2].startswith("."):
            out[p[2][1:]] = int(p[1].split(":")[-1], 16)
    return out


def disk_prg(d64: Path) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "prg"
        subprocess.run(["c1541", "-attach", str(d64), "-read", DISK_FILE,
                        str(out)], check=True, capture_output=True)
        return out.read_bytes()


def screen(client):
    lines = decode_screen(bytes(client.read_mem(0x0400, 1000)))
    return lines, screen_text(lines)


def wait_for(client, markers, budget):
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


def body_state(client, lab):
    raw = {n: bytes(client.read_mem(lab[n], w)) for n, w in SYMBOLS.items()}
    return decode_body_state(raw)


def drive_a(client) -> dict:
    info = client.list_drives()
    for d in info.get("drives", []):
        if "a" in d:
            return d["a"]
    return {}


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
    lab = labels()
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
        print(f"drive A now: {drive_a(client)}")

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
            client.send_text("I", finish_with_return=False)
            m, lines = wait_for(client, ["DHCP OK", "FAILED"], 120)
            if m != "DHCP OK":
                dump(lines, "init")
                raise Fail(f"network init: {m}")

            # --- 1. the default target ----------------------------------
            fetch_in_flight = True          # #234: a socket may be live
            client.send_text("G", finish_with_return=False)
            push_keys(client, target_keys("\r\r"))
            m, lines = wait_for(client, ["CONNECTION CLOSED", "TLS HANDSHAKE FAILED",
                                         "NOT RESPONDING"], FETCH_TIMEOUT)
            if m == "CONNECTION CLOSED":
                fetch_in_flight = False
            dump(lines, "default fetch")
            if m != "CONNECTION CLOSED":
                raise Fail(f"default fetch ended with {m!r}")
            state = body_state(client, lab)
            status, body = check_http_status(state), check_body_complete(state)
            print(f"  {state.summary()}")
            print(f"  HTTP status   : {status.reason}")
            print(f"  body complete : {body.reason}")
            if not (status.ok and body.ok):
                raise Fail("the default fetch is not HTTP 200 + complete")

            # --- 2. the negative ----------------------------------------
            fetch_in_flight = True
            client.send_text("G", finish_with_return=False)
            push_keys(client, target_keys(f"{NEGATIVE_HOST}\r/\r"))
            m, lines = wait_for(client, ["94,CERTIFICATE", "CONNECTION CLOSED",
                                         "NOT RESPONDING"], 300)
            if m in ("94,CERTIFICATE", "CONNECTION CLOSED"):
                fetch_in_flight = False     # refused: nothing was opened
            dump(lines, "negative")
            n = bytes(client.read_mem(lab["m3_status_len"], 1))[0]
            line = bytes(client.read_mem(lab["m3_status"], n)).decode("ascii", "replace")
            err = bytes(client.read_mem(lab["net_last_error"], 1))[0]
            owned = bytes(client.read_mem(lab["m3_owned"], 1))[0]
            print(f"  status line {line!r}, net_last_error ${err:02X}, m3_owned={owned}")
            if m != "94,CERTIFICATE" or "TLS HANDSHAKE FAILED" not in screen_text(lines):
                raise Fail(f"the negative was not refused with 94 on screen ({m!r})")
            if err != UCI_ERR_OPEN_REFUSED or owned:
                raise Fail("the refusal did not leave $8D and no handle")
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
                    client.unmount_disk("a")
                    path = before.get("image_path") or before.get("path")
                    file = before.get("image_file")
                    if path and file:
                        client.mount_disk_path("a", f"{path.rstrip('/')}/{file}")
                    print(f"drive A restored: {drive_a(client)}")
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
