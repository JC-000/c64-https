#!/usr/bin/env python3
"""Several HTTPS fetches in ONE boot, driven through the menu.

Every other HTTPS rig does one fetch per boot, so per-connection state that
a second `tls_connect` inherits from the first was never exercised: the
first connection runs on BSS that boot zeroed, and that hides anything
`tls_connect` forgets to reset. This rig boots once, presses 'I', then
presses 'G' (RETURN twice at the #155 target prompt: keep the build-time
HOST/PATH) FETCHES times, letting each fetch finish and its socket close
before the next. It never resets between fetches -- a reset over a live
firmware socket poisons the UCI lease (CLAUDE.md "Lease poisoning").

Point the PRG at a listener that answers every connection with a framed
200, e.g. `make BACKEND=uci USE_NISTCURVES_ONCHIP=1 HTTPS_HOST=<ip>
HTTPS_PORT=<port>` against tools/https_e2e/https_listener.py (the SAN check
needs a dNSName naming HTTPS_HOST). The build is not this rig's business;
it loads whatever PRG it is given -- onchip or comb, so it prepares the
device (clock, and the REU a comb image needs) before the REU preflight,
like the other crypto-path rigs.

Per fetch it records, from memory, after the fetch has finished:
tls_reached_connected, tls_last_state, tls_state, http_status,
net_last_error, and tls_read_seq / tls_write_seq as they stood before 'G'
(what the next connection would inherit if tls_connect did not reset them).
A fetch passes when tls_reached_connected = CONNECTED and http_status = 200.

Env: U64_HOST, PRG (default build/c64-https.prg; labels.txt beside it),
FETCHES (default 3), TURBO_MHZ (default 48), FETCH_TIMEOUT (s per fetch,
default 300 scaled by clock), C64_INIT_WAIT, DHCP_TIMEOUT.

Exit: 0 every fetch passed, 1 a fetch failed or a screen wait timed out,
2 fatal setup error, 3 DeviceLock timeout, 4 device prep / REU preflight /
PRG load.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import (
    DeviceLock, DeviceLockTimeout,
)
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import disable_uci, enable_uci

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _device_lock_helper import (  # noqa: E402
    LockTimeoutConfigError, acquire_device_lock,
)
from _prg_load import PrgLoadError, load_verified_and_run  # noqa: E402
from _device_prep import DevicePrepError, prepare_device  # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu  # noqa: E402
from boot_check import decode_screen, screen_text  # noqa: E402
from rig_https_local import (  # noqa: E402
    _create_run_dir, _prune_old_run_dirs,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ip65_hw_checks import check_shadow_ram_readable  # noqa: E402
from _rig_lifecycle import guard_socket_teardown  # noqa: E402
from _petscii_keys import push_keys, target_keys  # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
PRG_PATH = Path(os.environ.get(
    "PRG", Path(__file__).resolve().parents[2] / "build" / "c64-https.prg"))
LABELS_PATH = PRG_PATH.parent / "labels.txt"
FETCHES = int(os.environ.get("FETCHES", "3"))
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_SCALE = max(1.0, 48.0 / float(TURBO_MHZ))
INIT_WAIT = float(os.environ.get("C64_INIT_WAIT", str(75 * _SCALE)))
DHCP_TIMEOUT = float(os.environ.get("DHCP_TIMEOUT", str(90 * _SCALE)))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", str(300 * _SCALE)))
DEBUG_BASE_DIR = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug"))

TLS_STATE_CONNECTED = 0x07
NET_TCP_CONNECTED = 0x01
#: The last line do_https_get prints on each of its exits.
TERMINAL = ("CONNECTION CLOSED", "TLS HANDSHAKE FAILED", "TCP CONNECT FAILED",
            "DNS RESOLVE FAILED", "INVALID TARGET", "COLD BANK FAIL")
#: (symbol, width) read after each fetch.
STATE = (("tls_reached_connected", 1), ("tls_last_state", 1),
         ("tls_state", 1), ("http_status", 2), ("net_last_error", 1),
         ("net_tcp_state", 1))


def load_labels() -> dict[str, int]:
    out = {}
    for line in LABELS_PATH.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("."):
            out[parts[2][1:]] = int(parts[1].split(":")[1], 16)
    return out


def last_line(client) -> str:
    lines = decode_screen(bytes(client.read_mem(0x0400, 1000)))
    rows = [r for r in screen_text(lines).splitlines() if r.strip()]
    return rows[-1].strip() if rows else ""


def is_terminal(line: str) -> bool:
    return any(line.startswith(t) for t in TERMINAL)


def wait_screen(client, pred, budget: float) -> tuple[bool, str]:
    deadline = time.monotonic() + budget
    line = ""
    while time.monotonic() < deadline:
        line = last_line(client)
        if pred(line):
            return True, line
        time.sleep(1.0)
    return False, line


def dump(client, title: str) -> None:
    lines = decode_screen(bytes(client.read_mem(0x0400, 1000)))
    print(f"--- {title} ---")
    for i, row in enumerate(screen_text(lines).splitlines()):
        if row.strip():
            print(f"{i:02d}: {row}")
    print("--- end ---")


def main() -> int:
    if not PRG_PATH.is_file() or not LABELS_PATH.is_file():
        print(f"[fatal] need {PRG_PATH} and {LABELS_PATH}", file=sys.stderr)
        return 2
    if FETCHES < 2:
        print("[fatal] FETCHES must be >= 2: the point is the second one",
              file=sys.stderr)
        return 2
    labels = load_labels()
    missing = [n for n, _ in STATE if n not in labels]
    missing += [n for n in ("tls_read_seq", "tls_write_seq",
                            "https_target_prompt") if n not in labels]
    if missing:
        print(f"[fatal] labels missing (UCI build with the #155 prompt "
              f"needed): {missing}", file=sys.stderr)
        return 2
    prg = PRG_PATH.read_bytes()
    import hashlib
    prg_sha = hashlib.sha256(prg).hexdigest()
    print(f"PRG {PRG_PATH} ({len(prg)} B) sha256 {prg_sha}")

    lock = DeviceLock(HOST)
    try:
        acquire_device_lock(lock)
    except LockTimeoutConfigError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 3
    print(f"Acquired DeviceLock({HOST})")

    client = None
    uci_on = False
    fetch_in_flight = False
    results = []
    try:
        client = Ultimate64Client(host=HOST, timeout=20.0)
        try:
            info = client.get_info()
        except Exception as exc:    # noqa: BLE001
            info = {"error": str(exc)}
        print(f"device info: {json.dumps(info)}")
        enable_uci(client)
        uci_on = True
        if os.environ.get("C64_SKIP_TEMP_GC") != "1":
            try:
                from _temp_gc import gc_temp
                print(f"/Temp GC: removed {gc_temp(HOST)} stale file(s)")
            except Exception as exc:    # noqa: BLE001
                print(f"WARNING: /Temp GC skipped: {exc}")

        prep_dir = _create_run_dir(DEBUG_BASE_DIR)
        _prune_old_run_dirs(DEBUG_BASE_DIR, keep=5)
        try:
            prepare_device(client, LABELS_PATH, turbo_mhz=TURBO_MHZ,
                           artifact_dir=prep_dir)
        except DevicePrepError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        except ValueError as exc:
            print(f"[fatal] TURBO_MHZ={TURBO_MHZ}: {exc}", file=sys.stderr)
            return 2
        try:
            preflight_reu(client, LABELS_PATH)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4

        client.reset()
        time.sleep(2.5)
        try:
            load_verified_and_run(client, prg)
        except PrgLoadError as exc:
            print(f"[fatal] {exc}", file=sys.stderr)
            return 4

        ok, line = wait_screen(client, lambda s: "Q=QUIT" in s,
                               INIT_WAIT + 30)
        if not ok:
            dump(client, "boot timeout")
            return 1
        client.send_text("I", finish_with_return=False)
        ok, line = wait_screen(client, lambda s: "DHCP OK" in s, DHCP_TIMEOUT)
        if not ok:
            dump(client, "DHCP timeout")
            return 1
        shadow = check_shadow_ram_readable(bytes(client.read_mem(0xA000, 16)))
        print(f"shadow RAM: {shadow.reason}")
        if not shadow.ok:
            return 1

        keep_target = target_keys("\r\r")
        for n in range(1, FETCHES + 1):
            seq = bytes(client.read_mem(labels["tls_write_seq"], 8)
                        + client.read_mem(labels["tls_read_seq"], 8))
            print(f"\n=== fetch {n}/{FETCHES}: before 'G' write_seq="
                  f"{seq[:8].hex()} read_seq={seq[8:].hex()}")
            started = time.monotonic()
            fetch_in_flight = True
            client.send_text("G", finish_with_return=False)
            push_keys(client, keep_target)
            # The previous fetch's terminal line is still the last line until
            # this one prints its banner; wait for it to move first.
            ok, line = wait_screen(client, lambda s: not is_terminal(s), 30)
            if not ok:
                dump(client, f"fetch {n}: 'G' never started a fetch")
                return 1
            ok, line = wait_screen(client, is_terminal, FETCH_TIMEOUT)
            took = time.monotonic() - started
            row = {"fetch": n, "seconds": round(took, 1), "last_line": line,
                   "seq_before": seq.hex()}
            for name, width in STATE:
                b = bytes(client.read_mem(labels[name], width))
                row[name] = int.from_bytes(b, "little")
            fetch_in_flight = row["net_tcp_state"] == NET_TCP_CONNECTED or not ok
            row["pass"] = (ok
                           and row["tls_reached_connected"]
                           == TLS_STATE_CONNECTED
                           and row["http_status"] == 200)
            results.append(row)
            print(f"  {'PASS' if row['pass'] else 'FAIL'} {took:.1f}s "
                  f"last={line!r} reached=${row['tls_reached_connected']:02X}"
                  f" last_state=${row['tls_last_state']:02X} "
                  f"tls_state=${row['tls_state']:02X} "
                  f"http_status={row['http_status']} "
                  f"net_last_error=${row['net_last_error']:02X} "
                  f"net_tcp_state=${row['net_tcp_state']:02X}")
            if not ok:
                dump(client, f"fetch {n}: no terminal line in "
                     f"{FETCH_TIMEOUT:.0f}s")
                return 1
            time.sleep(2.0)

        dump(client, "final screen")
        (prep_dir / "refetch.json").write_text(json.dumps(
            {"prg_sha256": prg_sha, "device_info": info,
             "turbo_mhz": TURBO_MHZ, "fetches": results}, indent=2))
        print(f"\nrecord: {prep_dir / 'refetch.json'}")
        passed = sum(r["pass"] for r in results)
        print(f"RESULT: {passed}/{FETCHES} fetches passed in one boot")
        return 0 if passed == FETCHES else 1
    finally:
        if fetch_in_flight and client is not None:
            guard_socket_teardown(
                client.read_mem, labels.get("net_tcp_state"),
                tls_addrs=(labels["tls_state"],
                           labels["tls_reached_connected"]))
        if uci_on and client is not None:
            try:
                disable_uci(client)
            except Exception as exc:    # noqa: BLE001
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    sys.exit(main())
