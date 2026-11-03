#!/usr/bin/env python3
"""rig_https_handoff.py - a HANDOFF=1 helper fetching one URL on hardware.

Drives the helper the way a host program (Commodore Desk 64's WEB) does,
with no host program needed:

  1. assembles tools/uci/handoff_rig.s: a page-3 STUB and a stand-in HOST
     program, and mounts a .d64 holding HOST on drive a (device 8);
  2. device prep with the REU required (prepare_device(require_reu=True):
     the helper's crypto is on-chip, but its mailbox and the body live in
     the REU), then the REU preflight;
  3. writes the STUB to page 3 and HANDOFF_URL to $02A7-$02FF (the two rig
     scratch areas; at most 88 chars), then loads the helper verified with
     its SYS line pointed at the STUB ("SYS0820", same length). The STUB
     fills REU banks 0-7 with a pattern (a stand-in RAM drive), writes the
     request, and jumps to the helper's entry;
  4. waits for HOST: the helper loads it back when it is done. HOST checks
     banks 0-7 byte by byte and copies the mailbox, the response head and
     the first 16 KB of the body to C64 RAM;
  5. reads those back (REST reads only) and hands them to
     tools/handoff_checks.py, whose every verdict has a red unit case.

The helper closes its socket before it loads HOST, so a run that reaches
HOST leaves no live socket. One that does not is left as it is, never
reset (a reset with a live firmware socket poisons the UCI lease).

Env: U64_HOST, TURBO_MHZ (48), HANDOFF_URL (https://en.wikipedia.org/),
EXPECT_RESULT (0; e.g. 4 for an unresolvable host), EXPECT_STATUS,
EXPECT_BODY_FILE (the body must start with this file's bytes),
FETCH_TIMEOUT (s). Needs a HANDOFF=1 build in build/ (an onchip build; the
comb image is refused at make time) and ca65/ld65/c1541 on PATH.

Exit: 0 pass, 1 fail, 2 fatal (bad setup), 3 DeviceLock timeout,
4 device prep / REU preflight / load.

    U64_HOST=10.43.23.81 tools/uci/rig_https_handoff.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import disable_uci, enable_uci

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
from _device_lock_helper import LockTimeoutConfigError, acquire_device_lock  # noqa: E402
from _device_prep import DevicePrepError, prepare_device  # noqa: E402
from _prg_load import PrgLoadError, load_verified_and_run  # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu  # noqa: E402
from boot_check import decode_screen, screen_text  # noqa: E402
from rig_https_local import _create_run_dir, _prune_old_run_dirs  # noqa: E402
import handoff_checks as hc  # noqa: E402
from _skip_policy import verdict  # noqa: E402

HOST_IP = os.environ.get("U64_HOST", "192.168.1.81")
ROOT = HERE.parents[1]
PRG_PATH = ROOT / "build" / "c64-https.prg"
LABELS_PATH = ROOT / "build" / "labels.txt"
URL = os.environ.get("HANDOFF_URL", "https://en.wikipedia.org/").encode("ascii")
EXPECT_RESULT = int(os.environ.get("EXPECT_RESULT", "0"))
EXPECT_STATUS = (int(os.environ["EXPECT_STATUS"])
                 if os.environ.get("EXPECT_STATUS") else None)
EXPECT_BODY = (Path(os.environ["EXPECT_BODY_FILE"]).read_bytes()
               if os.environ.get("EXPECT_BODY_FILE") else None)
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_SCALE = max(1.0, 48.0 / TURBO_MHZ)
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", str(600 * _SCALE)))
DEBUG_BASE_DIR = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug"))

STUB_ADDR, PAGE3_END = 0x0334, 0x0400
RET_NAME, RET_ENTRY = b"HOST", 0x0810
URL_AT, URL_END = 0x02A7, 0x0300        # handoff_rig.s URL_AT/URL_MAX
DONE_AT, ERRS_AT = 0xC3F8, 0xC3F0


def request() -> bytes:
    """The fixed fields (src/handoff.inc); the URL travels separately."""
    L = hc.L
    r = bytearray(L["HO_O_URL"])
    r[0:8] = b"C64HTTPS"
    r[L["HO_O_VERSION"]] = L["HO_VERSION"]
    r[L["HO_O_STATE"]] = L["HO_ST_REQUEST"]
    r[L["HO_O_RET_DEV"]] = 8
    r[L["HO_O_RET_NLEN"]] = len(RET_NAME)
    r[L["HO_O_RET_ENTRY"]:L["HO_O_RET_ENTRY"] + 2] = RET_ENTRY.to_bytes(2, "little")
    r[L["HO_O_RET_NAME"]:L["HO_O_RET_NAME"] + len(RET_NAME)] = RET_NAME
    assert len(r) == 0x20, "HO_O_URL moved: handoff_rig.s stashes the URL at +$20"
    return bytes(r)


def assemble(tmp: Path) -> tuple[bytes, bytes]:
    """(stub bytes for $0334, HOST as a .prg)."""
    src = HERE / "handoff_rig.s"
    (tmp / "request.bin").write_bytes(request())
    cfg_stub = tmp / "stub.cfg"
    cfg_stub.write_text(
        f"MEMORY {{ RAM: start = ${STUB_ADDR:04X}, size = ${PAGE3_END - STUB_ADDR:04X}, file = %O; }}\n"
        "SEGMENTS { CODE: load = RAM, type = rw; }\n")
    cfg_host = tmp / "host.cfg"
    cfg_host.write_text(
        "MEMORY { HDR: start = $07FF, size = 2, file = %O;"
        " RAM: start = $0801, size = $1000, file = %O; }\n"
        "SEGMENTS { LOADADDR: load = HDR, type = ro; CODE: load = RAM, type = rw; }\n")
    out = {}
    for what, cfg in (("STUB", cfg_stub), ("HOST", cfg_host)):
        obj, binf = tmp / f"{what}.o", tmp / f"{what}.bin"
        subprocess.run(["ca65", "-D", what, "--bin-include-dir", str(tmp),
                        "-o", str(obj), str(src)], check=True)
        subprocess.run(["ld65", "-C", str(cfg), "-o", str(binf), str(obj)],
                       check=True)       # a stub past $03FF fails here
        out[what] = binf.read_bytes()
    return out["STUB"], out["HOST"]


def host_d64(tmp: Path, host_prg: bytes) -> bytes:
    prg, d64 = tmp / "host.prg", tmp / "host.d64"
    prg.write_bytes(host_prg)
    subprocess.run(["c1541", "-format", "handoff,ho", "d64", str(d64),
                    "-write", str(prg), RET_NAME.decode().lower()],
                   check=True, capture_output=True)
    return d64.read_bytes()


def point_sys_at_stub(prg: bytes) -> bytes:
    """SYS2061 -> SYS0820: same length, so the verified image is unchanged
    apart from these four digits, which load_verified_and_run then runs."""
    i = prg.find(b"\x9e2061")
    if i < 0 or i > 16:
        raise ValueError("no SYS2061 stub at the start of the PRG")
    return prg[:i + 1] + b"%04d" % STUB_ADDR + prg[i + 5:]


def screen(client) -> str:
    return screen_text(decode_screen(bytes(client.read_mem(0x0400, 1000))))


def main() -> int:
    for tool in ("ca65", "ld65", "c1541"):
        if shutil.which(tool) is None:
            print(f"[fatal] {tool} not on PATH", file=sys.stderr)
            return 2
    if not PRG_PATH.is_file() or ".ho_active" not in LABELS_PATH.read_text():
        print("[fatal] build/ holds no HANDOFF=1 build: make BACKEND=uci "
              "USE_NISTCURVES_ONCHIP=1 TRUST_STORE=1 PQ_HYBRID=1 HANDOFF=1",
              file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmpd:
        tmp = Path(tmpd)
        try:
            stub, host = assemble(tmp)
        except subprocess.CalledProcessError as exc:
            print(f"[fatal] assembling handoff_rig.s: {exc}", file=sys.stderr)
            return 2
        d64 = host_d64(tmp, host)
    url_z = URL + b"\0"
    if len(url_z) > URL_END - URL_AT:
        print(f"[fatal] HANDOFF_URL is {len(URL)} chars; the rig carries at "
              f"most {URL_END - URL_AT - 1} ($02A7-$02FF)", file=sys.stderr)
        return 2
    prg = point_sys_at_stub(PRG_PATH.read_bytes())
    print(f"URL {URL.decode()} | stub+request {len(stub)} B at "
          f"${STUB_ADDR:04X} | HOST {len(host)} B")

    lock = DeviceLock(HOST_IP)
    try:
        acquire_device_lock(lock)
    except LockTimeoutConfigError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST_IP}): {exc}", file=sys.stderr)
        return 3
    client = None
    uci_on = False
    try:
        client = Ultimate64Client(host=HOST_IP, timeout=20.0)
        enable_uci(client)
        uci_on = True
        prep_dir = _create_run_dir(DEBUG_BASE_DIR)
        _prune_old_run_dirs(DEBUG_BASE_DIR, keep=5)
        try:
            # On-chip crypto, but the mailbox and the body need a REU: comb
            # builds are refused at make time, so require_reu is the only
            # way this run gets one configured.
            prepare_device(client, LABELS_PATH, turbo_mhz=TURBO_MHZ,
                           require_reu=True, artifact_dir=prep_dir)
        except DevicePrepError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        try:
            preflight_reu(client, LABELS_PATH)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4

        client.mount_disk("a", d64, "d64")
        client.reset()
        time.sleep(2.5)
        # The stub first: load_verified_and_run loads the image and types
        # SYS0820 at once. Page 3 is no part of the image.
        client.write_mem(STUB_ADDR, stub)
        client.write_mem(URL_AT, url_z)
        if (bytes(client.read_mem(STUB_ADDR, len(stub))) != stub
                or bytes(client.read_mem(URL_AT, len(url_z))) != url_z):
            print("[fatal] the stub or the URL did not verify", file=sys.stderr)
            return 4
        t0 = time.monotonic()
        try:
            load_verified_and_run(client, prg)
        except PrgLoadError as exc:
            print(f"[fatal] {exc}", file=sys.stderr)
            return 4

        print(f"Waiting up to {FETCH_TIMEOUT:.0f}s for the helper to load HOST back...")
        last = 0.0
        done = False
        while time.monotonic() - t0 < FETCH_TIMEOUT:
            if bytes(client.read_mem(DONE_AT, 4)) == b"DONE":
                done = True
                break
            if time.monotonic() - last > 20:
                last = time.monotonic()
                tail = [r for r in screen(client).splitlines() if r.strip()][-3:]
                print(f"  {time.monotonic() - t0:5.0f}s | {' | '.join(tail)}")
            time.sleep(2.0)
        elapsed = time.monotonic() - t0
        if not done:
            print(screen(client))
            print(f"FAIL: HOST never ran within {FETCH_TIMEOUT:.0f}s. The "
                  "machine is left as it is (a live socket must not be "
                  "reset).", file=sys.stderr)
            return 1
        print(f"HOST ran {elapsed:.1f}s after SYS")
        mailbox = bytes(client.read_mem(0xC000, 0x200))
        head = bytes(client.read_mem(0x2000, 0x1000))
        body = bytes(client.read_mem(0x3000, 0x4000))
        errs = int.from_bytes(bytes(client.read_mem(ERRS_AT, 3)), "little")
        reply = hc.Reply.parse(mailbox)
        print(f"  reply: {reply.summary()}")
        print("  head: " + head[:min(reply.hdr_len, 300)].decode("latin-1")
              .replace("\r\n", " | ")[:300])
        checks = hc.check_handoff(mailbox=mailbox, head_raw=head,
                                  body_prefix=body, bank_errors=errs,
                                  expect_result=EXPECT_RESULT,
                                  expect_status=EXPECT_STATUS,
                                  expect_body_prefix=EXPECT_BODY)
        for c in checks:
            print(f"  {'PASS' if c.ok else 'FAIL'}: {c.what}")
        failed = [c for c in checks if not c.ok]
        print(f"\n{'PASS' if not failed else 'FAIL'}: "
              f"{len(checks) - len(failed)}/{len(checks)} checks, "
              f"{elapsed:.1f}s SYS to HOST")
        return verdict(len(checks) - len(failed), len(failed))
    finally:
        if uci_on and client is not None:
            try:
                disable_uci(client)
            except Exception as exc:     # noqa: BLE001
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST_IP})")


if __name__ == "__main__":
    sys.exit(main())
