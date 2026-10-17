#!/usr/bin/env python3
"""rig_mlkem_hw.py - the PQ_HYBRID ML-KEM image on a real Ultimate 64.

Needs a PQ_HYBRID=1 uci build in build/ (BACKEND=uci USE_NISTCURVES_ONCHIP=1
or the comb profile) and a U64E / C64U on the LAN. Nothing in the shipped
protocol calls ML-KEM yet, so this rig is where the loaded-at-$A000,
copied-to-$E000 image is proven on silicon:

  [1] IMAGE   boot, 'Q' to BASIC, park the CPU with all RAM banked in
              (sei / $01=$34 / jmp *), then read $E000.. and $FFFA through
              the REST API (which otherwise returns the KERNAL ROM there) and
              compare with the bytes the PRG carries at $A000.. (the span
              _prg_load cannot read back before the run).
  [2] KAT     boot again, 'Q', then run mlkem_keygen and mlkem_decaps_seed
              through pq_mlkem_call from a DMA-injected stub and compare ek,
              dk and K with the libs/mlkem reference (the one the library's
              ACVP runs are checked against).

Both phases run AFTER 'Q' (BASIC owns the machine), so no in-session call
(KeyGen between the menu and a connection) is proven here - that is P4's job.

Environment: U64_HOST (default 192.168.1.81), BOOT_TIMEOUT (default 60; set
C64_INIT_WAIT-style larger values for the comb profile's boot precompute),
C64_PRG. Exit 0 = all checks passed, 1 = a check failed, 2 = could not run.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "libs" / "mlkem" / "tools"))

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout  # noqa: E402
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import Ultimate64Client  # noqa: E402
from c64_test_harness.keyboard import send_text  # noqa: E402
from c64_test_harness.labels import Labels  # noqa: E402
from c64_test_harness.uci_network import disable_uci, enable_uci  # noqa: E402
from _device_lock_helper import LockTimeoutConfigError, acquire_device_lock  # noqa: E402
from _device_prep import DevicePrepError, prepare_device  # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu  # noqa: E402
from _memory_policy import TCP_RING_DEFAULT, _label_value, build_policy_and_low_ram_arbiter  # noqa: E402
from _prg_load import PrgLoadError, load_verified_and_run  # noqa: E402
from _skip_policy import cannot_run, verdict  # noqa: E402
from boot_check import decode_screen, screen_text  # noqa: E402

#: Labels a build must carry for this rig to run (tools/test_rig_scratch.py).
NEEDED = ("pq_mlkem_keygen",)

HOST = os.environ.get("U64_HOST", "192.168.1.81")
BOOT_TIMEOUT = float(os.environ.get("BOOT_TIMEOUT", os.environ.get("C64_INIT_WAIT", "60")))
PRG_PATH = Path(os.environ.get("C64_PRG", str(REPO / "build" / "c64-https.prg")))
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
LABELS_PATH = Path(os.environ.get("C64_LABELS", str(REPO / "build" / "labels.txt")))

# Scratch comes from build/labels.txt and tools/uci/_memory_policy.py, never
# hardcoded: page 3 (arbiter) for the stub, sentinel, seed and key; cert_buf
# for ek; the TCP ring (the real dk's home) for dk and ct. Set by layout().
STUB = SENT = SEED = KEY = EK_AT = DK_AT = CT_AT = None


def layout(labels):
    global STUB, SENT, SEED, KEY, EK_AT, DK_AT, CT_AT
    _, arb = build_policy_and_low_ram_arbiter(LABELS_PATH, PRG_PATH)
    STUB = arb.alloc(24, name="stub")
    SENT = arb.alloc(2, name="result+sentinel")
    SEED = arb.alloc(64, name="d||z seed")
    KEY = arb.alloc(32, name="shared key")
    EK_AT = labels["cert_buf"]
    assert labels["cert_buf_size"] >= 1184
    ring = _label_value(LABELS_PATH, "tcp_recv_buf", TCP_RING_DEFAULT)
    DK_AT = ring                    # 2,400 B
    CT_AT = ring + 2400             # 1,088 B: ends at ring + 3,488 < ring + 4 KB


D = bytes(range(1, 33))
Z = bytes(range(101, 133))
M = bytes(range(201, 233))

def park_stub():
    return bytes([0x78,                 # sei
                  0xA9, 0x34, 0x85, 0x01,   # lda #$34 / sta $01   (all RAM)
                  0x4C, (STUB + 5) & 255, STUB >> 8])  # jmp *  (at STUB+5)


class Tally:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
            print(f"  PASS  {what}")
        else:
            self.failed += 1
            print(f"  FAIL  {what}" + (f": {detail}" if detail else ""))
        return ok


def boot_to_basic(client, transport, prg):
    client.reset()
    time.sleep(2.5)
    load_verified_and_run(client, prg, labels_path=LABELS_PATH)
    deadline = time.monotonic() + BOOT_TIMEOUT
    while time.monotonic() < deadline:
        if "Q=QUIT" in screen_text(decode_screen(bytes(client.read_mem(0x0400, 1000)))):
            break
        time.sleep(2.0)
    else:
        raise RuntimeError("the menu never appeared")
    send_text(transport, "q\r")
    for _ in range(30):
        time.sleep(1.0)
        if "READY." in screen_text(decode_screen(bytes(client.read_mem(0x0400, 1000)))):
            return
    raise RuntimeError("BASIC READY. never appeared after Q")


def run_stub(transport, client, code, timeout):
    transport.write_memory(SENT, bytes(2))
    transport.write_memory(STUB, code)
    send_text(transport, f"sys{STUB}\r")
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if bytes(client.read_mem(SENT + 1, 1)) == b"\xA5":
            return bytes(client.read_mem(SENT, 1))[0], time.monotonic() - t0
        time.sleep(1.0)
    raise RuntimeError(f"the stub never finished within {timeout:.0f} s")


def call_stub(labels, entry):
    c = labels["pq_" + entry]                       # pq_mlkem_keygen / _decaps_seed
    return bytes([0x20, c & 255, c >> 8,                                 # jsr wrapper
                  0x8D, SENT & 255, SENT >> 8,                         # sta SENT
                  0xA9, 0xA5, 0x8D, (SENT + 1) & 255, (SENT + 1) >> 8,  # sentinel
                  0x60])                                               # rts: back to BASIC


def set_args(transport, labels, **ptrs):
    for name, addr in ptrs.items():
        transport.write_memory(labels[f"mlkem_arg_{name}"], bytes([addr & 255, addr >> 8]))


def image_phase(t, client, transport, prg, labels):
    print("\n[1] the copied image, read with the CPU parked and all RAM banked in")
    boot_to_basic(client, transport, prg)
    transport.write_memory(STUB, park_stub())
    send_text(transport, f"sys{STUB}\r")
    time.sleep(3.0)
    body = prg[2:]
    for seg in ("CODE", "RODATA"):
        load = labels[f"__LIB_MLKEM_{seg}_LOAD__"]
        run = labels[f"__LIB_MLKEM_{seg}_RUN__"]
        size = labels[f"__LIB_MLKEM_{seg}_SIZE__"]
        want = body[load - 0x0801:load - 0x0801 + size]
        got = b"".join(bytes(client.read_mem(run + o, min(2048, size - o)))
                       for o in range(0, size, 2048))
        t.check(got == want, f"{seg}: ${run:04X}..${run + size - 1:04X} == the PRG's "
                f"${load:04X}.. ({size} B)",
                f"first diff at +{next((i for i in range(size) if got[i] != want[i]), -1)}")
    vec = bytes(client.read_mem(0xFFFA, 6))
    rti = labels["mlkem_rti"]
    t.check(vec == bytes([rti & 255, rti >> 8]) * 3,
            f"$FFFA/$FFFC/$FFFE -> the RTI at ${rti:04X}", vec.hex())


def kat_phase(t, client, transport, prg, labels):
    import mlkem_ref as R
    print("\n[2] KeyGen and Decaps_seed through pq_mlkem_call")
    ek_ref, dk_ref = R.mlkem_keygen(D, Z)
    K_ref, ct_ref = R.mlkem_encaps(ek_ref, M)
    boot_to_basic(client, transport, prg)
    transport.write_memory(SEED, D + Z)
    transport.write_memory(EK_AT, bytes([0xEE]) * 1184)
    transport.write_memory(DK_AT, bytes([0xEE]) * 2400)
    set_args(transport, labels, seed=SEED, z=SEED + 32, ek=EK_AT, dk=DK_AT)
    a, dt = run_stub(transport, client, call_stub(labels, "mlkem_keygen"), 400)
    ek = bytes(client.read_mem(EK_AT, 1184))
    dk = b"".join(bytes(client.read_mem(DK_AT + o, min(1200, 2400 - o)))
                  for o in range(0, 2400, 1200))
    t.check(a == 0, f"mlkem_keygen returned A=0 ({dt:.0f} s)", f"A={a:02X}")
    t.check(ek == ek_ref, "ek == the reference's",
            f"first diff at +{next((i for i in range(1184) if ek[i] != ek_ref[i]), -1)}")
    t.check(dk == dk_ref, "dk == the reference's",
            f"first diff at +{next((i for i in range(2400) if dk[i] != dk_ref[i]), -1)}")
    transport.write_memory(CT_AT, ct_ref)
    transport.write_memory(KEY, bytes(32))
    set_args(transport, labels, seed=SEED, ct=CT_AT, key=KEY)
    a, dt = run_stub(transport, client, call_stub(labels, "mlkem_decaps_seed"), 600)
    K = bytes(client.read_mem(KEY, 32))
    t.check(K == K_ref, f"mlkem_decaps_seed K == the reference's ({dt:.0f} s)", K.hex())


def main():
    if not PRG_PATH.exists() or not LABELS_PATH.exists():
        return cannot_run(f"{PRG_PATH} / {LABELS_PATH} missing: build PQ_HYBRID=1 first",
                          certifies="the ML-KEM image on hardware")
    labels = Labels.from_file(str(LABELS_PATH))
    if labels.address("pq_mlkem_keygen") is None:
        return cannot_run("the build in build/ is not a PQ_HYBRID image",
                          certifies="the ML-KEM image on hardware")
    layout(labels)          # before the lock, like every rig
    prg = PRG_PATH.read_bytes()
    print(f"PRG {PRG_PATH} sha256 "
          f"{__import__('hashlib').sha256(prg).hexdigest()}")
    lock = DeviceLock(HOST)
    try:
        acquire_device_lock(lock)
    except (LockTimeoutConfigError, DeviceLockTimeout) as exc:
        return cannot_run(f"DeviceLock({HOST}): {exc}", certifies="the ML-KEM image on hardware")
    t = Tally()
    client = None
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        transport = Ultimate64Transport(host=HOST, timeout=15.0, client=client)
        enable_uci(client)
        import tempfile
        prepare_device(client, LABELS_PATH, turbo_mhz=TURBO_MHZ,
                       artifact_dir=tempfile.mkdtemp(prefix="mlkem_hw_"))
        preflight_reu(client, LABELS_PATH)
        image_phase(t, client, transport, prg, labels)
        kat_phase(t, client, transport, prg, labels)
    except (PrgLoadError, RuntimeError, DevicePrepError, ReuPreflightError) as exc:
        t.check(False, "rig ran to completion", str(exc))
    finally:
        try:
            if client is not None:
                disable_uci(client)
        finally:
            lock.release()
    print(f"\nRESULTS: {t.passed}/{t.passed + t.failed} passed, {t.failed} failed")
    return verdict(t.passed, t.failed, certifies="the ML-KEM image on hardware")


if __name__ == "__main__":
    sys.exit(main())
