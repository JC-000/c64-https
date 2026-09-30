#!/usr/bin/env python3
"""rig_trust_store.py -- the trust store's disk I/O on a real Ultimate (#155).

VICE has no UCI, so the DOS-target path of src/net/uci/trust_store.s is
proven here, on the U64E, against the firmware's real filesystem on /USB1.
tools/test_trust_store_6502.py covers the same logic against a model; this
rig checks the model's assumptions and the bytes that land on the stick.

Build first (the rig refuses any other store path, so it can never touch a
real TRUST.A / TRUST.B):

    make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1 TRUST_STORE=1 \\
        TRUST_STORE_DIR=/USB1/c64https-test
    U64_HOST=... python3 tools/uci/rig_trust_store.py

Everything happens in /USB1/c64https-test/, which the rig creates, requires
to hold nothing but TRUST.A / TRUST.B, and removes at the end. No socket is
ever opened (the program's boot DHCP is the only network traffic), so the
one reset the rig issues cannot poison a lease.

Phases (each checked against tools/trust_store.py, and over FTP):
  1  load, empty directory                    -> EMPTY
  2  save github.com                          -> TRUST.A, generation 1
  3  load GitHub.COM                          -> VALID, record found
  4  save lwn.net                             -> TRUST.B, generation 2
  5  TORN WRITE: open TRUST.A for write, send 100 B of an image, never
     close; reset the C64 there. TRUST.B must be untouched.
  6  reload the PRG; load                     -> VALID from TRUST.B, the
     torn TRUST.A reported FORMAT/CHECKSUM
  7  save example.com                         -> repairs TRUST.A, gen 3
  8  corrupt TRUST.B                          -> VALID from TRUST.A
  9  corrupt both / one corrupt + one absent  -> FAIL CHECKSUM
 10  neither file                             -> EMPTY
 11  version 2 file                           -> FAIL VERSION
 12  32 records (2,064 B, multi-part read); replace one -> 9 write chunks
 13  (TURBO_MHZ=1 only) reset DURING trust_store_save's WRITE_DATA
 14  directory removed                        -> FAIL NOPATH

The torn write in phase 5 is produced with the store's own DOS layer
(dos_open FA_WRITE|FA_CREATE_ALWAYS + one dos_write, no close), so it is
deterministic at any clock. Phase 13 interrupts the real save; only at
1 MHz is its write window (~1 s) wide enough for a REST poll to land in.

Exit: 0 pass, 1 a check failed, 2 could not run, 3 lock timeout, 4 device
prep/preflight/load refused.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import time
from ftplib import FTP, error_perm
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools"))

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout  # noqa: E402
from c64_test_harness.backends.ultimate64 import Ultimate64Transport              # noqa: E402
from c64_test_harness.backends.ultimate64_client import Ultimate64Client          # noqa: E402
from c64_test_harness.keyboard import send_text                                   # noqa: E402
from c64_test_harness.uci_network import disable_uci, enable_uci                  # noqa: E402

from _device_lock_helper import LockTimeoutConfigError, acquire_device_lock        # noqa: E402
from _device_prep import DevicePrepError, prepare_device                          # noqa: E402
from _memory_policy import build_policy_and_low_ram_arbiter                       # noqa: E402
from _prg_load import PrgLoadError, load_verified_and_run                         # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu                       # noqa: E402
from _skip_policy import cannot_run, verdict                                      # noqa: E402
from _temp_gc import gc_temp                                                      # noqa: E402
import trust_store as ts                                                          # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
SCALE = max(1.0, 48.0 / TURBO_MHZ)
PRG_PATH = REPO / "build" / "c64-https.prg"
LABELS_PATH = REPO / "build" / "labels.txt"
TEST_DIR = "/USB1/c64https-test"
OURS = ("TRUST.A", "TRUST.B")
A_PATH, B_PATH = f"{TEST_DIR}/TRUST.A", f"{TEST_DIR}/TRUST.B"
CERTIFIES = "the trust store's UCI DOS I/O on the U64E (#155 phase 2)"
TS_BUF = 0xC000
TEAR_LEN = 100
SENT = 0xA5
OP_LOAD, OP_SAVE, OP_TEAR = 0, 1, 2
FA_WRITE_NEW = 0x0A
SPKI_1 = hashlib.sha256(b"rig key one").digest()
SPKI_2 = hashlib.sha256(b"rig key two").digest()
NEEDED = ("trust_store_load", "trust_store_stage", "trust_store_save",
          "ts_state", "ts_reason", "ts_slot", "ts_gen", "ts_slot_st", "ts_rec",
          "ts_found", "ts_name", "ts_set_name", "ts_target", "dos_open",
          "dos_write", "dos_len", "net_initialized", "uci_status_buf",
          "uci_status_len")


def load_labels():
    out = {}
    for line in LABELS_PATH.read_text().splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == "al" and p[2].startswith("."):
            out[p[2][1:]] = int(p[1].split(":")[-1], 16)
    return out


def image_store_path(prg: bytes, labels) -> str:
    """The TRUST_STORE_DIR baked into the image (ts_name, up to the letter)."""
    load = prg[0] | prg[1] << 8
    off = labels["ts_name"] - load + 2
    end = labels["ts_letter"] - load + 2
    return prg[off:end].decode("ascii", "replace")


def build_routine(L, a, rec, host, op, sent, ra, rp):
    """One SYS entry: op 0 load(host), 1 stage(rec)+save, 2 torn write."""
    c = bytearray()

    def e(*b):
        c.extend(b)

    def w(v):
        return (v & 0xFF, v >> 8)

    def jsr(x):
        e(0x20, *w(x))

    e(0xA5, 0x01, 0x48, 0xA9, 0x36, 0x85, 0x01)        # save $01, BASIC out
    e(0xAD, *w(op))
    i_beq = len(c)
    e(0xF0, 0x00)                                       # beq load
    e(0x4A)                                             # lsr
    i_bcs = len(c)
    e(0xB0, 0x00)                                       # bcs save
    # op 2: torn write into the slot NOT loaded, then spin: the rig resets.
    e(0xAD, *w(L["ts_slot"]), 0x49, 0x01, 0xAA)         # lda ts_slot/eor #1/tax
    jsr(L["ts_set_name"])
    e(0xA9, L["ts_name"] & 0xFF, 0xA2, L["ts_name"] >> 8, 0xA0, FA_WRITE_NEW)
    jsr(L["dos_open"])
    e(0x08, 0x68, 0x8D, *w(rp))                         # php/pla/sta rp
    e(0xA9, TEAR_LEN, 0x8D, *w(L["dos_len"]), 0xA9, 0x00, 0x8D, *w(L["dos_len"] + 1))
    e(0xA9, TS_BUF & 0xFF, 0xA2, TS_BUF >> 8)
    jsr(L["dos_write"])
    e(0x08, 0x68, 0x8D, *w(ra))                         # php/pla/sta ra
    e(0xA9, SENT, 0x8D, *w(sent))
    spin = a + len(c)
    e(0x4C, *w(spin))                                   # jmp * -- never closes
    c[i_beq + 1] = len(c) - (i_beq + 2)
    e(0xA9, host & 0xFF, 0xA2, host >> 8)               # load:
    jsr(L["trust_store_load"])
    i_jmp = len(c)
    e(0x4C, 0, 0)                                       # jmp res
    c[i_bcs + 1] = len(c) - (i_bcs + 2)
    e(0xA9, rec & 0xFF, 0xA2, rec >> 8)                 # save:
    jsr(L["trust_store_stage"])
    jsr(L["trust_store_save"])
    res = a + len(c)
    c[i_jmp + 1:i_jmp + 3] = bytes(w(res))
    e(0x08, 0x8D, *w(ra), 0x68, 0x8D, *w(rp))           # php/sta ra/pla/sta rp
    e(0x68, 0x85, 0x01)                                 # restore $01
    e(0xA9, SENT, 0x8D, *w(sent), 0x60)
    return bytes(c)


class Ftp:
    def _do(self, fn):
        with FTP(HOST, timeout=15) as f:
            f.login()
            return fn(f)

    def listdir(self):
        """None if TEST_DIR does not exist. NLST alone cannot say: on the
        Ultimate's server it answers [] for a missing directory; CWD fails."""
        def go(f):
            try:
                f.cwd(TEST_DIR)
            except error_perm:
                return None
            return sorted(n.rsplit("/", 1)[-1] for n in f.nlst(TEST_DIR))
        return self._do(go)

    def get(self, path):
        buf = bytearray()
        try:
            self._do(lambda f: f.retrbinary(f"RETR {path}", buf.extend))
        except error_perm:
            return None
        return bytes(buf)

    def put(self, path, data):
        self._do(lambda f: f.storbinary(f"STOR {path}", io.BytesIO(data)))

    def delete(self, name):
        def go(f):
            try:
                f.delete(f"{TEST_DIR}/{name}")
            except error_perm:
                pass
        self._do(go)

    def mkdir(self):
        self._do(lambda f: f.mkd(TEST_DIR))

    def rmdir(self):
        self._do(lambda f: f.rmd(TEST_DIR))


class Rig:
    def __init__(self, tr, client, L, prg, alloc):
        self.tr, self.client, self.L, self.prg = tr, client, L, prg
        (self.a, self.rec, self.host, self.op, self.sent, self.ra,
         self.rp) = alloc
        self.code = build_routine(L, self.a, self.rec, self.host, self.op,
                                  self.sent, self.ra, self.rp)
        self.passed = 0
        self.failed = []
        self.notes = {}
        self.ftp = Ftp()

    def require(self, cond, what):
        """A check every later phase depends on: stop the run if it fails."""
        self.check(cond, what)
        if not cond:
            raise RuntimeError(f"stopping: {what} failed")

    def check(self, cond, what):
        if cond:
            self.passed += 1
            print(f"    ok   {what}")
        else:
            self.failed.append(what)
            print(f"    FAIL {what}")

    def boot(self):
        self.client.reset()
        time.sleep(2.5)
        load_verified_and_run(self.client, self.prg)
        # Boot runs net_init (DHCP) before the menu; the store needs neither,
        # but 'q' must reach the menu, not the boot.
        deadline = time.monotonic() + (30.0 if SCALE == 1 else 180.0)
        while time.monotonic() < deadline:
            if self.tr.read_memory(self.L["net_initialized"], 1)[0]:
                break
            time.sleep(0.5)
        else:
            print("  note: net_initialized stayed 0 (the store does not need it)")
        time.sleep(2.0 * min(SCALE, 5))
        send_text(self.tr, "q\r")
        time.sleep(2.0 * min(SCALE, 5))
        self.tr.write_memory(self.a, self.code)
        if bytes(self.tr.read_memory(self.a, len(self.code))) != self.code:
            raise RuntimeError("routine read back wrong")

    def sys(self, op, *, host=None, rec=None, wait=True):
        if host is not None:
            self.tr.write_memory(self.host, host.encode("ascii") + b"\0")
        if rec is not None:
            self.tr.write_memory(self.rec, rec)
        self.tr.write_memory(self.op, bytes([op]))
        self.tr.write_memory(self.sent, b"\0")
        t0 = time.monotonic()
        send_text(self.tr, f"sys{self.a}\r")
        if not wait:
            return None
        budget = 30.0 if SCALE == 1 else 900.0
        deadline = t0 + budget
        while time.monotonic() < deadline:
            if self.tr.read_memory(self.sent, 1)[0] == SENT:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError(f"op {op} did not finish in {budget:.0f} s")
        took = time.monotonic() - t0
        p = self.tr.read_memory(self.rp, 1)[0]
        a = self.tr.read_memory(self.ra, 1)[0]
        return p & 1, a, took

    def state(self):
        r = lambda n, k=1: bytes(self.tr.read_memory(self.L[n], k))  # noqa: E731
        st = {"state": r("ts_state")[0], "reason": r("ts_reason")[0],
              "slot": r("ts_slot")[0], "gen": int.from_bytes(r("ts_gen", 2), "little"),
              "slot_st": tuple(r("ts_slot_st", 2)), "found": r("ts_found")[0],
              "rec": r("ts_rec", 64)}
        n = r("uci_status_len")[0]
        st["status"] = r("uci_status_buf", min(n, 16)).decode("latin1") if n else ""
        return st

    def load(self, host):
        c, a, took = self.sys(OP_LOAD, host=host)
        st = self.state()
        print(f"  load({host}) C={c} A={a} {ts.STATE_NAMES.get(st['state'])} "
              f"reason={ts.REASON_NAMES.get(st['reason'])} slot={'AB'[st['slot'] & 1]} "
              f"gen={st['gen']} slot_st={[ts.REASON_NAMES.get(x, x) for x in st['slot_st']]} "
              f"found={st['found']} status={st['status']!r} ({took:.2f} s incl. SYS)")
        return c, a, st

    def save(self, host, rec):
        c, a, took = self.sys(OP_SAVE, rec=rec.pack())
        st = self.state()
        print(f"  save({host}) C={c} reason={ts.REASON_NAMES.get(st['reason'])} "
              f"slot={'AB'[st['slot'] & 1]} gen={st['gen']} status={st['status']!r} "
              f"({took:.2f} s incl. SYS)")
        return c, st

    def files(self):
        return self.ftp.get(A_PATH), self.ftp.get(B_PATH)


def rec(host, spki=SPKI_1):
    return ts.Record.for_host(host, spki)


def run_phases(r: Rig):
    ftp = r.ftp
    print("\n[1] load, empty directory")
    c, a, st = r.load("github.com")
    r.require(c == 0 and a == ts.ST_EMPTY and st["slot_st"] == (1, 1), "EMPTY, C=0")

    print("\n[2] save github.com")
    fa, fb = r.files()
    want = ts.save(fa, fb, "github.com", rec("github.com"))
    c, st = r.save("github.com", rec("github.com"))
    fa, fb = r.files()
    r.require(c == 0 and (st["state"], st["slot"], st["gen"]) == (ts.ST_VALID, 0, 1),
              "saved: VALID, slot A, generation 1")
    r.check(fa == want[1] and fb is None, "TRUST.A on the stick == the mirror; no TRUST.B")

    print("\n[3] load GitHub.COM")
    c, a, st = r.load("GitHub.COM")
    r.check(c == 0 and st["found"] == 1 and st["rec"] == rec("github.com").pack(),
            "VALID, record found case-insensitively, bytes exact")

    print("\n[4] save lwn.net")
    want = ts.save(fa, fb, "lwn.net", rec("lwn.net", SPKI_2))
    r.load("lwn.net")
    c, st = r.save("lwn.net", rec("lwn.net", SPKI_2))
    fa2, fb2 = r.files()
    r.check(c == 0 and (st["slot"], st["gen"]) == (1, 2), "saved to slot B, generation 2")
    r.check(fb2 == want[1] and fa2 == fa, "TRUST.B == mirror; TRUST.A untouched")

    print("\n[5] torn write into TRUST.A (open for write, 100 B, no close, reset)")
    c, a, st = r.load("lwn.net")                    # TS_BUF = TRUST.B's image
    r.check(st["slot"] == 1, "loaded slot B (the tear targets A)")
    pre_b = fb2
    rp, ra, took = r.sys(OP_TEAR)
    ra &= 1                                         # the write's carry
    torn_open = ftp.get(A_PATH)
    r.notes["torn_open_c"], r.notes["torn_write_c"] = rp, ra
    r.notes["torn_A_size_before_reset"] = None if torn_open is None else len(torn_open)
    print(f"  dos_open C={rp} dos_write C={ra}; TRUST.A over FTP before the reset: "
          f"{r.notes['torn_A_size_before_reset']} B")
    r.check(rp == 0 and ra == 0, "the torn open + write were accepted")
    r.client.reset()
    time.sleep(3.0)
    torn = ftp.get(A_PATH)
    r.notes["torn_A_size_after_reset"] = None if torn is None else len(torn)
    print(f"  TRUST.A after the reset: {r.notes['torn_A_size_after_reset']} B")
    r.check(ftp.get(B_PATH) == pre_b, "TRUST.B (the loaded slot) is byte-identical")
    r.check(torn is not None and ts.slot_result(torn) != ts.SLOT_OK,
            "TRUST.A is damaged, as DECISIONS #6 predicts")

    print("\n[6] reload the PRG; load after the torn write")
    r.boot()
    c, a, st = r.load("lwn.net")
    torn_after = ftp.get(A_PATH)
    r.notes["torn_A_size_after_load"] = None if torn_after is None else len(torn_after)
    print(f"  TRUST.A after the load's close-first: {r.notes['torn_A_size_after_load']} B")
    r.check(c == 0 and (st["state"], st["slot"], st["gen"]) == (ts.ST_VALID, 1, 2)
            and st["found"] == 1, "VALID from TRUST.B, generation 2, record found")
    r.check(st["slot_st"][0] in (ts.R_FORMAT, ts.R_CHECKSUM),
            f"torn TRUST.A reported {ts.REASON_NAMES.get(st['slot_st'][0])}")

    print("\n[7] save example.com repairs TRUST.A")
    fa, fb = r.files()
    want = ts.save(fa, fb, "example.com", rec("example.com"))
    r.load("example.com")
    c, st = r.save("example.com", rec("example.com"))
    fa, fb = r.files()
    r.check(c == 0 and (st["slot"], st["gen"]) == (0, 3), "saved to slot A, generation 3")
    r.check(fa == want[1] and fb == pre_b, "TRUST.A == mirror; TRUST.B untouched")

    print("\n[8] corrupt TRUST.B")
    bad_b = bytearray(fb)
    bad_b[20] ^= 0x01
    ftp.put(B_PATH, bytes(bad_b))
    c, a, st = r.load("example.com")
    r.check(c == 0 and (st["state"], st["slot"], st["gen"]) == (ts.ST_VALID, 0, 3)
            and st["slot_st"][1] == ts.R_CHECKSUM, "VALID from A; B reported CHECKSUM")

    print("\n[9] corrupt both; then one corrupt beside an absent one")
    bad_a = bytearray(fa)
    bad_a[-1] ^= 0x80
    ftp.put(A_PATH, bytes(bad_a))
    c, a, st = r.load("example.com")
    r.check(c == 1 and a == ts.ST_FAIL and st["reason"] == ts.R_CHECKSUM,
            "both corrupt: FAIL CHECKSUM")
    ftp.delete("TRUST.A")
    c, a, st = r.load("example.com")
    r.check(c == 1 and st["reason"] == ts.R_CHECKSUM and st["slot_st"][0] == ts.SLOT_ABSENT,
            "absent + corrupt: FAIL CHECKSUM (not EMPTY)")

    print("\n[10] neither file")
    ftp.delete("TRUST.B")
    c, a, st = r.load("example.com")
    r.check(c == 0 and a == ts.ST_EMPTY, "EMPTY")

    print("\n[11] unknown version")
    v2 = bytearray(ts.encode(1, [rec("example.com")]))
    v2[4] = 2
    ftp.put(A_PATH, bytes(v2))
    c, a, st = r.load("example.com")
    r.check(c == 1 and st["reason"] == ts.R_VERSION, "FAIL VERSION")
    ftp.delete("TRUST.A")

    print("\n[12] 32 records: a 2,064 B image")
    full = ts.encode(40, [rec(f"h{i}.example") for i in range(32)])
    ftp.put(A_PATH, full)
    c, a, st = r.load("h31.example")
    r.check(c == 0 and st["found"] == 1 and st["rec"] == rec("h31.example").pack(),
            "record 32 of 32 found (five 512 B read parts)")
    want = ts.save(full, None, "h31.example", rec("h31.example", SPKI_2))
    c, st = r.save("h31.example", rec("h31.example", SPKI_2))
    fa, fb = r.files()
    r.check(c == 0 and fb == want[1] and len(fb) == ts.FILE_MAX,
            "2,064 B TRUST.B == mirror (nine write chunks)")
    r.load("new.example")
    c, st = r.save("new.example", rec("new.example"))
    r.check(c == 1 and st["reason"] == ts.R_FULL, "33rd record refused: FULL")
    ftp.delete("TRUST.A")
    ftp.delete("TRUST.B")

    if TURBO_MHZ == 1:
        print("\n[13] reset DURING trust_store_save's write (1 MHz)")
        base = ts.encode(5, [rec("a.example"), rec("b.example"), rec("c.example")])
        ftp.put(A_PATH, base)
        c, a, st = r.load("d.example")
        r.check(c == 0 and st["slot"] == 0, "loaded generation 5 from A")
        r.tr.write_memory(r.L["ts_target"], b"\xff")
        r.tr.write_memory(r.rec, rec("d.example").pack())
        r.sys(OP_SAVE, wait=False)
        hit = None
        t0 = time.monotonic()
        while time.monotonic() - t0 < 120:
            tgt = r.tr.read_memory(r.L["ts_target"], 1)[0]
            dl = bytes(r.tr.read_memory(r.L["dos_len"], 2))
            if tgt != 0xFF and dl == b"\0\0":
                r.client.reset()
                hit = time.monotonic() - t0
                break
            if r.tr.read_memory(r.sent, 1)[0] == SENT:
                break
            time.sleep(0.02)
        time.sleep(3.0)
        fa, fb = r.files()
        r.notes["midsave_reset_at_s"] = hit
        r.notes["midsave_B_size"] = None if fb is None else len(fb)
        if hit is None:
            print("  INCONCLUSIVE: the poll missed the write window")
            r.notes["midsave"] = "missed"
        else:
            print(f"  reset {hit:.2f} s after SYS; TRUST.B now "
                  f"{r.notes['midsave_B_size']} B")
            r.check(fa == base, "TRUST.A (loaded) byte-identical after the reset")
            r.boot()
            c, a, st = r.load("d.example")
            r.check(c == 0 and (st["slot"], st["gen"]) == (0, 5) and st["found"] == 0,
                    "after the reset: VALID generation 5 from A, d.example absent")
        ftp.delete("TRUST.A")
        ftp.delete("TRUST.B")

    print("\n[14] no directory")
    ftp.rmdir()
    c, a, st = r.load("example.com")
    r.check(c == 1 and st["reason"] == ts.R_NOPATH, "FAIL NOPATH")


def main() -> int:
    if not PRG_PATH.is_file() or not LABELS_PATH.is_file():
        return cannot_run("build/c64-https.prg or labels.txt missing (see the docstring)",
                          executed=0, total=None, certifies=CERTIFIES)
    L = load_labels()
    missing = [n for n in NEEDED if n not in L]
    if missing:
        return cannot_run(f"not a TRUST_STORE=1 build (missing {missing})",
                          executed=0, total=None, certifies=CERTIFIES)
    prg = PRG_PATH.read_bytes()
    path = image_store_path(prg, L)
    if path != TEST_DIR + "/TRUST.":
        return cannot_run(f"the image stores at {path!r}; this rig only runs against "
                          f"TRUST_STORE_DIR={TEST_DIR}", executed=0, total=None,
                          certifies=CERTIFIES)
    policy, arbiter = build_policy_and_low_ram_arbiter(LABELS_PATH, PRG_PATH)
    code_len = len(build_routine(L, 0x0400, 0, 0, 0, 0, 0, 0))
    alloc = (arbiter.alloc(code_len, name="routine"), arbiter.alloc(64, name="record"),
             arbiter.alloc(16, name="host"), arbiter.alloc(1, name="op"),
             arbiter.alloc(1, name="sentinel"), arbiter.alloc(1, name="result_a"),
             arbiter.alloc(1, name="result_p"))
    sha = hashlib.sha256(prg).hexdigest()
    print(f"PRG sha256 {sha}\nstore {path}A/B; routine {code_len} B @ ${alloc[0]:04X}; "
          f"{TURBO_MHZ} MHz; device {HOST}")

    lock = DeviceLock(HOST)
    try:
        acquire_device_lock(lock)
    except LockTimeoutConfigError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 3
    run_dir = REPO / "build" / "rig_trust_store" / time.strftime("%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    client = tr = rig = None
    uci_enabled = False
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        tr = Ultimate64Transport(host=HOST, timeout=15.0, client=client)
        tr.memory_policy = policy
        ftp = Ftp()
        listing = ftp.listdir()
        if listing is None:
            ftp.mkdir()
        elif set(listing) - set(OURS):
            return cannot_run(f"{TEST_DIR} holds files that are not the rig's: {listing}",
                              executed=0, total=None, certifies=CERTIFIES)
        for n in OURS:
            ftp.delete(n)
        enable_uci(client)
        uci_enabled = True
        gc_temp(HOST)
        try:
            prepare_device(client, LABELS_PATH, turbo_mhz=TURBO_MHZ, artifact_dir=run_dir)
            preflight_reu(client, LABELS_PATH)
        except (DevicePrepError, ReuPreflightError) as exc:
            print(str(exc), file=sys.stderr)
            return 4
        rig = Rig(tr, client, L, prg, alloc)
        try:
            rig.boot()
        except PrgLoadError as exc:
            print(f"[fatal] {exc}", file=sys.stderr)
            return 4
        try:
            run_phases(rig)
        except RuntimeError as exc:
            rig.failed.append(str(exc))
            print(f"\n{exc}")
    finally:
        if rig is not None:
            summary = {"prg_sha256": sha, "turbo_mhz": TURBO_MHZ, "host": HOST,
                       "passed": rig.passed, "failed": rig.failed, "notes": rig.notes}
            (run_dir / "result.json").write_text(json.dumps(summary, indent=1))
            print(f"\nnotes: {json.dumps(rig.notes)}\nartifacts: {run_dir}")
        try:
            ftp = Ftp()
            for n in OURS:
                ftp.delete(n)
            if ftp.listdir() == []:
                ftp.rmdir()
            print(f"cleanup: {TEST_DIR} -> {ftp.listdir()}")
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: cleanup of {TEST_DIR} failed: {exc}")
        if client is not None:
            try:
                if uci_enabled:
                    disable_uci(client)
                client.reset()
            except Exception as exc:  # noqa: BLE001
                print(f"WARNING: teardown: {exc}")
        try:
            gc_temp(HOST)
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: gc_temp: {exc}")
        lock.release()
    return verdict(rig.passed, len(rig.failed), certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
