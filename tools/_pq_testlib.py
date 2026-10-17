"""tools/_pq_testlib.py - shared pieces of the PQ_HYBRID P4 suites.

  test_pq_sh.py    the ServerHello machine, fast (no ML-KEM, no X25519)
  test_pq_kem.py   KeyGen / Decaps / the full tls_recv_server_hello path, slow

Not a test module (no test_ prefix, no run_tests): helpers only.
"""

import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "libs" / "mlkem" / "tools"))

from c64_test_harness import (  # noqa: E402
    Labels, ViceInstanceManager, jsr, read_bytes, write_bytes, wait_for_text,
)
from _vice_helpers import default_vice_config, menu_wait  # noqa: E402

PRG = REPO / "build" / "c64-https.prg"
LABELS = REPO / "build" / "labels.txt"
PQ_ARGS = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=1"]

# tls_sh_err codes (src/constants.inc)
E_HRR, E_RECTYPE, E_HDR, E_FIXED, E_EXTLEN = 1, 2, 3, 4, 5
E_VERSION, E_GROUP, E_KSLEN, E_TRAIL, E_MISSING = 6, 7, 8, 9, 10
E_DECAPS, E_KEYGEN, E_EXT, E_RECORD = 11, 12, 13, 14

HRR_MAGIC = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
GROUP_HYB, GROUP_X = 0x11EC, 0x001D
CT_LEN, EK_LEN = 1088, 1184


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
            if os.environ.get("C64_FAIL_FAST") == "1":      # tools/mutate_pq_sh.py
                sys.stdout.flush()
                raise SystemExit(1)
        return ok


def make(args=None, extra=(), clean=True):
    if clean:
        subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
    r = subprocess.run(["make"] + list(args or PQ_ARGS) + list(extra), cwd=REPO,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def require_pq_image():
    """None if build/ holds a PQ_HYBRID P4 image, else the reason it does not
    (callers route it to cannot_run: exit 2, never a KeyError traceback)."""
    if not PRG.exists() or not LABELS.exists():
        return f"{PRG} / {LABELS} missing: build with PQ_HYBRID=1 first"
    names = set()
    for ln in LABELS.read_text().splitlines():
        p = ln.split()
        if len(p) >= 3:
            names.add(p[2].lstrip("."))
    for n in ("pq_sh_feed", "pq_connect_prep", "pq_mlkem_scrub"):
        if n not in names:
            return (f"the build in build/ is not a PQ_HYBRID=1 P4 image (no {n}); "
                    "build BACKEND=uci USE_NISTCURVES_ONCHIP=1 PQ_HYBRID=1")
    return None


def build_or_reuse():
    """Build the PQ uci-onchip image unless C64_SKIP_BUILD=1 (the suite then
    reuses build/, which must be that image)."""
    if os.environ.get("C64_SKIP_BUILD") == "1" and PRG.exists():
        return 0, ""
    return make()


# --------------------------------------------------------------------------
# ServerHello builders
# --------------------------------------------------------------------------
def ext(t, data):
    return struct.pack(">HH", t, len(data)) + data


def sv_ext(v=b"\x03\x04"):
    return ext(0x2B, v)


def ks_ext(group, key):
    return ext(0x33, struct.pack(">HH", group, len(key)) + key)


def sh_message(exts, random=None, version=b"\x03\x03", sid=b"", suite=b"\x13\x03",
               comp=b"\x00", hdr_type=2, ext_len=None, msg_len=None, len_top=0):
    """A ServerHello handshake message; every field overridable so a refusal
    case can break exactly one thing."""
    if random is None:
        random = bytes((7 * i + 3) & 255 for i in range(32))
    el = len(exts) if ext_len is None else ext_len
    body = (version + random + bytes([len(sid)]) + sid + suite + comp
            + struct.pack(">H", el) + exts)
    ml = len(body) if msg_len is None else msg_len
    return bytes([hdr_type, len_top]) + struct.pack(">H", ml) + body


def split_at(data, cuts, maxrec=512):
    """Records: data cut at *cuts* (sorted offsets), each piece further cut
    into <= maxrec bytes."""
    out, prev = [], 0
    for c in list(cuts) + [len(data)]:
        piece = data[prev:c]
        for i in range(0, len(piece), maxrec):
            out.append(piece[i:i + maxrec])
        prev = c
    return out


def chunks(data, sizes):
    """Cut *data* into pieces of the given sizes (the last size repeats)."""
    out, i, k = [], 0, 0
    while i < len(data):
        n = sizes[min(k, len(sizes) - 1)]
        out.append(data[i:i + n])
        i += n
        k += 1
    return out


# --------------------------------------------------------------------------
# X25519 (RFC 7748), host side
# --------------------------------------------------------------------------
_P = 2 ** 255 - 19


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * ((da - cb) ** 2) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + 121665 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def x25519_pub(sk):
    return x25519(sk, (9).to_bytes(32, "little"))


# --------------------------------------------------------------------------
# VICE session
# --------------------------------------------------------------------------
class Session:
    """One VICE boot of the PQ image with the page-3 call stub."""
    RES = 0x03B0            # +0 A, +1 P after the call
    STUB = 0x03C0

    def __init__(self, prg=PRG, reu=True):
        self.labels = Labels.from_file(str(LABELS))
        self.config = default_vice_config(prg_path=str(prg), warp=True,
                                          ntsc=True, sound=False)
        self.mgr = None
        self.tr = None

    def __enter__(self):
        self.mgr = ViceInstanceManager(config=self.config)
        self.mgr.__enter__()
        self.inst = self.mgr.acquire()
        self.tr = self.inst.transport
        if wait_for_text(self.tr, "Q=QUIT", timeout=menu_wait(60),
                         verbose=False) is None:
            raise RuntimeError("the menu never appeared")
        return self

    def __exit__(self, *exc):
        try:
            self.mgr.release(self.inst)
        finally:
            self.mgr.__exit__(*exc)

    def L(self, name):
        return self.labels[name]

    def rd(self, addr, n):
        return bytes(read_bytes(self.tr, addr, n))

    def wr(self, addr, data):
        write_bytes(self.tr, addr, bytes(data))

    def call(self, name, timeout=900.0):
        """jsr *name*; return (A, P)."""
        w = self.L(name)
        stub = bytes([0x20, w & 255, w >> 8,
                      0x8D, self.RES & 255, self.RES >> 8,
                      0x08, 0x68,
                      0x8D, (self.RES + 1) & 255, self.RES >> 8,
                      0x60])
        self.wr(self.STUB, stub)
        jsr(self.tr, self.STUB, timeout=timeout)
        a, p = self.rd(self.RES, 2)
        return a, p

    def call_port(self, name, iflag, timeout=1800.0):
        """jsr *name* entered with the I flag clear (iflag=0, cli) or set
        (iflag=1, sei). Returns (A, P_after, port_after): P and $01 as the
        routine left them. NOTE: a routine that leaks $01 = $34 AND leaves I
        clear livelocks on the first IRQ (the RTI vector acknowledges nothing),
        so callers check $01 under iflag=1 first and only then enter with I clear. The explicit restore checks of pq_mlkem_scrub's
        callers read these (a leaked $01 = $34 or I flag fails an assertion
        instead of hanging the next monitor access)."""
        w = self.L(name)
        r = self.RES
        stub = bytes([0x78 if iflag else 0x58,
                      0x20, w & 255, w >> 8,
                      0x8D, r & 255, r >> 8,            # sta RES   (A)
                      0x08, 0x68,                       # php / pla
                      0x8D, (r + 1) & 255, r >> 8,      # sta RES+1 (P)
                      0xA5, 0x01,                       # lda $01
                      0x8D, (r + 2) & 255, r >> 8,      # sta RES+2
                      0x60])
        self.wr(self.STUB, stub)
        jsr(self.tr, self.STUB, timeout=timeout)
        a, p, port = self.rd(r, 3)
        return a, p, port

    # --- the reader's state, as the tests see it ---
    def feed(self, rec, rtype=0x16):
        """Put *rec* in the record buffer and run pq_sh_feed. Returns
        (carry, zero)."""
        assert len(rec) <= 548
        self.wr(self.L("tls_rec_buf"), rec)
        self.wr(self.L("tls_rec_len"), [len(rec) & 255, len(rec) >> 8])
        self.wr(self.L("tls_rec_type"), [rtype])
        a, p = self.call("pq_sh_feed")
        return p & 1, (p >> 1) & 1

    def begin(self, offered=True):
        self.call("tls_transcript_init")
        self.wr(self.L("tls_pq_offered"), [1 if offered else 0])
        self.call("pq_sh_init")

    # RAM under the I/O page and the ROMs: bank to all-RAM around the access
    def ram_rd(self, addr, n):
        old = self.rd(1, 1)
        self.wr(1, b"\x34")
        try:
            return self.rd(addr, n)
        finally:
            self.wr(1, old)

    def ram_wr(self, addr, data):
        old = self.rd(1, 1)
        self.wr(1, b"\x34")
        try:
            self.wr(addr, data)
        finally:
            self.wr(1, old)

    def err(self):
        return self.rd(self.L("tls_sh_err"), 1)[0]

    def group(self):
        return self.rd(self.L("tls_kex_group"), 1)[0]

    def transcript(self):
        self.call("tls_transcript_hash")
        return self.rd(self.L("tls_transcript"), 32)


def ref_secret_pair(seed_d, seed_z):
    import mlkem_ref as R
    return R.mlkem_keygen(seed_d, seed_z)
