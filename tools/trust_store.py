#!/usr/bin/env python3
"""trust_store.py -- host-side mirror of the C64 TOFU trust store (#155 phase 2).

The on-C64 side is src/net/uci/trust_store.s; the format and every result
code are defined in src/trust_store.inc. This module reads, writes and
selects slots the same way, for tests and tooling. It is a MIRROR, not a
spec: where the two disagree, the 6502 is what ships, and
tools/test_trust_store_6502.py runs the 6502 against this module.

File (one slot):

    header   8 B   b"C6TS", version 1, generation (u16 LE), N
    records  N x 64 B
    trailer  8 B   SHA-256(header || records)[:8]  -- a checksum, not a MAC

Record (64 B): host key 16 | SPKI SHA-256 32 | mode 1 | flags 1 |
use count u16 LE | display prefix 12.

The host key is SHA-256 of the host with A-Z (bytes 0x41-0x5A) lowered and
nothing else changed, first 16 bytes -- exactly what the 6502 does.

CLI::

    python3 tools/trust_store.py dump TRUST.A [TRUST.B]
    python3 tools/trust_store.py key github.com
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INC = REPO / "src" / "trust_store.inc"

MAGIC = b"C6TS"
VERSION = 1
HDR_SIZE = 8
REC_SIZE = 64
SUM_SIZE = 8
KEY_SIZE = 16
MAX_RECS = 32
FILE_MAX = HDR_SIZE + MAX_RECS * REC_SIZE + SUM_SIZE

MODE_TOFU = 1
MODE_ACCEPTED = 2
MODE_OVERRIDE = 3

ST_NONE = 0
ST_VALID = 1
ST_EMPTY = 2
ST_FAIL = 3

SLOT_OK = 0
SLOT_ABSENT = 1
R_NOPATH = 2
R_DOS = 3
R_IO = 4
R_FORMAT = 5
R_VERSION = 6
R_CHECKSUM = 7
R_TIE = 8
R_BUSY = 9
R_NOTREADY = 10
R_CHANGED = 11
R_FULL = 12
R_WRITE = 13
R_VERIFY = 14
R_COLD = 15

REASON_NAMES = {
    SLOT_OK: "OK", SLOT_ABSENT: "ABSENT", R_NOPATH: "NOPATH", R_DOS: "DOS",
    R_IO: "IO", R_FORMAT: "FORMAT", R_VERSION: "VERSION",
    R_CHECKSUM: "CHECKSUM", R_TIE: "TIE", R_BUSY: "BUSY",
    R_NOTREADY: "NOTREADY", R_CHANGED: "CHANGED", R_FULL: "FULL",
    R_WRITE: "WRITE", R_VERIFY: "VERIFY", R_COLD: "COLD",
}
STATE_NAMES = {ST_NONE: "NONE", ST_VALID: "VALID", ST_EMPTY: "EMPTY",
               ST_FAIL: "FAIL"}

# Python name -> the .inc equate it must equal (checked by the format test).
INC_NAMES = {
    "VERSION": "TS_VERSION", "HDR_SIZE": "TS_HDR_SIZE",
    "REC_SIZE": "TS_REC_SIZE", "SUM_SIZE": "TS_SUM_SIZE",
    "KEY_SIZE": "TS_KEY_SIZE", "MAX_RECS": "TS_MAX_RECS",
    "MODE_TOFU": "TS_MODE_TOFU", "MODE_ACCEPTED": "TS_MODE_ACCEPTED",
    "MODE_OVERRIDE": "TS_MODE_OVERRIDE",
    "ST_NONE": "TS_ST_NONE", "ST_VALID": "TS_ST_VALID",
    "ST_EMPTY": "TS_ST_EMPTY", "ST_FAIL": "TS_ST_FAIL",
    "SLOT_OK": "TS_SLOT_OK", "SLOT_ABSENT": "TS_SLOT_ABSENT",
    "R_NOPATH": "TS_R_NOPATH", "R_DOS": "TS_R_DOS", "R_IO": "TS_R_IO",
    "R_FORMAT": "TS_R_FORMAT", "R_VERSION": "TS_R_VERSION",
    "R_CHECKSUM": "TS_R_CHECKSUM", "R_TIE": "TS_R_TIE",
    "R_BUSY": "TS_R_BUSY", "R_NOTREADY": "TS_R_NOTREADY",
    "R_CHANGED": "TS_R_CHANGED", "R_FULL": "TS_R_FULL",
    "R_WRITE": "TS_R_WRITE", "R_VERIFY": "TS_R_VERIFY",
    "R_COLD": "TS_R_COLD",
}


def parse_inc(path: Path = INC) -> dict:
    """The numeric `NAME = value` equates of src/trust_store.inc."""
    out = {}
    for line in path.read_text().splitlines():
        m = re.match(r"\s*([A-Z0-9_]+)\s*=\s*([^;]+?)\s*(;.*)?$", line)
        if not m:
            continue
        name, expr = m.group(1), m.group(2)
        expr = re.sub(r"'(.)'", lambda c: str(ord(c.group(1))), expr)
        expr = expr.replace("$", "0x")
        try:
            out[name] = eval(expr, {}, dict(out))  # noqa: S307 (our own file)
        except Exception:  # noqa: BLE001
            pass
    return out


def lower_ascii(host: bytes) -> bytes:
    return bytes(b | 0x20 if 0x41 <= b <= 0x5A else b for b in host)


def host_key(host) -> bytes:
    if isinstance(host, str):
        host = host.encode("ascii")
    return hashlib.sha256(lower_ascii(host)).digest()[:KEY_SIZE]


def checksum(body: bytes) -> bytes:
    return hashlib.sha256(body).digest()[:SUM_SIZE]


@dataclass
class Record:
    key: bytes
    spki: bytes
    mode: int = MODE_TOFU
    flags: int = 0
    uses: int = 0
    display: bytes = b""

    @classmethod
    def for_host(cls, host, spki: bytes, **kw) -> "Record":
        if "display" not in kw:
            h = host.encode("ascii") if isinstance(host, str) else host
            kw["display"] = h[:12]
        return cls(host_key(host), spki, **kw)

    def pack(self) -> bytes:
        if len(self.key) != KEY_SIZE or len(self.spki) != 32:
            raise ValueError("key must be 16 B and spki 32 B")
        disp = self.display[:12].ljust(12, b"\x00")
        return (self.key + self.spki
                + struct.pack("<BBH", self.mode, self.flags, self.uses) + disp)

    @classmethod
    def unpack(cls, raw: bytes) -> "Record":
        mode, flags, uses = struct.unpack_from("<BBH", raw, 48)
        return cls(raw[:16], raw[16:48], mode, flags, uses, raw[52:64])


def encode(gen: int, records) -> bytes:
    records = list(records)
    if len(records) > 255:
        raise ValueError("N is one byte")
    body = (MAGIC + bytes([VERSION]) + struct.pack("<H", gen & 0xFFFF)
            + bytes([len(records)])
            + b"".join(r.pack() if isinstance(r, Record) else bytes(r)
                       for r in records))
    return body + checksum(body)


class StoreError(ValueError):
    def __init__(self, code: int, detail: str = ""):
        super().__init__(f"{REASON_NAMES.get(code, code)}: {detail}")
        self.code = code


def decode(data: bytes):
    """-> (generation, [Record]); raises StoreError with the 6502's code.

    Checks run in the 6502's order, so a file that is wrong in two ways
    reports the same code on both sides: size floor, magic, version, size
    == 16 + 64 * N, checksum. A file larger than FILE_MAX is FORMAT, as on
    the C64 (it reads FILE_MAX + 1 bytes and the size then cannot match).
    """
    data = bytes(data)[:FILE_MAX + 1]
    if len(data) < HDR_SIZE + SUM_SIZE:
        raise StoreError(R_FORMAT, f"{len(data)} B is shorter than a header")
    if data[:4] != MAGIC:
        raise StoreError(R_FORMAT, f"magic {data[:4]!r}")
    if data[4] != VERSION:
        raise StoreError(R_VERSION, f"version {data[4]}")
    n = data[7]
    size = HDR_SIZE + n * REC_SIZE + SUM_SIZE
    if len(data) != size:
        raise StoreError(R_FORMAT, f"{len(data)} B, header says N={n} ({size} B)")
    body = data[:-SUM_SIZE]
    if checksum(body) != data[-SUM_SIZE:]:
        raise StoreError(R_CHECKSUM, "trailer mismatch")
    gen = struct.unpack_from("<H", data, 5)[0]
    recs = [Record.unpack(data[HDR_SIZE + i * REC_SIZE:HDR_SIZE + (i + 1) * REC_SIZE])
            for i in range(n)]
    return gen, recs


def slot_result(slot) -> int:
    """A slot as the C64 sees it: None = FILE DOESN'T EXIST, an int = that
    open failure code (R_NOPATH, R_DOS, R_IO), bytes = the file's content."""
    if slot is None:
        return SLOT_ABSENT
    if isinstance(slot, int):
        return slot
    try:
        decode(slot)
    except StoreError as e:
        return e.code
    return SLOT_OK


# What may sit beside a valid slot: a first save (absent) or a torn save
# (a partial file). An open/read failure or an unknown version may be the
# newer slot, so it fails closed (ts_tolerable in trust_store.s).
TOLERABLE = (SLOT_ABSENT, R_FORMAT, R_CHECKSUM)


def serial_newer(a: int, b: int):
    """True if b is newer than a, False if a is, None if neither (RFC 1982,
    16 bits: equal, or exactly 0x8000 apart)."""
    d = (b - a) & 0xFFFF
    if d == 0 or d == 0x8000:
        return None
    return d < 0x8000


@dataclass
class Selection:
    state: int
    reason: int = SLOT_OK
    slot: int = 1           # EMPTY: 1, so that a save writes slot A
    gen: int = 0
    records: list = None
    slot_st: tuple = (0, 0)


def select(slot_a, slot_b) -> Selection:
    """The 6502's ts_scan, over two slot contents (see slot_result)."""
    st = (slot_result(slot_a), slot_result(slot_b))
    slots = (slot_a, slot_b)
    if st[0] == SLOT_OK and st[1] == SLOT_OK:
        ga, gb = decode(slot_a)[0], decode(slot_b)[0]
        newer = serial_newer(ga, gb)
        if newer is None:
            return Selection(ST_FAIL, R_TIE, slot_st=st)
        pick = 1 if newer else 0
    elif st[0] == SLOT_OK or st[1] == SLOT_OK:
        pick = 0 if st[0] == SLOT_OK else 1
        other = st[pick ^ 1]
        if other not in TOLERABLE:
            return Selection(ST_FAIL, other, slot_st=st)
    elif st == (SLOT_ABSENT, SLOT_ABSENT):
        return Selection(ST_EMPTY, slot=1, gen=0, records=[], slot_st=st)
    else:
        reason = st[0] if st[0] != SLOT_ABSENT else st[1]
        return Selection(ST_FAIL, reason, slot_st=st)
    gen, recs = decode(slots[pick])
    return Selection(ST_VALID, SLOT_OK, pick, gen, recs, st)


def lookup(sel: Selection, host):
    if sel.state != ST_VALID:
        return None
    key = host_key(host)
    for r in sel.records:
        if r.key == key:
            return r
    return None


def save(slot_a, slot_b, host, record: Record):
    """The 6502's trust_store_save after a load of the same two slots.

    Returns (target_slot, new_file_bytes) or raises StoreError. The record's
    host key is forced to the host's, as trust_store_stage does.
    """
    sel = select(slot_a, slot_b)
    if sel.state not in (ST_VALID, ST_EMPTY):
        raise StoreError(R_NOTREADY, STATE_NAMES[sel.state])
    rec = Record(host_key(host), record.spki, record.mode, record.flags,
                 record.uses, record.display)
    recs = list(sel.records)
    for i, r in enumerate(recs):
        if r.key == rec.key:
            recs[i] = rec
            break
    else:
        if len(recs) >= MAX_RECS:
            raise StoreError(R_FULL, f"{len(recs)} records")
        recs.append(rec)
    return sel.slot ^ 1, encode((sel.gen + 1) & 0xFFFF, recs)


def _dump(paths):
    slots = []
    for p in paths:
        try:
            slots.append(Path(p).read_bytes())
        except FileNotFoundError:
            slots.append(None)
    for p, s in zip(paths, slots):
        code = slot_result(s)
        line = f"{p}: {REASON_NAMES[code]}"
        if code == SLOT_OK:
            gen, recs = decode(s)
            line += f", generation {gen}, {len(recs)} record(s)"
        print(line)
        if code == SLOT_OK:
            for r in decode(s)[1]:
                print(f"    key {r.key.hex()} spki {r.spki.hex()} mode {r.mode} "
                      f"flags {r.flags} uses {r.uses} "
                      f"display {r.display.rstrip(bytes(1))!r}")
    if len(slots) == 2:
        sel = select(*slots)
        print(f"selection: {STATE_NAMES[sel.state]}"
              + (f" slot {'AB'[sel.slot]} gen {sel.gen}" if sel.state == ST_VALID else "")
              + (f" reason {REASON_NAMES[sel.reason]}" if sel.state == ST_FAIL else ""))


def main(argv) -> int:
    if len(argv) >= 2 and argv[0] == "dump":
        _dump(argv[1:3])
        return 0
    if len(argv) == 2 and argv[0] == "key":
        print(host_key(argv[1]).hex())
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
