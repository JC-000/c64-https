#!/usr/bin/env python3
"""test_reu_body_sink.py -- the HTTP body sink stays inside its REU region.

WHAT THIS TESTS

http_sink_blit (src/http.s) used to STASH each 512 B bounce to
http_reu_body_base + cursor with no bound. REU addresses wrap: on a 512 KB
or 1 MB REU the default base $10:0000 IS bank 0, and on 16 MB the carry out
of the bank byte is dropped. A server's body then reached the multiply
rows (banks 0-1), comb's Lim-Lee table and the cold-code bank (bank 2), and
the next typed-target prompt ran the server's bytes.

On a uci-comb HTTPS_BODY_TO_REU=1 TRUST_STORE=1 image, on the repo's 6502
interpreter with a modelled REU (tools/_reu_model.py), at 512 KB, 1 MB and
16 MB and with no REU:

  * reu_probe_size finds the REU's size (and nothing, without one);
  * sink_room_init gives each base the region the probe allows: empty in
    banks 0-2 and 6-7, past the REU's end, or with no size established;
  * a blit that would cross the region's end writes NOTHING, latches
    http_sink_full, and every later blit is refused; one that ends exactly
    at the end is written;
  * adv-l5's attack (a body whose bytes, at the wrap offsets, are a forged
    cold-bank image with the marker and the XOR fixed): the REU's bank 2 is
    unchanged byte for byte -- Lim-Lee table and cold image -- and the next
    prompt runs the real prompt, not the server's code;
  * http_recv_timeout_verdict says C=1 for a refused body even when its
    Content-Length framing is otherwise satisfied.

The integrity check on the cold bank (marker + 8-bit XOR) is NOT what stops
this: a writer who knows the image can satisfy it. Bounding the writes is.

Usage:
    python3 tools/test_reu_body_sink.py      # make clean && make <comb demo TS>
    C64_SKIP_BUILD=1 python3 tools/test_reu_body_sink.py

Exit 0 pass, 1 fail, 2 could not run.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_cold_bank as tc                      # noqa: E402
import test_trust_store_6502 as t6               # noqa: E402
from test_trust_store_6502 import Env            # noqa: E402
from _reu_model import REU, Bus                  # noqa: E402
from _skip_policy import cannot_run, verdict     # noqa: E402

REPO = HERE.parent
PROFILE = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1",
           "HTTPS_HOST=en.wikipedia.org", "HTTPS_PATH=/wiki/Commodore_64",
           "HTTPS_BODY_TO_REU=1", "TRUST_STORE=1"]
CERTIFIES = "the HTTP body sink's REU-region bound (adv-l5 on #266)"
KB, MB = 1024, 1024 * 1024
PASSED = 0
FAILED: list[str] = []


def check(ok, msg):
    global PASSED
    if ok:
        PASSED += 1
    else:
        FAILED.append(msg)


class Box(tc.Rig):
    """test_cold_bank's machine, booted like boot.s: probe, then the bank."""

    def __init__(self, env, size=16 * MB, present=True, absent_status=0x00):
        super().__init__(env, init=False)
        self.reu = REU(self.ram, size=size, present=present,
                       absent_status=absent_status)
        self.m.reu = self.reu
        self.m.mem.uci = Bus(self.reu, self.dos)
        self.m.cpu.call(self.L["reu_probe_size"])
        self.m.cpu.call(self.L["cold_bank_init"])

    def u24(self, name):
        a = self.L[name]
        return self.ram[a] | self.ram[a + 1] << 8 | self.ram[a + 2] << 16

    def put24(self, name, v):
        a = self.L[name]
        self.ram[a:a + 3] = bytes([v & 0xFF, (v >> 8) & 0xFF, v >> 16])

    def body_begin(self, base):
        self.put24("http_reu_body_base", base)
        self.m.cpu.call(self.L["http_body_begin"])
        return self.u24("http_sink_room")

    def blit(self, cursor, data):
        """One bounce of `data` at `cursor`. -> the REU writes it made."""
        buf, ln = self.L["http_resp_buf"], self.L["http_resp_len"]
        self.ram[buf:buf + len(data)] = data
        self.ram[ln], self.ram[ln + 1] = len(data) & 0xFF, len(data) >> 8
        self.put24("http_reu_cursor", cursor)
        n = len(self.reu.log)
        self.m.cpu.call(self.L["http_sink_blit"])
        return [x for x in self.reu.log[n:] if x[0] == "stash"]


def case_probe(env):
    for size in (128 * KB, 256 * KB, 512 * KB, 1 * MB, 2 * MB, 16 * MB):
        b = Box(env, size=size)
        banks = size // (64 * KB)
        check(b.r8("reu_size_ok") == 1 and b.r8("reu_top_bank") == (banks - 1) & 0xFF,
              f"{size // KB} KB: probe says ok={b.r8('reu_size_ok')} "
              f"top={b.r8('reu_top_bank')}, want top {banks - 1}")
    for status in (0x00, 0xFF):
        b = Box(env, present=False, absent_status=status)
        room = b.body_begin(0x100000)
        check(room == 0, f"no REU (open bus ${status:02X}): region {room:#x}, want 0")


def case_regions(env):
    for size, base, want in [
        (512 * KB, 0x100000, 0),            # aliases bank 0: refused
        (1 * MB, 0x100000, 0),
        (16 * MB, 0x100000, 0xF00000),      # to the REU's end, no wrap
        (512 * KB, 0x030000, 0x030000),     # banks 3-5 (VICE tests)
        (512 * KB, 0x05F000, 0x001000),
        (16 * MB, 0x030000, 0x030000),      # stops below the P-384 banks
        (16 * MB, 0x080000, 0xF80000),
        (16 * MB, 0x020000, 0), (16 * MB, 0x02A000, 0),   # bank 2
        (16 * MB, 0x000000, 0), (16 * MB, 0x010000, 0),   # banks 0-1
        (16 * MB, 0x060000, 0), (16 * MB, 0x07FFFF, 0),   # banks 6-7
        (2 * MB, 0x200000, 0),              # past the end
    ]:
        b = Box(env, size=size)
        room = b.body_begin(base)
        check(room == want, f"{size // KB} KB base ${base:06X}: region {room:#x}, want {want:#x}")
        check(b.r8("http_sink_full") == 0, "body_begin left the latch set")


def case_bound(env):
    b = Box(env, size=512 * KB)
    room = b.body_begin(0x05F000)                    # 4 KB region
    data = bytes(range(256)) * 2
    w = b.blit(room - 512, data)
    check(len(w) == 1 and bytes(b.reu.mem[0x05F000 + room - 512:0x060000]) == data,
          f"a bounce ending exactly at the region's end was not written: {w}")
    p6 = bytes(b.reu.mem[0x060000:0x060200])
    w = b.blit(room - 511, data)
    check(not w and b.r8("http_sink_full") == 1,
          f"a bounce crossing the end by 1 B was written or not latched: {w}")
    check(bytes(b.reu.mem[0x060000:0x060200]) == p6, "bank 6 was written")
    w = b.blit(0, data)
    check(not w, "after the latch, a bounce inside the region was still written")
    b = Box(env, size=512 * KB)                       # fresh: no latch
    b.body_begin(0x05F000)
    w = b.blit(0xFFFF00, data)
    check(not w and b.r8("http_sink_full") == 1,
          "a cursor + length that wraps 24 bits was written")


def case_attack(env):
    """adv-l5's PoC: the forged cold image at the wrap offsets."""
    L = env.labels
    n = L["cold_marker_ui"] + 1 - L["__COLD_RUN_UI_START__"]
    for size, cursor in ((512 * KB, 0x2A000), (1 * MB, 0x2A000),
                         (16 * MB, 0xF2A000), (16 * MB, 0xF20000)):
        b = Box(env, size=size)
        bank2 = bytes(b.reu.mem[0x020000:0x030000])
        b.body_begin(0x100000)
        want = b.ram[L["cold_g_sum"]]
        code = bytes([0xA9, 0x42, 0x8D, 0x34, 0x03, 0x18, 0x60])
        body = bytearray(code + bytes(n - len(code)))
        body[-1] = tc.COLD_MARK
        x = 0
        for v in body[:-2]:
            x ^= v
        body[-2] = x ^ tc.COLD_MARK ^ want
        tag = f"{size // KB} KB cursor ${cursor:X}"
        w = b.blit(cursor, bytes(body))
        check(not w, f"{tag}: the forged image was written: {w}")
        check(bytes(b.reu.mem[0x020000:0x030000]) == bank2,
              f"{tag}: REU bank 2 (Lim-Lee + cold bank) changed")
        b.ram[0x0334] = 0
        b.set_states(0, 0)
        c, _ = b.prompt([])
        check(b.ram[0x0334] != 0x42 and not c,
              f"{tag}: the prompt ran server code (C={c}, $0334=${b.ram[0x0334]:02X})")


def case_verdict(env):
    """A refused body fails even when its Content-Length is satisfied."""
    b = Box(env, size=512 * KB)
    b.body_begin(0x05F000)
    b.blit(0x1000, bytes(512))                       # past the 4 KB region
    L = env.labels
    b.ram[L["http_parse_state"]] = 2
    b.ram[L["http_cl_valid"]] = 1
    b.put24("http_content_length", 5000)
    b.put24("http_body_total", 5000)
    c = b.m.cpu.call(L["http_recv_timeout_verdict"])
    check(c, "http_recv_timeout_verdict: C=0 for a body the sink refused")
    b.ram[L["http_sink_full"]] = 0                   # control: same framing
    c = b.m.cpu.call(L["http_recv_timeout_verdict"])
    check(not c, "control: C=1 for a complete Content-Length body")


CASES = [case_probe, case_regions, case_bound, case_attack, case_verdict]


def main() -> int:
    if os.environ.get("C64_SKIP_BUILD") != "1":
        subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
        p = subprocess.run(["make", *PROFILE], cwd=REPO, capture_output=True, text=True)
        if p.returncode != 0:
            return cannot_run(f"make {' '.join(PROFILE)} failed:\n{p.stdout[-1500:]}"
                              f"{p.stderr[-1500:]}", executed=0, total=len(CASES),
                              certifies=CERTIFIES)
    if not t6.PRG.is_file() or not t6.LABELS.is_file():
        return cannot_run("no build/c64-https.prg + labels.txt", executed=0,
                          total=len(CASES), certifies=CERTIFIES)
    env = Env()
    need = ("http_sink_blit", "cold_call", "http_sink_room", "reu_probe_size",
            "http_recv_timeout_verdict")
    missing = [n for n in need if n not in env.labels]
    if missing:
        return cannot_run(f"build/ is not a uci-comb sink + cold-bank image "
                          f"(no {', '.join(missing)})", executed=0,
                          total=len(CASES), certifies=CERTIFIES)
    print(f"PRG sha256 {hashlib.sha256(t6.PRG.read_bytes()).hexdigest()}")
    for case in CASES:
        before = len(FAILED)
        try:
            case(env)
        except (t6.CPUError, t6.Reset) as e:
            FAILED.append(f"{case.__name__}: {e}")
        print(f"{'PASS' if len(FAILED) == before else 'FAIL'} {case.__name__}")
    for f in FAILED:
        print("  -", f)
    print(f"{PASSED} checks passed, {len(FAILED)} failed")
    return verdict(PASSED, len(FAILED), certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
