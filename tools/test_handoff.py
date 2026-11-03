#!/usr/bin/env python3
"""test_handoff.py — HANDOFF=1 mechanics in VICE, no network.

A HANDOFF image (src/handoff.s) is started the way Commodore Desk 64 would
start it: with a request already in the REU mailbox and a host program
("cd64") on drive 8. VICE has no UCI, so the network never comes up; what
this proves is everything around the fetch:

  [A] valid request   -> reply HO_R_NO_NET, state DONE, banks 0-2 saved to
                         8-10 and restored, every probe byte put back, the
                         body region untouched, and the host loaded back
                         from drive 8 at the requested entry.
  [B] bad host        -> HO_R_BAD_REQ, at once, same restore guarantees.
  [C] no request      -> nothing written to the REU at all; key; back to
                         the default host (CD64, 8, $0810).
  [D] 512 KB REU      -> "needs 1 MB", nothing written; key; back.

The host's REU contents are a known pattern, so "untouched" is checked
byte for byte over banks 0-7 (CD64's RAM drive) and the probe banks.

Usage: python3 tools/test_handoff.py      (C64_SKIP_BUILD=1 reuses build/)
"""

import os
import re
import subprocess
import sys
import tempfile

from _skip_policy import verdict  # tools/, beside this file

from c64_test_harness import (
    Labels, DiskImage, ViceConfig, ViceInstanceManager,
    jsr, read_bytes, send_key, wait_for_memory, wait_for_text, write_bytes,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PRG = os.path.join(ROOT, "build", "c64-https.prg")
INC = os.path.join(ROOT, "src", "handoff.inc")
MAKE = ["make", "BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "TRUST_STORE=1",
        "PQ_HYBRID=1", "HANDOFF=1"]

BANK = 0x10000
MARK = 0x0340                      # the stand-in host writes "BACK" here
READER = 0xC100                    # REU -> $4000 reader, run with jsr()
WINDOW = 0x4000
CHUNK = 0x4000


def inc_constants():
    """src/handoff.inc's NAME = value lines (the normative layout)."""
    vals = {}
    for line in open(INC):
        m = re.match(r"^(HO_\w+)\s*=\s*([^;]+)", line)
        if not m:
            continue
        expr = m.group(2).strip().replace("$", "0x")
        vals[m.group(1)] = eval(expr, {}, dict(vals))
    return vals


C = inc_constants()


def pattern(size):
    """The host's REU: every byte a function of its address."""
    b = bytearray(size)
    for bank in range(size // BANK):
        row = bytes(((i * 7) ^ (i >> 8) ^ (bank * 37)) & 0xFF
                    for i in range(BANK))
        b[bank * BANK:(bank + 1) * BANK] = row
    return b


def request(url=b"https://www.foo.invalid/"):
    r = bytearray(C["HO_REQ_LEN"])
    r[0:8] = b"C64HTTPS"
    r[C["HO_O_VERSION"]] = C["HO_VERSION"]
    r[C["HO_O_STATE"]] = C["HO_ST_REQUEST"]
    r[C["HO_O_RET_DEV"]] = 8
    r[C["HO_O_RET_NLEN"]] = len(RET_NAME)
    o = C["HO_O_RET_NAME"]
    r[o:o + len(RET_NAME)] = RET_NAME
    o = C["HO_O_RET_ENTRY"]
    r[o:o + 2] = RET_ENTRY.to_bytes(2, "little")
    o = C["HO_O_URL"]
    r[o:o + len(url)] = url
    return bytes(r)


# The request names its own host program and entry; the default (no usable
# request) is CD64's. Each writes its own marker at $0340, and each has a
# decoy at the other's entry, so a wrong name OR a wrong entry shows.
RET_NAME = b"DESK"
RET_ENTRY = 0x0830                 # > $0810 + 23 B of marker code
DEFAULT_ENTRY = 0x0810
MARKERS = (b"BACK", b"DFLT", b"WENT")


def host_prg(entries):
    """A PRG at $0801: at each entry address, write its 4-byte marker at
    $0340 and spin."""
    img = bytearray(0x60)
    for entry, marker in entries.items():
        o = entry - 0x0801
        code = bytearray()
        for i, ch in enumerate(marker):
            code += bytes([0xA9, ch, 0x8D, (MARK + i) & 0xFF, MARK >> 8])
        spin = entry + len(code)
        code += bytes([0x4C, spin & 0xFF, spin >> 8])
        assert o + len(code) <= len(img)
        img[o:o + len(code)] = code
    return b"\x01\x08" + bytes(img)


def make_disk(tmp):
    d64 = os.path.join(tmp, "host.d64")
    files = {"cd64": {DEFAULT_ENTRY: b"DFLT", RET_ENTRY: b"WENT"},
             "desk": {DEFAULT_ENTRY: b"WENT", RET_ENTRY: b"BACK"}}
    cmd = ["c1541", "-format", "host,01", "d64", d64]
    for name, entries in files.items():
        prg = os.path.join(tmp, name + ".prg")
        open(prg, "wb").write(host_prg(entries))
        cmd += ["-write", prg, name]
    subprocess.run(cmd, check=True, capture_output=True)
    return d64


def reader_code(bank, hi):
    # FETCH CHUNK bytes from REU bank:hi00 to WINDOW, then RTS.
    regs = [(0x02, WINDOW & 0xFF), (0x03, WINDOW >> 8), (0x04, 0), (0x05, hi),
            (0x06, bank), (0x07, CHUNK & 0xFF), (0x08, CHUNK >> 8), (0x0A, 0)]
    code = bytearray()
    for reg, val in regs:
        code += bytes([0xA9, val, 0x8D, reg, 0xDF])
    code += bytes([0xA9, 0x91, 0x8D, 0x01, 0xDF, 0x60])
    return bytes(code)


def read_reu(t, start, length):
    out = bytearray()
    addr = start
    while len(out) < length:
        bank, off = addr >> 16, addr & 0xFFFF
        assert off % CHUNK == 0
        write_bytes(t, READER, reader_code(bank, off >> 8))
        jsr(t, READER, timeout=10.0)
        out += read_bytes(t, WINDOW, CHUNK)
        addr += CHUNK
    return bytes(out[:length])


class Result:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what):
        print(f"  {'PASS' if ok else 'FAIL'}: {what}")
        if ok:
            self.passed += 1
        else:
            self.failed += 1


def run_case(name, res, tmp, d64, reu_kb, mailbox, expect):
    print(f"\n--- [{name}] ---")
    size = reu_kb * 1024
    img = pattern(size)
    if mailbox is not None and size > C["HO_MBOX"]:
        img[C["HO_MBOX"]:C["HO_MBOX"] + len(mailbox)] = mailbox
    reu_path = os.path.join(tmp, f"reu-{name}.bin")
    open(reu_path, "wb").write(img)
    before = bytes(img)

    cfg = ViceConfig(prg_path=PRG, warp=True, ntsc=True, sound=False,
                     disk_image=DiskImage(d64),
                     extra_args=["-reu", "-reusize", str(reu_kb),
                                 "-reuimage", reu_path, "+reuimagerw"])
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        if expect.get("key"):
            grid = wait_for_text(t, expect["key"], timeout=120.0, verbose=False)
            res.check(grid is not None, f"screen says {expect['key']!r}")
            send_key(t, " ")
        want = expect.get("back", b"BACK")
        # Any host marker ends the wait: a wrong program or entry is a FAIL
        # now, not a 600 s timeout.
        got = wait_for_memory(t, MARK, lambda b: bytes(b) in MARKERS,
                              length=4, timeout=float(os.environ.get("HANDOFF_WAIT", "600")))
        if got is None:
            got = read_bytes(t, MARK, 4)
        got = bytes(got)
        res.check(got == want, f"returned to the right program and entry "
                               f"(marker {got!r}, want {want!r})")
        if got != want:
            mgr.release(inst)
            return
        # Before any read_reu(): its window ($4000-$7FFF) covers these.
        if "parsed" in expect:
            lb = Labels.from_file(os.path.join(ROOT, "build", "labels.txt"))
            host, port, path = expect["parsed"]
            hlen = read_bytes(t, lb["ho_host_len"], 1)[0]
            plen = read_bytes(t, lb["ho_path_len"], 1)[0]
            got = (bytes(read_bytes(t, lb["ho_host"], hlen)),
                   int.from_bytes(read_bytes(t, lb["ho_port"], 2), "little"),
                   bytes(read_bytes(t, lb["ho_path"], plen)))
            res.check(got == expect["parsed"],
                      f"parsed host/port/path {got!r}")
        hostlen = min(size, 8 * BANK)
        now = read_reu(t, 0, hostlen)
        res.check(now == before[:hostlen],
                  f"host REU banks 0-{hostlen // BANK - 1} byte-identical")
        for b in (16, 32, 64, 128):
            if b * BANK < size:
                v = read_reu(t, b * BANK, CHUNK)
                res.check(v == before[b * BANK:b * BANK + CHUNK],
                          f"probe bank {b} offset 0 page restored")
        if size > C["HO_BODY"]:
            v = read_reu(t, C["HO_BODY"], CHUNK)
            res.check(v == before[C["HO_BODY"]:C["HO_BODY"] + CHUNK],
                      "body region untouched (no body in VICE)")
        if size > C["HO_MBOX"]:
            mb = read_reu(t, C["HO_MBOX"], CHUNK)
            if "result" not in expect:
                res.check(mb == before[C["HO_MBOX"]:C["HO_MBOX"] + CHUNK],
                          "mailbox bank not written")
            else:
                st = mb[C["HO_O_STATE"]]
                res.check(st == C["HO_ST_DONE"], f"state DONE (got {st:#04x})")
                r = mb[C["HO_O_RESULT"]]
                res.check(r == expect["result"],
                          f"result {expect['result']} (got {r})")
                res.check(mb[C["HO_O_URL"]:C["HO_REQ_LEN"]]
                          == mailbox[C["HO_O_URL"]:C["HO_REQ_LEN"]],
                          "request fields left as the host wrote them")
                hl = int.from_bytes(mb[C["HO_O_HDR_LEN"]:C["HO_O_HDR_LEN"] + 2], "little")
                res.check(hl == 0, f"no response head (got {hl})")
                save = read_reu(t, C["HO_SAVE_BANK"] * BANK, 3 * BANK)
                res.check(save == before[:3 * BANK],
                          "banks 8-10 hold the saved copy of banks 0-2")
        mgr.release(inst)


def main():
    os.chdir(ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        subprocess.run(["make", "clean"], capture_output=True)
        r = subprocess.run(MAKE, capture_output=True, text=True)
        if r.returncode != 0:
            print("Build failed:\n" + r.stdout[-2000:] + r.stderr[-2000:])
            sys.exit(1)
    res = Result()
    with tempfile.TemporaryDirectory() as tmp:
        d64 = make_disk(tmp)
        ok, bad = C["HO_R_NO_NET"], C["HO_R_BAD_REQ"]
        # Every accepted URL reaches the network step (NO_NET in VICE);
        # every refused one is answered BAD_REQ before it.
        for case in [
                ("A valid", b"https://www.foo.invalid/x/y.html?a=1&b=2", ok,
                 (b"www.foo.invalid", 443, b"/x/y.html?a=1&b=2")),
                ("A2 caps, port, query", b"HTTPS://WWW.Foo.invalid:8443?q=1", ok,
                 (b"www.foo.invalid", 8443, b"/?q=1")),
                ("A3 no path, top port", b"https://a-b.c0:65535", ok,
                 (b"a-b.c0", 65535, b"/")),
                ("B bad host", b"https://bad..host/", bad),
                ("E bad path", b"https://www.foo.invalid/a b", bad),
                ("F http scheme", b"http://www.foo.invalid/", bad),
                ("G port 0", b"https://www.foo.invalid:0/", bad),
                ("H port 65536", b"https://www.foo.invalid:65536/", bad),
                ("I empty port", b"https://www.foo.invalid:/", bad),
                ("J path 101", b"https://h/" + b"p" * 100, bad)]:
            name, url, want = case[:3]
            exp = {"result": want}
            if len(case) > 3:
                exp["parsed"] = case[3]
            run_case(name, res, tmp, d64, 16384, request(url), exp)
        run_case("C no request", res, tmp, d64, 16384, None,
                 {"key": "NO HTTPS REQUEST", "back": b"DFLT"})
        run_case("D 512 KB", res, tmp, d64, 512, request(),
                 {"key": "NEEDS A REU OF 1 MB", "back": b"DFLT"})
    total = res.passed + res.failed
    print(f"\nResults: {res.passed}/{total} passed")
    sys.exit(verdict(res.passed, res.failed))


if __name__ == "__main__":
    main()
