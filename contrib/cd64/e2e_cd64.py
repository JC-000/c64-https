#!/usr/bin/env python3
"""e2e_cd64.py - Commodore Desk 64 WEB <-> HTTPS helper, in VICE, no network.

  [1] launch: WEB opens an https:// URL -> writes the request, launches
      HTTPS from drive 8 -> the helper (no UCI in VICE) answers code 3 and
      loads CD64 back -> CD64 reopens WEB -> "HTTPS FAILED, CODE 03";
      mailbox left IDLE; the host's REU banks 0-7 byte-identical.
  [2] replay: a DONE reply (status line, headers, HTML body) planted in the
      REU -> WEB renders the page through its normal HTML path.

Usage: e2e_cd64.py <CD64.d81> <web_main.sym> <c64-https src/handoff.inc>
"""
import os, re, sys, tempfile, time
from c64_test_harness import (DiskImage, ViceConfig, ViceInstanceManager,
                              goto, jsr, read_bytes, wait_for_text, write_bytes)

D81, SYM, INC = sys.argv[1:4]
BANK = 0x10000
SIZE = 16 * 1024 * 1024
TRAMP = 0x0340
READER = 0x0360
WINDOW, CHUNK = 0x4000, 0x4000


def syms(path):
    out = {}
    for line in open(path):
        m = re.match(r"\s*\.label (\w+)=\$([0-9a-fA-F]+)", line)
        if m:
            out.setdefault(m.group(1), int(m.group(2), 16))
    return out


def inc(path):
    v = {}
    for line in open(path):
        m = re.match(r"^(HO_\w+)\s*=\s*([^;]+)", line)
        if m:
            v[m.group(1)] = eval(m.group(2).strip().replace("$", "0x"), {}, dict(v))
    return v


S, C = syms(SYM), inc(INC)
WB_NEW = 0xC800
OPEN_APP, NV_GO, NT_PUSH = S["openApp"], S["nv_Go"], S["ntPush"]


def pattern():
    img = bytearray(SIZE)
    for b in range(8):                       # the host's RAM drive banks
        img[b * BANK:(b + 1) * BANK] = bytes(((i * 7) ^ (i >> 8) ^ (b * 37)) & 0xFF
                                             for i in range(BANK))
    return img


def reader(bank, hi):
    regs = [(2, WINDOW & 255), (3, WINDOW >> 8), (4, 0), (5, hi), (6, bank),
            (7, CHUNK & 255), (8, CHUNK >> 8), (10, 0)]
    code = bytearray()
    for r, v in regs:
        code += bytes([0xA9, v, 0x8D, r, 0xDF])
    return bytes(code + bytes([0xA9, 0x91, 0x8D, 0x01, 0xDF, 0x60]))


def read_reu(t, start, n):
    out = bytearray()
    while len(out) < n:
        a = start + len(out)
        write_bytes(t, READER, reader(a >> 16, (a >> 8) & 0xFF))
        jsr(t, READER, timeout=10)
        out += read_bytes(t, WINDOW, CHUNK)
    return bytes(out[:n])


def run(name, img, setup, needle, checks):
    print(f"\n--- [{name}] ---")
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        reu = os.path.join(tmp, "reu.bin")
        open(reu, "wb").write(img)
        cfg = ViceConfig(prg_path=D81, warp=True, ntsc=False, sound=False,
                         disk_image=DiskImage(D81),
                         extra_args=["-reu", "-reusize", "16384",
                                     "-reuimage", reu, "+reuimagerw"])
        with ViceInstanceManager(config=cfg) as mgr:
            t = mgr.acquire().transport
            if wait_for_text(t, "F1=HELP", timeout=180, verbose=False) is None:
                print("  FAIL: desktop never came up"); return False
            time.sleep(1)
            setup(t)
            g = wait_for_text(t, needle, timeout=900, verbose=False)
            print(f"  {'PASS' if g else 'FAIL'}: screen shows {needle!r}")
            ok &= g is not None
            for what, fn in checks:
                r = fn(t)
                print(f"  {'PASS' if r else 'FAIL'}: {what}")
                ok &= bool(r)
            if not ok or os.environ.get("E2E_DUMP"):
                scr = read_bytes(t, 0x0400, 1000)
                ch = lambda c: chr((c & 0x7f) + 64) if 1 <= (c & 0x7f) <= 26 else (chr(c & 0x7f) if 32 <= (c & 0x7f) < 64 else ".")
                for r in range(25):
                    print("   |" + "".join(ch(c) for c in scr[r * 40:(r + 1) * 40]))
    return ok


def open_web_then(t, extra=b""):
    # lda #15 / jsr openApp / <extra> / jmp *
    code = bytes([0xA9, 15, 0x20, OPEN_APP & 255, OPEN_APP >> 8]) + extra
    spin = TRAMP + len(code)
    write_bytes(t, TRAMP, code + bytes([0x4C, spin & 255, spin >> 8]))
    goto(t, TRAMP)


def case_launch():
    img = pattern()
    before = bytes(img[:8 * BANK])
    url = b"https://www.foo.invalid/x/y?z=1\0"

    def setup(t):
        write_bytes(t, WB_NEW, url)
        write_bytes(t, NT_PUSH, b"\0")
        # open WEB, then nv_Go to the https URL (never returns: HTTPS runs)
        open_web_then(t, bytes([0xA2, 0, 0x20, NV_GO & 255, NV_GO >> 8]))

    def mb(t):
        return read_reu(t, C["HO_MBOX"], CHUNK)
    checks = [
        ("mailbox: request URL as WEB wrote it",
         lambda t: mb(t)[C["HO_O_URL"]:C["HO_O_URL"] + len(url)] == url),
        ("mailbox: state IDLE after the replay", lambda t: mb(t)[C["HO_O_STATE"]] == 0),
        ("mailbox: result 3 (no network in VICE)", lambda t: mb(t)[C["HO_O_RESULT"]] == 3),
        ("host REU banks 0-7 byte-identical", lambda t: read_reu(t, 0, 8 * BANK) == before),
    ]
    return run("1 launch -> helper -> back", img, setup, "CODE 03", checks)


def case_replay():
    img = pattern()
    url = b"https://example.invalid/page\0"
    body = b"<html><title>TLS PAGE</title><body><h1>Hello from TLS 1.3</h1></body></html>"
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: %d\r\n\r\n" % len(body))
    m = bytearray(0x200)
    m[0:8] = b"C64HTTPS"; m[8] = 1; m[9] = C["HO_ST_DONE"]
    m[C["HO_O_URL"]:C["HO_O_URL"] + len(url)] = url
    r = C["HO_O_RESULT"]
    m[r] = 0
    m[C["HO_O_HTTP"]:C["HO_O_HTTP"] + 2] = (200).to_bytes(2, "little")
    m[C["HO_O_BODY_LEN"]:C["HO_O_BODY_LEN"] + 3] = len(body).to_bytes(3, "little")
    m[C["HO_O_BODY_TOTAL"]:C["HO_O_BODY_TOTAL"] + 3] = len(body).to_bytes(3, "little")
    m[C["HO_O_HDR_LEN"]:C["HO_O_HDR_LEN"] + 2] = len(head).to_bytes(2, "little")
    img[C["HO_MBOX"]:C["HO_MBOX"] + len(m)] = m
    img[C["HO_HDR"]:C["HO_HDR"] + len(head)] = head
    img[C["HO_BODY"]:C["HO_BODY"] + len(body)] = body
    # what follows the body must not be shown: fill with a marker
    img[C["HO_BODY"] + len(body):C["HO_BODY"] + len(body) + 256] = b"<p>OVERRUN</p>" * 18 + b"...."

    def setup(t):
        write_bytes(t, 0x02FF, b"\xa5")      # as WEB leaves it before HTTPS
        open_web_then(t)

    checks = [
        ("mailbox: state IDLE after the replay",
         lambda t: read_reu(t, C["HO_MBOX"], CHUNK)[C["HO_O_STATE"]] == 0),
        ("nothing past the body length was fed",
         lambda t: b"OVERRUN" not in bytes((c & 0x7f) + 64 if 1 <= (c & 0x7f) <= 26 else c & 0x7f
                                           for c in read_bytes(t, 0x0400, 1000))),
        ("flag $02FF cleared", lambda t: read_bytes(t, 0x02FF, 1)[0] == 0),
    ]
    return run("2 replay a DONE reply", img, setup, "HELLO FROM TLS", checks)


if __name__ == "__main__":
    results = [case_replay(), case_launch()]
    print("\nALL PASS" if all(results) else "\nSOME FAILED")
    sys.exit(0 if all(results) else 1)
