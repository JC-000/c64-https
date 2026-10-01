#!/usr/bin/env python3
"""test_typed_target.py - the typed HTTPS target (#155 phase 2, UCI only).

On UCI builds the menu 'G' asks for the host and the path. RETURN on an
empty field keeps the build-time HTTPS_HOST / HTTPS_PATH. This suite drives
that prompt with real keystrokes and then checks that the ONE typed name
reaches every consumer, not just the one that is easiest to see:

  SNI            tls_build_client_hello's server_name extension
  Host header    http_build_get's request (and the path in its request line)
  UCI connect    uci_host_buf, which net_dns_resolve stages for TCP_CONNECT
                 (the firmware does the DNS lookup from it)
  name check     x509_verify_hostname: a certificate naming the typed host
                 is ACCEPTED, and one naming anything else -- including the
                 build-time host the typed one replaced -- is REJECTED

and that anything the prompt cannot represent exactly is refused with
"INVALID TARGET" and nothing is dialled: no truncation, no silent fix-up.

What runs is the shipped path: keys go into the KERNAL buffer, the real
do_https_get runs from a JSR, the real net_dns_resolve copies the name.
Only net_tcp_connect is replaced -- VICE has no UCI -- by a stub that
records "dialled" and fails, so the flow stops before tls_connect.

Negative-heavy on purpose (the F7 trap in test_ecdsa_kat_oracle.py): a
prompt stubbed to "accept everything" or to "keep the build-time target"
fails most of these cases.

Usage:
    python3 tools/test_typed_target.py            # builds uci-onchip
    C64_SKIP_BUILD=1 python3 tools/test_typed_target.py

Exit: 0 all pass, 1 a check failed, 2 could not run (not a UCI build,
no VICE, no menu).
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceInstanceManager, read_bytes, write_bytes, jsr, wait_for_text,
)
from c64_test_harness import TimeoutError as HarnessTimeout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config, menu_wait  # noqa: E402
from _skip_policy import cannot_run, verdict  # noqa: E402
from test_x509_name import make_cert  # noqa: E402
from _petscii_keys import target_keys as keys  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
BUILD = ["make", "BACKEND=uci", "USE_NISTCURVES_ONCHIP=1"]

REQUIRED = [
    "do_https_get", "net_initialized", "net_tcp_connect", "uci_host_buf",
    "tls_hostname", "tls_hostname_len", "http_host_ptr", "http_host_len",
    "http_path_ptr", "http_path_len", "http_host_target", "https_path_target",
    "http_build_get", "http_req_buf", "http_req_len",
    "tls_build_client_hello", "tls_rec_buf",
    "x509_verify_hostname", "cert_buf", "cert_data_ptr",
]

# Cassette buffer; the harness jsr() trampoline owns $0334-$0338.
DRIVER = 0x0340          # JSR target / LDA #0 / ROL / STA CARRY / RTS
CARRY = 0x034A
MARK = 0x034B            # net_tcp_connect stub writes DIALLED here
DIALLED = 0x5A
POISON = 0xEE
SCREEN = 0x0400

KEY_CRSR_DOWN = 0x11
KEY_CBM_AT = 0xA4        # C=+@, drawn as '_' in the default charset


def lohi(a: int) -> tuple[int, int]:
    return a & 0xFF, a >> 8


def read_cstr(t, addr: int, cap: int = 128) -> bytes:
    raw = read_bytes(t, addr, cap)
    return raw.split(b"\x00", 1)[0]


def screen_text(t) -> str:
    out = []
    for c in read_bytes(t, SCREEN, 1000):
        c &= 0x7F
        if 1 <= c <= 26:
            out.append(chr(c + 64))
        elif 0x20 <= c <= 0x3F:
            out.append(chr(c))
        else:
            out.append(" ")
    return "".join(out)


def call(t, target: int, timeout: float = 30.0) -> int:
    """JSR *target* through a carry-latching driver; return C."""
    lo, hi = lohi(target)
    clo, chi = lohi(CARRY)
    write_bytes(t, DRIVER, bytes([0x20, lo, hi, 0xA9, 0x00, 0x2A,
                                  0x8D, clo, chi, 0x60]))
    write_bytes(t, CARRY, bytes([POISON]))
    jsr(t, DRIVER, timeout=timeout)
    c = read_bytes(t, CARRY, 1)[0]
    if c not in (0, 1):
        raise RuntimeError(f"driver never returned (carry byte ${c:02X})")
    return c


class Suite:
    def __init__(self, t, labels):
        self.t = t
        self.L = labels
        self.passed = 0
        self.failed = 0
        self.default_host = read_cstr(t, labels["http_host_target"])
        self.default_path = read_cstr(t, labels["https_path_target"])

    # --- plumbing -----------------------------------------------------------
    def check(self, name: str, ok: bool, detail: str = "") -> None:
        print(f"    [{'PASS' if ok else 'FAIL'}] {name}"
              f"{'' if ok else '  -- ' + detail}")
        if ok:
            self.passed += 1
        else:
            self.failed += 1

    def type_and_get(self, codes: list[int], buffered: bool = False) -> None:
        """Poison the observables, queue *codes*, run do_https_get once.

        *buffered* writes the keys straight into the KERNAL buffer ($0277,
        count $C6, at most 10) instead of VICE's feed, so all of them --
        including any typed AFTER the entry's last RETURN -- are already
        queued when the prompt finishes. That is the only way to see
        whether a refusal flushes type-ahead: the feed hands keys over a
        frame at a time and could deliver the tail after the flush.
        """
        t, L = self.t, self.L
        write_bytes(t, 0x00C6, b"\x00")                  # empty KERNAL buffer
        write_bytes(t, SCREEN, b"\x20" * 1000)
        write_bytes(t, MARK, bytes([POISON]))
        write_bytes(t, L["uci_host_buf"], bytes([POISON]) * 8)
        write_bytes(t, L["tls_hostname"], bytes([POISON]) * 64)
        write_bytes(t, L["tls_hostname_len"], bytes([POISON]))
        if buffered:
            assert len(codes) <= 10, "the KERNAL buffer holds 10 keys"
            write_bytes(t, 0x0277, bytes(codes))
            write_bytes(t, 0x00C6, bytes([len(codes)]))
        else:
            for i in range(0, len(codes), 10):
                t.inject_keys(codes[i:i + 10])
        call(t, L["do_https_get"], timeout=60.0)

    def host_state(self) -> dict:
        t, L = self.t, self.L
        hp = int.from_bytes(read_bytes(t, L["http_host_ptr"], 2), "little")
        hl = read_bytes(t, L["http_host_len"], 1)[0]
        pp = int.from_bytes(read_bytes(t, L["http_path_ptr"], 2), "little")
        pl = read_bytes(t, L["http_path_len"], 1)[0]
        n = read_bytes(t, L["tls_hostname_len"], 1)[0]
        return {
            "dialled": read_bytes(t, MARK, 1)[0] == DIALLED,
            "tls_hostname": read_bytes(t, L["tls_hostname"], 64)[:n] if n <= 64 else None,
            "tls_hostname_len": n,
            "host_hdr_src": read_bytes(t, hp, hl) if hl else b"",
            "path": read_bytes(t, pp, pl) if pl else b"",
            "uci_host_buf": read_cstr(t, L["uci_host_buf"], 80),
        }

    # --- consumers ------------------------------------------------------------
    def request(self) -> bytes:
        call(self.t, self.L["http_build_get"])
        n = int.from_bytes(read_bytes(self.t, self.L["http_req_len"], 2), "little")
        return read_bytes(self.t, self.L["http_req_buf"], min(n, 256))

    def client_hello(self) -> bytes:
        call(self.t, self.L["tls_build_client_hello"])
        return read_bytes(self.t, self.L["tls_rec_buf"], 400)

    def name_check(self, sans: list[str]) -> int:
        der = make_cert(sans)
        cb = self.L["cert_buf"]
        write_bytes(self.t, cb, der)
        write_bytes(self.t, self.L["cert_data_ptr"], bytes(lohi(cb)))
        return call(self.t, self.L["x509_verify_hostname"])

    # --- cases ----------------------------------------------------------------
    def accepted(self, title: str, codes: list[int], host: bytes, path: bytes,
                 consumers: bool = False) -> None:
        print(f"\n  {title}")
        self.type_and_get(codes)
        s = self.host_state()
        self.check("dialled (reached net_tcp_connect)", s["dialled"],
                   "the prompt refused or never returned")
        self.check(f"tls_hostname == {host.decode()!r}", s["tls_hostname"] == host,
                   f"got {s['tls_hostname']!r}")
        self.check("Host-header source (http_host_ptr/len) == that name",
                   s["host_hdr_src"] == host, f"got {s['host_hdr_src']!r}")
        self.check("UCI connect name (uci_host_buf) == that name",
                   s["uci_host_buf"] == host, f"got {s['uci_host_buf']!r}")
        self.check(f"path == {path.decode()!r}", s["path"] == path,
                   f"got {s['path']!r}")
        if not consumers:
            return
        req = self.request()
        want = b"GET " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\n"
        self.check("request line + Host header carry the typed target",
                   req.startswith(want), f"got {req[:len(want) + 8]!r}")
        n = len(host)
        sni = bytes([0, 0, 0, n + 5, 0, n + 3, 0, 0, n]) + host
        self.check("ClientHello SNI extension carries the typed name",
                   sni in self.client_hello(), "server_name extension not found")
        self.check("name check ACCEPTS a certificate naming the typed host",
                   self.name_check([host.decode()]) == 0, "C=1")
        other = self.default_host.decode()
        if host == self.default_host:
            other = "attacker.example"
        self.check(f"name check REJECTS a certificate naming only {other!r}",
                   self.name_check([other]) == 1, "C=0")

    def refused(self, title: str, codes: list[int],
                buffered: bool = False) -> None:
        print(f"\n  {title}")
        self.type_and_get(codes, buffered)
        s = self.host_state()
        self.check("nothing dialled", not s["dialled"], "net_tcp_connect ran")
        self.check("net_dns_resolve never ran (uci_host_buf untouched)",
                   read_bytes(self.t, self.L["uci_host_buf"], 1)[0] == POISON,
                   f"got {s['uci_host_buf']!r}")
        self.check("tls_hostname_len == 0 (a name check could only fail)",
                   s["tls_hostname_len"] == 0, f"got {s['tls_hostname_len']}")
        self.check("screen says INVALID TARGET",
                   "INVALID TARGET" in screen_text(self.t), "message not on screen")
        # A refusal must also swallow the rest of what the operator typed:
        # whatever reaches main_loop runs as a menu command ('H' dials
        # zimmers.net, 'I' re-inits, 'Q' quits). So let main_loop run for a
        # while with any leftovers, then look for each command's trace.
        self.check("KERNAL key buffer empty on return",
                   read_bytes(self.t, 0x00C6, 1)[0] == 0, "keys left queued")
        self.t.resume()
        time.sleep(3.0)
        scr = screen_text(self.t)
        self.check("no menu command ran afterwards (no dial, no HTTP GET, "
                   "no re-init, no quit)",
                   read_bytes(self.t, MARK, 1)[0] != DIALLED
                   and "HTTP GET" not in scr and "INITIALIZING" not in scr
                   and "READY." not in scr,
                   f"dialled={read_bytes(self.t, MARK, 1)[0] == DIALLED} "
                   f"screen={' '.join(scr.split())[:160]!r}")

    def run(self) -> None:
        dh, dp = self.default_host, self.default_path
        typed_host = b"example.org"
        self.accepted("RETURN, RETURN keeps the build-time target",
                      keys("\r\r"), dh, dp, consumers=True)
        self.accepted("typed host + path reach every consumer",
                      keys("example.org\r/typed/Path?q=1\r"),
                      typed_host, b"/typed/Path?q=1", consumers=True)
        self.accepted("shifted host letters are lowercased; path case kept",
                      keys("EN.Wikipedia.ORG\r/wiki/Commodore_64\r"),
                      b"en.wikipedia.org", b"/wiki/Commodore_64", consumers=True)
        self.accepted("C=+@ is '_' too",
                      keys("a.test\r/x") + [KEY_CBM_AT] + keys("y\r"),
                      b"a.test", b"/x_y")
        self.accepted("DEL edits the field before RETURN",
                      keys("exy\x7f\x7fxample.org\r\x7f/p\r"),
                      typed_host, b"/p")
        self.accepted("typed host only; RETURN keeps the build-time path",
                      keys("lwn.net\r\r"), b"lwn.net", dp)
        cap_host = b"h" * 59 + b".org"                   # 63 = HTTPS_HOST_MAX
        cap_path = b"/" + b"p" * 99                      # 100 = HTTPS_PATH_MAX
        self.accepted("63-char host and 100-char path are accepted whole",
                      keys(cap_host.decode() + "\r" + cap_path.decode() + "\r"),
                      cap_host, cap_path)

        self.refused("64-char host refused at the 64th key, not truncated",
                     keys("h" * 64 + "\r/p\r"))
        self.refused("101-char path refused at the 101st key",
                     keys("\r/" + "p" * 100 + "\r"))
        self.refused("'_' is not a hostname character", keys("bad_host\r/p\r"))
        self.refused("empty label: '..'", keys("a..b\r/p\r"))
        self.refused("empty label: leading '.' (would match *.foo.org)",
                     keys(".foo.org\r/p\r"))
        # Why that refusal is not cosmetic: fed straight to the name check,
        # an empty leftmost label satisfies a wildcard.
        write_bytes(self.t, self.L["tls_hostname"], b".foo.org\x00")
        write_bytes(self.t, self.L["tls_hostname_len"], bytes([8]))
        self.check("(evidence) x509_verify_hostname alone accepts '.foo.org' "
                   "against '*.foo.org'", self.name_check(["*.foo.org"]) == 0,
                   "C=1: the refusal's stated reason no longer holds")
        self.refused("empty label: trailing '.'", keys("foo.org.\r/p\r"))
        self.refused("space in host", keys("a \r/p\r"))
        self.refused("cursor key in host", keys("ab") + [KEY_CRSR_DOWN] + keys("\r/p\r"))
        self.refused("path without a leading '/'", keys("\rnopath\r"))
        self.refused("space in path (would split the request line)",
                     keys("\r/a \r"))

        # The operator keeps typing after the refused key. On a prompt that
        # returns at the refusal these reach main_loop as H / I / Q. Last,
        # because on such a prompt 'Q' leaves the program.
        self.refused("space in host, operator types on (h, i, q)",
                     keys("my hiq.org\r/hiq\r"))
        self.refused("64th host key, operator types on",
                     keys("h" * 63 + "hiq\r/hiq\r"))
        self.refused("empty label refused at RETURN; the path line follows",
                     keys("a..b\r/hiq\r"))
        self.refused("space in path, operator types on",
                     keys("\r/a hiq\r"))
        # Type-ahead already in the KERNAL buffer when the refusal lands:
        # only the flush keeps this 'h' from dialling zimmers.net.
        self.refused("refusal with 'h' typed ahead in the key buffer",
                     keys("a \r/p\rh"), buffered=True)


def main() -> int:
    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        r = subprocess.run(BUILD, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:])
            return cannot_run(f"{' '.join(BUILD)} failed", executed=0, total=1,
                              certifies="the typed HTTPS target prompt")
    if not os.path.exists(PRG_PATH):
        return cannot_run("build/c64-https.prg missing", executed=0, total=1,
                          certifies="the typed HTTPS target prompt")
    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED if labels.address(n) is None]
    if missing:
        return cannot_run(
            "labels missing: " + ", ".join(missing) + " -- the typed target "
            "is a BACKEND=uci feature", executed=0, total=1,
            certifies="the typed HTTPS target prompt")

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        try:
            if wait_for_text(t, "Q=QUIT", timeout=menu_wait(120),
                             verbose=False) is None:
                return cannot_run("menu never appeared", executed=0, total=1,
                                  certifies="the typed HTTPS target prompt")
            write_bytes(t, labels["net_initialized"], b"\x01")
            mlo, mhi = lohi(MARK)
            # net_tcp_connect -> LDA #DIALLED / STA MARK / SEC / RTS
            write_bytes(t, labels["net_tcp_connect"],
                        bytes([0xA9, DIALLED, 0x8D, mlo, mhi, 0x38, 0x60]))
            s = Suite(t, labels)
            print(f"  build-time target: {s.default_host.decode()!r} "
                  f"{s.default_path.decode()!r}")
            try:
                s.run()
            except (HarnessTimeout, RuntimeError) as exc:
                # A prompt that never returns (it waits for a RETURN the
                # case did not send because it expected a refusal) hangs
                # the JSR. The machine is not reusable after that: stop.
                s.check("do_https_get returned", False,
                        f"{type(exc).__name__}: {exc}")
        finally:
            mgr.release(inst)
    print(f"\nRESULTS: {s.passed}/{s.passed + s.failed} passed")
    return verdict(s.passed, s.failed,
                   certifies="the typed HTTPS target (UCI menu 'G')")


if __name__ == "__main__":
    sys.exit(main())
