#!/usr/bin/env python3
"""test_cold_bank.py -- the uci-comb cold-code bank's trampoline (#155 phase 2).

WHAT THIS TESTS

src/net/uci/cold_bank.s as linked into a uci-comb TRUST_STORE=1 PRG, on the
repo's 6502 interpreter with a modelled REU (tools/_reu_model.py) and the
trust store's DOS model (tools/test_trust_store_6502.py):

  * boot: cold_bank_init stashes exactly the PRG's two groups (UI, TRUST)
    back to back at COLD_REU and keeps each one's XOR, once per LOAD: a
    re-run over a TCP ring whose bytes a server chose (a perfect marker
    included) does NOT re-stash, and a PRG whose image is missing stashes
    nothing;
  * a call fetches its own group into cert_buf and runs THAT copy: the
    store from the TRUST group, the typed-target prompt (GETIN/CHROUT
    hooked) from the UI group, and a damaged group refuses only itself;
  * the guard: every socket / TLS state that may own cert_buf is refused
    with no DMA and no jump (the prompt reports COLD BANK FAIL), and the
    idle ones are let through;
  * fail closed on the fetch: a corrupted image byte, a corrupted marker,
    no REU whose open bus fails the confirm (reu_dma_timeout), and the
    timeout staying sticky afterwards; and no REU whose open bus PASSES the
    confirm, over a cert_buf that already holds the exact group (only the
    marker clear catches it) or bytes whose XOR collides (only the marker
    check does). Each one: C=1, cold_err = FETCH, the PC never enters
    cert_buf;
  * a refusal leaves the store FAILED, so a lookup after a load that never
    ran cannot read as "first use".

Each check of the trampoline goes red with its guard removed: the PR
records that mutation run (eight mutants, all killed).

And, with no build at all, that cfg/c64-https-uci-onchip-cold.cfg is
cfg/c64-https-uci-onchip.cfg plus the cold bank's edits and nothing else,
so a fix to the comb cfg cannot silently skip the cold one.

The store's own behaviour through the trampoline is
tools/test_trust_store_6502.py's job: run it with
C64_TS_PROFILE="BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1 TRUST_STORE=1".

WHAT IT DOES NOT PROVE

Real REU timing and the U64E's DMA: the hardware rigs (rig_trust_store,
rig_https_banner) do, on a comb image.

Usage:
    python3 tools/test_cold_bank.py          # make clean && make <comb TS>
    C64_SKIP_BUILD=1 python3 tools/test_cold_bank.py

Exit 0 pass, 1 fail, 2 could not run.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from functools import reduce
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_trust_store_6502 as t6               # noqa: E402
from test_trust_store_6502 import Dos, Env, A, st  # noqa: E402
from _reu_model import REU, Bus                  # noqa: E402
from _skip_policy import cannot_run, verdict     # noqa: E402
import trust_store as ts                         # noqa: E402

REPO = HERE.parent
PROFILE = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1", "TRUST_STORE=1"]
CERTIFIES = "the uci-comb cold-code bank's trampoline (#155 phase 2)"

COLD_REU = 0x02A000
COLD_MARK = 0x5C
R_BUSY, R_FETCH = ts.R_BUSY, ts.R_COLD
NET_CLOSED, NET_CONNECTED, NET_ERROR, NET_CONNECT_FAIL = 0, 1, 2, 3
TLS_IDLE, TLS_CERTIFICATE, TLS_CONNECTED, TLS_ERROR = 0, 4, 7, 0xFF

PASSED = 0
FAILED: list[str] = []


def check(ok, msg):
    global PASSED
    if ok:
        PASSED += 1
    else:
        FAILED.append(msg)


# --- the cfg pin (no build) --------------------------------------------------
# The cold cfg's whole delta from the comb cfg. If the comb cfg changes, the
# change is owed to the cold one too, and this fails until it is made.
CFG_EDITS = [
    ("    OVERLAY_FILE_PAD: start = $C000, size = $2000, file = %O, define = yes, fill = yes, fillval = $00;\n",
     "    # Cold bank: the PRG's copy of the cold groups (src/net/uci/cold_bank.s),\n"
     "    # back to back; boot stashes it into the REU. The head of what was\n"
     "    # OVERLAY_FILE_PAD, and of the TCP ring's range.\n"
     "    COLD_IMAGE:       start = $C000, size = $1000, file = %O, define = yes, fill = yes, fillval = $00;\n"
     "    OVERLAY_FILE_PAD: start = $D000, size = $1000, file = %O, define = yes, fill = yes, fillval = $00;\n"
     "    # Where each cold group runs: cert_buf, pinned below. Not file-backed.\n"
     "    COLD_RUN_UI:      start = $4200, size = $0800, type = rw, define = yes;\n"
     "    COLD_RUN_TRUST:   start = $4200, size = $0800, type = rw, define = yes;\n"),
    ("    X25519_RODATA: load = CRYPTO_OVERLAY, type = ro, align = $20;\n",
     "    # Cold bank: cert_buf first, at a fixed address, so the COLD_RUN_*\n"
     "    # areas can sit on it (src/net/uci/cold_bank.s asserts they do).\n"
     "    CERT_BUF_BSS:  load = CRYPTO_OVERLAY, type = bss, start = $4200;\n"
     "    X25519_RODATA: load = CRYPTO_OVERLAY, type = ro, align = $20;\n"),
    ("    TARGET_PROMPT_CODE: load = LOADER,    type = ro,  optional = yes;\n"
     "    # #155 phase 2 (L3): the signed bundle's check (TRUST_BUNDLE=1).\n"
     "    TRUST_BUNDLE_CODE:  load = LOADER,    type = ro,  optional = yes;\n",
     "    TARGET_PROMPT_CODE: load = COLD_IMAGE, run = COLD_RUN_UI, type = ro, define = yes;\n"
     "    TRUST_BUNDLE_CODE:  load = COLD_IMAGE, run = COLD_RUN_UI, type = ro, optional = yes;\n"
     "    COLD_TAIL_UI:       load = COLD_IMAGE, run = COLD_RUN_UI, type = ro, define = yes;\n"),
    ("    CERT_BUF_BSS:  load = CRYPTO_OVERLAY, type = bss, optional = yes;\n",
     "    # (cold bank: CERT_BUF_BSS is pinned at the head of the region, above)\n"),
    ("    TRUST_STORE_CODE: load = CRYPTO_HOT,     type = ro,  optional = yes;\n"
     "    # #155 phase 2 (L3): the trust policy's no-connection code, beside the\n"
     "    # store it drives; its resident state in CRYPTO_HOT, where the room is.\n"
     "    TRUST_POLICY_CODE: load = CRYPTO_HOT,    type = ro,  optional = yes;\n"
     "    TRUST_POLICY_RODATA: load = CRYPTO_HOT,  type = ro,  optional = yes;\n",
     "    TRUST_STORE_CODE: load = COLD_IMAGE, run = COLD_RUN_TRUST, type = ro, optional = yes, define = yes;\n"
     "    TRUST_POLICY_CODE: load = COLD_IMAGE, run = COLD_RUN_TRUST, type = ro, optional = yes;\n"
     "    TRUST_POLICY_RODATA: load = COLD_IMAGE, run = COLD_RUN_TRUST, type = ro, optional = yes;\n"
     "    COLD_TAIL_TRUST:  load = COLD_IMAGE, run = COLD_RUN_TRUST, type = ro, optional = yes, define = yes;\n"),
]
# The cold cfg also carries its own header block after the comb cfg's first
# line, ending with this.
COLD_HEADER_END = ("# Everything below this block is the comb cfg's own text.\n# "
                   + "-" * 77 + "\n")


def case_cfg_is_the_comb_cfg_plus_the_bank():
    base = (REPO / "cfg/c64-https-uci-onchip.cfg").read_text()
    cold = (REPO / "cfg/c64-https-uci-onchip-cold.cfg").read_text()
    want = base
    for old, new in CFG_EDITS:
        n = want.count(old)
        check(n == 1, f"comb cfg: {old.strip()!r} found {n}x (the cold "
                      "cfg's edit no longer applies: re-derive it)")
        want = want.replace(old, new)
    first = base.split("\n", 1)[0] + "\n"
    i = cold.find(COLD_HEADER_END)
    check(cold.startswith(first) and i > 0 and "COLD_BANK=0" in cold[:i],
          "cold cfg: its header block is missing or misplaced")
    check(i > 0 and first + cold[i + len(COLD_HEADER_END):] == want,
          "cold cfg differs from the comb cfg by more than the cold bank's "
          "edits: diff them and mirror the comb cfg's change")


# --- the machine ---------------------------------------------------------------
GROUPS = {"ui": ("__TARGET_PROMPT_CODE_LOAD__", "cold_marker_ui"),
          "trust": ("__TRUST_STORE_CODE_LOAD__", "cold_marker_trust")}
CHROUT, GETIN = 0xFFD2, 0xFFE4


class Rig:
    """One machine: the PRG, the DOS model, a modelled REU, boot's stash.

    The KERNAL is two Python hooks, enough for https_target_prompt: GETIN
    hands out `keys` (RETURN once they run out) and CHROUT records."""

    def __init__(self, env, dos=None, reu_present=True, absent_status=0x00,
                 init=True):
        self.env = env
        self.L = env.labels
        self.dos = dos or Dos()
        self.m = t6.Machine.__new__(t6.Machine)    # build it ourselves:
        m = self.m                                 #  Machine would run init
        m.labels, m.dos = self.L, self.dos
        m.mem = t6.Memory(env.image, env.load_addr, self.dos)
        for n in ("uci_status_len", "uci_status_force", "net_last_error",
                  "net_tcp_state"):
            m.mem.write(self.L[n], 0)
        m.cpu = t6.FastCPU(m.mem, self.L, False)
        self.reu = REU(m.mem.ram, present=reu_present, absent_status=absent_status)
        m.reu = self.reu
        m.mem.uci = Bus(self.reu, self.dos)
        self.run_lo = self.L["__COLD_RUN_UI_START__"]
        self.run_hi = self.run_lo + 0x7FF
        self.entered = False
        self.keys: list[int] = []
        self.out = bytearray()
        cpu = m.cpu
        step = cpu.step

        def traced():
            pc = cpu.pc
            if pc == GETIN or pc == CHROUT:
                if pc == GETIN:
                    cpu.a = self.keys.pop(0) if self.keys else 0x0D
                    cpu.z, cpu.n = cpu.a == 0, bool(cpu.a & 0x80)
                else:
                    self.out.append(cpu.a)
                cpu._op_RTS(None)
                cpu.steps += 1
                return
            if self.run_lo <= pc <= self.run_hi:
                self.entered = True
            step()
        cpu.step = traced
        if init:
            cpu.call(self.L["cold_bank_init"])

    @property
    def ram(self):
        return self.m.mem.ram

    def r8(self, name):
        return self.ram[self.L[name]]

    def set_states(self, net, tls):
        self.ram[self.L["net_tcp_state"]] = net
        self.ram[self.L["tls_state"]] = tls

    def load(self, host="a.example"):
        self.entered = False
        n = len(self.reu.log)
        c, a = self.m.load(host)
        return c, a, self.reu.log[n:]

    def prompt(self, keys=()):
        """do_https_get's call: https_target_prompt (the resident stub)."""
        self.entered = False
        self.keys = list(keys)
        self.out.clear()
        n = len(self.reu.log)
        c = self.m.cpu.call(self.L["https_target_prompt"], budget=40_000_000)
        return c, self.reu.log[n:]

    def cstr(self, addr, cap=80):
        return bytes(self.ram[addr:addr + cap]).split(b"\0", 1)[0]


def group(env, name):
    """(PRG copy's address, length, REU address) of a cold group."""
    L = env.labels
    load_sym, mark_sym = GROUPS[name]
    n = L[mark_sym] + 1 - L["__COLD_RUN_UI_START__"]
    return L[load_sym], n, COLD_REU + L[load_sym] - L["__COLD_IMAGE_START__"]


def image_bytes(env, name):
    addr, n, _ = group(env, name)
    return bytes(env.image[addr - env.load_addr:addr - env.load_addr + n])


def xor(data):
    return reduce(lambda a, b: a ^ b, data, 0)


# --- cases -------------------------------------------------------------------
def case_boot_stash(env):
    L = env.labels
    ui, trust = image_bytes(env, "ui"), image_bytes(env, "trust")
    check(ui[-1] == COLD_MARK and trust[-1] == COLD_MARK,
          "a PRG group does not end in the marker")
    check(group(env, "trust")[0] == group(env, "ui")[0] + len(ui),
          "the groups are not back to back in COLD_IMAGE")
    span = len(ui) + len(trust)
    r = Rig(env)
    check(r.reu.log == [("stash", L["__COLD_IMAGE_START__"], COLD_REU, span)],
          f"boot DMA log {r.reu.log}")
    for name, img in (("ui", ui), ("trust", trust)):
        _, n, at = group(env, name)
        check(bytes(r.reu.mem[at:at + n]) == img, f"REU lacks the {name} group")
    check(bytes(r.ram[L["cold_g_sum"]:L["cold_g_sum"] + 2]) == bytes([xor(ui), xor(trust)]),
          "cold_g_sum is not the groups' XORs")
    check(r.r8("cold_stashed") == 1, "cold_stashed not set")
    # A re-run without a LOAD: $C000 is the TCP ring, and a server chose
    # its bytes -- including a perfect copy of the marker.
    lo = L["__COLD_IMAGE_START__"]
    r.ram[lo:lo + span] = bytes([0xEA]) * span
    r.ram[L["__COLD_TAIL_UI_LOAD__"]] = COLD_MARK      # every marker forged
    r.ram[L["__COLD_TAIL_TRUST_LOAD__"]] = COLD_MARK
    r.m.cpu.call(L["cold_bank_init"])
    check(len(r.reu.log) == 1, f"re-run re-stashed the ring: {r.reu.log}")
    check(bytes(r.reu.mem[COLD_REU:COLD_REU + len(ui)]) == ui,
          "re-run overwrote the REU image")
    c, a, _ = r.load()
    check(not c and a == ts.ST_EMPTY, f"after a re-run the bank does not work: C={c} A={a}")
    # A LOAD whose image did not arrive: no marker, no stash, every call refused.
    r = Rig(env, init=False)
    r.ram[L["__COLD_TAIL_UI_LOAD__"]] = 0
    r.m.cpu.call(L["cold_bank_init"])
    check(not r.reu.log and r.r8("cold_stashed") == 0, "stashed an image with no marker")


def case_call_runs_the_fetched_copy(env):
    r = Rig(env)
    run = env.labels["__COLD_RUN_TRUST_START__"]
    r.ram[run:run + 0x800] = bytes(0x800)            # cert_buf as boot leaves it
    _, n, at = group(env, "trust")
    c, a, log = r.load()
    check(not c and a == ts.ST_EMPTY, f"load via the bank: C={c} A={a}")
    check(log and log[0] == ("fetch", run, at, n),
          f"the call's first DMA is not the TRUST group's fetch: {log}")
    check(r.entered, "the PC never reached cert_buf")
    check(r.r8("cold_err") == 0, f"cold_err {r.r8('cold_err')} after a good call")
    check(any(x[0] == "open" for x in r.dos.log), "the store never reached the DOS")


def case_prompt_runs_from_its_own_group(env):
    L = env.labels
    r = Rig(env)
    r.load()                                          # cert_buf: the TRUST group
    _, n, at = group(env, "ui")
    c, log = r.prompt([0x4C, 0x57, 0x4E, 0x2E, 0x4E, 0x45, 0x54, 0x0D, 0x2F, 0x0D])
    check(not c, "typed lwn.net /: C=1")
    check(log and log[0] == ("fetch", L["__COLD_RUN_UI_START__"], at, n),
          f"the prompt's first DMA is not the UI group's fetch: {log}")
    check(r.entered, "the prompt did not run from cert_buf")
    check(r.cstr(L["tls_hostname"]) == b"lwn.net",
          f"tls_hostname {r.cstr(L['tls_hostname'])!r}")
    c, _ = r.prompt([])                               # RETURN, RETURN
    check(not c and r.cstr(L["tls_hostname"]) == r.cstr(L["http_host_target"]),
          "RETURN did not keep the build-time host")
    c, _ = r.prompt([0x21, 0x0D, 0x0D])               # '!' is refused
    check(c and r.r8("cold_err") == 0 and b"INVALID TARGET" in bytes(r.out),
          "a refused entry is not the prompt's own refusal")


def case_guard(env):
    for net, tls, ok in [
        (NET_CONNECTED, TLS_IDLE, False), (NET_ERROR, TLS_IDLE, False),
        (NET_CLOSED, TLS_CERTIFICATE, False), (NET_CLOSED, TLS_CONNECTED, False),
        (NET_CONNECT_FAIL, TLS_CERTIFICATE, False),
        (NET_CLOSED, TLS_IDLE, True), (NET_CONNECT_FAIL, TLS_IDLE, True),
        (NET_CLOSED, TLS_ERROR, True), (NET_CONNECT_FAIL, TLS_ERROR, True),
    ]:
        r = Rig(env)
        r.set_states(net, tls)
        c, a, log = r.load()
        tag = f"net={net} tls=${tls:02X}"
        if ok:
            check(not c and log and r.entered, f"{tag}: refused an idle call")
            continue
        check(c, f"{tag}: C=0")
        check(not log, f"{tag}: DMA while a connection may own cert_buf: {log}")
        check(not r.entered, f"{tag}: jumped into cert_buf")
        check(not r.dos.log, f"{tag}: DOS traffic {r.dos.log}")
        check(r.r8("cold_err") == R_BUSY, f"{tag}: cold_err {r.r8('cold_err')}")
        check((r.r8("ts_state"), r.r8("ts_reason")) == (ts.ST_FAIL, ts.R_BUSY),
              f"{tag}: store not FAIL/BUSY")
        c, log = r.prompt([])
        check(c and not log and not r.entered and b"COLD BANK FAIL" in bytes(r.out),
              f"{tag}: the prompt was not refused and reported")


def _refused_fetch(r, tag):
    c, a, log = r.load()
    check(c, f"{tag}: C=0")
    check(not r.entered, f"{tag}: jumped into cert_buf")
    check(not r.dos.log, f"{tag}: the store ran (DOS traffic)")
    check(r.r8("cold_err") == R_FETCH, f"{tag}: cold_err {r.r8('cold_err')}")
    check((r.r8("ts_state"), r.r8("ts_reason")) == (ts.ST_FAIL, ts.R_COLD),
          f"{tag}: store state {(r.r8('ts_state'), r.r8('ts_reason'))}")


def case_corrupt_image(env):
    _, n, at = group(env, "trust")
    for off, what in [(n // 2, "a code byte"), (0, "the first byte"),
                      (n - 1, "the marker")]:
        r = Rig(env)
        r.reu.mem[at + off] ^= 0x01
        _refused_fetch(r, f"TRUST group in the REU, {what} flipped")


def case_groups_are_checked_apart(env):
    """A damaged UI group refuses the prompt and leaves the store working."""
    _, n, at = group(env, "ui")
    r = Rig(env)
    r.reu.mem[at + n // 2] ^= 0x01
    c, log = r.prompt([])
    check(c and log and not r.entered and r.r8("cold_err") == R_FETCH
          and b"COLD BANK FAIL" in bytes(r.out),
          "a damaged UI group was not refused and reported")
    c, a, _ = r.load()
    check(not c and a == ts.ST_EMPTY, "the TRUST group stopped working")


def case_no_reu(env):
    r = Rig(env, reu_present=False, absent_status=0x00)
    _refused_fetch(r, "no REU, confirm expires")
    check(r.r8("reu_dma_timeout") == 1, "the confirm did not expire")
    # Sticky: an REU that answers later does not reopen the bank.
    r = Rig(env)
    r.ram[env.labels["reu_dma_timeout"]] = 1
    _refused_fetch(r, "earlier DMA timed out (sticky)")


def _no_reu_over(env, content, tag):
    """No REU, and $DF00's open bus reads bit 6 set, so reu_execute sees a
    DMA complete that never happened: cert_buf keeps `content`."""
    r = Rig(env)
    run = env.labels["__COLD_RUN_TRUST_START__"]
    r.ram[run:run + len(content)] = content
    r.reu.present, r.reu.absent_status = False, 0xFF
    _refused_fetch(r, tag)
    check(r.r8("reu_dma_timeout") == 0, f"{tag}: open bus 0xFF timed out")


def case_no_reu_over_a_pristine_copy(env):
    """cert_buf already holds the exact group (a call that changed none of
    its own bytes). Marker and XOR both match: only clearing the marker
    before the fetch tells "fetched" from "left over"."""
    _no_reu_over(env, image_bytes(env, "trust"), "no REU over a pristine copy")


def case_no_reu_over_a_colliding_copy(env):
    """cert_buf holds bytes whose XOR, once the marker is cleared, still
    equals the group's (1 in 256 for leftovers). Only the marker check
    sees it."""
    img = bytearray(image_bytes(env, "trust"))
    img[-1] = COLD_MARK ^ 0xFF           # what the clear leaves there
    img[len(img) // 2] ^= 0xFF           # rebalance the XOR
    check(xor(img) == xor(image_bytes(env, "trust")), "setup: XOR does not collide")
    _no_reu_over(env, bytes(img), "no REU over an XOR-colliding copy")


def case_refusal_is_not_first_use(env):
    dos = Dos({A: st(1, "a.example")})
    r = Rig(env, dos=dos)
    c, a, log = r.load("a.example")
    check(not c and a == ts.ST_VALID and r.m.lookup() is not None,
          f"setup: VALID load with the host found: C={c} A={a}")
    _, n, at = group(env, "trust")
    r.reu.mem[at + 7] ^= 0x80
    c, a, log = r.load("other.example")
    check(c, "a refused load returned C=0")
    found = r.m.lookup()
    first_use = r.r8("ts_state") in (ts.ST_VALID, ts.ST_EMPTY) and found is None
    check(found is None and not first_use,
          f"after a refused load: lookup={found is not None} ts_state={r.r8('ts_state')}"
          " -- reads as first use")


def case_no_stash_refuses(env):
    """adv-l5 LOW 3a: boot skipped the stash, so cold_g_sum is still 0. Stale
    REU bytes that carry a marker and XOR to 0 must not run (they did: 1 in
    256 for leftovers, every time for a planted image)."""
    L = env.labels
    r = Rig(env, init=False)                 # no cold_bank_init at all
    _, n, at = group(env, "trust")
    code = bytes([0xA9, 0x42, 0x8D, 0x34, 0x03, 0x18, 0x60])  # sta $0334
    img = bytearray(n)
    entry = L["cold_ts_load"] - L["__COLD_RUN_TRUST_START__"]
    img[entry:entry + len(code)] = code      # at trust_store_load's entry
    img[-1] = COLD_MARK
    img[-2] ^= xor(img)                      # XOR 0 == the unset cold_g_sum
    r.reu.mem[at:at + n] = img
    r.ram[0x0334] = 0
    c, a, log = r.load()
    check(c and r.ram[0x0334] != 0x42 and not r.entered,
          f"no stash, planted image: C={c} $0334=${r.ram[0x0334]:02X} "
          f"entered={r.entered}")
    check(r.r8("cold_err") == R_FETCH, f"no stash: cold_err {r.r8('cold_err')}")


def case_truncated_group_is_not_stashed(env):
    """adv-l5 LOW 3b: a LOAD that cut the TRUST group short (its marker
    missing) must not be stashed and summed as if it were whole."""
    L = env.labels
    r = Rig(env, init=False)
    tl = L["__COLD_TAIL_TRUST_LOAD__"]
    r.ram[tl - 64:tl + 1] = bytes(65)        # the image's tail never arrived
    r.m.cpu.call(L["cold_bank_init"])
    check(not r.reu.log and r.r8("cold_stashed") == 0,
          f"a truncated TRUST group was stashed: {r.reu.log}")
    c, a, _ = r.load()
    check(c, "a call ran after an incomplete stash")


CASES = [case_no_stash_refuses, case_truncated_group_is_not_stashed,
         case_boot_stash, case_call_runs_the_fetched_copy,
         case_prompt_runs_from_its_own_group, case_guard, case_corrupt_image,
         case_groups_are_checked_apart, case_no_reu,
         case_no_reu_over_a_pristine_copy, case_no_reu_over_a_colliding_copy,
         case_refusal_is_not_first_use]


def main() -> int:
    total = len(CASES) + 1
    case_cfg_is_the_comb_cfg_plus_the_bank()
    print(f"{'PASS' if not FAILED else 'FAIL'} case_cfg_is_the_comb_cfg_plus_the_bank")
    if os.environ.get("C64_SKIP_BUILD") != "1":
        subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
        p = subprocess.run(["make", *PROFILE], cwd=REPO, capture_output=True, text=True)
        if p.returncode != 0:
            return cannot_run(f"make {' '.join(PROFILE)} failed:\n{p.stdout[-1500:]}"
                              f"{p.stderr[-1500:]}", executed=1, total=total,
                              certifies=CERTIFIES)
    if not t6.PRG.is_file() or not t6.LABELS.is_file():
        return cannot_run("no build/c64-https.prg + labels.txt", executed=1,
                          total=total, certifies=CERTIFIES)
    env = Env()
    need = ("cold_call", "cold_bank_init", "trust_store_load",
            "__COLD_RUN_TRUST_START__")
    missing = [n for n in need if n not in env.labels]
    if missing:
        return cannot_run(f"build/ is not a uci-comb TRUST_STORE=1 cold-bank "
                          f"image (no {', '.join(missing)})", executed=1,
                          total=total, certifies=CERTIFIES)
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
