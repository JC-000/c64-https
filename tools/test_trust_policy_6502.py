#!/usr/bin/env python3
"""test_trust_policy_6502.py -- the SHIPPED trust policy, end to end (#155 phase 2, L3).

WHAT THIS TESTS

do_https_get as linked into a TRUST_STORE=1 PRG -- the typed-target prompt,
trust_pre, the dial, the resident hook inside the handshake, the close and
trust_post -- on the repo's 6502 interpreter, against the trust store's UCI
DOS model (tools/test_trust_store_6502.py) and, on comb, the modelled REU
and the cold bank. Everything between the operator's keys and the store's
bytes on "disk" is the image's own code. Only the edges are Python:

  * the network: net_dns_resolve, net_tcp_connect, net_tcp_close (socket
    state kept honest: CONNECTED from connect to close);
  * the handshake around the hook: tls_connect runs cert_pin_hs_keys, then
    cert_pin_check (the hook) over a real 91 B P-256 SPKI window, then
    x509_verify_hostname (stubbed: the scenario's verdict), then
    cert_pin_send_finished, whose tls_send_finished is the event "client
    Finished sent";
  * the GET: tls_send / http_recv_body (stubs);
  * ecdsa_verify (bundle builds): a REAL P-256 verify, in Python, of the
    160 B r|s|h|Qx|Qy struct the C64 built in RAM. So the bundle's hash,
    trailer copy and key copy are checked, not assumed;
  * the KERNAL: GETIN / CHROUT. Keys typed AHEAD sit in the KERNAL buffer
    (counted by $C6, as the KERNAL does); a question that flushes $C6 must
    not see them.

Scenarios (each run on every image built):

  first use / EMPTY      TRUST STORE EMPTY; records TOFU, byte-identical to
                         the host mirror tools/trust_store.py
  match                  KNOWN KEY; Finished sent; NO DOS write
  changed, refused       KEY CHANGED + the full 64-hex hash; no Finished,
                         no GET, store unchanged
  accept exact           arm K2; K3 retry refused ("ACCEPTED KEY NOT SEEN")
                         and the arm is spent; K2 without re-arming refused;
                         re-arm K2, K2 retry records ACCEPTED/K2 exactly
  accept, other host     armed for A, a GET for B drops it; A then refused
  near collisions        two key pairs whose hashes share 4 bytes (first /
                         last): the store and the accept each refuse one
                         for the other, so every compare is all 32 bytes
  type-ahead             an 'A' typed before the question arms nothing
  name check fails       first use, Finished never sent, nothing recorded
  store FAIL             TRUST FAIL; N: NOT DIALLED, no connect; Y: one
                         UNPINNED fetch, banner, no DOS write
  changed -> unpinned    redials once, Finished sent, never records
  no trust_pre           the hook refuses (tp_mode = NONE)
  interlock (#152)       no Certificate in the flight, or a refused hook
                         whose carry the record layer drops: no Finished
  build pin (pinned img) the pin's host: no DOS traffic at all, PIN FAIL
                         refuses with no question asked; another host: TOFU
  bundle (bundle imgs)   good pin -> BUNDLE PIN, records TOFU; mismatch at
                         first use -> BUNDLE MISMATCH, RECORD KEY? (no: not
                         recorded; A: ACCEPTED); verify once per boot (no
                         second ECDSA), file swapped -> verified again;
                         tampered record / r / s -> BAD SIGNATURE; wrong
                         key -> BAD SIGNATURE; magic, size, N=33, unsorted,
                         duplicate, mode, flags, uses -> BAD FORMAT; gen <
                         floor -> OLD GEN (gen == floor accepted); absent ->
                         NO BUNDLE once; a bad bundle never blocks the fetch
  never mid-handshake    across every scenario: no GETIN while the socket
                         is CONNECTED

WHAT IT DOES NOT PROVE

Real UCI DOS timing, the U64E's REU, a real server: tools/uci/
rig_trust_policy.py does those on hardware. The ECDSA here is Python's;
tools/test_trust_bundle_c64.py runs the real 6502 verify in VICE.

Usage:
    python3 tools/test_trust_policy_6502.py            # builds every image
    C64_TP_IMAGES=onchip,comb python3 tools/test_trust_policy_6502.py
    C64_TP_SCENARIOS=sc_bundle,sc_build_pin ...   # a subset (mutation runs)

Leaves build/ holding the last image built. Exit 0 pass, 1 fail, 2 could
not run.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_trust_store_6502 as t6                        # noqa: E402
from test_trust_store_6502 import Dos                     # noqa: E402
from _reu_model import REU, Bus                           # noqa: E402
from _skip_policy import cannot_run, verdict              # noqa: E402
import trust_store as ts                                  # noqa: E402

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature)
except ImportError:                                       # pragma: no cover
    ec = None

REPO = HERE.parent
CERTIFIES = "the trust policy's 6502 flow (#155 phase 2, L3)"
PIN_HOST = "www.foo.invalid"            # boot.s's default HTTPS_HOST

CHROUT, GETIN, NDX = 0xFFD2, 0xFFE4, 0xC6
NESTED = 0xFFE8                         # return address for nested calls
NET_CLOSED, NET_CONNECTED = 0, 1
TLS_IDLE, TLS_CERT, TLS_CONNECTED, TLS_ERROR = 0, 4, 7, 0xFF


def _inc_consts(path, names):
    text = (REPO / path).read_text()
    out = {}
    for n in names:
        m = re.search(rf"^{n}\s*=\s*\$?([0-9A-Fa-f]+)", text, re.M)
        if not m:
            raise SystemExit(f"{path}: {n} not found")
        v = m.group(1)
        out[n] = int(v, 16) if "$" in m.group(0) else int(v)
    return out


TP = _inc_consts("src/trust_policy.inc",
                 ["TP_M_NONE", "TP_M_STORE", "TP_M_FIRST", "TP_M_UNPINNED",
                  "TP_ST_CHANGED", "TP_ST_REFUSED"])

IMAGES = {
    "onchip": ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "TRUST_STORE=1"],
    "comb": ["BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1", "TRUST_STORE=1"],
    "onchip-bundle": ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "TRUST_STORE=1",
                      "TRUST_BUNDLE=1"],
    "comb-bundle": ["BACKEND=uci", "USE_NISTCURVES_ONCHIP_COMB=1",
                    "TRUST_STORE=1", "TRUST_BUNDLE=1"],
    # the pin's value is set per run (the hash of K1)
    "onchip-pinned": ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "TRUST_STORE=1",
                      "TRUST_BUNDLE=1"],
}

PASSED = 0
FAILED: list[str] = []


def check(ok, what):
    global PASSED
    if ok:
        PASSED += 1
    else:
        FAILED.append(what)
        print(f"    FAIL: {what}")


# --- keys --------------------------------------------------------------------

def make_key(seed: int):
    return ec.derive_private_key(seed, ec.SECP256R1())


def spki_der(key) -> bytes:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    assert len(der) == 91
    return der


def spki_hash(key) -> bytes:
    return hashlib.sha256(spki_der(key)).digest()


def petscii_line(text: str) -> list[int]:
    """What the operator types: unshifted keys give lowercase ASCII."""
    return [ord(c.upper()) if c.isalpha() else ord(c) for c in text] + [0x0D]


# --- the machine ---------------------------------------------------------------

class Rig:
    def __init__(self, env, dos=None):
        self.env = env
        self.L = env.labels
        self.dos = dos or Dos()
        m = t6.Machine.__new__(t6.Machine)
        m.labels, m.dos = self.L, self.dos
        m.mem = t6.Memory(env.image, env.load_addr, self.dos)
        for n in ("uci_status_len", "uci_status_force", "net_last_error",
                  "net_tcp_state"):
            m.mem.write(self.L[n], 0)
        m.cpu = t6.FastCPU(m.mem, self.L, False)
        m.reu = None
        if "cold_bank_init" in self.L:
            m.reu = REU(m.mem.ram)
            m.mem.uci = Bus(m.reu, self.dos)
        self.m = m
        self.cpu = m.cpu
        self.ram = m.mem.ram
        # scenario knobs
        self.server_key = None              # None: the flight has no Certificate
        self.ignore_hook_carry = False      # model a record layer that drops it
        self.name_ok = True
        self.connect_ok = True
        self.bundle_pub = None              # cryptography public key
        # observations
        self.out = bytearray()
        self.ahead: list[int] = []          # in the KERNAL buffer already
        self.later: list[int] = []          # typed after the question
        self.events: list[str] = []
        self.getin_while_connected = 0
        self.ecdsa_calls = 0
        self._install()
        self.ram[self.L["net_initialized"]] = 1
        if m.reu is not None:
            self.cpu.call(self.L["cold_bank_init"])

    # -- hooks ------------------------------------------------------------------
    def _install(self):
        L, cpu, ram = self.L, self.cpu, self.ram
        step = cpu.step
        hooks = {
            CHROUT: self._chrout, GETIN: self._getin,
            L["net_dns_resolve"]: lambda: self._ret(False),
            L["net_tcp_connect"]: self._connect,
            L["net_tcp_close"]: self._close,
            L["tls_connect"]: self._tls_connect,
            L["tls_derive_handshake_keys"]: lambda: self._ret(False),
            L["tls_send_finished"]: self._finished,
            L["x509_verify_hostname"]: lambda: self._ret(not self.name_ok),
            L["http_build_get"]: lambda: self._ret(False),
            L["tls_send"]: self._get,
            L["http_recv_body"]: lambda: self._ret(False),
            L["print_resp_body"]: lambda: self._ret(False),
        }
        if "ecdsa_verify" in L:
            hooks[L["ecdsa_verify"]] = self._ecdsa
        self.hooks = hooks

        def traced():
            h = hooks.get(cpu.pc)
            if h is not None:
                h()
                cpu.steps += 1
                return
            step()
        cpu.step = traced

    def _ret(self, carry: bool):
        self.cpu.c = carry
        self.cpu._op_RTS(None)

    def _chrout(self):
        self.out.append(self.cpu.a)
        self._ret(self.cpu.c)

    def _getin(self):
        if self.ram[self.L["net_tcp_state"]] == NET_CONNECTED:
            self.getin_while_connected += 1
        if self.ram[NDX] and self.ahead:
            k = self.ahead.pop(0)
            self.ram[NDX] -= 1
        else:
            self.ahead.clear()          # the buffer is whatever $C6 says
            k = self.later.pop(0) if self.later else 0x0D
        self.cpu.a = k
        self.cpu.z, self.cpu.n = k == 0, bool(k & 0x80)
        self._ret(self.cpu.c)

    def _connect(self):
        self.events.append("connect")
        self.ram[self.L["net_tcp_state"]] = NET_CONNECTED if self.connect_ok else 3
        self._ret(not self.connect_ok)

    def _close(self):
        self.events.append("close")
        self.ram[self.L["net_tcp_state"]] = NET_CLOSED
        self._ret(False)

    def _finished(self):
        self.events.append("finished")
        self._ret(False)

    def _get(self):
        self.events.append("get")
        self._ret(False)

    def nested(self, addr) -> bool:
        cpu = self.cpu
        cpu._push((NESTED - 1) >> 8)
        cpu._push((NESTED - 1) & 0xFF)
        cpu.pc = addr
        n = 0
        while cpu.pc != NESTED:
            cpu.step()
            n += 1
            if n > 20_000_000:
                raise t6.CPUError(f"nested call to ${addr:04X} did not return")
        return cpu.c

    def _tls_connect(self):
        """The handshake, reduced to what the hook sees and decides."""
        L, ram = self.L, self.ram
        self.events.append("handshake")
        ram[L["tls_reached_connected"]] = 0
        ram[L["tls_state"]] = 2
        if self.nested(L["cert_pin_hs_keys"]):
            return self._tls_fail()
        ram[L["tls_state"]] = TLS_CERT
        if self.server_key is not None:
            win = L["cert_buf"] + 0x100       # where a leaf would sit
            ram[win:win + 91] = spki_der(self.server_key)
            qy = win + 59
            ram[0xFB], ram[0xFC] = qy & 0xFF, qy >> 8    # zp_ptr -> Qy
            ram[L["ecdsa_curve_id"]] = 0
            if self.nested(L["cert_pin_check"]) and not self.ignore_hook_carry:
                return self._tls_fail()
        if self.nested(L["cert_pin_send_finished"]):
            return self._tls_fail()
        ram[L["tls_state"]] = TLS_CONNECTED
        ram[L["tls_reached_connected"]] = 1
        self._ret(False)

    def _tls_fail(self):
        self.ram[self.L["tls_state"]] = TLS_ERROR
        self._ret(True)

    def _ecdsa(self):
        self.ecdsa_calls += 1
        a = self.L["ecdsa_sig_r"]
        st = bytes(self.ram[a:a + 160])
        r, s = int.from_bytes(st[0:32], "big"), int.from_bytes(st[32:64], "big")
        h = st[64:96]
        qx, qy = int.from_bytes(st[96:128], "big"), int.from_bytes(st[128:160], "big")
        ok = self.ram[self.L["ecdsa_curve_id"]] == 0
        try:
            pub = ec.EllipticCurvePublicNumbers(qx, qy, ec.SECP256R1()).public_key()
            from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
            pub.verify(encode_dss_signature(r, s), h,
                       ec.ECDSA(Prehashed(hashes.SHA256())))
        except (InvalidSignature, ValueError):
            ok = False
        self._ret(not ok)

    # -- driving ----------------------------------------------------------------
    def get(self, host="", keys=(), ahead=()):
        """Press G: type host (RETURN alone = the default) and path, then
        `keys` for whatever the policy asks. Returns the screen text."""
        self.out.clear()
        self.events.clear()
        self.later = petscii_line(host) + [0x0D] + list(keys)
        self.ahead = list(ahead)
        self.ram[NDX] = len(self.ahead)
        self.cpu.call(self.L["do_https_get"], budget=200_000_000)
        return self.screen()

    def screen(self) -> str:
        return "".join(chr(b) if 0x20 <= b < 0x60 else "\n" if b == 0x0D else ""
                       for b in self.out)

    def r8(self, name, off=0):
        return self.ram[self.L[name] + off]

    def rn(self, name, n):
        a = self.L[name]
        return bytes(self.ram[a:a + n])


class Env:
    def __init__(self, name, args):
        self.name = name
        self.args = args
        raw = (REPO / "build" / "c64-https.prg").read_bytes()
        self.load_addr = raw[0] | raw[1] << 8
        self.image = raw[2:]
        self.labels = {}
        for line in (REPO / "build" / "labels.txt").read_text().splitlines():
            p = line.split()
            if len(p) >= 3 and p[0] == "al" and p[2].startswith("."):
                self.labels[p[2][1:]] = int(p[1].split(":")[-1], 16)
        self.bundle = "TRUST_BUNDLE=1" in args
        self.pinned = any(a.startswith("HTTPS_PIN_SPKI_SHA256=") for a in args)


A_, B_ = f"{t6.DIR}/TRUST.A", f"{t6.DIR}/TRUST.B"
P_ = f"{t6.DIR}/TRUST.P"
K1, K2, K3, KB = (None,) * 4
HOST, OTHER = "lemon64.com", "github.com"
KEY_A, KEY_Y, KEY_N = 0x41, 0x59, 0x4E


def store_with(host, key, mode=ts.MODE_TOFU):
    return ts.encode(1, [ts.Record.for_host(host, spki_hash(key), mode=mode)])


def writes(dos):
    return [x for x in dos.log if x[0] == "open" and x[1][1] & 0x02]


def lookup(dos, host):
    """The host's record in the store on 'disk', as the 6502 would pick it."""
    return ts.lookup(ts.select(dos.files.get(A_), dos.files.get(B_)), host)


# --- scenarios ------------------------------------------------------------------

def sc_first_use(env):
    r2 = Rig(env)
    r2.server_key = K1
    scr = r2.get(HOST)
    check("TRUST STORE EMPTY" in scr and "TRUST: NEW HOST" in scr,
          f"{env.name} first use: banner lines missing:\n{scr}")
    check(r2.events == ["connect", "handshake", "finished", "get", "close"],
          f"{env.name} first use: events {r2.events}")
    want = ts.save(None, None, HOST, ts.Record.for_host(HOST, spki_hash(K1)))
    check(want[0] == 0 and r2.dos.files.get(A_) == want[1],
          f"{env.name} first use: TRUST.A is not the mirror's TOFU record")
    check(f"KEY RECORDED {spki_hash(K1)[:4].hex().upper()}" in scr,
          f"{env.name} first use: no KEY RECORDED line")
    # EMPTY is shown on every GET while the store is empty
    r3 = Rig(env)
    r3.server_key = K1
    r3.name_ok = False
    r3.get(HOST)
    s2 = r3.get(HOST)
    check("TRUST STORE EMPTY" in s2, f"{env.name}: EMPTY not shown on a later GET")
    return r2


def sc_match(env):
    dos = Dos({A_: store_with(HOST, K1)})
    r = Rig(env, dos)
    r.server_key = K1
    before = dict(dos.files)
    scr = r.get(HOST)
    check(f"TRUST: KNOWN KEY {spki_hash(K1)[:4].hex().upper()}" in scr,
          f"{env.name} match: no KNOWN KEY line:\n{scr}")
    check("finished" in r.events and "get" in r.events,
          f"{env.name} match: events {r.events}")
    check(not writes(dos) and dos.files == before,
          f"{env.name} match: the store was written ({writes(dos)})")


def sc_changed_refused(env):
    dos = Dos({A_: store_with(HOST, K1)})
    r = Rig(env, dos)
    r.server_key = K2
    before = dict(dos.files)
    scr = r.get(HOST, keys=[0x0D, KEY_N])
    full = spki_hash(K2).hex().upper()
    check("KEY CHANGED EXP" in scr, f"{env.name} changed: no KEY CHANGED:\n{scr}")
    check(full[:32] in scr and full[32:] in scr,
          f"{env.name} changed: the whole 32 B hash is not shown")
    check("finished" not in r.events and "get" not in r.events,
          f"{env.name} changed: Finished/GET went out: {r.events}")
    check(r.events.count("connect") == 1, f"{env.name} changed: redialled: {r.events}")
    check(dos.files == before and not writes(dos),
          f"{env.name} changed: the store was written")
    check(r.r8("tp_ovr_armed") == 0, f"{env.name} changed: armed without A")
    check(r.r8("tp_mode") == TP["TP_M_NONE"], f"{env.name} changed: tp_mode sticky")


def sc_accept_exact(env):
    dos = Dos({A_: store_with(HOST, K1)})
    r = Rig(env, dos)
    r.server_key = K2
    scr = r.get(HOST, keys=[KEY_A])                 # arm K2
    check("ACCEPT ARMED: G, SAME HOST" in scr and r.r8("tp_ovr_armed"),
          f"{env.name} accept: A did not arm:\n{scr}")
    check(r.rn("tp_override", 32) == spki_hash(K2),
          f"{env.name} accept: the armed hash is not the shown one")
    before = dict(dos.files)
    r.server_key = K3                               # a different key arrives
    scr = r.get(HOST, keys=[0x0D, KEY_N])
    check("ACCEPTED KEY NOT SEEN" in scr and "finished" not in r.events,
          f"{env.name} accept: K3 not refused:\n{scr} {r.events}")
    check(r.r8("tp_ovr_armed") == 0, f"{env.name} accept: the arm survived a mismatch")
    check(dos.files == before, f"{env.name} accept: K3 attempt wrote the store")
    r.server_key = K2                               # K2 again, NOT re-armed
    r.get(HOST, keys=[0x0D, KEY_N])
    check("finished" not in r.events and dos.files == before,
          f"{env.name} accept: a spent arm still accepted K2")
    r.get(HOST, keys=[KEY_A])                       # re-arm on K2
    scr = r.get(HOST)                               # retry with K2
    check("finished" in r.events and "get" in r.events,
          f"{env.name} accept: the armed K2 retry did not complete: {r.events}")
    rec = lookup(dos, HOST)
    check(rec is not None and rec.spki == spki_hash(K2) and rec.mode == ts.MODE_ACCEPTED,
          f"{env.name} accept: store holds {rec}")
    check(r.r8("tp_ovr_armed") == 0, f"{env.name} accept: arm not consumed")
    r.server_key = K3                               # and nothing sticky
    r.get(HOST, keys=[0x0D, KEY_N])
    check("finished" not in r.events, f"{env.name} accept: K3 accepted afterwards")


def sc_accept_other_host(env):
    dos = Dos({A_: ts.encode(1, [ts.Record.for_host(HOST, spki_hash(K1)),
                                 ts.Record.for_host(OTHER, spki_hash(K1))])})
    r = Rig(env, dos)
    r.server_key = K2
    r.get(HOST, keys=[KEY_A])                       # armed for HOST
    check(r.r8("tp_ovr_armed") == 1, f"{env.name} other host: not armed")
    r.get(OTHER, keys=[0x0D, KEY_N])                # OTHER presents K2
    check("finished" not in r.events, f"{env.name} other host: OTHER took the arm")
    check(lookup(dos, OTHER).spki == spki_hash(K1), f"{env.name} other host: OTHER rewritten")
    check(r.r8("tp_ovr_armed") == 0, f"{env.name} other host: arm survived another host")
    r.get(HOST, keys=[0x0D, KEY_N])                 # HOST with K2: refused now
    check("finished" not in r.events and lookup(dos, HOST).spki == spki_hash(K1),
          f"{env.name} other host: the dropped arm still applied to HOST")


def sc_type_ahead(env):
    """An 'A' already in the KERNAL buffer when the accept question is
    printed (typed ahead, e.g. a bounced key) must not answer it."""
    dos = Dos({A_: store_with(HOST, K1)})
    r = Rig(env, dos)
    r.server_key = K2
    orig = r.hooks[CHROUT]

    def chrout_seed():
        orig()
        if r.screen().endswith("ACCEPT ON RETRY? A=YES ") and not r.ahead:
            r.ahead = [KEY_A]           # in the buffer before the question
            r.ram[NDX] = 1              #  is answered
    r.hooks[CHROUT] = chrout_seed
    r.get(HOST, keys=[0x0D, KEY_N])
    check(r.r8("tp_ovr_armed") == 0, f"{env.name} type-ahead: a key typed ahead armed it")
    # control: the same key typed AFTER the question arms it
    r.hooks[CHROUT] = orig
    r.get(HOST, keys=[KEY_A])
    check(r.r8("tp_ovr_armed") == 1, f"{env.name} type-ahead control: A after the question did not arm")


# Seeds whose SPKI hashes share their first / last 4 bytes (found by a
# birthday search): a compare of fewer than 32 bytes, at either end, takes
# one key for the other.
PREFIX_PAIR = (111185, 112152)
SUFFIX_PAIR = (116863, 122820)


def sc_near_collision(env):
    for name, (a, b) in (("prefix", PREFIX_PAIR), ("suffix", SUFFIX_PAIR)):
        ka, kb = make_key(a), make_key(b)
        ha, hb = spki_hash(ka), spki_hash(kb)
        assert ha != hb and (ha[:4] == hb[:4] if name == "prefix" else ha[-4:] == hb[-4:])
        # the store holds ka; kb shares 4 bytes of its hash
        dos = Dos({A_: store_with(HOST, ka)})
        r = Rig(env, dos)
        r.server_key = kb
        r.get(HOST, keys=[0x0D, KEY_N])
        check("finished" not in r.events,
              f"{env.name} {name} near-collision: the store took kb for ka")
        # the accept armed for kb must not take ka
        dos = Dos({A_: store_with(HOST, K1)})
        r = Rig(env, dos)
        r.server_key = kb
        r.get(HOST, keys=[KEY_A])
        r.server_key = ka
        r.get(HOST, keys=[0x0D, KEY_N])
        check("finished" not in r.events and lookup(dos, HOST).spki == spki_hash(K1),
              f"{env.name} {name} near-collision: the accept for kb took ka")


def sc_name_fail(env):
    r = Rig(env)
    r.server_key = K1
    r.name_ok = False
    r.get(HOST)
    check("finished" not in r.events, f"{env.name} name fail: Finished sent")
    check(not writes(r.dos), f"{env.name} name fail: the store was written")


def sc_store_fail(env):
    bad = bytearray(store_with(HOST, K1))
    bad[-1] ^= 1                                    # checksum, both slots
    dos = Dos({A_: bytes(bad), B_: bytes(bad)})
    r = Rig(env, dos)
    r.server_key = K1
    scr = r.get(HOST, keys=[KEY_N])
    check("TRUST FAIL 05" in scr or "TRUST FAIL 07" in scr,
          f"{env.name} store fail: no TRUST FAIL line:\n{scr}")
    check("NOT DIALLED" in scr and "connect" not in r.events,
          f"{env.name} store fail: dialled after N: {r.events}")
    # no medium: Y overrides one fetch, unpinned
    dos2 = Dos(dirs=())
    r2 = Rig(env, dos2)
    r2.server_key = K2
    scr = r2.get(HOST, keys=[KEY_Y])
    check("TRUST FAIL 02" in scr, f"{env.name} no medium: reason not NOPATH:\n{scr}")
    check(scr.count("** UNPINNED: KEY NOT CHECKED **") == 2,
          f"{env.name} unpinned: the banner is not shown before and after")
    check("finished" in r2.events and "get" in r2.events,
          f"{env.name} unpinned: the fetch did not happen: {r2.events}")
    check(not writes(dos2), f"{env.name} unpinned: wrote the store")
    check(r2.r8("tp_mode") == TP["TP_M_NONE"], f"{env.name} unpinned: sticky")
    r2.get(HOST, keys=[KEY_N])                      # nothing carried over
    check("connect" not in r2.events, f"{env.name} unpinned: carried to the next GET")


def sc_changed_unpinned(env):
    dos = Dos({A_: store_with(HOST, K1)})
    r = Rig(env, dos)
    r.server_key = K2
    before = dict(dos.files)
    scr = r.get(HOST, keys=[0x0D, KEY_Y])
    check(r.events.count("connect") == 2 and r.events.count("finished") == 1,
          f"{env.name} changed->unpinned: events {r.events}")
    check("** UNPINNED: KEY NOT CHECKED **" in scr, f"{env.name} changed->unpinned: no banner")
    check(dos.files == before and not writes(dos),
          f"{env.name} changed->unpinned: recorded the new key")
    r.get(HOST, keys=[0x0D, KEY_N])
    check("finished" not in r.events, f"{env.name} changed->unpinned: sticky")


def sc_no_trust_pre(env):
    r = Rig(env)
    r.server_key = K1
    r.ram[r.L["tp_mode"]] = TP["TP_M_NONE"]
    r.ram[r.L["net_tcp_state"]] = NET_CONNECTED
    r.cpu.call(r.L["tls_connect"])
    check("finished" not in r.events and r.r8("cert_pin_status") == TP["TP_ST_REFUSED"],
          f"{env.name} no trust_pre: the hook did not refuse ({r.events})")


def sc_interlock(env):
    """#152: client Finished needs the hook to have RUN and allowed it,
    whatever the record layer does with the hook's carry."""
    r = Rig(env)
    r.server_key = None                             # no Certificate at all
    r.get(HOST)
    check("finished" not in r.events, f"{env.name} interlock: Finished with no Certificate")
    dos = Dos({A_: store_with(HOST, K1)})
    r = Rig(env, dos)
    r.server_key = K2
    r.ignore_hook_carry = True                      # KEY CHANGED, carry dropped
    r.get(HOST, keys=[0x0D, KEY_N])
    check("finished" not in r.events,
          f"{env.name} interlock: Finished after KEY CHANGED with the carry dropped")


def sc_build_pin(env):
    r = Rig(env)
    r.server_key = K2                               # the pin is K1
    scr = r.get("", keys=[KEY_A, KEY_Y])            # RETURN: the pinned host
    check("TRUST: BUILD PIN" in scr and "PIN FAIL EXP" in scr,
          f"{env.name} pin: not the build pin path:\n{scr}")
    check("finished" not in r.events and r.events.count("connect") == 1,
          f"{env.name} pin: bypassed or redialled: {r.events}")
    check(not r.dos.log, f"{env.name} pin: the store was touched: {r.dos.log[:3]}")
    check(r.later == [KEY_A, KEY_Y], f"{env.name} pin: a question was asked")
    r.server_key = K1
    r.get("")
    check("finished" in r.events and not r.dos.log,
          f"{env.name} pin: K1 not accepted, or the store touched")
    r.server_key = K2                               # another host: TOFU
    scr = r.get(OTHER)
    check("TRUST: NEW HOST" in scr and lookup(r.dos, OTHER) is not None,
          f"{env.name} pin: another host did not go to the store")


# --- bundle ---------------------------------------------------------------------

def bundle_file(records, gen=1, key=None):
    import trust_bundle as tb
    key = key or tb.load_private_key(tb.TEST_KEY_PATH)
    return tb.sign(key, gen, records)


def leaf(host, k):
    import trust_bundle as tb
    return tb.leaf_record(host, spki_hash(k))


def floor():
    text = (REPO / "tools/trust_bundle_TEST_ONLY_pubkey.inc").read_text()
    return int(re.search(r"TRUST_BUNDLE_GEN_FLOOR\s*=\s*\$([0-9A-F]+)", text).group(1), 16)


def sc_bundle(env):
    import trust_bundle as tb
    good = bundle_file([leaf(HOST, K1), leaf(OTHER, K3)], gen=floor())
    # good pin, first use, server agrees
    dos = Dos({P_: good})
    r = Rig(env, dos)
    r.server_key = K1
    scr = r.get(HOST)
    check("VERIFYING BUNDLE" in scr and f"BUNDLE PIN {spki_hash(K1)[:4].hex().upper()}" in scr,
          f"{env.name} bundle: good bundle not taken:\n{scr}")
    check(r.ecdsa_calls == 1, f"{env.name} bundle: {r.ecdsa_calls} verifies")
    rec = lookup(dos, HOST)
    check(rec is not None and rec.mode == ts.MODE_TOFU and rec.spki == spki_hash(K1),
          f"{env.name} bundle: agreed first use not recorded TOFU: {rec}")
    # verify once per boot: a second GET re-hashes, no ECDSA
    r.get(HOST)
    check(r.ecdsa_calls == 1, f"{env.name} bundle: verified again ({r.ecdsa_calls})")
    # swapped on disk: verified afresh
    dos.files[P_] = bundle_file([leaf(HOST, K1)], gen=floor() + 1)
    scr = r.get(HOST)
    check(r.ecdsa_calls == 2 and "BUNDLE PIN" in scr,
          f"{env.name} bundle: a swapped file was not re-verified")

    # mismatch at first use: warn, finish, ask; no -> not recorded
    dos = Dos({P_: good})
    r = Rig(env, dos)
    r.server_key = K2
    scr = r.get(HOST, keys=[0x0D])
    check("BUNDLE MISMATCH EXP" in scr and "RECORD KEY? A=YES" in scr,
          f"{env.name} bundle mismatch: no warning/question:\n{scr}")
    check("finished" in r.events and "get" in r.events,
          f"{env.name} bundle mismatch: the fetch was blocked")
    check(lookup(dos, HOST) is None, f"{env.name} bundle mismatch: recorded without A")
    r.get(HOST, keys=[KEY_A])
    rec = lookup(dos, HOST)
    check(rec is not None and rec.mode == ts.MODE_ACCEPTED and rec.spki == spki_hash(K2),
          f"{env.name} bundle mismatch: A did not record ACCEPTED/K2: {rec}")

    # every rejection: the fetch still happens, nothing pinned
    other = ec.generate_private_key(ec.SECP256R1())
    cases = {}
    t = bytearray(good); t[8 + 20] ^= 1; cases["record byte"] = (bytes(t), "BAD SIGNATURE")
    end = 8 + 64 * 2
    t = bytearray(good); t[end + 5] ^= 1; cases["r"] = (bytes(t), "BAD SIGNATURE")
    t = bytearray(good); t[end + 40] ^= 1; cases["s"] = (bytes(t), "BAD SIGNATURE")
    cases["wrong key"] = (bundle_file([leaf(HOST, K1)], gen=floor(), key=other), "BAD SIGNATURE")
    t = bytearray(good); t[0] ^= 1; cases["magic"] = (bytes(t), "BAD FORMAT")
    t = bytearray(good); t[4] = 2; cases["version"] = (bytes(t), "BAD FORMAT")
    cases["size +1"] = (good + b"\0", "BAD FORMAT")
    cases["size -1"] = (good[:-1], "BAD FORMAT")
    t = bytearray(good); t[7] = 33; cases["N=33"] = (bytes(t), "BAD FORMAT")
    recs = [leaf(HOST, K1), leaf(OTHER, K3)]
    recs.sort(key=lambda x: x.key)
    unsorted = tb.unsigned_body(floor(), recs)
    hdr, r0, r1 = unsorted[:8], unsorted[8:72], unsorted[72:136]
    cases["unsorted"] = (hdr + r1 + r0 + good[-64:], "BAD FORMAT")
    cases["duplicate"] = (hdr + r0 + r0 + good[-64:], "BAD FORMAT")
    for off, name in ((48, "mode"), (49, "flags"), (50, "uses")):
        t = bytearray(good); t[8 + off] ^= 0x02; cases[name] = (bytes(t), "BAD FORMAT")
    if floor() > 0:
        cases["gen below floor"] = (bundle_file([leaf(HOST, K1)], gen=floor() - 1), "OLD GEN")
    for name, (blob, want) in cases.items():
        dos = Dos({P_: blob})
        r = Rig(env, dos)
        r.server_key = K2
        scr = r.get(HOST)
        check(f"BUNDLE {want}" in scr and r.r8("tb_found") == 0,
              f"{env.name} bundle {name}: want {want}:\n{scr}")
        check("finished" in r.events and "BUNDLE MISMATCH" not in scr,
              f"{env.name} bundle {name}: the bad bundle affected the fetch")
    # absent: NO BUNDLE once per boot
    r = Rig(env)
    r.server_key = K1
    s1 = r.get(HOST, keys=[0x0D])
    s2 = r.get(OTHER, keys=[0x0D])
    check("NO BUNDLE" in s1 and "NO BUNDLE" not in s2,
          f"{env.name} bundle absent: NO BUNDLE not exactly once")


def sc_never_mid_handshake(env, rigs_getin):
    check(rigs_getin == 0, f"{env.name}: {rigs_getin} GETIN calls while CONNECTED")


# --- driver ---------------------------------------------------------------------

_ALL_RIGS: list[Rig] = []
_orig_init = Rig.__init__


def _tracking_init(self, *a, **kw):
    _orig_init(self, *a, **kw)
    _ALL_RIGS.append(self)


Rig.__init__ = _tracking_init


def build(args):
    subprocess.run(["make", "clean"], cwd=REPO, check=True, capture_output=True)
    p = subprocess.run(["make"] + args, cwd=REPO, capture_output=True, text=True)
    if p.returncode:
        sys.exit(cannot_run(f"make {' '.join(args)} failed:\n{p.stdout[-800:]}{p.stderr[-800:]}",
                            certifies=CERTIFIES))


def main():
    global K1, K2, K3
    if ec is None:
        return cannot_run("the `cryptography` package is not installed",
                          certifies=CERTIFIES)
    K1, K2, K3 = make_key(1111), make_key(2222), make_key(3333)
    want = os.environ.get("C64_TP_IMAGES")
    names = want.split(",") if want else list(IMAGES)
    for name in names:
        args = list(IMAGES[name])
        if name == "onchip-pinned":
            args.append("HTTPS_PIN_SPKI_SHA256=" + spki_hash(K1).hex())
        print(f"== {name}: make {' '.join(args)}")
        build(args)
        env = Env(name, args)
        _ALL_RIGS.clear()
        scenarios = [sc_first_use, sc_match, sc_changed_refused, sc_accept_exact,
                     sc_accept_other_host, sc_near_collision, sc_type_ahead,
                     sc_name_fail, sc_store_fail, sc_changed_unpinned,
                     sc_no_trust_pre, sc_interlock]
        if env.pinned:
            scenarios.append(sc_build_pin)
        if env.bundle:
            scenarios.append(sc_bundle)
        only = os.environ.get("C64_TP_SCENARIOS")
        if only:
            scenarios = [sc for sc in scenarios if sc.__name__ in only.split(",")]
        for sc in scenarios:
            n = len(FAILED)
            try:
                sc(env)
            except t6.CPUError as e:
                check(False, f"{env.name} {sc.__name__}: {e}")
            print(f"  {'PASS' if len(FAILED) == n else 'FAIL'} {sc.__name__}")
        sc_never_mid_handshake(env, sum(r.getin_while_connected for r in _ALL_RIGS))
    print(f"{PASSED} checks passed, {len(FAILED)} failed")
    return verdict(PASSED, len(FAILED), certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
