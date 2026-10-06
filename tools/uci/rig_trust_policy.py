#!/usr/bin/env python3
"""rig_trust_policy.py -- the trust policy, end to end, on a real Ultimate (#155, L3).

tools/test_trust_policy_6502.py runs the shipped policy against models.
This walks the MENU on the U64E, the way a person does, with the store on
the firmware's real /USB1 and a real TLS 1.3 server, and reads the result
back over FTP. Two modes:

LOCAL (default). A listener on this Mac serves a self-signed P-256 leaf
whose SAN dNSName is this Mac's LAN address, which is also what the rig
types at the HOST prompt (the firmware dials it; x509_name.s matches it).
Build with the test store directory and the listener's port:

    make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1 TRUST_STORE=1 \\
        TRUST_STORE_DIR=/USB1/c64https-test HTTPS_PORT=4433
    U64_HOST=... python3 tools/uci/rig_trust_policy.py

  1  first use, EMPTY store, key K1      TRUST STORE EMPTY, NEW HOST, KEY
                                        RECORDED; TRUST.A = the mirror's
                                        TOFU record for (host, K1)
  2  same key                           KNOWN KEY; the GET completes; the
                                        store is not written
  3  listener RESTARTED with a NEW key  KEY CHANGED; the full hash; no
     K2; RETURN, then N                 client Finished (the listener never
                                        completes its handshake); store
                                        unchanged
  4  K2 again; A (accept on retry)      ACCEPT ARMED
  5  K2, 'G' again                      the GET completes; TRUST.B =
                                        ACCEPTED/K2, generation 2
  6  listener restarted with K1;        KEY CHANGED, then UNPINNED: the
     RETURN, then Y                     rig sees a second connection that
                                        completes; the store is unchanged

LIVE (RIG_MODE=live): one GET of the build-time host, first use, on the
comb Wikipedia demo:

    make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1 TRUST_STORE=1 \\
        TRUST_STORE_DIR=/USB1/c64https-test HTTPS_HOST=en.wikipedia.org \\
        HTTPS_PATH=/wiki/Commodore_64 HTTPS_BODY_TO_REU=1
    RIG_MODE=live U64_HOST=... python3 tools/uci/rig_trust_policy.py

  L  TRUST STORE EMPTY, NEW HOST; the viewer opens (Q leaves it); KEY
     RECORDED; TRUST.A holds en.wikipedia.org's record, whose first 4
     bytes are the ones shown on screen. The key this Mac sees for the
     host is printed beside it (informational: edges may differ).

Both modes work in /USB1/c64https-test (shared with rig_trust_store.py),
which the rig creates, requires to hold nothing but TRUST.A / TRUST.B, and
removes at the end. Every fetch is allowed to finish (or to refuse and
close) before the next key; the C64 is reset only at boot, before any
socket, and at the end after the close is confirmed.

Exit: 0 pass, 1 a check failed, 2 could not run, 3 lock timeout, 4 device
prep/preflight/load refused.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools"))

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout  # noqa: E402
from c64_test_harness.backends.ultimate64_client import Ultimate64Client          # noqa: E402
from c64_test_harness.uci_network import disable_uci, enable_uci                  # noqa: E402
from cryptography import x509                                                     # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization                  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec                          # noqa: E402
from cryptography.x509.oid import NameOID                                         # noqa: E402

from _device_lock_helper import LockTimeoutConfigError, acquire_device_lock        # noqa: E402
from _device_prep import DevicePrepError, prepare_device                          # noqa: E402
from _petscii_keys import push_keys, target_keys                                 # noqa: E402
from _prg_load import PrgLoadError, load_verified_and_run                         # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu                       # noqa: E402
from _rig_lifecycle import guard_socket_teardown                                  # noqa: E402
from _skip_policy import cannot_run, verdict                                      # noqa: E402
from _temp_gc import gc_temp                                                      # noqa: E402
from boot_check import decode_screen, screen_text                                 # noqa: E402
from rig_trust_store import OURS, TEST_DIR, Ftp, image_store_path, load_labels   # noqa: E402
import trust_store as ts                                                          # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
MODE = os.environ.get("RIG_MODE", "local")
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
SCALE = max(1.0, 48.0 / TURBO_MHZ)
INIT_WAIT = float(os.environ.get("C64_INIT_WAIT", str(90 * SCALE)))
# live streams the ~750 KB Wikipedia demo body: 240 s did not cover it at
# 48 MHz (2026-10-06); 900 s is what rig_https_banner.py's runs of it use
FETCH_TIMEOUT = float(os.environ.get(
    "FETCH_TIMEOUT", str((900 if MODE == "live" else 240) * SCALE)))
PRG_PATH = REPO / "build" / "c64-https.prg"
LABELS_PATH = REPO / "build" / "labels.txt"
A_PATH, B_PATH = f"{TEST_DIR}/TRUST.A", f"{TEST_DIR}/TRUST.B"
CERTIFIES = "the trust policy on the U64E (#155 phase 2, L3)"
NET_CONNECTED = 1
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 19\r\nConnection: close\r\n\r\nHELLO TRUST POLICY\n")


# --- the listener ---------------------------------------------------------------

def make_leaf(name: str, out: Path):
    """(cert path, key path, SPKI SHA-256) of a fresh self-signed P-256 leaf
    whose only SAN is dNSName `name`."""
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .sign(key, hashes.SHA256()))
    out.mkdir(parents=True, exist_ok=True)
    tag = hashlib.sha256(name.encode() + os.urandom(8)).hexdigest()[:8]
    cp, kp = out / f"leaf-{tag}.pem", out / f"leaf-{tag}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return cp, kp, hashlib.sha256(spki).digest()


class Listener:
    """A TLS 1.3 server for one leaf; accepts connections until stopped and
    records, per connection, whether the handshake completed (i.e. the
    client Finished arrived) and the request it read."""

    def __init__(self, bind_ip, port, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = self.ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.load_cert_chain(str(cert), str(key))
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((bind_ip, port))
        self.srv.listen(2)
        self.srv.settimeout(0.5)
        self.conns: list[dict] = []
        self.stopping = False
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()

    def _run(self):
        while not self.stopping:
            try:
                raw, addr = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            rec = {"addr": addr[0], "handshake": False, "request": b""}
            self.conns.append(rec)
            raw.settimeout(FETCH_TIMEOUT)
            try:
                tls = self.ctx.wrap_socket(raw, server_side=True)
                rec["handshake"] = True     # the client Finished verified
                rec["request"] = tls.recv(1024)
                tls.sendall(RESPONSE)
                time.sleep(1.0)
                tls.close()
            except (ssl.SSLError, OSError) as exc:
                rec["error"] = f"{type(exc).__name__}: {exc}"
                try:
                    raw.close()
                except OSError:
                    pass

    def stop(self):
        self.stopping = True
        self.th.join(timeout=5)
        self.srv.close()


# --- the C64 ---------------------------------------------------------------------

class Run:
    def __init__(self, client, L):
        self.client, self.L = client, L
        self.passed, self.failed, self.notes = 0, [], {}
        self.seen = ""          # every screen since the last 'G' (lines scroll)

    def check(self, cond, what):
        if cond:
            self.passed += 1
            print(f"  ok    {what}")
        else:
            self.failed.append(what)
            print(f"  FAIL  {what}")

    def screen(self) -> str:
        s = screen_text(decode_screen(bytes(self.client.read_mem(0x0400, 1000))))
        self.seen += "\n" + s
        return s

    def r8(self, name):
        return self.client.read_mem(self.L[name], 1)[0]

    def wait(self, marker, budget, *, gone=None) -> str | None:
        end = time.monotonic() + budget
        while time.monotonic() < end:
            s = self.screen()
            if marker in s:
                return s
            time.sleep(0.5)
        print(f"  [timeout {budget:.0f}s waiting for {marker!r}]\n{self.screen()}")
        return None

    def keys(self, text):
        """Unshifted keys: target_keys sends "a" as the plain A key ($41),
        which is what the policy's questions compare; "A" would be SHIFT+A."""
        push_keys(self.client, target_keys(text))

    def settled(self, budget=60.0) -> bool:
        """do_https_get has returned: the socket is closed and trust_post
        is done (tp_mode back to NONE, nothing awaiting a key)."""
        end = time.monotonic() + budget
        while time.monotonic() < end:
            if (self.r8("net_tcp_state") != NET_CONNECTED and self.r8("tp_mode") == 0
                    and self.r8("tls_state") in (0, 0xFF)):
                time.sleep(1.0)
                return True
            time.sleep(0.5)
        return False

    def clear_screen(self):
        self.client.write_mem(0x0400, bytes([0x20]) * 1000)
        self.seen = ""


def record_of(ftp, host):
    return ts.lookup(ts.select(ftp.get(A_PATH), ftp.get(B_PATH)), host)


def phases_local(run, ftp, ip, port, out, listener_box, fetch_in_flight_box):
    """Phases 1-6; returns nothing, records checks on `run`."""
    c1, k1, h1 = make_leaf(ip, out)
    c2, k2, h2 = make_leaf(ip, out)
    run.notes.update(k1=h1.hex(), k2=h2.hex(), host=ip, port=port)
    hx = lambda h: h[:4].hex().upper()            # noqa: E731

    def restart(cert, key):
        if listener_box[0] is not None:
            listener_box[0].stop()
        listener_box[0] = Listener(ip, port, cert, key)
        return listener_box[0]

    def press_g(target_host):
        run.clear_screen()
        fetch_in_flight_box[0] = True
        run.client.send_text("G", finish_with_return=False)
        run.wait("HOST [", 20)
        run.keys(f"{target_host}\r\r")

    # 1 -- first use
    print("\n[1] first use, EMPTY store, K1")
    lst = restart(c1, k1)
    press_g(ip)
    s = run.wait("KEY RECORDED", FETCH_TIMEOUT)
    run.check(s is not None and "TRUST STORE EMPTY" in run.seen and "TRUST: NEW HOST" in run.seen,
              "first use: EMPTY + NEW HOST + KEY RECORDED on screen")
    run.check(s is not None and f"KEY RECORDED {hx(h1)}" in s, "first use: the recorded hash is K1's")
    run.check(run.settled(), "first use: settled")
    rec = record_of(ftp, ip)
    run.check(rec is not None and rec.spki == h1 and rec.mode == ts.MODE_TOFU,
              f"first use: the store on /USB1 holds TOFU/K1 ({rec})")
    want = ts.save(None, None, ip, ts.Record.for_host(ip, h1))
    run.check(want[0] == 0 and ftp.get(A_PATH) == want[1],
              "first use: TRUST.A is byte-identical to the host mirror's")
    run.check(lst.conns and lst.conns[-1]["handshake"] and b"GET " in lst.conns[-1]["request"],
              "first use: the listener saw client Finished and the GET")
    snap = (ftp.get(A_PATH), ftp.get(B_PATH))

    # 2 -- match
    print("\n[2] same key")
    n0 = len(lst.conns)
    press_g(ip)
    s = run.wait("DONE", FETCH_TIMEOUT)
    run.check(f"TRUST: KNOWN KEY {hx(h1)}" in run.seen, "match: KNOWN KEY K1")
    run.check(run.settled(), "match: settled")
    run.check(len(lst.conns) == n0 + 1 and lst.conns[-1]["handshake"], "match: the GET completed")
    run.check((ftp.get(A_PATH), ftp.get(B_PATH)) == snap, "match: the store was not written")

    # 3 -- restarted with a NEW key: refused
    print("\n[3] listener restarted with K2; RETURN, N")
    lst = restart(c2, k2)
    press_g(ip)
    s = run.wait("ACCEPT ON RETRY? A=YES", FETCH_TIMEOUT)
    full = h2.hex().upper()
    run.check(f"KEY CHANGED EXP {hx(h1)} GOT {hx(h2)}" in run.seen,
              "changed: KEY CHANGED EXP K1 GOT K2")
    run.check(s is not None and full[:32] in s and full[32:] in s, "changed: the full hash shown")
    run.keys("\r")
    run.wait("CONTINUE UNPINNED? Y/N", 30)
    run.keys("n")
    run.check(run.settled(), "changed: settled")
    run.check(all(not c["handshake"] for c in lst.conns) and len(lst.conns) == 1,
              f"changed: no client Finished reached the listener ({lst.conns})")
    run.check((ftp.get(A_PATH), ftp.get(B_PATH)) == snap, "changed: the store was not written")

    # 4 -- arm the accept
    print("\n[4] K2 again; A")
    press_g(ip)
    run.wait("ACCEPT ON RETRY? A=YES", FETCH_TIMEOUT)
    run.keys("a")
    s = run.wait("ACCEPT ARMED: G, SAME HOST", 30)
    run.check(s is not None, "accept: ACCEPT ARMED")
    run.check(run.settled(), "accept: settled")
    run.check((ftp.get(A_PATH), ftp.get(B_PATH)) == snap, "accept: arming wrote nothing")

    # 5 -- retry: recorded
    print("\n[5] K2, retry")
    n0 = len(lst.conns)
    press_g(ip)
    s = run.wait("KEY RECORDED", FETCH_TIMEOUT)
    run.check(f"ACCEPT ARMED {hx(h2)}" in run.seen and f"KEY RECORDED {hx(h2)}" in run.seen,
              "retry: armed K2, recorded K2")
    run.check(run.settled(), "retry: settled")
    run.check(len(lst.conns) == n0 + 1 and lst.conns[-1]["handshake"], "retry: the GET completed")
    rec = record_of(ftp, ip)
    run.check(rec is not None and rec.spki == h2 and rec.mode == ts.MODE_ACCEPTED,
              f"retry: the store holds ACCEPTED/K2 ({rec})")
    b = ftp.get(B_PATH)
    run.check(b is not None and ts.decode(b)[0] == 2, "retry: written to TRUST.B, generation 2")
    snap = (ftp.get(A_PATH), ftp.get(B_PATH))

    # 6 -- override
    print("\n[6] listener restarted with K1; RETURN, Y")
    lst = restart(c1, k1)
    press_g(ip)
    run.wait("ACCEPT ON RETRY? A=YES", FETCH_TIMEOUT)
    run.keys("\r")
    run.wait("CONTINUE UNPINNED? Y/N", 30)
    run.keys("y")
    s = run.wait("DONE", FETCH_TIMEOUT)
    run.check(run.seen.count("** UNPINNED: KEY NOT CHECKED **") >= 1, "override: UNPINNED banner")
    run.check(run.settled(), "override: settled")
    run.check(len(lst.conns) == 2 and not lst.conns[0]["handshake"] and lst.conns[1]["handshake"]
              and b"GET " in lst.conns[1]["request"],
              f"override: refused once, then one unpinned fetch ({lst.conns})")
    run.check((ftp.get(A_PATH), ftp.get(B_PATH)) == snap, "override: nothing recorded")
    rec = record_of(ftp, ip)
    run.check(rec is not None and rec.spki == h2, "override: the store still holds K2")


def phase_live(run, ftp, host, fetch_in_flight_box):
    print(f"\n[L] first use of {host}")
    run.clear_screen()
    fetch_in_flight_box[0] = True
    run.client.send_text("G", finish_with_return=False)
    run.wait("HOST [", 20)
    run.keys("\r\r")
    s = run.wait("TRUST: NEW HOST", 60)
    run.check(s is not None and "TRUST STORE EMPTY" in run.seen, "live: EMPTY + NEW HOST")
    # the viewer takes the screen once the body is in; Q leaves it, and
    # only then does do_https_get close the socket and run trust_post
    end = time.monotonic() + FETCH_TIMEOUT
    while time.monotonic() < end and "KEY RECORDED" not in run.screen():
        if run.r8("http_body_sink") and run.r8("net_tcp_state") != NET_CONNECTED:
            run.client.send_text("Q", finish_with_return=False)
            time.sleep(3)
        time.sleep(2)
    s = run.wait("KEY RECORDED", 30)
    run.check(s is not None, "live: KEY RECORDED")
    run.check(run.settled(), "live: settled")
    rec = record_of(ftp, host)
    shown = s.split("KEY RECORDED ", 1)[1][:8] if s else ""
    run.check(rec is not None and rec.mode == ts.MODE_TOFU and rec.spki[:4].hex().upper() == shown,
              f"live: TRUST.A holds TOFU for {host}, matching the screen ({shown})")
    if rec is not None:
        run.notes["live_spki"] = rec.spki.hex()
        try:
            import subprocess  # noqa: PLC0415
            p = subprocess.run([sys.executable, str(REPO / "tools" / "spki_pin.py"), host],
                               capture_output=True, text=True, timeout=60)
            run.notes["mac_sees"] = p.stdout.strip().splitlines()[-1]
            print(f"  (this Mac sees {run.notes['mac_sees']} for {host}; the C64 recorded "
                  f"{rec.spki.hex()})")
        except Exception as exc:        # noqa: BLE001 - informational only
            run.notes["mac_sees"] = f"unavailable: {exc}"


def main() -> int:
    if not PRG_PATH.is_file() or not LABELS_PATH.is_file():
        return cannot_run("build/c64-https.prg or labels.txt missing (see the docstring)",
                          certifies=CERTIFIES)
    L = load_labels()
    needed = ("trust_pre", "trust_post", "tp_mode", "net_tcp_state", "tls_state",
              "tls_reached_connected", "ts_name", "http_host_target")
    missing = [n for n in needed if n not in L]
    if missing:
        return cannot_run(f"not a TRUST_STORE=1 build with the policy (missing {missing})",
                          certifies=CERTIFIES)
    prg = PRG_PATH.read_bytes()
    path = image_store_path(prg, L)
    if path != TEST_DIR + "/TRUST.":
        return cannot_run(f"the image stores at {path!r}; this rig only runs against "
                          f"TRUST_STORE_DIR={TEST_DIR}", certifies=CERTIFIES)
    load = prg[0] | prg[1] << 8
    off = L["http_host_target"] - load + 2
    build_host = prg[off:prg.index(b"\0", off)].decode("ascii")
    port = int(os.environ.get("HTTPS_PORT", "4433"))
    sha = hashlib.sha256(prg).hexdigest()
    print(f"PRG sha256 {sha}\nmode {MODE}; build host {build_host}; device {HOST}; "
          f"{TURBO_MHZ} MHz; {'cold bank' if 'cold_call' in L else 'resident policy'}")
    if MODE not in ("local", "live"):
        return cannot_run(f"RIG_MODE={MODE!r}: local or live", certifies=CERTIFIES)

    lock = DeviceLock(HOST)
    try:
        acquire_device_lock(lock)
    except LockTimeoutConfigError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 3
    out = REPO / "build" / "rig_trust_policy" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    client = run = None
    uci_on = False
    fetch_in_flight = False
    box = [False]
    listener_box = [None]
    try:
        client = Ultimate64Client(host=HOST, timeout=20.0)
        info = client.get_info()
        print(f"device /v1/info: {json.dumps(info)}")
        ftp = Ftp()
        listing = ftp.listdir()
        if listing is None:
            ftp.mkdir()
        elif set(listing) - set(OURS):
            return cannot_run(f"{TEST_DIR} holds files that are not the rig's: {listing}",
                              certifies=CERTIFIES)
        for n in OURS:
            ftp.delete(n)
        enable_uci(client)
        uci_on = True
        gc_temp(HOST)
        try:
            prepare_device(client, LABELS_PATH, turbo_mhz=TURBO_MHZ, artifact_dir=out)
            preflight_reu(client, LABELS_PATH)
        except (DevicePrepError, ReuPreflightError) as exc:
            print(str(exc), file=sys.stderr)
            return 4
        client.reset()
        time.sleep(2.5)
        try:
            load_verified_and_run(client, prg)
        except PrgLoadError as exc:
            print(f"[fatal] {exc}", file=sys.stderr)
            return 4
        run = Run(client, L)
        run.notes.update(prg_sha256=sha, firmware=info, mode=MODE)
        if run.wait("Q=QUIT", INIT_WAIT + 30) is None:
            run.failed.append("the menu never appeared")
            return 1
        client.send_text("I", finish_with_return=False)
        if run.wait("DHCP OK", 90 * SCALE) is None:
            run.failed.append("no DHCP")
            return 1
        try:
            if MODE == "local":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((HOST, 80))
                ip = s.getsockname()[0]
                s.close()
                fetch_in_flight = True      # #234: from here a socket may be live
                phases_local(run, ftp, ip, port, out, listener_box, box)
            else:
                fetch_in_flight = True      # #234: from here a socket may be live
                phase_live(run, ftp, build_host, box)
            if run.settled(5):
                fetch_in_flight = False
        except Exception as exc:        # noqa: BLE001 - any escape is a failed run
            run.failed.append(f"{type(exc).__name__}: {exc}")
            print(f"\n{type(exc).__name__}: {exc}")
    finally:
        if fetch_in_flight and client is not None:
            guard_socket_teardown(
                client.read_mem, L["net_tcp_state"],
                tls_addrs=(L["tls_state"], L["tls_reached_connected"]),
                nudge=lambda: client.send_text("Q", finish_with_return=False))
        if listener_box[0] is not None:
            listener_box[0].stop()
        if run is not None:
            for name in ("tp_mode", "tp_ovr_armed"):
                run.notes[name] = run.r8(name)
            (out / "result.json").write_text(json.dumps(
                {"passed": run.passed, "failed": run.failed, "notes": run.notes},
                indent=1, default=str))
            print(f"\nartifacts: {out}")
        try:
            ftp = Ftp()
            for n in OURS:
                ftp.delete(n)
            if ftp.listdir() == []:
                ftp.rmdir()
            print(f"cleanup: {TEST_DIR} -> {ftp.listdir()}")
        except Exception as exc:        # noqa: BLE001
            print(f"WARNING: cleanup of {TEST_DIR} failed: {exc}")
        if client is not None:
            try:
                if uci_on:
                    disable_uci(client)
            except Exception as exc:    # noqa: BLE001
                print(f"WARNING: teardown: {exc}")
        try:
            gc_temp(HOST)
        except Exception as exc:        # noqa: BLE001
            print(f"WARNING: gc_temp: {exc}")
        lock.release()
    if run is None:
        return 2
    print(f"\n{run.passed} passed, {len(run.failed)} failed")
    return verdict(run.passed, len(run.failed), certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
