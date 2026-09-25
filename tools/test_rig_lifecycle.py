#!/usr/bin/env python3
"""Pin the UCI rigs' lifecycle rules: listener after the lock (#246), and no
lock release over a live firmware socket without a bounded wait (#234).

No VICE, no hardware, no build. Three layers:

1. ``tools/uci/_rig_lifecycle.py`` executed against a faked C64 memory:
   every branch of the teardown probe, including the one that matters most —
   a ``net_tcp_state`` read at $B3C0 while BASIC is banked IN returns a ROM
   byte, and a ROM byte of $00 would read as CLOSED. It must not.

2. ``rig_https_local.main()`` and ``rig_https_bad_finished.main()`` RUN with
   every device call faked, under the two conditions the issues describe:

   * #246: ``acquire_device_lock`` takes longer than ``ACCEPT_TIMEOUT``. The
     fake ``run_prg`` then dials the listener, which must still accept. On
     the pre-fix rigs the accept clock started before the lock, expired
     during the fake queue, and the dial is refused.
   * #234: the SYS that starts the fetch raises ``KeyboardInterrupt``. The
     rig must read ``net_tcp_state`` before ``disable_uci`` and
     ``lock.release()``, and warn loudly when it stays CONNECTED. On the
     pre-fix rigs ``finally`` released straight away.

3. AST guards over every ``tools/uci`` rig, so a new rig written to the old
   shape fails here rather than on a device.

Runs under pytest, and standalone::

    python3 tools/test_rig_lifecycle.py
"""

from __future__ import annotations

import ast
import contextlib
import importlib
import io
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
UCI = REPO / "tools" / "uci"
for p in (str(UCI), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import _rig_lifecycle as lc  # noqa: E402

_real_sleep = time.sleep

#: The first bytes of the BASIC ROM at $A000 (cold/warm start vectors), as
#: tools/ip65_hw_checks.py recognises them.
from ip65_hw_checks import BASIC_ROM_A000_PREFIX  # noqa: E402

TCP = 0xB3C0      # where net_tcp_state sits on UCI builds (shadow RAM)


class Clock:
    """Deterministic clock: sleep() advances it, nothing really waits."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def mem_reader(mem: bytearray, log=None, raise_at=None):
    def read(addr, n):
        if log is not None:
            log.append(("read", addr, n))
        if raise_at is not None and addr == raise_at:
            raise raise_at_exc()
        return bytes(mem[addr:addr + n])
    return read


def raise_at_exc():
    return OSError("REST read failed")


def fresh_mem(tcp_state=lc.NET_TCP_CONNECTED, rom_in=False):
    mem = bytearray(0x10000)
    mem[TCP] = tcp_state
    if rom_in:
        mem[0xA000:0xA000 + len(BASIC_ROM_A000_PREFIX)] = BASIC_ROM_A000_PREFIX
    return mem


def screen_codes(text: str) -> bytes:
    out = bytearray()
    for ch in text.upper():
        o = ord(ch)
        out.append(o - 64 if 65 <= o <= 90 else o)
    return bytes(out)


# ===========================================================================
# 1. the helper
# ===========================================================================

def test_probe_closed_states_count_as_closed() -> None:
    for v, name in ((lc.NET_TCP_CLOSED, "CLOSED"),
                    (lc.NET_TCP_CONNECT_FAIL, "CONNECT_FAIL")):
        closed, why = lc.probe_socket(mem_reader(fresh_mem(v)), TCP)
        assert closed is True and name in why, (v, closed, why)


def test_probe_connected_and_error_are_not_closed() -> None:
    for v in (lc.NET_TCP_CONNECTED, lc.NET_TCP_ERROR):
        closed, why = lc.probe_socket(mem_reader(fresh_mem(v)), TCP)
        assert closed is False, (v, closed, why)


def test_probe_rom_byte_is_never_read_as_closed() -> None:
    """BASIC banked in: $B3C0 returns ROM. A $00 there is not CLOSED."""
    mem = fresh_mem(lc.NET_TCP_CLOSED, rom_in=True)
    closed, why = lc.probe_socket(mem_reader(mem), TCP)
    assert closed is None, (closed, why)
    assert "ROM" in why


def test_probe_below_shadow_needs_no_rom_gate() -> None:
    mem = fresh_mem(rom_in=True)
    mem[0x610C] = lc.NET_TCP_CLOSED
    closed, _ = lc.probe_socket(mem_reader(mem), 0x610C)
    assert closed is True


def test_probe_screen_marker_counts_as_closed() -> None:
    mem = fresh_mem(lc.NET_TCP_CONNECTED)
    marker = screen_codes(lc.CLOSED_MARKER)
    mem[0x0400 + 80:0x0400 + 80 + len(marker)] = marker
    closed, why = lc.probe_socket(mem_reader(mem), TCP)
    assert closed is True and lc.CLOSED_MARKER in why, why


def test_probe_unreadable_is_unknown_not_closed() -> None:
    closed, _ = lc.probe_socket(mem_reader(fresh_mem(), raise_at=TCP), TCP)
    assert closed is None
    closed, _ = lc.probe_socket(mem_reader(fresh_mem(lc.NET_TCP_CLOSED)),
                                None)
    assert closed is None, "no label must not read as closed"


def test_await_returns_when_the_close_lands() -> None:
    mem = fresh_mem(lc.NET_TCP_CONNECTED)
    clk = Clock()

    def sleep(s):
        clk.sleep(s)
        if clk.t >= 3:
            mem[TCP] = lc.NET_TCP_CLOSED

    td = lc.await_socket_teardown(mem_reader(mem), TCP, budget=60,
                                  clock=clk, sleep=sleep)
    assert td.closed and 3 <= clk.t < 10, (td, clk.t)


def test_await_is_bounded() -> None:
    clk = Clock()
    td = lc.await_socket_teardown(mem_reader(fresh_mem()), TCP, budget=30,
                                  clock=clk, sleep=clk.sleep)
    assert not td.closed and 30 <= clk.t <= 31.5, (td, clk.t)


def test_guard_warns_loudly_and_never_raises() -> None:
    clk = Clock()
    out = io.StringIO()
    td = lc.guard_socket_teardown(mem_reader(fresh_mem()), TCP, budget=5,
                                  clock=clk, sleep=clk.sleep, out=out)
    assert not td.closed
    assert "POWER-CYCLED AT THE WALL" in out.getvalue()

    def interrupted(addr, n):
        raise KeyboardInterrupt
    out = io.StringIO()
    td = lc.guard_socket_teardown(interrupted, TCP, budget=5, clock=clk,
                                  sleep=clk.sleep, out=out)
    assert not td.closed and "interrupted" in td.reason
    assert "POWER-CYCLED AT THE WALL" in out.getvalue()


def test_guard_nudges_once_before_waiting() -> None:
    clk = Clock()
    mem = fresh_mem()
    calls = []

    def nudge():
        calls.append(clk.t)
        mem[TCP] = lc.NET_TCP_CLOSED     # the viewer saw 'Q' and closed
    td = lc.guard_socket_teardown(mem_reader(mem), TCP, budget=5, nudge=nudge,
                                  clock=clk, sleep=clk.sleep,
                                  out=io.StringIO())
    assert td.closed and calls == [0.0], (td, calls)


def test_teardown_budget_env() -> None:
    old = os.environ.get("C64_TEARDOWN_WAIT")
    try:
        os.environ["C64_TEARDOWN_WAIT"] = "7"
        assert lc.teardown_budget() == 7.0
        for bad in ("x", "-1", "nan"):
            os.environ["C64_TEARDOWN_WAIT"] = bad
            assert lc.teardown_budget() == lc.TEARDOWN_WAIT_DEFAULT, bad
    finally:
        if old is None:
            os.environ.pop("C64_TEARDOWN_WAIT", None)
        else:
            os.environ["C64_TEARDOWN_WAIT"] = old


def test_start_listener_reports_a_listener_that_never_comes_up() -> None:
    res: dict = {}
    th = lc.start_listener(lambda: None, result=res, wait_s=0.2)
    assert th is None
    res = {}
    th = lc.start_listener(lambda r: r.update(listening=True), args=(res,),
                           result=res, wait_s=2.0)
    assert th is not None


# ===========================================================================
# 2. the rigs, run with the device faked
# ===========================================================================

class _Stop(Exception):
    """Raised by a fake to end main() at the point under test."""


class FakeLock:
    def __init__(self, host, events):
        self.events = events

    def read_info(self):
        return {}

    def release(self):
        self.events.append(("release",))


class FakePolicy:
    reserved_regions = ()


class FakeArbiter:
    def __init__(self):
        self.next = 0x0334
        self.allocations = []

    def alloc(self, size, alignment=1, name=""):
        a = self.next
        self.next += size
        self.allocations.append((a, a + size - 1, name))
        return a


class _TimeShim:
    """The rig's `time`, with its long fixed sleeps (reset, boot, BASIC
    return) skipped. Short sleeps stay real so polling loops still poll."""

    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def sleep(s):
        if s < 0.5:
            _real_sleep(s)


def _patch_rig(mod, *, events, mem, run_prg, send_text, tmp):
    """Replace every device-touching name in a rig module. -> restore()."""
    saved = {}

    def setattr_(name, value):
        if name not in saved:
            saved[name] = getattr(mod, name, None)
        setattr(mod, name, value)

    class Client:
        def __init__(self, *a, **k):
            pass

        def reset(self):
            events.append(("reset",))

        def run_prg(self, prg):
            events.append(("run_prg",))
            run_prg()

    class Transport:
        memory_policy = None

        def __init__(self, *a, **k):
            pass

        def read_memory(self, addr, n):
            events.append(("read", addr, n))
            return bytes(mem[addr:addr + n])

        def write_memory(self, addr, data, override=None):
            mem[addr:addr + len(data)] = data

    labels = {n: 0x7000 + i for i, n in enumerate([
        "http_get", "http_host_ptr", "http_host_len", "http_path_ptr",
        "http_path_len", "http_port", "net_init", "net_initialized",
        "uci_socket_id", "tcp_recv_head", "tcp_recv_tail", "http_resp_buf",
        "http_resp_len", "http_status", "tls_state", "tls_last_state",
        "net_last_error"])}
    labels["net_tcp_state"] = TCP

    prg = tmp / "c64-https.prg"
    prg.write_bytes(b"\x01\x08" + bytes(16))
    lab = tmp / "labels.txt"
    lab.write_text("")

    for name in dir(mod):
        if name.startswith("build_policy_and_arbiter"):
            setattr_(name, lambda *a, **k: (FakePolicy(), FakeArbiter()))
    setattr_("PRG_PATH", prg)
    setattr_("LABELS_PATH", lab)
    setattr_("DeviceLock", lambda host: FakeLock(host, events))
    setattr_("Ultimate64Client", Client)
    setattr_("Ultimate64Transport", Transport)
    setattr_("enable_uci", lambda c: events.append(("enable_uci",)))
    setattr_("disable_uci", lambda c: events.append(("disable_uci",)))
    setattr_("runner_health_check", lambda c: None)
    setattr_("prepare_device", lambda *a, **k: None)
    setattr_("preflight_reu", lambda *a, **k: None)
    setattr_("send_text", send_text)
    setattr_("enforce_sni_precondition", lambda *a, **k: None)
    setattr_("_detect_local_ip", lambda h: "127.0.0.1")
    setattr_("time", _TimeShim())
    if hasattr(mod, "_ensure_certs_or_fail"):
        setattr_("_ensure_certs_or_fail", lambda: 0)
        setattr_("_load_labels", lambda: dict(labels))
        setattr_("DEBUG_CAPTURE_ENABLED", False)
        setattr_("UCI_DEBUG_BASE_DIR", tmp / "debug")
        setattr_("_make_ssl_context",
                 lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    if hasattr(mod, "_ensure_certs_p256"):
        setattr_("_ensure_certs_p256", lambda: ("cert.pem", "key.pem"))
        setattr_("Labels",
                 SimpleNamespace(from_file=lambda p: dict(labels)))
        setattr_("ARTIFACT_BASE", tmp / "art")

    def restore():
        for k, v in saved.items():
            setattr(mod, k, v)
    return restore


def _bind_ephemeral(mod, box, restore_list):
    orig = mod._try_bind

    def bind(ip, port):
        box.setdefault("events", []).append("bind")
        srv = orig("127.0.0.1", 0)
        box["port"] = srv.getsockname()[1]
        return srv
    mod._try_bind = bind
    restore_list.append(lambda: setattr(mod, "_try_bind", orig))


def _capture_server_result(mod, attr, box, restore_list):
    """Wrap the listener target so the test can see its result dict."""
    orig = getattr(mod, attr)

    def wrapped(*a, **k):
        box["result"] = k.get("result") if "result" in k else a[-1]
        return orig(*a, **k)
    setattr(mod, attr, wrapped)
    restore_list.append(lambda: setattr(mod, attr, orig))


def _run_slow_queue(modname, server_attr):
    """#246: acquire outlasts ACCEPT_TIMEOUT; does the listener still accept?"""
    mod = importlib.import_module(modname)
    events: list = []
    box: dict = {}
    restores: list = []
    verdict: dict = {}

    def run_prg():
        # The C64 dials the listener right after the load.
        try:
            s = socket.create_connection(("127.0.0.1", box["port"]),
                                         timeout=1.0)
        except OSError as exc:
            verdict["dial"] = f"refused ({exc})"
            raise _Stop
        verdict["dial"] = "connected"
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if (box.get("result") or {}).get("client_addr"):
                verdict["accepted"] = True
                break
            _real_sleep(0.02)
        s.close()
        raise _Stop

    with tempfile.TemporaryDirectory() as td:
        restores.append(_patch_rig(mod, events=events, mem=fresh_mem(),
                                   run_prg=run_prg,
                                   send_text=lambda t, s: None,
                                   tmp=Path(td)))
        _bind_ephemeral(mod, box, restores)
        _capture_server_result(mod, server_attr, box, restores)
        saved_acc = mod.ACCEPT_TIMEOUT
        saved_acq = mod.acquire_device_lock
        mod.ACCEPT_TIMEOUT = 0.3

        def slow_acquire(lock, **k):
            events.append(("acquire",))
            verdict["bound_before_lock"] = bool(box.get("events"))
            _real_sleep(1.0)          # queued behind another lane
        mod.acquire_device_lock = slow_acquire
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    rc = mod.main()
                    verdict["rc"] = rc
                except _Stop:
                    pass
        finally:
            mod.ACCEPT_TIMEOUT = saved_acc
            mod.acquire_device_lock = saved_acq
            for r in reversed(restores):
                r()
    return verdict, events


def test_local_rig_listener_survives_a_slow_lock_queue() -> None:
    verdict, events = _run_slow_queue("rig_https_local", "_run_https_server")
    assert verdict.get("bound_before_lock") is False, (
        "the port is bound while queued: it would refuse every other lane's "
        "local rig on this host for the length of the queue")
    assert verdict.get("dial") == "connected", (
        f"#246: the listener was gone by the time the C64 dialled: {verdict}")
    assert verdict.get("accepted"), verdict
    assert ("release",) in events


def test_bad_finished_rig_listener_survives_a_slow_lock_queue() -> None:
    verdict, events = _run_slow_queue("rig_https_bad_finished",
                                      "serve_one_connection")
    assert verdict.get("bound_before_lock") is False, (
        "the port is bound while queued: it would refuse every other lane's "
        "local rig on this host for the length of the queue")
    assert verdict.get("dial") == "connected", (
        f"#246: the listener was gone by the time the C64 dialled: {verdict}")
    assert verdict.get("accepted"), verdict
    assert ("release",) in events


def _run_ctrl_c_mid_fetch(modname):
    """#234: Ctrl-C lands while the fetch is live; what happens before release?"""
    mod = importlib.import_module(modname)
    events: list = []
    box: dict = {}
    restores: list = []
    mem = fresh_mem(lc.NET_TCP_CONNECTED)

    def send_text(transport, text):
        if text.startswith("sys"):
            raise KeyboardInterrupt      # the operator gave up mid-fetch

    err = io.StringIO()
    old_env = os.environ.get("C64_TEARDOWN_WAIT")
    os.environ["C64_TEARDOWN_WAIT"] = "0.5"
    with tempfile.TemporaryDirectory() as td:
        restores.append(_patch_rig(mod, events=events, mem=mem,
                                   run_prg=lambda: None, send_text=send_text,
                                   tmp=Path(td)))
        _bind_ephemeral(mod, box, restores)
        saved_acq = mod.acquire_device_lock
        mod.acquire_device_lock = lambda lock, **k: events.append(("acquire",))
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                try:
                    mod.main()
                except KeyboardInterrupt:
                    pass
        finally:
            mod.acquire_device_lock = saved_acq
            for r in reversed(restores):
                r()
            if old_env is None:
                os.environ.pop("C64_TEARDOWN_WAIT", None)
            else:
                os.environ["C64_TEARDOWN_WAIT"] = old_env
    return events, err.getvalue()


def _assert_teardown_guarded(events, err):
    idx = {e: i for i, e in enumerate(events) if e[0] != "read"}
    assert ("release",) in idx, "the lock was never released"
    tcp_reads = [i for i, e in enumerate(events)
                 if e[0] == "read" and e[1] == TCP]
    assert tcp_reads, ("#234: net_tcp_state was never read before the "
                       "DeviceLock went — the lock was released over a "
                       "possibly live socket")
    assert max(tcp_reads) < idx[("release",)], "read after release"
    if ("disable_uci",) in idx:
        assert max(tcp_reads) < idx[("disable_uci",)], (
            "#234: the socket wait ran after disable_uci, when the C64 can no "
            "longer issue the SOCKET_CLOSE it is waiting for")
    assert "POWER-CYCLED AT THE WALL" in err, (
        "a CONNECTED socket at release must produce the loud warning")


def test_local_rig_waits_for_the_socket_before_releasing() -> None:
    _assert_teardown_guarded(*_run_ctrl_c_mid_fetch("rig_https_local"))


def test_bad_finished_rig_waits_for_the_socket_before_releasing() -> None:
    _assert_teardown_guarded(*_run_ctrl_c_mid_fetch("rig_https_bad_finished"))


def test_bad_finished_reports_and_judges_the_carry() -> None:
    """#247: the latched http_get carry is printed and is a criterion."""
    bf = importlib.import_module("rig_https_bad_finished")
    body = bf.DEFAULT_BODY.encode()
    server = {"client_hello_seen": True, "server_flight_sent": True,
              "finished_corrupted": True, "client_accepted_finished": False,
              "client_finished_valid": True, "response_sent": True,
              "request": b"GET / HTTP/1.1"}
    bad = {"tls_state": 0xFF, "tls_last_state": 6, "http_status": 0,
           "http_resp_buf": b"", "http_get_carry": 1}
    ok, _ = bf._evaluate("bad", server, bad, "")
    assert ok
    ok, why = bf._evaluate("bad", server, dict(bad, http_get_carry=0), "")
    assert not ok and any("carry" in r and r.startswith("FAIL") for r in why)
    good_srv = dict(server, finished_corrupted=False,
                    client_accepted_finished=True)
    good = {"tls_state": 0, "tls_last_state": 0, "http_status": 200,
            "http_resp_buf": body, "http_get_carry": 0}
    ok, _ = bf._evaluate("good", good_srv, good, "")
    assert ok
    for c in (1, None):
        ok, _ = bf._evaluate("good", good_srv, dict(good, http_get_carry=c),
                             "")
        assert not ok, c
    src = (UCI / "rig_https_bad_finished.py").read_text()
    assert "http_get carry  = " in src, "the carry is never printed"


# ===========================================================================
# 3. AST guards over every rig
# ===========================================================================

def _rig_files():
    return sorted(p for p in UCI.glob("*.py") if not p.name.startswith("_"))


def _calls(tree, name):
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            fn = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
            if fn == name:
                out.append(n.lineno)
    return sorted(out)


def _drives_a_fetch(src: str) -> bool:
    """A rig that presses 'G', or SYSes a trampoline that opens a socket
    (it names `http_get` or `net_tcp_connect`), can hold a live socket."""
    menu = 'send_text("G"' in src or 'send_text(transport, "g")' in src
    sys_ = 'f"sys{' in src or "'sys{" in src or "sys_line" in src
    net = any(f'"{n}"' in src for n in ("http_get", "http_get_plain",
                                             "net_tcp_connect"))
    return menu or (sys_ and net)


def test_discovery_finds_the_known_fetch_rigs() -> None:
    found = {p.name for p in _rig_files() if _drives_a_fetch(p.read_text())}
    expected = {"rig_https_local.py", "rig_https_live.py",
                "rig_https_bad_finished.py", "rig_https_banner.py",
                "rig_https_wiki.py", "rig_http_local.py", "rig_http_live.py",
                "phase3_tcp_echo.py"}
    missing = expected - found
    assert not missing, f"the fetch-rig rule no longer selects {missing}"


def test_every_listener_starts_after_the_lock() -> None:
    """#246, structurally: in main(), no listener bind or thread before
    acquire_device_lock."""
    bad = []
    for p in _rig_files():
        tree = ast.parse(p.read_text())
        mains = [n for n in tree.body
                 if isinstance(n, ast.FunctionDef) and n.name == "main"]
        if not mains:
            continue
        tree = mains[0]
        acq = _calls(tree, "acquire_device_lock")
        if not acq:
            continue
        for fn in ("start_listener", "Thread", "_try_bind",
                   "_bind_https_listener", "bind"):
            for line in _calls(tree, fn):
                if line < acq[0]:
                    bad.append(f"{p.name}:{line} {fn} before the lock "
                               f"(line {acq[0]})")
    assert not bad, "\n".join(bad)


def test_every_fetch_rig_guards_the_socket_before_release() -> None:
    """#234, structurally: guard_socket_teardown in the release `finally`,
    ahead of disable_uci and lock.release()."""
    bad = []
    for p in _rig_files():
        src = p.read_text()
        if not _drives_a_fetch(src):
            continue
        tree = ast.parse(src)
        ok = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try) or not node.finalbody:
                continue
            fin = ast.Module(body=node.finalbody, type_ignores=[])
            rel = _calls(fin, "release")
            if not rel:
                continue
            guard = _calls(fin, "guard_socket_teardown")
            dis = _calls(fin, "disable_uci")
            if guard and guard[0] < rel[0] and (not dis or guard[0] < dis[0]):
                ok = True
        if not ok:
            bad.append(p.name)
    assert not bad, (f"#234: these fetch rigs release the DeviceLock without "
                     f"guard_socket_teardown ahead of disable_uci/release: "
                     f"{bad}")


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}: {exc}")
        except Exception as exc:                              # noqa: BLE001
            failed += 1
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    from _skip_policy import verdict
    return verdict(len(tests) - failed, failed,
                   certifies="the UCI rig lifecycle (#246, #234)")


if __name__ == "__main__":
    sys.exit(main())
