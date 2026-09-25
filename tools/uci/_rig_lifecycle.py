"""tools/uci/_rig_lifecycle.py - two lifecycle rules every UCI rig shares.

1. **The listener's accept clock starts when the C64 does (#246).**
   A local-listener rig used to start its TLS listener - and with it the
   ``ACCEPT_TIMEOUT`` wall clock - *before* taking the DeviceLock. The lock
   queues behind a live holder for as long as it takes, so any queue longer
   than the accept budget failed the run before the C64 ever dialled, and it
   read as a network fault. Measured 2026-09-24: 39 min queued, accept timed
   out first. The rigs now *bind* early (a port problem still costs no device
   time) and call :func:`start_listener` only once the lock is held, right
   before ``run_prg``.

2. **The lock is not released over a live firmware socket without a bounded
   wait and a loud warning (#234).** An exception, a Ctrl-C or a sentinel
   timeout inside a fetch used to fall straight through ``finally`` into
   ``disable_uci`` + ``lock.release()``. The next lane then resets the C64,
   and a reset over a live firmware socket poisons the DHCP lease until a
   wall power cycle (CLAUDE.md, "Device gotchas"). Sending 'Q' does not help:
   the C64 reads the keyboard only in ``main_loop`` and the viewer, never in
   ``http_recv_body``. :func:`guard_socket_teardown` waits, bounded, for
   evidence that ``net_tcp_close`` has run, and says so loudly if none comes.
   It must run BEFORE ``disable_uci``: with the command interface off, the
   C64 cannot issue the SOCKET_CLOSE the wait is waiting for.

Pure logic apart from the injected ``read_mem`` / ``clock`` / ``sleep``, so
``tools/test_rig_lifecycle.py`` executes all of it without hardware.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from boot_check import decode_screen, screen_text  # noqa: E402
from ip65_hw_checks import check_shadow_ram_readable  # noqa: E402

#: src/net/net_states.inc
NET_TCP_CLOSED = 0x00
NET_TCP_CONNECTED = 0x01
NET_TCP_ERROR = 0x02
NET_TCP_CONNECT_FAIL = 0x03

#: Printed by `do_https_get` (src/boot.s `done_msg`) after `net_tcp_close`.
CLOSED_MARKER = "CONNECTION CLOSED"

SCREEN_RAM = 0x0400
SHADOW_BASE = 0xA000

#: Default bound on the teardown wait, seconds. It covers the fast paths
#: (an ERROR socket unwinds through `net_tcp_close` in ~0.1 s; a viewer
#: build closes as soon as the viewer returns) and is deliberately far
#: short of the ~87 min a CONNECTED-but-silent socket can take: past the
#: bound the answer is a warning, not a longer hold on a shared device.
TEARDOWN_WAIT_DEFAULT = 120.0


def teardown_budget() -> float:
    """``C64_TEARDOWN_WAIT`` seconds, else the default. Malformed -> default."""
    raw = os.environ.get("C64_TEARDOWN_WAIT", "")
    try:
        v = float(raw) if raw else TEARDOWN_WAIT_DEFAULT
    except ValueError:
        return TEARDOWN_WAIT_DEFAULT
    return v if v >= 0 and v == v else TEARDOWN_WAIT_DEFAULT


# ---------------------------------------------------------------------------
# 1. listener start (#246)
# ---------------------------------------------------------------------------

def start_listener(target, *, args=(), kwargs=None, result: dict,
                   wait_s: float = 5.0, clock=time.monotonic,
                   sleep=time.sleep):
    """Start the listener thread and wait for it to report ``listening``.

    Call this only once the DeviceLock is held - its ``target`` starts the
    ``ACCEPT_TIMEOUT`` clock. Returns the (daemon) thread, or None if
    ``result["listening"]`` did not appear within ``wait_s``.
    """
    th = threading.Thread(target=target, args=tuple(args),
                          kwargs=dict(kwargs or {}), daemon=True)
    th.start()
    deadline = clock() + wait_s
    while not result.get("listening"):
        if clock() >= deadline:
            return None
        sleep(0.05)
    return th


# ---------------------------------------------------------------------------
# 2. socket teardown before the lock is released (#234)
# ---------------------------------------------------------------------------

@dataclass
class Teardown:
    closed: bool
    reason: str


def probe_socket(read_mem, tcp_state_addr):
    """One look at the C64 -> (closed: True/False/None, description).

    True: `net_tcp_close` has run (the screen marker, or `net_tcp_state`
    CLOSED / CONNECT_FAIL - every CLOSED store after `net_init` is inside
    `net_tcp_close`). False: CONNECTED, or ERROR (the stream is dead but the
    close has not run yet). None: could not tell.

    `net_tcp_state` lives in CRYPTO_COLD_SHADOW on UCI ($B3C0 at the time of
    writing); a host read of $A000+ with BASIC banked in returns the ROM, so
    such a read counts only after `check_shadow_ram_readable` says RAM.
    """
    try:
        text = screen_text(decode_screen(bytes(read_mem(SCREEN_RAM, 1000))))
    except Exception as exc:        # noqa: BLE001 - a REST hiccup is "unknown"
        return None, f"screen unreadable ({type(exc).__name__}: {exc})"
    if CLOSED_MARKER in text:
        return True, f"'{CLOSED_MARKER}' on screen"
    if tcp_state_addr is None:
        return None, "no net_tcp_state label in this build"
    try:
        if tcp_state_addr >= SHADOW_BASE:
            shadow = check_shadow_ram_readable(
                bytes(read_mem(SHADOW_BASE, 16)))
            if not shadow.ok:
                return None, ("net_tcp_state unreadable: $A000 reads the "
                              "BASIC ROM, not RAM")
        v = bytes(read_mem(tcp_state_addr, 1))[0]
    except Exception as exc:        # noqa: BLE001
        return None, f"net_tcp_state unreadable ({type(exc).__name__}: {exc})"
    if v in (NET_TCP_CLOSED, NET_TCP_CONNECT_FAIL):
        name = "CLOSED" if v == NET_TCP_CLOSED else "CONNECT_FAIL"
        return True, f"net_tcp_state={name}"
    if v == NET_TCP_CONNECTED:
        return False, "net_tcp_state=CONNECTED"
    if v == NET_TCP_ERROR:
        return False, "net_tcp_state=ERROR (net_tcp_close not yet run)"
    return None, f"net_tcp_state=${v:02X} (unrecognised)"


def await_socket_teardown(read_mem, tcp_state_addr, *, budget: float,
                          clock=time.monotonic, sleep=time.sleep,
                          interval: float = 1.0) -> Teardown:
    """Poll :func:`probe_socket` until it says closed or ``budget`` runs out."""
    deadline = clock() + budget
    while True:
        closed, why = probe_socket(read_mem, tcp_state_addr)
        if closed:
            return Teardown(True, why)
        if clock() >= deadline:
            return Teardown(False, why)
        sleep(interval)


def teardown_warning(reason: str, waited: float) -> str:
    bar = "!!! " + "=" * 68
    return "\n".join([
        bar,
        "!!! Releasing the DeviceLock while the C64 may still hold a LIVE",
        f"!!! firmware TCP socket ({reason}; waited {waited:.0f}s).",
        "!!! A reset by the next lane over that socket poisons the DHCP",
        "!!! lease: GET_IPADDR returns 0.0.0.0 on every interface until the",
        "!!! device is POWER-CYCLED AT THE WALL. Before the next run, either",
        "!!! power-cycle it or let the fetch finish (up to ~87 min against a",
        "!!! silent CONNECTED socket). Do not reset it.",
        bar,
    ])


def guard_socket_teardown(read_mem, tcp_state_addr, *, budget=None,
                          nudge=None, clock=time.monotonic, sleep=time.sleep,
                          out=None) -> Teardown:
    """Rig ``finally`` hook: bounded wait for the close, else a loud warning.

    ``nudge`` (optional, zero-argument) runs once before the wait - a rig
    whose C64 sits in the viewer passes one that types 'Q', since the viewer
    is the one place that key closes the socket. Its failure is ignored.

    Never raises - a teardown helper that raised would skip the
    ``lock.release()`` behind it. A Ctrl-C during the wait ends the wait
    (and warns); it does not skip the release.
    """
    out = out if out is not None else sys.stderr
    budget = teardown_budget() if budget is None else budget
    started = clock()
    print(f"Fetch did not finish: waiting up to {budget:.0f}s for the C64 to "
          "close its socket before the DeviceLock is released "
          "(C64_TEARDOWN_WAIT)...", file=out)
    try:
        if nudge is not None:
            try:
                nudge()
            except Exception as exc:    # noqa: BLE001
                print(f"  (nudge failed: {type(exc).__name__}: {exc})",
                      file=out)
        td = await_socket_teardown(read_mem, tcp_state_addr, budget=budget,
                                   clock=clock, sleep=sleep)
    except KeyboardInterrupt:
        td = Teardown(False, "wait interrupted (Ctrl-C)")
    except Exception as exc:        # noqa: BLE001
        td = Teardown(False, f"wait failed ({type(exc).__name__}: {exc})")
    if td.closed:
        print(f"  socket closed: {td.reason}", file=out)
    else:
        print(teardown_warning(td.reason, clock() - started), file=out)
    return td


__all__ = [
    "NET_TCP_CLOSED", "NET_TCP_CONNECTED", "NET_TCP_ERROR",
    "NET_TCP_CONNECT_FAIL", "CLOSED_MARKER", "TEARDOWN_WAIT_DEFAULT",
    "Teardown", "await_socket_teardown", "guard_socket_teardown",
    "probe_socket", "start_listener", "teardown_budget", "teardown_warning",
]
