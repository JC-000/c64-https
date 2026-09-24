#!/usr/bin/env python3
"""net_poll must not read a SOCKET_READ reply before it is valid (#230 b).

WHAT THIS TESTS

``$DF1C`` bit 0 (``UCI_STAT_CMD_BUSY``) is ``handshake_in(0)``, the
new-command flag.  The firmware's command task clears it *before* it
stages the reply (``command_intf.cc`` ``run_task``)::

    command_targets[target]->parse_command(&incoming_command, &data, &status);
    CMD_IF_HANDSHAKE_OUT = HANDSHAKE_ACCEPT_COMMAND; // clears CMD_NEW_COMMAND
    ...
    copy_result(data, status); // sets state to 10 or 11

and ``copy_result`` writes VALIDATE only after both memcpys.  Between the
two, STATE reads ``"01"`` and DATA_AV / STAT_AV read low.  A wait that
returns on CMD_BUSY=0 can therefore look for the reply inside that window
and see none.  In ``net_poll`` that is the "no data" exit, whose DATA_ACC
does nothing (``command_protocol.vhd`` gates it on ``state(1)``).  The
reply then goes valid, the next poll's PUSH_CMD meets a non-idle
interface — ``error_busy``, ``$86 UCI_ERR_READ_FAIL`` — and that error
path drains the late reply away.  For a TCP stream those are bytes the
firmware has already handed over: a permanent hole.  If VALIDATE lands
a little earlier — after the header test but before the no-data exit's
own single-shot ``uci_drain_resp`` — that drain reads the reply to
nowhere and the ACK succeeds: the same hole with ``net_last_error`` $00.

The fix waits for STATE bit 5 (VALIDATE has run) or the ERROR bit.

HOW IT TESTS IT

The shipped machine code (``build/c64-https.prg`` at ``build/labels.txt``
addresses) runs on ``test_uci_data_acc.py``'s 6502 interpreter against
``test_uci_timeout_recovery.py``'s register-file model, extended here with
one thing that model folds into a single step: ACCEPT and VALIDATE happen
``WINDOW`` status reads apart.  ``WINDOW = 0`` is the old atomic model and
is run as a control.

WHAT IT DOES NOT PROVE

How long the window is on a real device, or how often a real poll lands in
it.  The window is counted in ``$DF1C`` reads here, not in microseconds, so
this pins the *ordering* the code waits on, not a timing margin.  The
hardware A/B in the PR is the measurement.

Runs standalone or under pytest (same exit-code contract as its siblings:
0 pass, 1 fail, 2 cannot run; ``C64_UCI_TESTS_OPTIONAL=1`` opts out)::

    python3 tools/test_uci_reply_valid_wait.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_uci_data_acc import CPU, CPUError               # noqa: E402
import test_uci_timeout_recovery as base                  # noqa: E402
from test_uci_timeout_recovery import (                   # noqa: E402
    CommandInterface, Memory, Unavailable, VoluntarySkip,
    ST_BUSY, ST_DATA_LAST, FW_LATENCY, NET_TCP_CONNECTED,
    UCI_ERR_READ_FAIL, UCI_ERR_WAIT_TIMEOUT,
)

OPT_OUT_ENV = "C64_UCI_TESTS_OPTIONAL"

# $DF1C reads between ACCEPT (CMD_BUSY clears) and VALIDATE (state "10").
# Anything >= 3 puts the old code's first DATA_AV test inside the window.
WINDOW = 6

OK = b"00,OK"
NET_TCP_ERROR = 0x02   # src/net/net_states.inc


def _read_reply(data):
    """SOCKET_READ's reply: actual_len (LE) + data."""
    return bytes([len(data) & 0xFF, len(data) >> 8]) + bytes(data)


class WindowedInterface(CommandInterface):
    """ACCEPT_COMMAND and copy_result's VALIDATE are `window` reads apart."""

    def __init__(self, replies=(), window=WINDOW):
        super().__init__(replies)
        self.window = window
        self._validate_countdown = None
        self._pending = None
        self.status_reads_since_push = 0

    def read(self, addr):
        if addr == 0xDF1C:
            self.status_reads_since_push += 1
        return super().read(addr)

    def write(self, addr, value):
        if addr == 0xDF1C and value & 0x01:        # PUSH_CMD
            self.status_reads_since_push = 0
        super().write(addr, value)

    def _tick(self):
        if self._validate_countdown is not None:
            self._validate_countdown -= 1
            if self._validate_countdown <= 0:
                self._validate_countdown = None
                response, status = self._pending
                self.response, self.status = bytes(response), bytes(status)
                self.resp_ptr = self.stat_ptr = 0
                self.state = ST_DATA_LAST          # VALIDATE_LAST
            return
        if self._fw_countdown is not None and self.window > 0:
            self._fw_countdown -= 1
            if self._fw_countdown <= 0:
                self._fw_countdown = None
                self._pending = (self.replies.pop(0) if self.replies
                                 else (b"", b""))
                self.new_command = False           # ACCEPT_COMMAND only
                # state stays "01" until copy_result finishes
                self._validate_countdown = self.window
            return
        super()._tick()


def _machine(replies, window, state=None, error_busy=False):
    labels = base._labels()
    for needed in base.NEEDED_LABELS:
        if needed not in labels:
            raise Unavailable(
                "%s is not in build/labels.txt — this is not a BACKEND=uci "
                "build; rebuild with `make BACKEND=uci "
                "USE_NISTCURVES_ONCHIP=1`" % needed)
    if not base.PRG.is_file():
        raise Unavailable("build/c64-https.prg is missing")
    raw = base.PRG.read_bytes()
    uci = WindowedInterface(replies, window)
    if state is not None:
        uci.state = state
    uci.error_busy = error_busy
    mem = Memory(raw[2:], raw[0] | (raw[1] << 8), uci,
                 tod_reads_per_tenth=10_000)   # no wait may expire here
    for name in ("uci_status_len", "uci_status_force", "net_last_error"):
        mem.write(labels[name], 0)
    for off in range(2):
        mem.write(labels["tcp_recv_head"] + off, 0)
        mem.write(labels["tcp_recv_tail"] + off, 0)
    mem.write(labels["uci_socket_id"], 0x01)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    return CPU(mem), mem, uci, labels


def _require(*args):
    try:
        return _machine(*args)
    except Unavailable as exc:
        if os.environ.get(OPT_OUT_ENV) != "1":
            raise
        reason = ("EXPLICIT SKIP (%s=1): %s — this exit-0 certifies NOTHING "
                  "about the #230(b) reply wait." % (OPT_OUT_ENV, exc))
        pytest = sys.modules.get("pytest")
        if pytest is None:
            raise VoluntarySkip(reason)
        pytest.skip(reason)


def _ring(mem, labels, n):
    base_addr = labels["tcp_recv_buf"]
    return bytes(mem.read(base_addr + i) for i in range(n))


def _tail(mem, labels):
    a = labels["tcp_recv_tail"]
    return mem.read(a) | (mem.read(a + 1) << 8)


def _poll_twice(window):
    first, second = b"STREAM-A", b"STREAM-B"
    cpu, mem, uci, labels = _require(
        [(_read_reply(first), OK), (_read_reply(second), OK)], window)
    cpu.call(labels["net_poll"])
    cpu.call(labels["net_poll"])
    return mem, uci, labels, first + second


def _assert_both_polls_delivered(window):
    mem, uci, labels, expect = _poll_twice(window)
    err = mem.read(labels["net_last_error"])
    base._check(uci.pushes_rejected == 0, (
        "a SOCKET_READ push was rejected (error_busy, the $86 setter) in "
        "state %s: the previous poll left a reply behind that it never "
        "accepted (window=%d reads)" % (uci.rejections, window)))
    base._check(err == 0, "net_last_error = $%02X (window=%d)" % (err, window))
    base._check(mem.read(labels["net_tcp_state"]) == NET_TCP_CONNECTED,
                "net_tcp_state left CONNECTED (window=%d)" % window)
    tail = _tail(mem, labels)
    got = _ring(mem, labels, tail)
    base._check(got == expect, (
        "ring holds %r after two polls, expected %r — the reply that "
        "arrived inside the ACCEPT->VALIDATE window was lost (window=%d)"
        % (got, expect, window)))


def test_atomic_reply_control():
    """Control: ACCEPT and VALIDATE together (the old model). Must pass on
    both the old and the new code, or the harness is what is broken."""
    _assert_both_polls_delivered(window=0)


def test_reply_inside_accept_validate_window():
    """The #230(b) regression: CMD_BUSY clears WINDOW reads before VALIDATE."""
    _assert_both_polls_delivered(window=WINDOW)


def test_every_window_length_delivers():
    """Sweep the window. On the unfixed code it fails two different ways,
    depending on where VALIDATE lands among net_poll's single-shot reads:
    late, and the next push is rejected ($86); in between, and the no-data
    exit's own uci_drain_resp reads the reply to nowhere and the ACK then
    succeeds — a silent hole with no error byte at all."""
    for window in range(1, 13):
        _assert_both_polls_delivered(window=window)


def test_rejected_push_ends_the_wait():
    """A PUSH into a busy ("01") interface sets only ERROR; the wait must see
    it and report $86, not spin out its budget as $89."""
    cpu, mem, uci, labels = _require([], 0, ST_BUSY)   # stuck, never replies
    mem._per_tenth = 1                                  # let a spin expire
    cpu.call(labels["net_poll"])
    err = mem.read(labels["net_last_error"])
    base._check(uci.pushes_rejected == 1,
                "expected the push to be rejected, got %d rejections"
                % uci.pushes_rejected)
    base._check(err == UCI_ERR_READ_FAIL, (
        "net_last_error = $%02X, expected $%02X READ_FAIL (a $%02X means "
        "the wait ignored the ERROR bit and ran out its budget)"
        % (err, UCI_ERR_READ_FAIL, UCI_ERR_WAIT_TIMEOUT)))
    base._check(mem.read(labels["net_tcp_state"]) == NET_TCP_ERROR,
                "net_tcp_state should be ERROR after a rejected push")


def test_empty_reply_is_a_reply():
    """A VALIDATE with no data bytes (c_message_empty: SOCKET_READ errors,
    SOCKET_CLOSE, failed connects) leaves DATA_AV/STAT_AV low but still sets
    STATE "10". A wait keyed on the availability bits instead of STATE never
    ends on it; here the TOD advances every read, so that shows up as $89."""
    # (b"", b"") has the SHAPE of the firmware's "Null command" reply:
    # VALIDATE_LAST with no data AND no status, so neither availability bit
    # ever rises. A real SOCKET_READ always attaches a status, so as a
    # SOCKET_READ reply this is a stress case, not a reachable one.
    for window, status in ((0, OK), (WINDOW, OK), (WINDOW, b"")):
        cpu, mem, uci, labels = _require(
            [(b"", status), (_read_reply(b"AFTER"), OK)], window)
        mem._per_tenth = 1
        cpu.call(labels["net_poll"])
        err = mem.read(labels["net_last_error"])
        base._check(err != UCI_ERR_WAIT_TIMEOUT, (
            "empty SOCKET_READ reply timed out the wait ($89) — it waited for "
            "data/status availability, not for STATE (window=%d)" % window))
        base._check(uci.accepts == 1 and uci.idle,
                    "empty reply was not accepted back to idle (window=%d)"
                    % window)
        cpu.call(labels["net_poll"])
        base._check(_ring(mem, labels, _tail(mem, labels)) == b"AFTER",
                    "the poll after an empty reply did not deliver (window=%d)"
                    % window)

        cpu, mem, uci, labels = _require([(b"", OK)], window)
        mem._per_tenth = 1
        cpu.call(labels["net_tcp_close"])
        err = mem.read(labels["net_last_error"])
        base._check(err != UCI_ERR_WAIT_TIMEOUT and uci.accepts == 1, (
            "SOCKET_CLOSE's empty reply: net_last_error=$%02X, accepts=%d "
            "(window=%d)" % (err, uci.accepts, window)))


def test_wait_budget_is_fifty_tenths():
    """Pin the bound: a command the firmware accepts but never validates
    must fail as $89 after exactly UCI_WAIT_IDLE_BUDGET_TENTHS (50) TOD
    transitions. The model advances one tenth per $DC08 read, one per loop."""
    cpu, mem, uci, labels = _require([(b"", OK)], 10 ** 9)  # never VALIDATEs
    mem._per_tenth = 1
    cpu.call(labels["net_poll"])
    err = mem.read(labels["net_last_error"])
    base._check(err == UCI_ERR_WAIT_TIMEOUT,
                "net_last_error=$%02X, expected $89" % err)
    base._check(mem.read(labels["net_tcp_state"]) == NET_TCP_ERROR,
                "a timed-out SOCKET_READ must leave net_tcp_state ERROR")
    base._check(uci.status_reads_since_push == base.BUDGET_TENTHS, (
        "the wait gave up after %d status reads / tenths, expected %d"
        % (uci.status_reads_since_push, base.BUDGET_TENTHS)))


def test_stale_error_bit_does_not_end_the_wait():
    """error_busy is sticky. If it is already set when the push goes out
    (left by anything else), the ERROR arm of the wait must not fire before
    the firmware has even accepted the command: the push has to clear it."""
    first, second = b"STREAM-A", b"STREAM-B"
    cpu, mem, uci, labels = _require(
        [(_read_reply(first), OK), (_read_reply(second), OK)], WINDOW,
        None, True)
    cpu.call(labels["net_poll"])
    cpu.call(labels["net_poll"])
    err = mem.read(labels["net_last_error"])
    got = _ring(mem, labels, _tail(mem, labels))
    base._check(err == 0 and uci.pushes_rejected == 0 and got == first + second,
                "stale ERROR bit: net_last_error=$%02X, rejected=%d, ring=%r"
                % (err, uci.pushes_rejected, got))


TESTS = (
    test_atomic_reply_control,
    test_reply_inside_accept_validate_window,
    test_every_window_length_delivers,
    test_rejected_push_ends_the_wait,
    test_empty_reply_is_a_reply,
    test_wait_budget_is_fifty_tenths,
    test_stale_error_bit_does_not_end_the_wait,
)


def main():
    failed = 0
    for test in TESTS:
        try:
            test()
        except VoluntarySkip as exc:
            print("SKIP: %s" % exc)
            return 0
        except Unavailable as exc:
            print("CANNOT RUN: %s" % exc)
            return 2
        except (AssertionError, CPUError) as exc:
            failed += 1
            print("FAIL %s: %s" % (test.__name__, exc))
        else:
            print("ok   %s" % test.__name__)
    print("%d/%d passed, %d assertions" % (len(TESTS) - failed, len(TESTS),
                                           base.ASSERTIONS_RUN))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
