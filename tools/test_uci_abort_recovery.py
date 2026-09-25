#!/usr/bin/env python3
"""ABORT must be waited for (#230 a), and every connect/close timeout
exit must abort (#221).

WHAT THIS TESTS

(a) Writing ABORT ($04) to ``$DF1C`` only sets ``handshake_in(2)``, which
reads back as bit 2.  The reset is done later, by the firmware's command
task (``command_intf.cc`` ``run_task``)::

    if(status_byte & CMD_ABORT_DATA) {
        ...
        CMD_IF_HANDSHAKE_OUT = HANDSHAKE_RESET;    // 0x87

and in ``command_protocol.vhd`` that one write clears bit 2, forces state
``"00"`` and rewinds ``command_pointer``.  So a command whose bytes (or
PUSH) go out before the reset lands is lost: the pointer is rewound under
it, and the firmware parses an empty ("Null command") or truncated
("21,UNKNOWN COMMAND") buffer.  A TCP_CONNECT lost that way reads back no
socket id: ``$88 UCI_ERR_NO_SOCKET``.  The pending abort shows in neither
STATE nor CMD_BUSY, so ``uci_wait_idle``'s ``$31`` mask can pass while it
is still pending.  ``uci_abort`` used a fixed 32-iteration spin; it now
falls into ``uci_wait_idle``, whose mask is now ``$35`` (bit 2 included),
on the CIA1 TOD bound, so every entry wait also waits out a pending abort.

(b) ``net_tcp_connect`` and ``net_tcp_close`` had timeout exits that
returned without accepting or aborting the transaction.  The interface
stayed where the firmware had put it, and every later connect spent 5 s in
``uci_wait_idle`` and failed, until a reboot.  Each exit now ends in
``uci_txn_bail`` (ABORT, then one wait for reset + idle), which is #194's
``@sb_bail`` shared.
Each test below stalls one exit and then asks for a fresh connect.

HOW IT TESTS IT

The shipped machine code (``build/c64-https.prg`` at ``build/labels.txt``
addresses) runs on ``test_uci_data_acc.py``'s 6502 interpreter against
``test_uci_timeout_recovery.py``'s register-file model, extended here with:

  * the command buffer: bytes written to ``$DF1D`` accumulate, the reset
    and ACCEPT rewind it, and the modelled firmware parses what is there
    at service time (empty -> Null command, bad target/command ->
    ``21,UNKNOWN COMMAND``, a first byte with bit 7 set -> no reply at
    all (``CMD_IF_NO_REPLY``), else the scripted reply);
  * a pending abort: bit 2 reads set, DATA_AV/STAT_AV read low (the VHDL
    gates both on ``not handshake_in(2)``);
  * a FIFO firmware task, as ``run_task`` is: the IRQ queues each new
    handshake bit and the task actions them in order. An abort written
    while a command is still being serviced waits BEHIND it: the command
    completes (``copy_result``, state "10") and only then does the reset
    land. A command pushed while an abort is queued ahead of it is parsed
    after the reset, against the rewound pointer. Each item is actioned
    N ticks after reaching the head (``abort_latency``, ``cmd_latencies``);
    ``None`` is a task that never returns, which blocks the abort too;
  * an absent interface (open bus), for the NOT_PRESENT path.

Model time advances on ``$DF1C`` reads (as in the sibling models) and, here,
on ``$DF1D`` command writes too, so an abort can land mid-command.

The interpreter skips each inline ``uci_fence`` in one step (its only
effects are a delay and C=1/V=0/NZ-from-A), because the unfixed code's
65,536-iteration DATA_AV spin in ``uci_read_resp_bytes`` is otherwise too
slow to interpret.  The fence reads no register, so no model tick is lost.

WHAT IT DOES NOT PROVE

How long the real abort round trip is, or how often it loses a command on
a device: latency here is counted in register accesses, not microseconds.
The hardware A/B in the PR is the measurement.  The TOD advances one tenth
per ``$DC08`` read in the (b) tests, so "5 s" is ~50 loop iterations: this
proves the code waits and is bounded, not that 5 s is enough.  The (b)
error-branch test reaches ``@tc_err`` by staging a late reply (an earlier
command's, landing after the entry wait passed) on the first command-byte
write, so the TCP_CONNECT push is rejected (``error_busy``): with
``uci_push_wait`` clearing ERROR before its PUSH (#238), a rejected push is
the only way to set it.

Runs standalone or under pytest (exit 0 pass, 1 fail, 2 cannot run;
``C64_UCI_TESTS_OPTIONAL=1`` opts out)::

    python3 tools/test_uci_abort_recovery.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_uci_data_acc import CPU, CPUError               # noqa: E402
import test_uci_timeout_recovery as base                  # noqa: E402
from test_uci_timeout_recovery import (                   # noqa: E402
    CommandInterface, Memory, Unavailable, VoluntarySkip, ENDLESS,
    ST_IDLE, ST_DATA_LAST, UCI_CTRL_ABORT, UCI_STAT_DATA_AV,
    UCI_STAT_STAT_AV, UCI_ERR_WAIT_TIMEOUT,
)

OPT_OUT_ENV = "C64_UCI_TESTS_OPTIONAL"
from _skip_policy import require, verdict  # noqa: E402
CERTIFIES = "#230(a) / #221 / #243 / net_poll EOF"

UCI_STAT_ABORT_PENDING = 0x04

NET_TCP_CLOSED = 0x00
NET_TCP_CONNECTED = 0x01
NET_TCP_CONNECT_FAIL = 0x03

UCI_ERR_NOT_PRESENT = 0x81
UCI_ERR_NO_SOCKET = 0x88

TARGET_NETWORK = 0x03
CMD_TCP_CONNECT = 0x07
KNOWN_COMMANDS = {0x05, 0x07, 0x09, 0x10, 0x11}
CMD_IF_MAX_TARGET = 0x0F            # command_intf.h
CMD_IF_NO_REPLY = 0x80

OK = b"00,OK"
CONNECT_OK = (b"\x01", OK)          # socket id 1
PORT = 443
HOST = b"h"
CONNECT_BYTES = (bytes([TARGET_NETWORK, CMD_TCP_CONNECT, PORT & 0xFF,
                        PORT >> 8]) + HOST + b"\x00")

# The default reset latency for the (b) tests: >1, so a bail that does not
# wait for the reset loses the NEXT command too.
ABORT_LATENCY = 4

LABELS_NEEDED = ("net_init", "net_tcp_connect", "net_tcp_close", "net_poll",
                 "net_tcp_send", "net_send_len", "net_recv_byte",
                 "tcp_recv_buf",
                 "tcp_recv_head", "tcp_recv_tail",
                 "uci_host_buf", "uci_socket_id", "net_last_error",
                 "net_tcp_state", "uci_status_len", "uci_status_force")

# uci_fence (uci_regs.inc), OUTER=5 INNER=217, as assembled.
FENCE = bytes.fromhex("488A48A205A9D9E901D0FCCAD0F768AA68")


class FastCPU(CPU):
    """The sibling interpreter, with each inline uci_fence taken in one step.

    Effects of the fence as written: A, X and SP restored; the last SBC
    leaves C=1 and V=0; the final PLA sets N/Z from A.  It touches no
    register, so the register model sees exactly the same access sequence.
    """

    def step(self):
        pc = self.pc
        ram = self.mem.ram
        if ram[pc] == 0x48 and ram[pc:pc + len(FENCE)] == FENCE:
            self.steps += 1
            self.pc = (pc + len(FENCE)) & 0xFFFF
            self.c, self.v = True, False
            self._nz(self.a)
            return
        super().step()


class AbortModel(CommandInterface):
    """CommandInterface + command buffer + a FIFO firmware task.

    run_task (command_intf.cc) takes the handshake bits the IRQ queued, in
    order, one item at a time. So an ABORT written while the task is still
    busy with a command waits BEHIND that command: the command completes
    (ACCEPT, copy_result -> state "10") and only then does HANDSHAKE_RESET
    land. A command pushed while an abort is queued ahead of it is serviced
    after the reset, against the rewound command pointer.

    Each queue item is [kind, ticks]: it is actioned after `ticks` model
    ticks at the HEAD of the queue; None means never (a task that does not
    return, which also blocks everything behind it).
    """

    def __init__(self, replies=(), abort_latency=ABORT_LATENCY,
                 present=True):
        super().__init__(replies)
        self.abort_latency = abort_latency      # None: never serviced
        self.present = present
        self.cmd_buf = []
        self.abort_pending = False              # handshake_in(2), bit 2
        self.queue = []                         # FIFO of [kind, ticks]
        self.cmd_latencies = []                 # per accepted push; default
        self.late_reply = None                  # staged at first $DF1D write
        self.on_push = None                     # hook(model) at each push
        self.parsed = []                        # (bytes, kind) per service
        self.status_reads_while_abort_pending = 0

    # -- firmware -----------------------------------------------------------
    def _reset(self):
        """HANDSHAKE_RESET (0x87): one write, all of these at once."""
        self.abort_pending = False
        self.state = ST_IDLE
        self.new_command = False
        self.cmd_buf = []                       # command_pointer rewound
        self.response = self.status = b""
        self.resp_ptr = self.stat_ptr = 0
        self.endless = False
        self.aborts_completed += 1
        # A NEW_COMMAND item already queued behind the abort survives: the
        # task services it next, against the rewound pointer.

    def _service(self):
        buf = bytes(self.cmd_buf)
        self.cmd_buf = []                       # ACCEPT_COMMAND rewinds too
        if buf and buf[0] & CMD_IF_NO_REPLY:
            # run_task: target = message[0] & 0x0F; no_reply = bit 7. After
            # parse_command it writes ACCEPT, then HANDSHAKE_RESET instead of
            # copy_result: state "00", nothing staged, no VALIDATE ever.
            self.parsed.append((buf, "noreply"))
            self.new_command = False
            self.abort_pending = False          # 0x87 clears bits 0-2 too
            self.state = ST_IDLE
            self.response = self.status = b""
            self.resp_ptr = self.stat_ptr = 0
            self.endless = False
            return
        if not buf:
            kind, reply = "null", (b"", b"")
        elif (len(buf) < 2 or buf[0] & CMD_IF_MAX_TARGET != TARGET_NETWORK
              or buf[1] not in KNOWN_COMMANDS):
            kind, reply = "unknown", (b"", b"21,UNKNOWN COMMAND")
        else:
            kind = "ok"
            reply = self.replies.pop(0) if self.replies else (b"", OK)
        self.parsed.append((buf, kind))
        response, status = reply
        self.endless = response is ENDLESS
        self.response = b"" if self.endless else bytes(response)
        self.status = bytes(status)
        self.resp_ptr = self.stat_ptr = 0
        self.new_command = False
        self.state = ST_DATA_LAST

    def _run_head(self):
        kind, _ = self.queue.pop(0)
        if kind == "abort":
            self._reset()
        else:
            self._service()

    def _tick(self):
        if not self.queue:
            return
        head = self.queue[0]
        if head[1] is None:
            return                              # task never returns
        head[1] -= 1
        if head[1] <= 0:
            self._run_head()

    def _enqueue(self, kind, ticks):
        self.queue.append([kind, ticks])
        if ticks == 0 and len(self.queue) == 1:
            self._run_head()

    # -- host side ----------------------------------------------------------
    def read(self, addr):
        if not self.present:
            return 0xFF                         # open bus: every bit set
        if addr == 0xDF1C and self.abort_pending:
            self.status_reads_while_abort_pending += 1
        value = super().read(addr)
        if addr == 0xDF1C and self.abort_pending:
            value |= UCI_STAT_ABORT_PENDING
            value &= ~(UCI_STAT_DATA_AV | UCI_STAT_STAT_AV) & 0xFF
        return value

    def write(self, addr, value):
        if not self.present:
            return
        if addr == 0xDF1D:
            self._tick()
            if self.late_reply is not None:
                response, status = self.late_reply
                self.late_reply = None
                self.endless = response is ENDLESS
                self.response = b"" if self.endless else bytes(response)
                self.status = bytes(status)
                self.resp_ptr = self.stat_ptr = 0
                self.state = ST_DATA_LAST
            self.cmd_buf.append(value)
            return
        if addr != 0xDF1C:
            return
        if value & UCI_CTRL_ABORT:
            self.abort_writes += 1
            if not self.abort_pending:          # the IRQ queues a new bit
                self.abort_pending = True       # only once until serviced
                self._enqueue("abort", self.abort_latency)
            value &= ~UCI_CTRL_ABORT
        if not value:
            return
        accepted = self.pushes_accepted
        super().write(addr, value)
        if self.pushes_accepted > accepted:
            self._fw_countdown = None           # the base model's timer:
            if self.on_push is not None:        # replaced by the queue
                self.on_push(self)
            ticks = (self.cmd_latencies.pop(0) if self.cmd_latencies
                     else base.FW_LATENCY)
            self._enqueue("cmd", ticks)


# ---------------------------------------------------------------------------
# Rig
# ---------------------------------------------------------------------------

def _machine(uci, tod_reads_per_tenth):
    if not base.PRG.is_file() or not base.LABELS.is_file():
        raise Unavailable("build/c64-https.prg or labels.txt is missing — "
                          "build with `make BACKEND=uci "
                          "USE_NISTCURVES_ONCHIP=1`")
    labels = base._labels()
    for needed in LABELS_NEEDED:
        if needed not in labels:
            raise Unavailable(
                "%s is not in build/labels.txt — this is not a BACKEND=uci "
                "build; rebuild with `make BACKEND=uci "
                "USE_NISTCURVES_ONCHIP=1`" % needed)
    raw = base.PRG.read_bytes()
    mem = Memory(raw[2:], raw[0] | (raw[1] << 8), uci,
                 tod_reads_per_tenth=tod_reads_per_tenth)
    for name in ("uci_status_len", "uci_status_force", "net_last_error",
                 "net_tcp_state", "uci_socket_id"):
        mem.write(labels[name], 0)
    for off in range(2):
        mem.write(labels["tcp_recv_head"] + off, 0)
        mem.write(labels["tcp_recv_tail"] + off, 0)
    for i, b in enumerate(HOST + b"\x00"):
        mem.write(labels["uci_host_buf"] + i, b)
    return FastCPU(mem), mem, labels


def _require(uci, tod_reads_per_tenth=1):
    try:
        return _machine(uci, tod_reads_per_tenth)
    except Unavailable as exc:
        if os.environ.get(OPT_OUT_ENV) != "1":
            raise
        # _skip_policy.require() folds the warning into the reason
        # and hands pytest a skip only when pytest is driving (#178).
        require(False, str(exc), executed=0, total=len(TESTS),
                certifies=CERTIFIES, opt_out_env=OPT_OUT_ENV)


def _connect(cpu, labels, budget=8_000_000):
    cpu.a, cpu.x = PORT & 0xFF, PORT >> 8
    return cpu.call(labels["net_tcp_connect"], budget=budget)


def _err(mem, labels):
    return mem.read(labels["net_last_error"])


def _state(mem, labels):
    return mem.read(labels["net_tcp_state"])


def _assert_connected(cpu, mem, uci, labels, what):
    """A fresh TCP_CONNECT must reach the firmware whole and succeed."""
    before = len(uci.parsed)
    mem.write(labels["net_last_error"], 0)
    carry = _connect(cpu, labels)
    seen = uci.parsed[before:]
    base._check(carry is False and _state(mem, labels) == NET_TCP_CONNECTED
                and mem.read(labels["uci_socket_id"]) == 1, (
        "%s: the connect that followed FAILED — C=%d, net_last_error=$%02X, "
        "net_tcp_state=$%02X; the firmware parsed %r (expected one "
        "TCP_CONNECT %r)"
        % (what, carry, _err(mem, labels), _state(mem, labels), seen,
           CONNECT_BYTES)))
    base._check(seen == [(CONNECT_BYTES, "ok")], (
        "%s: the firmware parsed %r, expected exactly [(%r, 'ok')]"
        % (what, seen, CONNECT_BYTES)))


# ---------------------------------------------------------------------------
# (a) #230: the command after an ABORT
# ---------------------------------------------------------------------------

def _init_then_connect(latency):
    """net_init (ABORT) straight into net_tcp_connect: the trampoline shape."""
    uci = AbortModel([CONNECT_OK], abort_latency=latency)
    cpu, mem, labels = _require(uci)
    carry = cpu.call(labels["net_init"])
    base._check(carry is False, (
        "net_init returned C=1 (net_last_error=$%02X) with an abort that "
        "lands after %d ticks" % (_err(mem, labels), latency)))
    base._check(uci.abort_writes == 1,
                "net_init wrote ABORT %d times" % uci.abort_writes)
    _assert_connected(cpu, mem, uci, labels,
                      "abort latency %d ticks" % latency)
    base._check(uci.aborts_completed == 1, "the abort never landed")


def test_prompt_abort_control():
    """Control: the reset lands at once. Passes on the old code too."""
    _init_then_connect(latency=0)


def test_connect_after_a_delayed_abort():
    """The #230(a) loss: the reset lands after the PUSH, so the firmware
    parses an empty buffer (Null command) and TCP_CONNECT reads back no
    socket: $88, the field signature."""
    _init_then_connect(latency=10)


def test_port_443_reset_after_the_command_byte():
    """The reset lands after the target and command bytes, so the firmware
    takes port_lo as message[0]. For 443 that is $BB: bit 7 is
    CMD_IF_NO_REPLY, so no reply is ever staged and a reply wait can only
    time out ($89) — where a lost command otherwise reads back as $88."""
    assert CONNECT_BYTES[2] == 0xBB and CONNECT_BYTES[2] & CMD_IF_NO_REPLY
    _init_then_connect(latency=4)       # 1 status read + 3 byte writes


def test_every_abort_latency_keeps_the_command():
    """Sweep the latency. On the old code a reset landing mid-write leaves
    a truncated command (21,UNKNOWN COMMAND); one landing after the PUSH
    leaves an empty one (Null command). Both read back no socket: $88."""
    for latency in range(0, 16):
        _init_then_connect(latency)


def test_an_abort_that_never_lands_is_reported():
    """The new wait is bounded: a reset that never comes is $89, C=1."""
    uci = AbortModel([CONNECT_OK], abort_latency=None)
    cpu, mem, labels = _require(uci, tod_reads_per_tenth=1)
    carry = cpu.call(labels["net_init"])
    base._check(carry is True and _err(mem, labels) == UCI_ERR_WAIT_TIMEOUT, (
        "net_init returned C=%d, net_last_error=$%02X with an abort the "
        "firmware never serviced; expected C=1 and $89 (the command after "
        "it would be lost)" % (carry, _err(mem, labels))))
    base._check(uci.status_reads_while_abort_pending >= 2, (
        "net_init returned after %d status read(s) with the abort pending "
        "— it did not wait for the reset at all"
        % uci.status_reads_while_abort_pending))


def test_absent_interface_is_still_not_present():
    """Open bus: bit 2 reads set forever. Still NOT_PRESENT, not $89."""
    uci = AbortModel([], present=False)
    cpu, mem, labels = _require(uci, tod_reads_per_tenth=1)
    carry = cpu.call(labels["net_init"])
    base._check(carry is True and _err(mem, labels) == UCI_ERR_NOT_PRESENT, (
        "net_init with no interface returned C=%d, net_last_error=$%02X; "
        "expected C=1, $81 NOT_PRESENT" % (carry, _err(mem, labels))))


# ---------------------------------------------------------------------------
# (b) #221: each connect/close timeout exit, then a fresh connect
# ---------------------------------------------------------------------------

def _dirty_interface(uci):
    """A data phase someone else left open (e.g. a net_poll bail)."""
    uci.state = ST_DATA_LAST
    uci.endless = True


def _after_bail(cpu, mem, uci, labels, carry, what, want_state):
    base._check(carry is True, "%s returned C=0" % what)
    base._check(_err(mem, labels) == UCI_ERR_WAIT_TIMEOUT, (
        "%s: net_last_error=$%02X, expected $89"
        % (what, _err(mem, labels))))
    if want_state is not None:
        base._check(_state(mem, labels) == want_state, (
            "%s: net_tcp_state=$%02X, expected $%02X"
            % (what, _state(mem, labels), want_state)))
    left = uci.describe()
    _assert_connected(cpu, mem, uci, labels,
                      "%s (interface left in state %s)" % (what, left))
    base._check(uci.abort_writes >= 1, (
        "%s returned without writing ABORT, yet the next connect worked; "
        "the model and the code disagree" % what))


def test_connect_entry_wait_bail():
    uci = AbortModel([CONNECT_OK])
    _dirty_interface(uci)
    cpu, mem, labels = _require(uci)
    carry = _connect(cpu, labels)
    _after_bail(cpu, mem, uci, labels, carry,
                "net_tcp_connect's entry uci_wait_idle bail",
                NET_TCP_CONNECT_FAIL)


# A task busy this many model ticks on one command: longer than the push
# wait's ~50-tick budget, shorter than push wait + abort wait. The stalled
# command then completes (state "10"), and the abort queued behind it resets.
STALL_RECOVERS = 70


def test_connect_push_wait_bail():
    """The task is slow on TCP_CONNECT; the abort waits behind it (FIFO)."""
    uci = AbortModel([CONNECT_OK, CONNECT_OK])
    uci.cmd_latencies = [STALL_RECOVERS]
    cpu, mem, labels = _require(uci)
    carry = _connect(cpu, labels)
    _after_bail(cpu, mem, uci, labels, carry,
                "net_tcp_connect's uci_push_wait bail", NET_TCP_CONNECT_FAIL)


def test_connect_error_path_drain_bail():
    """@tc_err: the push is rejected (ERROR), then the drain of the late
    reply that caused it never finishes."""
    uci = AbortModel([CONNECT_OK])
    uci.late_reply = (ENDLESS, b"")
    cpu, mem, labels = _require(uci)
    carry = _connect(cpu, labels)
    base._check(uci.pushes_rejected == 1 and not uci.parsed, (
        "the TCP_CONNECT push was not rejected (%d rejections, parsed %r): "
        "this test no longer reaches @tc_err" % (uci.pushes_rejected,
                                                 uci.parsed)))
    _after_bail(cpu, mem, uci, labels, carry,
                "net_tcp_connect's error-path drain bail (@tc_err)", None)


def test_connect_ok_path_drain_bail():
    """@tc_ok: a good reply whose data never ends."""
    uci = AbortModel([(ENDLESS, OK), CONNECT_OK])
    cpu, mem, labels = _require(uci)
    carry = _connect(cpu, labels)
    _after_bail(cpu, mem, uci, labels, carry,
                "net_tcp_connect's success-path drain bail (@tc_ok)",
                NET_TCP_CONNECT_FAIL)


def _close(cpu, labels):
    return cpu.call(labels["net_tcp_close"])


CMD_SOCKET_CLOSE = 0x09
CLOSE_BYTES = bytes([TARGET_NETWORK, CMD_SOCKET_CLOSE, 1])
UCI_ERR_READ_FAIL = 0x86


def _closes(uci):
    return [p for p in uci.parsed if p[0] == CLOSE_BYTES]


def test_close_entry_wait_bail_retries_the_close():
    """#243: the entry wait finds a transaction somebody left open (a
    net_poll bail). The abort clears it, so the close must still reach the
    firmware: without the retry the socket stays live while net_tcp_state
    says CLOSED, and the next C64 reset over it poisons the lease. A
    retry that succeeds reports success and leaves the error the caller
    came in with (here net_poll's $86), not the entry wait's $89."""
    uci = AbortModel([(b"", OK), CONNECT_OK])
    _dirty_interface(uci)
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    mem.write(labels["net_last_error"], UCI_ERR_READ_FAIL)
    carry = _close(cpu, labels)
    base._check(_closes(uci) == [(CLOSE_BYTES, "ok")], (
        "after the entry-wait abort the firmware parsed %r: no SOCKET_CLOSE "
        "%r reached it, so the socket is still live" % (uci.parsed,
                                                        CLOSE_BYTES)))
    base._check(uci.abort_writes == 1 and uci.aborts_completed == 1, (
        "abort writes=%d completed=%d; expected exactly one, landed"
        % (uci.abort_writes, uci.aborts_completed)))
    base._check(carry is False and _err(mem, labels) == UCI_ERR_READ_FAIL, (
        "the retried close succeeded but returned C=%d, net_last_error=$%02X;"
        " expected C=0 and the entry value $86"
        % (carry, _err(mem, labels))))
    base._check(_state(mem, labels) == NET_TCP_CLOSED,
                "net_tcp_state=$%02X after the close" % _state(mem, labels))
    _assert_connected(cpu, mem, uci, labels, "connect after the retried close")


def test_close_no_retry_when_the_abort_never_lands():
    """The entry wait expired because the task is stuck, so the abort
    queued behind it never lands either. Retrying would only stack a third
    5 s wait: report $89 after the entry wait + ONE abort wait, as before."""
    uci = AbortModel([(b"", OK)], abort_latency=None)
    _dirty_interface(uci)
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    carry = _close(cpu, labels)
    base._check(carry is True and _err(mem, labels) == UCI_ERR_WAIT_TIMEOUT
                and _state(mem, labels) == NET_TCP_CLOSED, (
        "stuck task: close returned C=%d, net_last_error=$%02X, "
        "net_tcp_state=$%02X; expected C=1, $89, CLOSED"
        % (carry, _err(mem, labels), _state(mem, labels))))
    base._check(uci.abort_writes == 1 and not uci.parsed
                and uci.pushes_accepted + uci.pushes_rejected == 0, (
        "stuck task: %d abort write(s), %d push(es), parsed %r; expected one "
        "abort and no command" % (uci.abort_writes, uci.pushes_accepted
                                   + uci.pushes_rejected, uci.parsed)))
    reads = mem._tod_reads
    budget = base.BUDGET_TENTHS
    base._check(2 * budget <= reads < 3 * budget, (
        "the stuck-task close read the TOD %d times: expected the entry wait "
        "+ one abort wait (%d-%d)" % (reads, 2 * budget, 3 * budget - 1)))


def test_close_retry_that_also_fails_reports_89():
    """The abort lands, but the retried SOCKET_CLOSE stalls too: $89, C=1,
    CLOSED, exactly one retry, and the interface still left clean."""
    uci = AbortModel([(b"", OK), CONNECT_OK])
    uci.cmd_latencies = [STALL_RECOVERS]
    _dirty_interface(uci)
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    carry = _close(cpu, labels)
    base._check(_closes(uci) == [(CLOSE_BYTES, "ok")], (
        "expected exactly one (retried) SOCKET_CLOSE, the firmware parsed %r"
        % uci.parsed))
    _after_bail(cpu, mem, uci, labels, carry,
                "net_tcp_close's retried close, push wait bail",
                NET_TCP_CLOSED)


def test_close_push_wait_bail():
    """The task is slow on SOCKET_CLOSE; the abort waits behind it (FIFO)."""
    uci = AbortModel([(b"", OK), CONNECT_OK])
    uci.cmd_latencies = [STALL_RECOVERS]
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    carry = _close(cpu, labels)
    _after_bail(cpu, mem, uci, labels, carry,
                "net_tcp_close's uci_push_wait bail", NET_TCP_CLOSED)


def test_close_drain_bail():
    uci = AbortModel([(ENDLESS, OK), CONNECT_OK])
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    carry = _close(cpu, labels)
    _after_bail(cpu, mem, uci, labels, carry,
                "net_tcp_close's drain bail (@cl_drain_to)", NET_TCP_CLOSED)


def test_bail_whose_abort_never_lands():
    """The task never returns from TCP_CONNECT, so the abort queued behind
    it never lands either. The bail must report it ($89, C=1) after ONE
    abort wait, not stack a second 5 s wait behind it."""
    uci = AbortModel([CONNECT_OK])
    uci.cmd_latencies = [None]
    cpu, mem, labels = _require(uci)
    carry = _connect(cpu, labels)
    base._check(carry is True and _err(mem, labels) == UCI_ERR_WAIT_TIMEOUT
                and _state(mem, labels) == NET_TCP_CONNECT_FAIL, (
        "stuck task: connect returned C=%d, net_last_error=$%02X, "
        "net_tcp_state=$%02X; expected C=1, $89, CONNECT_FAIL"
        % (carry, _err(mem, labels), _state(mem, labels))))
    base._check(uci.abort_writes == 1 and uci.aborts_completed == 0, (
        "abort writes=%d, completed=%d; expected one write that never lands"
        % (uci.abort_writes, uci.aborts_completed)))
    # One TENTHS read per wait-loop iteration and one tenth per read, so
    # each expired wait costs BUDGET reads: push wait + ONE abort wait.
    reads = mem._tod_reads
    budget = base.BUDGET_TENTHS
    base._check(2 * budget <= reads < 3 * budget, (
        "the stuck-task connect read the TOD %d times: expected two expired "
        "waits (%d-%d), push wait + one abort wait; %d or more means a "
        "further wait was stacked behind an abort that cannot land"
        % (reads, 2 * budget, 3 * budget - 1, 3 * budget)))


def test_closed_is_not_visible_before_the_close_ran():
    """#232's close_confirmed reads CLOSED as "net_tcp_close ran to
    completion or timed out". It must not be visible at the SOCKET_CLOSE
    push, and must be there on the way out."""
    uci = AbortModel([(b"", OK)])
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    seen = []
    uci.on_push = lambda m: seen.append(_state(mem, labels))
    _close(cpu, labels)
    base._check(seen == [NET_TCP_CONNECTED], (
        "net_tcp_state at the SOCKET_CLOSE push was %r; expected "
        "[$01 CONNECTED] — CLOSED became visible before the close ran"
        % seen))
    base._check(_state(mem, labels) == NET_TCP_CLOSED,
                "net_tcp_close left net_tcp_state=$%02X"
                % _state(mem, labels))


def test_abort_outlasting_init_is_waited_out_by_the_next_command():
    """net_init's abort wait expires with the reset still pending (state
    "00", bit 2 set). The trampoline ignores net_init's carry, so the next
    thing is net_tcp_connect: its entry wait must see bit 2 ($35 mask), or
    the command it writes is rewound under it (#230 a, residual case)."""
    uci = AbortModel([CONNECT_OK], abort_latency=base.BUDGET_TENTHS + 10)
    cpu, mem, labels = _require(uci)
    carry = cpu.call(labels["net_init"])
    base._check(carry is True and _err(mem, labels) == UCI_ERR_WAIT_TIMEOUT
                and uci.abort_pending, (
        "premise: net_init should time out with the abort still pending "
        "(C=%d, err=$%02X, pending=%s)"
        % (carry, _err(mem, labels), uci.abort_pending)))
    _assert_connected(cpu, mem, uci, labels,
                      "connect after net_init's abort wait expired")


def test_clean_connect_close_connect_never_aborts():
    """Control: the happy paths write no ABORT and keep their carries."""
    uci = AbortModel([CONNECT_OK, (b"", OK), CONNECT_OK])
    cpu, mem, labels = _require(uci)
    _assert_connected(cpu, mem, uci, labels, "first clean connect")
    carry = _close(cpu, labels)
    base._check(carry is False and _state(mem, labels) == NET_TCP_CLOSED, (
        "a clean close returned C=%d, net_tcp_state=$%02X; expected C=0, "
        "CLOSED" % (carry, _state(mem, labels))))
    _assert_connected(cpu, mem, uci, labels, "second clean connect")
    base._check(uci.abort_writes == 0, (
        "the clean paths wrote ABORT %d time(s); the bail has leaked onto "
        "a success path" % uci.abort_writes))
    base._check(uci.pushes_rejected == 0,
                "%d push(es) rejected on the clean paths" % uci.pushes_rejected)


def _poll_once(reply):
    uci = AbortModel([reply])
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    cpu.call(labels["net_poll"], budget=8_000_000)
    return uci, mem, labels


def test_poll_eof_closes_the_socket_state():
    """SOCKET_READ answering actual_len 0 is the peer's FIN: read_socket
    has already lwip_close()d the socket and said "01,CONNECTION CLOSED BY
    HOST". net_poll must stop reporting CONNECTED, or http_recv_body polls
    a dead socket for its whole tick budget (~87 min; live: github.com and
    browserleaks.com runs sat out the rig's 900 s sentinel this way)."""
    uci, mem, labels = _poll_once((b"\x00\x00", b"01,CONNECTION CLOSED BY HOST"))
    base._check(uci.parsed and uci.parsed[0][0][:2] == bytes([TARGET_NETWORK,
                                                              0x10]), (
        "premise: net_poll did not issue a SOCKET_READ (parsed %r)"
        % uci.parsed))
    base._check(_state(mem, labels) == NET_TCP_CLOSED, (
        "after an EOF reply net_tcp_state=$%02X, expected $00 CLOSED"
        % _state(mem, labels)))
    base._check(_err(mem, labels) == 0,
                "an EOF set net_last_error=$%02X; a FIN is not an error"
                % _err(mem, labels))
    base._check(uci.idle and uci.abort_writes == 0,
                "the EOF poll left the interface in %s (aborts=%d)"
                % (uci.describe(), uci.abort_writes))


def test_poll_no_data_keeps_the_socket():
    """Control: the idle answer ($FFFF, "02,NO DATA: 11") is not EOF."""
    uci, mem, labels = _poll_once((b"\xff\xff", b"02,NO DATA: 11"))
    base._check(_state(mem, labels) == NET_TCP_CONNECTED, (
        "an idle poll changed net_tcp_state to $%02X"
        % _state(mem, labels)))


def test_eof_keeps_the_bytes_already_in_the_ring():
    """The body's last bytes and the EOF cannot share a reply (read_socket
    answers data OR 0), but they can share a moment: the data poll fills
    the ring, the EOF poll runs before the HTTP/TLS layer has drained it.
    Flipping to CLOSED must not drop them: the ring is untouched and
    net_recv_byte (which never reads net_tcp_state) still hands out every
    byte; only further SOCKET_READs stop. http_recv_body's verdict is then
    decided by the body's own framing, as test_body_truncation.py pins."""
    uci = AbortModel([(b"\x00\x00", b"01,CONNECTION CLOSED BY HOST")])
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    tail = b"0\r\n\r\n" + bytes(range(0x40, 0x4B))   # a body's last bytes
    for i, b in enumerate(tail):
        mem.write(labels["tcp_recv_buf"] + i, b)
    mem.write(labels["tcp_recv_tail"], len(tail))
    cpu.call(labels["net_poll"], budget=8_000_000)
    base._check(_state(mem, labels) == NET_TCP_CLOSED,
                "premise: the EOF poll left net_tcp_state=$%02X"
                % _state(mem, labels))
    head = mem.read(labels["tcp_recv_head"]) | mem.read(labels["tcp_recv_head"] + 1) << 8
    tl = mem.read(labels["tcp_recv_tail"]) | mem.read(labels["tcp_recv_tail"] + 1) << 8
    base._check((head, tl) == (0, len(tail)), (
        "the EOF poll moved the ring: head=%d tail=%d, expected 0/%d"
        % (head, tl, len(tail))))
    got = []
    for _ in range(len(tail) + 1):
        carry = cpu.call(labels["net_recv_byte"])
        if carry:
            break
        got.append(cpu.a)
    base._check(bytes(got) == tail, (
        "after the EOF net_recv_byte returned %r, expected %r"
        % (bytes(got), tail)))
    parsed = len(uci.parsed)
    cpu.call(labels["net_poll"], budget=8_000_000)
    base._check(len(uci.parsed) == parsed,
                "net_poll issued another command after the EOF: %r"
                % uci.parsed[parsed:])


UCI_ERR_SHORT_WRITE = 0x87
CMD_SOCKET_WRITE = 0x11


def test_send_error_is_not_a_length():
    """SOCKET_WRITE answering written=$FFFF is lwip_send's -1 (a peer that
    has closed). Read as a length it moved the source back a byte and grew
    the remaining count by one per round trip: ~65k SOCKET_WRITEs, ~45 min
    on the device, then C=0. Live: browserleaks.com closes during the
    onchip handshake and the client Finished write hung for the rig's
    whole 900 s. It must fail at once: C=1, $87, one write."""
    uci = AbortModel([(b"\xff\xff", b"12,SEND ERROR: 9")] * 4)
    cpu, mem, labels = _require(uci)
    mem.write(labels["uci_socket_id"], 1)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    mem.write(labels["net_send_len"], 58)
    mem.write(labels["net_send_len"] + 1, 0)
    cpu.a, cpu.x = 0x00, 0x04
    try:
        carry = cpu.call(labels["net_tcp_send"], budget=4_000_000)
    except CPUError as exc:
        raise AssertionError(
            "net_tcp_send did not return after a -1 write (%d SOCKET_WRITEs "
            "parsed): %s" % (sum(1 for b, _ in uci.parsed
                                 if b[1:2] == bytes([CMD_SOCKET_WRITE])), exc))
    writes = [b for b, _ in uci.parsed if b[1:2] == bytes([CMD_SOCKET_WRITE])]
    base._check(carry is True and _err(mem, labels) == UCI_ERR_SHORT_WRITE
                and len(writes) == 1, (
        "a -1 write returned C=%d, net_last_error=$%02X after %d "
        "SOCKET_WRITE(s); expected C=1, $87, one"
        % (carry, _err(mem, labels), len(writes))))


TESTS = (
    test_prompt_abort_control,
    test_connect_after_a_delayed_abort,
    test_port_443_reset_after_the_command_byte,
    test_every_abort_latency_keeps_the_command,
    test_an_abort_that_never_lands_is_reported,
    test_absent_interface_is_still_not_present,
    test_connect_entry_wait_bail,
    test_connect_push_wait_bail,
    test_connect_error_path_drain_bail,
    test_connect_ok_path_drain_bail,
    test_close_entry_wait_bail_retries_the_close,
    test_close_no_retry_when_the_abort_never_lands,
    test_close_retry_that_also_fails_reports_89,
    test_close_push_wait_bail,
    test_close_drain_bail,
    test_bail_whose_abort_never_lands,
    test_closed_is_not_visible_before_the_close_ran,
    test_abort_outlasting_init_is_waited_out_by_the_next_command,
    test_clean_connect_close_connect_never_aborts,
    test_poll_eof_closes_the_socket_state,
    test_poll_no_data_keeps_the_socket,
    test_eof_keeps_the_bytes_already_in_the_ring,
    test_send_error_is_not_a_length,
)


def main():
    passed = failed = 0
    for test in TESTS:
        try:
            test()
        except VoluntarySkip as exc:
            print("SKIP: %s" % exc)
            return verdict(passed, failed,
                           skipped=len(TESTS) - passed - failed,
                           opt_out_env=OPT_OUT_ENV, certifies=CERTIFIES)
        except Unavailable as exc:
            print("CANNOT RUN: %s" % exc)
            return 2
        except (AssertionError, CPUError) as exc:
            failed += 1
            print("FAIL %s: %s" % (test.__name__, exc))
        else:
            passed += 1
            print("ok   %s" % test.__name__)
    print("%d/%d passed, %d assertions" % (len(TESTS) - failed, len(TESTS),
                                           base.ASSERTIONS_RUN))
    if base.ASSERTIONS_RUN == 0:
        print("CANNOT RUN: no assertion executed")
        return 2
    return verdict(passed, failed, certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
