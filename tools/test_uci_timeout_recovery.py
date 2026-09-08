#!/usr/bin/env python3
"""net_tcp_send must not abandon a half-finished transaction (issue #194).

WHAT THIS TESTS

``net_tcp_send`` has three exits that a bounded wait can take
mid-transaction: ``uci_push_wait`` timing out on the SOCKET_WRITE
response, and either drain (``uci_drain_resp`` / ``uci_drain_status``)
timing out on the error path or on the success path.  All three are
honest failures — ``net_last_error`` is already ``UCI_ERR_WAIT_TIMEOUT``
($89) and the caller gets C=1 — but before #194 they returned without
ever accepting **or** aborting the transaction, so the command interface
was left wherever the firmware had put it.

That matters because of what the FPGA does with the *next* command.  In
``command_protocol.vhd`` a PUSH_CMD is honoured only from the idle
state::

    if state = "00" then
        state <= "01";
        handshake_in(0) <= '1';
    else
        error_busy <= '1';

``error_busy`` is ``$DF1C`` bit 3 and that branch is its only setter, so
a push arriving while the interface is not idle is **silently dropped**
and reported as bit 3 — which this adapter surfaces as
``UCI_ERR_READ_FAIL`` ($86) when the rejected push was ``net_poll``'s
SOCKET_READ.  ``net_poll`` reaches PUSH_CMD through ``uci_wait_not_busy``
(mask ``UCI_STAT_CMD_BUSY``, $01), *not* ``uci_wait_idle`` (mask $31), so
a left-over data phase does not hold it back: CMD_BUSY is already clear
in that state and it pushes straight into the rejection.  And a
``net_tcp_send`` bail leaves ``net_tcp_state`` at CONNECTED, so the next
``net_poll`` runs.

WHAT THIS DOES *NOT* CLAIM

That this is the source of the ``$86`` seen in the field.  Nothing here
is a hardware measurement: the checks below run the shipped 6502 code
against a model of the register file, so they show what the code does to
the *model*, given a reading of the VHDL and of the firmware's command
task.  No captured run pairs a send ``$89`` with a following ``$86``.
The protocol defect stands on its own — an un-accepted, un-aborted
transaction is wrong whatever it goes on to cause.

WHY ABORT AND NOT DATA_ACC

DATA_ACC is gated on ``state(1) = '1'`` in the same VHDL process, so on
the ``uci_push_wait`` exit — where the firmware has not replied yet and
state is "01" — writing it does nothing at all.  The abort bit sets
``handshake_in(2)`` unconditionally; ``command_intf.cc``'s task then
writes ``HANDSHAKE_RESET`` (0x87), whose bit 7 hits the ``state <= "00"``
arm.  That is a firmware round trip, not an FPGA-cycle affair, which is
why the fix follows ``uci_abort`` with the bounded ``uci_wait_idle``
rather than trusting ``uci_abort``'s own 32-iteration settle.

HOW IT TESTS IT

Like ``tools/test_uci_data_acc.py`` (whose 6502 interpreter it reuses):
the *shipped machine code* is lifted out of ``build/c64-https.prg`` at
the addresses in ``build/labels.txt`` and executed against a model of
``$DF1B-$DF1F``.  This model is richer than that suite's, because these
paths need three things it does not have:

  * the four-state machine and its ``error_busy`` rejection branch,
  * a firmware that answers a command after a delay rather than
    instantly, so CMD_BUSY and the data phase can be observed, and an
    ABORT that takes effect only after that same delay,
  * a CIA1 TOD that actually advances, so the 5 s bounded waits can
    expire on purpose.  (``test_uci_data_acc.py`` freezes the TOD for the
    opposite reason: there, a timeout would be the bug.)

Runs standalone or under pytest::

    python3 tools/test_uci_timeout_recovery.py
    pytest tools/test_uci_timeout_recovery.py
"""

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PRG = REPO / "build" / "c64-https.prg"
LABELS = REPO / "build" / "labels.txt"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_uci_data_acc import CPU, CPUError          # noqa: E402  (the interpreter)

OPT_OUT_ENV = "C64_UCI_TESTS_OPTIONAL"

# --- register bits (uci_regs.inc) ------------------------------------------
UCI_STAT_DATA_AV = 0x80
UCI_STAT_STAT_AV = 0x40
UCI_STAT_ERROR = 0x08
UCI_STAT_CMD_BUSY = 0x01

UCI_CTRL_PUSH_CMD = 0x01
UCI_CTRL_DATA_ACC = 0x02
UCI_CTRL_ABORT = 0x04
UCI_CTRL_CLR_ERR = 0x08

# --- the four protocol states (command_protocol.vhd header comment) --------
ST_IDLE = 0b00          # Ultimate ready, waiting for a new command
ST_BUSY = 0b01          # command written, Ultimate processing it
ST_DATA_LAST = 0b10     # replied, last data
ST_DATA_MORE = 0b11     # replied, more data to come

# net_states.inc
NET_TCP_CONNECTED = 0x01

# uci_errors.inc
UCI_ERR_READ_FAIL = 0x86
UCI_ERR_WAIT_TIMEOUT = 0x89

# How many $DF1C reads the modelled firmware takes to answer a command or to
# act on an abort. Any small number > 0 works; it exists so that "the FPGA
# is not idle yet" is a state the code can actually observe, and so that a
# recovery that does not wait cannot pass by accident.
FW_LATENCY = 3

# The TOD budget the waits use (UCI_WAIT_IDLE_BUDGET_TENTHS in uci_cmd.s).
BUDGET_TENTHS = 50

ENDLESS = object()      # a response queue that never runs dry


class VoluntarySkip(Exception):
    pass


class Unavailable(Exception):
    pass


class CommandInterface:
    """$DF1B-$DF1F, modelled from command_protocol.vhd + command_intf.cc.

    `replies` is consumed one entry per accepted PUSH_CMD; each entry is
    ``(response, status)`` where `response` is bytes or ENDLESS.
    """

    def __init__(self, replies=()):
        self.replies = list(replies)
        self.state = ST_IDLE
        self.new_command = False        # handshake_in(0) -> UCI_STAT_CMD_BUSY
        self.error_busy = False         # slot_status(3)
        self.response = b""
        self.status = b""
        self.resp_ptr = 0
        self.stat_ptr = 0
        self.endless = False
        # counters
        self.pushes_accepted = 0
        self.pushes_rejected = 0        # the error_busy branch: $86's setter
        self.accepts = 0                # DATA_ACC writes that did something
        self.acc_writes = 0             # DATA_ACC writes, effective or not
        self.abort_writes = 0
        self.aborts_completed = 0       # HANDSHAKE_RESET actually applied
        # firmware timing
        self._fw_countdown = None
        self._abort_countdown = None

    # -- the modelled firmware task ----------------------------------------
    def _tick(self):
        """Run one step of the Ultimate-side task. Driven by status reads."""
        if self._abort_countdown is not None:
            self._abort_countdown -= 1
            if self._abort_countdown <= 0:
                # command_intf.cc: target->abort(), then HANDSHAKE_RESET
                # (0x87) -> bit 7 forces `state <= "00"`, bits 0/1/2 clear
                # the three handshake_in flags.
                self._abort_countdown = None
                self.state = ST_IDLE
                self.new_command = False
                self.response = self.status = b""
                self.resp_ptr = self.stat_ptr = 0
                self.endless = False
                self.aborts_completed += 1
            return
        if self._fw_countdown is not None:
            self._fw_countdown -= 1
            if self._fw_countdown <= 0:
                self._fw_countdown = None
                response, status = (self.replies.pop(0) if self.replies
                                    else (b"", b""))
                self.endless = response is ENDLESS
                self.response = b"" if self.endless else bytes(response)
                self.status = bytes(status)
                self.resp_ptr = self.stat_ptr = 0
                self.new_command = False    # HANDSHAKE_ACCEPT_COMMAND
                self.state = ST_DATA_LAST   # copy_result: 10 (no more data)

    # -- host reads ---------------------------------------------------------
    def read(self, addr):
        if addr == 0xDF1C:                      # STATUS
            self._tick()
            bits = (self.state & 0x03) << 4
            if self.state & 0b10:               # response/status valid only
                if self.endless or self.resp_ptr < len(self.response):
                    bits |= UCI_STAT_DATA_AV
                if self.stat_ptr < len(self.status):
                    bits |= UCI_STAT_STAT_AV
            if self.error_busy:
                bits |= UCI_STAT_ERROR
            if self.new_command:
                bits |= UCI_STAT_CMD_BUSY
            return bits
        if addr == 0xDF1D:                      # ID
            return 0xC9
        if addr == 0xDF1E:                      # response queue
            if not self.state & 0b10:
                return 0x00
            if self.endless:
                return 0x5A
            if self.resp_ptr >= len(self.response):
                return 0x00
            value = self.response[self.resp_ptr]
            self.resp_ptr += 1                  # reads auto-advance
            return value
        if addr == 0xDF1F:                      # status queue
            if not self.state & 0b10 or self.stat_ptr >= len(self.status):
                return 0x00
            value = self.status[self.stat_ptr]
            self.stat_ptr += 1
            return value
        return 0x00

    # -- host writes --------------------------------------------------------
    def write(self, addr, value):
        if addr != 0xDF1C:
            return
        if value & UCI_CTRL_CLR_ERR:
            self.error_busy = False
        if value & UCI_CTRL_PUSH_CMD:
            if self.state == ST_IDLE:
                self.state = ST_BUSY
                self.new_command = True
                self.pushes_accepted += 1
                self._fw_countdown = FW_LATENCY
            else:
                # the one setter of $DF1C bit 3
                self.error_busy = True
                self.pushes_rejected += 1
        if value & UCI_CTRL_DATA_ACC:
            self.acc_writes += 1
            if self.state & 0b10:               # gated on state(1)='1'
                self.accepts += 1
                self.state = ST_IDLE
                self.response = self.status = b""
                self.resp_ptr = self.stat_ptr = 0
                self.endless = False
        if value & UCI_CTRL_ABORT:
            self.abort_writes += 1
            self._abort_countdown = FW_LATENCY

    @property
    def idle(self):
        return self.state == ST_IDLE and not self.new_command


class Memory:
    """64 KB of RAM with a *running* CIA1 TOD and the UCI registers over it."""

    def __init__(self, image, load_addr, uci, tod_reads_per_tenth=1):
        self.ram = bytearray(0x10000)
        self.ram[load_addr:load_addr + len(image)] = image
        self.uci = uci
        self.tenths = 0
        self._tod_reads = 0
        self._per_tenth = tod_reads_per_tenth

    def read(self, addr):
        addr &= 0xFFFF
        if 0xDF00 <= addr <= 0xDFFF:
            return self.uci.read(addr)
        if addr == 0xDC0B:              # TOD HOUR — the latch read
            return 0x11
        if addr == 0xDC08:              # TOD TENTHS — unlatches and advances
            self._tod_reads += 1
            if self._tod_reads % self._per_tenth == 0:
                self.tenths = (self.tenths + 1) % 10
            return self.tenths
        if 0xDC00 <= addr <= 0xDCFF:
            return 0x00
        return self.ram[addr]

    def write(self, addr, value):
        addr &= 0xFFFF
        if 0xDF00 <= addr <= 0xDFFF:
            self.uci.write(addr, value & 0xFF)
            return
        if 0xDC00 <= addr <= 0xDCFF:
            return
        self.ram[addr] = value & 0xFF


# ---------------------------------------------------------------------------
# Rig
# ---------------------------------------------------------------------------

ASSERTIONS_RUN = 0

NEEDED_LABELS = ("net_tcp_send", "net_poll", "net_send_len", "uci_socket_id",
                 "net_last_error", "net_tcp_state", "uci_abort",
                 "uci_status_len", "uci_status_force",
                 "tcp_recv_head", "tcp_recv_tail")

SEND_SRC = 0x0400       # scratch source buffer for the payload
SEND_LEN = 4


def _check(condition, message):
    global ASSERTIONS_RUN
    ASSERTIONS_RUN += 1
    if not condition:
        raise AssertionError(message)


def _labels():
    if not LABELS.is_file():
        raise Unavailable("build/labels.txt is missing — build first with "
                          "`make BACKEND=uci USE_NISTCURVES_ONCHIP=1`")
    table = {}
    for line in LABELS.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "al" and parts[2].startswith("."):
            table[parts[2][1:]] = int(parts[1].split(":")[-1], 16)
    return table


def _machine(replies):
    if not PRG.is_file():
        raise Unavailable("build/c64-https.prg is missing — build first with "
                          "`make BACKEND=uci USE_NISTCURVES_ONCHIP=1`")
    labels = _labels()
    for needed in NEEDED_LABELS:
        if needed not in labels:
            raise Unavailable(
                "%s is not in build/labels.txt — this is not a BACKEND=uci "
                "build; rebuild with `make clean && make BACKEND=uci "
                "USE_NISTCURVES_ONCHIP=1`" % needed)

    raw = PRG.read_bytes()
    load_addr = raw[0] | (raw[1] << 8)
    uci = CommandInterface(replies)
    mem = Memory(raw[2:], load_addr, uci)

    # What net_init would have zeroed, plus the send's own inputs.
    for name in ("uci_status_len", "uci_status_force", "net_last_error"):
        mem.write(labels[name], 0)
    for off in range(2):
        mem.write(labels["tcp_recv_head"] + off, 0)
        mem.write(labels["tcp_recv_tail"] + off, 0)
    mem.write(labels["uci_socket_id"], 0x01)
    mem.write(labels["net_tcp_state"], NET_TCP_CONNECTED)
    mem.write(labels["net_send_len"] + 0, SEND_LEN & 0xFF)
    mem.write(labels["net_send_len"] + 1, SEND_LEN >> 8)
    for i in range(SEND_LEN):
        mem.write(SEND_SRC + i, 0x40 + i)

    cpu = CPU(mem)
    cpu.a = SEND_SRC & 0xFF
    cpu.x = SEND_SRC >> 8
    return cpu, mem, uci, labels


def _require(fn, *args):
    try:
        return fn(*args)
    except Unavailable as exc:
        if os.environ.get(OPT_OUT_ENV) != "1":
            raise
        reason = ("EXPLICIT SKIP (%s=1 is set in this environment): %s "
                  "0 of %d checks ran; this exit-0 certifies NOTHING about "
                  "net_tcp_send's timeout exits (#194)."
                  % (OPT_OUT_ENV, exc, len(TESTS)))
        pytest = sys.modules.get("pytest")
        if pytest is None:
            raise VoluntarySkip(reason)
        pytest.skip(reason, allow_module_level=False)


def _send(cpu, labels, budget=8_000_000):
    """JSR net_tcp_send with AX already pointing at the payload."""
    return cpu.call(labels["net_tcp_send"], budget=budget)


def _leftover_state(uci):
    names = {ST_IDLE: '"00" (idle)', ST_BUSY: '"01" (busy)',
             ST_DATA_LAST: '"10" (data, last)',
             ST_DATA_MORE: '"11" (data, more)'}
    return "%s, CMD_BUSY=%d" % (names[uci.state], int(uci.new_command))


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------

def test_drain_timeout_on_the_success_path_leaves_the_interface_idle():
    """Exit 3: both drains time out after a good SOCKET_WRITE reply.

    The firmware answers with the 2-byte written count and then keeps
    DATA_AV asserted forever, so uci_drain_resp burns its 5 s budget and
    net_tcp_send bails.  Before #194 it returned straight from there,
    leaving the data phase open.
    """
    cpu, mem, uci, labels = _require(_machine, [(ENDLESS, b"")])

    carry = _send(cpu, labels)
    _check(carry is True,
           "net_tcp_send returned C=0 after a drain timeout — the failure "
           "itself is no longer reported")
    _check(mem.read(labels["net_last_error"]) == UCI_ERR_WAIT_TIMEOUT,
           "net_last_error is $%02X, expected $89 UCI_ERR_WAIT_TIMEOUT"
           % mem.read(labels["net_last_error"]))

    _check(uci.abort_writes >= 1, (
        "net_tcp_send bailed out of a live transaction without writing "
        "ABORT ($04 -> $DF1C). The interface is left in state %s, and the "
        "next PUSH_CMD from any command hits the `else error_busy <= '1'` "
        "branch in command_protocol.vhd (issue #194)."
        % _leftover_state(uci)))
    _check(uci.idle, (
        "the command interface is still in state %s after net_tcp_send "
        "returned; ABORT was written but nothing waited for the firmware "
        "to act on it" % _leftover_state(uci)))


def test_push_wait_timeout_leaves_the_interface_idle():
    """Exit 1: the firmware never picks the command up.

    CMD_BUSY stays set, so uci_push_wait times out with the interface in
    state "01" — the state in which DATA_ACC is a no-op, which is why the
    recovery has to be ABORT.
    """
    cpu, mem, uci, labels = _require(_machine, [])
    uci.replies = []                    # nothing to deliver...

    # ...and the firmware never gets round to answering at all.
    original_tick = uci._tick

    def stalled_tick():
        if uci._abort_countdown is not None:
            original_tick()
    uci._tick = stalled_tick

    carry = _send(cpu, labels)
    _check(carry is True, "net_tcp_send returned C=0 after a push timeout")
    _check(mem.read(labels["net_last_error"]) == UCI_ERR_WAIT_TIMEOUT,
           "net_last_error is $%02X, expected $89 UCI_ERR_WAIT_TIMEOUT"
           % mem.read(labels["net_last_error"]))

    _check(uci.abort_writes >= 1, (
        "net_tcp_send returned from the uci_push_wait timeout without "
        "writing ABORT; the interface is left in state %s (#194)"
        % _leftover_state(uci)))
    _check(uci.idle, (
        "the command interface is still in state %s after the push-wait "
        "bail" % _leftover_state(uci)))
    _check(uci.accepts == 0, (
        "DATA_ACC did something on the push-wait path — the model says it "
        "is gated on state(1)='1' and cannot; the model and the code "
        "disagree and one of them is wrong"))


def test_a_send_timeout_does_not_get_the_next_poll_rejected():
    """The consequence, end to end in the model.

    net_tcp_send bails; net_tcp_state is untouched, so the HTTP/TLS layer
    keeps polling.  net_poll reaches PUSH_CMD through uci_wait_not_busy,
    which does not test STATE, so a left-open data phase does not hold it
    back — the push is simply rejected, and that rejection is the single
    setter of $DF1C bit 3, which net_poll reports as $86.

    This is the model, not the field: it shows the code produces the
    rejection, not that any observed $86 came from here.
    """
    cpu, mem, uci, labels = _require(
        _machine, [(ENDLESS, b""), (b"\x00\x00", b"")])

    _check(_send(cpu, labels) is True, "net_tcp_send did not report failure")
    _check(mem.read(labels["net_tcp_state"]) == NET_TCP_CONNECTED,
           "net_tcp_send changed net_tcp_state; this test's premise (that "
           "polling continues after a send timeout) needs re-deriving")

    before = uci.pushes_rejected
    cpu.call(labels["net_poll"], budget=8_000_000)

    _check(uci.pushes_rejected == before, (
        "the SOCKET_READ push after a send timeout was REJECTED "
        "(%d rejection(s)): PUSH_CMD arrived while the interface was in "
        "state %s, which is the `else error_busy <= '1'` branch — the only "
        "setter of $DF1C bit 3, reported here as $86 UCI_ERR_READ_FAIL. "
        "net_last_error ended at $%02X."
        % (uci.pushes_rejected - before, _leftover_state(uci),
           mem.read(labels["net_last_error"]))))
    _check(mem.read(labels["net_last_error"]) != UCI_ERR_READ_FAIL,
           "net_poll reported $86 UCI_ERR_READ_FAIL after a clean recovery")


def test_a_clean_send_neither_aborts_nor_leaves_the_phase_open():
    """Control: the happy path is unchanged.

    The recovery must not leak onto the path that works — a send that
    completes accepts exactly once, with DATA_ACC, and never writes ABORT.
    If this fails together with the three above, the fault is in the fix
    or in this harness, not in the timeout exits.
    """
    cpu, mem, uci, labels = _require(_machine, [(b"\x04\x00", b"00,OK")])

    carry = _send(cpu, labels)
    _check(carry is False, "net_tcp_send reported failure on a clean send "
                           "(net_last_error $%02X)"
                           % mem.read(labels["net_last_error"]))
    _check(uci.accepts == 1,
           "a clean send wrote DATA_ACC %d effective time(s), expected 1"
           % uci.accepts)
    _check(uci.abort_writes == 0,
           "a clean send wrote ABORT %d time(s); the recovery has leaked "
           "onto the success path" % uci.abort_writes)
    _check(uci.idle, "the interface is not idle after a clean send: state %s"
                     % _leftover_state(uci))
    _check(uci.pushes_rejected == 0,
           "a clean send had %d push(es) rejected" % uci.pushes_rejected)


# ---------------------------------------------------------------------------
# Dual-mode runner (same conventions as tools/test_uci_data_acc.py)
# ---------------------------------------------------------------------------

TESTS = (
    test_drain_timeout_on_the_success_path_leaves_the_interface_idle,
    test_push_wait_timeout_leaves_the_interface_idle,
    test_a_send_timeout_does_not_get_the_next_poll_rejected,
    test_a_clean_send_neither_aborts_nor_leaves_the_phase_open,
)

EXIT_OK, EXIT_FAILED, EXIT_CANNOT_RUN = 0, 1, 2


def _cannot_run(reason):
    print("CANNOT RUN: %s" % reason)
    print("  0 of %d checks executed; %d assertions ran. This run certifies "
          "nothing about\n  net_tcp_send's timeout exits (#194)."
          % (len(TESTS), ASSERTIONS_RUN))
    print("  Set %s=1 to make skipping it a deliberate, exit-0 choice."
          % OPT_OUT_ENV)
    return EXIT_CANNOT_RUN


def main():
    if not PRG.is_file() or not LABELS.is_file():
        if os.environ.get(OPT_OUT_ENV) == "1":
            print("EXPLICIT SKIP (%s=1): no build in build/; "
                  "test_uci_timeout_recovery.py did NOT run." % OPT_OUT_ENV)
            return EXIT_OK
        return _cannot_run("no build to test. Run `make clean && make "
                           "BACKEND=uci USE_NISTCURVES_ONCHIP=1`")

    failures = 0
    executed = 0
    skipped = []
    for fn in TESTS:
        try:
            fn()
        except VoluntarySkip as exc:
            skipped.append(fn.__name__)
            print("SKIP %s: %s" % (fn.__name__, exc))
        except Unavailable as exc:
            return _cannot_run(str(exc))
        except AssertionError as exc:
            failures += 1
            executed += 1
            print("FAIL %s\n     %s" % (fn.__name__, exc))
        except CPUError as exc:
            failures += 1
            executed += 1
            print("FAIL %s (interpreter): %s" % (fn.__name__, exc))
        else:
            executed += 1
            print("PASS %s" % fn.__name__)

    if skipped:
        print("\nEXPLICIT SKIP (%s=1): %d of %d checks did NOT run."
              % (OPT_OUT_ENV, len(skipped), len(TESTS)))
        if executed == 0:
            return EXIT_OK

    if failures:
        print("\n%d/%d checks failed (%d assertions executed)"
              % (failures, executed, ASSERTIONS_RUN))
        return EXIT_FAILED

    if executed == 0 or ASSERTIONS_RUN == 0:
        return _cannot_run("no check executed and no assertion ran")

    print("\nall %d checks passed (%d assertions executed)"
          % (executed, ASSERTIONS_RUN))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
