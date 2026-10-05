#!/usr/bin/env python3
"""net_dhcp_acquire must take a lease only from a full GET_IPADDR reply.

WHAT THIS TESTS

``net_dhcp_acquire`` (src/net/uci/net.s) probes UCI interface indices 0..3
with GET_IPADDR and takes the first non-zero address.  The firmware
(``network_target.cc``, unchanged from GideonZ/1541ultimate 915cfbe7 in
2015 through 3a1ff9ff) answers an index at or past
``getNumberOfInterfaces()`` with ``c_message_empty`` and the status line
``"82,PARAMETER(S) OUT OF RANGE"``.  That is an ordinary, VALID reply: the
``$DF1C`` ERROR bit has one setter, a PUSH while not idle
(``command_protocol.vhd``), so ``uci_check_err`` returns C=0 and the old
code went on to read 12 bytes that were never sent.  Two consequences:

  * ``uci_read_resp_bytes`` waits out its 65,536 fenced spins for the
    first missing byte.  That spin is iteration-counted, not TOD-bounded:
    ~5,490 cycles per spin, so ~7.5 s per out-of-range probe at 48 MHz,
    ~5.6 s at 64 MHz and ~6 min at 1 MHz.  It is reached only when no
    in-range interface has a lease (the loop stops at the first one).
  * whatever ``uci_ipaddr_resp`` already held is copied to
    ``net_local_ip`` and, if non-zero, returned as a lease with C=0.

The second one needs a probe that returns fewer than 12 bytes with no full
reply before it in the same call.  On firmware every in-range index
returns 12 bytes and in-range indices are probed first, so on a box with
at least one interface (every U64E and C64U: Ethernet registers as index
0, cable or not) the buffer is always freshly written before an empty
probe can read it.  The stale-lease checks below therefore pin the
CONTRACT -- only a complete reply yields a lease -- against a modelled
zero-interface or short-reply firmware; they do not reproduce a failure
seen on a device.

HOW IT TESTS IT

The shipped machine code (``build/c64-https.prg`` at ``build/labels.txt``
addresses) runs on ``test_uci_data_acc.py``'s 6502 interpreter against
``test_uci_timeout_recovery.py``'s register-file model, extended with a
firmware that answers GET_IPADDR from the command bytes actually written
to ``$DF1D``.  The ``uci_fence`` delay loops are shortened in the loaded
image (inner count 217 -> 1): they are timing, not logic, and at full
length one out-of-range probe is ~140 M interpreted instructions.  Wasted
waiting is measured in ``$DF1C`` reads per probe, which the fence does not
change.

Runs standalone or under pytest (exit codes as its siblings: 0 pass,
1 fail, 2 cannot run; ``C64_UCI_TESTS_OPTIONAL=1`` opts out)::

    python3 tools/test_uci_dhcp_probe.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_uci_data_acc import CPU, CPUError               # noqa: E402
import test_uci_timeout_recovery as base                  # noqa: E402
from test_uci_timeout_recovery import (                   # noqa: E402
    CommandInterface, Memory, Unavailable, VoluntarySkip,
)
from _skip_policy import require, verdict                 # noqa: E402

OPT_OUT_ENV = "C64_UCI_TESTS_OPTIONAL"
CERTIFIES = "net_dhcp_acquire's interface probe"

UCI_ERR_NO_IP = 0x83
UCI_TARGET_NETWORK = 0x03
UCI_CMD_GET_IPADDR = 0x05

OK = b"00,OK"
OUT_OF_RANGE = b"82,PARAMETER(S) OUT OF RANGE"

NEEDED_LABELS = ("net_dhcp_acquire", "net_local_ip", "net_last_error",
                 "uci_ipaddr_resp", "uci_status_len", "uci_status_force")

# ldx #UCI_FENCE_OUTER / lda #UCI_FENCE_INNER / sbc #1 / bne / dex / bne
FENCE = bytes([0xA2, 0x05, 0xA9, 0xD9, 0xE9, 0x01, 0xD0, 0xFC, 0xCA, 0xD0,
               0xF7])
INNER_OFFSET = 3

# $DF1C reads a probe may spend.  A full reply costs a few dozen; the old
# read of an empty reply costs 65,536 on its own.
PROBE_READ_CEILING = 1000

LEASE_A = bytes([10, 43, 23, 83])
LEASE_B = bytes([10, 53, 21, 158])


def _reply(ip):
    """GET_IPADDR's 12-byte record: IP, netmask, gateway."""
    return bytes(ip) + bytes([255, 255, 255, 0]) + bytes(ip[:3]) + b"\x01"


class Raw:
    """A reply sent verbatim, not built from an IP."""

    def __init__(self, data):
        self.data = bytes(data)


class Firmware(CommandInterface):
    """Answers GET_IPADDR from the bytes written to $DF1D, as
    network_target.cc does.  `ifaces` is one entry per registered
    interface: an IP (4 bytes, all-zero = no lease) or a Raw reply."""

    def __init__(self, ifaces):
        super().__init__()
        self.ifaces = list(ifaces)
        self.cmd = []
        self.probes = []                # interface index per GET_IPADDR
        self.reads_per_probe = []       # $DF1C reads from push to next push

    def read(self, addr):
        if addr == 0xDF1C and self.reads_per_probe:
            self.reads_per_probe[-1] += 1
        return super().read(addr)

    def write(self, addr, value):
        if addr == 0xDF1D:
            self.cmd.append(value)
            return
        if addr == 0xDF1C and value & 0x01 and self.state == 0:
            self.replies = [self._answer(self.cmd)]
            self.cmd = []
            self.reads_per_probe.append(0)
        super().write(addr, value)

    def _answer(self, cmd):
        if (len(cmd) != 3 or cmd[0] != UCI_TARGET_NETWORK
                or cmd[1] != UCI_CMD_GET_IPADDR):
            raise AssertionError("unexpected command bytes %s"
                                 % " ".join("%02X" % b for b in cmd))
        index = cmd[2]
        self.probes.append(index)
        if index >= len(self.ifaces):
            return (b"", OUT_OF_RANGE)
        entry = self.ifaces[index]
        return (entry.data if isinstance(entry, Raw) else _reply(entry), OK)


def _fast_fences(image):
    out = bytearray(image)
    count = 0
    at = out.find(FENCE)
    while at >= 0:
        out[at + INNER_OFFSET] = 0x01
        count += 1
        at = out.find(FENCE, at + 1)
    if count == 0:
        raise Unavailable("no uci_fence sequence found in the PRG — the "
                          "macro changed; update FENCE in this test")
    return bytes(out)


def _machine(ifaces):
    labels = base._labels()
    for needed in NEEDED_LABELS:
        if needed not in labels:
            raise Unavailable(
                "%s is not in build/labels.txt — this is not a BACKEND=uci "
                "build; rebuild with `make BACKEND=uci "
                "USE_NISTCURVES_ONCHIP=1`" % needed)
    if not base.PRG.is_file():
        raise Unavailable("build/c64-https.prg is missing")
    raw = base.PRG.read_bytes()
    fw = Firmware(ifaces)
    mem = Memory(_fast_fences(raw[2:]), raw[0] | (raw[1] << 8), fw,
                 tod_reads_per_tenth=10_000)   # no TOD wait may expire
    for name in ("uci_status_len", "uci_status_force", "net_last_error"):
        mem.write(labels[name], 0)
    return CPU(mem), mem, fw, labels


def _require(*args):
    try:
        return _machine(*args)
    except Unavailable as exc:
        if os.environ.get(OPT_OUT_ENV) != "1":
            raise
        require(False, str(exc), executed=0, total=len(TESTS),
                certifies=CERTIFIES, opt_out_env=OPT_OUT_ENV)


def _acquire(cpu, labels):
    return cpu.call(labels["net_dhcp_acquire"], budget=20_000_000)


def _ip(mem, labels):
    return bytes(mem.read(labels["net_local_ip"] + i) for i in range(4))


def _err(mem, labels):
    return mem.read(labels["net_last_error"])


def _probe_costs_bounded(fw):
    worst = max(fw.reads_per_probe)
    base._check(worst < PROBE_READ_CEILING, (
        "a probe spent %d $DF1C reads (per probe, indices %s: %s). An empty "
        "GET_IPADDR reply is being read as if 12 bytes were coming: "
        "uci_read_resp_bytes spins 65,536 fenced iterations for the first "
        "missing byte, ~7.5 s per probe at 48 MHz and ~6 min at 1 MHz"
        % (worst, fw.probes, fw.reads_per_probe)))


def test_lease_on_index_zero():
    """Control: Ethernet with a lease. One probe, C=0, that address."""
    cpu, mem, fw, labels = _require([LEASE_A, bytes(4)])
    carry = _acquire(cpu, labels)
    base._check(carry is False and _ip(mem, labels) == LEASE_A, (
        "C=%d ip=%s err=$%02X" % (carry, list(_ip(mem, labels)),
                                  _err(mem, labels))))
    base._check(fw.probes == [0], "probed %s, expected [0]" % fw.probes)
    base._check(_err(mem, labels) == 0, "net_last_error not cleared")


def test_lease_on_wifi_index_one():
    """Control: a box on WiFi. Index 0 answers 0.0.0.0, index 1 has it."""
    cpu, mem, fw, labels = _require([bytes(4), LEASE_B])
    carry = _acquire(cpu, labels)
    base._check(carry is False and _ip(mem, labels) == LEASE_B, (
        "C=%d ip=%s err=$%02X" % (carry, list(_ip(mem, labels)),
                                  _err(mem, labels))))
    base._check(fw.probes == [0, 1], "probed %s" % fw.probes)
    base._check(_err(mem, labels) == 0, "net_last_error not cleared")


def test_no_lease_does_not_wait_out_the_empty_probes():
    """Two interfaces, neither leased: probes 2 and 3 are out of range.
    Expected $83, and no probe may spin out a read of an empty reply."""
    cpu, mem, fw, labels = _require([bytes(4), bytes(4)])
    carry = _acquire(cpu, labels)
    base._check(carry is True and _err(mem, labels) == UCI_ERR_NO_IP, (
        "C=%d err=$%02X, expected C=1 $83" % (carry, _err(mem, labels))))
    base._check(fw.probes == [0, 1, 2, 3], "probed %s" % fw.probes)
    base._check(fw.idle and fw.pushes_rejected == 0,
                "interface left %s, %d push(es) rejected"
                % (fw.describe(), fw.pushes_rejected))
    _probe_costs_bounded(fw)


def test_reinit_does_not_return_the_previous_lease():
    """'I' re-init in one PRG run: the first call leases LEASE_A; by the
    second the modelled firmware has no interfaces, so every probe is
    out of range. The second call must not report LEASE_A again."""
    cpu, mem, fw, labels = _require([LEASE_A])
    base._check(_acquire(cpu, labels) is False
                and _ip(mem, labels) == LEASE_A,
                "first acquire did not lease (control)")
    fw.ifaces = []
    fw.probes, fw.reads_per_probe = [], []
    carry = _acquire(cpu, labels)
    base._check(carry is True, (
        "second acquire returned C=0 with ip=%s from %d out-of-range "
        "probes — the previous call's reply, still in uci_ipaddr_resp"
        % (list(_ip(mem, labels)), len(fw.probes))))
    base._check(_err(mem, labels) == UCI_ERR_NO_IP,
                "net_last_error=$%02X, expected $83" % _err(mem, labels))
    _probe_costs_bounded(fw)


def test_uninitialised_buffer_is_not_a_lease():
    """First call, zero interfaces, uci_ipaddr_resp holding whatever RAM
    held (UCI_BSS is not zeroed at boot)."""
    cpu, mem, fw, labels = _require([])
    for i, b in enumerate(b"\xde\xad\xbe\xef" + bytes(8)):
        mem.write(labels["uci_ipaddr_resp"] + i, b)
    carry = _acquire(cpu, labels)
    base._check(carry is True and _err(mem, labels) == UCI_ERR_NO_IP, (
        "C=%d ip=%s err=$%02X: leftover buffer bytes were reported as a "
        "lease" % (carry, list(_ip(mem, labels)), _err(mem, labels))))


def test_short_reply_is_not_a_lease():
    """A reply shorter than the 12-byte record (4 bytes: an IP and nothing
    else) is not GET_IPADDR's answer and must not be taken as a lease."""
    cpu, mem, fw, labels = _require([LEASE_A])   # first fill the buffer
    _acquire(cpu, labels)
    fw.ifaces = [Raw(LEASE_B)]                    # a 4-byte reply
    fw.probes, fw.reads_per_probe = [], []
    carry = _acquire(cpu, labels)
    base._check(carry is True, (
        "a 4-byte reply was accepted as a lease (ip=%s)"
        % list(_ip(mem, labels))))


TESTS = (
    test_lease_on_index_zero,
    test_lease_on_wifi_index_one,
    test_no_lease_does_not_wait_out_the_empty_probes,
    test_reinit_does_not_return_the_previous_lease,
    test_uninitialised_buffer_is_not_a_lease,
    test_short_reply_is_not_a_lease,
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
    return verdict(passed, failed, certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
