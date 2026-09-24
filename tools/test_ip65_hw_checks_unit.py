#!/usr/bin/env python3
"""tools/test_ip65_hw_checks_unit.py — proof that the RR-Net hardware
validation is CAPABLE OF FAILING.

The risk this suite exists to eliminate
=======================================
`tests/rig_ip65_rrnet_hw.py` is the first thing in this project ever to run
the ip65 backend against real CS8900a silicon; every prior ip65 result came
from VICE. The failure to fear is not "the hardware run fails". It is "the
hardware run passes and means nothing" — and this repo has that on record
three times over: `test_x509_name.py` returning 0 on a build it could not
test (#158), a runner list that named two omissions when there were four
(#169), and PR #168 passing the ip65 gate with four substantive defects
(#176). c64-wireguard, whose module this one is adapted from, shipped a
tool cited for two days as "verified byte-for-byte" whose verification
function was defined and never called.

So for every verdict `tools/ip65_hw_checks.py` reaches, this suite feeds it
a KNOWN-BAD input off-device and requires it to fail, and a known-good one
and requires it to pass. No hardware, no VICE, no build, no DeviceLock.
Milliseconds. It runs under bare `pytest` from the repo root and is listed
in pytest.ini's testpaths.

WHAT MAKES THE RED CASES EVIDENCE, NOT DECORATION
=================================================
Several red cases are paired with a NAIVE checker — the plausible
implementation someone would actually have written, in some cases the shape
that is already in this tree — and the case asserts BOTH halves:

    the naive checker PASSES the bad input   (the trap is live: this is
                                              what the hardware run would
                                              have reported as green)
    the real checker FAILS it                (the alarm sounds)

If a naive arm ever stops passing, that assertion goes red and says the
trap is no longer live, rather than quietly leaving a red case that proves
nothing.

test_every_check_has_a_red_case() is the backstop: it enumerates the
module's `check_*` functions by introspection and fails if one of them is
not in the registry below. A verdict with no failing case is not evidence,
and adding one silently is the exact move this file exists to prevent.

Structure over text: verdicts are read from `Verdict.ok`,
`Verdict.status` and `Verdict.evidence`, never by matching
`Verdict.reason`.

Randomised: MACs, payloads and the response body are drawn from a seeded
RNG (C64_TEST_SEED to reproduce), so no check can be satisfied by a fixed
string that happens to be in the test.

Standalone too, for anyone without pytest::

    python3 tools/test_ip65_hw_checks_unit.py
"""
from __future__ import annotations

import os
import random
import string
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import ip65_hw_checks as hw  # noqa: E402

SEED = int(os.environ.get("C64_TEST_SEED", "20260905"))
RNG = random.Random(SEED)

HOST_MAC = bytes.fromhex("c05627b11638")
C64_MAC = hw.RIG_C64_MAC
HOST_IP = hw.RIG_HOST_IP
C64_IP = hw.RIG_C64_IP
PORT = 4433
SNI = "www.foo.invalid"

#: Every `check_*` in the module must appear here, mapped to the test that
#: feeds it a known-bad input. test_every_check_has_a_red_case() enforces it.
RED_CASES = {
    "check_capture_grew": "test_capture_grew_red_green",
    "check_capture_bracket": "test_capture_bracket_red_green",
    "check_c64_originated": "test_c64_originated_red_green",
    "check_mac_on_wire": "test_mac_on_wire_red_green",
    "check_dhcp_lease": "test_dhcp_lease_red_green",
    "check_dns_query_on_wire": "test_dns_query_red_green",
    "check_client_hello_on_wire": "test_client_hello_red_green",
    "check_tls_traffic_both_ways": "test_tls_both_ways_red_green",
    "check_body_not_on_wire": "test_body_not_on_wire_red_green",
    "check_shadow_ram_readable": "test_shadow_ram_red_green",
    "check_tls_connected": "test_tls_connected_red_green",
    "check_http_response": "test_http_response_red_green",
    "check_net_last_error": "test_net_last_error_red_green",
    "check_image_readback": "test_image_readback_red_green",
    "check_ip65_config_written": "test_ip65_config_written_red_green",
}


# ===========================================================================
# Synthetic wire
# ===========================================================================
def _rand_body(n: int) -> bytes:
    return "".join(RNG.choice(string.ascii_uppercase + string.digits)
                   for _ in range(n)).encode()


def _eth(src: bytes, dst: bytes, ethertype: int, payload: bytes) -> bytes:
    return bytes(dst) + bytes(src) + struct.pack(">H", ethertype) + payload


def _ipv4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0, 64, proto, 0)
    return hdr + hw.ip4_bytes(src) + hw.ip4_bytes(dst) + payload


def _tcp(sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    return (struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x18,
                        8192, 0, 0) + payload)


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp_frame(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str,
               sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    return _eth(src_mac, dst_mac, hw.ETHERTYPE_IPV4,
                _ipv4(hw.IPPROTO_TCP, src_ip, dst_ip,
                      _tcp(sport, dport, seq, payload)))


def _udp_frame(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str,
               sport: int, dport: int, payload: bytes) -> bytes:
    return _eth(src_mac, dst_mac, hw.ETHERTYPE_IPV4,
                _ipv4(hw.IPPROTO_UDP, src_ip, dst_ip,
                      _udp(sport, dport, payload)))


def _dns_query(name: str) -> bytes:
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + \
        struct.pack(">HH", 1, 1)


def _client_hello(sni: str) -> bytes:
    """A ClientHello record body with a server_name extension."""
    host = sni.encode()
    sni_ext_data = struct.pack(">H", len(host) + 3) + b"\x00" + \
        struct.pack(">H", len(host)) + host
    ext = struct.pack(">HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    body = (b"\x03\x03" + bytes(RNG.getrandbits(8) for _ in range(32))
            + b"\x00"                          # legacy_session_id
            + struct.pack(">H", 2) + b"\x13\x03"   # cipher_suites
            + b"\x01\x00"                      # compression
            + struct.pack(">H", len(ext)) + ext)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def _tls_record(ctype: int, body: bytes) -> bytes:
    return bytes([ctype]) + b"\x03\x03" + struct.pack(">H", len(body)) + body


def _pcap(frames, *, ts0: float | None = None, snaplen_clip: int = 0,
          linktype: int = 1) -> bytes:
    ts0 = time.time() if ts0 is None else ts0
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144,
                                linktype))
    for i, f in enumerate(frames):
        ts = ts0 + i * 0.01
        incl = len(f) if not snaplen_clip else min(len(f), snaplen_clip)
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), incl, len(f))
        out += f[:incl]
    return bytes(out)


def _good_capture(ts0: float, body: bytes) -> list:
    """A capture of a healthy run: DHCP, DNS, ClientHello, appdata both ways."""
    frames = [
        # DHCP request, broadcast, from the C64
        _udp_frame(C64_MAC, b"\xff" * 6, "0.0.0.0", "255.255.255.255", 68, 67,
                   b"\x01\x01\x06\x00" + bytes(300)),
        # DNS query from the C64, and the Mac's answer
        _udp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1024, 53, _dns_query(SNI)),
        _udp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, 53, 1024, _dns_query(SNI)),
        # ClientHello from the C64
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1000,
                   _tls_record(hw.TLS_CONTENT_HANDSHAKE, _client_hello(SNI))),
        # server flight (opaque to us; content type 22 then 23)
        _tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, 5000,
                   _tls_record(hw.TLS_CONTENT_HANDSHAKE, _rand_body(120))),
        # encrypted GET from the C64
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT,
                   1000 + len(_tls_record(hw.TLS_CONTENT_HANDSHAKE,
                                          _client_hello(SNI))),
                   _tls_record(hw.TLS_CONTENT_APPDATA, _rand_body(64))),
        # encrypted response from the Mac -- the body is NOT in the clear
        _tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025,
                   5000 + len(_tls_record(hw.TLS_CONTENT_HANDSHAKE,
                                          _rand_body(120))),
                   _tls_record(hw.TLS_CONTENT_APPDATA,
                               _rand_body(len(body) + 90))),
    ]
    return hw.parse_pcap(_pcap(frames, ts0=ts0))


# ===========================================================================
# Verdict semantics
# ===========================================================================
def test_verdict_refuses_inconclusive_and_ok() -> None:
    """An inconclusive verdict must never read as a pass.

    The whole three-state design collapses if `ok` can be true while
    `status` says we could not look; that combination is refused at
    construction rather than trusted to callers.
    """
    hw.Verdict(True, "fine")
    hw.Verdict(False, "bad")
    v = hw.Verdict(False, "could not look", status="inconclusive")
    assert v.inconclusive and not v.ok
    for args, kwargs in ((("x",), {"status": "inconclusive"}),
                         ((False, "x"), {"status": "pass"}),
                         ((True, "x"), {"status": "fail"})):
        try:
            hw.Verdict(True, *args, **kwargs) if len(args) == 1 else \
                hw.Verdict(*args, **kwargs)
        except ValueError:
            continue
        raise AssertionError(f"Verdict accepted {args} {kwargs}")


# ===========================================================================
# pcap decoding
# ===========================================================================
def test_pcap_refuses_a_snaplen_clipped_capture() -> None:
    """tcpdump without -s 0 must be refused, not silently searched.

    THE TRAP: a clipped capture parses fine and every frame looks real. A
    plaintext search over it cannot see the end of a record, so an absence
    result is a statement about the snaplen, not about the wire — and the
    person who started the capture is not the person reading the result.
    """
    frames = _good_capture(time.time(), b"X" * 22)
    raw = [f.raw for f in frames]
    clipped = _pcap(raw, snaplen_clip=40)
    try:
        hw.parse_pcap(clipped)
    except hw.PcapError as exc:
        assert "TRUNCATED" in str(exc)
    else:
        raise AssertionError("a snaplen-clipped capture was accepted")
    # ...and the same frames unclipped are fine.
    assert len(hw.parse_pcap(_pcap(raw))) == len(raw)


def test_pcap_refuses_a_non_ethernet_link_type() -> None:
    """No Ethernet header means no source MAC means no discrimination."""
    raw = [f.raw for f in _good_capture(time.time(), b"X" * 22)]
    try:
        hw.parse_pcap(_pcap(raw, linktype=101))       # LINKTYPE_RAW
    except hw.PcapError as exc:
        assert "EN10MB" in str(exc)
    else:
        raise AssertionError("a non-Ethernet capture was accepted")


def test_pcap_keeps_the_ethernet_source_the_in_tree_decoder_drops() -> None:
    """The decoder must keep the field the whole suite discriminates on.

    NAIVE ARM: the pcap decoder this project already has
    (tools/test_ip65_arp_first_send_vice.py's `parse_frame` in the sibling
    repo, and any IP-level decoder) returns IP/UDP fields and drops the
    Ethernet source, so nothing built on it can tell a C64 frame from a Mac
    frame. Shown here as a checker that "identifies the sender" by IP.
    """
    frames = _good_capture(time.time(), b"X" * 22)

    def naive_sender_is_the_c64(fs) -> bool:
        # An IP address is a claim the sender makes about itself.
        return any(f.ip_src == hw.ip4_bytes(C64_IP) for f in fs)

    # Forge: the HOST puts frames on the wire carrying the C64's IP.
    forged = [_tcp_frame(HOST_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1,
                         b"hello")]
    spoofed = hw.parse_pcap(_pcap(forged))
    assert naive_sender_is_the_c64(spoofed), "naive arm no longer fires"
    assert not hw.check_c64_originated(spoofed, C64_MAC, HOST_MAC).ok
    assert hw.check_c64_originated(frames, C64_MAC, HOST_MAC).ok


def test_tcp_stream_dedupes_retransmissions() -> None:
    """A retransmitted segment contributes its bytes ONCE.

    A naive concatenation in capture order doubles them, which turns one
    ClientHello into two records and makes any offset-based reasoning about
    the stream wrong.
    """
    payload = _rand_body(40)
    raw = [_tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 7000,
                      payload)] * 3
    frames = hw.parse_pcap(_pcap(raw))
    naive = b"".join(f.tcp_payload for f in frames)
    assert naive == payload * 3, "naive arm no longer fires"
    assert hw.tcp_stream(frames, eth_src=C64_MAC, dport=PORT) == payload


def test_tcp_streams_are_split_per_connection() -> None:
    """Two connections must not be fused into one sequence space.

    A run that retries — ip65 has no next-hop MAC yet, or the first connect
    is refused — puts a short stub connection on the cable ahead of the real
    one. Keying assembly on the absolute sequence number across both would
    zero-fill the gulf between two unrelated ISNs and destroy the framing of
    each, so a completed handshake would read as "no TLS records".
    """
    ch = _tls_record(hw.TLS_CONTENT_HANDSHAKE, _client_hello(SNI))
    frames = hw.parse_pcap(_pcap([
        # attempt 1: a stub that carried nothing useful, high ISN
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1024, PORT,
                   0xF000_0000, b"\x16\x03"),
        # attempt 2: the real connection, low ISN, a different source port
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1000, ch),
    ]))
    streams = hw.tcp_streams(frames, eth_src=C64_MAC, dport=PORT)
    assert len(streams) == 2, streams
    assert max(len(s) for s in streams) == len(ch)
    # The whole point: the ClientHello is still decodable, and picking the
    # longest connection is what finds it.
    v = hw.check_client_hello_on_wire(frames, C64_MAC, port=PORT,
                                      expect_sni=SNI)
    assert v.ok, v.reason


# ===========================================================================
# The capture is OF this run, and adequate
# ===========================================================================
def test_capture_grew_red_green() -> None:
    """A capture that did not grow is a dead tap, not a clean wire."""
    assert not hw.check_capture_grew(4096, 4096).ok          # tcpdump not running
    assert not hw.check_capture_grew(9000, 4096).ok          # rotated mid-run
    assert not hw.check_capture_grew(None, 4096).ok          # never sampled
    assert not hw.check_capture_grew(4096, None).ok
    v = hw.check_capture_grew(4096, 40960, path="/tmp/x.pcap")
    assert v.ok and v.evidence["grew_by"] == 36864


def test_capture_bracket_red_green() -> None:
    """A stale pcap from an earlier session must not be scored as this run.

    NAIVE ARM: "the file parses and holds frames" — true of a capture taken
    yesterday, including one holding an earlier run's successful handshake.
    """
    now = time.time()
    stale = _good_capture(now - 7200, b"X" * 22)

    def naive_capture_is_usable(fs) -> bool:
        return len(fs) > 0

    assert naive_capture_is_usable(stale), "naive arm no longer fires"
    v = hw.check_capture_bracket(stale, now, now + 60)
    assert not v.ok and v.evidence["diagnosis"] == "no-frame-inside-the-window"

    assert hw.check_capture_bracket([], now, now + 60).evidence["diagnosis"] == "empty"
    assert hw.check_capture_bracket(stale, now + 60, now).evidence["diagnosis"] \
        == "inverted-window"

    fresh = _good_capture(now + 1, b"X" * 22)
    v = hw.check_capture_bracket(stale + fresh, now, now + 60)
    assert v.ok and v.evidence["diagnosis"] == "ok"
    assert v.evidence["before"] == len(stale)
    # ...and too few frames inside is its own diagnosis, not a pass.
    v = hw.check_capture_bracket(stale + fresh, now, now + 60, min_inside=999)
    assert not v.ok and v.evidence["diagnosis"] == "too-few-frames-inside"


def test_frames_in_window_excludes_the_lead_in() -> None:
    now = time.time()
    stale = _good_capture(now - 7200, b"X" * 22)
    fresh = _good_capture(now + 1, b"X" * 22)
    picked = hw.frames_in_window(stale + fresh, now, now + 60)
    assert len(picked) == len(fresh)


# ===========================================================================
# Two-station discrimination
# ===========================================================================
def test_c64_originated_red_green() -> None:
    """A capture of the Mac talking to itself must not pass.

    THE CENTRAL TRAP. With the cartridge unplugged the Mac still ARPs,
    retransmits and (in a real failure) resends its SYN-ACKs, so a capture
    "containing HTTPS traffic" is satisfied with no C64 on the cable at all.

    NAIVE ARM: count frames on the port.
    """
    now = time.time()
    host_only = hw.parse_pcap(_pcap([
        _tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, i * 100,
                   _rand_body(20)) for i in range(1, 6)
    ], ts0=now))

    def naive_traffic_seen(fs, port) -> bool:
        return any(f.dport == port or f.sport == port for f in fs)

    assert naive_traffic_seen(host_only, PORT), "naive arm no longer fires"
    v = hw.check_c64_originated(host_only, C64_MAC, HOST_MAC, tcp_port=PORT)
    assert not v.ok and v.evidence["from_c64"] == 0

    # A third MAC is a hard failure: this is not the segment under test.
    third = bytes.fromhex("aabbccddeeff")
    mixed = hw.parse_pcap(_pcap(
        [f.raw for f in _good_capture(now, b"X" * 22)]
        + [_tcp_frame(third, HOST_MAC, "10.0.66.9", HOST_IP, 1, PORT, 1, b"z")],
        ts0=now))
    v = hw.check_c64_originated(mixed, C64_MAC, HOST_MAC)
    assert not v.ok and v.evidence["from_other"] == 1

    # Same address for both stations: the discrimination would be vacuous.
    assert not hw.check_c64_originated(mixed, C64_MAC, C64_MAC).ok

    good = _good_capture(now, b"X" * 22)
    assert hw.check_c64_originated(good, C64_MAC, HOST_MAC, tcp_port=PORT).ok
    assert not hw.check_c64_originated(good, C64_MAC, HOST_MAC,
                                       tcp_port=PORT, min_frames=99).ok


def test_mac_on_wire_red_green() -> None:
    """The C64's MAC has to be a SOURCE on the cable, not a value we read."""
    good = _good_capture(time.time(), b"X" * 22)
    for bad, why in ((b"\x00" * 6, "never programmed"),
                     (b"\xff" * 6, "broadcast"),
                     (bytes([0x01]) + bytes(5), "multicast source"),
                     (bytes(hw.IP65_DEFAULT_CFG_MAC), "ip65 build-time default")):
        assert not hw.check_mac_on_wire(good, bad, HOST_MAC).ok, why
    # A plausible MAC that never actually appears as a source.
    absent = bytes.fromhex("02deadbeef01")
    v = hw.check_mac_on_wire(good, absent, HOST_MAC)
    assert not v.ok and v.evidence["frames_with_that_source"] == 0
    assert not hw.check_mac_on_wire(good, HOST_MAC, HOST_MAC).ok
    assert hw.check_mac_on_wire(good, C64_MAC, HOST_MAC).ok


# ===========================================================================
# DHCP
# ===========================================================================
def test_dhcp_lease_red_green() -> None:
    """ip65's build-time default must be rejected BY VALUE.

    NAIVE ARM: "the address is non-zero, so DHCP worked". ip65 ships cfg_ip
    as 192.168.1.64 with the zeroed variant commented out, so that test is
    already satisfied with the cable unplugged.
    """
    def naive_dhcp_ok(ip) -> bool:
        return any(ip)

    default = bytes(hw.IP65_DEFAULT_CFG_IP)
    assert naive_dhcp_ok(default), "naive arm no longer fires"
    # ISOLATED: no subnet, no expect_ip, nothing else that could reject it.
    # With those constraints supplied, 192.168.1.64 fails the subnet test
    # anyway, so a checker that had DROPPED the build-time-default rejection
    # would still look right -- mutation-verified: removing that branch
    # survived this case until it was asserted on its own.
    assert not hw.check_dhcp_lease(default).ok
    assert not hw.check_dhcp_lease(default, subnet="10.0.66.0",
                                   host_ip=HOST_IP, expect_ip=C64_IP).ok

    for bad in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff",
                bytes([127, 0, 0, 1]), bytes([224, 0, 0, 1]),
                bytes([169, 254, 3, 4])):
        assert not hw.check_dhcp_lease(bad, subnet="10.0.66.0").ok, bad.hex()
    assert not hw.check_dhcp_lease(None).ok
    assert not hw.check_dhcp_lease(b"\x0a\x00").ok
    # the host's own address, an off-subnet address, and a POOL address
    assert not hw.check_dhcp_lease(hw.ip4_bytes(HOST_IP), host_ip=HOST_IP).ok
    assert not hw.check_dhcp_lease(hw.ip4_bytes("10.0.65.200"),
                                   subnet="10.0.66.0").ok
    v = hw.check_dhcp_lease(hw.ip4_bytes("10.0.66.42"), subnet="10.0.66.0",
                            host_ip=HOST_IP, expect_ip=C64_IP)
    assert not v.ok, "a pool address is a quiet divergence, not a pass"
    assert hw.check_dhcp_lease(hw.ip4_bytes(C64_IP), subnet="10.0.66.0",
                               host_ip=HOST_IP, expect_ip=C64_IP).ok


# ===========================================================================
# The wire: DNS and TLS
# ===========================================================================
def test_dns_query_red_green() -> None:
    """The query has to come from the CARTRIDGE.

    NAIVE ARM: "the capture contains the hostname". The Mac resolves names
    constantly, and on this segment it is the DNS server, so its own
    traffic carries the name in both directions.
    """
    now = time.time()
    host_only = hw.parse_pcap(_pcap([
        _udp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, 53, 1024, _dns_query(SNI)),
    ], ts0=now))

    def naive_name_seen(fs, name) -> bool:
        return any(name.encode() in f.raw for f in fs)

    # One label, because a DNS QNAME length-prefixes each one and the dotted
    # form is never contiguous on the wire -- which is itself a reason a
    # substring search over a capture is a poor way to ask this question.
    assert naive_name_seen(host_only, "invalid"), "naive arm no longer fires"
    assert not hw.check_dns_query_on_wire(host_only, C64_MAC, SNI).ok

    good = _good_capture(now, b"X" * 22)
    assert hw.check_dns_query_on_wire(good, C64_MAC, SNI).ok
    v = hw.check_dns_query_on_wire(good, C64_MAC, "en.wikipedia.org")
    assert not v.ok and v.evidence["names_seen"] == [SNI]


def test_client_hello_red_green() -> None:
    """A ClientHello sent BY THE MAC must not satisfy the C64's assertion.

    NAIVE ARM: search the capture for the TLS record header bytes. Both
    stations speak TLS on this cable, so that matches the server's records
    and (on any laptop) the Mac's own browsing.
    """
    now = time.time()
    ch = _tls_record(hw.TLS_CONTENT_HANDSHAKE, _client_hello(SNI))
    host_only = hw.parse_pcap(_pcap([
        _tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, 1025, PORT, 1, ch)
    ], ts0=now))

    def naive_tls_seen(fs) -> bool:
        return any(b"\x16\x03" in f.raw for f in fs)

    assert naive_tls_seen(host_only), "naive arm no longer fires"
    assert not hw.check_client_hello_on_wire(host_only, C64_MAC, port=PORT).ok

    # Payload from the C64 that is not TLS at all.
    junk = hw.parse_pcap(_pcap([
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1,
                   b"GET / HTTP/1.0\r\n\r\n")], ts0=now))
    assert not hw.check_client_hello_on_wire(junk, C64_MAC, port=PORT).ok

    # A TLS record from the C64 that is not a ClientHello.
    notch = hw.parse_pcap(_pcap([
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1,
                   _tls_record(hw.TLS_CONTENT_APPDATA, _rand_body(30)))], ts0=now))
    assert not hw.check_client_hello_on_wire(notch, C64_MAC, port=PORT).ok

    good = _good_capture(now, b"X" * 22)
    assert not hw.check_client_hello_on_wire(good, C64_MAC, port=PORT + 1).ok
    v = hw.check_client_hello_on_wire(good, C64_MAC, port=PORT, expect_sni=SNI)
    assert v.ok and v.evidence["sni"] == SNI
    assert not hw.check_client_hello_on_wire(good, C64_MAC, port=PORT,
                                             expect_sni="example.com").ok


def test_tls_both_ways_red_green() -> None:
    """One direction of application data is not a completed exchange."""
    now = time.time()
    ch = _tls_record(hw.TLS_CONTENT_HANDSHAKE, _client_hello(SNI))
    c64_only = hw.parse_pcap(_pcap([
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1, ch),
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1 + len(ch),
                   _tls_record(hw.TLS_CONTENT_APPDATA, _rand_body(50))),
    ], ts0=now))
    v = hw.check_tls_traffic_both_ways(c64_only, C64_MAC, HOST_MAC, port=PORT)
    assert not v.ok and v.evidence["host_appdata"] == 0

    host_only = hw.parse_pcap(_pcap([
        _tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, 1,
                   _tls_record(hw.TLS_CONTENT_APPDATA, _rand_body(50))),
    ], ts0=now))
    v = hw.check_tls_traffic_both_ways(host_only, C64_MAC, HOST_MAC, port=PORT)
    assert not v.ok and v.evidence["c64_appdata"] == 0

    good = _good_capture(now, b"X" * 22)
    v = hw.check_tls_traffic_both_ways(good, C64_MAC, HOST_MAC, port=PORT)
    assert v.ok and v.evidence["c64_appdata"] and v.evidence["host_appdata"]


def test_body_not_on_wire_red_green() -> None:
    """Absence is only reported when the search is shown to find things.

    NAIVE ARM: "we grepped the capture and the body was not there". Over an
    empty corpus, a capture of the wrong interface, or a search with a bug,
    that is true and means nothing. The control needle is the SNI hostname,
    which TLS 1.3 leaves in the clear in the same frames.
    """
    now = time.time()
    body = _rand_body(22)
    control = SNI.encode()

    def naive_absent(fs, secret) -> bool:
        return not any(secret in f.raw for f in fs)

    # 1. Empty corpus: naive says clean, we say INCONCLUSIVE (and not ok).
    assert naive_absent([], body), "naive arm no longer fires"
    v = hw.check_body_not_on_wire([], body, control)
    assert not v.ok and v.inconclusive

    # 2. A capture with no control hit: the search is unproven.
    no_control = hw.parse_pcap(_pcap([
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1,
                   _rand_body(60))], ts0=now))
    assert naive_absent(no_control, body), "naive arm no longer fires"
    v = hw.check_body_not_on_wire(no_control, body, control)
    assert not v.ok and v.inconclusive

    # 3. The body IN THE CLEAR: a plain-HTTP regression, or TLS not applied.
    leaky = hw.parse_pcap(_pcap(
        [f.raw for f in _good_capture(now, body)]
        + [_tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, 9000,
                      b"HTTP/1.1 200 OK\r\n\r\n" + body)], ts0=now))
    v = hw.check_body_not_on_wire(leaky, body, control)
    assert not v.ok and v.status == "fail" and v.evidence["secret_hits"] >= 1

    # 4. A body split across TCP segments is still found -- per-frame
    #    searching alone would miss it, stream reassembly catches it. The
    #    pieces are SHORTER than the partial-run floor (#202): with two
    #    11-byte halves the per-frame partial search found each half on its
    #    own, and dropping reassembly entirely went unnoticed (#201).
    step = hw.PARTIAL_RUN_MIN - 1
    split = hw.parse_pcap(_pcap([
        f.raw for f in _good_capture(now, body)] + [
        _tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, 20000 + at,
                   body[at:at + step]) for at in range(0, len(body), step)
    ], ts0=now))
    assert naive_absent(split, body), "naive arm no longer fires"
    v = hw.check_body_not_on_wire(split, body, control)
    assert not v.ok and v.evidence["secret_hits"] >= 1, v.evidence

    # 5. Green: control found, body absent.
    clean = _good_capture(now, body)
    v = hw.check_body_not_on_wire(clean, body, control)
    assert v.ok and v.evidence["control_hits"] >= 1 and v.evidence["secret_hits"] == 0
    # ...and a missing needle or control is a refusal, not a pass.
    assert not hw.check_body_not_on_wire(clean, b"", control).ok
    assert not hw.check_body_not_on_wire(clean, body, b"").ok
    # An empty secret is a CALLER bug, so it is a FAIL even where the corpus
    # is empty -- not the INCONCLUSIVE an empty capture would earn. Without
    # this, the guard was subsumed: b"" is in every corpus, so the leak
    # branch failed the green capture above anyway (#201).
    v = hw.check_body_not_on_wire([], b"", control)
    assert not v.ok and v.status == "fail"

    # 6. A leak in a NON-TCP frame. Reassembly covers TCP only, so the
    #    per-frame search is the one that must find this; every leak above
    #    rides TCP and is found by the streams as well (#201).
    udp_leak = hw.parse_pcap(_pcap(
        [f.raw for f in _good_capture(now, body)]
        + [_udp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1030, 9999,
                      b"\x00" + body + b"\x00")], ts0=now))
    v = hw.check_body_not_on_wire(udp_leak, body, control)
    assert not v.ok and v.status == "fail" and v.evidence["secret_hits"] >= 1


# ===========================================================================
# #202 — the leak search covers what a C64 would actually transmit
# ===========================================================================
def test_body_leak_in_the_petscii_shifted_block_is_found() -> None:
    """The rig's body is UPPERCASE: only the shifted form does work there.

    c64-wireguard's docstring for this form says it "must not be lost when
    that tool moves onto this library", and #202 records that it was.
    NAIVE ARM: the pre-#202 search, a whole-needle `in` over the staged
    ASCII bytes -- it passes a capture carrying the body in the shifted
    block, because none of those bytes equal the ASCII ones.
    """
    now = time.time()
    body = b"TLS13 OK OVER REAL RRNET"            # the rig's RESPONSE_BODY shape
    shifted = bytes(b + 0x80 if 0x41 <= b <= 0x5A else b for b in body)
    frames = hw.parse_pcap(_pcap(
        [f.raw for f in _good_capture(now, body)]
        + [_tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 60000,
                      b"\x17\x03\x03\x00\x20" + shifted)], ts0=now))

    def naive_absent(fs, secret) -> bool:
        return not any(secret in f.raw for f in fs)

    assert naive_absent(frames, body), "naive arm no longer fires"
    v = hw.check_body_not_on_wire(frames, body, SNI.encode())
    assert not v.ok and v.status == "fail", v.reason
    assert v.evidence["secret_hit_forms"] == ["petscii-shifted"], v.evidence


def test_body_leak_in_the_petscii_folded_form_is_found() -> None:
    """A lowercase body leaves a C64 as uppercase bytes; that is still it.

    PETSCII folds a-z onto $41-$5A. NAIVE ARM: search for the staged ASCII.
    """
    now = time.time()
    body = "".join(RNG.choice(string.ascii_lowercase) for _ in range(20)).encode()
    frames = hw.parse_pcap(_pcap(
        [f.raw for f in _good_capture(now, body)]
        + [_tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, 60000,
                      b"HTTP/1.1 200 OK\r\n\r\n" + body.upper())], ts0=now))
    assert not any(body in f.raw for f in frames), "naive arm no longer fires"
    v = hw.check_body_not_on_wire(frames, body, SNI.encode())
    assert not v.ok and v.evidence["secret_hit_forms"] == ["petscii"], v.evidence


def test_body_partial_leak_is_found() -> None:
    """23 of 24 bytes on the wire is a leak, not an absence (#202 item 2).

    NAIVE ARM: the pre-#202 whole-needle test, which reads every
    proper-prefix leak as absent.
    """
    now = time.time()
    body = _rand_body(24)
    control = SNI.encode()

    def with_payload(payload: bytes):
        return hw.parse_pcap(_pcap(
            [f.raw for f in _good_capture(now, body)]
            + [_tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, 70000,
                          b"\x00" + payload + b"\x00")], ts0=now))

    most = with_payload(body[:-1])
    assert not any(body in f.raw for f in most), "naive arm no longer fires"
    v = hw.check_body_not_on_wire(most, body, control)
    assert not v.ok and v.status == "fail", v.reason
    assert v.evidence["partial_longest"] == len(body) - 1, v.evidence

    # The floor, exactly: PARTIAL_RUN_MIN bytes are reported, one fewer are
    # not. \x00 delimiters cannot extend a run of an uppercase body.
    k = hw.PARTIAL_RUN_MIN
    v = hw.check_body_not_on_wire(with_payload(body[5:5 + k]), body, control)
    assert not v.ok and v.evidence["partial_longest"] == k, v.evidence
    v = hw.check_body_not_on_wire(with_payload(body[5:5 + k - 1]), body, control)
    assert v.ok and v.evidence["partial_hits"] == 0, v.reason
    # ...and a caller's own floor is honoured, not the module default.
    v = hw.check_body_not_on_wire(with_payload(body[:-1]), body, control,
                                  partial_min=len(body))
    assert v.ok, v.reason

    # A partial run in the SHIFTED block is still found: the partial search
    # covers every form, not just the staged bytes.
    shifted = hw.petscii_shifted_form(body)
    v = hw.check_body_not_on_wire(with_payload(shifted[:-2]), body, control)
    assert not v.ok and v.evidence["partial_detail"][0]["form"] == \
        "petscii-shifted", v.evidence


def test_body_leak_fails_even_with_no_control_hit() -> None:
    """A FOUND leak is a FAIL, not INCONCLUSIVE, whatever the control did.

    The control exists to prove the searcher can find things; a secret hit
    proves that on its own. Before #202 a capture carrying the body in the
    clear but not the SNI came back INCONCLUSIVE (exit 78) rather than as
    the leak it is -- c64-wireguard reports the leak first for this reason.
    """
    now = time.time()
    body = _rand_body(22)
    leak_only = hw.parse_pcap(_pcap([
        _tcp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, PORT, 1025, 1,
                   b"HTTP/1.1 200 OK\r\n\r\n" + body)], ts0=now))
    v = hw.check_body_not_on_wire(leak_only, body, SNI.encode())
    assert v.evidence["control_hits"] == 0
    assert not v.ok and v.status == "fail", (v.status, v.reason)


def test_petscii_forms_and_longest_run() -> None:
    """The encodings at their boundaries, and the run finder."""
    assert hw.petscii_form(b"`az{19") == b"`AZ{19"      # $60/$7B untouched
    assert hw.petscii_shifted_form(b"@AZ[az9") == b"@\xc1\xda[\xc1\xda9"
    # Forms that coincide are searched once, and named once.
    assert [n for n, _ in hw.secret_forms(b"ABC1")] == ["exact", "petscii-shifted"]
    assert [n for n, _ in hw.secret_forms(b"abc")] == \
        ["exact", "petscii", "petscii-shifted"]
    assert [n for n, _ in hw.secret_forms(b"1234")] == ["exact"]
    assert hw.longest_run(b"xxBCDEyy", b"ABCDEF") == (4, 1)
    assert hw.longest_run(b"nothing", b"ABC") == (0, -1)
    assert hw.longest_run(b"..ABC..", b"ABC") == (3, 0)


# ===========================================================================
# What the C64 says
# ===========================================================================
def test_shadow_ram_red_green() -> None:
    """A DMA read that returned the BASIC ROM is not a read of our BSS.

    NAIVE ARM: "the read came back and it is not all zeros, so the memory
    is there". $A000 under the ROM answers that with ROM bytes all day.
    """
    rom = hw.BASIC_ROM_A000_PREFIX + b"CBMBASIC" + bytes(4)

    def naive_read_ok(data) -> bool:
        return bool(data) and any(data)

    assert naive_read_ok(rom), "naive arm no longer fires"
    assert not hw.check_shadow_ram_readable(rom).ok
    # Each ROM marker asserted ON ITS OWN. A real $A000 read carries both, so
    # a checker that had lost one arm would still reject the realistic input
    # and look correct -- mutation-verified.
    prefix_only = hw.BASIC_ROM_A000_PREFIX + bytes(RNG.getrandbits(8)
                                                   for _ in range(12))
    assert not hw.check_shadow_ram_readable(prefix_only).ok
    signature_only = bytes(4) + hw.BASIC_ROM_SIGNATURE + bytes(4)
    assert not hw.check_shadow_ram_readable(signature_only).ok
    assert not hw.check_shadow_ram_readable(None).ok
    assert not hw.check_shadow_ram_readable(b"\x01\x02\x03").ok      # too short
    assert hw.check_shadow_ram_readable(bytes(RNG.getrandbits(8)
                                              for _ in range(16))).ok
    assert hw.check_shadow_ram_readable(bytes(16)).ok                # zeroed BSS


def test_tls_connected_red_green() -> None:
    """FINISHED is not CONNECTED, and an unread state is not a pass.

    State 6 is the interesting red case: the server's Finished verified but
    the client never reached CONNECTED. The server would report a completed
    handshake in exactly that situation.
    """
    assert not hw.check_tls_connected(None).ok
    v = hw.check_tls_connected(hw.TLS_STATE_FINISHED)
    assert not v.ok and v.evidence["state_name"] == "FINISHED"
    assert not hw.check_tls_connected(hw.TLS_STATE_IDLE).ok
    assert not hw.check_tls_connected(hw.TLS_STATE_ERROR,
                                      hw.TLS_STATE_FINISHED).ok
    assert hw.check_tls_connected(hw.TLS_STATE_CONNECTED).ok


def test_http_response_red_green() -> None:
    """Status, length AND content, out of the C64's own buffer.

    NAIVE ARM: "http_status is 200". A 200 says the header parser ran; it
    says nothing about the body having been decrypted correctly, and
    http_resp_buf holds whatever the previous fetch left there.
    """
    body = _rand_body(22)

    def naive_ok(status) -> bool:
        return status == 200

    stale = _rand_body(22)
    assert naive_ok(200), "naive arm no longer fires"
    assert not hw.check_http_response(200, len(stale), stale, body).ok
    assert not hw.check_http_response(404, len(body), body, body).ok
    assert not hw.check_http_response(200, len(body) - 1, body, body).ok
    assert not hw.check_http_response(None, None, None, body).ok
    assert not hw.check_http_response(200, len(body), body, b"").ok
    # A buffer that merely STARTS with the body is not the body.
    assert not hw.check_http_response(200, len(body) + 3, body + b"XYZ", body).ok
    # SAME LENGTH, right first bytes, wrong content. This is the case that
    # isolates the exact compare: every other red case above has a length
    # mismatch too, so a checker that compared only a prefix would pass them
    # all on the length check alone -- mutation-verified. (The converse
    # holds: with the exact compare in place the length check cannot fail on
    # its own, so it is kept for its message, not for its coverage.)
    near_miss = body[:4] + _rand_body(len(body) - 4)
    assert near_miss != body and len(near_miss) == len(body)
    assert not hw.check_http_response(200, len(body), near_miss, body).ok
    assert hw.check_http_response(200, len(body), body + b"\x00" * 100, body).ok


def test_net_last_error_red_green() -> None:
    """A defined code fails, and an UNDEFINED one fails harder."""
    src = (REPO / "src" / "net" / "ip65" / "ip65_errors.inc").read_text()
    table = hw.net_error_table(src)
    # The header must still define the codes this decode depends on; an empty
    # table would make every value read as "unregistered" and the decode
    # useless in exactly the direction that looks fine.
    assert 0x42 in table and table[0x42] == "NET_ERR_IP65_DHCP", table
    assert not hw.check_net_last_error(0x42, table).ok
    assert not hw.check_net_last_error(0x99, table).ok
    assert not hw.check_net_last_error(None, table).ok
    assert hw.check_net_last_error(0x00, table).ok
    assert hw.net_error_table(None) == {}


def test_image_readback_red_green() -> None:
    """One flipped byte in a 47 kB load must be caught before SYS."""
    img = bytes(RNG.getrandbits(8) for _ in range(4096))
    torn = bytearray(img)
    torn[1234] ^= 0xFF
    v = hw.check_image_readback(img, bytes(torn))
    assert not v.ok and v.evidence["first_difference"] == 1234
    assert not hw.check_image_readback(img, img[:-1]).ok
    assert not hw.check_image_readback(img, None).ok
    assert hw.check_image_readback(img, img).ok


# ===========================================================================
# #202 item 4 — ip65's own config fields
# ===========================================================================
_HEALTHY_CFG = {
    "cfg_ip": hw.ip4_bytes(C64_IP),
    "cfg_netmask": bytes(hw.IP65_DEFAULT_CFG_NETMASK),   # correct on the /24
    "cfg_gateway": hw.ip4_bytes(HOST_IP),
    "cfg_mac": C64_MAC,
}


def _cfg(**over):
    d = dict(_HEALTHY_CFG)
    d.update(over)
    return hw.check_ip65_config_written(d["cfg_ip"], d["cfg_netmask"],
                                        d["cfg_gateway"], d["cfg_mac"])


def test_ip65_config_written_red_green() -> None:
    """Every decisive field still at its build-time constant fails ON ITS OWN.

    NAIVE ARM: "every field is populated". ip65/ip65/config.s ships all four
    non-zero, so a machine that never ran eth_init or DHCP satisfies it.
    """
    defaults = {"cfg_ip": bytes(hw.IP65_DEFAULT_CFG_IP),
                "cfg_netmask": bytes(hw.IP65_DEFAULT_CFG_NETMASK),
                "cfg_gateway": bytes(hw.IP65_DEFAULT_CFG_GATEWAY),
                "cfg_mac": bytes(hw.IP65_DEFAULT_CFG_MAC)}

    def naive_written(d) -> bool:
        return all(any(v) for v in d.values())

    assert naive_written(defaults), "naive arm no longer fires"
    v = _cfg(**defaults)
    assert not v.ok and sorted(v.evidence["still_default"]) == \
        ["cfg_gateway", "cfg_ip", "cfg_mac"], v.evidence

    # Each decisive field, isolated: the other three are healthy.
    for name in ("cfg_ip", "cfg_gateway", "cfg_mac"):
        v = _cfg(**{name: defaults[name]})
        assert not v.ok and v.evidence["still_default"] == [name], (name, v.evidence)
    # The netmask default is ALSO the right answer on this /24: reported,
    # never asserted -- a healthy run must pass with it.
    v = _cfg()
    assert v.ok, v.reason
    assert v.evidence["default_but_not_decisive"] == ["cfg_netmask"]
    assert _cfg(cfg_netmask=bytes([255, 255, 0, 0])).evidence[
        "default_but_not_decisive"] == []

    # Unread, and read at the wrong width, fail -- for every field.
    for name, size in (("cfg_ip", 4), ("cfg_netmask", 4),
                       ("cfg_gateway", 4), ("cfg_mac", 6)):
        v = _cfg(**{name: None})
        assert not v.ok and v.evidence["unread"] == [name], (name, v.evidence)
        v = _cfg(**{name: bytes(range(1, size))})
        assert not v.ok and v.evidence["unread"] == [name], (name, v.evidence)


def _fake_memory(image: dict):
    """read_memory(addr, n) over a sparse {addr: byte} map; unset reads 0."""
    def read(addr, n):
        return bytes(image.get(a, 0) for a in range(addr, addr + n))
    return read


def _vt_image(pointers: dict, values: dict) -> dict:
    mem: dict = {}
    for name, off, _size in hw.IP65_VT_FIELDS:
        ptr = pointers[name]
        mem[hw.IP65_VT_ADDR + off] = ptr & 0xFF
        mem[hw.IP65_VT_ADDR + off + 1] = ptr >> 8
        for i, b in enumerate(values.get(name, b"")):
            mem[ptr + i] = b
    return mem


_BLOB_PTRS = {"cfg_mac": 0x3A84, "cfg_ip": 0x3A8A,
              "cfg_netmask": 0x3A8E, "cfg_gateway": 0x3A92}


def test_read_ip65_config_follows_the_pointer_table() -> None:
    """The fields are read THROUGH the blob's table, and a pointer that
    cannot be ip65's is reported unread rather than followed."""
    fields, ptrs = hw.read_ip65_config(_fake_memory(_vt_image(_BLOB_PTRS,
                                                              _HEALTHY_CFG)))
    assert ptrs == _BLOB_PTRS, ptrs
    assert fields == _HEALTHY_CFG, fields
    assert hw.check_ip65_config_written(fields["cfg_ip"], fields["cfg_netmask"],
                                        fields["cfg_gateway"],
                                        fields["cfg_mac"]).ok

    # No PRG / zeroed RAM: every pointer is $0000, every field unread, and
    # the verdict fails rather than judging zero-page bytes as ip65's.
    fields, ptrs = hw.read_ip65_config(_fake_memory({}))
    assert set(ptrs.values()) == {0} and set(fields.values()) == {None}
    assert not hw.check_ip65_config_written(*(fields[n] for n in (
        "cfg_ip", "cfg_netmask", "cfg_gateway", "cfg_mac"))).ok

    # The range edge: a field must FIT below the end of ip65's space.
    lo, hi = hw.IP65_VT_TARGET_RANGE
    fits = dict(_BLOB_PTRS, cfg_mac=hi - 6)
    fields, _ = hw.read_ip65_config(_fake_memory(_vt_image(fits, _HEALTHY_CFG)))
    assert fields["cfg_mac"] == _HEALTHY_CFG["cfg_mac"]
    overhangs = dict(_BLOB_PTRS, cfg_ip=hi - 3)
    fields, _ = hw.read_ip65_config(_fake_memory(_vt_image(overhangs,
                                                           _HEALTHY_CFG)))
    assert fields["cfg_ip"] is None, "a 4-byte field starting 3 bytes from the end"
    below = dict(_BLOB_PTRS, cfg_gateway=lo - 1)
    fields, _ = hw.read_ip65_config(_fake_memory(_vt_image(below, _HEALTHY_CFG)))
    assert fields["cfg_gateway"] is None

    # A transport that returns short reads the field as unread.
    short = _fake_memory(_vt_image(_BLOB_PTRS, _HEALTHY_CFG))
    fields, _ = hw.read_ip65_config(lambda a, n: short(a, n)[:max(0, n - 1)]
                                    if a != hw.IP65_VT_ADDR else short(a, n))
    assert set(fields.values()) == {None}, fields


def test_ip65_vt_layout_matches_the_blob_sources() -> None:
    """IP65_VT_ADDR and the slot order are READ against the tree, not trusted.

    Two sources: src/net/ip65/ip65_symbols.inc (the equates net.s is built
    against) and ip65-build/ip65_stub.s (the `.word` table the blob is
    linked from). A copy of either here would go stale silently and point
    the read at a neighbouring field.
    """
    import re
    inc = (REPO / "src" / "net" / "ip65" / "ip65_symbols.inc").read_text()
    base = int(re.search(r"^ip65_base\s*=\s*\$([0-9a-fA-F]+)", inc, re.M).group(1), 16)
    vt = int(re.search(r"^ip65_vt\s*=\s*ip65_base\s*\+\s*(\d+)", inc, re.M).group(1))
    assert hw.IP65_BLOB_BASE == base and hw.IP65_VT_ADDR == base + vt
    for name, off, _size in hw.IP65_VT_FIELDS:
        m = re.search(rf"^ip65_vt_{name}\s*=\s*ip65_vt\s*\+\s*(\d+)", inc, re.M)
        assert m and int(m.group(1)) == off, (name, off)
    stub = (REPO / "ip65-build" / "ip65_stub.s").read_text()
    words = re.findall(r"^\.word\s+(\w+)\s*;\s*\+(\d+)", stub, re.M)
    slot = {w: int(o) - vt for w, o in words}
    for name, off, _size in hw.IP65_VT_FIELDS:
        assert slot.get(name) == off, (name, off, slot)


# ===========================================================================
# #201 — defence-in-depth branches, each reached ON ITS OWN
# ===========================================================================
def test_pcap_decoder_refusals_isolated() -> None:
    """Short, non-pcap and absurd-length inputs raise PcapError, and a
    half-written trailing record is skipped rather than decoded."""
    for bad, why in ((b"\xd4\xc3\xb2\xa1" + bytes(10), "short"),
                     (b"PK\x03\x04" + bytes(40), "not a pcap"),
                     (b"\x0a\x0d\x0d\x0a" + bytes(40), "pcapng")):
        try:
            hw.parse_pcap(bad)
        except hw.PcapError:
            continue
        raise AssertionError(f"parse_pcap accepted {why}")
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    try:
        hw.parse_pcap(header + struct.pack("<IIII", 0, 0, 300000, 300000))
    except hw.PcapError:
        pass
    else:
        raise AssertionError("a 300 kB record claim was accepted")
    raw = [f.raw for f in _good_capture(time.time(), b"X" * 22)]
    whole = _pcap(raw)
    torn = whole + struct.pack("<IIII", 0, 0, len(raw[3]), len(raw[3])) \
        + raw[3][:40]
    assert len(hw.parse_pcap(torn)) == len(raw)


def test_tcp_stream_keeps_the_longest_copy_of_a_segment() -> None:
    """A retransmission that carries MORE than the first copy wins."""
    payload = _rand_body(40)
    frames = hw.parse_pcap(_pcap([
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 7000,
                   payload[:10]),
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 7000, payload),
    ]))
    assert hw.tcp_stream(frames, eth_src=C64_MAC, dport=PORT) == payload


def test_tls_records_need_a_tls_version() -> None:
    """A record header with a non-3.x version is not a record."""
    ch = _client_hello(SNI)
    assert hw.parse_tls_records(b"\x16\x03\x03" + struct.pack(">H", len(ch)) + ch)
    assert hw.parse_tls_records(b"\x16\x00\x00" + struct.pack(">H", len(ch)) + ch) == []


def test_c64_originated_branches_isolated() -> None:
    now = time.time()
    good = _good_capture(now, b"X" * 22)
    c64_only = [f for f in good if bytes(f.eth_src) == C64_MAC]
    # c64_mac == host_mac on a capture with no third station: only the
    # same-address guard can reject it.
    assert not hw.check_c64_originated(c64_only, C64_MAC, C64_MAC).ok
    # The C64 spoke -- DHCP and TCP -- but never on the port under test.
    off_port = hw.parse_pcap(_pcap([
        _udp_frame(C64_MAC, b"\xff" * 6, "0.0.0.0", "255.255.255.255", 68, 67,
                   bytes(300)),
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, 80, 1, b"x"),
    ], ts0=now))
    v = hw.check_c64_originated(off_port, C64_MAC, HOST_MAC, tcp_port=PORT)
    assert not v.ok and v.evidence["from_c64_on_port"] == 0


def test_mac_on_wire_value_rejections_isolated() -> None:
    """Each bad MAC is ALSO an Ethernet source in the capture, so the value
    rejection is the only thing that can fail it. Before #201 none of them
    was, and the frame count rejected them all."""
    now = time.time()
    good = [f.raw for f in _good_capture(now, b"X" * 22)]
    for bad, why in ((b"\x00" * 6, "never programmed"),
                     (b"\xff" * 6, "broadcast"),
                     (bytes([0x01, 0, 0x5E, 0, 0, 1]), "multicast"),
                     (bytes(hw.IP65_DEFAULT_CFG_MAC), "ip65 build-time default")):
        frames = hw.parse_pcap(_pcap(good + [
            _tcp_frame(bad, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1, b"y")],
            ts0=now))
        v = hw.check_mac_on_wire(frames, bad, HOST_MAC)
        assert not v.ok and "frames_with_that_source" not in v.evidence, why
    # Not six bytes: with min_frames=0 nothing else can reject it.
    assert not hw.check_mac_on_wire([], C64_MAC[:5], HOST_MAC, min_frames=0).ok
    assert hw.check_mac_on_wire([], C64_MAC, HOST_MAC, min_frames=0).ok
    # Unread fails closed rather than raising.
    v = hw.check_mac_on_wire(hw.parse_pcap(_pcap(good, ts0=now)), None, HOST_MAC)
    assert not v.ok and v.evidence["c64_mac"] is None


def test_dhcp_lease_value_rejections_isolated() -> None:
    """Each reserved address fails with NO subnet/host/expect constraint;
    the pre-#201 cases all passed subnet=, which rejected them anyway."""
    for bad in (b"\x00\x00\x00\x00", bytes([127, 0, 0, 1]), bytes([224, 0, 0, 1]),
                b"\xff\xff\xff\xff", bytes([169, 254, 3, 4])):
        assert not hw.check_dhcp_lease(bad).ok, bad.hex()
    assert hw.check_dhcp_lease(bytes([169, 253, 3, 4])).ok
    assert hw.check_dhcp_lease(bytes([223, 1, 2, 3])).ok


def test_dns_query_branches_isolated() -> None:
    now = time.time()
    # The Mac querying port 53 itself: only the Ethernet-source filter
    # rejects it (the old red case was a RESPONSE, rejected by the port).
    mac_asks = hw.parse_pcap(_pcap([
        _udp_frame(HOST_MAC, C64_MAC, HOST_IP, C64_IP, 1024, 53, _dns_query(SNI))],
        ts0=now))
    assert not hw.check_dns_query_on_wire(mac_asks, C64_MAC, SNI).ok
    # The C64 asking on mDNS is not the C64 asking this segment's resolver.
    mdns = hw.parse_pcap(_pcap([
        _udp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 5353, 5353, _dns_query(SNI))],
        ts0=now))
    assert not hw.check_dns_query_on_wire(mdns, C64_MAC, SNI).ok
    # A longer name that CONTAINS the wanted one is a different name.
    longer = hw.parse_pcap(_pcap([
        _udp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1024, 53,
                   _dns_query(SNI + ".example"))], ts0=now))
    v = hw.check_dns_query_on_wire(longer, C64_MAC, SNI)
    assert not v.ok and v.evidence["names_seen"] == [SNI + ".example"]


def test_client_hello_branches_isolated() -> None:
    now = time.time()
    # Content type 23 whose first body byte happens to be 1: only the
    # content-type test rejects it (the old red case's first byte was a
    # random letter, which the ClientHello-type test rejected anyway).
    looks_like_ch = hw.parse_pcap(_pcap([
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1,
                   _tls_record(hw.TLS_CONTENT_APPDATA, _client_hello(SNI)))],
        ts0=now))
    assert not hw.check_client_hello_on_wire(looks_like_ch, C64_MAC, port=PORT).ok
    # A handshake record that is not a ClientHello (ServerHello, type 2).
    sh = b"\x02" + _client_hello(SNI)[1:]
    not_ch = hw.parse_pcap(_pcap([
        _tcp_frame(C64_MAC, HOST_MAC, C64_IP, HOST_IP, 1025, PORT, 1,
                   _tls_record(hw.TLS_CONTENT_HANDSHAKE, sh))], ts0=now))
    assert not hw.check_client_hello_on_wire(not_ch, C64_MAC, port=PORT).ok


def test_http_response_guards_isolated() -> None:
    """The vacuous and unread guards, each reached without a length mismatch."""
    body = _rand_body(22)
    # Nothing expected and nothing recorded: only the vacuity guard rejects.
    assert not hw.check_http_response(200, 0, b"", b"").ok
    # Status and length read, buffer not: must be a FAIL verdict, not a raise.
    assert not hw.check_http_response(200, len(body), None, body).ok


def test_net_last_error_names_a_defined_code() -> None:
    """A defined code is DECODED, not just failed: the name is the point."""
    src = (REPO / "src" / "net" / "ip65" / "ip65_errors.inc").read_text()
    table = hw.net_error_table(src)
    v = hw.check_net_last_error(0x42, table)
    assert not v.ok and v.evidence.get("name") == "NET_ERR_IP65_DHCP", v.evidence
    assert "name" not in hw.check_net_last_error(0x99, table).evidence


# ===========================================================================
# Build-derived inputs
# ===========================================================================
def test_resolve_symbols_red_green() -> None:
    """A missing symbol is a hard failure, not a skipped diagnostic."""
    labels = {"http_status": 0xAB28, "net_local_ip": 0xB9B5}
    v = hw.resolve_symbols(labels, ("http_status", "tls_state"))
    assert not v.ok and v.evidence["missing"] == ["tls_state"]
    assert not hw.resolve_symbols(labels, ()).ok
    v = hw.resolve_symbols(labels, ("http_status", "net_local_ip"))
    assert v.ok and v.evidence["found"]["http_status"] == "$AB28"


def test_the_build_exports_every_symbol_the_rig_reads() -> None:
    """This build's labels.txt carries the whole diagnostic set.

    NO SILENT SKIP. This used to `return` when `build/labels.txt` was
    absent, printing PASS while verifying nothing — the exact shape
    CLAUDE.md flags on `test_x509_name.py` and that #158/#165 spent real
    effort removing. An absent build is a state where this check DID NOT
    RUN, and the two must not look alike.

    So: absent labels.txt is a FAILURE by default, opt-out-able with
    `C64_ALLOW_NO_BUILD=1` for a lane that knowingly has no build — and
    even then it says so loudly rather than passing quietly. The
    exemplars are `test_x509.py` (missing labels counted as failures) and
    `test_finished_verify.py` (missing label = FATAL).
    """
    labels_path = REPO / "build" / "labels.txt"
    if not labels_path.exists():
        msg = (f"{labels_path} is absent, so this check verified NOTHING about "
               "whether the build exports the symbols the hardware rig reads. "
               "Build first (`make BACKEND=ip65 USE_NISTCURVES_ONCHIP=1`), or "
               "set C64_ALLOW_NO_BUILD=1 to accept an unverified run.")
        if os.environ.get("C64_ALLOW_NO_BUILD") == "1":
            print(f"\n!! EXPLICIT SKIP (C64_ALLOW_NO_BUILD=1): {msg}")
            return
        raise AssertionError(msg)
    labels = {}
    for line in labels_path.read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "al" and parts[2].startswith("."):
            labels[parts[2][1:]] = int(parts[1].split(":")[-1], 16)
    v = hw.resolve_symbols(labels, hw.DIAG_SYMBOLS)
    assert v.ok, v.reason


def test_rig_const_reads_the_script_and_refuses_a_missing_name() -> None:
    """The segment's addressing is READ from the rig script, never copied.

    c64-wireguard moved this segment from 10.0.65/24 to 10.0.66/24 mid-write;
    a suite carrying its own copy would have preflighted a subnet nobody
    serves and sent someone to debug a cable.
    """
    script = REPO / "tools" / "rig-up-rrnet-macos.sh"
    assert hw.rig_const("HOST_IP", script) == hw.RIG_HOST_IP
    assert hw.rig_const("C64_IP", script) == hw.RIG_C64_IP
    assert hw.parse_mac(hw.rig_const("C64_MAC", script)) == hw.RIG_C64_MAC
    assert hw.rig_const("TEST_HOST", script)
    try:
        hw.rig_const("NO_SUCH_CONSTANT", script)
    except KeyError:
        return
    raise AssertionError("rig_const invented a value for a name the script "
                         "does not define")


def test_provenance_flags_a_modified_input() -> None:
    """A run over a dirty worktree is not a run of the commit it names."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        run = lambda *a: subprocess.run(("git", "-C", str(root)) + a,  # noqa: E731
                                        capture_output=True, env=env)
        run("init", "-q")
        (root / "checker.py").write_text("original\n")
        run("add", "-A")
        # --no-verify: this developer's git installs a global pre-commit hook
        # (core.hooksPath) that rejects a foreign author email, and it would
        # otherwise leave this throwaway repo with no HEAD -- the assertion
        # below would then fail for a reason that has nothing to do with
        # provenance.
        run("commit", "-qm", "x", "--no-verify")
        prov = hw.provenance([root / "checker.py"], repo=root)
        assert prov["commit"] and prov["dirty"] is False
        assert prov["loaded_modified"] == []
        assert any("CLEAN" in line for line in hw.format_provenance(prov))

        (root / "checker.py").write_text("edited by another lane\n")
        prov = hw.provenance([root / "checker.py"], repo=root)
        assert prov["dirty"] is True
        assert prov["loaded_modified"] == ["checker.py"]
        assert any("is NOT of" in line for line in hw.format_provenance(prov))


# ===========================================================================
# The backstop
# ===========================================================================
def test_every_check_has_a_red_case() -> None:
    """No verdict may exist without a test that feeds it a known-bad input.

    Introspection, not a hand-maintained list of names in prose: adding a
    `check_*` to the module and forgetting to prove it can fail is the exact
    move that produces a green hardware run nobody can rely on, and it fails
    here rather than passing quietly on the bench.
    """
    module_checks = {n for n in dir(hw)
                     if n.startswith("check_") and callable(getattr(hw, n))}
    missing = sorted(module_checks - set(RED_CASES))
    assert not missing, (
        f"{missing} have no entry in RED_CASES -- every verdict needs a test "
        "that shows it failing on a known-bad input")
    stale = sorted(set(RED_CASES) - module_checks)
    assert not stale, f"RED_CASES names checks that no longer exist: {stale}"
    for check, testname in RED_CASES.items():
        assert testname in globals(), f"{check} points at missing test {testname}"


def main() -> int:
    print(f"seed {SEED} (reproduce with C64_TEST_SEED={SEED})")
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
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
