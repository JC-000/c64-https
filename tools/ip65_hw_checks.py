#!/usr/bin/env python3
"""tools/ip65_hw_checks.py — the ASSERTIONS for the ip65/RR-Net HARDWARE run.

Why this is a separate module
=============================
Every ip65/RR-Net result this project has ever recorded came out of an
emulator: `tests/rig_vice_https_macos.py` drives the ip65 PRG inside a
pcap-patched VICE against a feth pair. `c64-https-ip65-onchip.prg` is a
SHIPPED product, so the first run against real CS8900a silicon is the one
result nobody has a baseline for — and therefore the one nobody re-reads
if it comes back green.

This repo's documented failure mode is exactly that: suites that pass for
the wrong reason (#158, #161, #176 — `test_x509_name.py` returning 0 on a
build it could not test; a runner list that named two omissions when there
were four). c64-wireguard's `tools/ip65_hw_checks.py`, which this module is
adapted from, was written after a tool of theirs was cited for two days as
"verified byte-for-byte" whose verification function was defined and never
called, and whose main() returned 0 unconditionally.

So the verdicts live here, as pure functions over bytes, and
`tools/test_ip65_hw_checks_unit.py` feeds each one a KNOWN-BAD input
off-device and requires it to fail. The hardware rig
(`tests/rig_ip65_rrnet_hw.py`) supplies the pcap and the DMA reads; it
decides nothing.

Every function returns a `Verdict`. `ok` is the verdict, `reason` is for
humans, `evidence` is the structured record the caller logs. Callers branch
on `ok`, never on `reason`.

THE TOPOLOGY THIS IS WRITTEN FOR
================================
    [ RR-Net (CS8900a) in the U64E's cartridge port ]
                   |
                   |  cable, no switch
                   |
    [ Mac en4, USB-C LAN, 10.0.66.1 ]

There are exactly TWO stations on that segment and the Mac is one of them.
"The capture contains HTTPS traffic" therefore proves nothing about the
C64: the Mac's own outbound frames satisfy it in full, and so would a
capture taken with the cartridge unplugged, or a capture of the wrong
interface. Every wire assertion here discriminates BY ETHERNET SOURCE
ADDRESS, and a frame from a third MAC is a hard failure rather than an
ignorable oddity — on a two-station cable it means the capture is not of
the segment we think it is.

The capture itself is started BY HAND (sudo prompts on this bench), so its
adequacy is asserted rather than assumed: `parse_pcap` refuses a
snaplen-clipped file, `check_capture_grew` refuses one that did not grow
across the run, `check_capture_bracket` refuses one whose frames all
predate the run, and `check_c64_originated` refuses one holding no frame
from the cartridge at all. Those four are the shapes that turn a useless
file into a confident green.

TRAPS ALREADY IN THIS TREE, AND IN ip65
=======================================
* `ip65/ip65/config.s` initialises `cfg_ip` to 192.168.1.64, NOT to zeros
  (the zeroed line under it is commented out), and `cfg_mac` to
  00:80:10:00:51:00. "We got a lease" can never be "the address is
  non-zero" — that is true before DHCP runs at all. Our adapter only
  copies `cfg_ip` into `net_local_ip` on a C=0 return
  (`src/net/ip65/net.s` `net_dhcp_acquire`), which narrows it but does not
  close it, so `check_dhcp_lease` rejects the shipped default BY VALUE.
* Everything interesting on the C64 side lives in `CRYPTO_COLD_SHADOW`
  ($A000-$BFFF), which is RAM *under the BASIC ROM*. A host DMA read of
  that span follows the machine's banking and returns ROM bytes unless
  BASIC is banked out. Our `boot.s` keeps $01 bit 0 clear for all runtime
  operation, so the reads work — but "the read returned something" is not
  evidence that it returned RAM, and a body check against ROM bytes fails
  for a reason that has nothing to do with TLS. `check_shadow_ram_readable`
  is the discriminator; run it before believing any $A000+ read.
"""
from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

# ---------------------------------------------------------------------------
# ip65 build-time defaults. Here so a check can REJECT them: reading one of
# these back means the code that was supposed to overwrite it never ran.
# ip65/ip65/config.s.
# ---------------------------------------------------------------------------
IP65_DEFAULT_CFG_IP = (192, 168, 1, 64)
IP65_DEFAULT_CFG_NETMASK = (255, 255, 255, 0)
IP65_DEFAULT_CFG_GATEWAY = (192, 168, 1, 1)
IP65_DEFAULT_CFG_MAC = (0x00, 0x80, 0x10, 0x00, 0x51, 0x00)

# ---------------------------------------------------------------------------
# The segment. 10.0.66.0/24 and deliberately NOT 10.0.65.0/24: the VICE feth
# rig (tools/rig-up-macos.sh) owns 10.0.65.1 and both rigs must be able to run
# at once, because comparing real silicon against the emulated pair is the
# point. These are DEFAULTS for the unit test's convenience; the rig reads the
# live values out of tools/rig-up-rrnet-macos.sh so the two cannot drift (see
# rig_const()).
# ---------------------------------------------------------------------------
RIG_HOST_IP = "10.0.66.1"
RIG_C64_IP = "10.0.66.200"
RIG_C64_MAC = bytes.fromhex("000e3a646464")     # ip65's built-in cs8900a MAC

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

TLS_CONTENT_CCS = 0x14
TLS_CONTENT_ALERT = 0x15
TLS_CONTENT_HANDSHAKE = 0x16
TLS_CONTENT_APPDATA = 0x17
TLS_HS_CLIENT_HELLO = 0x01

#: The first bytes of the C64's BASIC ROM at $A000, and the signature four
#: bytes in. A DMA read of CRYPTO_COLD_SHADOW that returns these is reading
#: ROM, not our BSS.
BASIC_ROM_A000_PREFIX = bytes.fromhex("94e37be3")
BASIC_ROM_SIGNATURE = b"CBMBASIC"

#: src/constants.inc TLS_STATE_*.
TLS_STATE_IDLE = 0
TLS_STATE_FINISHED = 6
TLS_STATE_CONNECTED = 7
TLS_STATE_ERROR = 0xFF
TLS_STATE_NAMES = {
    0: "IDLE", 1: "CLIENT_HELLO", 2: "SERVER_HELLO", 3: "ENCRYPTED_EXT",
    4: "CERTIFICATE", 5: "CERT_VERIFY", 6: "FINISHED", 7: "CONNECTED",
    0xFF: "ERROR",
}


class PcapError(ValueError):
    """The capture is not something we can decide anything from."""


# ===========================================================================
# Verdicts
# ===========================================================================
@dataclass
class Verdict:
    """A verdict with THREE states, not two.

    "we looked and it was clean" and "we could not look" are different
    facts, and collapsing them is how an absence claim gets made about an
    empty corpus. `status` is "pass", "fail" or "inconclusive"; `ok` is true
    only for "pass", so an inconclusive verdict FAILS CLOSED for any caller
    that branches on `ok` alone, while a caller that wants to distinguish
    them reads `status`. Inconclusive-and-ok is refused at construction.
    """
    ok: bool
    reason: str
    evidence: dict = field(default_factory=dict)
    status: str = ""

    def __post_init__(self) -> None:
        if not self.status:
            self.status = "pass" if self.ok else "fail"
        if self.status not in ("pass", "fail", "inconclusive"):
            raise ValueError(f"unknown verdict status {self.status!r}")
        if self.status != "pass" and self.ok:
            raise ValueError("a verdict that is not a pass must not read as ok")
        if self.status == "pass" and not self.ok:
            raise ValueError("a passing verdict must read as ok")

    @property
    def inconclusive(self) -> bool:
        return self.status == "inconclusive"

    def __bool__(self) -> bool:          # pragma: no cover - convenience
        return self.ok


def fmt_mac(mac) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def fmt_ip(ip) -> str:
    return ".".join(str(b) for b in ip)


def ip4_bytes(text: str) -> bytes:
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError(f"not a dotted quad: {text!r}")
    return bytes(int(p) for p in parts)


def parse_mac(text: str) -> bytes:
    raw = text.replace(":", "").replace("-", "")
    if len(raw) != 12:
        raise ValueError(f"not a MAC address: {text!r}")
    return bytes.fromhex(raw)


# ===========================================================================
# pcap decoding — KEEPS the Ethernet header
# ===========================================================================
@dataclass
class Frame:
    index: int
    ts: float
    eth_src: bytes
    eth_dst: bytes
    ethertype: int
    raw: bytes                       # whole captured frame, Ethernet header included
    ip_src: bytes | None = None
    ip_dst: bytes | None = None
    ip_proto: int | None = None
    ip_payload: bytes = b""
    sport: int | None = None
    dport: int | None = None
    udp_payload: bytes = b""
    tcp_seq: int | None = None
    tcp_flags: int | None = None
    tcp_payload: bytes = b""
    arp_op: int | None = None
    arp_sender_mac: bytes | None = None
    arp_sender_ip: bytes | None = None
    arp_target_ip: bytes | None = None


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def parse_pcap(data: bytes, *, strict: bool = True) -> list[Frame]:
    """Decode a classic pcap (link type EN10MB) into Frames.

    KEEPS the Ethernet header, and returns ARP and other ethertypes rather
    than dropping them: the source MAC is the only thing that tells a C64
    frame from a Mac frame, and DHCP/ARP/DNS are how the lease and the
    cartridge's own address show up on the wire at all.

    A truncated trailing record (tcpdump mid-write) is skipped, not
    mis-parsed. Anything else wrong raises PcapError when `strict` — a
    capture we cannot decode must never read as "we looked and it was
    clean". A snaplen-clipped capture (tcpdump without `-s 0`) is refused
    for the same reason: a search over clipped frames cannot see the end of
    a record, and the person who started the capture is not the person
    reading the result.
    """
    if len(data) < 24:
        raise PcapError(f"capture is {len(data)} bytes, shorter than a pcap header")
    magic = data[:4]
    if magic not in _PCAP_MAGICS:
        raise PcapError(f"not a pcap file (magic {magic.hex()}); pcapng is not supported")
    endian, ts_div = _PCAP_MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1 and strict:
        raise PcapError(f"link type {linktype} is not EN10MB(1); there is no "
                        "Ethernet header to read a MAC from")
    frames: list[Frame] = []
    off, idx = 24, 0
    while off + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > 262144:
            raise PcapError(f"record {idx} claims {incl} captured bytes")
        if off + incl > len(data):
            break                                    # still being written
        raw = data[off:off + incl]
        off += incl
        if incl < orig and strict:
            raise PcapError(
                f"record {idx} is TRUNCATED ({incl} of {orig} bytes on the "
                "wire) -- tcpdump was run without `-s 0`; a search over a "
                "snaplen-clipped capture cannot see the end of a record")
        f = _decode_frame(idx, sec + frac / ts_div, raw)
        idx += 1
        if f is not None:
            frames.append(f)
    return frames


def _decode_frame(index: int, ts: float, raw: bytes) -> Frame | None:
    if len(raw) < 14:
        return None
    dst, src = raw[0:6], raw[6:12]
    etype = struct.unpack(">H", raw[12:14])[0]
    body = raw[14:]
    if etype == 0x8100 and len(body) >= 4:           # 802.1Q; unwrap one tag
        etype = struct.unpack(">H", body[2:4])[0]
        body = body[4:]
    f = Frame(index=index, ts=ts, eth_src=src, eth_dst=dst, ethertype=etype, raw=raw)
    if etype == ETHERTYPE_ARP:
        _decode_arp(f)
        return f
    if etype != ETHERTYPE_IPV4 or len(body) < 20:
        return f
    ihl = (body[0] & 0x0F) * 4
    if ihl < 20 or len(body) < ihl:
        return f
    total = struct.unpack(">H", body[2:4])[0]
    # Trust the IP total-length field over the captured length: Ethernet pads
    # short frames to 60 bytes and that padding is NOT content. A search that
    # included it would report bytes no sender chose.
    if 20 <= total <= len(body):
        body = body[:total]
    f.ip_proto = body[9]
    f.ip_src, f.ip_dst = body[12:16], body[16:20]
    f.ip_payload = body[ihl:]
    if f.ip_proto == IPPROTO_UDP and len(f.ip_payload) >= 8:
        sport, dport, ulen = struct.unpack(">HHH", f.ip_payload[0:6])
        f.sport, f.dport = sport, dport
        f.udp_payload = f.ip_payload[8:8 + max(0, ulen - 8)]
    elif f.ip_proto == IPPROTO_TCP and len(f.ip_payload) >= 20:
        sport, dport, seq = struct.unpack(">HHI", f.ip_payload[0:8])
        doff = (f.ip_payload[12] >> 4) * 4
        f.sport, f.dport, f.tcp_seq = sport, dport, seq
        f.tcp_flags = f.ip_payload[13]
        if doff >= 20 and len(f.ip_payload) >= doff:
            f.tcp_payload = f.ip_payload[doff:]
    return f


def _decode_arp(f: Frame) -> None:
    body = f.raw[14:]
    if len(body) < 28:
        return
    htype, ptype, hlen, plen, op = struct.unpack(">HHBBH", body[0:8])
    if (htype, ptype, hlen, plen) != (1, ETHERTYPE_IPV4, 6, 4):
        return
    f.arp_op = op
    f.arp_sender_mac = body[8:14]
    f.arp_sender_ip = body[14:18]
    f.arp_target_ip = body[24:28]


# ===========================================================================
# TCP stream reassembly and TLS record framing
# ===========================================================================
def tcp_stream(frames: Sequence[Frame], *, eth_src: bytes | None = None,
               dport: int | None = None, sport: int | None = None) -> bytes:
    """The bytes one station put into a TCP connection, in sequence order.

    Keyed on the TCP sequence number rather than capture order, so a
    retransmission contributes its bytes ONCE and an out-of-order capture
    still assembles. Frames are selected by Ethernet source, never by IP: an
    IP address is a claim the sender makes about itself, an Ethernet source
    address on a two-station cable is a fact about which box put the frame
    on the wire.
    """
    pieces: dict[int, bytes] = {}
    for f in frames:
        if f.ip_proto != IPPROTO_TCP or not f.tcp_payload or f.tcp_seq is None:
            continue
        if eth_src is not None and bytes(f.eth_src) != bytes(eth_src):
            continue
        if dport is not None and f.dport != dport:
            continue
        if sport is not None and f.sport != sport:
            continue
        prev = pieces.get(f.tcp_seq)
        if prev is None or len(f.tcp_payload) > len(prev):
            pieces[f.tcp_seq] = f.tcp_payload
    if not pieces:
        return b""
    out = bytearray()
    base = min(pieces)
    for seq in sorted(pieces):
        off = seq - base
        if off > len(out):
            out.extend(b"\x00" * (off - len(out)))
        out[off:off + len(pieces[seq])] = pieces[seq]
    return bytes(out)


@dataclass
class TlsRecord:
    content_type: int
    version: int
    length: int
    body: bytes
    offset: int


def parse_tls_records(stream: bytes) -> list[TlsRecord]:
    """TLS records out of one direction of a TCP stream.

    Stops at the first header that cannot be a record rather than
    resynchronising: a stream we have lost framing on must not go on
    producing plausible-looking records.
    """
    out: list[TlsRecord] = []
    off = 0
    while off + 5 <= len(stream):
        ctype = stream[off]
        version = struct.unpack(">H", stream[off + 1:off + 3])[0]
        length = struct.unpack(">H", stream[off + 3:off + 5])[0]
        if ctype not in (TLS_CONTENT_CCS, TLS_CONTENT_ALERT,
                         TLS_CONTENT_HANDSHAKE, TLS_CONTENT_APPDATA):
            break
        if version >> 8 != 0x03 or length > 0x4000 + 256:
            break
        body = stream[off + 5:off + 5 + length]
        out.append(TlsRecord(ctype, version, length, body, off))
        off += 5 + length
        if len(body) < length:
            break                        # truncated tail; recorded, then stop
    return out


def client_hello_sni(record_body: bytes) -> str | None:
    """The server_name a ClientHello carries, or None.

    TLS 1.3 leaves SNI in the clear, which makes it the one field of the
    handshake readable off the wire without keys — and therefore the
    positive control for the plaintext search (see check_body_not_on_wire).
    """
    b = record_body
    if len(b) < 4 or b[0] != TLS_HS_CLIENT_HELLO:
        return None
    hs_len = int.from_bytes(b[1:4], "big")
    body = b[4:4 + hs_len]
    off = 2 + 32                                     # version + random
    if len(body) < off + 1:
        return None
    off += 1 + body[off]                             # legacy_session_id
    if len(body) < off + 2:
        return None
    off += 2 + int.from_bytes(body[off:off + 2], "big")        # cipher_suites
    if len(body) < off + 1:
        return None
    off += 1 + body[off]                             # compression methods
    if len(body) < off + 2:
        return None
    ext_len = int.from_bytes(body[off:off + 2], "big")
    off += 2
    end = min(len(body), off + ext_len)
    while off + 4 <= end:
        etype = int.from_bytes(body[off:off + 2], "big")
        elen = int.from_bytes(body[off + 2:off + 4], "big")
        edata = body[off + 4:off + 4 + elen]
        off += 4 + elen
        if etype != 0x0000 or len(edata) < 5:        # server_name
            continue
        nlen = int.from_bytes(edata[3:5], "big")
        name = edata[5:5 + nlen]
        try:
            return name.decode("ascii")
        except UnicodeDecodeError:
            return None
    return None


def dns_question_names(payload: bytes) -> list[str]:
    """QNAMEs from a DNS message. Compression pointers are not followed."""
    if len(payload) < 12:
        return []
    qdcount = int.from_bytes(payload[4:6], "big")
    off, names = 12, []
    for _ in range(min(qdcount, 8)):
        labels = []
        while off < len(payload):
            n = payload[off]
            if n == 0:
                off += 1
                break
            if n & 0xC0:                              # pointer: stop, no follow
                off += 2
                break
            labels.append(payload[off + 1:off + 1 + n].decode("ascii", "replace"))
            off += 1 + n
        if labels:
            names.append(".".join(labels))
        off += 4                                      # qtype + qclass
    return names


# ===========================================================================
# Who sent it: the two-station discrimination
# ===========================================================================
@dataclass
class SourceSplit:
    c64: list[Frame]
    host: list[Frame]
    other: list[Frame]


def split_by_source(frames: Sequence[Frame], c64_mac: bytes,
                    host_mac: bytes) -> SourceSplit:
    c64_mac, host_mac = bytes(c64_mac), bytes(host_mac)
    s = SourceSplit([], [], [])
    for f in frames:
        src = bytes(f.eth_src)
        (s.c64 if src == c64_mac else s.host if src == host_mac else s.other).append(f)
    return s


def check_c64_originated(frames: Sequence[Frame], c64_mac: bytes,
                         host_mac: bytes, *, min_frames: int = 1,
                         tcp_port: int | None = None) -> Verdict:
    """At least `min_frames` frames on this cable came FROM the C64.

    THE TRAP THIS EXISTS FOR. There are two stations on the segment and the
    Mac is one of them. "The capture contains a TLS handshake" is satisfied
    in full by the Mac's own retransmissions to a C64 that is wedged,
    powered off, or not plugged in — and by the feth rig's traffic if the
    wrong interface was tapped. Only the Ethernet source address separates
    them.

    A frame from a THIRD MAC fails rather than being ignored: on a
    two-station cable it means the capture is not of the segment under test
    (wrong interface, a switch, a VM bridge), so no count taken from it
    means what the caller thinks.
    """
    if bytes(c64_mac) == bytes(host_mac):
        return Verdict(False, "c64_mac and host_mac are the same address -- the "
                              "discrimination would be vacuous", {})
    s = split_by_source(frames, c64_mac, host_mac)
    ev = {"c64_mac": fmt_mac(c64_mac), "host_mac": fmt_mac(host_mac),
          "from_c64": len(s.c64), "from_host": len(s.host),
          "from_other": len(s.other),
          "other_macs": sorted({fmt_mac(f.eth_src) for f in s.other})}
    if s.other:
        return Verdict(False,
                       f"{len(s.other)} frames from unexpected MACs "
                       f"{ev['other_macs']} -- this is not a two-station capture",
                       ev)
    if tcp_port is not None:
        matching = [f for f in s.c64
                    if f.ip_proto == IPPROTO_TCP
                    and (f.dport == tcp_port or f.sport == tcp_port)]
        ev["from_c64_on_port"] = len(matching)
        if len(matching) < min_frames:
            return Verdict(False,
                           f"only {len(matching)} frames from the C64 on TCP "
                           f"{tcp_port} (needed {min_frames}); the Mac sent "
                           f"{len(s.host)} frames in total", ev)
        return Verdict(True, f"{len(matching)} frames from the C64 on TCP {tcp_port}",
                       ev)
    if len(s.c64) < min_frames:
        return Verdict(False,
                       f"only {len(s.c64)} frames from the C64 (needed "
                       f"{min_frames}); the Mac sent {len(s.host)} -- a capture "
                       "of the Mac talking to itself would look exactly like this",
                       ev)
    return Verdict(True, f"{len(s.c64)} frames from the C64, {len(s.host)} from "
                         "the Mac", ev)


def check_mac_on_wire(frames: Sequence[Frame], c64_mac: bytes,
                      host_mac: bytes, *, min_frames: int = 1) -> Verdict:
    """The C64's MAC is on the CABLE, not merely in a field we read back.

    Reading the address out of the driver's own table proves the table
    round-trips; it does not prove a frame ever left the cartridge carrying
    it. Rejects the all-zero MAC, the broadcast MAC, a multicast source
    (illegal as a source address), and ip65's build-time cfg_mac default,
    which is the ABSENCE of a MAC rather than a MAC to check.
    """
    ev = {"c64_mac": fmt_mac(c64_mac), "host_mac": fmt_mac(host_mac)}
    mac = bytes(c64_mac)
    if len(mac) != 6:
        return Verdict(False, f"MAC is {len(mac)} bytes, expected 6", ev)
    if mac == b"\x00" * 6:
        return Verdict(False, "the C64's MAC is 00:00:00:00:00:00 -- never programmed",
                       ev)
    if mac == b"\xff" * 6:
        return Verdict(False, "the C64's MAC is the broadcast address", ev)
    if mac[0] & 0x01:
        return Verdict(False, f"{fmt_mac(mac)} has the multicast bit set; it "
                              "cannot be a station's source address", ev)
    if tuple(mac) == IP65_DEFAULT_CFG_MAC:
        return Verdict(False, f"the C64's MAC is {fmt_mac(mac)}, ip65's BUILD-TIME "
                              "DEFAULT (ip65/ip65/config.s) -- eth_init never ran, "
                              "so this is the ABSENCE of a MAC", ev)
    if mac == bytes(host_mac):
        return Verdict(False, "the C64's MAC equals the Mac's; the discrimination "
                              "would be vacuous", ev)
    seen = [f for f in frames if bytes(f.eth_src) == mac]
    ev["frames_with_that_source"] = len(seen)
    ev["sources_seen"] = sorted({fmt_mac(f.eth_src) for f in frames})
    if len(seen) < min_frames:
        return Verdict(False,
                       f"{fmt_mac(mac)} is the C64's MAC but is the Ethernet "
                       f"SOURCE of only {len(seen)} captured frames (needed "
                       f"{min_frames}); sources seen: {ev['sources_seen']}", ev)
    return Verdict(True, f"{len(seen)} frames on the cable carry the C64's MAC "
                         f"{fmt_mac(mac)} as their source", ev)


# ===========================================================================
# The capture bracket — a pcap has to be OF this run
# ===========================================================================
def check_capture_grew(size_before: int | None, size_after: int | None,
                       *, path: str | None = None) -> Verdict:
    """The capture file grew while the run was in flight.

    The tap is started by a human outside this process, so nothing here
    proves it is pointed at the right interface, still running, or writing
    unbuffered. A file that did not grow across a 40-minute fetch is one of
    those three, and every wire assertion downstream would then be scored
    against a previous session's bytes. Cheapest possible evidence, one
    stat call at each end.
    """
    ev = {"path": path, "size_before": size_before, "size_after": size_after}
    if size_before is None or size_after is None:
        return Verdict(False, "the capture's size was not sampled at both ends of "
                              "the run", ev)
    if size_after < size_before:
        return Verdict(False, f"the capture SHRANK ({size_before} -> {size_after} "
                              "bytes): it was rotated or restarted mid-run, so "
                              "the file no longer holds this run's start", ev)
    if size_after == size_before:
        return Verdict(False,
                       f"the capture did not grow ({size_before} bytes at both "
                       "ends of the run): tcpdump is not watching this segment, "
                       "has exited, or is buffering without -U", ev)
    ev["grew_by"] = size_after - size_before
    return Verdict(True, f"the capture grew {size_before} -> {size_after} bytes "
                         f"(+{size_after - size_before}) across the run", ev)


def check_capture_bracket(frames: Sequence[Frame], started_at: float,
                          ended_at: float, *, path: str | None = None,
                          min_inside: int = 1, slack_s: float = 2.0) -> Verdict:
    """Frames from THIS run exist in the capture.

    The capture is hand-started, so nothing truncates the file and nothing
    asserts it was created by this run. Without this, a pcap from an earlier
    session parses fine and reports agreement about traffic that predates
    the build under test — including, in the worst case, an earlier run's
    successful handshake.

    `evidence["diagnosis"]` is a stable machine-readable code the caller
    branches on: "inverted-window", "empty", "no-frame-inside-the-window",
    "too-few-frames-inside", "ok". Frames BEFORE the window are expected and
    not an error — a hand-started tcpdump has legitimately been running for
    minutes — they are counted and excluded, which is what makes the run's
    corpus the run's.
    """
    ev = {"path": path, "frames": len(frames), "started_at": started_at,
          "ended_at": ended_at, "slack_s": slack_s}
    if ended_at < started_at:
        ev["diagnosis"] = "inverted-window"
        return Verdict(False, "the run's end time precedes its start time", ev)
    if not frames:
        ev["diagnosis"] = "empty"
        return Verdict(False, "the capture is empty; there is nothing to date", ev)
    lo, hi = started_at - slack_s, ended_at + slack_s
    stamps = [f.ts for f in frames]
    inside = [t for t in stamps if lo <= t <= hi]
    before = [t for t in stamps if t < lo]
    after = [t for t in stamps if t > hi]
    ev.update({"inside": len(inside), "before": len(before), "after": len(after),
               "first_ts": min(stamps), "last_ts": max(stamps)})
    if not inside:
        ev["diagnosis"] = "no-frame-inside-the-window"
        gap = started_at - max(stamps)
        return Verdict(False,
                       f"every one of the {len(frames)} frames falls OUTSIDE this "
                       f"run's window; the newest predates the run by {gap:.0f}s. "
                       "This is a stale capture from an earlier session, and "
                       "scoring it would report agreement about traffic that has "
                       "nothing to do with this build", ev)
    if len(inside) < min_inside:
        ev["diagnosis"] = "too-few-frames-inside"
        return Verdict(False, f"only {len(inside)} frames inside the run window "
                              f"(needed {min_inside})", ev)
    ev["diagnosis"] = "ok"
    return Verdict(True, f"{len(inside)} of {len(frames)} frames fall inside the "
                         f"run window ({len(before)} older frames excluded)", ev)


def frames_in_window(frames: Sequence[Frame], started_at: float,
                     ended_at: float, *, slack_s: float = 2.0) -> list[Frame]:
    """The run's corpus: frames timestamped inside the run window."""
    lo, hi = started_at - slack_s, ended_at + slack_s
    return [f for f in frames if lo <= f.ts <= hi]


# ===========================================================================
# DHCP
# ===========================================================================
def check_dhcp_lease(local_ip: bytes | None, *, subnet: str | None = None,
                     host_ip: str | None = None,
                     expect_ip: str | None = None) -> Verdict:
    """A lease was obtained, read from the C64's OWN memory over DMA.

    IT MUST NOT BE THE dnsmasq LEASE FILE. A lease there says our DHCP
    server answered; it says nothing about whether ip65 parsed the reply and
    stored it, and dnsmasq's log APPENDS, so a grep for a DHCPACK matches
    yesterday's line with the C64 powered off.

    AND IT MUST NOT BE "NON-ZERO". ip65 ships cfg_ip as 192.168.1.64 with
    the zeroed variant commented out, so a non-zero test is already
    satisfied before dhcp_init runs. The build-time default is rejected by
    value, as are 0.0.0.0, the broadcast address, loopback, multicast and
    169.254/16 (the C64 does not do IPv4LL, so a link-local address here
    means something other than DHCP wrote the field).
    """
    ev = {"local_ip": fmt_ip(local_ip) if local_ip else None,
          "subnet": subnet, "host_ip": host_ip, "expect_ip": expect_ip}
    if local_ip is None:
        return Verdict(False, "the C64's IP was never read", ev)
    if len(local_ip) != 4:
        return Verdict(False, f"read back {len(local_ip)} bytes, expected 4", ev)
    octets = tuple(local_ip)
    if octets == (0, 0, 0, 0):
        return Verdict(False, "the C64's IP is 0.0.0.0 -- no lease", ev)
    if octets == IP65_DEFAULT_CFG_IP:
        return Verdict(False, f"the C64's IP is {fmt_ip(octets)}, ip65's BUILD-TIME "
                              "DEFAULT (ip65/ip65/config.s) -- no lease was parsed",
                       ev)
    if octets[0] == 127:
        return Verdict(False, f"the C64's IP is loopback {fmt_ip(octets)}", ev)
    if octets == (255, 255, 255, 255):
        return Verdict(False, "the C64's IP is the broadcast address", ev)
    if octets[0] >= 224:
        return Verdict(False, f"the C64's IP is multicast/reserved {fmt_ip(octets)}",
                       ev)
    if octets[0] == 169 and octets[1] == 254:
        return Verdict(False, f"the C64's IP is link-local {fmt_ip(octets)}; the C64 "
                              "does not do IPv4LL, so this is not a DHCP lease", ev)
    if host_ip is not None and fmt_ip(octets) == host_ip:
        return Verdict(False, f"the C64's IP is the HOST's address {host_ip}", ev)
    if subnet is not None:
        want = subnet.split(".")[:3]
        if [str(o) for o in octets[:3]] != want:
            return Verdict(False, f"{fmt_ip(octets)} is not on the rig subnet "
                                  f"{'.'.join(want)}.0/24", ev)
    if expect_ip is not None and fmt_ip(octets) != expect_ip:
        return Verdict(False,
                       f"the C64's IP is {fmt_ip(octets)}, not the pinned "
                       f"{expect_ip}. The rig reserves that address for the "
                       "RR-Net's MAC with --dhcp-host; a POOL address here means "
                       "the reservation did not match, which is a quiet divergence "
                       "rather than an error and stops every capture keyed on the "
                       "pinned address from lining up", ev)
    return Verdict(True, f"the C64 holds a lease: {fmt_ip(octets)}", ev)


# ===========================================================================
# The wire: DNS, TLS
# ===========================================================================
def check_dns_query_on_wire(frames: Sequence[Frame], c64_mac: bytes,
                            hostname: str) -> Verdict:
    """The C64 asked THIS segment's resolver for the hostname it was built for.

    ip65's resolver runs on the 6510 and its query has to leave the
    cartridge. Sourced by Ethernet address, so the Mac's own lookups — which
    are constant on a laptop — cannot satisfy it.
    """
    want = hostname.lower().rstrip(".")
    mac = bytes(c64_mac)
    ev = {"hostname": want, "c64_mac": fmt_mac(mac)}
    seen: list[str] = []
    for f in frames:
        if f.ip_proto != IPPROTO_UDP or f.dport != 53:
            continue
        if bytes(f.eth_src) != mac:
            continue
        for name in dns_question_names(f.udp_payload):
            seen.append(name)
            if name.lower().rstrip(".") == want:
                ev["query_frame"] = f.index
                ev["names_seen"] = sorted(set(seen))
                return Verdict(True, f"the C64 queried DNS for {name}", ev)
    ev["names_seen"] = sorted(set(seen))
    return Verdict(False,
                   f"no DNS query for {want} from {fmt_mac(mac)} in the capture "
                   f"(names the C64 did ask for: {ev['names_seen'] or 'none'})", ev)


def check_client_hello_on_wire(frames: Sequence[Frame], c64_mac: bytes,
                               *, port: int,
                               expect_sni: str | None = None) -> Verdict:
    """A TLS ClientHello left the cartridge, on the port under test.

    This is the assertion that the CS8900a carried our TLS bytes, as opposed
    to the C64 merely completing DHCP. The record is DECODED rather than
    pattern-matched: "the capture contains 16 03" is true of any TLS traffic
    in either direction, including the Mac's own browsing.
    """
    mac = bytes(c64_mac)
    stream = tcp_stream(frames, eth_src=mac, dport=port)
    ev = {"c64_mac": fmt_mac(mac), "port": port, "stream_bytes": len(stream)}
    if not stream:
        return Verdict(False, f"the C64 put no TCP payload bytes at all towards "
                              f"port {port} on this cable", ev)
    records = parse_tls_records(stream)
    ev["records"] = [{"type": r.content_type, "len": r.length} for r in records[:8]]
    if not records:
        return Verdict(False, f"the {len(stream)} bytes the C64 sent to port {port} "
                              "do not frame as TLS records", ev)
    first = records[0]
    if first.content_type != TLS_CONTENT_HANDSHAKE:
        return Verdict(False, f"the C64's first record to port {port} is content "
                              f"type {first.content_type}, not handshake (22)", ev)
    if not first.body or first.body[0] != TLS_HS_CLIENT_HELLO:
        got = first.body[0] if first.body else None
        return Verdict(False, f"the C64's first handshake message is type {got}, "
                              "not ClientHello (1)", ev)
    sni = client_hello_sni(first.body)
    ev["sni"] = sni
    if expect_sni is not None and (sni or "").lower() != expect_sni.lower():
        return Verdict(False, f"the ClientHello carries SNI {sni!r}, not the "
                              f"expected {expect_sni!r}", ev)
    return Verdict(True, f"the C64 sent a ClientHello to port {port}"
                         + (f" with SNI {sni}" if sni else ""), ev)


def check_tls_traffic_both_ways(frames: Sequence[Frame], c64_mac: bytes,
                                host_mac: bytes, *, port: int) -> Verdict:
    """Encrypted application data crossed the cable in BOTH directions.

    In TLS 1.3 the request and the response are both content type 23, so
    this is the wire counterpart of "the C64 encrypted a GET and the server
    encrypted a reply". One direction alone is not enough: the server's
    records are produced by the Mac and prove nothing about the cartridge,
    and the client's records alone are consistent with a handshake that was
    never answered.
    """
    c64 = tcp_stream(frames, eth_src=bytes(c64_mac), dport=port)
    host = tcp_stream(frames, eth_src=bytes(host_mac), sport=port)
    c64_recs = parse_tls_records(c64)
    host_recs = parse_tls_records(host)
    c64_app = [r for r in c64_recs if r.content_type == TLS_CONTENT_APPDATA]
    host_app = [r for r in host_recs if r.content_type == TLS_CONTENT_APPDATA]
    ev = {"port": port, "c64_records": len(c64_recs), "host_records": len(host_recs),
          "c64_appdata": len(c64_app), "host_appdata": len(host_app),
          "c64_appdata_bytes": sum(r.length for r in c64_app),
          "host_appdata_bytes": sum(r.length for r in host_app)}
    if not c64_app:
        return Verdict(False, "no application-data record from the C64 -- it never "
                              "got far enough to encrypt the GET", ev)
    if not host_app:
        return Verdict(False, "no application-data record from the host -- the "
                              "server never answered on this cable", ev)
    return Verdict(True, f"{len(c64_app)} application-data records from the C64 and "
                         f"{len(host_app)} from the host", ev)


def check_body_not_on_wire(frames: Sequence[Frame], secret: bytes,
                           control: bytes) -> Verdict:
    """The response body never appears in cleartext, and the search WORKS.

    An absence claim over a corpus nothing was ever found in is worth
    nothing, so this refuses to report absence unless it first finds
    `control` — for this rig, the SNI hostname, which TLS 1.3 leaves in the
    clear inside the ClientHello and which therefore rides the same frames
    through the same decoder as the secret would. No control hit, no
    verdict: the result is INCONCLUSIVE, which fails closed.

    Searched per frame AND over each reassembled direction, so a secret
    split across two segments is still found, without inventing matches
    across the junction between unrelated frames.
    """
    ev = {"secret_len": len(secret), "control_len": len(control),
          "frames": len(frames)}
    if not secret:
        return Verdict(False, "no secret was supplied; the search would be vacuous",
                       ev)
    if not control:
        return Verdict(False, "no control needle was supplied; an absence result "
                              "with no positive control is not evidence", ev)
    if not frames:
        return Verdict(False, "the capture holds no frames; 'not found' over an "
                              "empty corpus is not an absence result", ev,
                       status="inconclusive")
    corpora: list[bytes] = [bytes(f.raw) for f in frames]
    for src in sorted({bytes(f.eth_src) for f in frames}):
        s = tcp_stream(frames, eth_src=src)
        if s:
            corpora.append(s)
    control_hits = [i for i, c in enumerate(corpora) if control in c]
    secret_hits = [i for i, c in enumerate(corpora) if secret in c]
    ev["control_hits"] = len(control_hits)
    ev["secret_hits"] = len(secret_hits)
    if not control_hits:
        return Verdict(False,
                       f"the control needle ({control[:32]!r}) was NOT found "
                       "anywhere in the capture, so this search has not been shown "
                       "to be capable of finding anything. Reporting the body as "
                       "absent from a corpus like that would be a claim about the "
                       "searcher, not about the wire", ev, status="inconclusive")
    if secret_hits:
        return Verdict(False,
                       f"the response body appears IN CLEARTEXT in "
                       f"{len(secret_hits)} places on the wire -- those bytes were "
                       "not encrypted", ev)
    return Verdict(True, f"the {len(secret)} byte response body appears nowhere in "
                         f"cleartext, in a capture where the control needle was "
                         f"found {len(control_hits)} times", ev)


# ===========================================================================
# What the C64 itself says — DMA reads
# ===========================================================================
def check_shadow_ram_readable(bytes_at_a000: bytes | None) -> Verdict:
    """A read of $A000 returned RAM, not the BASIC ROM.

    Everything this run reads back — http_status, http_resp_buf,
    net_local_ip, tls_state — lives in CRYPTO_COLD_SHADOW, RAM under the
    BASIC ROM. A host DMA read of that span follows the machine's banking,
    so with $01 bit 0 set the reads come back as ROM: plausible bytes,
    consistently wrong, and a body comparison that then fails for a reason
    with nothing to do with TLS. `boot.s` keeps the ROM banked out for all
    runtime operation, and this is how we know it did.
    """
    ev = {"read": (bytes_at_a000 or b"")[:16].hex()}
    if bytes_at_a000 is None:
        return Verdict(False, "$A000 was never read; the shadow reads below cannot "
                              "be trusted without it", ev)
    if len(bytes_at_a000) < 12:
        return Verdict(False, f"only {len(bytes_at_a000)} bytes read at $A000; need "
                              "at least 12 to recognise the ROM", ev)
    if bytes_at_a000.startswith(BASIC_ROM_A000_PREFIX) or \
            BASIC_ROM_SIGNATURE in bytes_at_a000[:16]:
        return Verdict(False,
                       "the read at $A000 returned the BASIC ROM "
                       f"({bytes_at_a000[:12].hex()}), not RAM. Every $A000+ read "
                       "in this run is then a ROM byte; the machine has BASIC "
                       "banked IN, which boot.s clears for runtime operation", ev)
    return Verdict(True, f"$A000 reads RAM ({bytes_at_a000[:8].hex()}), not the "
                         "BASIC ROM", ev)


def check_tls_connected(tls_state_max: int | None,
                        tls_last_state: int | None = None) -> Verdict:
    """The C64's own TLS state machine reached CONNECTED.

    Sampled DURING the run, not after: `http.s` calls `tls_close` on the way
    out, which writes tls_state back to IDLE (0), so a post-run read cannot
    distinguish a completed handshake from one that never started.
    `tls_state_max` is the highest value the rig observed while polling.

    None is a failure, not a pass: an unread state machine is not a working
    one, and the server's view of the handshake is not evidence about the
    client — the server completes as soon as it has sent its Finished,
    whether or not the C64 ever verified it.
    """
    ev = {"tls_state_max": tls_state_max, "tls_last_state": tls_last_state,
          "connected_value": TLS_STATE_CONNECTED,
          "state_name": TLS_STATE_NAMES.get(tls_state_max, "unknown")}
    if tls_state_max is None:
        return Verdict(False, "tls_state was never read from the C64", ev)
    if tls_state_max == TLS_STATE_ERROR:
        name = TLS_STATE_NAMES.get(tls_last_state, f"unknown({tls_last_state})")
        return Verdict(False, f"tls_state is ERROR ($FF); the last state attempted "
                              f"was {name}", ev)
    if tls_state_max != TLS_STATE_CONNECTED:
        return Verdict(False,
                       f"the highest tls_state observed is {ev['state_name']} "
                       f"({tls_state_max}), not CONNECTED "
                       f"({TLS_STATE_CONNECTED})", ev)
    return Verdict(True, "the C64's tls_state reached CONNECTED (7)", ev)


def check_http_response(status: int | None, resp_len: int | None,
                        resp_buf: bytes | None, expected_body: bytes) -> Verdict:
    """HTTP 200 and the EXACT body, read back out of the C64's own buffer.

    Content, not a count, and not a screen scrape: the body scrolls off a
    25-line display behind the response headers, and "the screen holds the
    first word" is satisfied by a partially decrypted record. Status, length
    and content are all asserted, so a buffer left holding a previous fetch
    cannot pass on its content alone.
    """
    ev = {"http_status": status, "resp_len": resp_len,
          "expected_len": len(expected_body),
          "buf_prefix": (resp_buf or b"")[:48].decode("ascii", "replace")}
    if not expected_body:
        return Verdict(False, "no expected body was supplied; the check would be "
                              "vacuous", ev)
    if status is None or resp_len is None or resp_buf is None:
        return Verdict(False, "the response was never read back from the C64; "
                              "'the listener served it' is not evidence that the "
                              "C64 decrypted it", ev)
    if status != 200:
        return Verdict(False, f"http_status is {status}, not 200", ev)
    if resp_len != len(expected_body):
        return Verdict(False, f"the C64 recorded {resp_len} body bytes, expected "
                              f"{len(expected_body)}", ev)
    got = resp_buf[:resp_len]
    if got != expected_body:
        same = sum(a == b for a, b in zip(got, expected_body))
        ev["matching_bytes"] = same
        return Verdict(False, f"the C64's {resp_len} decrypted body bytes differ "
                              f"from what the listener served ({same}/"
                              f"{len(expected_body)} in common)", ev)
    return Verdict(True, f"HTTP 200 and the exact {resp_len} byte body, read out of "
                         "the C64's own buffer", ev)


# ---------------------------------------------------------------------------
# net_last_error
# ---------------------------------------------------------------------------
def net_error_table(inc_source: str | None = None) -> dict:
    """The ip65 backend's error codes, PARSED FROM THE HEADER, not copied.

    A copy here would go stale silently and decode a live code as
    "unregistered". `inc_source` is the text of
    src/net/ip65/ip65_errors.inc.
    """
    if not inc_source:
        return {}
    out = {}
    for name, val in re.findall(r"^(NET_ERR_IP65_\w+)\s*=\s*\$([0-9A-Fa-f]{2})",
                                inc_source, re.M):
        out[int(val, 16)] = name
    return out


def check_net_last_error(value: int | None, table: dict) -> Verdict:
    """net_last_error is clean, and an unknown value is NOT clean.

    A code the header does not define is a harder failure than a defined
    one: it means the byte was never written, was written by something else,
    or was read from the wrong address (every symbol here moves with the
    build — see resolve_symbols).
    """
    ev = {"net_last_error": value,
          "known": {f"${k:02X}": v for k, v in sorted(table.items())}}
    if value is None:
        return Verdict(False, "net_last_error was never read", ev)
    if value == 0:
        return Verdict(True, "net_last_error is $00", ev)
    if value in table:
        ev["name"] = table[value]
        return Verdict(False, f"net_last_error is ${value:02X} {table[value]}", ev)
    return Verdict(False, f"net_last_error is ${value:02X}, which no code in "
                          "src/net/ip65/ip65_errors.inc defines -- an unwritten "
                          "byte, or the wrong address", ev)


def check_image_readback(expected: bytes, readback: bytes | None) -> Verdict:
    """The PRG landed in RAM byte-exact before SYS was typed.

    A ~47 kB image goes over REST in hundreds of small unverified writes. A
    torn load then gets SYS'd and fails later as something else — most
    likely as a network fault, since that is the first thing the program
    does, which is precisely the conclusion this whole exercise must not
    manufacture.
    """
    ev = {"expected_bytes": len(expected),
          "expected_sha256": hashlib.sha256(expected).hexdigest()}
    if readback is None:
        return Verdict(False, "the image was never read back; a torn load would "
                              "fail later as a network fault", ev)
    ev["readback_bytes"] = len(readback)
    ev["readback_sha256"] = hashlib.sha256(readback).hexdigest()
    if len(readback) != len(expected):
        return Verdict(False, f"read back {len(readback)} bytes, wrote "
                              f"{len(expected)}", ev)
    if readback != expected:
        first = next(i for i, (a, b) in enumerate(zip(expected, readback)) if a != b)
        ev["first_difference"] = first
        return Verdict(False, f"the image in RAM differs from the file; first "
                              f"difference at offset {first}", ev)
    return Verdict(True, f"{len(expected)} bytes verified in RAM, sha256 "
                         f"{ev['expected_sha256'][:16]}…", ev)


DIAG_SYMBOLS = ("net_local_ip", "net_last_error", "tls_state", "tls_last_state",
                "http_status", "http_resp_len", "http_resp_buf")


def resolve_symbols(labels, names: Sequence[str] = DIAG_SYMBOLS) -> Verdict:
    """Addresses out of THIS build's own labels.txt.

    Not written down here, because they move with the build: a rig that
    reads a stale address gets a byte of unrelated RAM and reports it as
    http_status with a straight face. A missing symbol is a hard failure —
    an absent diagnostic is not a clean one.
    """
    ev = {"requested": list(names)}
    if not names:
        return Verdict(False, "no symbols requested; the resolution would be "
                              "vacuous", ev)
    found, missing = {}, []
    for n in names:
        try:
            addr = labels.get(n)
        except AttributeError:                                # not a mapping
            addr = None
        if addr is None:
            missing.append(n)
        else:
            found[n] = addr
    ev["found"] = {n: f"${a:04X}" for n, a in found.items()}
    ev["missing"] = missing
    if missing:
        return Verdict(False,
                       f"this build does not export {', '.join(missing)}; those "
                       "bytes cannot be read, and a run that skips them silently "
                       "is a run with no way to tell a dead cartridge from a "
                       "failed handshake", ev)
    return Verdict(True, "resolved " + ", ".join(f"{n}=${a:04X}"
                                                 for n, a in found.items()), ev)


# ===========================================================================
# Provenance
# ===========================================================================
def _git(repo: Path, *args: str) -> str | None:
    try:
        r = subprocess.run(("git", "-C", str(repo)) + args,
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    # rstrip("\n") and NOT strip(): `git status --porcelain` encodes the status
    # in the first two COLUMNS, so " M tools/x.py" begins with a space and a
    # leading strip() eats it -- the path then parses one character short and
    # matches nothing.
    return r.stdout.rstrip("\n") if r.returncode == 0 else None


def provenance(paths: Sequence, *, repo=None) -> dict:
    """Which commit, and whether the worktree was dirty, produced this run.

    A file hash identifies that FILE, not the state of the work. The dirty
    marker matters more than the commit: on a tree several lanes write to, a
    run over a dirty worktree silently attributes someone else's edits to
    your freeze.
    """
    root = Path(repo) if repo is not None else Path.cwd()
    commit = _git(root, "rev-parse", "--short", "HEAD")
    toplevel = _git(root, "rev-parse", "--show-toplevel")
    porcelain = _git(root, "status", "--porcelain") if commit else None
    out: dict = {
        "repo": toplevel, "commit": commit,
        "dirty": None if porcelain is None else bool(porcelain.strip()),
        "dirty_files": [], "untracked": [], "loaded": [], "loaded_modified": [],
        "note": "" if commit else "not a git repository, or git unavailable -- "
                                  "this output cannot be tied to a commit",
    }
    changed: set = set()
    untracked: set = set()
    if porcelain:
        for line in porcelain.splitlines():
            name = line[3:].strip()
            if "->" in name:
                name = name.split("->")[-1].strip()
            if not name:
                continue
            (untracked if line.startswith("??") else changed).add(name)
        out["dirty_files"] = sorted(changed)
        out["untracked"] = sorted(untracked)
    for p in paths:
        p = Path(p)
        try:
            data = p.read_bytes()
        except OSError as exc:
            out["loaded"].append({"path": str(p), "error": str(exc)})
            continue
        entry = {"path": str(p), "sha256": hashlib.sha256(data).hexdigest(),
                 "bytes": len(data),
                 "mtime": time.strftime("%Y-%m-%dT%H:%M:%S",
                                        time.localtime(p.stat().st_mtime))}
        rel = None
        if toplevel:
            try:
                rel = str(p.resolve().relative_to(Path(toplevel).resolve()))
            except ValueError:
                rel = None
        entry["repo_relative"] = rel
        if rel is not None and rel in changed:
            out["loaded_modified"].append(rel)
        out["loaded"].append(entry)
    return out


def format_provenance(prov: dict) -> list:
    """The stamp, as lines. The commit and the dirty state share ONE line."""
    lines: list = []
    if prov.get("commit"):
        tracked = len(prov.get("dirty_files") or [])
        untracked_n = len(prov.get("untracked") or [])
        if prov.get("dirty") is None:
            state = "worktree state UNKNOWN"
        elif tracked:
            state = f"DIRTY ({tracked} tracked paths modified"
            state += f", {untracked_n} untracked)" if untracked_n else ")"
        elif untracked_n:
            state = f"tracked tree CLEAN ({untracked_n} untracked paths)"
        else:
            state = "CLEAN"
        lines.append(f"provenance: {prov['commit']} {state}   repo={prov.get('repo')}")
    else:
        lines.append(f"provenance: NO COMMIT -- {prov.get('note')}")
    for entry in prov.get("loaded", []):
        if "error" in entry:
            lines.append(f"  loaded !! {entry['path']}: {entry['error']}")
            continue
        where = entry.get("repo_relative") or entry["path"]
        lines.append(f"  loaded {where}  sha256={entry['sha256'][:16]} "
                     f"bytes={entry['bytes']} mtime={entry['mtime']}")
    for rel in prov.get("loaded_modified", []):
        lines.append(f"  !! {rel} is MODIFIED in the worktree -- this run is NOT "
                     f"of {prov.get('commit')}")
    return lines


# ===========================================================================
# The rig script is the single source of truth for the segment's addressing
# ===========================================================================
def rig_const(name: str, script) -> str:
    """Read a top-level `NAME=value` assignment out of the rig script.

    Read rather than copied: c64-wireguard moved this segment from
    10.0.65.0/24 to 10.0.66.0/24 while their suite was being written, and a
    suite carrying its own copy of that constant would have kept
    preflighting a subnet nobody serves, reported "rig down", and sent
    someone to debug a cable. Anything the script stops defining raises here
    instead of falling back to a stale value.
    """
    text = Path(script).read_text()
    m = re.search(rf"^{name}=([^\s#]+)\s*$", text, re.M)
    if not m:
        raise KeyError(f"{script} no longer defines {name}=; this suite reads the "
                       "segment's addressing from the rig script so the two cannot "
                       "drift apart -- update both together")
    return m.group(1)
