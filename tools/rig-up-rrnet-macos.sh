#!/usr/bin/env bash
# =============================================================================
# tools/rig-up-rrnet-macos.sh — bring up the PHYSICAL RR-Net segment on macOS.
#
# ADAPTED FROM c64-wireguard's tools/rig-up-rrnet-macos.sh, which brought this
# same cable up for their ip65 hardware validation. Their reasoning for the
# subnet choice, the link-media sanity checks and the unconditional truncation
# of the lease/log files is reproduced here because all three apply verbatim.
# What is ours: DNS is ENABLED (the c64-https client resolves HTTPS_HOST before
# it connects, so a DHCP-only segment cannot serve this test at all) and the
# rig serves an A record for the build's default target.
#
# Topology: a real RR-Net cartridge in the U64E's cartridge port, cabled
# DIRECTLY (no switch) to a USB-Ethernet NIC on this Mac. The NIC is the only
# other station on that segment, so it plays gateway, DHCP server, DNS server
# and HTTPS origin all at once.
#
#   [ C64 + RR-Net (CS8900a, 10baseT) ] <--cable--> [ Mac USB-Eth NIC ]
#
# WHY THIS IS NEEDED. src/boot.s's do_net_init calls net_dhcp_acquire and
# returns on failure -- there is no static-IP path in the shipped image. And
# do_https_get resolves HTTPS_HOST through net_dns_resolve before it opens the
# socket, so a segment with DHCP but no DNS stops at DNS RESOLVE FAILED. Both
# services therefore have to live on this cable. Self-assigned 169.254
# addressing is not enough either: the C64 does not do IPv4LL, it does DHCP or
# nothing.
#
# SUBNET CHOICE: 10.0.66.0/24, deliberately NOT 10.0.65.0/24. The VICE-side
# feth rig (tools/rig-up-macos.sh, the emulated counterpart of this test)
# already owns 10.0.65.1 on feth1. Sharing the subnet would put 10.0.65.1 on
# two interfaces, make the route for 10.0.65.0/24 ambiguous, and have a second
# dnsmasq fight for a listen-address the first already holds -- and we want
# BOTH rigs up at once, since comparing real silicon against the emulated pair
# is the whole point of tests/rig_ip65_rrnet_hw.py existing.
#
# NOTE: a lease is NOT a route. This link has no path off itself. The HTTPS
# listener must therefore run ON this Mac, bound to HOST_IP, which is what
# tests/rig_ip65_rrnet_hw.py does (tools/https_e2e, port 4433 so it needs no
# sudo). Reaching anything beyond the cable would need ip forwarding plus a
# pfctl NAT rule, deliberately out of scope for a hardware validation whose
# job is to test the C64 side.
#
# THIS SCRIPT IS DOCUMENTATION AND RECOVERY. On a bench where the segment is
# already up you should not need to run it; it exists so the rig can be rebuilt
# from scratch, and so tests/rig_ip65_rrnet_hw.py can READ the addressing out
# of it (hw.rig_const) instead of carrying a second copy that drifts.
#
# Requires sudo: binding UDP/67 and UDP/53 and setting an interface address all
# do.
#
#   Up:    sudo bash tools/rig-up-rrnet-macos.sh en4
#   Down:  sudo bash tools/rig-up-rrnet-macos.sh en4 down
#
# Idempotent. `down` restores DHCP (self-assigned) addressing on the NIC.
# =============================================================================
set -euo pipefail

IFACE="${1:?usage: $0 <interface> [down]   e.g. $0 en4}"
ACTION="${2:-up}"

HOST_IP=10.0.66.1
NETMASK=255.255.255.0
LEASE_LO=10.0.66.10
LEASE_HI=10.0.66.60
LEASE_TIME=1h

# ip65's built-in MAC for this cartridge (the Cirrus Logic OUI plus the
# __C64__ suffix baked into ip65/drivers/cs8900a.s). Pinned with --dhcp-host so
# the C64 always takes the SAME address, which is what lets a capture and a
# checker be compared across runs -- and what lets the checker assert an exact
# address instead of "something in the pool".
C64_MAC=00:0e:3a:64:64:64
C64_IP=10.0.66.200

# The build's default HTTPS_HOST (Makefile: HTTPS_HOST ?= www.foo.invalid).
# .invalid is reserved by RFC 2606 and can never resolve globally, so serving
# it here cannot collide with anything real, and a lookup that succeeds proves
# it was answered by THIS segment.
TEST_HOST=www.foo.invalid

PIDFILE=/tmp/c64-rrnet-dnsmasq.pid
LOGFILE=/tmp/c64-rrnet-dnsmasq.log
LEASEFILE=/tmp/c64-rrnet-dnsmasq.leases
DNSMASQ="$(command -v dnsmasq || echo /opt/homebrew/sbin/dnsmasq)"

if [[ "$ACTION" == "down" ]]; then
    if [[ -f "$PIDFILE" ]]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
        echo "dnsmasq stopped"
    fi
    # Hand the NIC back to DHCP/self-assigned.
    ipconfig set "$IFACE" DHCP 2>/dev/null || true
    echo "$IFACE returned to DHCP addressing"
    exit 0
fi

# --- sanity: the NIC must exist and the cable must be up ---------------------
if ! ifconfig "$IFACE" >/dev/null 2>&1; then
    echo "ERROR: no such interface: $IFACE" >&2; exit 1
fi
if ! ifconfig "$IFACE" | grep -q "status: active"; then
    echo "ERROR: $IFACE is not 'status: active' -- is the cable connected and" >&2
    echo "       the C64 powered on? A CS8900a only lights the link when the" >&2
    echo "       cartridge has power." >&2
    ifconfig "$IFACE" | sed 's/^/       /' >&2
    exit 1
fi
# A 10baseT link is the expected media for an RR-Net; anything faster means we
# are almost certainly pointed at the wrong NIC.
if ! ifconfig "$IFACE" | grep -q "10baseT"; then
    echo "WARNING: $IFACE is not negotiated at 10baseT. An RR-Net (CS8900a) is" >&2
    echo "         10 Mbps only, so this may be the wrong interface." >&2
    ifconfig "$IFACE" | grep media | sed 's/^/         /' >&2
fi

# --- refuse to collide with the feth rig -------------------------------------
if pgrep -f "dnsmasq.*listen-address=$HOST_IP" >/dev/null 2>&1; then
    echo "ERROR: a dnsmasq is already serving $HOST_IP. Two rigs cannot share" >&2
    echo "       an address. Check: pgrep -fl dnsmasq" >&2
    exit 1
fi

# --- address -----------------------------------------------------------------
ifconfig "$IFACE" inet "$HOST_IP" netmask "$NETMASK" up
echo "$IFACE -> $HOST_IP/${NETMASK}"

# --- dnsmasq -----------------------------------------------------------------
# TRUNCATE BOTH UNCONDITIONALLY. --log-facility APPENDS, and the lease file
# survives a rig-up that finds dnsmasq already running -- so without this a
# checker grepping for "DHCPACK ... 10.0.66.200" matches YESTERDAY's line and
# reports "the C64 took a lease" with the C64 POWERED OFF. That is a false pass
# on the one step everything downstream depends on, since our build stops at
# DHCP failure and never reaches the fetch. (tests/rig_ip65_rrnet_hw.py does
# not decide anything from these files for exactly that reason -- the lease
# assertion reads the C64's own memory -- but they are the first thing a human
# looks at, so they must not lie either.)
: > "$LEASEFILE"
: > "$LOGFILE"
echo "leases and log truncated"

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "dnsmasq already running (pid $(cat "$PIDFILE"))"
else
    # --conf-file=/dev/null and --no-resolv: this resolver answers for exactly
    # one name and forwards nothing. A segment that could fall back to an
    # upstream resolver would let a run pass while pointed somewhere else
    # entirely, and would make the C64's DNS query indistinguishable from the
    # Mac's own.
    "$DNSMASQ" \
        --conf-file=/dev/null \
        --interface="$IFACE" \
        --bind-interfaces \
        --except-interface=lo0 \
        --listen-address="$HOST_IP" \
        --no-resolv \
        --address="/$TEST_HOST/$HOST_IP" \
        --dhcp-range="$LEASE_LO,$LEASE_HI,$LEASE_TIME" \
        --dhcp-host="$C64_MAC,$C64_IP" \
        --dhcp-option=option:router,"$HOST_IP" \
        --dhcp-option=option:dns-server,"$HOST_IP" \
        --dhcp-authoritative \
        --log-dhcp \
        --log-queries \
        --log-facility="$LOGFILE" \
        --pid-file="$PIDFILE" \
        --dhcp-leasefile="$LEASEFILE"
    echo "dnsmasq started (pid $(cat "$PIDFILE" 2>/dev/null || echo '?'))"
fi

echo
echo "Rig up on $IFACE:"
echo "  host / listener    : $HOST_IP"
echo "  DHCP pool          : $LEASE_LO - $LEASE_HI"
echo "  pinned lease       : $C64_MAC -> $C64_IP"
echo "  DNS                : $TEST_HOST -> $HOST_IP (and nothing else)"
echo "  leases             : $LEASEFILE"
echo "  dnsmasq log        : $LOGFILE"
echo
echo "Verify DNS:                       dig +short @$HOST_IP $TEST_HOST"
echo "Watch the C64 take a lease with:  tail -f $LOGFILE"
echo "Capture the wire with:            sudo tcpdump -i $IFACE -n -s0 -U -w /tmp/rrnet-https.pcap"
echo "  (-s0 and -U are BOTH load-bearing: tools/ip65_hw_checks.py refuses a"
echo "   snaplen-clipped capture, and without -U the file does not grow while"
echo "   the run is in flight, which the same module reads as a dead tap.)"
