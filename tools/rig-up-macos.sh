#!/usr/bin/env bash
# rig-up-macos.sh — one-shot (per boot) root setup for hardware-free ip65
# testing: VICE RR-Net emulation (pcap on feth0) <-> host services on feth1.
#
# Topology (macOS): VICE attaches via pcap to feth0; the feth PEER link
# forwards L2 frames to feth1, where the host owns 10.0.65.1 and runs
# dnsmasq (DHCP+DNS) and, later, the TLS listener. bridge10 is created by
# the harness script only to satisfy iface_present() preconditions — per
# c64-test-harness PR #66 the feth peer itself is the L2 path and the
# bridge must NOT enslave the feth pair.
#
# Run:   sudo bash tools/rig-up-macos.sh
# Down:  sudo pkill -F /tmp/c64-rig-dnsmasq.pid; sudo bash \
#        ../c64-test-harness/scripts/teardown-bridge-feth-macos.sh
#
# Idempotent — safe to re-run.

set -euo pipefail

HARNESS_SETUP="$(dirname "$0")/../../c64-test-harness/scripts/setup-bridge-feth-macos.sh"
HOST_IF="feth1"
HOST_ADDR="10.0.65.1"
DNSMASQ_PID=/tmp/c64-rig-dnsmasq.pid
DNSMASQ_LOG=/tmp/c64-rig-dnsmasq.log
DNSMASQ_BIN="$(command -v dnsmasq || echo /opt/homebrew/sbin/dnsmasq)"

if [[ $EUID -ne 0 ]]; then echo "run with sudo"; exit 2; fi

# 1. feth pair + bridge10 (harness script, idempotent)
bash "$HARNESS_SETUP"

# 2. Host IP on the feth peer so host services are L2-adjacent to VICE.
#    The harness script also assigns HOST_ADDR to bridge10 — remove that
#    alias: bridge10 is NOT L2-connected to the feth link (peers are
#    deliberately not bridge members), so a duplicate address there can
#    steal host-originated replies into a dead end.
ifconfig bridge10 -alias "$HOST_ADDR" 2>/dev/null || true
ifconfig "$HOST_IF" inet "$HOST_ADDR" netmask 255.255.255.0 up
echo "[ok] $HOST_IF up at $HOST_ADDR (bridge10 alias removed)"

# 3. Open BPF devices so VICE (pcap) runs unprivileged from here on
chmod o+rw /dev/bpf*
echo "[ok] /dev/bpf* opened (o+rw, reverts on reboot)"

# 4. dnsmasq: DHCP 10.0.65.100-150 + DNS records, bound to the feth peer.
#    Flags mirror tools/net_test_env.py::start_dnsmasq.
#
#    The pool starts at .100, NOT .2, because 10.0.65.0/24 is shared with
#    c64-test-harness and it reserves the bottom of the range: .1 host side
#    of the bridge, .2 and .3 the two emulated C64s its bridge tests
#    hardcode (test_bridge_ping, test_ethernet_bridge, ...). A .2-.10 pool
#    hands out exactly those two addresses, so whenever this rig was up the
#    harness's bridge tests failed or behaved oddly with nothing on either
#    side detecting it (c64-https#108). Keep this clear of .1-.3.
if [[ -f "$DNSMASQ_PID" ]] && kill -0 "$(cat "$DNSMASQ_PID")" 2>/dev/null; then
    echo "[ok] dnsmasq already running (pid $(cat "$DNSMASQ_PID"))"
else
    rm -f "$DNSMASQ_PID"
    # --conf-file=/dev/null: ignore the brew template config.
    # --except-interface=lo0: dnsmasq auto-adds loopback to its listen
    #   set; this Mac has 127.0.2.x loopback aliases with a resident DNS
    #   service on :53 (VPN/security agent), which made the unpatched
    #   invocation die with "127.0.2.3: Address already in use".
    "$DNSMASQ_BIN" \
        --conf-file=/dev/null \
        --except-interface=lo0 \
        --interface="$HOST_IF" \
        --bind-interfaces \
        --listen-address="$HOST_ADDR" \
        --dhcp-range=10.0.65.100,10.0.65.150,255.255.255.0,5m \
        --dhcp-option=6,"$HOST_ADDR" \
        --no-ping \
        --address=/www.foo.bar/"$HOST_ADDR" \
        --address=/foo.bar/"$HOST_ADDR" \
        --address=/c64test.local/"$HOST_ADDR" \
        --log-queries --log-dhcp --no-resolv \
        --pid-file="$DNSMASQ_PID" \
        --log-facility="$DNSMASQ_LOG"
    sleep 1
    kill -0 "$(cat "$DNSMASQ_PID")" 2>/dev/null \
        && echo "[ok] dnsmasq up (pid $(cat "$DNSMASQ_PID"), log $DNSMASQ_LOG)" \
        || { echo "[fail] dnsmasq did not stay up — see $DNSMASQ_LOG"; exit 1; }
fi

echo
echo "Rig is up. VICE tests attach with: -ethernetcart -ethernetcartmode 1 \\"
echo "  -ethernetiodriver pcap -ethernetioif feth0"
