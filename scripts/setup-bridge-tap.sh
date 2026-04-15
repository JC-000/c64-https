#!/usr/bin/env bash
# setup-bridge-tap.sh -- Bridge + TAP + dnsmasq for c64-https end-to-end tests.
#
# Vendored and extended from c64-test-harness/scripts/setup-bridge-tap.sh.
# Creates br-c64 with tap-c64-0 and tap-c64-1, host IP 10.0.65.1/24, iptables
# FORWARD rules, and then starts a dnsmasq bound to br-c64 that:
#   - serves DHCP leases on 10.0.65.50-10.0.65.150 (1h)
#   - pushes default gw + DNS = 10.0.65.1
#   - overrides zimmers.net and foo.bar to 10.0.65.1
#
# Idempotent -- safe to run twice. Run via sudo. Pair with cleanup-bridge-tap.sh.
#
# Usage:
#   sudo ./scripts/setup-bridge-tap.sh

set -euo pipefail

BRIDGE="br-c64"
BRIDGE_ADDR="10.0.65.1/24"
BRIDGE_IP="${BRIDGE_ADDR%/*}"
TAP0="tap-c64-0"
TAP1="tap-c64-1"
TAP_USER="${SUDO_USER:-$USER}"

DNSMASQ_PIDFILE="/tmp/c64-https-dnsmasq.pid"
DNSMASQ_LOGFILE="/tmp/c64-https-dnsmasq.log"
DHCP_RANGE_START="10.0.65.50"
DHCP_RANGE_END="10.0.65.150"
DHCP_LEASE="1h"

echo "Bridge:      $BRIDGE ($BRIDGE_ADDR)"
echo "TAP devices: $TAP0, $TAP1 (owner: $TAP_USER)"
echo "dnsmasq:     pid=$DNSMASQ_PIDFILE log=$DNSMASQ_LOGFILE"
echo

# --- Bridge ------------------------------------------------------------------

if ip link show "$BRIDGE" &>/dev/null; then
    echo "[ok] $BRIDGE already exists"
else
    ip link add name "$BRIDGE" type bridge
    echo "[created] $BRIDGE"
fi

if [[ -f "/sys/devices/virtual/net/$BRIDGE/bridge/stp_state" ]]; then
    if [[ "$(cat /sys/devices/virtual/net/$BRIDGE/bridge/stp_state)" != "0" ]]; then
        ip link set "$BRIDGE" type bridge stp_state 0
        echo "[disabled] STP on $BRIDGE"
    fi
fi

if ip addr show "$BRIDGE" | grep -q "$BRIDGE_IP"; then
    echo "[ok] $BRIDGE has $BRIDGE_ADDR"
else
    ip addr add "$BRIDGE_ADDR" dev "$BRIDGE"
    echo "[addr] $BRIDGE_ADDR assigned"
fi

if ip link show "$BRIDGE" | grep -q 'state UP'; then
    echo "[ok] $BRIDGE is UP"
else
    ip link set "$BRIDGE" up
    echo "[up] $BRIDGE"
fi

# --- TAP interfaces ----------------------------------------------------------

for TAP_DEV in "$TAP0" "$TAP1"; do
    if ip link show "$TAP_DEV" &>/dev/null; then
        echo "[ok] $TAP_DEV already exists"
    else
        ip tuntap add dev "$TAP_DEV" mode tap user "$TAP_USER"
        echo "[created] $TAP_DEV"
    fi

    if ip link show "$TAP_DEV" 2>/dev/null | grep -q "master $BRIDGE"; then
        echo "[ok] $TAP_DEV already bridged"
    else
        ip link set "$TAP_DEV" master "$BRIDGE"
        echo "[bridge] $TAP_DEV added to $BRIDGE"
    fi

    if ip link show "$TAP_DEV" | grep -q 'state UP'; then
        echo "[ok] $TAP_DEV is UP"
    else
        ip link set "$TAP_DEV" up
        echo "[up] $TAP_DEV"
    fi
done

# --- iptables FORWARD rules --------------------------------------------------

for DEV in "$BRIDGE" "$TAP0" "$TAP1"; do
    if ! iptables -C FORWARD -i "$DEV" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$DEV" -j ACCEPT
        echo "[added] FORWARD: $DEV inbound"
    fi
    if ! iptables -C FORWARD -o "$DEV" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -o "$DEV" -j ACCEPT
        echo "[added] FORWARD: $DEV outbound"
    fi
done

# --- dnsmasq -----------------------------------------------------------------
# Stop any stale dnsmasq we previously started.

if [[ -f "$DNSMASQ_PIDFILE" ]]; then
    OLD_PID="$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
        # Only kill if it's actually a dnsmasq process
        if grep -q dnsmasq "/proc/$OLD_PID/comm" 2>/dev/null; then
            kill "$OLD_PID" 2>/dev/null || true
            sleep 0.3
            kill -9 "$OLD_PID" 2>/dev/null || true
            echo "[killed] stale dnsmasq pid=$OLD_PID"
        fi
    fi
    rm -f "$DNSMASQ_PIDFILE"
fi

if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "ERROR: dnsmasq not installed" >&2
    exit 1
fi

# Start dnsmasq as a daemon with its own pidfile. --bind-interfaces + listen
# on the bridge ip so we don't clash with a system resolver on other ifaces.
: >"$DNSMASQ_LOGFILE"
dnsmasq \
    --keep-in-foreground \
    --pid-file="$DNSMASQ_PIDFILE" \
    --interface="$BRIDGE" \
    --bind-interfaces \
    --listen-address="$BRIDGE_IP" \
    --no-resolv \
    --no-hosts \
    --dhcp-range="$DHCP_RANGE_START,$DHCP_RANGE_END,255.255.255.0,$DHCP_LEASE" \
    --dhcp-option=3,"$BRIDGE_IP" \
    --dhcp-option=6,"$BRIDGE_IP" \
    --address=/zimmers.net/"$BRIDGE_IP" \
    --address=/foo.bar/"$BRIDGE_IP" \
    --log-queries \
    --log-dhcp \
    >>"$DNSMASQ_LOGFILE" 2>&1 &
DNSMASQ_PID=$!
disown "$DNSMASQ_PID" 2>/dev/null || true

# dnsmasq in --keep-in-foreground does NOT write the pidfile itself, so we
# write the child PID manually.
echo "$DNSMASQ_PID" >"$DNSMASQ_PIDFILE"

# Wait briefly for it to bind.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        echo "ERROR: dnsmasq exited early. Log tail:" >&2
        tail -20 "$DNSMASQ_LOGFILE" >&2 || true
        exit 1
    fi
    if ss -lnup 2>/dev/null | grep -q "$BRIDGE_IP:53" \
       && ss -lnup 2>/dev/null | grep -q "$BRIDGE_IP:67"; then
        break
    fi
    sleep 0.2
done
echo "[dnsmasq] pid=$DNSMASQ_PID bound to $BRIDGE_IP (DHCP $DHCP_RANGE_START-$DHCP_RANGE_END)"

echo
echo "Done. Bridge $BRIDGE ready, dnsmasq serving DHCP+DNS on $BRIDGE_IP."
echo "Tear down with: sudo ./scripts/cleanup-bridge-tap.sh"
