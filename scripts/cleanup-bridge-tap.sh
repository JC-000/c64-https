#!/usr/bin/env bash
# cleanup-bridge-tap.sh -- Tear down the bridge+dnsmasq env set up by
# setup-bridge-tap.sh. Idempotent -- safe to run if already torn down.
#
# Kills any leftover VICE processes, tears down the br-c64 bridge and
# its tap-c64-0/tap-c64-1 interfaces, removes the iptables FORWARD rules,
# and cleans up stale /tmp/vice_eth_*.rc files.
#
# Usage:
#   sudo ./scripts/cleanup-bridge-tap.sh

set -u  # don't set -e: we want to keep going through all cleanup steps

BRIDGE="br-c64"
TAP0="tap-c64-0"
TAP1="tap-c64-1"
TAP_LEGACY="tap-c64"
DNSMASQ_PIDFILE="/tmp/c64-https-dnsmasq.pid"

echo "=== c64-https bridge networking cleanup ==="
echo

# --- 1. Kill any leftover x64sc processes ------------------------------------
echo "[1/6] Killing any leftover x64sc processes..."
if pgrep -x x64sc > /dev/null 2>&1; then
    pgrep -a x64sc | while read -r pid cmd; do
        echo "  killing PID $pid: $cmd"
    done
    pkill -TERM x64sc 2>/dev/null || true
    sleep 1
    if pgrep -x x64sc > /dev/null 2>&1; then
        pkill -KILL x64sc 2>/dev/null || true
        sleep 1
    fi
    if pgrep -x x64sc > /dev/null 2>&1; then
        echo "  WARNING: x64sc still running after SIGKILL"
    else
        echo "  all x64sc processes killed"
    fi
else
    echo "  no x64sc processes running"
fi
echo

# --- 2. Kill dnsmasq (pidfile + /proc scan) ----------------------------------
echo "[2/6] Killing dnsmasq processes..."
found_dns=0

# 2a. Primary path: pidfile
if [[ -f "$DNSMASQ_PIDFILE" ]]; then
    PID="$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        if grep -q dnsmasq "/proc/$PID/comm" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            for _ in 1 2 3 4 5; do
                kill -0 "$PID" 2>/dev/null || break
                sleep 0.2
            done
            kill -9 "$PID" 2>/dev/null || true
            echo "  [killed] dnsmasq pid=$PID (via pidfile)"
            found_dns=1
        else
            echo "  [ok] pidfile pid $PID is not dnsmasq, skipping"
        fi
    else
        echo "  [ok] dnsmasq pidfile pid $PID already gone"
    fi
    rm -f "$DNSMASQ_PIDFILE"
fi

# 2b. Fallback: scan /proc cmdlines for dnsmasq bound to our TAPs/bridge
if command -v pgrep > /dev/null; then
    while read -r pid; do
        if [[ -n "$pid" ]]; then
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "")
            if echo "$cmdline" | grep -qE "(tap-c64-|br-c64|tap-c64)"; then
                echo "  [killed] dnsmasq pid=$pid (via /proc scan): $cmdline"
                kill -TERM "$pid" 2>/dev/null || true
                found_dns=1
            fi
        fi
    done < <(pgrep -x dnsmasq 2>/dev/null)
fi

if [[ "$found_dns" == "0" ]]; then
    echo "  no dnsmasq processes found"
fi
echo

# --- 3. Remove iptables FORWARD rules ----------------------------------------
echo "[3/6] Removing iptables FORWARD rules..."
removed=0
for DEV in "$BRIDGE" "$TAP0" "$TAP1" "$TAP_LEGACY"; do
    if iptables -D FORWARD -i "$DEV" -j ACCEPT 2>/dev/null; then
        echo "  [removed] FORWARD -i $DEV"
        removed=$((removed + 1))
    fi
    if iptables -D FORWARD -o "$DEV" -j ACCEPT 2>/dev/null; then
        echo "  [removed] FORWARD -o $DEV"
        removed=$((removed + 1))
    fi
done
if [[ "$removed" == "0" ]]; then
    echo "  no FORWARD rules to remove"
fi
echo

# --- 4. Tear down TAP interfaces and bridge -----------------------------------
echo "[4/6] Tearing down TAP interfaces and bridge..."
for TAP_DEV in "$TAP0" "$TAP1" "$TAP_LEGACY"; do
    if ip link show "$TAP_DEV" > /dev/null 2>&1; then
        ip link set "$TAP_DEV" down 2>/dev/null || true
        ip tuntap del dev "$TAP_DEV" mode tap 2>/dev/null
        if ip link show "$TAP_DEV" > /dev/null 2>&1; then
            echo "  WARNING: $TAP_DEV still exists"
        else
            echo "  [removed] $TAP_DEV"
        fi
    else
        echo "  [ok] $TAP_DEV already absent"
    fi
done

if ip link show "$BRIDGE" > /dev/null 2>&1; then
    ip link set "$BRIDGE" down 2>/dev/null || true
    ip link del "$BRIDGE" type bridge 2>/dev/null
    if ip link show "$BRIDGE" > /dev/null 2>&1; then
        echo "  WARNING: $BRIDGE still exists"
    else
        echo "  [removed] $BRIDGE"
    fi
else
    echo "  [ok] $BRIDGE already absent"
fi
echo

# --- 5. Remove stale temp vicerc files ----------------------------------------
echo "[5/6] Removing stale /tmp/vice_eth_*.rc files..."
shopt -s nullglob
rc_files=(/tmp/vice_eth_*.rc)
if [[ ${#rc_files[@]} -gt 0 ]]; then
    for f in "${rc_files[@]}"; do
        rm -f "$f" && echo "  [removed] $f"
    done
else
    echo "  no stale vicerc files"
fi
shopt -u nullglob
echo

# --- 6. Remove stale dnsmasq pidfile (if not already cleaned) -----------------
echo "[6/6] Final pidfile cleanup..."
if [[ -f "$DNSMASQ_PIDFILE" ]]; then
    rm -f "$DNSMASQ_PIDFILE"
    echo "  [removed] $DNSMASQ_PIDFILE"
else
    echo "  [ok] no stale pidfile"
fi
echo

echo "=== Cleanup complete ==="
