"""BridgeEnv -- context manager wrapping scripts/setup-bridge-tap.sh.

Runs the vendored setup script (br-c64 + tap-c64-0/1 + dnsmasq) on __enter__
and the cleanup script on __exit__. Polls until dnsmasq is listening on
10.0.65.1:53 (DNS UDP) and :67 (DHCP). Tolerates repeated entry by letting
the setup script itself be idempotent.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from contextlib import contextmanager

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SETUP_SCRIPT = os.path.join(_REPO_ROOT, "scripts", "setup-bridge-tap.sh")
_CLEANUP_SCRIPT = os.path.join(_REPO_ROOT, "scripts", "cleanup-bridge-tap.sh")

BRIDGE_IP = "10.0.65.1"
BRIDGE_IFACE = "br-c64"
TAP0 = "tap-c64-0"
TAP1 = "tap-c64-1"


def platform_supported() -> bool:
    """True if this host can run the br-c64 bridge rig at all.

    Asked BEFORE check_prerequisites(), and deliberately NOT folded into
    it: that function returns a flat list of strings, and "ip not on PATH"
    means "apt install iproute2" on Linux but "this OS has no iproute2 and
    never will" on Darwin.  No partition of the list can tell those apart,
    because the platform question has to be answered first.

    The rig needs Linux netfilter (the setup script's iptables rules), the
    iproute2 `ip` command, and /proc/net/udp -- which _port_open_udp()
    below reads directly.  A wrong platform is a VOLUNTARY skip owned by
    tests/rig_vice_https_macos.py; a missing tool ON Linux is installable
    and stays an involuntary one.  See issue #178.
    """
    return sys.platform.startswith("linux")


def check_prerequisites() -> list[str]:
    """Return a list of missing prereqs. Empty list means all OK.

    Contract unchanged (issue #178 added platform_supported() beside it
    rather than partitioning this list): the five tool checks and the sudo
    probe below all describe things that are INSTALLABLE on the rig's
    target platform.  Callers ask platform_supported() first.
    """
    missing: list[str] = []
    for tool in ("x64sc", "dnsmasq", "sudo", "ip", "iptables"):
        if shutil.which(tool) is None:
            missing.append(f"{tool} not on PATH")
    if not os.path.isfile(_SETUP_SCRIPT):
        missing.append(f"setup script missing: {_SETUP_SCRIPT}")
    if not os.path.isfile(_CLEANUP_SCRIPT):
        missing.append(f"cleanup script missing: {_CLEANUP_SCRIPT}")
    # sudo without password?
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if r.returncode != 0:
            missing.append("sudo requires a password (NOPASSWD not configured)")
    except (OSError, subprocess.TimeoutExpired) as e:
        missing.append(f"sudo probe failed: {e}")
    return missing


def _port_open_udp(host: str, port: int) -> bool:
    """Crude UDP 'is something listening' probe -- check /proc/net/udp."""
    # UDP sockets don't accept connections, so best to scan /proc/net/udp.
    try:
        with open("/proc/net/udp", "r") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return False
    # Format: sl local_address rem_address st ...
    # local_address is HEX_IP:HEX_PORT where HEX_IP is little-endian for IPv4.
    try:
        packed = socket.inet_aton(host)
        hex_ip = "".join(f"{b:02X}" for b in reversed(packed))
    except OSError:
        return False
    needle = f"{hex_ip}:{port:04X}"
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1].upper() == needle:
            return True
    return False


_DNSMASQ_PIDFILE = "/tmp/c64-https-dnsmasq.pid"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True  # process exists but owned by another user (e.g. nobody)
    except (OSError, ProcessLookupError):
        return False
    return True


def _wait_for_dnsmasq(timeout: float = 10.0) -> None:
    """Wait until dnsmasq is serving DNS on 10.0.65.1:53.

    dnsmasq's DHCP listener uses a raw packet socket (not a regular UDP
    socket bound to :67), so we only check :53 for the UDP listener and
    rely on the pidfile + process liveness as the DHCP-ready signal.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        dns_ok = _port_open_udp(BRIDGE_IP, 53)
        pid_ok = False
        if os.path.isfile(_DNSMASQ_PIDFILE):
            try:
                with open(_DNSMASQ_PIDFILE) as f:
                    pid = int(f.read().strip())
                pid_ok = _pid_alive(pid)
            except (OSError, ValueError):
                pid_ok = False
        if dns_ok and pid_ok:
            return
        time.sleep(0.2)
    raise RuntimeError(
        f"dnsmasq not ready within {timeout}s "
        f"(dns_on_{BRIDGE_IP}:53={_port_open_udp(BRIDGE_IP, 53)})"
    )


def _run_sudo_script(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sudo", script],
        capture_output=True,
        text=True,
    )


class BridgeEnv:
    """Context manager that brings up br-c64 + taps + dnsmasq.

    Usage::

        with BridgeEnv() as env:
            # env.tap0 / env.bridge_ip available
            ...
    """

    bridge_ip = BRIDGE_IP
    bridge_iface = BRIDGE_IFACE
    tap0 = TAP0
    tap1 = TAP1

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._entered = False

    def __enter__(self) -> "BridgeEnv":
        # Clean any stale state first so repeated entry is safe.
        if self.verbose:
            print(f"[BridgeEnv] cleanup stale state...")
        _run_sudo_script(_CLEANUP_SCRIPT)  # errors ignored

        if self.verbose:
            print(f"[BridgeEnv] running setup: {_SETUP_SCRIPT}")
        r = _run_sudo_script(_SETUP_SCRIPT)
        if r.returncode != 0:
            raise RuntimeError(
                f"setup-bridge-tap.sh failed (exit {r.returncode}):\n"
                f"STDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
            )
        if self.verbose:
            # Show a compact tail
            tail = "\n".join(r.stdout.splitlines()[-6:])
            print(f"[BridgeEnv] setup ok:\n{tail}")

        if not os.path.isdir(f"/sys/class/net/{self.bridge_iface}"):
            raise RuntimeError(f"{self.bridge_iface} not up after setup")
        for t in (self.tap0, self.tap1):
            if not os.path.isdir(f"/sys/class/net/{t}"):
                raise RuntimeError(f"{t} not up after setup")

        _wait_for_dnsmasq(timeout=10.0)
        if self.verbose:
            print(f"[BridgeEnv] dnsmasq bound to {BRIDGE_IP}:53/67")

        self._entered = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.verbose:
            print(f"[BridgeEnv] cleanup...")
        r = _run_sudo_script(_CLEANUP_SCRIPT)
        if r.returncode != 0 and self.verbose:
            print(
                f"[BridgeEnv] cleanup non-zero exit={r.returncode}\n"
                f"STDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
            )
