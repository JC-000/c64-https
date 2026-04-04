#!/usr/bin/env python3
"""net_test_env.py -- Consolidated network test environment for C64 VICE emulator tests.

Provides a NetworkTestEnv context manager that handles TAP interface setup,
dnsmasq lifecycle, and optional HTTP/HTTPS server startup. Replaces the
duplicated inline setup/teardown code across test_dns.py, test_http_integration.py,
and test_https_integration.py.

Usage as context manager:
    with NetworkTestEnv(dns_records={"c64test.local": "10.0.65.1"}) as env:
        # env.dnsmasq_proc is running
        # env.server is running if http_server=True
        run_tests(...)

Usage as CLI:
    python3 tools/net_test_env.py --dns-record c64test.local=10.0.65.1
    python3 tools/net_test_env.py --wrap python3 tools/test_dns.py
"""

from __future__ import annotations

import argparse
import atexit
import os
import shutil
import signal
import ssl
import subprocess
import sys
import time
from typing import Optional

# Allow importing test_server from the same directory.
sys.path.insert(0, os.path.dirname(__file__))
from test_server import TestHTTPServer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TAP_SYSFS = "/sys/class/net/{iface}"
SETUP_TAP_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "c64-test-harness", "scripts", "setup-tap-networking.sh",
)
# Resolve to absolute path
SETUP_TAP_SCRIPT = os.path.normpath(SETUP_TAP_SCRIPT)

DEFAULT_DNS_RECORDS: dict[str, str] = {"c64test.local": "10.0.65.1"}


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

def skip_if_no_network(tap_interface: str = "tap-c64") -> bool:
    """Check if network test prerequisites are missing.

    Returns True if tests should be skipped (i.e., something is missing).
    Prints a SKIP message for the first missing prerequisite found.
    """
    if not os.path.exists(TAP_SYSFS.format(iface=tap_interface)):
        print(f"SKIP: {tap_interface} interface not found")
        return True
    if shutil.which("x64sc") is None:
        print("SKIP: x64sc not on PATH")
        return True
    if shutil.which("dnsmasq") is None:
        print("SKIP: dnsmasq not on PATH")
        return True
    if shutil.which("sudo") is None:
        print("SKIP: sudo not on PATH")
        return True
    return False


def start_dnsmasq(
    tap_interface: str = "tap-c64",
    tap_address: str = "10.0.65.1",
    dhcp_range: tuple[str, str] = ("10.0.65.2", "10.0.65.10"),
    dns_records: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
    verbose: bool = True,
) -> subprocess.Popen:
    """Start dnsmasq providing DHCP and DNS on a TAP interface.

    Args:
        tap_interface: Network interface to bind to.
        tap_address: Listen address for dnsmasq.
        dhcp_range: (start, end) IP range for DHCP leases.
        dns_records: Mapping of hostname -> IP for --address entries.
        extra_args: Additional command-line arguments for dnsmasq.
        verbose: Print the command and PID.

    Returns:
        The Popen object for the dnsmasq process.

    Raises:
        RuntimeError: If dnsmasq exits immediately after launch.
    """
    if dns_records is None:
        dns_records = dict(DEFAULT_DNS_RECORDS)

    range_start, range_end = dhcp_range
    cmd = [
        "sudo", "dnsmasq",
        "--no-daemon",
        f"--interface={tap_interface}",
        "--bind-interfaces",
        f"--listen-address={tap_address}",
        f"--dhcp-range={range_start},{range_end},255.255.255.0,5m",
        f"--dhcp-option=6,{tap_address}",
        "--log-queries",
        "--no-resolv",
    ]
    for hostname, ip in dns_records.items():
        cmd.append(f"--address=/{hostname}/{ip}")
    if extra_args:
        cmd.extend(extra_args)

    if verbose:
        print(f"  dnsmasq cmd: {' '.join(cmd)}")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Give it a moment to bind ports.
    time.sleep(0.5)
    if proc.poll() is not None:
        _, stderr = proc.communicate()
        raise RuntimeError(f"dnsmasq failed to start: {stderr.decode()}")

    if verbose:
        print(f"  dnsmasq PID={proc.pid}")
    return proc


def stop_dnsmasq(proc: subprocess.Popen, timeout: int = 5) -> None:
    """Terminate a dnsmasq process gracefully, killing it if necessary.

    Args:
        proc: The Popen object returned by start_dnsmasq().
        timeout: Seconds to wait for graceful termination before killing.
    """
    if proc.poll() is not None:
        return  # Already exited.
    try:
        proc.terminate()
        try:
            proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    except OSError:
        pass  # Process already gone.


def _kill_stale_dnsmasq() -> None:
    """Kill any leftover dnsmasq processes. Errors are silently ignored."""
    try:
        subprocess.run(
            ["sudo", "killall", "dnsmasq"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# NetworkTestEnv context manager
# ---------------------------------------------------------------------------

class NetworkTestEnv:
    """Context manager that sets up and tears down the full network test environment.

    Manages:
    - TAP interface creation (optional, delegates to setup-tap-networking.sh)
    - dnsmasq lifecycle (DHCP + DNS)
    - Optional HTTP/HTTPS server via TestHTTPServer

    Example::

        with NetworkTestEnv(http_server=True, http_port=8080) as env:
            assert env.dnsmasq_proc.poll() is None  # running
            assert env.server is not None
            # ... run VICE tests ...
    """

    def __init__(
        self,
        tap_interface: str = "tap-c64",
        tap_address: str = "10.0.65.1",
        dhcp_range: tuple[str, str] = ("10.0.65.2", "10.0.65.10"),
        dns_records: dict[str, str] | None = None,
        extra_dnsmasq_args: list[str] | None = None,
        setup_tap: bool = True,
        teardown_tap: bool = False,
        http_server: bool = False,
        http_host: str = "10.0.65.1",
        http_port: int = 80,
        ssl_context: ssl.SSLContext | None = None,
        verbose: bool = True,
    ):
        self.tap_interface = tap_interface
        self.tap_address = tap_address
        self.dhcp_range = dhcp_range
        self.dns_records = dns_records if dns_records is not None else dict(DEFAULT_DNS_RECORDS)
        self.extra_dnsmasq_args = extra_dnsmasq_args
        self.setup_tap = setup_tap
        self.teardown_tap = teardown_tap
        self.http_server_enabled = http_server
        self.http_host = http_host
        self.http_port = http_port
        self.ssl_context = ssl_context
        self.verbose = verbose

        self._dnsmasq_proc: subprocess.Popen | None = None
        self._server: TestHTTPServer | None = None
        self._torn_down = False
        self._prev_sigint = None
        self._prev_sigterm = None

    # ---- Properties --------------------------------------------------------

    @property
    def dnsmasq_proc(self) -> subprocess.Popen | None:
        """The running dnsmasq Popen object, or None if not started."""
        return self._dnsmasq_proc

    @property
    def server(self) -> TestHTTPServer | None:
        """The running TestHTTPServer instance, or None if not started."""
        return self._server

    # ---- Prerequisite check ------------------------------------------------

    def check_prerequisites(self) -> list[str]:
        """Return a list of missing prerequisites. Empty list means all OK."""
        missing: list[str] = []
        if not self.setup_tap and not os.path.exists(
            TAP_SYSFS.format(iface=self.tap_interface)
        ):
            missing.append(f"{self.tap_interface} interface not found (and setup_tap=False)")
        if shutil.which("dnsmasq") is None:
            missing.append("dnsmasq not on PATH")
        if shutil.which("sudo") is None:
            missing.append("sudo not on PATH")
        if self.setup_tap and not os.path.isfile(SETUP_TAP_SCRIPT):
            missing.append(f"TAP setup script not found: {SETUP_TAP_SCRIPT}")
        return missing

    # ---- Setup / teardown --------------------------------------------------

    def setup(self) -> "NetworkTestEnv":
        """Set up the network test environment.

        1. Create TAP interface if needed.
        2. Kill stale dnsmasq processes.
        3. Start dnsmasq.
        4. Start HTTP server if requested.

        Returns self for chaining.
        """
        # Install signal handlers and atexit for safety.
        self._install_signal_handlers()
        atexit.register(self.teardown)

        # 1. TAP interface.
        tap_exists = os.path.exists(TAP_SYSFS.format(iface=self.tap_interface))
        if self.setup_tap and not tap_exists:
            if self.verbose:
                print(f"  Setting up TAP interface {self.tap_interface}...")
            result = subprocess.run(
                ["sudo", SETUP_TAP_SCRIPT],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"TAP setup failed (exit {result.returncode}):\n{result.stderr}"
                )
            if self.verbose:
                print(f"  TAP interface {self.tap_interface} created")
        elif tap_exists:
            if self.verbose:
                print(f"  TAP interface {self.tap_interface} already exists")
        else:
            if self.verbose:
                print(f"  Skipping TAP setup (setup_tap=False)")

        # 2. Kill stale dnsmasq.
        _kill_stale_dnsmasq()

        # 3. Start dnsmasq.
        if self.verbose:
            print("  Starting dnsmasq...")
        self._dnsmasq_proc = start_dnsmasq(
            tap_interface=self.tap_interface,
            tap_address=self.tap_address,
            dhcp_range=self.dhcp_range,
            dns_records=self.dns_records,
            extra_args=self.extra_dnsmasq_args,
            verbose=self.verbose,
        )

        # 4. HTTP server.
        if self.http_server_enabled:
            if self.verbose:
                proto = "HTTPS" if self.ssl_context else "HTTP"
                print(f"  Starting {proto} server on {self.http_host}:{self.http_port}...")
            self._server = TestHTTPServer(
                host=self.http_host,
                port=self.http_port,
                ssl_context=self.ssl_context,
            )
            self._server.start()
            if self.verbose:
                proto = "HTTPS" if self.ssl_context else "HTTP"
                print(f"  {proto} server listening on {self.http_host}:{self.http_port}")

        return self

    def teardown(self) -> None:
        """Tear down the network test environment. Idempotent."""
        if self._torn_down:
            return
        self._torn_down = True

        if self.verbose:
            print("  NetworkTestEnv teardown...")

        # Stop HTTP server.
        if self._server is not None:
            try:
                self._server.stop()
                if self.verbose:
                    proto = "HTTPS" if self.ssl_context else "HTTP"
                    print(f"  {proto} server stopped")
            except Exception as e:
                print(f"  WARNING: HTTP server stop failed: {e}")
            self._server = None

        # Stop dnsmasq.
        if self._dnsmasq_proc is not None:
            try:
                stop_dnsmasq(self._dnsmasq_proc)
                if self.verbose:
                    print(f"  dnsmasq stopped (exit={self._dnsmasq_proc.returncode})")
            except Exception as e:
                print(f"  WARNING: dnsmasq stop failed: {e}")
            self._dnsmasq_proc = None

        # Teardown TAP if requested.
        if self.teardown_tap:
            try:
                subprocess.run(
                    ["sudo", "ip", "link", "delete", self.tap_interface],
                    capture_output=True,
                )
                if self.verbose:
                    print(f"  TAP interface {self.tap_interface} removed")
            except Exception as e:
                print(f"  WARNING: TAP teardown failed: {e}")

        # Restore signal handlers.
        self._restore_signal_handlers()

        # Unregister atexit (best-effort; atexit doesn't support unregister,
        # but the idempotent guard above prevents double-teardown).

    # ---- Context manager protocol ------------------------------------------

    def __enter__(self) -> "NetworkTestEnv":
        return self.setup()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.teardown()

    # ---- Signal handling ---------------------------------------------------

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers that trigger teardown."""
        def _handler(signum, frame):
            self.teardown()
            # Re-raise with default handler so the process exits with the
            # correct signal status.
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)

        try:
            self._prev_sigint = signal.signal(signal.SIGINT, _handler)
            self._prev_sigterm = signal.signal(signal.SIGTERM, _handler)
        except (OSError, ValueError):
            # signal.signal can fail if not on the main thread.
            pass

    def _restore_signal_handlers(self) -> None:
        """Restore previous signal handlers."""
        try:
            if self._prev_sigint is not None:
                signal.signal(signal.SIGINT, self._prev_sigint)
                self._prev_sigint = None
            if self._prev_sigterm is not None:
                signal.signal(signal.SIGTERM, self._prev_sigterm)
                self._prev_sigterm = None
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_dns_record(value: str) -> tuple[str, str]:
    """Parse a 'host=ip' string into a (host, ip) tuple."""
    if "=" not in value:
        raise argparse.ArgumentTypeError(
            f"DNS record must be in host=ip format, got: {value!r}"
        )
    host, ip = value.split("=", 1)
    return host.strip(), ip.strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Set up network test environment for C64 VICE emulator tests.",
    )
    parser.add_argument(
        "--setup-tap", action="store_true", default=True,
        help="Set up TAP interface if it doesn't exist (default: True)",
    )
    parser.add_argument(
        "--no-setup-tap", action="store_false", dest="setup_tap",
        help="Skip TAP interface setup",
    )
    parser.add_argument(
        "--teardown-tap", action="store_true", default=False,
        help="Tear down TAP interface on exit",
    )
    parser.add_argument(
        "--dns-record", action="append", type=_parse_dns_record,
        metavar="HOST=IP", dest="dns_records",
        help="DNS record (repeatable). Default: c64test.local=10.0.65.1",
    )
    parser.add_argument(
        "--http-port", type=int, default=None,
        help="Start an HTTP server on this port",
    )
    parser.add_argument(
        "--https-port", type=int, default=None,
        help="Start an HTTPS server on this port (generates self-signed cert)",
    )
    parser.add_argument(
        "--wrap", nargs=argparse.REMAINDER, metavar="CMD",
        help="Run CMD with the environment set up, then teardown and exit",
    )
    parser.add_argument(
        "--quiet", action="store_true", default=False,
        help="Suppress verbose output",
    )

    args = parser.parse_args()

    # Build dns_records dict.
    dns_records: dict[str, str] | None = None
    if args.dns_records:
        dns_records = dict(args.dns_records)

    # Determine HTTP/HTTPS settings.
    http_server = args.http_port is not None or args.https_port is not None
    http_port = args.https_port or args.http_port or 80
    ssl_ctx: ssl.SSLContext | None = None

    if args.https_port is not None:
        import tempfile
        cert_dir = tempfile.mkdtemp(prefix="c64tls_")
        cert_path = os.path.join(cert_dir, "cert.pem")
        key_path = os.path.join(cert_dir, "key.pem")
        subprocess.run([
            "openssl", "req", "-new", "-x509",
            "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes",
            "-subj", "/CN=c64test.local",
        ], check=True, capture_output=True)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ssl_ctx.load_cert_chain(cert_path, key_path)
        if not args.quiet:
            print(f"Generated self-signed TLS cert in {cert_dir}")

    verbose = not args.quiet

    env = NetworkTestEnv(
        dns_records=dns_records,
        extra_dnsmasq_args=None,
        setup_tap=args.setup_tap,
        teardown_tap=args.teardown_tap,
        http_server=http_server,
        http_port=http_port,
        ssl_context=ssl_ctx,
        verbose=verbose,
    )

    # Check prerequisites before doing anything.
    missing = env.check_prerequisites()
    if missing:
        for m in missing:
            print(f"ERROR: {m}")
        return 1

    if args.wrap:
        # --wrap mode: setup, run command, teardown, exit with command's code.
        if not args.wrap:
            parser.error("--wrap requires a command")
        with env:
            if verbose:
                print(f"\n  Running: {' '.join(args.wrap)}")
            result = subprocess.run(args.wrap)
            return result.returncode
    else:
        # Interactive mode: setup, print status, wait for Ctrl+C.
        with env:
            proto = "HTTPS" if ssl_ctx else "HTTP" if http_server else None
            print(f"\n{'='*60}")
            print(f"Network test environment is running.")
            print(f"  TAP interface: {env.tap_interface}")
            print(f"  dnsmasq PID:   {env.dnsmasq_proc.pid}")
            if env.server is not None:
                print(f"  {proto} server:  {env.http_host}:{env.http_port}")
            print(f"  DNS records:   {env.dns_records}")
            print(f"{'='*60}")
            print(f"Press Ctrl+C to stop.\n")
            try:
                while True:
                    time.sleep(1.0)
            except KeyboardInterrupt:
                print("\nInterrupted.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
