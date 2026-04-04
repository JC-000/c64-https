#!/usr/bin/env python3
"""Unit tests for net_test_env.py.

All external dependencies (TAP interfaces, dnsmasq, VICE, subprocess) are mocked.
No sudo, no network, no VICE required.
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch, call


class TestSkipIfNoNetwork(unittest.TestCase):
    """Tests for the skip_if_no_network() helper."""

    @patch("net_test_env.shutil.which", return_value="/usr/bin/thing")
    @patch("net_test_env.os.path.exists", return_value=False)
    def test_skip_if_no_network_missing_tap(self, mock_exists, mock_which):
        from net_test_env import skip_if_no_network
        self.assertTrue(skip_if_no_network())
        mock_exists.assert_called_once_with("/sys/class/net/tap-c64")

    @patch("net_test_env.shutil.which", return_value="/usr/bin/thing")
    @patch("net_test_env.os.path.exists", return_value=True)
    def test_skip_if_no_network_all_present(self, mock_exists, mock_which):
        from net_test_env import skip_if_no_network
        self.assertFalse(skip_if_no_network())

    @patch("net_test_env.shutil.which")
    @patch("net_test_env.os.path.exists", return_value=True)
    def test_skip_if_no_network_missing_dnsmasq(self, mock_exists, mock_which):
        from net_test_env import skip_if_no_network

        def which_side_effect(name):
            if name == "dnsmasq":
                return None
            return "/usr/bin/" + name

        mock_which.side_effect = which_side_effect
        self.assertTrue(skip_if_no_network())


class TestCheckPrerequisites(unittest.TestCase):
    """Tests for NetworkTestEnv.check_prerequisites()."""

    @patch("net_test_env.shutil.which", return_value="/usr/bin/thing")
    @patch("net_test_env.os.path.exists", return_value=False)
    @patch("net_test_env.os.path.isfile", return_value=True)
    def test_check_prerequisites_missing_tap(self, mock_isfile, mock_exists, mock_which):
        from net_test_env import NetworkTestEnv
        env = NetworkTestEnv(setup_tap=False)
        missing = env.check_prerequisites()
        self.assertTrue(any("interface not found" in m for m in missing))

    @patch("net_test_env.shutil.which")
    @patch("net_test_env.os.path.exists", return_value=True)
    @patch("net_test_env.os.path.isfile", return_value=True)
    def test_check_prerequisites_missing_dnsmasq(self, mock_isfile, mock_exists, mock_which):
        from net_test_env import NetworkTestEnv

        def which_side_effect(name):
            if name == "dnsmasq":
                return None
            return "/usr/bin/" + name

        mock_which.side_effect = which_side_effect
        env = NetworkTestEnv(setup_tap=False)
        missing = env.check_prerequisites()
        self.assertTrue(any("dnsmasq" in m for m in missing))


class TestStartDnsmasq(unittest.TestCase):
    """Tests for start_dnsmasq() command construction."""

    @patch("net_test_env.time.sleep")
    @patch("net_test_env.subprocess.Popen")
    def test_start_dnsmasq_command_construction(self, mock_popen_cls, mock_sleep):
        from net_test_env import start_dnsmasq

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 12345
        mock_popen_cls.return_value = mock_proc

        dns = {"example.local": "10.0.65.1", "other.local": "10.0.65.2"}
        start_dnsmasq(dns_records=dns, verbose=False)

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("--address=/example.local/10.0.65.1", cmd)
        self.assertIn("--address=/other.local/10.0.65.2", cmd)
        self.assertIn("--interface=tap-c64", cmd)
        self.assertIn("sudo", cmd)

    @patch("net_test_env.time.sleep")
    @patch("net_test_env.subprocess.Popen")
    def test_start_dnsmasq_extra_args(self, mock_popen_cls, mock_sleep):
        from net_test_env import start_dnsmasq

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 12345
        mock_popen_cls.return_value = mock_proc

        start_dnsmasq(extra_args=["--port=5353", "--bogus-priv"], verbose=False)

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("--port=5353", cmd)
        self.assertIn("--bogus-priv", cmd)


class TestStopDnsmasq(unittest.TestCase):
    """Tests for stop_dnsmasq()."""

    def test_stop_dnsmasq_already_exited(self):
        from net_test_env import stop_dnsmasq

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0
        stop_dnsmasq(mock_proc)
        mock_proc.terminate.assert_not_called()

    def test_stop_dnsmasq_graceful(self):
        from net_test_env import stop_dnsmasq

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.communicate.return_value = (b"", b"")
        stop_dnsmasq(mock_proc)
        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_not_called()

    def test_stop_dnsmasq_timeout_kills(self):
        from net_test_env import stop_dnsmasq

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="dnsmasq", timeout=5)
        stop_dnsmasq(mock_proc, timeout=5)
        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()


class TestContextManager(unittest.TestCase):
    """Tests for NetworkTestEnv as a context manager."""

    @patch("net_test_env.TestHTTPServer")
    @patch("net_test_env._kill_stale_dnsmasq")
    @patch("net_test_env.start_dnsmasq")
    @patch("net_test_env.stop_dnsmasq")
    @patch("net_test_env.os.path.exists", return_value=True)
    def test_context_manager_teardown_on_exception(
        self, mock_exists, mock_stop, mock_start, mock_kill, mock_http_cls
    ):
        from net_test_env import NetworkTestEnv

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_start.return_value = mock_proc

        try:
            with NetworkTestEnv(setup_tap=False, verbose=False) as env:
                raise ValueError("boom")
        except ValueError:
            pass

        mock_stop.assert_called_once_with(mock_proc)

    @patch("net_test_env.TestHTTPServer")
    @patch("net_test_env._kill_stale_dnsmasq")
    @patch("net_test_env.start_dnsmasq")
    @patch("net_test_env.stop_dnsmasq")
    @patch("net_test_env.os.path.exists", return_value=True)
    def test_teardown_idempotent(
        self, mock_exists, mock_stop, mock_start, mock_kill, mock_http_cls
    ):
        from net_test_env import NetworkTestEnv

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_start.return_value = mock_proc

        env = NetworkTestEnv(setup_tap=False, verbose=False)
        env.setup()
        env.teardown()
        env.teardown()  # second call should be a no-op

        mock_stop.assert_called_once_with(mock_proc)


class TestDnsRecordsDefault(unittest.TestCase):
    """Test default DNS records."""

    def test_dns_records_default(self):
        from net_test_env import NetworkTestEnv
        env = NetworkTestEnv()
        self.assertEqual(env.dns_records, {"c64test.local": "10.0.65.1"})


class TestHTTPServerStarted(unittest.TestCase):
    """Test that HTTP server is started when http_server=True."""

    @patch("net_test_env.TestHTTPServer")
    @patch("net_test_env._kill_stale_dnsmasq")
    @patch("net_test_env.start_dnsmasq")
    @patch("net_test_env.os.path.exists", return_value=True)
    def test_http_server_started_when_enabled(
        self, mock_exists, mock_start, mock_kill, mock_http_cls
    ):
        from net_test_env import NetworkTestEnv

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 99
        mock_start.return_value = mock_proc

        mock_server = MagicMock()
        mock_http_cls.return_value = mock_server

        env = NetworkTestEnv(setup_tap=False, http_server=True, verbose=False)
        env.setup()

        mock_http_cls.assert_called_once_with(
            host="10.0.65.1", port=80, ssl_context=None
        )
        mock_server.start.assert_called_once()

        env.teardown()


if __name__ == "__main__":
    unittest.main()
