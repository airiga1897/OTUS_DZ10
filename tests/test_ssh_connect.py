import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import paramiko  # noqa: E402
from common import LabError  # noqa: E402
from remote import Remote, SSHDisconnected, SSHUnavailable  # noqa: E402


class SSHConnectTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.remote = Remote(
            Path(directory.name),
            "192.0.2.1",
            {
                "timeouts": {"host_seconds": 60, "poll_seconds": 1},
                "effective_admin_cidrs": ["8.8.8.8/32"],
            },
        )
        self.remote.command = Mock(return_value="8.8.8.8 12345 192.0.2.1 22")
        self.first, self.second = Mock(), Mock()
        for target, options in (
            ("remote.ssh_key", {"return_value": "ssh-ed25519 synthetic-public-key"}),
            ("remote.paramiko.SSHClient", {"side_effect": [self.first, self.second]}),
            ("remote.time.sleep", {}),
        ):
            patched = patch(target, **options)
            setattr(self, target.rsplit(".", 1)[-1], patched.start())
            self.addCleanup(patched.stop)
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def test_eof_during_handshake_retries_and_keeps_pinned_host_key(self):
        self.first.connect.side_effect = EOFError()
        self.assertIs(self.remote.connect(), self.remote)
        self.first.close.assert_called_once()
        self.second.load_host_keys.assert_called_once_with(str(self.remote.runtime / "known_hosts"))
        self.second.get_transport.return_value.set_keepalive.assert_called_once_with(15)
        self.assertEqual(self.sleep.call_count, 1)

    def test_temporary_socket_error_is_retried(self):
        self.first.connect.side_effect = ConnectionResetError(10054, "synthetic reset")
        self.remote.connect(timeout=10)
        self.first.close.assert_called_once()
        self.second.connect.assert_called_once()

    def test_temporary_ssh_error_is_retried(self):
        self.first.connect.side_effect = paramiko.SSHException("synthetic startup")
        self.remote.connect()
        self.second.connect.assert_called_once()

    def test_disconnect_while_reading_client_address_is_retried(self):
        self.remote.command.side_effect = [SSHDisconnected("synthetic reset"), "8.8.8.8 1 2 22"]
        self.remote.connect()
        self.first.close.assert_called_once()
        self.second.connect.assert_called_once()

    def test_handshake_eof_exhausts_deadline_as_controlled_error(self):
        self.first.connect.side_effect = EOFError()
        with patch("remote.time.monotonic", side_effect=[0, 0, 0, 11]):
            with self.assertRaises(SSHUnavailable):
                self.remote.connect(timeout=10)
        self.first.close.assert_called_once()
        self.second.connect.assert_not_called()

    def test_bad_host_key_is_fatal_and_not_retried(self):
        self.first.connect.side_effect = paramiko.BadHostKeyException("192.0.2.1", Mock(), Mock())
        with self.assertRaisesRegex(LabError, "закреплённому"):
            self.remote.connect()
        self.first.close.assert_called_once()
        self.second.connect.assert_not_called()
        self.sleep.assert_not_called()

    def test_unapproved_ssh_source_is_fatal_without_widening_access(self):
        self.remote.command.return_value = "1.1.1.1 12345 192.0.2.1 22"
        with self.assertRaisesRegex(LabError, "разрешённых"):
            self.remote.connect()
        self.assertEqual(self.remote.cfg["effective_admin_cidrs"], ["8.8.8.8/32"])
        self.second.connect.assert_not_called()
