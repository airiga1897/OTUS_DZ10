import contextlib
import io
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from access import copy_password, guest_shell  # noqa: E402
from common import LabError  # noqa: E402
from security import ssh_key  # noqa: E402

NATIVE_RUN = subprocess.run


class ClipboardTests(unittest.TestCase):
    def test_password_only_on_stdin(self):
        with patch("access.subprocess.run", return_value=SimpleNamespace(returncode=0)) as run:
            copy_password("synthetic-secret")
        args, kwargs = run.call_args
        self.assertNotIn("synthetic-secret", str(args))
        self.assertEqual(kwargs["input"], "synthetic-secret")
        self.assertTrue(kwargs["capture_output"])
        self.assertEqual(kwargs["timeout"], 15)

    def test_missing_password(self):
        for value in (None, "", 42):
            with self.subTest(value=value), self.assertRaises(LabError):
                copy_password(value)

    def test_errors_are_sanitized(self):
        for error in (
            OSError("synthetic-secret"),
            subprocess.TimeoutExpired("synthetic-secret", 15),
        ):
            with patch("access.subprocess.run", side_effect=error):
                with self.assertRaises(LabError) as caught:
                    copy_password("synthetic-secret")
                self.assertNotIn("synthetic-secret", str(caught.exception))
        with patch("access.subprocess.run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(LabError):
                copy_password("synthetic-secret")


class GuestShellTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dz10 test ")
        self.addCleanup(temporary.cleanup)
        self.runtime = Path(temporary.name)
        self.host = {"public_ip": "192.0.2.1"}
        self.guest = {"address": "10.111.0.10/24", "username": "student"}
        for name in ("operator", "pve-host", "guest-host"):
            ssh_key(self.runtime / name)
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stdout(self.output)
        self.capture.__enter__()
        self.addCleanup(self.capture.__exit__, None, None, None)
        self.run = patch(
            "access.subprocess.run", return_value=SimpleNamespace(returncode=0)
        ).start()
        self.addCleanup(patch.stopall)

    def connect(self):
        guest_shell(self.runtime, self.host, self.guest)

    def test_pinned_hops_terminal_and_recreated_guest(self):
        self.connect()
        first = (self.runtime / "interactive-known-hosts").read_text()
        (self.runtime / "guest-host").unlink()
        replacement = ssh_key(self.runtime / "guest-host")
        self.connect()
        known = (self.runtime / "interactive-known-hosts").read_text()
        self.assertNotEqual(first, known)
        self.assertIn("dz10-guest " + replacement, known)
        config = (self.runtime / "interactive-ssh.conf").read_text()
        for setting in (
            "StrictHostKeyChecking yes",
            "BatchMode yes",
            "ProxyJump dz10-node",
            "HostKeyAlias dz10-node",
            "HostKeyAlias dz10-guest",
            "GlobalKnownHostsFile none",
        ):
            self.assertIn(setting, config)
        self.assertIn(f'IdentityFile "{self.runtime.resolve().as_posix()}/operator"', config)
        self.assertEqual(
            self.run.call_args.args[0],
            ["ssh", "-F", str(self.runtime.resolve() / "interactive-ssh.conf"), "-t", "dz10-guest"],
        )
        self.assertEqual(self.run.call_args.kwargs, {"check": False})
        self.assertIn("exit или Ctrl+D", self.output.getvalue())

    def test_invalid_username(self):
        self.guest["username"] = "student\nProxyCommand evil"
        with self.assertRaises(LabError):
            self.connect()
        self.run.assert_not_called()

    def test_missing_key_does_not_regenerate(self):
        (self.runtime / "guest-host").unlink()
        with self.assertRaises(LabError):
            self.connect()
        self.assertFalse((self.runtime / "guest-host").exists())

    def test_symlink_rejected(self):
        with patch("pathlib.Path.is_symlink", return_value=True):
            with self.assertRaises(LabError):
                self.connect()

    def test_invalid_path(self):
        with patch("pathlib.Path.as_posix", return_value='invalid"path'):
            with self.assertRaises(LabError):
                self.connect()

    def test_native_ssh_failure_and_host_key_rejection(self):
        self.run.return_value.returncode = 255
        with self.assertRaises(LabError):
            self.connect()
        self.run.side_effect = OSError("synthetic-secret")
        with self.assertRaises(LabError) as caught:
            self.connect()
        self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_native_openssh_parses_both_hops(self):
        self.connect()
        # Save the unmocked runner before setUp patches subprocess.run.
        for alias, address, user in (
            ("dz10-node", "192.0.2.1", "operator"),
            ("dz10-guest", "10.111.0.10", "student"),
        ):
            result = NATIVE_RUN(
                ["ssh", "-G", "-F", str(self.runtime / "interactive-ssh.conf"), alias],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            self.assertIn("hostname " + address, result.stdout)
            self.assertIn("user " + user, result.stdout)
            self.assertIn("stricthostkeychecking true", result.stdout)
            self.assertIn("batchmode yes", result.stdout)
            if alias == "dz10-guest":
                self.assertIn("proxyjump dz10-node", result.stdout)


class NativeHostKeyTests(unittest.TestCase):
    def test_unexpected_remote_key_is_rejected_without_prompt(self):
        with (
            tempfile.TemporaryDirectory(prefix="dz10 native ") as directory,
            patch("paramiko.transport.Transport._log"),
        ):
            runtime = Path(directory)
            for name in ("operator", "pve-host", "guest-host", "unexpected-host"):
                ssh_key(runtime / name)
            with (
                patch("access.subprocess.run", return_value=SimpleNamespace(returncode=0)),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                guest_shell(
                    runtime,
                    {"public_ip": "127.0.0.1"},
                    {"address": "10.111.0.10/24", "username": "student"},
                )
            server_key = paramiko.Ed25519Key.from_private_key(
                io.StringIO((runtime / "unexpected-host").read_text())
            )
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(5)
                finished = threading.Event()

                def serve():
                    connection, _ = listener.accept()
                    transport = paramiko.Transport(connection)
                    transport.add_server_key(server_key)
                    try:
                        transport.start_server(server=paramiko.ServerInterface())
                        finished.wait(5)
                    except (EOFError, OSError, paramiko.SSHException):
                        pass
                    finally:
                        transport.close()

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                try:
                    result = NATIVE_RUN(
                        [
                            "ssh",
                            "-F",
                            str(runtime / "interactive-ssh.conf"),
                            "-p",
                            str(listener.getsockname()[1]),
                            "dz10-node",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=8,
                    )
                    self.assertEqual(result.returncode, 255)
                    self.assertIn("HOST IDENTIFICATION HAS CHANGED", result.stderr)
                    self.assertNotIn("yes/no", result.stderr)
                finally:
                    finished.set()
                    worker.join(6)
                self.assertFalse(worker.is_alive())
