import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from common import LabError, save_json  # noqa: E402
from lab import Lab, main  # noqa: E402


class OpenInstructionsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.lab = Lab(Path(directory.name))
        self.lab.runtime.mkdir(parents=True)
        host = {"public_ip": "192.0.2.1"}
        self.lab.context = {
            "phase": "deployed",
            "host": host,
            "identity": {"zone": "synthetic-zone"},
            "config": {"guest": {"vm_id": 110}},
        }
        save_json(self.lab.runtime / "yc.tfstate", {"outputs": {"host": {"value": host}}})
        save_json(self.lab.runtime / "proxmox.tfstate", {"outputs": {"guest_id": {"value": 110}}})
        save_json(self.lab.runtime / "credentials.json", {"ui_password": "synthetic-secret"})
        self.browser = patch("lab.open_browser").start()
        self.clipboard = patch("lab.copy_password").start()
        self.addCleanup(patch.stopall)
        self.output = io.StringIO()
        capture = contextlib.redirect_stdout(self.output)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)

    def test_no_context_rejects_open(self):
        self.lab.context = None
        with self.assertRaises(LabError):
            self.lab.open()

    def test_unfinished_deployment_rejects_open(self):
        self.lab.context["phase"] = "host-created"
        with self.assertRaises(LabError):
            self.lab.open()

    def test_host_state_mismatch_rejects_open(self):
        save_json(self.lab.runtime / "yc.tfstate", {})
        with self.assertRaisesRegex(LabError, "не совпадают"):
            self.lab.open()

    def test_guest_state_mismatch_rejects_open(self):
        save_json(self.lab.runtime / "proxmox.tfstate", {})
        with self.assertRaisesRegex(LabError, "гостя"):
            self.lab.open()

    def test_browser_login_and_authentication_type_are_separate_without_secret_output(self):
        for phase in ("deployed", "verified"):
            with self.subTest(phase=phase):
                self.lab.context["phase"] = phase
                self.lab.open()
        text = self.output.getvalue()
        self.assertIn("https://192.0.2.1:8006/", text)
        self.assertIn("User name: reviewer (без @pve)", text)
        self.assertIn("Realm (тип аутентификации): Proxmox VE authentication server (pve)", text)
        self.assertIn("Пароль скопирован", text)
        self.clipboard.assert_called_with("synthetic-secret")
        self.browser.assert_called_with("https://192.0.2.1:8006/")
        self.assertNotIn("synthetic-secret", text)
        self.assertNotIn("User name: reviewer@pve", text)

    def test_clipboard_error_has_safe_manual_fallback(self):
        self.clipboard.side_effect = LabError("Буфер недоступен")
        with self.assertRaises(LabError):
            self.lab.open()
        self.browser.assert_not_called()
        self.assertIn("Set-Clipboard", self.output.getvalue())
        self.assertNotIn("synthetic-secret", self.output.getvalue())

    def test_browser_opens_only_after_password_copy(self):
        events = []
        self.clipboard.side_effect = lambda password: events.append("clipboard")
        self.browser.side_effect = lambda url: events.append("browser")
        self.lab.open()
        self.assertEqual(events, ["clipboard", "browser"])

    def test_browser_failure_keeps_url_and_copied_password(self):
        self.browser.side_effect = LabError("Откройте URL вручную")
        with self.assertRaises(LabError):
            self.lab.open()
        self.clipboard.assert_called_once_with("synthetic-secret")
        self.assertIn("https://192.0.2.1:8006/", self.output.getvalue())
        self.assertNotIn("URL передан браузеру", self.output.getvalue())

    def test_ssh_checks_state_before_interactive_connection(self):
        with patch("lab.guest_shell") as shell:
            self.lab.ssh()
        shell.assert_called_once_with(
            self.lab.runtime, self.lab.context["host"], self.lab.context["config"]["guest"]
        )


class CommandTests(unittest.TestCase):
    def test_command_routing_without_cloud_auth_for_local_access(self):
        for command, profile, auth in (
            ("open", True, False),
            ("ssh", True, False),
            ("deploy", True, True),
            ("verify", False, False),
        ):
            arguments = ["lab.py", command] + (["--yc-profile"] if profile else [])
            with (
                patch("sys.argv", arguments),
                patch("lab.exclusive"),
                patch("lab.Lab") as lab,
                patch("lab.YC.from_profile") as yc,
            ):
                self.assertEqual(main(), 0)
                self.assertEqual(yc.called, auth)
                getattr(lab.return_value, command).assert_called_once_with()

    def test_command_failure_is_reported(self):
        with (
            patch("sys.argv", ["lab.py", "ssh"]),
            patch("lab.exclusive"),
            patch("lab.Lab") as lab,
            contextlib.redirect_stderr(io.StringIO()) as output,
        ):
            lab.return_value.ssh.side_effect = LabError("Ошибка доступа")
            self.assertEqual(main(), 1)
        self.assertIn("Ошибка доступа", output.getvalue())
