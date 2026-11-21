import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from common import LabError, save_json  # noqa: E402
from lab import Lab  # noqa: E402


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
        self.assertIn("Set-Clipboard", text)
        self.assertNotIn("synthetic-secret", text)
        self.assertNotIn("User name: reviewer@pve", text)
