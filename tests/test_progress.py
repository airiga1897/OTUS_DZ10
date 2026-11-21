import contextlib
import hashlib
import io
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from common import LabError  # noqa: E402
from progress import Stage  # noqa: E402
from remote import Remote, SSHDisconnected  # noqa: E402

from terraform import Terraform  # noqa: E402


class ProgressTests(unittest.TestCase):
    def test_heartbeat_is_visible_before_operation_finishes(self):
        visible = threading.Event()

        def output(message, **kwargs):
            if "[ожидание]" in message:
                self.assertTrue(kwargs["flush"])
                visible.set()

        with patch("progress.print", side_effect=output), Stage("Установка", interval=0.01):
            self.assertTrue(visible.wait(2), "No progress while the operation is blocked")

    def test_fragmented_markers_do_not_disclose_raw_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), Stage("Настройка") as stage:
            stage.feed(b"DZ10_PRO")
            stage.feed(b"GRESS:accounts\npassword=synthetic-secret\n")
            stage.feed(b"DZ10_PROGRESS:synthetic-secret\n")
            stage.feed(b"prefix DZ10_PROGRESS:image\n")
        self.assertIn("Настройка учётных записей", output.getvalue())
        self.assertNotIn("synthetic-secret", output.getvalue())
        self.assertNotIn("образа Debian", output.getvalue())

    def test_failed_stage_does_not_report_success_or_exception_content(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
            with Stage("Настройка"):
                raise RuntimeError("synthetic-secret")
        self.assertIn("[ошибка]", output.getvalue())
        self.assertNotIn("[готово]", output.getvalue())
        self.assertNotIn("synthetic-secret", output.getvalue())


class FakeChannel:
    def __init__(self, exit_code=0):
        self.step = 0
        self.exit_code = exit_code
        self.out = b'{"api_token":"synthetic-secret"}'
        self.errors = [b"DZ10_PRO", b"GRESS:accounts\nsynthetic-secret\n"]

    def recv_ready(self):
        return bool(self.out)

    def recv(self, count):
        result, self.out = self.out, b""
        return result

    def recv_stderr_ready(self):
        return bool(self.errors)

    def recv_stderr(self, count):
        return self.errors.pop(0)

    def exit_status_ready(self):
        return not self.errors and self.step > 1

    def recv_exit_status(self):
        return self.exit_code


class RemoteProgressTests(unittest.TestCase):
    def run_command(self, exit_code):
        channel = FakeChannel(exit_code)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            remote = Remote(Path(directory), "192.0.2.1", {})
            remote.client = SimpleNamespace(
                exec_command=lambda *a, **kw: (
                    SimpleNamespace(channel=SimpleNamespace(shutdown_write=lambda: None)),
                    SimpleNamespace(channel=channel),
                    None,
                )
            )

            def advance(_):
                channel.step += 1
                if not channel.errors:
                    self.assertIn("Настройка учётных записей", output.getvalue())
                    self.assertNotIn("[готово]", output.getvalue())

            with (
                contextlib.redirect_stdout(output),
                patch("remote.time.sleep", side_effect=advance),
            ):
                if exit_code:
                    with self.assertRaises(LabError):
                        remote.command("synthetic command", progress="Настройка")
                    self.assertTrue((Path(directory) / "remote-error.log").exists())
                    result = None
                else:
                    result = remote.command("synthetic command", progress="Настройка")
        self.assertNotIn("synthetic-secret", output.getvalue())
        return output.getvalue(), result

    def test_ssh_reports_progress_before_completion_and_keeps_credentials_private(self):
        output, result = self.run_command(0)
        self.assertIn("[готово]", output)
        self.assertIn("synthetic-secret", result)

    def test_ssh_failure_preserves_log_without_false_success(self):
        output, _ = self.run_command(1)
        self.assertIn("[ошибка]", output)
        self.assertNotIn("[готово]", output)


class DurableJobTests(unittest.TestCase):
    active = {"LoadState": "loaded", "ActiveState": "activating", "SubState": "start"}
    complete = {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "exited",
        "ExecMainStatus": "0",
    }
    missing = {"LoadState": "not-found"}

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.remote = Remote(Path(directory.name), "192.0.2.1", {})
        self.command = "/bin/bash /synthetic-install.sh"
        self.digest = hashlib.sha256(self.command.encode()).hexdigest()
        self.calls = []
        self.definitions = []
        self.remote.connect = Mock()
        self.remote.close = Mock()
        self.remote.upload = Mock()
        self.remote.command = self.command_result

    def command_result(self, command, **kwargs):
        self.calls.append(command)
        if command.endswith(".sha256"):
            return self.digest
        if "grep " in command:
            return "DZ10_PROGRESS:accounts\nDZ10_PROGRESS:synthetic-secret\n"
        if command.endswith(".stdout"):
            return '{"api_token":"synthetic-secret"}'
        if command.endswith(".stderr"):
            return "synthetic failure details"
        if "tee /etc/systemd/system" in command:
            self.definitions.append(kwargs["payload"])
        return ""

    def execute(self, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("remote.time.sleep"):
            result = self.remote.run_job("install", self.command, [], **kwargs)
        self.assertNotIn("synthetic-secret", output.getvalue())
        return result, output.getvalue()

    def test_running_job_survives_disconnect_without_parallel_start(self):
        self.remote.job_status = Mock(
            side_effect=[self.active, SSHDisconnected("reset"), self.complete]
        )
        result, output = self.execute()
        self.assertIn("synthetic-secret", result)
        self.remote.connect.assert_called_once()
        self.remote.upload.assert_not_called()
        self.assertFalse(any("systemctl start" in c for c in self.calls))
        self.assertIn("Переподключение", output)

    def test_clean_install_uses_systemd_and_waits_for_queued_start(self):
        queued = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "Job": "42 dz10-install.service",
        }
        self.remote.job_status = Mock(
            side_effect=[self.missing, self.missing, queued, self.complete]
        )
        self.execute()
        self.assertEqual(sum("systemctl start --no-block" in c for c in self.calls), 1)
        self.assertIn("Type=oneshot", self.definitions[0])
        self.assertIn("RemainAfterExit=yes", self.definitions[0])
        self.assertIn("UMask=0077", self.definitions[0])
        self.assertIn("StandardOutput=truncate:/var/lib/dz10/install.stdout", self.definitions[0])

    def test_lost_start_acknowledgement_is_not_replayed(self):
        self.remote.job_status = Mock(side_effect=[self.missing, self.missing, self.complete])
        original = self.remote.command

        def lose_ack(command, **kwargs):
            result = original(command, **kwargs)
            if "systemctl start --no-block" in command:
                raise SSHDisconnected("reset")
            return result

        self.remote.command = lose_ack
        self.execute()
        self.remote.connect.assert_called_once()
        self.assertEqual(sum("systemctl start --no-block" in c for c in self.calls), 1)

    def test_retry_reuses_queued_job_instead_of_cancelling_it(self):
        queued = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "Job": "42 dz10-install.service",
        }
        self.remote.job_status = Mock(side_effect=[queued, queued, self.complete])
        self.execute()
        self.assertFalse(any("systemctl start" in c or "systemctl stop" in c for c in self.calls))

    def test_other_active_job_prevents_uploads_or_stopping_services(self):
        self.remote.job_status = Mock(side_effect=[self.missing, self.active])
        with self.assertRaises(LabError):
            self.execute()
        self.remote.upload.assert_not_called()
        self.assertFalse(any("systemctl stop" in c for c in self.calls))

    def test_changed_configuration_cannot_overwrite_active_job(self):
        self.remote.job_status = Mock(return_value=self.active)
        self.digest = "different"
        with self.assertRaises(LabError):
            self.execute()
        self.remote.upload.assert_not_called()
        self.assertEqual(len(self.calls), 1)

    def test_job_failure_preserves_log_and_does_not_report_success(self):
        failed = {"LoadState": "loaded", "ActiveState": "failed", "ExecMainStatus": "1"}
        self.remote.job_status = Mock(side_effect=[self.active, failed])
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(LabError):
            self.execute()
        self.assertTrue((self.remote.runtime / "remote-error.log").exists())
        self.assertNotIn("[готово]", output.getvalue())

    def test_client_timeout_keeps_server_job_running(self):
        self.remote.job_status = Mock(return_value=self.active)
        with self.assertRaises(LabError):
            self.execute(timeout=0)
        self.assertFalse(any("systemctl stop" in c for c in self.calls))


class OfflineTerraformTests(unittest.TestCase):
    def test_init_uses_local_provider_cache_with_readonly_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / ".local/runtime"
            runtime.mkdir(parents=True)
            module = root / "terraform/yc"
            module.mkdir(parents=True)
            (module / ".terraform.lock.hcl").write_text("synthetic lock")
            terraform = Terraform(root, runtime, "yc")
            with patch.object(terraform, "call") as call:
                terraform.init()
            self.assertNotIn("TF_PLUGIN_CACHE_DIR", terraform.env)
            args = call.call_args.args
            self.assertIn("-lockfile=readonly", args)
            self.assertIn(f"-plugin-dir={(root / '.tools/provider-cache').as_posix()}", args)
