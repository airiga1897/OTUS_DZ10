import contextlib
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from common import LabError  # noqa: E402
from proxmox import ProxmoxAPI  # noqa: E402


def response(data):
    return io.StringIO(json.dumps({"data": data}))


class ProxmoxAPITests(unittest.TestCase):
    def setUp(self):
        self.api = ProxmoxAPI("192.0.2.1", "synthetic-secret")
        self.output = io.StringIO()
        output = contextlib.redirect_stdout(self.output)
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)
        self.now = 0
        clock = patch("proxmox.time.monotonic", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

        def advance(delay):
            self.now += delay

        sleep = patch("proxmox.time.sleep", side_effect=advance)
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def tearDown(self):
        self.assertNotIn("synthetic-secret", self.output.getvalue())

    def test_token_is_required(self):
        with self.assertRaises(LabError):
            ProxmoxAPI("192.0.2.1", "")

    def test_new_guest_is_configured_and_read_back_without_ssh(self):
        with patch(
            "proxmox.urllib.request.urlopen",
            side_effect=[
                response({}),
                response(None),
                response({"kvm": 0}),
            ],
        ) as call:
            self.api.disable_kvm("dz10-pve", 110)
        self.assertEqual(
            [c.args[0].get_method() for c in call.call_args_list], ["GET", "PUT", "GET"]
        )
        update = call.call_args_list[1].args[0]
        self.assertEqual(
            update.full_url, "https://192.0.2.1:8006/api2/json/nodes/dz10-pve/qemu/110/config"
        )
        self.assertEqual(update.data, b"kvm=0")
        self.assertEqual(update.get_header("Authorization"), "PVEAPIToken=synthetic-secret")

    def test_already_disabled_kvm_does_not_write_or_restart_guest(self):
        with patch("proxmox.urllib.request.urlopen", return_value=response({"kvm": "0"})) as call:
            self.api.disable_kvm("dz10-pve", 110)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.args[0].get_method(), "GET")

    def test_invalid_guest_configuration_is_not_written(self):
        with patch("proxmox.urllib.request.urlopen", return_value=response([])) as call:
            with self.assertRaises(LabError):
                self.api.disable_kvm("dz10-pve", 110)
        self.assertEqual(call.call_count, 1)

    def test_unconfirmed_update_prevents_success(self):
        for current in ({"kvm": 1}, None):
            with (
                self.subTest(current=current),
                patch(
                    "proxmox.urllib.request.urlopen",
                    side_effect=[
                        response({"kvm": 1}),
                        response(None),
                        response(current),
                    ],
                ),
            ):
                with self.assertRaisesRegex(LabError, "не подтвердил"):
                    self.api.disable_kvm("dz10-pve", 110)

    def test_transient_api_restart_is_retried(self):
        error = urllib.error.HTTPError("synthetic", 503, "synthetic-secret", {}, io.BytesIO())
        with patch(
            "proxmox.urllib.request.urlopen", side_effect=[error, response({"kvm": 0})]
        ) as call:
            self.api.disable_kvm("dz10-pve", 110)
        self.assertEqual(call.call_count, 2)
        self.sleep.assert_called_once_with(2)

    def test_permission_error_is_not_retried_or_disclosed(self):
        error = urllib.error.HTTPError("synthetic", 403, "synthetic-secret", {}, io.BytesIO())
        with patch("proxmox.urllib.request.urlopen", side_effect=error) as call:
            with self.assertRaisesRegex(LabError, "HTTP 403") as caught:
                self.api.disable_kvm("dz10-pve", 110)
        self.assertNotIn("synthetic-secret", str(caught.exception))
        self.assertEqual(call.call_count, 1)
        self.sleep.assert_not_called()

    def test_lost_put_response_repeats_only_idempotent_assignment(self):
        error = urllib.error.HTTPError("synthetic", 502, "synthetic-secret", {}, io.BytesIO())
        with patch(
            "proxmox.urllib.request.urlopen",
            side_effect=[
                response({"kvm": 1}),
                error,
                response(None),
                response({"kvm": 0}),
            ],
        ) as call:
            self.api.disable_kvm("dz10-pve", 110)
        self.assertEqual(
            [c.args[0].get_method() for c in call.call_args_list], ["GET", "PUT", "PUT", "GET"]
        )
        self.assertEqual(call.call_args_list[1].args[0].data, b"kvm=0")
        self.assertEqual(call.call_args_list[2].args[0].data, b"kvm=0")

    def test_connection_failures_are_bounded_and_sanitized(self):
        with patch(
            "proxmox.urllib.request.urlopen", side_effect=urllib.error.URLError("synthetic-secret")
        ) as call:
            with self.assertRaises(LabError) as caught:
                self.api.disable_kvm("dz10-pve", 110)
        self.assertEqual(call.call_count, 30)
        self.assertEqual(self.sleep.call_count, 30)
        self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_malformed_responses_never_confirm_success(self):
        for raw in ("not-json", "{}", "[]"):
            with (
                self.subTest(raw=raw),
                patch(
                    "proxmox.urllib.request.urlopen",
                    side_effect=[io.StringIO(raw) for _ in range(30)],
                ) as call,
            ):
                with self.assertRaises(LabError):
                    self.api.disable_kvm("dz10-pve", 110)
                self.assertEqual(call.call_count, 30)
