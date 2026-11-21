import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from common import LabError, check_plan, cleanup, merge_cidrs, save_json  # noqa: E402
from lab import Lab  # noqa: E402
from security import cloud_init, remove_legacy_ca  # noqa: E402
from yc import YC  # noqa: E402

PROJECT = Path(__file__).resolve().parents[1]


def load_function():
    spec = importlib.util.spec_from_file_location(
        "operator_function", PROJECT / "functions/operator_ip/main.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.handler


class AccessTests(unittest.TestCase):
    def test_https_session_uses_cookie_and_rejects_anonymous_access(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = Lab(Path(directory))
            instance.runtime.mkdir(parents=True)
            instance.context = {
                "host": {"public_ip": "192.0.2.1"},
                "config": {"guest": {"vm_id": 110}},
            }
            save_json(
                instance.runtime / "credentials.json",
                {
                    "ui_username": "reviewer@pve",
                    "ui_password": "synthetic",
                },
            )

            def response(data):
                return io.StringIO(json.dumps({"data": data}))

            with patch(
                "lab.urllib.request.urlopen",
                side_effect=[
                    response({"username": "reviewer@pve", "ticket": "synthetic:ticket"}),
                    response({"version": "9.2"}),
                    response([{"vmid": 110}]),
                    urllib.error.HTTPError("synthetic", 401, "denied", {}, None),
                ],
            ) as requests:
                instance.session_check()
                self.assertEqual(requests.call_count, 4)
                self.assertEqual(
                    requests.call_args_list[1].args[0].get_header("Cookie"),
                    "PVEAuthCookie=synthetic%3Aticket",
                )
                self.assertNotIn("Authorization", requests.call_args_list[1].args[0].headers)

    def test_legacy_ca_rejects_non_exact_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(LabError):
                remove_legacy_ca(Path(directory), ["OTUS*"])

    def test_legacy_ca_removes_only_exact_recorded_root(self):
        with tempfile.TemporaryDirectory() as directory:
            fingerprint = "A" * 40
            with (
                patch("security.os.name", "nt"),
                patch("security.run_powershell", side_effect=["True", "False"]) as probe,
                patch("security.run") as command,
            ):
                remove_legacy_ca(Path(directory), [fingerprint])
                command.assert_called_once_with(
                    ["certutil.exe", "-user", "-delstore", "Root", fingerprint]
                )
                for call in probe.call_args_list:
                    self.assertIn("Root\\" + fingerprint, call.args[0])

    def test_proxmox_credentials_use_password_api_and_reuse_token(self):
        spec = importlib.util.spec_from_file_location(
            "node_configure", PROJECT / "provision/configure.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            actual_path = Path
            calls = []

            def command(*args, **kwargs):
                calls.append(args)
                if args[:3] == ("pveum", "user", "list"):
                    return '[{"userid":"terraform@pve"},{"userid":"reviewer@pve"}]'
                if args[:4] == ("pveum", "user", "token", "list"):
                    return "[]"
                if args[:4] == ("pveum", "user", "token", "add"):
                    return '{"full-tokenid":"terraform@pve!dz10","value":"synthetic-token"}'
                if args[:3] == ("pveum", "acl", "modify") or args[:3] == (
                    "pvesh",
                    "set",
                    "/access/password",
                ):
                    return ""
                raise AssertionError("Unsupported Proxmox command")

            def path(value):
                return (
                    actual_path(directory) if str(value) == "/var/lib/dz10" else actual_path(value)
                )

            with (
                patch.object(module, "Path", side_effect=path),
                patch.object(module, "command", side_effect=command),
                patch.object(module.secrets, "token_urlsafe", return_value="synthetic-password"),
            ):
                first = module.credentials()
                second = module.credentials()
            self.assertEqual(first, second)
            self.assertEqual(sum(c[:4] == ("pveum", "user", "token", "add") for c in calls), 1)
            self.assertEqual(sum(c[:3] == ("pvesh", "set", "/access/password") for c in calls), 2)

    def test_operator_uses_existing_unprivileged_group_without_name_collision(self):
        cfg = json.loads((PROJECT / "config/lab.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            rendered = cloud_init(Path(directory), cfg)
        user = json.loads(rendered.split("\n", 1)[1])["users"][0]
        self.assertEqual(user["name"], "operator")
        self.assertEqual(user.get("primary_group"), "users")
        self.assertTrue(user["lock_passwd"])
        self.assertEqual(len(user["ssh_authorized_keys"]), 1)

    def test_profile_is_explicit_and_uses_only_own_clone(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / ".tools/bin/yc.exe"
            executable.parent.mkdir(parents=True)
            executable.touch()
            with (
                patch("yc.require_private_file") as privacy,
                patch(
                    "yc.run",
                    side_effect=["syntheticcloud\n", "syntheticfolder\n", "synthetic-token\n"],
                ) as cli,
            ):
                api = YC.from_profile(root)
            self.assertEqual(api.token, "synthetic-token")
            privacy.assert_called_once_with(root / ".local/yc/config.yaml")
            for call in cli.call_args_list:
                self.assertEqual(call.args[0][0], executable)
                self.assertEqual(call.args[0][2], root / ".local/yc/config.yaml")
                self.assertNotIn("YC_TOKEN", call.kwargs["env"])

    def test_partial_environment_does_not_read_profile(self):
        with (
            patch.dict("os.environ", {"YC_CLOUD_ID": "synthetic"}, clear=True),
            patch.object(YC, "from_profile") as profile,
            self.assertRaises(LabError),
        ):
            YC.from_env()
        profile.assert_not_called()

    def test_insecure_profile_rejected_before_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / ".tools/bin/yc.exe"
            executable.parent.mkdir(parents=True)
            executable.touch()
            with (
                patch("yc.require_private_file", side_effect=LabError("unsafe")),
                patch("yc.run") as cli,
                self.assertRaises(LabError),
            ):
                YC.from_profile(root)
            cli.assert_not_called()

    def test_function_uses_context_not_headers(self):
        handler = load_function()
        event = {
            "queryStringParameters": {"nonce": "a" * 64},
            "requestContext": {"identity": {"sourceIp": "8.8.8.8"}},
            "headers": {"X-Forwarded-For": "1.1.1.1"},
            "body": '{"ip":"1.1.1.1"}',
        }
        response = json.loads(handler(event, None)["body"])
        self.assertEqual(response, {"nonce": "a" * 64, "ip": "8.8.8.8"})
        event["requestContext"]["identity"]["sourceIp"] = "192.168.1.1"
        self.assertEqual(handler(event, None)["statusCode"], 422)
        event["queryStringParameters"]["nonce"] = "invalid"
        self.assertEqual(handler(event, None)["statusCode"], 400)

    def test_ip_validation_and_nonce(self):
        api = YC("cloud", "folder", "never-log-this")
        with patch("yc.secrets.token_hex", return_value="a" * 64):
            for payload in (
                {"nonce": "b" * 64, "ip": "8.8.8.8"},
                {"nonce": "a" * 64, "ip": "10.0.0.1"},
                {"nonce": "a" * 64, "ip": "2001:4860:4860::8888"},
            ):
                with (
                    patch.object(api, "request", return_value=payload),
                    self.assertRaises(LabError),
                ):
                    api.operator_ip("function")
            with patch.object(api, "request", return_value={"nonce": "a" * 64, "ip": "8.8.8.8"}):
                self.assertEqual(api.operator_ip("function"), "8.8.8.8")

    def test_access_additive_and_strict(self):
        self.assertEqual(
            merge_cidrs(["8.8.8.8/32"], ["1.1.1.1/32", "8.8.8.8/32"]), ["1.1.1.1/32", "8.8.8.8/32"]
        )
        for cidr in ("0.0.0.0/0", "8.8.8.0/24", "127.0.0.1/32", "10.0.0.1/32"):
            with self.assertRaises(LabError):
                merge_cidrs([cidr])


class PlanTests(unittest.TestCase):
    def test_delete_replace_unknown_rejected(self):
        for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
            with self.assertRaises(LabError):
                check_plan(
                    {"resource_changes": [{"address": "own", "change": {"actions": actions}}]}
                )
        with self.assertRaises(LabError):
            check_plan(
                {"resource_changes": [{"address": "foreign", "change": {"actions": ["update"]}}]},
                allowed={"own"},
            )

    def test_delete_plan_cannot_create(self):
        with self.assertRaises(LabError):
            check_plan(
                {"resource_changes": [{"address": "own", "change": {"actions": ["create"]}}]},
                destroy=True,
            )
        check_plan(
            {"resource_changes": [{"address": "own", "change": {"actions": ["delete"]}}]},
            destroy=True,
        )

    def test_cleanup_only_exact_temporary_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            runtime = root / ".local/runtime"
            runtime.mkdir(parents=True)
            (runtime / "secret").write_text("synthetic")
            save_json(root / ".local/observed-addresses.json", {"synthetic": ["8.8.8.8/32"]})
            for target in (root, root.parent, root / ".local", root / "other"):
                with self.assertRaises(LabError):
                    cleanup(root, target)
            cleanup(root, runtime)
            self.assertFalse(runtime.exists())
            self.assertTrue((root / ".local/observed-addresses.json").exists())


class FakeYC:
    cloud_id, folder_id = "synthetic-cloud", "synthetic-folder"
    token = "synthetic-token"

    def __init__(self, events):
        self.events = events
        self.ip = "8.8.8.8"
        self.fail_ip = False
        self.fail_audit = False

    def scope(self):
        self.events.append("scope")

    def preflight(self, cfg, owned):
        self.events.append("preflight")

    def operator_ip(self, function):
        self.events.append("ip")
        if self.fail_ip:
            raise LabError("Synthetic IP failure")
        return self.ip

    def get(self, *args, **kwargs):
        return None

    def audit_absent(self, resources, namespace):
        self.events.append("audit")
        if self.fail_audit:
            raise LabError("Synthetic API failure")


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((PROJECT / "config/lab.json").read_text())
        self.cfg["host"]["image_id"] = "synthetic-image"
        self.cfg["host"]["disk_type"] = "network-ssd"
        self.api = YC("cloud", "folder", "synthetic-token")
        self.catalog = {
            ("compute", "zones"): {"zones": [{"id": self.cfg["zone"], "status": "UP"}]},
            ("compute", "diskTypes"): {
                "diskTypes": [{"id": "network-ssd", "zoneIds": [self.cfg["zone"]]}]
            },
            ("compute", "images/synthetic-image"): {
                "status": "READY",
                "family": "debian-13",
                "minDiskSize": str(2**30),
            },
        }
        self.items = {}
        self.queries = []

    def get(self, service, path, **kwargs):
        self.queries.append((service, path))
        if service == "quota":
            return {"limit": 10**15, "usage": 0}
        return self.catalog[(service, path)]

    def preflight(self):
        with (
            patch.object(self.api, "scope"),
            patch.object(self.api, "get", side_effect=self.get),
            patch.object(self.api, "list", side_effect=lambda s, c: self.items.get((s, c), [])),
        ):
            self.api.preflight(self.cfg, set())

    def test_compatible_tuple(self):
        self.preflight()

    def test_replicated_ssd_catalog_without_zone_list_checks_zonal_quota(self):
        self.catalog[("compute", "diskTypes")]["diskTypes"][0].pop("zoneIds")
        self.preflight()

    def test_explicit_hdd_selection_checks_hdd_not_ssd_quota(self):
        self.cfg["host"]["disk_type"] = "network-hdd"
        self.catalog[("compute", "diskTypes")]["diskTypes"] = [{"id": "network-hdd"}]
        self.preflight()
        quota_paths = [path for service, path in self.queries if service == "quota"]
        self.assertTrue(any("compute.hddDisks.size." in path for path in quota_paths))
        self.assertFalse(any("compute.ssdDisks.size." in path for path in quota_paths))

    def test_disk_in_another_zone_rejected(self):
        self.catalog[("compute", "diskTypes")]["diskTypes"][0]["zoneIds"] = ["ru-central1-b"]
        with self.assertRaises(LabError):
            self.preflight()

    def test_no_automatic_disk_alternative(self):
        self.catalog[("compute", "diskTypes")]["diskTypes"] = [
            {"id": "network-hdd", "zoneIds": [self.cfg["zone"]]}
        ]
        with self.assertRaises(LabError):
            self.preflight()

    def test_subnet_conflict(self):
        self.items[("vpc", "subnets")] = [{"id": "foreign", "v4CidrBlocks": ["10.110.0.0/24"]}]
        with self.assertRaises(LabError):
            self.preflight()

    def test_unknown_or_failed_quota_response(self):
        original = self.get
        for quota_result in ({}, {"limit": 0, "usage": 0}):

            def get(service, path, _result=quota_result, **kwargs):
                return _result if service == "quota" else original(service, path, **kwargs)

            with (
                patch.object(self.api, "scope"),
                patch.object(self.api, "get", side_effect=get),
                patch.object(self.api, "list", return_value=[]),
                self.assertRaises(LabError),
            ):
                self.api.preflight(self.cfg, set())

    def test_unknown_namespace_resources_rejected(self):
        self.items[("compute", "instances")] = [
            {"id": "foreign", "labels": {"lab": self.cfg["namespace"]}}
        ]
        with self.assertRaises(LabError):
            self.preflight()


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        quiet = patch("builtins.print")
        quiet.start()
        self.addCleanup(quiet.stop)
        self.root = Path(self.directory.name).resolve()
        (self.root / "functions/operator_ip").mkdir(parents=True)
        (self.root / "functions/operator_ip/main.py").write_text("# synthetic function\n")
        self.cfg = json.loads((PROJECT / "config/lab.json").read_text())
        self.cfg["host"]["image_id"] = "synthetic-image"
        self.events, self.states, self.calls = [], {}, []
        self.cfg["admin_cidrs"] = []
        self.api = FakeYC(self.events)
        self.fail_module = None
        case = self

        class FakeTF:
            def __init__(self, root, runtime, module, env=None):
                self.runtime, self.module = runtime, module
                case.states.setdefault(module, [])

            def init(self):
                pass

            def resources(self):
                return case.states[self.module]

            def apply(self, variables, **kwargs):
                case.events.append(
                    self.module + ("-destroy" if kwargs.get("destroy") else "-apply")
                )
                case.calls.append((self.module, copy.deepcopy(variables), kwargs.copy()))
                if kwargs.get("destroy"):
                    case.states[self.module] = []
                    return
                if self.module == "yc":
                    case.states["yc"] = [
                        {"type": "yandex_function", "values": {"id": "synthetic-function"}}
                    ]
                else:
                    case.states["proxmox"] = [
                        {"type": "proxmox_virtual_environment_vm", "values": {"id": "110"}}
                    ]
                (self.runtime / (self.module + ".tfstate")).write_text("{}")
                if case.fail_module == self.module:
                    raise LabError("Synthetic apply failure")

            def output(self, name):
                if name == "function_id":
                    return "synthetic-function"
                return {
                    "id": "synthetic-host",
                    "public_ip": "8.8.4.4",
                    "private_ip": "10.110.0.10",
                    "disk_id": "synthetic-disk",
                }

        class FakeRemote:
            def __init__(self, *args):
                pass

            def connect(self):
                case.events.append("ssh")

            def configure(self, *args):
                case.events.append("configure")
                return {"api_token": "synthetic-token"}

            def command(self, value):
                case.events.append("qm" if "qm set" in value else "pve-api")
                return "[]"

            def close(self):
                pass

            def verify_guest(self):
                case.events.append("guest-verify")

        self.tf_factory, self.remote_factory = FakeTF, FakeRemote
        for target, value in (("lab.config", self.cfg),):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target in (
            "lab.remove_legacy_ca",
            "lab.Lab.tls_check",
            "lab.Lab.session_check",
            "lab.private_dir",
        ):
            patcher = patch(target)
            if target == "lab.remove_legacy_ca":
                patcher = patch(target, return_value="synthetic-thumbprint")
            patcher.start()
            self.addCleanup(patcher.stop)

    def lab(self):
        return Lab(
            self.root, yc=self.api, tf_factory=self.tf_factory, remote_factory=self.remote_factory
        )

    def test_deploy_order_and_additive_repeat(self):
        self.lab().deploy()
        self.assertLess(self.events.index("preflight"), self.events.index("yc-apply"))
        self.assertLess(self.events.index("ip"), self.events.index("configure"))
        self.assertLess(self.events.index("configure"), self.events.index("proxmox-apply"))
        calls = [c for c in self.calls if c[0] == "proxmox"]
        self.assertEqual([c[1]["start_guest"] for c in calls], [False, True])
        self.api.ip = "1.1.1.1"
        self.lab().deploy()
        self.assertEqual(
            self.lab().context["config"]["effective_admin_cidrs"], ["1.1.1.1/32", "8.8.8.8/32"]
        )

    def test_ip_failure_preserves_state_and_does_not_create_host(self):
        self.api.fail_ip = True
        with self.assertRaises(LabError):
            self.lab().deploy()
        self.assertTrue((self.root / ".local/runtime/yc.tfstate").exists())
        self.assertNotIn("configure", self.events)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][2]["target"], "yandex_function.operator_ip")

    def test_partial_guest_creation_retry(self):
        self.fail_module = "proxmox"
        with self.assertRaises(LabError):
            self.lab().deploy()
        self.assertTrue((self.root / ".local/runtime/proxmox.tfstate").exists())
        self.fail_module = None
        self.lab().deploy()
        self.assertEqual(self.lab().context["phase"], "deployed")

    def test_placement_is_not_overwritten(self):
        self.lab().deploy()
        self.cfg["zone"] = "ru-central1-b"
        with self.assertRaises(LabError):
            self.lab().deploy()

    def test_destroy_cycle_keeps_observations_without_ip_probe(self):
        self.lab().deploy()
        self.events.clear()
        self.api.fail_ip = True
        self.lab().destroy()
        self.assertNotIn("ip", self.events)
        self.assertLess(self.events.index("proxmox-destroy"), self.events.index("yc-destroy"))
        self.assertFalse((self.root / ".local/runtime").exists())
        self.api.fail_ip = False
        self.api.ip = "1.1.1.1"
        self.states.clear()
        self.lab().deploy()
        self.assertEqual(
            self.lab().context["config"]["effective_admin_cidrs"], ["1.1.1.1/32", "8.8.8.8/32"]
        )

    def test_failed_deletion_preserves_recovery(self):
        self.lab().deploy()
        self.api.fail_audit = True
        with self.assertRaises(LabError):
            self.lab().destroy()
        self.assertTrue((self.root / ".local/runtime/context.json").exists())
        self.assertTrue((self.root / ".local/runtime/credentials.json").exists())
        self.api.fail_audit = False
        self.events.clear()
        self.lab().destroy()
        self.assertNotIn("ssh", self.events)
        self.assertFalse((self.root / ".local/runtime").exists())

    def test_scope_mismatch_prevents_deletion(self):
        self.lab().deploy()
        self.events.clear()
        self.api.folder_id = "different-folder"
        with self.assertRaises(LabError):
            self.lab().destroy()
        self.assertNotIn("proxmox-destroy", self.events)


if __name__ == "__main__":
    unittest.main()
