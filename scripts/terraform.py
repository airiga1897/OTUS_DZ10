import json
import os

from common import LabError, check_plan, run, save_json

YC_ADDRESSES = {
    "yandex_function.operator_ip",
    "yandex_compute_instance.proxmox",
    "yandex_compute_disk.guests",
    "yandex_compute_disk.boot",
    "yandex_vpc_network.lab",
    "yandex_vpc_subnet.lab",
    "yandex_vpc_security_group.admin",
}
PVE_ADDRESSES = {"proxmox_virtual_environment_vm.guest"}


class Terraform:
    def __init__(self, root, runtime, module, env=None):
        self.root, self.runtime, self.module = root, runtime, module
        self.directory = root / "terraform" / module
        self.state = runtime / f"{module}.tfstate"
        self.executable = root / ".tools" / ("terraform.exe" if os.name == "nt" else "terraform")
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("TF_CLI_ARGS", "TF_LOG", "PROXMOX_VE_", "YC_"))
        }
        if module == "yc":
            self.env["YC_TOKEN"] = os.environ.get("YC_TOKEN", "")
        self.env.update(env or {})
        self.env["TF_IN_AUTOMATION"] = "1"
        self.env["TF_WORKSPACE"] = "default"
        cache = root / ".tools/provider-cache"
        cache.mkdir(parents=True, exist_ok=True)
        self.env["TF_PLUGIN_CACHE_DIR"] = str(cache)
        cli_config = runtime / "terraform.rc"
        cli_config.write_text(
            "disable_checkpoint = true\nprovider_installation {\n  direct {}\n}\n"
        )
        self.env["TF_CLI_CONFIG_FILE"] = str(cli_config)
        # Explicit module-local backend metadata, without reading the user's TF_DATA_DIR.
        self.env["TF_DATA_DIR"] = str(runtime / (module + "-data"))
        self.allowed = YC_ADDRESSES if module == "yc" else PVE_ADDRESSES

    def call(self, *args):
        return run([self.executable, f"-chdir={self.directory}", *args], env=self.env)

    def init(self):
        if not (self.directory / ".terraform.lock.hcl").exists():
            raise LabError("Отсутствует lock-файл Terraform")
        self.call(
            "init",
            "-input=false",
            "-lockfile=readonly",
            "-reconfigure",
            f"-backend-config=path={self.state.as_posix()}",
        )

    def resources(self):
        if not self.state.exists():
            return []
        state = json.loads(self.call("show", "-json", self.state))
        resources = state.get("values", {}).get("root_module", {}).get("resources", [])
        if any(r["address"] not in self.allowed for r in resources):
            raise LabError("State содержит неизвестные ресурсы")
        return resources

    def apply(self, variables, *, target=None, destroy=False, unchanged=False):
        path = self.runtime / f"{self.module}-vars.json"
        save_json(path, variables)
        plan = self.runtime / f"{self.module}.tfplan"
        args = ["plan", "-input=false", f"-var-file={path}", f"-out={plan}"]
        if target:
            if target != "yandex_function.operator_ip" or self.module != "yc":
                raise LabError("Недопустимый target")
            args.append("-target=" + target)
        if destroy:
            args.append("-destroy")
        self.call(*args)
        data = json.loads(self.call("show", "-json", plan))
        check_plan(data, destroy=destroy, allowed=self.allowed)
        changed = any(
            r["change"]["actions"] != ["no-op"]
            for r in data.get("resource_changes", [])
            if r.get("mode") != "data"
        )
        if unchanged:
            if changed:
                raise LabError("Повторный Terraform-план содержит изменения")
            return
        try:
            self.call("apply", "-input=false", plan)
        finally:
            # The state and variables are intentionally preserved on failure for recovery.
            if plan.exists():
                plan.unlink()

    def output(self, name):
        return json.loads(self.call("output", "-json", name))


def resource_ids(resources):
    result = []
    for item in resources:
        values = item["values"]
        if values.get("id"):
            result.append({"type": item["type"], "id": values["id"]})
        if item["type"] == "yandex_compute_instance":
            for boot in values.get("boot_disk", []):
                if boot.get("disk_id"):
                    result.append({"type": "yandex_compute_disk", "id": boot["disk_id"]})
    return result
