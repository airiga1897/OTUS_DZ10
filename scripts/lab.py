"""User entry point. No cloud operations occur on import or during local checks."""

import argparse
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager

from common import ROOT, LabError, cleanup, config, load_json, merge_cidrs, private_dir, save_json
from progress import Stage, report_stage
from remote import Remote
from security import cloud_init, remove_legacy_ca, ssh_key
from yc import YC

from terraform import Terraform, resource_ids


@contextmanager
def exclusive(root):
    directory = root / ".local"
    for path in (directory, directory / "runtime"):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise LabError("Ссылки вместо служебных каталогов запрещены")
    with Stage("Подготовка локальных данных и проверка прав доступа"):
        private_dir(directory)
    with (directory / "operation.lock").open("a+b") as stream:
        stream.seek(0)
        stream.write(b"0")
        stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise LabError("Другая команда уже управляет этим клоном") from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


class Lab:
    def __init__(self, root=ROOT, *, yc=None, tf_factory=Terraform, remote_factory=Remote):
        self.root = root.resolve()
        self.runtime = self.root / ".local/runtime"
        self.context_path = self.runtime / "context.json"
        self.context = load_json(self.context_path)
        self.yc = yc
        self.tf_factory, self.remote_factory = tf_factory, remote_factory

    def api(self):
        if self.yc is None:
            self.yc = YC.from_env()
        return self.yc

    def save(self):
        save_json(self.context_path, self.context)

    @report_stage("Проверка локального контекста и размещения")
    def bind(self, cfg):
        api = self.api()
        identity = {
            "provider": "yc",
            "cloud_id": api.cloud_id,
            "folder_id": api.folder_id,
            "namespace": cfg["namespace"],
            "zone": cfg["zone"],
            "platform_id": cfg["platform_id"],
            "host": cfg["host"],
            "network_cidr": cfg["network_cidr"],
        }
        if self.context:
            if self.context["identity"] != identity:
                raise LabError("Область или размещение отличаются от сохранённого стенда")
        else:
            private_dir(self.runtime)
            self.context = {
                "identity": identity,
                "config": cfg,
                "resources": [],
                "phase": "prepared",
            }
            self.save()

    @report_stage("Проверка сохранённой области ресурсов YC")
    def bound_api(self):
        if not self.context:
            raise LabError("Локальный контекст отсутствует")
        api = self.api()
        scope = self.context["identity"]
        if (api.cloud_id, api.folder_id) != (scope["cloud_id"], scope["folder_id"]):
            raise LabError("Реквизиты относятся к другой области YC")
        api.scope()
        return api

    def tf(self, module):
        env = {"YC_TOKEN": self.api().token} if module == "yc" else {}
        if module == "proxmox":
            credentials = load_json(self.runtime / "credentials.json")
            if not credentials:
                raise LabError("Нет служебного токена Proxmox; повторите deploy для восстановления")
            env = {
                "PROXMOX_VE_API_TOKEN": credentials["api_token"],
            }
        return self.tf_factory(self.root, self.runtime, module, env=env)

    def remember(self, tf):
        items = resource_ids(tf.resources())
        previous = self.context["resources"]
        self.context["resources"] = [
            dict(t) for t in sorted({tuple(sorted(x.items())) for x in previous + items})
        ]
        self.save()

    @report_stage("Подготовка параметров Terraform и cloud-init")
    def yc_variables(self, cfg):
        package = self.runtime / "function.zip"
        if not package.exists():
            content = (self.root / "functions/operator_ip/main.py").read_bytes()
            with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
                info = zipfile.ZipInfo("main.py", date_time=(2026, 1, 1, 0, 0, 0))
                archive.writestr(info, content)
        return {
            "cloud_id": self.context["identity"]["cloud_id"],
            "folder_id": self.context["identity"]["folder_id"],
            **{
                key: cfg[key]
                for key in ("zone", "namespace", "platform_id", "host", "network_cidr")
            },
            "admin_cidrs": cfg.get("effective_admin_cidrs", []),
            "cloud_init": cloud_init(self.runtime, cfg),
            "function_zip": package.as_posix(),
            "function_hash": hashlib.sha256(package.read_bytes()).hexdigest(),
        }

    def pve_variables(self, cfg, *, start=True):
        return {
            "endpoint": f"https://{self.context['host']['public_ip']}:8006/",
            "node_name": cfg["host"]["name"],
            "guest": cfg["guest"],
            "public_key": ssh_key(self.runtime / "operator"),
            "cloud_init_file": "local:snippets/dz10-guest.yaml",
            "start_guest": start,
        }

    @report_stage("Проверка HTTPS API и версии Proxmox")
    def tls_check(self):
        address = self.context["host"]["public_ip"]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            credentials = load_json(self.runtime / "credentials.json")
            if not credentials or not credentials.get("api_token"):
                raise LabError("Нет служебного токена Proxmox")
            request = urllib.request.Request(
                f"https://{address}:8006/api2/json/version",
                headers={"Authorization": "PVEAPIToken=" + credentials["api_token"]},
            )
            with urllib.request.urlopen(request, context=ctx, timeout=30) as response:
                if not json.load(response).get("data", {}).get("version", "").startswith("9."):
                    raise LabError("API не подтвердил Proxmox VE 9")
        except (OSError, ValueError, urllib.error.URLError):
            raise LabError("Не удалось проверить HTTPS API Proxmox") from None

    def deploy(self):
        cfg = config(self.root)
        self.bind(cfg)
        tf = self.tf("yc")
        tf.init()
        self.remember(tf)
        self.bound_api().preflight(cfg, {x["id"] for x in self.context["resources"]})
        print("Область, размещение и квоты проверены. Подготовка функции определения IPv4.")
        variables = self.yc_variables(cfg)
        try:
            tf.apply(variables, target="yandex_function.operator_ip")
        finally:
            self.remember(tf)
        address = self.api().operator_ip(tf.output("function_id"))
        observations_path = self.root / ".local/observed-addresses.json"
        observations = load_json(observations_path, {})
        scope = self.api().cloud_id + "/" + self.api().folder_id
        observed = merge_cidrs(observations.get(scope, []), [address + "/32"])
        observations[scope] = observed
        save_json(observations_path, observations)
        cfg["effective_admin_cidrs"] = merge_cidrs(
            cfg["admin_cidrs"],
            observed,
            self.context.get("config", {}).get("effective_admin_cidrs", []),
        )
        self.context["config"] = cfg
        self.save()
        variables["admin_cidrs"] = cfg["effective_admin_cidrs"]
        print("IPv4 подтверждён. Создание или обновление инфраструктуры YC.")
        try:
            tf.apply(variables)
        finally:
            self.remember(tf)
        self.context["host"] = tf.output("host")
        self.context["phase"] = "host-created"
        self.save()
        remove_legacy_ca(self.runtime, [self.context.get("ca_thumbprint")])
        self.context.pop("ca_thumbprint", None)
        self.context.pop("ca_trust_pending", None)
        self.save()
        (self.runtime / "guest-cloud-init.yaml").write_text(
            cloud_init(self.runtime, cfg, guest=True)
        )
        remote = self.remote_factory(self.runtime, self.context["host"]["public_ip"], cfg)
        try:
            print("Установка и настройка Proxmox VE.")
            remote.connect()
            save_json(self.runtime / "credentials.json", remote.configure(self.root, self.context))
            self.tls_check()
            pve = self.tf("proxmox")
            pve.init()
            existing = pve.resources()
            if not existing:
                # API cannot start a kvm=1 guest in YC. Create stopped, set the unsupported
                # provider field through qm, then let Terraform perform the actual start.
                pve.apply(self.pve_variables(cfg, start=False))
            vm_id = int(cfg["guest"]["vm_id"])
            with Stage("Настройка гостя для QEMU без KVM"):
                remote.command(f"sudo qm set {vm_id} --kvm 0")
            print("Terraform создаёт и запускает гостевую ВМ в режиме QEMU.")
            pve.apply(self.pve_variables(cfg))
            self.context["guest_deleted"] = False
            self.context["phase"] = "deployed"
            self.save()
        finally:
            remote.close()
        print("Стенд оставлен работающим. Выполните verify для проверки гостевой ОС.")

    @report_stage("Проверка входа в Proxmox и cookie-сеанса")
    def session_check(self):
        """Exercise the web account's ticket and cookie session over native HTTPS."""
        credentials = load_json(self.runtime / "credentials.json")
        base = f"https://{self.context['host']['public_ip']}:8006/api2/json"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            request = urllib.request.Request(
                base + "/access/ticket",
                data=urllib.parse.urlencode(
                    {
                        "username": credentials["ui_username"],
                        "password": credentials["ui_password"],
                    }
                ).encode(),
            )
            with urllib.request.urlopen(request, context=ctx, timeout=30) as response:
                session = json.load(response)["data"]
            if session["username"] != credentials["ui_username"]:
                raise LabError("Учётная запись веб-сеанса не совпадает")
            cookie = "PVEAuthCookie=" + urllib.parse.quote(session["ticket"], safe="")
            for endpoint in ("/version", "/cluster/resources?type=vm"):
                request = urllib.request.Request(base + endpoint, headers={"Cookie": cookie})
                with urllib.request.urlopen(request, context=ctx, timeout=30) as response:
                    data = json.load(response)["data"]
                if endpoint.startswith("/cluster") and not any(
                    int(vm.get("vmid", -1)) == self.context["config"]["guest"]["vm_id"]
                    for vm in data
                ):
                    raise LabError("Веб-сеанс не видит созданную гостевую ВМ")
            try:
                with urllib.request.urlopen(base + "/cluster/resources", context=ctx, timeout=30):
                    raise LabError("API допустил запрос без авторизации")
            except urllib.error.HTTPError as exc:
                if exc.code != 401:
                    raise LabError("Неожиданный ответ API без авторизации") from None
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            raise LabError("Проверка входа и cookie-сеанса Proxmox не пройдена") from None

    def verify(self):
        self.bound_api()
        cfg = self.context["config"]
        self.tls_check()
        self.session_check()
        remote = self.remote_factory(self.runtime, self.context["host"]["public_ip"], cfg)
        try:
            remote.connect()
            remote.verify_guest()
            for module, variables in (
                ("yc", self.yc_variables(cfg)),
                ("proxmox", self.pve_variables(cfg)),
            ):
                tf = self.tf(module)
                tf.init()
                tf.apply(variables, unchanged=True)
        finally:
            remote.close()
        self.context["phase"] = "verified"
        self.save()
        # Only non-secret evidence; no IDs, addresses, credentials or raw API responses.
        save_json(
            self.root / "evidence/verification.json",
            {
                "guest_parameters": "passed",
                "guest_ssh": "passed",
                "cloud_init": "passed",
                "https_api": "passed",
                "web_account_login_cookie_session": "passed",
                "certificate_verification": "disabled_by_agreement",
                "terraform_no_changes": "passed",
            },
        )
        print("Параметры ВМ, гостевая ОС, cloud-init, SSH, HTTPS API и повторные планы проверены.")

    @report_stage("Проверка локального state и подготовка URL")
    def open(self):
        if not self.context or self.context["phase"] not in ("deployed", "verified"):
            raise LabError("Нет завершённого локального развёртывания")
        state = load_json(self.runtime / "yc.tfstate", {})
        host = state.get("outputs", {}).get("host", {}).get("value")
        if host != self.context.get("host"):
            raise LabError("Локальные context и state не совпадают")
        guest_state = load_json(self.runtime / "proxmox.tfstate", {})
        if (
            guest_state.get("outputs", {}).get("guest_id", {}).get("value")
            != self.context["config"]["guest"]["vm_id"]
        ):
            raise LabError("State гостя не соответствует контексту")
        print("Размещение: YC / " + self.context["identity"]["zone"])
        print(f"https://{host['public_ip']}:8006/")
        print("User name: reviewer (без @pve)")
        print("Realm (тип аутентификации): Proxmox VE authentication server (pve)")
        print("Выберите указанный Realm в списке формы входа.")
        print("Скопировать пароль в буфер обмена (PowerShell):")
        print(
            "(Get-Content .local/runtime/credentials.json -Raw | ConvertFrom-Json).ui_password"
            " | Set-Clipboard"
        )
        print(
            "Штатный сертификат PVE: примите предупреждение браузера; проверка Terraform отключена."
        )

    def destroy(self):
        if not self.context:
            raise LabError("Контекст отсутствует; автоматическое удаление по имени запрещено")
        api = self.bound_api()
        cfg = self.context["config"]
        tf = self.tf("yc")
        tf.init()
        self.remember(tf)
        # Verify ownership through API before *any* deletion, including guest deletion.
        mapping = {
            "yandex_function": ("functions", "functions"),
            "yandex_compute_instance": ("compute", "instances"),
            "yandex_compute_disk": ("compute", "disks"),
            "yandex_vpc_network": ("vpc", "networks"),
            "yandex_vpc_subnet": ("vpc", "subnets"),
            "yandex_vpc_security_group": ("vpc", "securityGroups"),
        }
        with Stage("Проверка владения ресурсами перед удалением"):
            for resource in self.context["resources"]:
                service, collection = mapping[resource["type"]]
                current = api.get(service, collection + "/" + resource["id"], missing_ok=True)
                if current and (
                    current.get("folderId") != api.folder_id
                    or (current.get("labels", {}).get("lab") != cfg["namespace"])
                ):
                    raise LabError("API не подтвердил владение ресурсом")
        if (self.runtime / "proxmox.tfstate").exists() and not self.context.get("guest_deleted"):
            pve = self.tf("proxmox")
            pve.init()
            pve.apply(self.pve_variables(cfg), destroy=True)
            if pve.resources():
                raise LabError("State гостя не пуст после удаления")
            # The guest must also be absent in the live Proxmox API before deleting its host.
            remote = self.remote_factory(self.runtime, self.context["host"]["public_ip"], cfg)
            try:
                remote.connect()
                vms = json.loads(
                    remote.command(
                        "sudo pvesh get /cluster/resources --type vm --output-format json"
                    )
                )
                if any(int(vm["vmid"]) == cfg["guest"]["vm_id"] for vm in vms):
                    raise LabError("API Proxmox не подтвердил удаление гостя")
            finally:
                remote.close()
            self.context["guest_deleted"] = True
            self.save()
        self.context["phase"] = "destroying"
        self.save()
        tf.apply(self.yc_variables(cfg), destroy=True)
        if tf.resources():
            raise LabError("State YC не пуст после удаления")
        api.audit_absent(self.context["resources"], cfg["namespace"])
        remove_legacy_ca(self.runtime, [self.context.get("ca_thumbprint")])
        save_json(
            self.root / "evidence/deletion.json", {"terraform_empty": True, "api_absent": True}
        )
        with Stage("Очистка локальных данных после подтверждённого удаления"):
            cleanup(self.root, self.runtime)
        print("Удаление подтверждено state и API. Служебные данные стенда очищены.")


def main():
    parser = argparse.ArgumentParser(description="OTUS DZ10: Proxmox on YC")
    parser.add_argument("command", choices=["deploy", "verify", "open", "destroy"])
    parser.add_argument(
        "--yc-profile",
        action="store_true",
        help="Явно получить IAM-токен из собственного профиля YC CLI",
    )
    args = parser.parse_args()
    try:
        with exclusive(ROOT):
            api = YC.from_profile(ROOT) if args.yc_profile and args.command != "open" else None
            getattr(Lab(yc=api), args.command)()
    except (LabError, OSError, ValueError) as exc:
        # These exception classes carry only sanitized application messages or local paths.
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
