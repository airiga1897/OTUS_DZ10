"""YC REST adapter with environment auth or an explicitly selected clone-local CLI profile."""

import ipaddress
import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

from common import LabError, public_ipv4, require_private_file, run
from progress import report_stage

SERVICES = {
    "resource": "https://resource-manager.api.cloud.yandex.net/resource-manager/v1",
    "compute": "https://compute.api.cloud.yandex.net/compute/v1",
    "vpc": "https://vpc.api.cloud.yandex.net/vpc/v1",
    "functions": "https://serverless-functions.api.cloud.yandex.net/functions/v1",
    "quota": "https://quota-manager.api.cloud.yandex.net/quota-manager/v1",
}


class YC:
    def __init__(self, cloud_id, folder_id, token):
        self.cloud_id, self.folder_id, self.token = cloud_id, folder_id, token

    @classmethod
    @report_stage("Чтение реквизитов YC из окружения")
    def from_env(cls):
        values = [os.environ.get(key, "") for key in ("YC_CLOUD_ID", "YC_FOLDER_ID", "YC_TOKEN")]
        if not all(values):
            raise LabError("Нужны YC_CLOUD_ID, YC_FOLDER_ID и YC_TOKEN текущей сессии")
        return cls(*values)

    @classmethod
    @report_stage("Авторизация YC через локальный профиль")
    def from_profile(cls, root):
        executable = root / ".tools/bin/yc.exe"
        profile = root / ".local/yc/config.yaml"
        if not executable.is_file():
            raise LabError("YC CLI отсутствует; выполните scripts/setup.ps1")
        require_private_file(profile)
        cli_env = {key: value for key, value in os.environ.items() if not key.startswith("YC_")}
        cli_env.update({"YC_TRACE_LOG_PATH": os.devnull, "YC_DISABLE_UPDATE": "1"})

        def value(*args, pattern):
            try:
                result = run(
                    [executable, "--config", profile, *args], timeout=90, env=cli_env
                ).strip()
            except (LabError, OSError):
                raise LabError("Вход YC недоступен; повторите yc init с профилем ДЗ10") from None
            if not re.fullmatch(pattern, result):
                raise LabError("YC CLI вернул некорректные данные авторизации")
            return result

        cloud = value("config", "get", "cloud-id", pattern=r"[a-z0-9]+")
        folder = value("config", "get", "folder-id", pattern=r"[a-z0-9]+")
        token = value("iam", "create-token", "--no-browser", pattern=r"\S+")
        return cls(cloud, folder, token)

    def request(self, url, *, missing_ok=False):
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=45) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if missing_ok and exc.code == 404:
                return None
            raise LabError(f"YC API: HTTP {exc.code}; проверьте права и область ресурсов") from None
        except (OSError, ValueError):
            raise LabError("YC API: не удалось получить достоверный ответ") from None

    def get(self, service, path, *, missing_ok=False):
        return self.request(SERVICES[service] + "/" + path, missing_ok=missing_ok)

    def list(self, service, collection):
        result, token = [], ""
        while True:
            query = urllib.parse.urlencode(
                {"folderId": self.folder_id, "pageSize": 1000, "pageToken": token}
            )
            page = self.get(service, collection + "?" + query)
            result.extend(page.get(collection, []))
            token = page.get("nextPageToken", "")
            if not token:
                return result

    def scope(self):
        folder = self.get("resource", "folders/" + self.folder_id)
        if folder.get("cloudId") != self.cloud_id or folder.get("status") != "ACTIVE":
            raise LabError("Каталог не принадлежит выбранному облаку или неактивен")
        cloud = self.get("resource", "clouds/" + self.cloud_id)
        if cloud.get("id") != self.cloud_id:
            raise LabError("Не подтверждена область облака")

    @report_stage("Проверка области YC, размещения, образа, квот и сетей")
    def preflight(self, cfg, owned):
        self.scope()
        for service, collection in (
            ("compute", "instances"),
            ("compute", "disks"),
            ("vpc", "networks"),
            ("vpc", "subnets"),
            ("vpc", "securityGroups"),
            ("functions", "functions"),
        ):
            for item in self.list(service, collection):
                if (
                    item.get("labels", {}).get("lab") == cfg["namespace"]
                    and item["id"] not in owned
                ):
                    raise LabError(
                        "Найдены ресурсы namespace вне собственного state; нужна диагностика"
                    )
        zones = self.get("compute", "zones").get("zones", [])
        if not any(z["id"] == cfg["zone"] and z["status"] == "UP" for z in zones):
            raise LabError("Зона недоступна или не подтверждена")
        types = self.get("compute", "diskTypes").get("diskTypes", [])
        disk_type = next((t for t in types if t["id"] == cfg["host"]["disk_type"]), None)
        if disk_type is None:
            raise LabError("Тип диска отсутствует в каталоге YC")
        disk_zones = disk_type.get("zoneIds", [])
        if disk_zones and cfg["zone"] not in disk_zones:
            raise LabError("Тип диска недоступен в выбранной зоне")
        # YC omits zoneIds for ordinary replicated disks in both REST and gRPC.
        # Check the global catalogue plus the selected class's zonal quota below.
        # Never apply this rule to a different storage class or substitute one.
        quota_classes = {"network-ssd": "ssdDisks", "network-hdd": "hddDisks"}
        if disk_type["id"] not in quota_classes:
            raise LabError("Не подтверждено размещение выбранного класса дисков")
        disk_quota = "compute." + quota_classes[disk_type["id"]] + ".size." + cfg["zone"]
        image = self.get("compute", "images/" + cfg["host"]["image_id"])
        if (
            image.get("status") != "READY"
            or "debian" not in (image.get("family", "") + image.get("name", "")).lower()
            or "13" not in (image.get("family", "") + image.get("name", ""))
        ):
            raise LabError("Нужен доступный образ Debian 13")
        if int(image["minDiskSize"]) > cfg["host"]["boot_gib"] * 2**30:
            raise LabError("Системный диск меньше требования образа")
        for subnet in self.list("vpc", "subnets"):
            if subnet["id"] in owned:
                continue
            for cidr in subnet.get("v4CidrBlocks", []):
                if ipaddress.ip_network(cidr).overlaps(ipaddress.ip_network(cfg["network_cidr"])):
                    raise LabError("Конфликт сети с существующей подсетью")
        # Fail closed on unknown quotas. Values are obtained from the provider, not guessed.
        demands = {
            "compute.instances.count": 1,
            "compute.instanceCores.count." + cfg["zone"]: cfg["host"]["cores"],
            "compute.instanceMemory.size." + cfg["zone"]: cfg["host"]["memory_gib"] * 2**30,
            disk_quota: (cfg["host"]["boot_gib"] + cfg["host"]["data_gib"]) * 2**30,
            "compute.disks.count": 2,
            "vpc.networks.count": 1,
            "vpc.subnets.count": 1,
            "vpc.securityGroups.count": 1,
            "vpc.externalAddresses.count": 1,
            "serverless.functions.count": 1,
        }
        instances = self.list("compute", "instances")
        disks = self.list("compute", "disks")
        credit = {key: 0 for key in demands}
        for vm in instances:
            if vm["id"] in owned:
                credit["compute.instances.count"] += 1
                if vm["zoneId"] != cfg["zone"]:
                    raise LabError("Собственная ВМ находится в другой зоне")
                credit["compute.instanceCores.count." + cfg["zone"]] += int(
                    vm["resources"]["cores"]
                )
                credit["compute.instanceMemory.size." + cfg["zone"]] += int(
                    vm["resources"]["memory"]
                )
                credit["vpc.externalAddresses.count"] += sum(
                    "oneToOneNat" in nic.get("primaryV4Address", {})
                    for nic in vm.get("networkInterfaces", [])
                )
        for disk in disks:
            if disk["id"] in owned:
                if disk["zoneId"] != cfg["zone"] or disk["typeId"] != cfg["host"]["disk_type"]:
                    raise LabError("Собственный диск не соответствует сохранённому размещению")
                credit[disk_quota] += int(disk["size"])
                credit["compute.disks.count"] += 1
        for service, collection, quota in (
            ("vpc", "networks", "vpc.networks.count"),
            ("vpc", "subnets", "vpc.subnets.count"),
            ("vpc", "securityGroups", "vpc.securityGroups.count"),
            ("functions", "functions", "serverless.functions.count"),
        ):
            credit[quota] = sum(item["id"] in owned for item in self.list(service, collection))
        query = urllib.parse.urlencode(
            {"resource.id": self.cloud_id, "resource.type": "resource-manager.cloud"}
        )
        for quota, required in demands.items():
            data = self.get("quota", "quotaLimits/" + quota + "?" + query)
            if "limit" not in data or "usage" not in data:
                raise LabError("API не подтвердил значение квоты " + quota)
            if float(data["limit"]) - float(data["usage"]) < max(0, required - credit[quota]):
                raise LabError("Недостаточная квота: " + quota)
        # Platform constraints are explicit: only the chosen standard-v3 tuple is allowed.
        if (
            cfg["platform_id"] != "standard-v3"
            or cfg["host"]["cores"] != 4
            or cfg["host"]["memory_gib"] != 8
        ):
            raise LabError(
                "Конфигурация платформы выходит за проверяемое сочетание standard-v3 4/8"
            )

    @report_stage("Подтверждение IPv4 оператора через приватную функцию YC")
    def operator_ip(self, function_id):
        nonce = secrets.token_hex(32)
        response = self.request(f"https://functions.yandexcloud.net/{function_id}?nonce={nonce}")
        if response.get("nonce") != nonce:
            raise LabError("Ответ функции не соответствует nonce текущего запроса")
        return public_ipv4(response.get("ip", ""))

    @report_stage("Проверка отсутствия ресурсов через API YC")
    def audit_absent(self, resources, namespace):
        collections = {
            "yandex_function": ("functions", "functions"),
            "yandex_compute_instance": ("compute", "instances"),
            "yandex_compute_disk": ("compute", "disks"),
            "yandex_vpc_subnet": ("vpc", "subnets"),
            "yandex_vpc_network": ("vpc", "networks"),
            "yandex_vpc_security_group": ("vpc", "securityGroups"),
        }
        for resource in resources:
            service, collection = collections[resource["type"]]
            if self.get(service, collection + "/" + resource["id"], missing_ok=True) is not None:
                raise LabError("API не подтвердил удаление ресурса стенда")
        for service, collection in set(collections.values()):
            if any(
                item.get("labels", {}).get("lab") == namespace
                for item in self.list(service, collection)
            ):
                raise LabError("В API остались помеченные ресурсы стенда")
