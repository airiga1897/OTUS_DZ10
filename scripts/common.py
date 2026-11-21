"""Local state, configuration and process boundaries for this clone only."""

import base64
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]


class LabError(RuntimeError):
    pass


def run(args, *, env=None, capture=True, timeout=1800, cwd=None):
    try:
        result = subprocess.run(
            [str(a) for a in args],
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=capture,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise LabError(f"{Path(str(args[0])).name}: превышено время ожидания") from None
    if result.returncode:
        # Terraform/SSH output may contain metadata, tokens or cloud identifiers.
        raise LabError(f"{Path(str(args[0])).name}: ошибка, код {result.returncode}")
    return result.stdout if capture else ""


def run_powershell(script):
    # PowerShell 7's module path can prevent Windows PowerShell's security module loading.
    env = {key: value for key, value in os.environ.items() if key.lower() != "psmodulepath"}
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], env=env
    )


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        literal = str(path.resolve()).replace("'", "''")
        script = (
            "$ErrorActionPreference='Stop'; "
            "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
            f"$acl=Get-Acl -LiteralPath '{literal}'; "
            "if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){exit 1}; "
            f"& icacls.exe '{literal}' /inheritance:r /grant:r ('*'+$sid.Value+':(OI)(CI)F') | Out-Null; "
            "if($LASTEXITCODE){exit 1}; "
            f"$acl=Get-Acl -LiteralPath '{literal}'; "
            "foreach($old in @($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])))"
            "{if($old.AccessControlType -eq 'Allow' -and $old.IdentityReference.Value -ne $sid.Value){"
            f"& icacls.exe '{literal}' /remove:g ('*'+$old.IdentityReference.Value) | Out-Null; "
            "if($LASTEXITCODE){exit 1}}}; "
            f"$actual=Get-Acl -LiteralPath '{literal}'; "
            "if(-not $actual.AreAccessRulesProtected){exit 1}; "
            "foreach($r in $actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))"
            "{if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -ne $sid.Value){exit 1}}"
        )
        run_powershell(script)
    else:
        path.chmod(0o700)


def require_private_file(path):
    if not path.is_file() or path.is_symlink():
        raise LabError("Нет собственного профиля YC; выполните yc init для ДЗ10")
    if any(
        p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
        for p in (path.parent, path.parent.parent)
    ):
        raise LabError("Ссылки в пути профиля YC запрещены")
    if os.name != "nt":
        if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
            raise LabError("Профиль YC должен быть доступен только владельцу")
        return
    literal = str(path).replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop'; "
        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
        f"$acl=Get-Acl -LiteralPath '{literal}'; "
        "if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid){exit 1}; "
        "$rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]); "
        "foreach($rule in $rules){if($rule.AccessControlType -eq 'Allow' -and "
        "$rule.IdentityReference.Value -ne $sid){exit 1}}"
    )
    try:
        run_powershell(script)
    except LabError:
        raise LabError(
            "Проверьте владельца и права профиля YC: доступ только текущему пользователю"
        ) from None


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path, default=None):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4 and address.is_global:
            return str(address)
    except ValueError:
        pass
    raise LabError("Не подтверждён публичный IPv4; проверьте маршрут, VPN и прокси")


def merge_cidrs(*groups):
    result = set()
    for group in groups:
        for cidr in group:
            if not cidr.endswith("/32"):
                raise LabError("Для административного доступа допустимы только IPv4 /32")
            result.add(public_ipv4(cidr[:-3]) + "/32")
    return sorted(result)


def check_plan(plan, *, destroy=False, allowed=None):
    for change in plan.get("resource_changes", []):
        if change.get("mode") == "data":
            continue
        address = change["address"]
        if allowed is not None and address not in allowed:
            raise LabError("План содержит ресурс вне области стенда")
        actions = change["change"]["actions"]
        if any(action not in {"no-op", "create", "update", "delete"} for action in actions):
            raise LabError("План содержит неподдерживаемую операцию")
        if destroy:
            if actions not in (["delete"], ["no-op"]):
                raise LabError("План удаления содержит создание или изменение")
        elif "delete" in actions:
            raise LabError("Запрещено удаление или замена ресурсов при deploy")


def cleanup(root, runtime):
    root = root.resolve(strict=True)
    # Accept only the project's fixed service directory; reject symlinks/junctions.
    expected = root / ".local" / "runtime"
    if runtime != expected or runtime.is_symlink() or runtime.resolve() != expected:
        raise LabError("Небезопасный путь очистки")
    for item in runtime.rglob("*"):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise LabError("Ссылки внутри каталога очистки запрещены")
    if runtime.exists():
        shutil.rmtree(runtime)


def config(root):
    cfg = load_json(root / "config/lab.json")
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,40}", cfg["namespace"]):
        raise LabError("Некорректный namespace")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", cfg["host"]["name"]):
        raise LabError("Некорректное имя узла")
    merge_cidrs(cfg["admin_cidrs"])
    net = ipaddress.ip_network(cfg["network_cidr"])
    guest = ipaddress.ip_interface(cfg["guest"]["address"])
    gateway = ipaddress.ip_address(cfg["guest"]["gateway"])
    if net.version != 4 or not net.is_private or net.overlaps(guest.network):
        raise LabError("Сети YC и гостя должны быть разными приватными IPv4 сетями")
    if gateway not in guest.network or gateway == guest.ip:
        raise LabError("Некорректный шлюз гостя")
    if guest.version != 4 or not guest.network.is_private or not 16 <= net.prefixlen <= 28:
        raise LabError("Некорректные параметры приватных сетей")
    for key in ("name", "username"):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", cfg["guest"][key]):
            raise LabError("Некорректное имя гостя или пользователя")
    for key in ("vm_id", "cores", "memory_mib", "disk_gib"):
        if type(cfg["guest"][key]) is not int or cfg["guest"][key] <= 0:
            raise LabError("Параметры гостя должны быть положительными целыми числами")
    if cfg["guest"]["vm_id"] < 100 or not re.fullmatch(r"vmbr[0-9]+", cfg["guest"]["bridge"]):
        raise LabError("Некорректный ID ВМ или мост")
    url = urlparse(cfg["guest"]["image_url"])
    if url.scheme != "https" or url.hostname != "cloud.debian.org":
        raise LabError("Образ гостя должен загружаться по HTTPS из cloud.debian.org")
    for field in ("image_sha512",):
        if not re.fullmatch(r"[0-9a-f]{128}", cfg["guest"][field]):
            raise LabError("Задайте SHA512 закреплённого образа гостя в config/lab.json")
    if not cfg["host"]["image_id"]:
        raise LabError("Задайте ID образа Debian 13 в config/lab.json")
    if not re.fullmatch(r"[0-9a-f]{64}", cfg["proxmox"]["key_sha256"]):
        raise LabError("Задайте SHA256 ключа репозитория Proxmox")
    return cfg
