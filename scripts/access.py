"""Local clipboard and pinned interactive SSH access; no cloud authentication."""

import ipaddress
import os
import re
import subprocess
from pathlib import Path

from common import LabError
from security import ssh_key


def copy_password(password: object) -> None:
    """Pass the password through stdin only, keeping process arguments secret-free."""
    if not isinstance(password, str) or not password:
        raise LabError("Пароль веб-интерфейса отсутствует")
    environment = os.environ.copy()
    environment.pop("PSModulePath", None)
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-STA",
                "-Command",
                "[Console]::InputEncoding = [Text.UTF8Encoding]::new($false); "
                "$ErrorActionPreference = 'Stop'; Set-Clipboard -Value ([Console]::In.ReadToEnd())",
            ],
            env=environment,
            input=password,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise LabError("Не удалось скопировать пароль в буфер обмена") from None
    if result.returncode:
        raise LabError("Не удалось скопировать пароль в буфер обмена")


def guest_shell(runtime: Path, host: dict, guest: dict) -> None:
    """Pin both hops from cloud-init keys and inherit the operator's terminal."""
    host_ip = str(ipaddress.IPv4Address(host["public_ip"]))
    guest_ip = str(ipaddress.IPv4Interface(guest["address"]).ip)
    username = guest["username"]
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", username):
        raise LabError("Некорректный пользователь гостя")
    runtime = runtime.resolve()
    for name in ("operator", "pve-host", "guest-host"):
        if not (runtime / name).is_file():
            raise LabError("Отсутствует SSH-ключ стенда: " + name)
    known = runtime / "interactive-known-hosts"
    config = runtime / "interactive-ssh.conf"
    for path in (known, config):
        if path.is_symlink():
            raise LabError("Ссылка вместо служебного SSH-файла запрещена")
    known.write_text(
        "dz10-node " + ssh_key(runtime / "pve-host") + "\n"
        "dz10-guest " + ssh_key(runtime / "guest-host") + "\n",
        encoding="ascii",
    )
    # OpenSSH configuration quotes paths; disallow line/quote injection before writing.
    directory = runtime.as_posix()
    if any(character in directory for character in ('"', "\n", "\r")):
        raise LabError("Путь стенда содержит недопустимые для SSH символы")
    config.write_text(
        f'Host *\n  IdentityFile "{directory}/operator"\n'
        f'  UserKnownHostsFile "{known.as_posix()}"\n'
        "  GlobalKnownHostsFile none\n  IdentitiesOnly yes\n"
        "  StrictHostKeyChecking yes\n  BatchMode yes\n"
        "  ForwardAgent no\n  ConnectTimeout 20\n"
        f"Host dz10-node\n  HostName {host_ip}\n  User operator\n"
        "  HostKeyAlias dz10-node\n"
        f"Host dz10-guest\n  HostName {guest_ip}\n  User {username}\n"
        "  HostKeyAlias dz10-guest\n  ProxyJump dz10-node\n",
        encoding="utf-8",
    )
    print(f"SSH: {username}@{guest_ip} через operator@{host_ip}", flush=True)
    print("Выход из гостя: exit или Ctrl+D. Аварийный разрыв: Enter, затем ~.", flush=True)
    try:
        result = subprocess.run(["ssh", "-F", str(config), "-t", "dz10-guest"], check=False)
    except OSError:
        raise LabError("Не удалось запустить OpenSSH: проверьте установку ssh") from None
    if result.returncode:
        raise LabError("SSH-сеанс завершился с ошибкой; проверьте доступ и ключи узлов")
