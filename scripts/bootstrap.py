"""Stdlib-only installer for the project's pinned Terraform binary."""

import hashlib
import io
import json
import os
import platform
import urllib.request
import zipfile
from pathlib import Path


def install_terraform(root):
    version = json.loads((root / "config/lab.json").read_text())["tools"]["terraform"]
    system = "windows" if os.name == "nt" else "linux"
    if platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("Поддерживается x86_64")
    tools = root / ".tools"
    tools.mkdir(exist_ok=True)
    target = tools / ("terraform.exe" if os.name == "nt" else "terraform")
    if target.exists():
        import subprocess

        try:
            installed = json.loads(subprocess.check_output([target, "version", "-json"]))
        except (OSError, ValueError, subprocess.CalledProcessError):
            installed = {}
        if installed:
            if installed["terraform_version"] == version:
                return
            raise SystemExit("Версия .tools/terraform отличается от config/lab.json")
    base = f"https://releases.hashicorp.com/terraform/{version}/"
    filename = f"terraform_{version}_{system}_amd64.zip"
    with urllib.request.urlopen(base + f"terraform_{version}_SHA256SUMS", timeout=60) as response:
        sums = response.read().decode()
    checksum = next(line.split()[0] for line in sums.splitlines() if line.endswith("  " + filename))
    with urllib.request.urlopen(base + filename, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise SystemExit("Terraform SHA256 mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        temporary = target.with_suffix(".part")
        try:
            temporary.write_bytes(archive.read(target.name))
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    target.chmod(0o755)


def install_yc(root):
    if os.name != "nt":
        return
    settings = json.loads((root / "config/lab.json").read_text())["tools"]["yc"]
    target = root / ".tools/bin/yc.exe"
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != settings["sha256"]:
            raise SystemExit("YC CLI не соответствует закреплённой контрольной сумме")
        return
    with urllib.request.urlopen(settings["url"], timeout=180) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != settings["sha256"]:
        raise SystemExit("YC CLI SHA256 mismatch")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".part")
    try:
        temporary.write_bytes(data)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    root = Path(__file__).resolve().parents[1]
    install_terraform(root)
    install_yc(root)


if __name__ == "__main__":
    main()
