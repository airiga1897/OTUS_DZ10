import json
import os
import re

from common import LabError, run, run_powershell
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def ssh_key(path):
    if not path.exists():
        key = ed25519.Ed25519PrivateKey.generate()
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
    key = serialization.load_ssh_private_key(path.read_bytes(), password=None)
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )


def cloud_init(runtime, cfg, *, guest=False):
    name = "guest-host" if guest else "pve-host"
    public = ssh_key(runtime / name)
    operator = ssh_key(runtime / "operator")
    user = cfg["guest"]["username"] if guest else "operator"
    data = {
        "hostname": cfg["guest"]["name"] if guest else cfg["host"]["name"],
        # PVE must keep its hostname mapped to the private NIC address across reboots.
        "manage_etc_hosts": guest,
        "ssh_pwauth": False,
        "disable_root": True,
        "ssh_keys": {"ed25519_private": (runtime / name).read_text(), "ed25519_public": public},
        "users": [
            {
                "name": user,
                "groups": ["sudo"],
                "shell": "/bin/bash",
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "lock_passwd": True,
                "ssh_authorized_keys": [operator],
            }
        ],
    }
    if not guest:
        # Debian already has the system group 'operator' (GID 37). useradd's
        # default private-group creation collides with it. Reuse 'users' instead.
        data["users"][0]["primary_group"] = "users"
    if guest:
        data.update(
            {
                "package_update": True,
                "apt": {
                    "primary": [{"arches": ["default"], "uri": "https://mirror.yandex.ru/debian"}],
                    "security": [
                        {"arches": ["default"], "uri": "https://mirror.yandex.ru/debian-security"}
                    ],
                },
                "packages": ["qemu-guest-agent"],
                "runcmd": [["systemctl", "enable", "--now", "qemu-guest-agent"]],
            }
        )
    return "#cloud-config\n" + json.dumps(data, indent=2)


def remove_legacy_ca(runtime, fingerprints=()):
    """Remove only this lab's exact recorded fingerprints; never search by subject."""
    known = set(filter(None, fingerprints))
    certificate = runtime / "ca.crt"
    if certificate.exists():
        known.add(
            x509.load_pem_x509_certificate(certificate.read_bytes())
            .fingerprint(hashes.SHA1())
            .hex()
            .upper()
        )
    for fingerprint in known:
        if not re.fullmatch(r"[0-9A-Fa-f]{40}", fingerprint):
            raise LabError("Некорректный отпечаток прежнего CA")
        if os.name == "nt":
            probe = f"Test-Path -LiteralPath 'Cert:\\CurrentUser\\Root\\{fingerprint}'"
            if run_powershell(probe).strip().lower() == "true":
                run(["certutil.exe", "-user", "-delstore", "Root", fingerprint])
                if run_powershell(probe).strip().lower() != "false":
                    raise LabError("Удаление прежнего CA не подтверждено")
    for name in ("ca.crt", "ca.key", "pve.crt", "pve.key"):
        (runtime / name).unlink(missing_ok=True)
