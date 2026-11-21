"""Run as root on this project's Proxmox node. Secrets are only returned over SSH."""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path


def command(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def write(path, value, mode=0o644):
    path = Path(path)
    path.write_text(value, encoding="utf-8")
    path.chmod(mode)


def storage():
    device = Path("/dev/disk/by-id/virtio-dz10-guests").resolve(strict=True)
    target = Path("/srv/dz10-guests")
    marker = Path("/var/lib/dz10-storage.json")
    # Never accept the root disk or a partition as the secondary disk.
    if command("lsblk", "-ndo", "TYPE", str(device)) != "disk":
        raise RuntimeError("Guest storage is not a whole disk")
    if len(command("lsblk", "-nro", "NAME", str(device)).splitlines()) != 1:
        raise RuntimeError("Disk with partitions is not accepted")
    identity = command("lsblk", "-ndo", "SERIAL", str(device))
    if identity != "dz10-guests":
        raise RuntimeError("Wrong disk serial")
    current = subprocess.run(
        ["blkid", "-p", "-s", "TYPE", "-o", "value", str(device)], capture_output=True, text=True
    )
    if marker.exists():
        record = json.loads(marker.read_text())
        if (
            record["serial"] != identity
            or current.returncode != 0
            or current.stdout.strip() != "ext4"
        ):
            raise RuntimeError("Storage ownership mismatch")
        uuid = command("blkid", "-s", "UUID", "-o", "value", str(device))
        if uuid != record["uuid"]:
            raise RuntimeError("Storage UUID mismatch")
    else:
        if current.returncode != 2 or current.stdout.strip():
            raise RuntimeError("Refusing to format nonempty or unknown disk")
        # wipefs also catches partition tables/signatures not reported as TYPE by blkid.
        signatures = json.loads(command("wipefs", "--json", str(device)))
        if signatures.get("signatures"):
            raise RuntimeError("Refusing to format a disk with signatures")
        # Record intent before mkfs; a partial format is never automatically repeated.
        write(marker, json.dumps({"serial": identity, "uuid": None}), 0o600)
        command("mkfs.ext4", "-L", "dz10-guests", str(device))
        uuid = command("blkid", "-s", "UUID", "-o", "value", str(device))
        write(marker, json.dumps({"serial": identity, "uuid": uuid}), 0o600)
    target.mkdir(exist_ok=True)
    fstab = Path("/etc/fstab")
    line = f"UUID={uuid} {target} ext4 defaults 0 2"
    contents = fstab.read_text()
    if str(target) not in contents:
        write(fstab, contents.rstrip() + "\n" + line + "\n")
    elif line not in contents.splitlines():
        raise RuntimeError("Unexpected mount definition")
    if not os.path.ismount(target):
        command("mount", str(target))
    actual = command("findmnt", "-n", "-o", "UUID", "--target", str(target))
    if actual != uuid:
        raise RuntimeError("Unexpected mounted filesystem")
    configured = json.loads(command("pvesh", "get", "/storage", "--output-format", "json"))
    entry = next((x for x in configured if x["storage"] == "dz10-guests"), None)
    if entry:
        if entry.get("path") != str(target) or entry.get("type") != "dir":
            raise RuntimeError("Unexpected Proxmox datastore")
    else:
        command(
            "pvesm",
            "add",
            "dir",
            "dz10-guests",
            "--path",
            str(target),
            "--content",
            "images",
            "--is_mountpoint",
            "1",
        )


def network(guest):
    bridge = guest["bridge"]
    if not re.fullmatch(r"vmbr[0-9]+", bridge):
        raise RuntimeError("Invalid bridge")
    net = ipaddress.ip_interface(guest["address"]).network
    gateway = ipaddress.ip_address(guest["gateway"])
    if gateway not in net:
        raise RuntimeError("Invalid guest gateway")
    interfaces = Path("/etc/network/interfaces")
    if not interfaces.exists():
        write(interfaces, "source /etc/network/interfaces.d/*\n")
    elif not re.search(
        r"^source(?:-directory)?\s+/etc/network/interfaces.d/", interfaces.read_text(), re.M
    ):
        with interfaces.open("a") as stream:
            stream.write("\nsource /etc/network/interfaces.d/*\n")
    Path("/etc/network/interfaces.d").mkdir(exist_ok=True)
    write(
        "/etc/network/interfaces.d/dz10",
        f"auto {bridge}\niface {bridge} inet static\n"
        f"    address {gateway}/{net.prefixlen}\n    bridge-ports none\n"
        "    bridge-stp off\n    bridge-fd 0\n",
    )
    # Bring up only our private bridge; never reload the cloud-facing interface.
    command("ifup", bridge)
    write("/etc/sysctl.d/90-dz10.conf", "net.ipv4.ip_forward=1\n")
    command("sysctl", "-p", "/etc/sysctl.d/90-dz10.conf")
    # Own nftables table only; never flush other firewall rules.
    route = json.loads(command("ip", "-j", "route", "get", "1.1.1.1"))[0]
    uplink = route["dev"]
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", uplink) or uplink == bridge:
        raise RuntimeError("Invalid uplink")
    nft = f'''table ip dz10_nat {{
      chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
        ip saddr {net} oifname "{uplink}" masquerade
      }}
    }}
    '''
    write("/etc/dz10-nat.nft", nft)
    write(
        "/etc/systemd/system/dz10-nat.service",
        """[Unit]
Description=OTUS DZ10 guest NAT
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table ip dz10_nat
ExecStart=/usr/sbin/nft -f /etc/dz10-nat.nft
ExecStop=-/usr/sbin/nft delete table ip dz10_nat
[Install]
WantedBy=multi-user.target
""",
    )
    command("systemctl", "daemon-reload")
    command("systemctl", "enable", "dz10-nat.service")
    command("systemctl", "restart", "dz10-nat.service")


def credentials():
    directory = Path("/var/lib/dz10")
    directory.mkdir(mode=0o700, exist_ok=True)
    password_path = directory / "ui-password"
    if not password_path.exists():
        write(password_path, secrets.token_urlsafe(32), 0o600)
    password = password_path.read_text()
    users = json.loads(command("pveum", "user", "list", "--output-format", "json"))
    for name in ("terraform@pve", "reviewer@pve"):
        if not any(x["userid"] == name for x in users):
            command("pveum", "user", "add", name)
    # Dedicated account within this single-node lab, not the operator's YC identity.
    command("pveum", "acl", "modify", "/", "--users", "terraform@pve", "--roles", "PVEAdmin")
    command("pveum", "acl", "modify", "/", "--users", "reviewer@pve", "--roles", "PVEAuditor")
    command("pvesh", "set", "/access/password", "--userid", "reviewer@pve", "--password", password)
    token_path = directory / "api-token.json"
    if not token_path.exists():
        tokens = json.loads(
            command("pveum", "user", "token", "list", "terraform@pve", "--output-format", "json")
        )
        if any(t["tokenid"] == "dz10" for t in tokens):
            raise RuntimeError("Token exists without recovery file; explicit repair required")
        token = json.loads(
            command(
                "pveum",
                "user",
                "token",
                "add",
                "terraform@pve",
                "dz10",
                "--privsep",
                "0",
                "--output-format",
                "json",
            )
        )
        write(token_path, json.dumps(token), 0o600)
    token = json.loads(token_path.read_text())
    return {
        "api_token": token["full-tokenid"] + "=" + token["value"],
        "ui_username": "reviewer@pve",
        "ui_password": password,
    }


def image(guest):
    target = Path("/var/lib/vz/import/dz10-debian13.qcow2")
    target.parent.mkdir(parents=True, exist_ok=True)

    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha512").hexdigest()

    if not target.exists() or digest(target) != guest["image_sha512"]:
        temporary = target.with_suffix(".part")
        try:
            command(
                "curl",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--max-time",
                "900",
                "--output",
                str(temporary),
                guest["image_url"],
            )
            if digest(temporary) != guest["image_sha512"]:
                raise RuntimeError("Guest image SHA512 mismatch")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)


def progress(stage):
    print("DZ10_PROGRESS:" + stage, file=sys.stderr, flush=True)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    cfg = json.load(sys.stdin)
    progress("storage")
    storage()
    progress("network")
    network(cfg["guest"])
    progress("image")
    image(cfg["guest"])
    progress("cloud_init")
    # 'local' is the standard PVE directory storage; snippets stay private to the node.
    local = json.loads(command("pvesh", "get", "/storage/local", "--output-format", "json"))
    if local.get("path") != "/var/lib/vz" or local.get("type") != "dir":
        raise RuntimeError("Unexpected local storage")
    content = set(local["content"].split(",")) | {"snippets", "iso", "import"}
    command("pvesm", "set", "local", "--content", ",".join(sorted(content)))
    snippets = Path("/var/lib/vz/snippets")
    snippets.mkdir(exist_ok=True)
    write(
        snippets / "dz10-guest.yaml",
        Path("/home/operator/dz10/guest-cloud-init.yaml").read_text(),
        0o600,
    )
    progress("certificate")
    # Use PVE's native certificate; remove only a previous custom override.
    if Path("/etc/pve/local/pveproxy-ssl.pem").exists():
        command("pvenode", "cert", "delete", "--restart", "1")
    progress("accounts")
    result = credentials()
    progress("finish")
    for name in ("pve.key", "pve.crt", "guest-cloud-init.yaml"):
        Path("/home/operator/dz10", name).unlink(missing_ok=True)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        # Arguments may contain generated passwords. Never include them in a traceback/log.
        print(
            f"Provision command failed: {Path(exc.cmd[0]).name}, exit {exc.returncode}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    except Exception as exc:
        message = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("Provision failed: " + message, file=sys.stderr)
        raise SystemExit(1) from None
