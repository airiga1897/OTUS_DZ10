import ipaddress
import json
import shlex
import time
from contextlib import contextmanager

import paramiko
from common import LabError
from security import ssh_key


class Remote:
    def __init__(self, runtime, ip, cfg):
        self.runtime, self.ip, self.cfg = runtime, ip, cfg
        self.client = None

    def connect(self, timeout=None):
        deadline = time.monotonic() + (timeout or self.cfg["timeouts"]["host_seconds"])
        pub = ssh_key(self.runtime / "pve-host").split()[1]
        known = self.runtime / "known_hosts"
        known.write_text(f"{self.ip} ssh-ed25519 {pub}\n", encoding="utf-8")
        while time.monotonic() < deadline:
            client = paramiko.SSHClient()
            client.load_host_keys(str(known))
            try:
                client.connect(
                    self.ip,
                    username="operator",
                    key_filename=str(self.runtime / "operator"),
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=10,
                    banner_timeout=15,
                    auth_timeout=15,
                )
                client.get_transport().set_keepalive(15)
                self.client = client
                # SSH_CONNECTION reports the actual source of this TCP connection.
                actual = self.command("printf '%s' \"$SSH_CONNECTION\"").split()[0]
                if actual + "/32" not in self.cfg["effective_admin_cidrs"]:
                    raise LabError("Фактический IPv4 SSH-клиента отсутствует в разрешённых /32")
                return self
            except paramiko.BadHostKeyException:
                client.close()
                raise LabError("SSH-ключ узла не соответствует закреплённому") from None
            except (OSError, paramiko.SSHException):
                client.close()
                time.sleep(self.cfg["timeouts"]["poll_seconds"])
        raise LabError("SSH недоступен; проверьте маршрут и разрешённые /32, порт остаётся 22")

    def close(self):
        if self.client:
            self.client.close()

    def command(self, command, *, payload=None, timeout=1800):
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        if payload is not None:
            stdin.write(payload)
        stdin.channel.shutdown_write()
        # Drain both streams concurrently to avoid a full stderr pipe.
        channel = stdout.channel
        out = bytearray()
        errors = bytearray()
        deadline = time.monotonic() + timeout
        while True:
            if channel.recv_ready():
                out.extend(channel.recv(65536))
            if channel.recv_stderr_ready():
                errors.extend(channel.recv_stderr(65536))
            if (
                channel.exit_status_ready()
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                break
            if time.monotonic() > deadline:
                channel.close()
                raise LabError("Превышено время удалённой команды")
            time.sleep(0.05)
        if channel.recv_exit_status():
            (self.runtime / "remote-error.log").write_bytes(errors)
            raise LabError("Ошибка настройки или проверки узла; служебные данные сохранены")
        return out.decode("utf-8")

    def upload(self, source, destination):
        with self.client.open_sftp() as sftp:
            sftp.put(str(source), destination)
            sftp.chmod(destination, 0o600)

    def configure(self, root, context):
        self.command("cloud-init status --wait", timeout=900)
        self.command("install -d -m 700 /home/operator/dz10")
        for name in ("install.sh", "configure.py", "proxmox-archive-keyring.gpg"):
            self.upload(root / "provision" / name, "/home/operator/dz10/" + name)
        self.upload(
            root / "config/proxmox-packages.json", "/home/operator/dz10/proxmox-packages.json"
        )
        install = self.cfg["proxmox"]
        args = [
            self.cfg["host"]["name"],
            context["host"]["private_ip"],
            install["version"],
            install["kernel_package"],
            install["kernel_version"],
            install["key_sha256"],
        ]
        self.command("sudo bash /home/operator/dz10/install.sh " + shlex.join(args), timeout=1800)
        if not self.command("uname -r").strip().endswith("-pve"):
            self.command("sudo systemd-run --on-active=3 /usr/sbin/reboot")
            self.close()
            time.sleep(15)
            self.connect()
            if not self.command("uname -r").strip().endswith("-pve"):
                raise LabError("Узел не загрузился с ядром Proxmox")
        for name in ("guest-cloud-init.yaml",):
            self.upload(self.runtime / name, "/home/operator/dz10/" + name)
        remote_config = {"guest": self.cfg["guest"], "namespace": self.cfg["namespace"]}
        result = self.command(
            "sudo python3 /home/operator/dz10/configure.py",
            payload=json.dumps(remote_config),
            timeout=1800,
        )
        credentials = json.loads(result)
        # Never print token or password; the caller writes them only to the protected runtime.
        return credentials

    @contextmanager
    def guest(self):
        address = str(ipaddress.ip_interface(self.cfg["guest"]["address"]).ip)
        key = paramiko.Ed25519Key.from_private_key_file(str(self.runtime / "guest-host"))
        deadline = time.monotonic() + self.cfg["timeouts"]["guest_seconds"]
        client = None
        while time.monotonic() < deadline:
            client = paramiko.SSHClient()
            client.get_host_keys().add(address, "ssh-ed25519", key)
            try:
                channel = self.client.get_transport().open_channel(
                    "direct-tcpip", (address, 22), ("127.0.0.1", 0), timeout=10
                )
                client.connect(
                    address,
                    username=self.cfg["guest"]["username"],
                    key_filename=str(self.runtime / "operator"),
                    sock=channel,
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=10,
                    banner_timeout=15,
                    auth_timeout=15,
                )
                client.get_transport().set_keepalive(15)
                break
            except paramiko.BadHostKeyException:
                client.close()
                raise LabError("SSH-ключ гостя не соответствует закреплённому") from None
            except (OSError, paramiko.SSHException):
                client.close()
                client = None
                time.sleep(self.cfg["timeouts"]["poll_seconds"])
        if client is None:
            raise LabError("Гостевая ОС не стала доступна по SSH за отведённое время")
        try:
            yield client
        finally:
            client.close()

    def verify_guest(self):
        vm = self.cfg["guest"]
        current = json.loads(
            self.command(
                f"sudo pvesh get /nodes/{self.cfg['host']['name']}/qemu/{vm['vm_id']}/config --output-format json"
            )
        )
        expected = {"name": vm["name"], "cores": vm["cores"], "memory": vm["memory_mib"], "kvm": 0}
        if any(str(current.get(k)) != str(v) for k, v in expected.items()):
            raise LabError("Параметры гостя в Proxmox не соответствуют конфигурации")
        if f"size={vm['disk_gib']}G" not in current.get(
            "virtio0", ""
        ) or f"bridge={vm['bridge']}" not in current.get("net0", ""):
            raise LabError("Диск или сеть гостя не соответствуют конфигурации")
        with self.guest() as client:
            previous = self.client
            try:
                self.client = client
                self.command(
                    "sudo cloud-init status --wait", timeout=self.cfg["timeouts"]["guest_seconds"]
                )
                checks = json.loads(
                    self.command(
                        "python3 -c "
                        + shlex.quote(
                            "import json,os,subprocess; "
                            "print(json.dumps({'cpu':os.cpu_count(),"
                            "'memory':int(open('/proc/meminfo').read().split('MemTotal:')[1].split()[0]),"
                            "'disk':int(subprocess.check_output(['lsblk','-bndo','SIZE','/dev/vda'])),"
                            "'os':open('/etc/os-release').read(),"
                            "'net':subprocess.check_output(['ip','-j','-4','addr']).decode()}))"
                        )
                    )
                )
            finally:
                self.client = previous
        address = str(ipaddress.ip_interface(vm["address"]).ip)
        interfaces = json.loads(checks["net"])
        addresses = [a["local"] for nic in interfaces for a in nic.get("addr_info", [])]
        if (
            checks["cpu"] != vm["cores"]
            or checks["disk"] != vm["disk_gib"] * 2**30
            or not vm["memory_mib"] * 0.8 * 1024 <= checks["memory"] <= vm["memory_mib"] * 1024
            or 'VERSION_ID="13"' not in checks["os"]
            or address not in addresses
        ):
            raise LabError("Параметры внутри гостевой ОС не соответствуют заданным")
