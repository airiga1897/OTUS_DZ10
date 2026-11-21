import hashlib
import ipaddress
import json
import shlex
import time
from contextlib import contextmanager

import paramiko
from common import LabError
from progress import Stage, report_stage
from security import ssh_key


class SSHDisconnected(LabError):
    pass


class SSHUnavailable(LabError):
    pass


class Remote:
    def __init__(self, runtime, ip, cfg):
        self.runtime, self.ip, self.cfg = runtime, ip, cfg
        self.client = None

    @report_stage("Подключение к узлу по SSH и проверка адреса клиента")
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
        raise SSHUnavailable(
            "SSH недоступен; проверьте маршрут и разрешённые /32, порт остаётся 22"
        )

    def close(self):
        if self.client:
            self.client.close()

    def command(
        self, command, *, payload=None, timeout=1800, progress=None, allowed_exit_codes=(0,)
    ):
        with Stage(progress) as stage:
            try:
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
                        data = channel.recv_stderr(65536)
                        errors.extend(data)
                        stage.feed(data)
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
                exit_code = channel.recv_exit_status()
                if exit_code == -1:
                    raise SSHDisconnected(
                        "SSH-соединение прервано; состояние задания будет проверено после подключения"
                    )
                if exit_code not in allowed_exit_codes:
                    (self.runtime / "remote-error.log").write_bytes(errors)
                    raise LabError("Ошибка настройки или проверки узла; служебные данные сохранены")
                return out.decode("utf-8")
            except (paramiko.SSHException, OSError, EOFError):
                raise SSHDisconnected(
                    "SSH-соединение прервано; данные восстановления сохранены"
                ) from None

    @report_stage("Передача файлов настройки на узел по SSH")
    def upload(self, source, destination):
        with self.client.open_sftp() as sftp:
            sftp.put(str(source), destination)
            sftp.chmod(destination, 0o600)

    def job_status(self, name):
        value = self.command(
            f"sudo systemctl show dz10-{name}.service --property=LoadState --property=ActiveState "
            "--property=SubState --property=ExecMainStatus --property=Job",
            timeout=20,
            allowed_exit_codes=(0, 4),
        )
        status = dict(line.split("=", 1) for line in value.splitlines() if "=" in line)
        if status.get("LoadState") not in ("loaded", "not-found"):
            raise LabError("Не удалось определить состояние задания Proxmox")
        return status

    def run_job(self, name, command, files, *, input_file=None, timeout=1800):
        """Persist the job and its private result on the node, independent of SSH."""
        if name not in ("install", "configure"):
            raise LabError("Неизвестное задание Proxmox")
        prefix = f"/var/lib/dz10/{name}"
        unit = f"dz10-{name}.service"
        digest = hashlib.sha256(command.encode())
        for source, destination in files:
            digest.update(destination.encode())
            digest.update(source.read_bytes())
        if input_file:
            digest.update(input_file[1].encode())
        fingerprint = digest.hexdigest()
        with Stage(
            "Установка Proxmox VE" if name == "install" else "Настройка Proxmox VE"
        ) as stage:
            status = self.job_status(name)
            active = status.get("ActiveState") in ("activating", "active") or bool(
                status.get("Job")
            )
            old_hash = ""
            if status["LoadState"] == "loaded":
                old_hash = self.command(
                    f"sudo cat {prefix}.sha256", allowed_exit_codes=(0, 1)
                ).strip()
            if active and status.get("SubState") != "exited" and old_hash != fingerprint:
                raise LabError("Работает задание с другими параметрами; файлы узла не изменены")
            if not (active and old_hash == fingerprint):
                other = self.job_status("configure" if name == "install" else "install")
                if (
                    other.get("ActiveState") in ("activating", "active") or other.get("Job")
                ) and other.get("SubState") != "exited":
                    raise LabError("Другое задание Proxmox ещё работает; файлы не изменены")
                if status["LoadState"] == "loaded":
                    self.command(f"sudo systemctl stop {unit}")
                for source, destination in files:
                    self.upload(source, destination)
                if input_file:
                    self.command(
                        "umask 077; cat > /home/operator/dz10/config.json", payload=input_file[1]
                    )
                self.command("sudo install -d -m 700 /var/lib/dz10")
                self.command(f"sudo tee {prefix}.sha256 >/dev/null", payload=fingerprint)
                definition = (
                    "[Unit]\nDescription=OTUS DZ10 managed job\n[Service]\n"
                    "Type=oneshot\nRemainAfterExit=yes\nUMask=0077\n"
                    f"ExecStart={command}\nTimeoutStartSec={timeout}\n"
                    f"StandardOutput=truncate:{prefix}.stdout\n"
                    f"StandardError=truncate:{prefix}.stderr\n"
                )
                if input_file:
                    definition += "StandardInput=file:/home/operator/dz10/config.json\n"
                self.command(f"sudo tee /etc/systemd/system/{unit} >/dev/null", payload=definition)
                self.command("sudo systemctl daemon-reload")
                try:
                    self.command(f"sudo systemctl start --no-block {unit}")
                except (SSHDisconnected, paramiko.SSHException, OSError, EOFError):
                    # The start may already have reached systemd. Never replay it blindly.
                    self.close()
                    try:
                        self.connect(timeout=min(30, timeout))
                    except SSHUnavailable:
                        pass

            else:
                print("[этап] Подхват сохранённого задания на узле", flush=True)
            deadline = time.monotonic() + timeout
            seen = 0
            while time.monotonic() < deadline:
                try:
                    status = self.job_status(name)
                    markers = self.command(
                        f"sudo grep '^DZ10_PROGRESS:' {prefix}.stderr", allowed_exit_codes=(0, 1, 2)
                    ).splitlines()
                    stage.feed(("\n".join(markers[seen:]) + "\n").encode())
                    seen = len(markers)
                    if (
                        status.get("SubState") == "exited"
                        and status.get("ExecMainStatus") == "0"
                        and not status.get("Job")
                    ):
                        return self.command(f"sudo cat {prefix}.stdout")
                    if status.get("ActiveState") == "failed":
                        errors = self.command(f"sudo cat {prefix}.stderr")
                        (self.runtime / "remote-error.log").write_text(errors, encoding="utf-8")
                        raise LabError("Задание Proxmox завершилось с ошибкой; журнал сохранён")
                    if status.get("LoadState") == "not-found" or (
                        status.get("ActiveState") == "inactive" and not status.get("Job")
                    ):
                        raise LabError(
                            "Задание Proxmox отсутствует или остановлено; данные сохранены"
                        )
                except (SSHDisconnected, paramiko.SSHException, OSError, EOFError):
                    print(
                        "[этап] Связь потеряна; задание продолжает работу на узле. Переподключение.",
                        flush=True,
                    )
                    self.close()
                    while time.monotonic() < deadline:
                        try:
                            self.connect(timeout=min(30, max(1, deadline - time.monotonic())))
                            break
                        except SSHUnavailable:
                            continue
                time.sleep(min(5, max(0, deadline - time.monotonic())))
            raise LabError(
                "Истекло время ожидания задания; оно и данные восстановления сохранены на узле"
            )

    def configure(self, root, context):
        self.command("cloud-init status --wait", timeout=900, progress="Ожидание cloud-init узла")
        self.command("install -d -m 700 /home/operator/dz10")
        install = self.cfg["proxmox"]
        args = [
            self.cfg["host"]["name"],
            context["host"]["private_ip"],
            install["version"],
            install["kernel_package"],
            install["kernel_version"],
            install["key_sha256"],
        ]
        files = [
            (root / "provision" / name, "/home/operator/dz10/" + name)
            for name in ("install.sh", "configure.py", "proxmox-archive-keyring.gpg")
        ]
        files.append(
            (root / "config/proxmox-packages.json", "/home/operator/dz10/proxmox-packages.json")
        )
        self.run_job(
            "install", "/bin/bash /home/operator/dz10/install.sh " + shlex.join(args), files
        )
        if not self.command("uname -r").strip().endswith("-pve"):
            with Stage("Перезагрузка узла с ядром Proxmox"):
                self.command("sudo systemd-run --on-active=3 /usr/sbin/reboot")
                self.close()
                time.sleep(15)
                self.connect()
                if not self.command("uname -r").strip().endswith("-pve"):
                    raise LabError("Узел не загрузился с ядром Proxmox")
        remote_config = {"guest": self.cfg["guest"], "namespace": self.cfg["namespace"]}
        result = self.run_job(
            "configure",
            "/usr/bin/python3 /home/operator/dz10/configure.py",
            [
                (root / "provision/configure.py", "/home/operator/dz10/configure.py"),
                (
                    self.runtime / "guest-cloud-init.yaml",
                    "/home/operator/dz10/guest-cloud-init.yaml",
                ),
            ],
            input_file=("config.json", json.dumps(remote_config)),
        )
        return json.loads(result)

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

    @report_stage("Проверка параметров гостя, SSH и cloud-init")
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
                    "sudo cloud-init status --wait",
                    timeout=self.cfg["timeouts"]["guest_seconds"],
                    progress="Ожидание cloud-init гостевой Debian",
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
