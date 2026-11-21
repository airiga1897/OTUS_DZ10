"""Safe stage output: fixed labels, no command arguments or raw process streams."""

import threading
import time
from functools import wraps

PROVISION_STAGES = {
    "host_prepare": "Подготовка Debian и имени узла",
    "debian_update": "Обновление индексов Debian с зеркала Яндекса",
    "base_packages": "Установка базовых пакетов",
    "pve_repo": "Настройка подписанного репозитория Proxmox",
    "pve_update": "Обновление индексов Proxmox",
    "pve_kernel": "Установка ядра Proxmox",
    "pve_download": "Загрузка пакетов Proxmox",
    "pve_install": "Установка пакетов Proxmox",
    "bootloader": "Настройка загрузчика",
    "storage": "Проверка и настройка хранилища гостя",
    "network": "Настройка приватного моста и NAT",
    "image": "Загрузка и проверка SHA512 образа Debian",
    "cloud_init": "Подготовка cloud-init гостя",
    "certificate": "Подготовка штатного HTTPS Proxmox",
    "accounts": "Настройка учётных записей и токена Proxmox",
    "finish": "Завершение настройки узла",
}


class Stage:
    def __init__(self, label, *, interval=30):
        self.label = label
        self.interval = interval
        self.pending = b""
        self.stopped = threading.Event()
        self.worker = None

    def __enter__(self):
        self.started = time.monotonic()
        if self.label:
            print(f"[начало] {self.label}", flush=True)
            self.worker = threading.Thread(target=self._heartbeat, daemon=True)
            self.worker.start()
        return self

    def _heartbeat(self):
        while not self.stopped.wait(self.interval):
            elapsed = int(time.monotonic() - self.started)
            print(f"[ожидание] {self.label}; операция выполняется, {elapsed} с", flush=True)

    def feed(self, data):
        """Accept only complete allowlisted stderr markers, including fragmented reads."""
        if not self.label:
            return
        lines = (self.pending + data).split(b"\n")
        self.pending = lines.pop()[-256:]
        for line in lines:
            marker = line.rstrip(b"\r").removeprefix(b"DZ10_PROGRESS:")
            if line.startswith(b"DZ10_PROGRESS:"):
                label = PROVISION_STAGES.get(marker.decode("ascii", errors="replace"))
                if label:
                    self.label = label
                    print(f"[этап] {label}", flush=True)

    def __exit__(self, exc_type, exc, traceback):
        self.stopped.set()
        if self.worker:
            self.worker.join()
        if self.label:
            status = "готово" if exc_type is None else "ошибка"
            print(f"[{status}] {self.label}", flush=True)


def report_stage(label):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with Stage(label):
                return function(*args, **kwargs)

        return wrapped

    return decorate
