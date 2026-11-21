"""Idempotent PVE configuration calls independent of the provisioning SSH session."""

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from common import LabError
from progress import report_stage


class ProxmoxAPI:
    def __init__(self, address, token):
        if not token:
            raise LabError("Нет служебного токена Proxmox")
        self.base = f"https://{address}:8006/api2/json"
        self.token = token
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE  # Agreed native PVE certificate in this lab.

    def request(self, path, values=None):
        """Retry only reads and assignment of kvm=0; never replay a VM start here."""
        payload = None if values is None else urllib.parse.urlencode(values).encode()
        request = urllib.request.Request(
            self.base + path,
            data=payload,
            method="GET" if values is None else "PUT",
            headers={"Authorization": "PVEAPIToken=" + self.token},
        )
        deadline = time.monotonic() + 60
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LabError("API Proxmox не дал достоверный ответ; state сохранён")
            try:
                with urllib.request.urlopen(
                    request, context=self.tls, timeout=min(30, remaining)
                ) as response:
                    return json.load(response)["data"]
            except (OSError, ValueError, KeyError, TypeError) as exc:
                if isinstance(exc, urllib.error.HTTPError):
                    status = exc.code
                    exc.close()
                    if status not in (502, 503, 504):
                        raise LabError(
                            f"API Proxmox: HTTP {status}; проверьте права токена"
                        ) from None
                print("[ожидание] API Proxmox временно недоступен; повтор запроса", flush=True)
                time.sleep(min(2, max(0, deadline - time.monotonic())))

    @report_stage("Настройка гостя для QEMU без KVM через HTTPS API")
    def disable_kvm(self, node, vm_id):
        path = f"/nodes/{urllib.parse.quote(node, safe='')}/qemu/{int(vm_id)}/config"
        current = self.request(path)
        if not isinstance(current, dict):
            raise LabError("API Proxmox вернул некорректную конфигурацию гостя")
        if str(current.get("kvm", 1)) == "0":
            return
        self.request(path, {"kvm": 0})
        current = self.request(path)
        if not isinstance(current, dict) or str(current.get("kvm", 1)) != "0":
            raise LabError("API Proxmox не подтвердил kvm=0; запуск гостя отменён")
