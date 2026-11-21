#!/bin/bash
set -euo pipefail
exec 1>&2
export DEBIAN_FRONTEND=noninteractive
node=$1 private_ip=$2 version=$3 kernel=$4 kernel_version=$5 key_sha=$6
test "$(id -u)" = 0
. /etc/os-release
test "$ID" = debian && test "$VERSION_ID" = 13
hostnamectl set-hostname "$node"
# Proxmox requires the hostname to resolve to the node's non-loopback address.
python3 - "$node" "$private_ip" <<'PY'
import ipaddress, pathlib, sys
name, address = sys.argv[1:]
ipaddress.ip_address(address)
p = pathlib.Path('/etc/hosts')
lines = [line for line in p.read_text().splitlines() if name not in line.split()[1:]]
p.write_text('\n'.join(lines) + '\n' + address + ' ' + name + '\n')
PY
# Use the reachable Yandex mirrors, retaining Debian/Proxmox signature checks.
python3 - <<'PYMIRROR'
from pathlib import Path
paths = [Path('/etc/apt/sources.list'), *Path('/etc/apt/sources.list.d').glob('*.list'), *Path('/etc/apt/sources.list.d').glob('*.sources')]
for path in paths:
    if path.exists():
        text = path.read_text()
        for origin in ('http://security.debian.org/debian-security', 'https://security.debian.org/debian-security', 'http://security.debian.org', 'https://security.debian.org'):
            text = text.replace(origin, 'https://mirror.yandex.ru/debian-security')
        text = text.replace('http://download.proxmox.com/debian/pve', 'https://mirror.yandex.ru/mirrors/download.proxmox.com/debian/pve')
        path.write_text(text)
PYMIRROR
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=20 update --error-on=any
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=20 install -y ca-certificates curl gnupg
install -m 644 /home/operator/dz10/proxmox-archive-keyring.gpg /usr/share/keyrings/proxmox-archive-keyring.gpg
echo "$key_sha  /usr/share/keyrings/proxmox-archive-keyring.gpg" | sha256sum -c -
cat >/etc/apt/sources.list.d/dz10-pve.sources <<'EOF'
Types: deb
URIs: https://mirror.yandex.ru/mirrors/download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
# This is a private lab using the signed no-subscription repository.
rm -f /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/pve-enterprise.list
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=20 update --error-on=any
python3 - <<'PYPINS'
import json
from pathlib import Path
pins = json.loads(Path('/home/operator/dz10/proxmox-packages.json').read_text())
text = '\n\n'.join(f'Package: {name}\nPin: version {version or "*"}\nPin-Priority: {1001 if version else -1}' for name, version in pins.items()) + '\n'
Path('/etc/apt/preferences.d/dz10-pve').write_text(text)
PYPINS
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=20 install -y "$kernel=$kernel_version"
# Keep the cloud Debian kernel as a recovery option. PVE's kernel is selected by GRUB.
# Seed the stock LXC catalogue from the signed package. This lab uses QEMU;
# its installation must not wait for the optional external LXC catalogue update.
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=20 install --download-only -y "proxmox-ve=$version" ifupdown2 nftables e2fsprogs python3 curl
if test ! -e /var/lib/pve-manager/apl-info/download.proxmox.com; then
    mkdir -p /var/lib/pve-manager/apl-info
    package=$(find /var/cache/apt/archives -maxdepth 1 -name 'pve-manager_*.deb' -print -quit)
    test -n "$package"
    dpkg-deb --fsys-tarfile "$package" | tar -xOf - ./usr/share/doc/pve-manager/aplinfo.dat > /var/lib/pve-manager/apl-info/download.proxmox.com
fi
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=20 install -y "proxmox-ve=$version" ifupdown2 nftables e2fsprogs python3 curl
rm -f /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/pve-enterprise.list
apt-mark hold proxmox-ve "$kernel"
update-grub
