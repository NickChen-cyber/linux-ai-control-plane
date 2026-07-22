#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "請使用 sudo 執行此腳本" >&2; exit 1; }
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || { echo "目前只支援 Ubuntu" >&2; exit 1; }

operator=${1:-${SUDO_USER:-}}
[ -n "$operator" ] && id "$operator" >/dev/null 2>&1 || { echo "請指定既有管理帳號，例如：sudo $0 nickc" >&2; exit 1; }

cpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)
mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
disk_kib=$(df -Pk / | awk 'NR==2 {print $4}')
[ "$cpu" -ge 2 ] || { echo "CPU 不足 2 核心，停止準備" >&2; exit 1; }
[ "$mem_kib" -ge 2097152 ] || { echo "記憶體不足 2 GB，請先關機調整 VM RAM" >&2; exit 1; }
[ "$disk_kib" -ge 20971520 ] || { echo "根目錄可用空間不足 20 GB" >&2; exit 1; }

apt-get update
apt-get install -y ca-certificates curl git gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
arch=$(dpkg --print-architecture)
codename=${UBUNTU_CODENAME:-$VERSION_CODENAME}
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' "$arch" "$codename" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker "$operator"
install -d -m 0750 -o "$operator" -g "$operator" /opt/linux-ai-standby
systemctl enable --now docker

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$script_dir/verify-cold-standby.sh"
echo "請重新登入 $operator，讓 docker 群組權限生效。"
echo '腳本不會開放防火牆、不會啟動 PostgreSQL 複寫，也不會複製任何密碼或私鑰。'
