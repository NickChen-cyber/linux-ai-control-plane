#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "請使用 sudo 執行：sudo sh deploy/install-managed-host-sudoers.sh" >&2
  exit 1
fi

if ! id linux-agent >/dev/null 2>&1; then
  echo "找不到 linux-agent 帳號，請先完成主機註冊。" >&2
  exit 1
fi

tmp_file=$(mktemp)
trap 'rm -f "$tmp_file"' EXIT INT TERM

printf '%s\n' \
  'linux-agent ALL=(root) NOPASSWD: /usr/bin/systemctl reset-failed' \
  'linux-agent ALL=(root) NOPASSWD: /usr/bin/apt-get update' \
  'linux-agent ALL=(root) NOPASSWD: /usr/bin/unattended-upgrade -d' > "$tmp_file"

chmod 0440 "$tmp_file"
visudo -cf "$tmp_file"
install -m 0440 -o root -g root "$tmp_file" /etc/sudoers.d/linux-ai-agent

if id -nG linux-agent | tr ' ' '\n' | grep -qx sudo; then
  gpasswd -d linux-agent sudo
fi

echo "已安裝受限 sudoers：/etc/sudoers.d/linux-ai-agent"
echo "只允許 reset-failed、apt-get update 與 unattended-upgrade -d。"
echo "已確認 linux-agent 不再屬於 sudo 群組。"
