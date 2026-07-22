#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer with sudo" >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -m 0755 "$SCRIPT_DIR/external-watchdog.sh" /usr/local/sbin/linux-ai-external-watchdog
install -m 0644 "$SCRIPT_DIR/linux-ai-watchdog.service" /etc/systemd/system/linux-ai-watchdog.service
if [ ! -f /etc/linux-ai-watchdog.env ]; then
  install -m 0600 "$SCRIPT_DIR/linux-ai-watchdog.env.example" /etc/linux-ai-watchdog.env
fi
systemctl daemon-reload
echo "Edit /etc/linux-ai-watchdog.env, then run: sudo systemctl enable --now linux-ai-watchdog"
