#!/bin/sh
set -eu

mkdir -p "${CONFIG_REPO_PATH:-/var/lib/linux-ai-config}"
chown -R app:app "${CONFIG_REPO_PATH:-/var/lib/linux-ai-config}"

exec gosu app "$@"
