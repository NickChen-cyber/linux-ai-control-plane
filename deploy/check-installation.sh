#!/bin/sh
set -eu

project_dir=${1:-$(pwd)}
failed=0
check() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then printf 'OK   %s\n' "$label"; else printf 'FAIL %s\n' "$label"; failed=1; fi
}

test -d "$project_dir" || { echo "找不到專案目錄：$project_dir"; exit 2; }
check "Docker Engine" docker version
check "Docker Compose" docker compose version
check "Git" git --version
check ".env" test -f "$project_dir/.env"
check "compose.yaml" test -f "$project_dir/compose.yaml"
check "SSH private key" test -r "${SSH_KEY_PATH:-/home/nickc/.ssh/linux_ai_agent}"
check "known_hosts" test -r "${KNOWN_HOSTS_PATH:-/home/nickc/.ssh/known_hosts}"
check "Compose config" docker compose -f "$project_dir/compose.yaml" config --quiet
exit "$failed"
