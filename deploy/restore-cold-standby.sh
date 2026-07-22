#!/bin/sh
set -eu

usage() {
  echo "用法: CONFIRM_RESTORE=RESTORE $0 DB_DUMP DB_SHA256 RECOVERY_TAR RECOVERY_SHA256" >&2
  exit 2
}

[ "$#" -eq 4 ] || usage
[ "${CONFIRM_RESTORE:-}" = "RESTORE" ] || { echo "必須設定 CONFIRM_RESTORE=RESTORE" >&2; exit 2; }

db_dump=$1
db_sha=$2
recovery_tar=$3
recovery_sha=$4
[ -f "$db_dump" ] && [ -f "$recovery_tar" ] || { echo "找不到備份檔" >&2; exit 1; }

printf '%s  %s\n' "$db_sha" "$db_dump" | sha256sum -c -
printf '%s  %s\n' "$recovery_sha" "$recovery_tar" | sha256sum -c -

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
tar -xzf "$recovery_tar" -C "$staging"
[ -d "$staging/config-history/.git" ] || { echo "復原封存缺少 Git 歷史" >&2; exit 1; }
[ -f "$staging/known_hosts" ] || { echo "復原封存缺少 known_hosts" >&2; exit 1; }

. ./.env
db=${POSTGRES_DB:-linux_ai}
user=${POSTGRES_USER:-linux_ai}
known_hosts=${KNOWN_HOSTS_PATH:-/home/nickc/.ssh/known_hosts}

docker compose stop gateway ui backup api
docker compose exec -T postgres psql -U "$user" -d postgres -v ON_ERROR_STOP=1 \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$db' AND pid <> pg_backend_pid();"
docker compose exec -T postgres dropdb -U "$user" --if-exists "$db"
docker compose exec -T postgres createdb -U "$user" "$db"
docker compose exec -T postgres pg_restore -U "$user" -d "$db" --no-owner --no-privileges < "$db_dump"

docker compose run --rm --no-deps -v "$staging/config-history:/source:ro" api \
  sh -c 'rm -rf /var/lib/linux-ai-config/.git /var/lib/linux-ai-config/config.json; cp -a /source/. /var/lib/linux-ai-config/'
cp "$known_hosts" "$known_hosts.before-cold-restore"
cp "$staging/known_hosts" "$known_hosts"
chmod 600 "$known_hosts"

docker compose up -d
echo "冷備還原完成；請檢查 docker compose ps 與 /api/health。"
