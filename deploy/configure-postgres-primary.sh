#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if [ "$#" -ne 1 ]; then
  echo "Usage: sh deploy/configure-postgres-primary.sh <standby-ip>" >&2
  exit 2
fi
standby_ip=$1

case "$standby_ip" in
  *[!0-9.]*|*.*.*.*.*|.*|*.) echo "Standby IP 格式不正確：$standby_ip" >&2; exit 2 ;;
esac
old_ifs=$IFS; IFS=.; set -- $standby_ip; IFS=$old_ifs
if [ "$#" -ne 4 ]; then echo "Standby IP 格式不正確：$standby_ip" >&2; exit 2; fi
for octet in "$@"; do
  case "$octet" in ''|*[!0-9]*) echo "Standby IP 格式不正確" >&2; exit 2;; esac
  [ "$octet" -le 255 ] || { echo "Standby IP 格式不正確" >&2; exit 2; }
done

[ -f .env ] || { echo "找不到 .env，請先由 .env.example 建立。" >&2; exit 1; }
set -a
# shellcheck disable=SC1091
. ./.env
set +a

repl_user=${POSTGRES_REPLICATION_USER:-linux_ai_replication}
repl_password=${POSTGRES_REPLICATION_PASSWORD:-}
slot=${POSTGRES_REPLICATION_SLOT:-linux_ai_standby}
db_user=${POSTGRES_USER:-linux_ai}
db_name=${POSTGRES_DB:-linux_ai}
bind_ip=${POSTGRES_BIND_IP:-127.0.0.1}

case "$repl_user" in ''|[0-9]*|*[!A-Za-z0-9_]*) echo "複寫帳號只允許英文字母、數字與底線，且不可由數字開頭。" >&2; exit 2;; esac
case "$slot" in ''|[0-9]*|*[!A-Za-z0-9_]*) echo "Slot 名稱只允許英文字母、數字與底線，且不可由數字開頭。" >&2; exit 2;; esac
[ "${#repl_password}" -ge 16 ] || { echo "POSTGRES_REPLICATION_PASSWORD 至少需要 16 碼。" >&2; exit 1; }
case "$bind_ip" in 127.*|localhost) echo "POSTGRES_BIND_IP 仍是 $bind_ip；請改成中央主機的固定區網 IP，再重建 postgres 容器。" >&2; exit 1;; esac

docker compose exec -T \
  -e REPL_USER="$repl_user" -e REPL_PASSWORD="$repl_password" -e REPL_SLOT="$slot" \
  postgres sh -eu -c '
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
      -v repl_user="$REPL_USER" -v repl_password="$REPL_PASSWORD" -v repl_slot="$REPL_SLOT" <<'"'"'SQL'"'"'
SELECT format('"'"'CREATE ROLE %I WITH REPLICATION LOGIN PASSWORD %L'"'"', :'"'"'repl_user'"'"', :'"'"'repl_password'"'"')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'"'"'repl_user'"'"') \gexec
SELECT format('"'"'ALTER ROLE %I WITH REPLICATION LOGIN PASSWORD %L'"'"', :'"'"'repl_user'"'"', :'"'"'repl_password'"'"') \gexec
SELECT pg_create_physical_replication_slot(:'"'"'repl_slot'"'"')
WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = :'"'"'repl_slot'"'"');
SQL
  '

hba_file=$(docker compose exec -T postgres psql -U "$db_user" -d "$db_name" -Atc 'SHOW hba_file' | tr -d '\r')
hba_line="host replication $repl_user $standby_ip/32 scram-sha-256"
docker compose exec -T -e HBA_FILE="$hba_file" -e HBA_LINE="$hba_line" postgres sh -eu -c '
  grep -qxF "$HBA_LINE" "$HBA_FILE" || printf "%s\n" "$HBA_LINE" >> "$HBA_FILE"
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT pg_reload_conf();"
'

echo "Primary 複寫設定完成："
echo "  Standby IP: $standby_ip/32"
echo "  Replication user: $repl_user"
echo "  Physical slot: $slot"
echo "此腳本沒有修改 UFW。若啟用 UFW，只允許 $standby_ip 連入 TCP 5432。"
echo "接著在備援中央主機執行：docker compose -f compose.standby.yaml up -d"
