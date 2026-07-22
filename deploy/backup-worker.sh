#!/bin/sh
set -eu

BACKUP_DIR=${BACKUP_DIR:-/backups}
BACKUP_INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-24}
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-7}
BACKUP_POLL_SECONDS=${BACKUP_POLL_SECONDS:-10}

for value in "$BACKUP_INTERVAL_HOURS" "$BACKUP_RETENTION_DAYS" "$BACKUP_POLL_SECONDS"; do
  case "$value" in
    ''|*[!0-9]*|0) echo "Backup interval settings must be positive integers" >&2; exit 1 ;;
  esac
done

mkdir -p "$BACKUP_DIR"

psql_base() {
  psql -X -v ON_ERROR_STOP=1 -qAt "$@"
}

mark_failed() {
  job_id=$1
  detail=$2
  psql_base -v job_id="$job_id" -v detail="$detail" <<'SQL'
UPDATE database_backup_jobs
SET status = 'failed', detail = :'detail', completed_at = NOW()
WHERE id = :'job_id';
SQL
}

while true; do
  date +%s > "$BACKUP_DIR/.worker-heartbeat"

  psql_base <<'SQL'
UPDATE database_backup_jobs
SET status = 'failed', detail = '備份工作逾時，已由背景服務終止', completed_at = NOW()
WHERE status = 'running' AND started_at < NOW() - INTERVAL '2 hours';
SQL

  psql_base -v interval_hours="$BACKUP_INTERVAL_HOURS" <<'SQL'
INSERT INTO database_backup_jobs (id, kind, status)
SELECT 'bkp-' || substr(md5(random()::text || clock_timestamp()::text), 1, 20),
       'scheduled', 'queued'
WHERE NOT EXISTS (
    SELECT 1 FROM database_backup_jobs WHERE status IN ('queued', 'running')
)
AND NOT EXISTS (
    SELECT 1 FROM database_backup_jobs
    WHERE status = 'success'
      AND completed_at >= NOW() - make_interval(hours => :'interval_hours'::int)
);
SQL

  job_id=$(psql_base <<'SQL'
WITH selected AS (
    SELECT id FROM database_backup_jobs
    WHERE status = 'queued'
    ORDER BY requested_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE database_backup_jobs b
SET status = 'running', started_at = NOW(), detail = '正在建立 PostgreSQL 備份'
FROM selected
WHERE b.id = selected.id
RETURNING b.id;
SQL
  )

  if [ -n "$job_id" ]; then
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    filename="linux_ai_${stamp}_${job_id}.dump"
    backup_path="$BACKUP_DIR/$filename"
    recovery_filename="linux_ai_recovery_${stamp}_${job_id}.tar.gz"
    recovery_path="$BACKUP_DIR/$recovery_filename"
    verify_db="linux_ai_verify_$(date +%s)_$$"

    if ! pg_dump --format=custom --no-owner --no-privileges --file="$backup_path"; then
      rm -f "$backup_path"
      mark_failed "$job_id" "pg_dump 建立備份失敗"
      sleep "$BACKUP_POLL_SECONDS"
      continue
    fi

    if ! pg_restore --list "$backup_path" >/dev/null 2>&1; then
      rm -f "$backup_path"
      mark_failed "$job_id" "備份封存格式驗證失敗"
      sleep "$BACKUP_POLL_SECONDS"
      continue
    fi

    restore_ok=false
    if createdb "$verify_db" && pg_restore --no-owner --no-privileges --dbname="$verify_db" "$backup_path" >/dev/null 2>&1; then
      table_count=$(psql -X -qAt --dbname="$verify_db" -c "SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'" || echo 0)
      if [ "${table_count:-0}" -gt 0 ]; then
        restore_ok=true
      fi
    fi
    dropdb --if-exists "$verify_db" >/dev/null 2>&1 || true

    if [ "$restore_ok" != true ]; then
      rm -f "$backup_path"
      mark_failed "$job_id" "還原演練失敗，未保留此備份"
      sleep "$BACKUP_POLL_SECONDS"
      continue
    fi

    if ! tar -czf "$recovery_path" -C /recovery-input config-history known_hosts \
      || ! tar -tzf "$recovery_path" >/dev/null 2>&1; then
      rm -f "$backup_path" "$recovery_path"
      mark_failed "$job_id" "Git 設定版控與 known_hosts 復原封存建立失敗"
      sleep "$BACKUP_POLL_SECONDS"
      continue
    fi

    size_bytes=$(wc -c < "$backup_path" | tr -d ' ')
    checksum=$(sha256sum "$backup_path" | cut -d ' ' -f 1)
    recovery_size_bytes=$(wc -c < "$recovery_path" | tr -d ' ')
    recovery_checksum=$(sha256sum "$recovery_path" | cut -d ' ' -f 1)
    psql_base \
      -v job_id="$job_id" \
      -v filename="$filename" \
      -v size_bytes="$size_bytes" \
      -v checksum="$checksum" \
      -v recovery_filename="$recovery_filename" \
      -v recovery_size_bytes="$recovery_size_bytes" \
      -v recovery_checksum="$recovery_checksum" <<'SQL'
UPDATE database_backup_jobs
SET status = 'success', filename = :'filename', size_bytes = :'size_bytes'::bigint,
    sha256 = :'checksum', restore_verified = TRUE,
    recovery_filename = :'recovery_filename',
    recovery_size_bytes = :'recovery_size_bytes'::bigint,
    recovery_sha256 = :'recovery_checksum', recovery_verified = TRUE,
    detail = 'PostgreSQL 還原演練與中央復原封存驗證均已通過', completed_at = NOW()
WHERE id = :'job_id';
SQL
  fi

  find "$BACKUP_DIR" -type f -name '*.dump' -mtime "+$BACKUP_RETENTION_DAYS" -delete
  find "$BACKUP_DIR" -type f -name '*.tar.gz' -mtime "+$BACKUP_RETENTION_DAYS" -delete
  psql_base -v retention_days="$BACKUP_RETENTION_DAYS" <<'SQL'
UPDATE database_backup_jobs
SET filename = NULL, recovery_filename = NULL, detail = '備份檔已依保留政策刪除'
WHERE filename IS NOT NULL
  AND completed_at < NOW() - make_interval(days => :'retention_days'::int);
SQL

  sleep "$BACKUP_POLL_SECONDS"
done
