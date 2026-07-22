#!/bin/sh
set -eu

: "${POSTGRES_PRIMARY_HOST:?POSTGRES_PRIMARY_HOST is required}"
: "${POSTGRES_PRIMARY_PORT:=5432}"
: "${POSTGRES_REPLICATION_USER:=linux_ai_replication}"
: "${POSTGRES_REPLICATION_PASSWORD:?POSTGRES_REPLICATION_PASSWORD is required}"
: "${POSTGRES_REPLICATION_SLOT:=linux_ai_standby}"
: "${PGDATA:=/var/lib/postgresql/18/docker}"

mkdir -p "$PGDATA"
chown -R postgres:postgres "$(dirname "$PGDATA")"
chmod 700 "$PGDATA"

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "Initializing PostgreSQL standby from ${POSTGRES_PRIMARY_HOST}:${POSTGRES_PRIMARY_PORT}"
  find "$PGDATA" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  export PGPASSWORD="$POSTGRES_REPLICATION_PASSWORD"
  gosu postgres pg_basebackup \
    --host="$POSTGRES_PRIMARY_HOST" \
    --port="$POSTGRES_PRIMARY_PORT" \
    --username="$POSTGRES_REPLICATION_USER" \
    --pgdata="$PGDATA" \
    --slot="$POSTGRES_REPLICATION_SLOT" \
    --format=plain \
    --wal-method=stream \
    --write-recovery-conf \
    --progress
  unset PGPASSWORD
fi

exec gosu postgres postgres -D "$PGDATA" -c hot_standby=on
