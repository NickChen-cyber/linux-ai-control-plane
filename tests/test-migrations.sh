#!/bin/sh
set -eu

container="linux-ai-migration-test-$$"
trap 'docker stop "$container" >/dev/null 2>&1 || true' EXIT
docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=linux_ai postgres:18-alpine >/dev/null
tries=0
# The official image starts a temporary server during initdb and then restarts
# PostgreSQL. pg_isready can briefly succeed against that temporary server, so
# require three consecutive SQL queries before applying migrations.
stable=0
while [ "$stable" -lt 3 ]; do
  if docker exec "$container" psql -U postgres -d linux_ai -Atqc 'SELECT 1' >/dev/null 2>&1; then
    stable=$((stable+1))
  else
    stable=0
  fi
  tries=$((tries+1))
  test "$tries" -lt 60 || { echo "PostgreSQL 測試容器未穩定就緒"; docker logs "$container"; exit 1; }
  sleep 1
done
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/sql/001_init.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/002_release_completion.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/003_stage2_operations.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/004_observability_capacity.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.maintenance_workers') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.capacity_forecasts') IS NOT NULL" | grep -qx t
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/004_observability_capacity.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.capacity_forecasts') IS NULL" | grep -qx t
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/003_stage2_operations.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.maintenance_workers') IS NULL" | grep -qx t
echo "Migration 001 → 002 → 003 → 004 與 004/003 rollback 測試通過"
