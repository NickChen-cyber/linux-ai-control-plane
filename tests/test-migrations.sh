#!/bin/sh
set -eu

container="linux-ai-migration-test-$$"
trap 'docker stop "$container" >/dev/null 2>&1 || true' EXIT
docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=linux_ai postgres:18-alpine >/dev/null
tries=0
until docker exec "$container" pg_isready -U postgres -d linux_ai >/dev/null 2>&1; do
  tries=$((tries+1)); test "$tries" -lt 30 || { echo "PostgreSQL 測試容器未就緒"; exit 1; }; sleep 1
done
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/sql/001_init.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/002_release_completion.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/003_stage2_operations.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.maintenance_workers') IS NOT NULL" | grep -qx t
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/003_stage2_operations.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.maintenance_workers') IS NULL" | grep -qx t
echo "Migration 001 → 002 → 003 與 003 rollback 測試通過"
