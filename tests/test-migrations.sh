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
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/005_reliability_slo.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/006_scheduled_reports.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/007_email_notifications.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/008_notification_governance.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/009_notification_escalation.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/010_metric_rollups.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/011_notification_test_lab.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/012_notification_routing.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/013_notification_failure_center.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/014_notification_delivery_slo.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/015_maintenance_windows.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/016_alert_inhibition.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/017_alert_correlations.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/018_alert_storms.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/019_on_call_scheduling.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/020_alert_ownership.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/021_alert_ownership_sla.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/022_alert_sla_escalations.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/023_on_call_handoffs.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/024_on_call_coverage.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/025_on_call_gap_alerts.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.maintenance_workers') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.capacity_forecasts') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.reliability_policy') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.operational_reports') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT 1 FROM pg_constraint WHERE conname='notification_deliveries_channel_check' AND pg_get_constraintdef(oid) LIKE '%email%'" | grep -qx 1
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.alert_silences') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.notification_escalations') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.host_metric_daily') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.notification_test_runs') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.notification_routes') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.notification_retry_actions') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.notification_delivery_policy') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.maintenance_windows') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.alert_inhibition_rules') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.alert_correlations') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.alert_storms') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.on_call_shifts') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.alert_assignments_event_idx') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT is_nullable FROM information_schema.columns WHERE table_name='alert_assignments' AND column_name='user_id'" | grep -qx YES
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.alert_ownership_policy') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.alert_sla_escalations') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.on_call_handoffs') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.on_call_coverage_policy') IS NOT NULL" | grep -qx t
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.on_call_gap_alerts') IS NOT NULL" | grep -qx t
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/025_on_call_gap_alerts.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/024_on_call_coverage.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/023_on_call_handoffs.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/022_alert_sla_escalations.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/021_alert_ownership_sla.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/020_alert_ownership.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/019_on_call_scheduling.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/018_alert_storms.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/017_alert_correlations.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/016_alert_inhibition.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/015_maintenance_windows.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/014_notification_delivery_slo.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/013_notification_failure_center.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/012_notification_routing.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/011_notification_test_lab.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/010_metric_rollups.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/009_notification_escalation.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/008_notification_governance.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/007_email_notifications.sql >/dev/null
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/006_scheduled_reports.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.operational_reports') IS NULL" | grep -qx t
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/005_reliability_slo.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.reliability_policy') IS NULL" | grep -qx t
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/004_observability_capacity.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.capacity_forecasts') IS NULL" | grep -qx t
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d linux_ai < backend/migrations/down/003_stage2_operations.sql >/dev/null
docker exec "$container" psql -At -U postgres -d linux_ai -c "SELECT to_regclass('public.maintenance_workers') IS NULL" | grep -qx t
echo "Migration 001 → 025 與 rollback 測試通過"
