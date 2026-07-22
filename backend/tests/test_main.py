import hashlib
import unittest
from pathlib import Path

from app.audit import integrity_hash


class AuditChainTests(unittest.TestCase):
    def test_hash_is_deterministic_and_sha256(self):
        values = (
            "genesis",
            "event-1",
            "2026-07-14T10:00:00+00:00",
            "user-1",
            "ui.click",
            "clicked sync",
        )
        digest = integrity_hash(*values)
        self.assertEqual(digest, integrity_hash(*values))
        self.assertEqual(len(digest), 64)
        int(digest, 16)

    def test_hash_matches_documented_chain_format(self):
        raw = "genesis|event-1|2026-07-14T10:00:00+00:00|user-1|ui.click|clicked sync"
        expected = hashlib.sha256(raw.encode()).hexdigest()
        self.assertEqual(
            integrity_hash(
                "genesis",
                "event-1",
                "2026-07-14T10:00:00+00:00",
                "user-1",
                "ui.click",
                "clicked sync",
            ),
            expected,
        )

    def test_stage2_worker_retention_and_resource_controls_are_wired(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        worker = (project / "backend" / "app" / "maintenance_worker.py").read_text()
        migration = (project / "backend" / "migrations" / "003_stage2_operations.sql").read_text()
        compose = (project / "compose.yaml").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("FOR UPDATE SKIP LOCKED", worker)
        self.assertIn("MAINTENANCE_WORKER_CONCURRENCY", worker)
        self.assertIn("maintenance-worker:", compose)
        self.assertIn("mem_limit:", compose)
        self.assertIn("pids_limit:", compose)
        self.assertIn("API_RATE_LIMIT_PER_MINUTE", source)
        self.assertIn("SSH_MAX_CONCURRENCY", source)
        self.assertIn('/api/tasks/workers', source)
        self.assertIn('/api/retention/run', source)
        self.assertIn("data_retention_policy", migration)
        self.assertIn("audit_events", migration)
        self.assertIn("TRUE", migration)
        self.assertIn("資料保存與自動清理", ui)

    def test_monitoring_task_count_is_mapped_to_events_not_rules(self):
        source = (Path(__file__).parents[1] / "app" / "main.py").read_text()
        start = source.index("def read_monitoring_summary")
        end = source.index('@app.get("/api/monitoring")', start)
        summary = source[start:end]
        rules_block = summary[summary.index('"rules": ['):summary.index('"events": [')]
        events_block = summary[summary.index('"events": ['):summary.index('"stats": {')]
        self.assertNotIn('row["task_count"]', rules_block)
        self.assertIn('"taskCount": row["task_count"]', events_block)

    def test_stage3_observability_capacity_and_worker_registry(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        worker = (project / "backend" / "app" / "maintenance_worker.py").read_text()
        migration = (project / "backend" / "migrations" / "004_observability_capacity.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("service_health_samples", migration)
        self.assertIn("capacity_forecasts", migration)
        self.assertIn("capacity_forecast", migration)
        self.assertIn('/api/observability', source)
        self.assertIn("regr_slope", source)
        self.assertIn("observability_loop", source)
        self.assertIn("INTERVAL '10 minutes'", worker)
        self.assertIn("中央服務與容量預測", ui)

    def test_postgresql_schema_has_required_types_and_indexes(self):
        schema = (Path(__file__).parents[1] / "sql" / "001_init.sql").read_text()
        self.assertIn("TIMESTAMPTZ", schema)
        self.assertIn("JSONB", schema)
        self.assertIn("GENERATED ALWAYS AS IDENTITY", schema)
        self.assertIn("audit_occurred_at_idx", schema)
        self.assertIn("managed_hosts", schema)
        self.assertIn("platform_users", schema)
        self.assertIn("platform_groups", schema)
        self.assertIn("platform_sessions", schema)
        self.assertIn("auth_login_events", schema)
        self.assertIn("auth_login_events_time_idx", schema)
        self.assertIn("auth_security_policy", schema)
        self.assertIn("password_policy", schema)
        self.assertIn("password_hash", schema)
        self.assertIn("host_metric_samples", schema)
        self.assertIn("host_patch_scans", schema)
        self.assertIn("host_patch_scans_host_time_idx", schema)
        self.assertIn("security_count", schema)
        self.assertIn("cve_count", schema)
        self.assertIn("risk_summary", schema)
        self.assertIn("security_source_status", schema)
        self.assertIn("host_security_scans", schema)
        self.assertIn("host_security_scans_host_time_idx", schema)
        self.assertIn("alert_rules", schema)
        self.assertIn("alert_events", schema)
        self.assertIn("alert_events_active_idx", schema)
        self.assertIn("notification_deliveries", schema)
        self.assertIn("notification_deliveries_time_idx", schema)
        self.assertIn("database_backup_jobs", schema)
        self.assertIn("database_backup_jobs_active_idx", schema)
        self.assertIn("restore_verified", schema)
        self.assertIn("external_watchdogs", schema)
        self.assertIn("external_watchdogs_seen_idx", schema)
        self.assertIn("watchdog_outages", schema)
        self.assertIn("watchdog_outages_time_idx", schema)
        self.assertIn("ai_diagnostics", schema)
        self.assertIn("ai_diagnostics_host_time_idx", schema)
        self.assertIn("maintenance_tasks", schema)
        self.assertIn("maintenance_tasks_time_idx", schema)
        self.assertIn("last_recovered_at", schema)
        self.assertIn("notified_at", schema)
        self.assertIn("notification_retry_jobs", schema)
        self.assertIn("notification_retry_jobs_due_idx", schema)
        self.assertIn("retry_key", schema)
        self.assertIn("consecutive_samples", schema)
        self.assertIn("UNIQUE (address, port, ssh_user)", schema)
        self.assertNotIn("AUTOINCREMENT", schema)

    def test_backup_worker_dumps_and_performs_restore_drill(self):
        project = Path(__file__).parents[2]
        worker = (project / "deploy" / "backup-worker.sh").read_text()
        compose = (project / "compose.yaml").read_text()
        self.assertIn("pg_dump --format=custom", worker)
        self.assertIn("pg_restore --no-owner", worker)
        self.assertIn("createdb", worker)
        self.assertIn("dropdb --if-exists", worker)
        self.assertIn('tar -czf "$recovery_path"', worker)
        self.assertIn("recovery_sha256", worker)
        self.assertIn("backup-data:/backups", compose)
        self.assertIn("config-history:/recovery-input/config-history:ro", compose)
        self.assertIn("backup-data:/backups:ro", compose)
        self.assertIn('/api/backups/{job_id}/download/{artifact}', (project / "backend" / "app" / "main.py").read_text())
        self.assertIn("CONFIRM_RESTORE", (project / "deploy" / "restore-cold-standby.sh").read_text())
        source = (project / "backend" / "app" / "main.py").read_text()
        self.assertIn("REMOTE_STANDBY_PREFLIGHT", source)
        self.assertIn('/api/standby-preflights/{host_id}', source)
        self.assertIn("standby_preflight_checks", source)
        prepare = (project / "deploy" / "prepare-cold-standby.sh").read_text()
        verify = (project / "deploy" / "verify-cold-standby.sh").read_text()
        self.assertIn("download.docker.com/linux/ubuntu", prepare)
        self.assertIn("記憶體不足 2 GB", prepare)
        self.assertIn("5432 與 8080", verify)

    def test_postgresql_streaming_replication_is_opt_in_and_observable(self):
        project = Path(__file__).parents[2]
        compose = (project / "compose.yaml").read_text()
        standby_compose = (project / "compose.standby.yaml").read_text()
        primary_script = (project / "deploy" / "configure-postgres-primary.sh").read_text()
        standby_script = (project / "deploy" / "postgres-standby-entrypoint.sh").read_text()
        api_source = (project / "backend" / "app" / "main.py").read_text()
        self.assertIn("${POSTGRES_BIND_IP:-127.0.0.1}:5432:5432", compose)
        self.assertIn("wal_level=replica", compose)
        self.assertIn("pg_stat_replication", api_source)
        self.assertIn('/api/replication/status', api_source)
        self.assertIn("pg_create_physical_replication_slot", primary_script)
        self.assertIn("scram-sha-256", primary_script)
        self.assertIn("pg_basebackup", standby_script)
        self.assertIn("--write-recovery-conf", standby_script)
        self.assertIn("postgres-standby-data", standby_compose)

    def test_platform_health_is_read_only_and_does_not_expose_secrets(self):
        source = (Path(__file__).parents[1] / "app" / "main.py").read_text()
        start = source.index("def read_platform_health")
        end = source.index('@app.post("/api/watchdog/heartbeat")', start)
        health_source = source[start:end]
        self.assertIn('/api/platform-health', health_source)
        self.assertIn('require_permission(request, "audit.read")', health_source)
        self.assertIn('.worker-heartbeat', health_source)
        self.assertIn('rev-parse", "--verify", "HEAD', health_source)
        self.assertIn('SSH_KEY_PATH', health_source)
        self.assertNotIn('TELEGRAM_BOT_TOKEN,', health_source)
        self.assertNotIn('OPENAI_API_KEY,', health_source)

    def test_session_security_records_authentication_and_supports_revocation(self):
        source = (Path(__file__).parents[1] / "app" / "main.py").read_text()
        self.assertIn("def record_login_event", source)
        self.assertIn("invalid_credentials", source)
        self.assertIn("rate_limited", source)
        self.assertIn('/api/security/sessions', source)
        self.assertIn('/api/security/sessions/{session_id}', source)
        self.assertIn('/api/security/sessions/revoke-others', source)
        self.assertIn("目前 Session 請使用左下角登出", source)
        self.assertIn("recent_failed_login_count", source)
        self.assertIn('/api/security/policy', source)
        self.assertIn("event_retention_days", source)
        self.assertIn("request_source_address(request)", source)
        self.assertNotIn("login_attempts:", source)
        self.assertNotIn("payload.password, source_address", source)

    def test_local_https_is_opt_in_and_keeps_private_keys_out_of_source_control(self):
        project = Path(__file__).parents[2]
        script = (project / "deploy" / "generate-local-tls.sh").read_text()
        tls_config = (project / "deploy" / "nginx-tls.conf").read_text()
        http_config = (project / "deploy" / "nginx.conf").read_text()
        overlay = (project / "compose.https.yaml").read_text()
        gitignore = (project / ".gitignore").read_text()
        self.assertIn("subjectAltName=IP:", script)
        self.assertIn("openssl verify", script)
        self.assertIn("/secrets/", gitignore)
        self.assertIn('COOKIE_SECURE: "true"', overlay)
        self.assertIn("8443:443", overlay)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3", tls_config)
        self.assertIn("Strict-Transport-Security", tls_config)
        self.assertIn("Content-Security-Policy", tls_config)
        self.assertIn("X-Frame-Options", http_config)
        self.assertIn("resolver 127.0.0.11", tls_config)
        self.assertIn("server api:8000 resolve", tls_config)
        self.assertIn("server ui:3000 resolve", tls_config)
        self.assertIn("resolver 127.0.0.11", http_config)
        self.assertIn("server api:8000 resolve", http_config)
        self.assertIn("server ui:3000 resolve", http_config)

    def test_reliability_slo_reporting_is_versioned_and_exportable(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        migration = (project / "backend" / "migrations" / "005_reliability_slo.sql").read_text()
        rollback = (project / "backend" / "migrations" / "down" / "005_reliability_slo.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS reliability_policy", migration)
        self.assertIn("DROP TABLE IF EXISTS reliability_policy", rollback)
        self.assertIn('/api/reliability', source)
        self.assertIn('/api/reliability/policy', source)
        self.assertIn('/api/reliability/export.csv', source)
        self.assertIn('require_permission(request, "backup.manage")', source)
        self.assertIn("可靠性報表", ui)
        self.assertIn("平均確認 MTTA", ui)
        self.assertIn("平均修復 MTTR", ui)

    def test_scheduled_operations_reports_are_persisted_and_audited(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        migration = (project / "backend" / "migrations" / "006_scheduled_reports.sql").read_text()
        rollback = (project / "backend" / "migrations" / "down" / "006_scheduled_reports.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS operational_reports", migration)
        self.assertIn("CREATE TABLE IF NOT EXISTS report_policy", migration)
        self.assertIn("DROP TABLE IF EXISTS operational_reports", rollback)
        self.assertIn('/api/reports', source)
        self.assertIn('/api/reports/policy', source)
        self.assertIn('scheduled_report_loop', source)
        self.assertIn('reports.generate', source)
        self.assertIn("週／月營運報表", ui)

    def test_smtp_email_notifications_keep_credentials_out_of_ui(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        migration = (project / "backend" / "migrations" / "007_email_notifications.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("SMTP Email", source)
        self.assertIn("client.starttls()", source)
        self.assertIn("client.send_message(message)", source)
        self.assertIn("'email'", migration)
        self.assertNotIn("SMTP_PASSWORD", ui)

    def test_unacknowledged_alert_escalation_is_bounded_and_persisted(self):
        project = Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"009_notification_escalation.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("notification_escalation_policy",migration); self.assertIn("UNIQUE(alert_event_id,reminder_number)",migration)
        self.assertIn("notification_escalation_loop",source); self.assertIn("WHERE e.status='firing'",source); self.assertIn('/api/notifications/escalation',source)
        self.assertIn("再次提醒與重大告警升級",ui)

    def test_metric_rollups_support_long_term_indexed_trends(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"010_metric_rollups.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("host_metric_hourly",migration); self.assertIn("host_metric_daily",migration); self.assertIn("host_metric_daily_time_idx",migration)
        self.assertIn("metric_rollup_loop",source); self.assertIn('/metric-trends',source); self.assertIn('90d',ui)

    def test_notification_test_lab_is_isolated_from_alert_events(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"011_notification_test_lab.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("notification_test_runs",migration); self.assertNotIn("REFERENCES alert_events",migration)
        self.assertIn('/api/notification-tests',source); self.assertIn('evaluate_notification_test',source)
        self.assertIn("測試資料不會進入正式告警",ui)

    def test_release_snapshot_is_written_inside_project_directory(self):
        project=Path(__file__).parents[2]; script=(project/"deploy"/"install-release.sh").read_text()
        self.assertIn('snapshot_dir="$project_dir/release-snapshots"',script)
        self.assertNotIn('snapshot="$project_dir/../',script)
        self.assertIn("--exclude='./release-snapshots'",script)
        self.assertIn("grep -Fqx",script)
        self.assertIn("可能多包了一層目錄",script)

    def test_notification_routes_are_prioritized_and_have_fallback(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"012_notification_routing.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("notification_routes",migration); self.assertIn("UNIQUE(priority)",migration)
        self.assertIn("resolve_notification_route",source); self.assertIn("ORDER BY priority LIMIT 1",source)
        self.assertIn("告警通知路由",ui); self.assertIn("預設備援路由",ui)

    def test_notification_failure_center_supports_replay_and_resolution(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"013_notification_failure_center.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("notification_retry_actions",migration); self.assertIn("manual_replay_count",migration); self.assertIn("dismissed",migration)
        self.assertIn('/api/notification-retries/{job_id}/replay',source); self.assertIn('/api/notification-retries/replay-failed',source)
        self.assertIn("通知失敗處理中心",ui); self.assertIn("忽略結案",ui)

    def test_notification_delivery_slo_excludes_tests_and_suppression(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"014_notification_delivery_slo.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("notification_delivery_policy",migration); self.assertIn("success_target",migration)
        self.assertIn("kind<>'test'",source); self.assertIn("status IN ('sent','failed')",source)
        self.assertIn("通知交付健康度",ui); self.assertIn("最低樣本數",ui)

    def test_maintenance_windows_keep_evidence_but_pause_notifications(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"015_maintenance_windows.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("maintenance_windows",migration); self.assertIn("pause_escalations",migration)
        self.assertIn("維護時段：",source); self.assertIn("NOT EXISTS(SELECT 1 FROM maintenance_windows",source)
        self.assertIn("維護時段管理",ui); self.assertIn("持續採集與保存告警證據",ui)

    def test_alert_inhibition_is_same_host_and_preserves_child_events(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"016_alert_inhibition.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("alert_inhibition_rules",migration); self.assertIn("CHECK(source_rule_id<>target_rule_id)",migration)
        self.assertIn("src.host_id=target.host_id",source); self.assertIn("相依抑制：",source)
        self.assertIn("告警相依與抑制",ui); self.assertIn("子告警證據仍保留",ui)

    def test_root_cause_correlations_persist_and_release(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"017_alert_correlations.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("alert_correlations",migration); self.assertIn("UNIQUE(root_event_id,child_event_id)",migration)
        self.assertIn("ON CONFLICT(root_event_id,child_event_id)",source); self.assertIn("status='released'",source)
        self.assertIn("根因關聯視圖",ui); self.assertIn("作用中關聯",ui)

    def test_alert_storm_protection_sends_one_summary_then_suppresses(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"018_alert_storms.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("alert_storm_policy",migration); self.assertIn("alert_storms",migration)
        self.assertIn("evaluate_alert_storm",source); self.assertIn("告警風暴摘要",source); self.assertIn("告警風暴保護：",source)
        self.assertIn("告警風暴保護",ui); self.assertIn("冷卻時間",ui)

    def test_on_call_shift_assigns_new_alerts_without_notification_dependency(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"019_on_call_scheduling.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("on_call_shifts",migration); self.assertIn("alert_assignments",migration); self.assertIn("UNIQUE REFERENCES alert_events",migration.replace("alert_event_id TEXT NOT NULL ",""))
        self.assertIn("assign_alert_to_on_call",source); self.assertIn("assignee_id IS NULL",source)
        self.assertIn("值班排程與自動指派",ui); self.assertIn("永久指派歷史",ui)

    def test_on_call_uses_enabled_as_account_lock_state(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); ui=(project/"app"/"console.tsx").read_text()
        section=source[source.index("def assign_alert_to_on_call"):source.index("async def dispatch_notifications")]+source[source.index("def read_on_call_schedule"):source.index("def read_notification_governance")]
        self.assertIn("u.enabled=TRUE",section); self.assertNotIn("locked",section)
        self.assertIn("伺服器錯誤（HTTP",ui)

    def test_alert_ownership_supports_reassignment_and_preserves_history(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"020_alert_ownership.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("DROP CONSTRAINT IF EXISTS alert_assignments_alert_event_id_key",migration)
        self.assertIn("ON DELETE SET NULL",migration); self.assertIn("previous_user_id",migration); self.assertIn("alert_assignments_event_idx",migration)
        self.assertIn('/api/alert-ownership/{event_id}',source); self.assertIn('action="unassign"',source); self.assertIn("previous_user_id",source)
        self.assertIn("SELECT 1 FROM alert_assignments WHERE alert_event_id=%s LIMIT 1",source)
        self.assertIn("告警負責人工作佇列",ui); self.assertIn("解除指派",ui); self.assertIn("異動備註",ui)

    def test_alert_ownership_sla_tracks_deadlines_and_unassigned_events(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"021_alert_ownership_sla.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("alert_ownership_policy",migration); self.assertIn("unassigned_minutes",migration); self.assertIn("due_soon_percent",migration)
        self.assertIn('/api/alert-ownership-sla',source); self.assertIn('unassigned_overdue',source); self.assertIn('state="overdue"',source)
        self.assertIn("告警責任時效",ui); self.assertIn("未指派逾時",ui); self.assertIn("即將逾期",ui)

    def test_alert_ownership_sla_escalates_once_and_records_recovery(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"022_alert_sla_escalations.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("alert_sla_escalations",migration); self.assertIn("alert_event_id TEXT NOT NULL UNIQUE",migration); self.assertIn("recovered_at",migration)
        self.assertIn("alert_ownership_sla_loop",source); self.assertIn("責任 SLA 逾期",source); self.assertIn("ON CONFLICT(alert_event_id) DO NOTHING",source)
        self.assertIn("責任逾期升級紀錄",ui); self.assertIn("每個事件只發送一次",ui)

    def test_on_call_handoff_updates_shift_and_preserves_chain(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"023_on_call_handoffs.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("on_call_handoffs",migration); self.assertIn("ON DELETE SET NULL",migration); self.assertIn("handed_off_by",migration)
        self.assertIn('/api/on-call-handoffs',source); self.assertIn("FOR UPDATE",source); self.assertIn("代理人不可與目前值班人相同",source)
        self.assertIn("值班交接與代理",ui); self.assertIn("交接原因",ui)

    def test_on_call_coverage_merges_shifts_and_reports_gaps(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"024_on_call_coverage.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("on_call_coverage_policy",migration); self.assertIn("horizon_hours",migration); self.assertIn("target_percent",migration)
        self.assertIn('/api/on-call-coverage',source); self.assertIn("intervals[-1][1]",source); self.assertIn("uncoveredMinutes",source)
        self.assertIn("值班覆蓋率與缺口",ui); self.assertIn("觀察範圍內沒有值班缺口",ui)

    def test_on_call_gap_alerts_are_deduplicated_and_resolved(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"025_on_call_gap_alerts.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("on_call_gap_alerts",migration); self.assertIn("fingerprint TEXT NOT NULL UNIQUE",migration); self.assertIn("alert_lead_hours",migration)
        self.assertIn("on_call_gap_alert_loop",source); self.assertIn("ON CONFLICT(fingerprint) DO NOTHING",source); self.assertIn("status='resolved'",source)
        self.assertIn("值班缺口自動通知",ui); self.assertIn("啟用值班缺口通知",ui)

    def test_recurring_on_call_materializes_without_overlap(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"026_recurring_on_call.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("on_call_templates",migration); self.assertIn("on_call_shifts_template_start_idx",migration); self.assertIn("interval_days",migration)
        self.assertIn("materialize_on_call_templates",source); self.assertIn("starts_at<%s AND ends_at>%s",source); self.assertIn("recurring_on_call_loop",source)
        self.assertIn("週期值班範本",ui); self.assertIn("建立並展開",ui)

    def test_on_call_fairness_combines_schedule_and_operational_load(self):
        project=Path(__file__).parents[2]; source=(project/"backend"/"app"/"main.py").read_text(); migration=(project/"backend"/"migrations"/"027_on_call_fairness.sql").read_text(); ui=(project/"app"/"console.tsx").read_text()
        self.assertIn("on_call_fairness_policy",migration); self.assertIn("imbalance_percent",migration)
        self.assertIn('/api/on-call-fairness',source); self.assertIn("scheduled_hours",source); self.assertIn("sla_breaches",source); self.assertIn("handoffs_in",source)
        self.assertIn("值班負載與公平性",ui); self.assertIn("偏離平均",ui)

    def test_patch_inventory_is_read_only_and_persisted(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        start = source.index("REMOTE_PATCH_STATUS")
        end = source.index("class AuditEvent", start)
        remote = source[start:end]
        self.assertIn("apt', 'list', '--upgradable", remote)
        self.assertIn("reboot-required", remote)
        self.assertIn("unattended-upgrades.service", remote)
        self.assertIn("u.pro.packages.updates.v1", remote)
        self.assertIn("apt-cache', 'policy", remote)
        self.assertNotIn("apt', 'update", remote)
        self.assertNotIn("apt', 'upgrade", remote)
        self.assertNotIn("reboot',", remote)
        self.assertIn('/api/patch-inventory', source)
        self.assertIn('/api/patch-inventory/scan', source)
        self.assertIn('/api/patch-inventory/policy', source)
        self.assertIn("INSERT INTO host_patch_scans", source)
        self.assertIn("CREATE TABLE IF NOT EXISTS patch_inventory_policy", schema)
        self.assertIn("rule-security-updates", schema)
        self.assertIn("patch_inventory_loop", source)
        self.assertIn("update_security_update_alert", source)
        self.assertIn("自動更新風險盤點", ui)
        self.assertIn("安全更新告警門檻", ui)
        self.assertIn("def ubuntu_security_notice_index", source)
        self.assertIn("https://ubuntu.com/security/notices.json", source)
        self.assertIn("def enrich_patch_packages", source)
        self.assertIn('"isSecurity": is_security', source)
        self.assertIn('"cves": cves[:50]', source)
        self.assertIn('require_permission(request, "hosts.manage")', source)

    def test_security_baseline_is_read_only_and_persisted(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        start = source.index("REMOTE_SECURITY_BASELINE")
        end = source.index("class AuditEvent", start)
        remote = source[start:end]
        self.assertIn("/etc/ssh/sshd_config", remote)
        self.assertIn("systemctl', 'is-enabled", remote)
        self.assertIn("/sys/module/apparmor/parameters/enabled", remote)
        self.assertIn("NTPSynchronized", remote)
        self.assertIn("authorized_keys", remote)
        self.assertNotIn("subprocess.run(['chmod'", remote)
        self.assertNotIn("systemctl', 'enable", remote)
        self.assertNotIn("apt', 'upgrade", remote)
        self.assertNotIn("sudo", remote)
        self.assertIn('/api/security-baselines', source)
        self.assertIn('/api/security-baselines/scan', source)
        self.assertIn('/api/security-baselines/policy', source)
        self.assertIn('/api/security-baselines/{host_id}/history', source)
        self.assertIn("ROW_NUMBER() OVER", source)
        self.assertIn('"scoreDelta"', source)
        self.assertIn('"direction": "improved"', source)
        self.assertIn("INSERT INTO host_security_scans", source)
        self.assertIn("CREATE TABLE IF NOT EXISTS security_baseline_policy", schema)
        self.assertIn("rule-security-baseline", schema)
        self.assertIn("security_baseline_loop", source)
        self.assertIn("security_regression_count", source)
        self.assertIn("update_security_baseline_alert", source)
        self.assertIn("自動安全基準政策", ui)
        self.assertIn("最低安全分數", ui)
        self.assertIn('require_permission(request, "hosts.read")', source)
        self.assertIn('require_permission(request, "hosts.manage")', source)

    def test_asset_inventory_is_read_only_persisted_and_detects_drift(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS host_asset_scans", schema)
        self.assertIn("host_asset_scans_host_time_idx", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS asset_inventory_policy", schema)
        self.assertIn("rule-asset-drift", schema)
        self.assertIn("REMOTE_ASSET_INVENTORY", source)
        self.assertIn("compare_asset_snapshots", source)
        self.assertIn("asset_inventory_loop", source)
        self.assertIn("collect_asset_inventory_cycle", source)
        self.assertIn("update_asset_drift_alert", source)
        self.assertIn('/api/asset-inventory/scan', source)
        self.assertIn('/api/asset-inventory/policy', source)
        self.assertIn('/api/asset-inventory/{host_id}/history', source)
        self.assertIn("資產盤點", ui)
        self.assertIn("偵測到設定漂移", ui)
        self.assertIn("自動盤點與漂移告警", ui)
        self.assertIn("盤點政策", ui)
        remote = source[source.index("REMOTE_ASSET_INVENTORY"):source.index("REMOTE_SECURITY_BASELINE")]
        self.assertNotIn("sudo", remote)

    def test_automation_center_records_scheduled_and_manual_inspection_runs(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS automation_runs", schema)
        self.assertIn("automation_runs_type_time_idx", schema)
        self.assertIn("start_automation_run", source)
        self.assertIn("finish_automation_run", source)
        self.assertIn('/api/automation/{job_type}/run', source)
        self.assertIn('/api/automation/runs/{run_id}', source)
        self.assertIn("read_automation_run_detail", source)
        self.assertIn('trigger_type="scheduled"', source)
        self.assertIn("API 重新啟動，前次巡檢未完成", source)
        self.assertIn("自動巡檢排程中心", ui)
        self.assertIn("巡檢執行紀錄", ui)
        self.assertIn("查看結果", ui)
        self.assertIn("INSPECTION EVIDENCE", ui)

    def test_external_watchdog_checks_health_and_reports_heartbeat(self):
        project = Path(__file__).parents[2]
        watchdog = (project / "deploy" / "external-watchdog.sh").read_text()
        service = (project / "deploy" / "linux-ai-watchdog.service").read_text()
        self.assertIn("/api/health", watchdog)
        self.assertIn("/api/watchdog/heartbeat", watchdog)
        self.assertIn("X-Watchdog-Token", watchdog)
        self.assertIn("FAILURE_THRESHOLD", watchdog)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn(r'\"version\":\"2\"', watchdog)
        self.assertIn("Control plane recovered", watchdog)

    def test_notification_connectors_include_line_sms_and_retry_worker(self):
        source = (Path(__file__).parents[1] / "app" / "main.py").read_text()
        self.assertIn("https://api.line.me/v2/bot/message/push", source)
        self.assertIn("X-Line-Retry-Key", source)
        self.assertIn("SMS_GATEWAY_URL", source)
        self.assertIn("notification_retry_loop", source)
        self.assertIn("enqueue_notification_retry", source)

    def test_ai_diagnostics_are_structured_redacted_and_analysis_only(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        compose = (project / "compose.yaml").read_text()
        self.assertIn("/v1/responses", source)
        self.assertIn('"type": "json_schema"', source)
        self.assertIn('"store": False', source)
        self.assertIn("REDACTED_PRIVATE_KEY", source)
        self.assertIn("不得聲稱已執行任何指令", source)
        self.assertIn("local_rule_diagnosis", source)
        self.assertIn('AI_DIAGNOSTIC_MODE", "local"', source)
        self.assertIn("OPENAI_API_KEY", compose)
        self.assertIn("AI_DIAGNOSTIC_MODE", compose)

    def test_maintenance_tasks_only_execute_allowlisted_runbooks(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        worker = (project / "backend" / "app" / "maintenance_worker.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        self.assertIn("SAFE_RUNBOOKS", source)
        self.assertIn('runbook = SAFE_RUNBOOKS.get(payload.runbook_id)', source)
        self.assertIn("不允許的 Runbook", source)
        self.assertIn('/api/tasks/{task_id}/approve', source)
        self.assertIn('/api/tasks/{task_id}/execute', source)
        self.assertIn('approval_policy', source)
        self.assertIn('中高風險任務必須由另一位具核准權限的使用者核准', source)
        self.assertIn('output_sha256', source)
        self.assertIn('verification_status="passed"', worker)
        self.assertIn('payload.confirmation != "EXECUTE"', source)
        self.assertIn('runbook.get("precheck")', worker)
        self.assertIn('runbook.get("verify_command")', worker)
        self.assertIn('/api/tasks/readiness', source)
        self.assertIn('inspect_maintenance_sudo_policy', source)
        self.assertIn('維運權限檢查失敗', worker)
        self.assertIn('unexpectedGrantCount', source)
        self.assertIn('MAINTENANCE_APPROVAL_TTL_MINUTES', source)
        self.assertIn('maintenance_one_running_per_host_idx', schema)
        self.assertIn('approval_expires_at TIMESTAMPTZ', schema)
        self.assertIn("FOR UPDATE SKIP LOCKED", worker)
        self.assertIn("heartbeat_at", worker)
        self.assertIn("sudo -n /usr/bin/apt-get update", source)
        self.assertIn("/etc/sudoers.d/linux-ai-agent", source)
        self.assertIn("gpasswd -d linux-agent sudo", source)
        self.assertNotIn("payload.command", source)

    def test_alerts_can_only_create_contextual_allowlisted_maintenance_tasks(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        self.assertIn("ALERT_RUNBOOKS", source)
        self.assertIn('/api/alert-events/{event_id}/runbooks', source)
        self.assertIn('/api/alert-events/{event_id}/tasks', source)
        self.assertIn("已恢復的告警不可建立新的維運任務", source)
        self.assertIn("不允許的告警 Runbook", source)
        self.assertIn("source_alert_id", source)
        self.assertIn("source_alert_id TEXT", schema)
        self.assertIn("tasks.create_from_alert", source)
        self.assertIn('/api/alert-events/{event_id}/tasks', source)
        self.assertIn('require_permission(request, "tasks.read")', source)

    def test_release_completion_has_task_control_incidents_and_migrations(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        migration = (project / "backend" / "migrations" / "002_release_completion.sql").read_text()
        runner = (project / "backend" / "app" / "migrations.py").read_text()
        integration = (project / "tests" / "run-integration.sh").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        for endpoint in ('/cancel', '/retry', '/api/tasks/recover-stuck', '/incident', '/timeline', '/close', '/api/releases/preflight'):
            self.assertIn(endpoint, source)
        self.assertIn("maintenance_reaper_loop", source)
        self.assertIn("schema_migrations", runner)
        self.assertIn("checksum 不一致", runner)
        self.assertIn("incident_timeline", migration)
        self.assertIn("release_operations", migration)
        self.assertIn("CONTROL_PLANE_TEST_OTP", integration)
        self.assertIn("告警事件結案", source)
        self.assertIn("回收卡住任務", ui)
        self.assertIn("系統版本與更新準備", ui)

    def test_core_security_release_has_mfa_vault_rotation_and_central_logs(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        compose = (project / "compose.yaml").read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS user_mfa", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS secret_vault", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS central_log_events", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS ssh_key_rotations", schema)
        self.assertIn('/api/security/mfa/enable', source)
        self.assertIn("AESGCM(master_key()).encrypt", source)
        self.assertIn('/api/security/ssh-keys/rotations/{rotation_id}/promote', source)
        self.assertIn("oldKeyRemoved\":False", source)
        self.assertIn("central_log_collection_loop", source)
        self.assertIn('"install_security_updates"', source)
        self.assertNotIn("payload.command", source)
        self.assertIn("PLATFORM_MASTER_KEY", compose)

    def test_identity_security_completion_requires_verification_and_independent_key_retirement(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        self.assertIn("require_mfa_admins", schema)
        self.assertIn("仍有 {missing} 位啟用中的管理員尚未設定 MFA", source)
        self.assertIn('/api/security/mfa/recovery-codes', source)
        self.assertIn('MFA 已啟用；請使用復原碼重建功能', source)
        self.assertIn('/api/security/secrets/{name}', source)
        self.assertIn("CREATE TABLE IF NOT EXISTS ssh_key_retirement_requests", schema)
        self.assertIn("舊金鑰退役必須由另一位管理員核准", source)
        self.assertIn('/api/security/ssh-keys/retirements/{retirement_id}/execute', source)
        self.assertIn("record_backend_audit", source)

    def test_central_log_search_export_policy_and_collection_alerts(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        schema = (project / "backend" / "sql" / "001_init.sql").read_text()
        ui = (project / "app" / "console.tsx").read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS central_log_collection_status", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS central_log_policy", schema)
        self.assertIn("systemd_unit TEXT", schema)
        self.assertIn('/api/logs/search', source)
        self.assertIn('/api/logs/export.csv', source)
        self.assertIn('/api/logs/policy', source)
        self.assertIn("rule-log-collection", source)
        self.assertIn("metric NOT IN ('log_collection','asset_drift','security_updates','security_baseline','capacity_forecast')", source)
        self.assertIn("集中日誌連續 {failures} 次採集失敗", source)
        self.assertIn("全部主機", ui)
        self.assertIn("匯出 CSV", ui)
        self.assertIn("central_log_collection_lock", source)
        self.assertIn("collect_central_logs_for_host", source)
        self.assertIn("with connection.cursor() as cursor:", source)
        self.assertIn("cursor.executemany", source)
        self.assertNotIn("connection.executemany", source)
        self.assertIn("集中日誌採集超過 35 秒", source)
        self.assertIn("finally{window.clearTimeout(timer);setLoading(false);}", ui)

    def test_configuration_versions_use_local_git_without_secrets(self):
        project = Path(__file__).parents[2]
        source = (project / "backend" / "app" / "main.py").read_text()
        dockerfile = (project / "backend" / "Dockerfile").read_text()
        compose = (project / "compose.yaml").read_text()
        self.assertIn('/api/config-versions', source)
        self.assertIn('git_config(*command, "-m"', source)
        self.assertIn('"secretsIncluded": False', source)
        self.assertNotIn('password_hash', source[source.index("def configuration_snapshot"):source.index("def git_config")])
        self.assertIn("git gosu openssh-client", dockerfile)
        self.assertIn("config-history:/var/lib/linux-ai-config", compose)
        self.assertIn('/api/config-restore-requests/{restore_id}/approve', source)
        self.assertIn('設定回滾必須由另一位管理者核准', source)
        self.assertIn('設定回滾前自動快照', source)
        self.assertIn('restore_configuration_snapshot', source)


if __name__ == "__main__":
    unittest.main()
