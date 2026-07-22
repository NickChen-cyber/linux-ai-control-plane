CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    chain_seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    occurred_at TIMESTAMPTZ NOT NULL,
    session_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    page TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    result TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    integrity_hash TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_occurred_at_idx
    ON audit_events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS audit_actor_event_idx
    ON audit_events (actor_id, event_type, occurred_at DESC);

COMMENT ON TABLE audit_events IS 'Linux AI Control Plane UI and operation audit trail';
COMMENT ON COLUMN audit_events.integrity_hash IS 'SHA-256 hash linked to previous_hash';

CREATE TABLE IF NOT EXISTS managed_hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    ssh_user TEXT NOT NULL,
    group_name TEXT NOT NULL DEFAULT 'LAB / MANAGED',
    machine_id TEXT,
    host_key_fingerprint TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (address, port, ssh_user)
);

CREATE INDEX IF NOT EXISTS managed_hosts_enabled_idx
    ON managed_hosts (enabled, created_at);

CREATE TABLE IF NOT EXISTS platform_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    system_group BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS platform_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS platform_user_groups (
    user_id TEXT NOT NULL REFERENCES platform_users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES platform_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS platform_sessions (
    token_hash TEXT PRIMARY KEY,
    id TEXT UNIQUE,
    user_id TEXT NOT NULL REFERENCES platform_users(id) ON DELETE CASCADE,
    source_address TEXT,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS platform_sessions_expires_idx
    ON platform_sessions (expires_at);

ALTER TABLE platform_sessions ADD COLUMN IF NOT EXISTS id TEXT;
ALTER TABLE platform_sessions ADD COLUMN IF NOT EXISTS source_address TEXT;
ALTER TABLE platform_sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;
UPDATE platform_sessions
SET id = 'ses-' || substr(md5(token_hash), 1, 20)
WHERE id IS NULL;
ALTER TABLE platform_sessions ALTER COLUMN id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS platform_sessions_id_idx ON platform_sessions (id);

CREATE TABLE IF NOT EXISTS auth_login_events (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    user_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    success BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    source_address TEXT,
    user_agent TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS auth_login_events_time_idx
    ON auth_login_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS auth_login_events_user_time_idx
    ON auth_login_events (user_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS host_patch_scans (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
    kernel_version TEXT,
    reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
    reboot_packages JSONB NOT NULL DEFAULT '[]'::jsonb,
    unattended_upgrades TEXT,
    pending_count INTEGER NOT NULL DEFAULT 0,
    packages JSONB NOT NULL DEFAULT '[]'::jsonb,
    os_codename TEXT,
    security_count INTEGER NOT NULL DEFAULT 0,
    cve_count INTEGER NOT NULL DEFAULT 0,
    risk_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    security_source_status TEXT,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    error TEXT,
    checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS host_patch_scans_host_time_idx
    ON host_patch_scans (host_id, checked_at DESC);

ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS os_codename TEXT;
ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS security_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS cve_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS risk_summary JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS security_source_status TEXT;

CREATE TABLE IF NOT EXISTS patch_inventory_policy (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    interval_hours INTEGER NOT NULL CHECK (interval_hours BETWEEN 1 AND 168),
    security_threshold INTEGER NOT NULL CHECK (security_threshold BETWEEN 1 AND 1000),
    notify_security_updates BOOLEAN NOT NULL DEFAULT TRUE,
    last_started_at TIMESTAMPTZ,
    last_completed_at TIMESTAMPTZ,
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO patch_inventory_policy (
    id, enabled, interval_hours, security_threshold, notify_security_updates
) VALUES (1, TRUE, 24, 1, TRUE) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS host_asset_scans (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
    snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    changes JSONB NOT NULL DEFAULT '{}'::jsonb,
    snapshot_sha256 TEXT,
    error TEXT,
    checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS host_asset_scans_host_time_idx
    ON host_asset_scans (host_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS asset_inventory_policy (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    interval_hours INTEGER NOT NULL CHECK (interval_hours BETWEEN 1 AND 168),
    notify_drift BOOLEAN NOT NULL DEFAULT TRUE,
    last_started_at TIMESTAMPTZ,
    last_completed_at TIMESTAMPTZ,
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO asset_inventory_policy (id, enabled, interval_hours, notify_drift)
VALUES (1, TRUE, 24, TRUE) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS host_security_scans (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
    score INTEGER NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
    checks JSONB NOT NULL DEFAULT '[]'::jsonb,
    error TEXT,
    checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS host_security_scans_host_time_idx
    ON host_security_scans (host_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS security_baseline_policy (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    interval_hours INTEGER NOT NULL CHECK (interval_hours BETWEEN 1 AND 168),
    minimum_score INTEGER NOT NULL CHECK (minimum_score BETWEEN 0 AND 100),
    notify_regression BOOLEAN NOT NULL DEFAULT TRUE,
    last_started_at TIMESTAMPTZ,
    last_completed_at TIMESTAMPTZ,
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO security_baseline_policy (
    id, enabled, interval_hours, minimum_score, notify_regression
) VALUES (1, TRUE, 24, 80, TRUE) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS automation_runs (
    id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL CHECK (job_type IN ('asset_inventory', 'patch_inventory', 'security_baseline')),
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('scheduled', 'manual')),
    status TEXT NOT NULL CHECK (status IN ('running', 'success', 'partial', 'failed')),
    requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    total_hosts INTEGER NOT NULL DEFAULT 0,
    succeeded_hosts INTEGER NOT NULL DEFAULT 0,
    failed_hosts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS automation_runs_type_time_idx
    ON automation_runs (job_type, started_at DESC);

CREATE TABLE IF NOT EXISTS auth_security_policy (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    max_failed_attempts INTEGER NOT NULL CHECK (max_failed_attempts BETWEEN 3 AND 10),
    lockout_minutes INTEGER NOT NULL CHECK (lockout_minutes BETWEEN 1 AND 1440),
    event_retention_days INTEGER NOT NULL CHECK (event_retention_days BETWEEN 30 AND 365),
    require_mfa_admins BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);

INSERT INTO auth_security_policy (
    id, max_failed_attempts, lockout_minutes, event_retention_days
) VALUES (1, 5, 5, 90)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS password_policy (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    min_length INTEGER NOT NULL CHECK (min_length BETWEEN 8 AND 128),
    require_upper BOOLEAN NOT NULL DEFAULT FALSE,
    require_lower BOOLEAN NOT NULL DEFAULT FALSE,
    require_number BOOLEAN NOT NULL DEFAULT FALSE,
    require_special BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);

INSERT INTO password_policy (
    id, min_length, require_upper, require_lower,
    require_number, require_special
) VALUES (1, 10, FALSE, FALSE, FALSE, FALSE)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS host_metric_samples (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    state TEXT NOT NULL CHECK (state IN ('healthy', 'warning', 'offline')),
    cpu_percent NUMERIC(5,1) NOT NULL DEFAULT 0,
    ram_percent NUMERIC(5,1) NOT NULL DEFAULT 0,
    disk_percent NUMERIC(5,1) NOT NULL DEFAULT 0,
    load_one NUMERIC(8,2),
    uptime_seconds BIGINT,
    failed_service_count INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE INDEX IF NOT EXISTS host_metric_samples_host_time_idx
    ON host_metric_samples (host_id, collected_at DESC);

CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    metric TEXT NOT NULL CHECK (metric IN ('availability', 'cpu', 'ram', 'disk', 'failed_services', 'log_collection', 'asset_drift', 'security_updates', 'security_baseline')),
    threshold NUMERIC(8,1) NOT NULL DEFAULT 1,
    consecutive_samples INTEGER NOT NULL DEFAULT 2 CHECK (consecutive_samples BETWEEN 1 AND 60),
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_events (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('firing', 'acknowledged', 'resolved')),
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    message TEXT NOT NULL,
    last_value NUMERIC(8,1),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS alert_events_recent_idx
    ON alert_events (started_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS alert_events_active_idx
    ON alert_events (rule_id, host_id)
    WHERE status IN ('firing', 'acknowledged');

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id TEXT PRIMARY KEY,
    alert_event_id TEXT REFERENCES alert_events(id) ON DELETE SET NULL,
    channel TEXT NOT NULL CHECK (channel IN ('telegram', 'line', 'sms', 'webhook')),
    kind TEXT NOT NULL CHECK (kind IN ('firing', 'resolved', 'test', 'backup_failed')),
    status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
    destination_hint TEXT NOT NULL,
    message TEXT NOT NULL,
    response_detail TEXT,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS notification_deliveries_time_idx
    ON notification_deliveries (attempted_at DESC);

CREATE TABLE IF NOT EXISTS notification_retry_jobs (
    id TEXT PRIMARY KEY,
    alert_event_id TEXT REFERENCES alert_events(id) ON DELETE SET NULL,
    channel TEXT NOT NULL CHECK (channel IN ('telegram', 'line', 'sms', 'webhook')),
    kind TEXT NOT NULL CHECK (kind IN ('firing', 'resolved', 'test', 'backup_failed')),
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    message TEXT NOT NULL,
    retry_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'sending', 'sent', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 1,
    max_attempts INTEGER NOT NULL DEFAULT 4,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (channel, retry_key)
);

CREATE INDEX IF NOT EXISTS notification_retry_jobs_due_idx
    ON notification_retry_jobs (status, next_attempt_at);

CREATE TABLE IF NOT EXISTS database_backup_jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('scheduled', 'manual')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'success', 'failed')),
    filename TEXT,
    size_bytes BIGINT,
    sha256 TEXT,
    restore_verified BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_filename TEXT,
    recovery_size_bytes BIGINT,
    recovery_sha256 TEXT,
    recovery_verified BOOLEAN NOT NULL DEFAULT FALSE,
    detail TEXT,
    requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

ALTER TABLE database_backup_jobs
    ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS database_backup_jobs_time_idx
    ON database_backup_jobs (requested_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS database_backup_jobs_active_idx
    ON database_backup_jobs ((TRUE))
    WHERE status IN ('queued', 'running');

CREATE TABLE IF NOT EXISTS external_watchdogs (
    id TEXT PRIMARY KEY,
    node_name TEXT NOT NULL,
    last_status TEXT NOT NULL CHECK (last_status IN ('healthy', 'recovered')),
    last_outage_seconds INTEGER NOT NULL DEFAULT 0,
    source_address TEXT,
    version TEXT NOT NULL DEFAULT '1',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_recovered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE external_watchdogs
    ADD COLUMN IF NOT EXISTS last_recovered_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS external_watchdogs_seen_idx
    ON external_watchdogs (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS watchdog_outages (
    id TEXT PRIMARY KEY,
    watchdog_id TEXT NOT NULL REFERENCES external_watchdogs(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL,
    recovered_at TIMESTAMPTZ NOT NULL,
    duration_seconds INTEGER NOT NULL CHECK (duration_seconds > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (watchdog_id, recovered_at)
);

CREATE INDEX IF NOT EXISTS watchdog_outages_time_idx
    ON watchdog_outages (recovered_at DESC);

CREATE TABLE IF NOT EXISTS ai_diagnostics (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    model TEXT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    result JSONB,
    redaction_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ai_diagnostics_host_time_idx
    ON ai_diagnostics (host_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS maintenance_tasks (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    runbook_id TEXT NOT NULL,
    title TEXT NOT NULL,
    command_preview TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT 'low',
    approval_policy TEXT NOT NULL DEFAULT 'single',
    verification_method TEXT NOT NULL DEFAULT '',
    verification_status TEXT NOT NULL DEFAULT 'pending',
    output_sha256 TEXT,
    duration_ms INTEGER,
    source_alert_id TEXT,
    request_note TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'running', 'succeeded', 'failed')),
    output TEXT,
    error TEXT,
    requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    approved_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    decision_note TEXT NOT NULL DEFAULT '',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    approval_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS maintenance_tasks_time_idx
    ON maintenance_tasks (requested_at DESC);
CREATE INDEX IF NOT EXISTS maintenance_tasks_source_alert_idx
    ON maintenance_tasks (source_alert_id, requested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS maintenance_one_running_per_host_idx
    ON maintenance_tasks (host_id) WHERE status = 'running';

CREATE TABLE IF NOT EXISTS user_mfa (
    user_id TEXT PRIMARY KEY REFERENCES platform_users(id) ON DELETE CASCADE,
    secret_encrypted TEXT NOT NULL, recovery_code_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS secret_vault (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, purpose TEXT NOT NULL,
    value_encrypted TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS identity_providers (
    provider_type TEXT PRIMARY KEY CHECK (provider_type IN ('oidc','ldap')),
    display_name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT FALSE,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS central_log_events (
    id BIGSERIAL PRIMARY KEY, host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    cursor TEXT NOT NULL, occurred_at TIMESTAMPTZ, priority TEXT NOT NULL,
    systemd_unit TEXT, identifier TEXT, process_id TEXT, transport TEXT, boot_id TEXT, message TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(host_id, cursor)
);
CREATE INDEX IF NOT EXISTS central_logs_search_idx ON central_log_events(host_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS central_logs_unit_time_idx ON central_log_events(systemd_unit, occurred_at DESC);
CREATE TABLE IF NOT EXISTS central_log_policy (
    id SMALLINT PRIMARY KEY CHECK(id=1), retention_days INTEGER NOT NULL,
    interval_seconds INTEGER NOT NULL, failure_threshold INTEGER NOT NULL,
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO central_log_policy(id,retention_days,interval_seconds,failure_threshold)
VALUES(1,30,300,2) ON CONFLICT(id) DO NOTHING;
CREATE TABLE IF NOT EXISTS central_log_collection_status (
    host_id TEXT PRIMARY KEY REFERENCES managed_hosts(id) ON DELETE CASCADE,
    last_attempt_at TIMESTAMPTZ, last_success_at TIMESTAMPTZ, last_event_at TIMESTAMPTZ,
    last_event_count INTEGER NOT NULL DEFAULT 0, consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_error TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ssh_key_rotations (
    id TEXT PRIMARY KEY, status TEXT NOT NULL, old_fingerprint TEXT, new_fingerprint TEXT NOT NULL,
    public_key TEXT NOT NULL, private_key_encrypted TEXT NOT NULL,
    created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), promoted_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS ssh_key_rotation_hosts (
    rotation_id TEXT NOT NULL REFERENCES ssh_key_rotations(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    status TEXT NOT NULL, error TEXT, verified_at TIMESTAMPTZ,
    PRIMARY KEY(rotation_id,host_id)
);
CREATE TABLE IF NOT EXISTS ssh_key_retirement_requests (
    id TEXT PRIMARY KEY, rotation_id TEXT NOT NULL REFERENCES ssh_key_rotations(id) ON DELETE CASCADE,
    public_key_to_remove TEXT NOT NULL, status TEXT NOT NULL,
    requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    approved_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    request_note TEXT NOT NULL DEFAULT '', decision_note TEXT NOT NULL DEFAULT '',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), decided_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ, result JSONB, error TEXT
);

CREATE TABLE IF NOT EXISTS config_restore_requests (
    id TEXT PRIMARY KEY,
    version_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'applying', 'applied', 'failed')),
    note TEXT NOT NULL DEFAULT '',
    decision_note TEXT NOT NULL DEFAULT '',
    requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    approved_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    applied_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    before_version_id TEXT,
    result JSONB,
    error TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS config_restore_requests_time_idx
    ON config_restore_requests (requested_at DESC);

CREATE TABLE IF NOT EXISTS standby_preflight_checks (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
    ready BOOLEAN NOT NULL,
    result JSONB NOT NULL,
    checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS standby_preflight_time_idx
    ON standby_preflight_checks (checked_at DESC);

INSERT INTO watchdog_outages (
    id, watchdog_id, started_at, recovered_at, duration_seconds
)
SELECT 'wdo-legacy-' || substr(md5(id || last_seen_at::text), 1, 12),
       id, last_seen_at - make_interval(secs => last_outage_seconds),
       last_seen_at, last_outage_seconds
FROM external_watchdogs
WHERE last_status = 'recovered'
  AND last_outage_seconds > 0
  AND last_recovered_at IS NULL
ON CONFLICT (watchdog_id, recovered_at) DO NOTHING;

UPDATE external_watchdogs
SET last_recovered_at = last_seen_at
WHERE last_status = 'recovered'
  AND last_outage_seconds > 0
  AND last_recovered_at IS NULL;

INSERT INTO alert_rules (
    id, name, metric, threshold, consecutive_samples, severity
) VALUES
    ('rule-host-offline', '主機無法連線', 'availability', 1, 2, 'critical'),
    ('rule-cpu-high', 'CPU 使用率過高', 'cpu', 90, 3, 'warning'),
    ('rule-ram-high', '記憶體使用率過高', 'ram', 85, 3, 'warning'),
    ('rule-disk-high', '磁碟使用率過高', 'disk', 80, 2, 'critical'),
    ('rule-service-failed', 'systemd 服務失敗', 'failed_services', 1, 1, 'critical'),
    ('rule-log-collection', '集中日誌採集失敗', 'log_collection', 1, 2, 'warning'),
    ('rule-asset-drift', '主機資產設定漂移', 'asset_drift', 1, 1, 'warning'),
    ('rule-security-updates', '主機有安全更新待處理', 'security_updates', 1, 1, 'critical'),
    ('rule-security-baseline', '主機安全基準低於門檻', 'security_baseline', 80, 1, 'warning')
ON CONFLICT (id) DO NOTHING;
