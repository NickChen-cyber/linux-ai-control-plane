CREATE TABLE IF NOT EXISTS maintenance_windows (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host_id TEXT REFERENCES managed_hosts(id) ON DELETE CASCADE,
    rule_id TEXT REFERENCES alert_rules(id) ON DELETE CASCADE,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL,
    suppress_notifications BOOLEAN NOT NULL DEFAULT TRUE,
    pause_escalations BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK(ends_at>starts_at)
);
CREATE INDEX IF NOT EXISTS maintenance_windows_active_idx ON maintenance_windows(starts_at,ends_at,host_id,rule_id);
