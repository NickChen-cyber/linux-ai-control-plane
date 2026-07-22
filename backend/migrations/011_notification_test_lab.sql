CREATE TABLE IF NOT EXISTS notification_test_runs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    host_id TEXT REFERENCES managed_hosts(id) ON DELETE SET NULL,
    rule_id TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
    delivery_requested BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS notification_test_runs_created_idx ON notification_test_runs(created_at DESC);
