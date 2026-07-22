CREATE TABLE IF NOT EXISTS notification_routes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL CHECK(priority BETWEEN 1 AND 9999),
    severity TEXT CHECK(severity IN ('warning','critical')),
    host_id TEXT REFERENCES managed_hosts(id) ON DELETE CASCADE,
    rule_id TEXT REFERENCES alert_rules(id) ON DELETE CASCADE,
    channels JSONB NOT NULL DEFAULT '[]'::jsonb,
    title_template TEXT NOT NULL DEFAULT '[Linux AI] {{severity}} - {{host}}',
    body_template TEXT NOT NULL DEFAULT '{{message}}',
    created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(priority)
);
CREATE INDEX IF NOT EXISTS notification_routes_match_idx ON notification_routes(enabled,priority,severity,host_id,rule_id);
