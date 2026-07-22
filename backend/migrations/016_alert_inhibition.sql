CREATE TABLE IF NOT EXISTS alert_inhibition_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_rule_id TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    target_rule_id TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    reason TEXT NOT NULL,
    created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK(source_rule_id<>target_rule_id),
    UNIQUE(source_rule_id,target_rule_id)
);
CREATE INDEX IF NOT EXISTS alert_inhibition_rules_target_idx ON alert_inhibition_rules(enabled,target_rule_id);
