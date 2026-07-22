CREATE TABLE IF NOT EXISTS alert_correlations (
    id TEXT PRIMARY KEY,
    inhibition_rule_id TEXT NOT NULL REFERENCES alert_inhibition_rules(id) ON DELETE CASCADE,
    root_event_id TEXT NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
    child_event_id TEXT NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','released')),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at TIMESTAMPTZ,
    UNIQUE(root_event_id,child_event_id)
);
CREATE INDEX IF NOT EXISTS alert_correlations_status_idx ON alert_correlations(status,last_seen_at DESC);
