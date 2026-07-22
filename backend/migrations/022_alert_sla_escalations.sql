CREATE TABLE IF NOT EXISTS alert_sla_escalations(
    id TEXT PRIMARY KEY,
    alert_event_id TEXT NOT NULL UNIQUE REFERENCES alert_events(id) ON DELETE CASCADE,
    breach_type TEXT NOT NULL CHECK(breach_type IN ('ack_deadline','unassigned')),
    status TEXT NOT NULL CHECK(status IN ('queued','sent','failed','suppressed','no_channel','recovered')),
    delivery_count INTEGER NOT NULL DEFAULT 0,
    detail TEXT,
    breached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    recovered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS alert_sla_escalations_time_idx ON alert_sla_escalations(breached_at DESC);
