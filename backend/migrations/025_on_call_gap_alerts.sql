ALTER TABLE on_call_coverage_policy ADD COLUMN IF NOT EXISTS alert_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE on_call_coverage_policy ADD COLUMN IF NOT EXISTS alert_lead_hours INTEGER NOT NULL DEFAULT 24 CHECK(alert_lead_hours BETWEEN 1 AND 168);
CREATE TABLE IF NOT EXISTS on_call_gap_alerts(
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    gap_starts_at TIMESTAMPTZ NOT NULL,
    gap_ends_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('queued','sent','failed','suppressed','no_channel','resolved')),
    delivery_count INTEGER NOT NULL DEFAULT 0,
    detail TEXT,
    notified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS on_call_gap_alerts_time_idx ON on_call_gap_alerts(notified_at DESC);
