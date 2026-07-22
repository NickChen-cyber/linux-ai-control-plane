DROP TABLE IF EXISTS on_call_gap_alerts;
ALTER TABLE on_call_coverage_policy DROP COLUMN IF EXISTS alert_lead_hours;
ALTER TABLE on_call_coverage_policy DROP COLUMN IF EXISTS alert_enabled;
