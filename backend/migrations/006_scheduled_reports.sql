CREATE TABLE IF NOT EXISTS report_policy (
  id SMALLINT PRIMARY KEY CHECK(id=1),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  weekly_day SMALLINT NOT NULL DEFAULT 1 CHECK(weekly_day BETWEEN 1 AND 7),
  monthly_day SMALLINT NOT NULL DEFAULT 1 CHECK(monthly_day BETWEEN 1 AND 28),
  generate_hour_utc SMALLINT NOT NULL DEFAULT 0 CHECK(generate_hour_utc BETWEEN 0 AND 23),
  notify_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);
INSERT INTO report_policy(id) VALUES(1) ON CONFLICT(id) DO NOTHING;

CREATE TABLE IF NOT EXISTS operational_reports (
  id TEXT PRIMARY KEY,
  report_type TEXT NOT NULL CHECK(report_type IN ('manual','weekly','monthly')),
  period_start DATE NOT NULL,
  period_end DATE NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('completed','failed')),
  snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  delivery_status TEXT NOT NULL DEFAULT 'not_requested' CHECK(delivery_status IN ('not_requested','sent','failed','no_channel')),
  delivered_channels JSONB NOT NULL DEFAULT '[]'::jsonb,
  error TEXT,
  requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS operational_reports_time_idx ON operational_reports(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS operational_reports_scheduled_idx
  ON operational_reports(report_type,period_start,period_end)
  WHERE report_type IN ('weekly','monthly');

ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_kind_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind_check
  CHECK(kind IN ('firing','resolved','test','backup_failed','report'));
ALTER TABLE notification_retry_jobs DROP CONSTRAINT IF EXISTS notification_retry_jobs_kind_check;
ALTER TABLE notification_retry_jobs ADD CONSTRAINT notification_retry_jobs_kind_check
  CHECK(kind IN ('firing','resolved','test','backup_failed','report'));
