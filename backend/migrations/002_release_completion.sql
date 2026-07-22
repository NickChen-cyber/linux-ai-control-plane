ALTER TABLE maintenance_tasks DROP CONSTRAINT IF EXISTS maintenance_tasks_status_check;
ALTER TABLE maintenance_tasks ADD CONSTRAINT maintenance_tasks_status_check
  CHECK (status IN ('pending','approved','rejected','running','succeeded','failed','cancelled','timed_out'));
ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS retry_of TEXT REFERENCES maintenance_tasks(id) ON DELETE SET NULL;
ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 1;
ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS timeout_seconds INTEGER NOT NULL DEFAULT 300;
ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;
ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS cancel_requested_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS maintenance_tasks_retry_idx ON maintenance_tasks(retry_of, requested_at DESC);

ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS assignee_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL;
ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS resolution_summary TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS resolution_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;
ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS closed_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS incident_timeline (
  id TEXT PRIMARY KEY,
  alert_event_id TEXT NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  actor_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS incident_timeline_event_idx ON incident_timeline(alert_event_id, created_at);

CREATE TABLE IF NOT EXISTS release_operations (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  previous_version TEXT,
  status TEXT NOT NULL CHECK (status IN ('preflight','backup_queued','ready','applying','succeeded','failed','rolled_back')),
  compatibility JSONB NOT NULL DEFAULT '{}'::jsonb,
  backup_job_id TEXT REFERENCES database_backup_jobs(id) ON DELETE SET NULL,
  detail TEXT NOT NULL DEFAULT '',
  requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS release_operations_time_idx ON release_operations(requested_at DESC);
