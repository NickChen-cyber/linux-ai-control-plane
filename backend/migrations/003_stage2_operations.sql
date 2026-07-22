ALTER TABLE maintenance_tasks DROP CONSTRAINT IF EXISTS maintenance_tasks_status_check;
ALTER TABLE maintenance_tasks ADD CONSTRAINT maintenance_tasks_status_check
  CHECK (status IN ('pending','approved','queued','rejected','running','succeeded','failed','cancelled','timed_out'));
ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;
ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS worker_id TEXT;
CREATE INDEX IF NOT EXISTS maintenance_tasks_queue_idx ON maintenance_tasks(status,queued_at,requested_at)
  WHERE status='queued';

CREATE TABLE IF NOT EXISTS maintenance_workers (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  concurrency INTEGER NOT NULL,
  active_tasks INTEGER NOT NULL DEFAULT 0,
  last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS data_retention_policy (
  dataset TEXT PRIMARY KEY,
  retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 3650),
  protected BOOLEAN NOT NULL DEFAULT FALSE,
  updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO data_retention_policy(dataset,retention_days,protected) VALUES
  ('audit_events',3650,TRUE),('alert_events',365,FALSE),('maintenance_tasks',365,FALSE),
  ('host_metrics',90,FALSE),('automation_runs',180,FALSE),('inventory_scans',180,FALSE),
  ('login_events',90,FALSE),('central_logs',30,FALSE)
ON CONFLICT(dataset) DO NOTHING;

CREATE TABLE IF NOT EXISTS data_retention_runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('running','success','failed')),
  preview BOOLEAN NOT NULL DEFAULT FALSE,
  result JSONB NOT NULL DEFAULT '{}'::jsonb,
  error TEXT,
  requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS data_retention_runs_time_idx ON data_retention_runs(started_at DESC);
