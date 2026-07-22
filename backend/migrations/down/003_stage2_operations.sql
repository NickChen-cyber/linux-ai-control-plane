DROP TABLE IF EXISTS data_retention_runs;
DROP TABLE IF EXISTS data_retention_policy;
DROP TABLE IF EXISTS maintenance_workers;
DROP INDEX IF EXISTS maintenance_tasks_queue_idx;
ALTER TABLE maintenance_tasks DROP COLUMN IF EXISTS worker_id;
ALTER TABLE maintenance_tasks DROP COLUMN IF EXISTS queued_at;
ALTER TABLE maintenance_tasks DROP CONSTRAINT IF EXISTS maintenance_tasks_status_check;
ALTER TABLE maintenance_tasks ADD CONSTRAINT maintenance_tasks_status_check
  CHECK (status IN ('pending','approved','rejected','running','succeeded','failed','cancelled','timed_out'));
