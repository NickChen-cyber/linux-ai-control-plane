ALTER TABLE notification_retry_jobs ADD COLUMN IF NOT EXISTS manual_replay_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE notification_retry_jobs ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
ALTER TABLE notification_retry_jobs ADD COLUMN IF NOT EXISTS resolved_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL;
ALTER TABLE notification_retry_jobs ADD COLUMN IF NOT EXISTS resolution TEXT;
ALTER TABLE notification_retry_jobs DROP CONSTRAINT IF EXISTS notification_retry_jobs_status_check;
ALTER TABLE notification_retry_jobs ADD CONSTRAINT notification_retry_jobs_status_check CHECK(status IN ('queued','sending','sent','failed','dismissed'));
CREATE TABLE IF NOT EXISTS notification_retry_actions (
    id TEXT PRIMARY KEY,
    retry_job_id TEXT NOT NULL REFERENCES notification_retry_jobs(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK(action IN ('replay','dismiss')),
    note TEXT,
    actor_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS notification_retry_actions_job_idx ON notification_retry_actions(retry_job_id,created_at DESC);
