DROP TABLE IF EXISTS notification_retry_actions;
ALTER TABLE notification_retry_jobs DROP CONSTRAINT IF EXISTS notification_retry_jobs_status_check;
UPDATE notification_retry_jobs SET status='failed' WHERE status='dismissed';
ALTER TABLE notification_retry_jobs ADD CONSTRAINT notification_retry_jobs_status_check CHECK(status IN ('queued','sending','sent','failed'));
ALTER TABLE notification_retry_jobs DROP COLUMN IF EXISTS resolution;
ALTER TABLE notification_retry_jobs DROP COLUMN IF EXISTS resolved_by;
ALTER TABLE notification_retry_jobs DROP COLUMN IF EXISTS resolved_at;
ALTER TABLE notification_retry_jobs DROP COLUMN IF EXISTS manual_replay_count;
