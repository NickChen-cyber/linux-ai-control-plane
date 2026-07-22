ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_kind_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind_check
  CHECK(kind IN ('firing','resolved','test','backup_failed'));
ALTER TABLE notification_retry_jobs DROP CONSTRAINT IF EXISTS notification_retry_jobs_kind_check;
ALTER TABLE notification_retry_jobs ADD CONSTRAINT notification_retry_jobs_kind_check
  CHECK(kind IN ('firing','resolved','test','backup_failed'));
DROP TABLE IF EXISTS operational_reports;
DROP TABLE IF EXISTS report_policy;
