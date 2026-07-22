ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_channel_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_check
  CHECK(channel IN ('telegram','line','sms','webhook','email'));
ALTER TABLE notification_retry_jobs DROP CONSTRAINT IF EXISTS notification_retry_jobs_channel_check;
ALTER TABLE notification_retry_jobs ADD CONSTRAINT notification_retry_jobs_channel_check
  CHECK(channel IN ('telegram','line','sms','webhook','email'));
