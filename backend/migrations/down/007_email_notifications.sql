DELETE FROM notification_retry_jobs WHERE channel='email';
DELETE FROM notification_deliveries WHERE channel='email';
ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_channel_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_check
  CHECK(channel IN ('telegram','line','sms','webhook'));
ALTER TABLE notification_retry_jobs DROP CONSTRAINT IF EXISTS notification_retry_jobs_channel_check;
ALTER TABLE notification_retry_jobs ADD CONSTRAINT notification_retry_jobs_channel_check
  CHECK(channel IN ('telegram','line','sms','webhook'));
