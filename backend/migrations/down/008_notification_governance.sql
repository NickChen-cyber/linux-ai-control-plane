DELETE FROM notification_deliveries WHERE status='suppressed';
ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_status_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_status_check CHECK(status IN ('sent','failed'));
DROP TABLE IF EXISTS alert_silences;
DROP TABLE IF EXISTS notification_governance_policy;
