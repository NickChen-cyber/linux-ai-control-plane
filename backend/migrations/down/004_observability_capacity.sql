DELETE FROM alert_events WHERE rule_id='rule-capacity-forecast';
DELETE FROM alert_rules WHERE id='rule-capacity-forecast';
ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (
  metric IN ('availability','cpu','ram','disk','failed_services','log_collection',
             'asset_drift','security_updates','security_baseline')
);
DROP TABLE IF EXISTS capacity_forecasts;
DROP TABLE IF EXISTS service_health_samples;
