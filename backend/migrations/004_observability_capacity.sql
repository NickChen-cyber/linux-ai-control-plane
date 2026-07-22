CREATE TABLE IF NOT EXISTS service_health_samples (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  service TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('healthy','warning','critical')),
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
  detail TEXT NOT NULL DEFAULT '',
  collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS service_health_samples_time_idx
  ON service_health_samples(service,collected_at DESC);

CREATE TABLE IF NOT EXISTS capacity_forecasts (
  host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
  resource TEXT NOT NULL CHECK(resource IN ('cpu','ram','disk')),
  current_percent NUMERIC(5,1) NOT NULL,
  slope_per_day NUMERIC(10,3) NOT NULL DEFAULT 0,
  threshold_percent NUMERIC(5,1) NOT NULL DEFAULT 85,
  predicted_days NUMERIC(10,1),
  sample_count INTEGER NOT NULL DEFAULT 0,
  confidence TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
  calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(host_id,resource)
);
CREATE INDEX IF NOT EXISTS capacity_forecasts_risk_idx
  ON capacity_forecasts(predicted_days,calculated_at DESC);

ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (
  metric IN ('availability','cpu','ram','disk','failed_services','log_collection',
             'asset_drift','security_updates','security_baseline','capacity_forecast')
);
INSERT INTO alert_rules(id,name,metric,threshold,consecutive_samples,severity,enabled)
VALUES('rule-capacity-forecast','容量即將達到門檻','capacity_forecast',14,1,'warning',TRUE)
ON CONFLICT(id) DO NOTHING;
