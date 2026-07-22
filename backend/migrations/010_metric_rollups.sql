CREATE TABLE IF NOT EXISTS host_metric_hourly(host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,bucket_at TIMESTAMPTZ NOT NULL,sample_count INTEGER NOT NULL,availability_percent NUMERIC(5,2) NOT NULL,cpu_avg NUMERIC(5,1) NOT NULL,cpu_max NUMERIC(5,1) NOT NULL,ram_avg NUMERIC(5,1) NOT NULL,ram_max NUMERIC(5,1) NOT NULL,disk_avg NUMERIC(5,1) NOT NULL,disk_max NUMERIC(5,1) NOT NULL,failed_service_max INTEGER NOT NULL,PRIMARY KEY(host_id,bucket_at));
CREATE INDEX IF NOT EXISTS host_metric_hourly_time_idx ON host_metric_hourly(bucket_at DESC);
CREATE TABLE IF NOT EXISTS host_metric_daily(LIKE host_metric_hourly INCLUDING ALL);
ALTER TABLE host_metric_daily DROP CONSTRAINT IF EXISTS host_metric_daily_pkey;
ALTER TABLE host_metric_daily ADD PRIMARY KEY(host_id,bucket_at);
CREATE INDEX IF NOT EXISTS host_metric_daily_time_idx ON host_metric_daily(bucket_at DESC);
