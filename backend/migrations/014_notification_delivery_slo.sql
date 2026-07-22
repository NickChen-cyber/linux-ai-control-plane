CREATE TABLE IF NOT EXISTS notification_delivery_policy (
    id SMALLINT PRIMARY KEY CHECK(id=1),
    window_days INTEGER NOT NULL DEFAULT 30 CHECK(window_days BETWEEN 1 AND 90),
    success_target NUMERIC(5,2) NOT NULL DEFAULT 99.00 CHECK(success_target BETWEEN 50 AND 100),
    minimum_samples INTEGER NOT NULL DEFAULT 5 CHECK(minimum_samples BETWEEN 1 AND 1000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);
INSERT INTO notification_delivery_policy(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
