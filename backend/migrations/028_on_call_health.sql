CREATE TABLE IF NOT EXISTS on_call_health_policy(
    id INTEGER PRIMARY KEY CHECK(id=1),
    horizon_days INTEGER NOT NULL DEFAULT 14 CHECK(horizon_days BETWEEN 1 AND 90),
    max_shift_hours NUMERIC(5,2) NOT NULL DEFAULT 12 CHECK(max_shift_hours BETWEEN 1 AND 168),
    min_rest_hours NUMERIC(5,2) NOT NULL DEFAULT 8 CHECK(min_rest_hours BETWEEN 0 AND 72),
    max_weekly_hours NUMERIC(6,2) NOT NULL DEFAULT 60 CHECK(max_weekly_hours BETWEEN 1 AND 168),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);
INSERT INTO on_call_health_policy(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
