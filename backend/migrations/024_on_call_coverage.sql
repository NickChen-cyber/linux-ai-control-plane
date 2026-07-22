CREATE TABLE IF NOT EXISTS on_call_coverage_policy(
    id INTEGER PRIMARY KEY CHECK(id=1),
    horizon_hours INTEGER NOT NULL DEFAULT 168 CHECK(horizon_hours BETWEEN 1 AND 720),
    target_percent NUMERIC(5,2) NOT NULL DEFAULT 100 CHECK(target_percent BETWEEN 1 AND 100),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);
INSERT INTO on_call_coverage_policy(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
