CREATE TABLE IF NOT EXISTS on_call_fairness_policy(
    id INTEGER PRIMARY KEY CHECK(id=1),
    window_days INTEGER NOT NULL DEFAULT 30 CHECK(window_days BETWEEN 1 AND 180),
    imbalance_percent NUMERIC(5,2) NOT NULL DEFAULT 25 CHECK(imbalance_percent BETWEEN 1 AND 100),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);
INSERT INTO on_call_fairness_policy(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
