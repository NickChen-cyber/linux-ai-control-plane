CREATE TABLE IF NOT EXISTS alert_ownership_policy(
    id INTEGER PRIMARY KEY CHECK(id=1),
    warning_minutes INTEGER NOT NULL DEFAULT 30 CHECK(warning_minutes BETWEEN 1 AND 10080),
    critical_minutes INTEGER NOT NULL DEFAULT 10 CHECK(critical_minutes BETWEEN 1 AND 10080),
    unassigned_minutes INTEGER NOT NULL DEFAULT 5 CHECK(unassigned_minutes BETWEEN 1 AND 1440),
    due_soon_percent INTEGER NOT NULL DEFAULT 25 CHECK(due_soon_percent BETWEEN 5 AND 90),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);
INSERT INTO alert_ownership_policy(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
