CREATE TABLE IF NOT EXISTS on_call_templates(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES platform_users(id) ON DELETE CASCADE,
    first_starts_at TIMESTAMPTZ NOT NULL,
    interval_days INTEGER NOT NULL CHECK(interval_days BETWEEN 1 AND 31),
    duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 30 AND 10080),
    horizon_days INTEGER NOT NULL DEFAULT 30 CHECK(horizon_days BETWEEN 1 AND 180),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE on_call_shifts ADD COLUMN IF NOT EXISTS template_id TEXT REFERENCES on_call_templates(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS on_call_shifts_template_start_idx ON on_call_shifts(template_id,starts_at) WHERE template_id IS NOT NULL;
