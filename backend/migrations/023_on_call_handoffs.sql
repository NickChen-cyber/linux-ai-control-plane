CREATE TABLE IF NOT EXISTS on_call_handoffs(
    id TEXT PRIMARY KEY,
    shift_id TEXT REFERENCES on_call_shifts(id) ON DELETE SET NULL,
    from_user_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    to_user_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    reason TEXT NOT NULL,
    handed_off_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
    handed_off_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS on_call_handoffs_shift_time_idx ON on_call_handoffs(shift_id,handed_off_at DESC);
