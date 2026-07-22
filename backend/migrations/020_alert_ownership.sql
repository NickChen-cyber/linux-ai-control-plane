ALTER TABLE alert_assignments DROP CONSTRAINT IF EXISTS alert_assignments_alert_event_id_key;
ALTER TABLE alert_assignments DROP CONSTRAINT IF EXISTS alert_assignments_user_id_fkey;
ALTER TABLE alert_assignments ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE alert_assignments ADD CONSTRAINT alert_assignments_user_id_fkey FOREIGN KEY(user_id) REFERENCES platform_users(id) ON DELETE SET NULL;
ALTER TABLE alert_assignments ADD COLUMN IF NOT EXISTS previous_user_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL;
ALTER TABLE alert_assignments ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'assign' CHECK(action IN ('assign','reassign','unassign'));
ALTER TABLE alert_assignments ADD COLUMN IF NOT EXISTS note TEXT;
ALTER TABLE alert_assignments ADD COLUMN IF NOT EXISTS actor_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS alert_assignments_event_idx ON alert_assignments(alert_event_id,assigned_at DESC);
