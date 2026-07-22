DROP INDEX IF EXISTS on_call_shifts_template_start_idx;
ALTER TABLE on_call_shifts DROP COLUMN IF EXISTS template_id;
DROP TABLE IF EXISTS on_call_templates;
