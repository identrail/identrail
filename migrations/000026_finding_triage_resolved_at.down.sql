-- 000026_finding_triage_resolved_at.down.sql

DROP INDEX IF EXISTS idx_finding_triage_states_scope_resolved_at;

ALTER TABLE finding_triage_states
    DROP COLUMN IF EXISTS resolved_at;
