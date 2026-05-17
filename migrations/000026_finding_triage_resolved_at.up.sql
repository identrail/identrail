-- 000026_finding_triage_resolved_at.up.sql
-- Additive: records when a finding entered the resolved state so the
-- executive report can compute an accurate mean-time-to-resolve (MTTR).

ALTER TABLE finding_triage_states
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

-- Best-effort historical backfill: existing resolved rows only have a mutable
-- updated_at, so use it as the closest available proxy for the resolution time.
UPDATE finding_triage_states
SET resolved_at = updated_at
WHERE status = 'resolved'
  AND resolved_at IS NULL;

-- Defensive: a non-resolved row must never carry a resolution time.
UPDATE finding_triage_states
SET resolved_at = NULL
WHERE status <> 'resolved'
  AND resolved_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_scope_resolved_at
    ON finding_triage_states (tenant_id, workspace_id, resolved_at);
