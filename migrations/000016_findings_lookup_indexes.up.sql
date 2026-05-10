CREATE INDEX IF NOT EXISTS idx_findings_finding_id_created_at
    ON findings (finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_repo_findings_finding_id_created_at
    ON repo_findings (finding_id, created_at DESC);
