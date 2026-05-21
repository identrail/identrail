ALTER TABLE repo_findings
    ADD COLUMN IF NOT EXISTS lifecycle_key TEXT,
    ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS fixed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS dismissed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS suppression_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS lifecycle_status TEXT NOT NULL DEFAULT 'open',
    ADD COLUMN IF NOT EXISTS owner TEXT,
    ADD COLUMN IF NOT EXISTS rule_version TEXT,
    ADD COLUMN IF NOT EXISTS detector_version TEXT,
    ADD COLUMN IF NOT EXISTS adapter_source TEXT,
    ADD COLUMN IF NOT EXISTS confidence_state TEXT,
    ADD COLUMN IF NOT EXISTS verification_status TEXT,
    ADD COLUMN IF NOT EXISTS scan_mode TEXT,
    ADD COLUMN IF NOT EXISTS evidence_version TEXT;

UPDATE repo_findings rf
SET
    lifecycle_key = COALESCE(
        NULLIF(rf.lifecycle_key, ''),
        NULLIF(rf.evidence->>'lifecycle_key', ''),
        CONCAT_WS(
            E'\x1f',
            'repo_finding',
            LOWER(COALESCE(NULLIF(rf.evidence->>'repository', ''), rs.repository)),
            rf.type,
            LOWER(COALESCE(NULLIF(rf.evidence->>'detector', ''), '')),
            LOWER(COALESCE(NULLIF(rf.evidence->>'file_path', ''), '')),
            COALESCE(NULLIF(rf.evidence->>'line_number', ''), ''),
            rf.finding_id
        )
    ),
    first_seen_at = COALESCE(rf.first_seen_at, rf.created_at),
    last_seen_at = COALESCE(rf.last_seen_at, rf.created_at),
    lifecycle_status = COALESCE(NULLIF(rf.lifecycle_status, ''), NULLIF(rf.evidence->>'lifecycle_status', ''), 'open'),
    owner = COALESCE(NULLIF(rf.owner, ''), NULLIF(rf.evidence->>'owner', ''), NULLIF(rf.evidence->>'owner_hint', ''), NULLIF(rf.evidence->>'owner_team', ''), NULLIF(rf.evidence->>'assignee', '')),
    rule_version = COALESCE(NULLIF(rf.rule_version, ''), NULLIF(rf.evidence->>'rule_version', '')),
    detector_version = COALESCE(NULLIF(rf.detector_version, ''), NULLIF(rf.evidence->>'detector_version', '')),
    adapter_source = COALESCE(NULLIF(rf.adapter_source, ''), NULLIF(rf.evidence->>'adapter_source', '')),
    confidence_state = COALESCE(NULLIF(rf.confidence_state, ''), NULLIF(rf.evidence->>'confidence_state', '')),
    verification_status = COALESCE(NULLIF(rf.verification_status, ''), NULLIF(rf.evidence->>'verification_status', '')),
    scan_mode = COALESCE(NULLIF(rf.scan_mode, ''), NULLIF(rf.evidence->>'scan_mode', '')),
    evidence_version = COALESCE(NULLIF(rf.evidence_version, ''), NULLIF(rf.evidence->>'evidence_version', ''))
FROM repo_scans rs
WHERE rs.id = rf.repo_scan_id;

ALTER TABLE repo_findings
    DROP CONSTRAINT IF EXISTS repo_findings_lifecycle_status_valid,
    DROP CONSTRAINT IF EXISTS repo_findings_lifecycle_time_order;

ALTER TABLE repo_findings
    ADD CONSTRAINT repo_findings_lifecycle_status_valid
        CHECK (lifecycle_status IN ('open', 'fixed', 'reopened', 'suppressed', 'risk_accepted', 'false_positive')) NOT VALID,
    ADD CONSTRAINT repo_findings_lifecycle_time_order
        CHECK (
            first_seen_at IS NULL
            OR last_seen_at IS NULL
            OR first_seen_at <= last_seen_at
        ) NOT VALID;

ALTER TABLE repo_findings VALIDATE CONSTRAINT repo_findings_lifecycle_status_valid;
ALTER TABLE repo_findings VALIDATE CONSTRAINT repo_findings_lifecycle_time_order;

CREATE INDEX IF NOT EXISTS idx_repo_findings_lifecycle_scope_key
    ON repo_findings (lifecycle_key, lifecycle_status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_repo_findings_lifecycle_status_last_seen
    ON repo_findings (lifecycle_status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_repo_findings_owner_last_seen
    ON repo_findings (owner, last_seen_at DESC);
