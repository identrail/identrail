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

WITH repo_finding_backfill AS (
    SELECT
        rf.repo_scan_id,
        rf.finding_id,
        LOWER(COALESCE(NULLIF(rf.evidence->>'repository', ''), rs.repository)) AS repository_key,
        LOWER(COALESCE(NULLIF(rf.evidence->>'detector', ''), '')) AS detector_key,
        LOWER(COALESCE(NULLIF(rf.evidence->>'file_path', ''), '')) AS file_path_key,
        COALESCE(NULLIF(rf.evidence->>'line_number', ''), '') AS line_number_key,
        LOWER(COALESCE(
            NULLIF(rf.evidence->>'secret_fingerprint', ''),
            NULLIF(rf.evidence->>'match_fingerprint', ''),
            NULLIF(rf.evidence->>'finding_fingerprint', ''),
            NULLIF(rf.evidence->>'fingerprint', '')
        )) AS fingerprint_key,
        LOWER(TRIM(COALESCE(rf.title, ''))) AS title_key,
        CASE LOWER(TRIM(COALESCE(rf.evidence->>'lifecycle_status', '')))
            WHEN 'open' THEN 'open'
            WHEN 'fixed' THEN 'fixed'
            WHEN 'reopened' THEN 'reopened'
            WHEN 'suppressed' THEN 'suppressed'
            WHEN 'risk_accepted' THEN 'risk_accepted'
            WHEN 'false_positive' THEN 'false_positive'
            ELSE COALESCE(NULLIF(rf.lifecycle_status, ''), 'open')
        END AS lifecycle_status_key
    FROM repo_findings rf
    JOIN repo_scans rs ON rs.id = rf.repo_scan_id
)
UPDATE repo_findings rf
SET
    lifecycle_key = COALESCE(
        NULLIF(rf.lifecycle_key, ''),
        NULLIF(rf.evidence->>'lifecycle_key', ''),
        CASE
            WHEN bf.fingerprint_key <> '' THEN CONCAT_WS(E'\x1f', 'repo_finding', bf.repository_key, rf.type, bf.detector_key, 'fingerprint', bf.fingerprint_key, bf.file_path_key)
            WHEN bf.file_path_key <> '' OR bf.line_number_key <> '' OR bf.detector_key <> '' THEN CONCAT_WS(E'\x1f', 'repo_finding', bf.repository_key, rf.type, bf.detector_key, bf.file_path_key, bf.line_number_key, bf.title_key)
            ELSE CONCAT_WS(E'\x1f', 'repo_finding', bf.repository_key, rf.type, bf.detector_key, TRIM(rf.finding_id))
        END
    ),
    first_seen_at = COALESCE(rf.first_seen_at, rf.created_at),
    last_seen_at = COALESCE(rf.last_seen_at, rf.created_at),
    lifecycle_status = bf.lifecycle_status_key,
    owner = COALESCE(NULLIF(rf.owner, ''), NULLIF(rf.evidence->>'owner', ''), NULLIF(rf.evidence->>'owner_hint', ''), NULLIF(rf.evidence->>'owner_team', ''), NULLIF(rf.evidence->>'codeowners', ''), NULLIF(rf.evidence->>'assignee', '')),
    rule_version = COALESCE(NULLIF(rf.rule_version, ''), NULLIF(rf.evidence->>'rule_version', '')),
    detector_version = COALESCE(NULLIF(rf.detector_version, ''), NULLIF(rf.evidence->>'detector_version', '')),
    adapter_source = COALESCE(NULLIF(rf.adapter_source, ''), NULLIF(rf.evidence->>'adapter_source', '')),
    confidence_state = COALESCE(NULLIF(rf.confidence_state, ''), NULLIF(rf.evidence->>'confidence_state', '')),
    verification_status = COALESCE(NULLIF(rf.verification_status, ''), NULLIF(rf.evidence->>'verification_status', '')),
    scan_mode = COALESCE(NULLIF(rf.scan_mode, ''), NULLIF(rf.evidence->>'scan_mode', '')),
    evidence_version = COALESCE(NULLIF(rf.evidence_version, ''), NULLIF(rf.evidence->>'evidence_version', ''))
FROM repo_finding_backfill bf
WHERE bf.repo_scan_id = rf.repo_scan_id
  AND bf.finding_id = rf.finding_id;

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
