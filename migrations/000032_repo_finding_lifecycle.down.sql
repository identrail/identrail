DROP INDEX IF EXISTS idx_repo_findings_owner_last_seen;
DROP INDEX IF EXISTS idx_repo_findings_lifecycle_status_last_seen;
DROP INDEX IF EXISTS idx_repo_findings_lifecycle_scope_key;

ALTER TABLE repo_findings
    DROP CONSTRAINT IF EXISTS repo_findings_lifecycle_time_order,
    DROP CONSTRAINT IF EXISTS repo_findings_lifecycle_status_valid;

ALTER TABLE repo_findings
    DROP COLUMN IF EXISTS evidence_version,
    DROP COLUMN IF EXISTS scan_mode,
    DROP COLUMN IF EXISTS verification_status,
    DROP COLUMN IF EXISTS confidence_state,
    DROP COLUMN IF EXISTS adapter_source,
    DROP COLUMN IF EXISTS detector_version,
    DROP COLUMN IF EXISTS rule_version,
    DROP COLUMN IF EXISTS owner,
    DROP COLUMN IF EXISTS lifecycle_status,
    DROP COLUMN IF EXISTS suppression_expires_at,
    DROP COLUMN IF EXISTS dismissed_at,
    DROP COLUMN IF EXISTS reopened_at,
    DROP COLUMN IF EXISTS fixed_at,
    DROP COLUMN IF EXISTS last_seen_at,
    DROP COLUMN IF EXISTS first_seen_at,
    DROP COLUMN IF EXISTS lifecycle_key;
