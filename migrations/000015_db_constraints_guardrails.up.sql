ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS scans_status_valid,
    DROP CONSTRAINT IF EXISTS scans_asset_count_non_negative,
    DROP CONSTRAINT IF EXISTS scans_finding_count_non_negative;

ALTER TABLE scans
    ADD CONSTRAINT scans_status_valid
        CHECK (status IN ('queued', 'running', 'completed', 'succeeded', 'failed')) NOT VALID,
    ADD CONSTRAINT scans_asset_count_non_negative
        CHECK (asset_count >= 0) NOT VALID,
    ADD CONSTRAINT scans_finding_count_non_negative
        CHECK (finding_count >= 0) NOT VALID;

ALTER TABLE scans VALIDATE CONSTRAINT scans_status_valid;
ALTER TABLE scans VALIDATE CONSTRAINT scans_asset_count_non_negative;
ALTER TABLE scans VALIDATE CONSTRAINT scans_finding_count_non_negative;

ALTER TABLE repo_scans
    DROP CONSTRAINT IF EXISTS repo_scans_status_valid,
    DROP CONSTRAINT IF EXISTS repo_scans_commits_scanned_non_negative,
    DROP CONSTRAINT IF EXISTS repo_scans_files_scanned_non_negative,
    DROP CONSTRAINT IF EXISTS repo_scans_finding_count_non_negative;

ALTER TABLE repo_scans
    ADD CONSTRAINT repo_scans_status_valid
        CHECK (status IN ('queued', 'running', 'completed', 'succeeded', 'failed')) NOT VALID,
    ADD CONSTRAINT repo_scans_commits_scanned_non_negative
        CHECK (commits_scanned >= 0) NOT VALID,
    ADD CONSTRAINT repo_scans_files_scanned_non_negative
        CHECK (files_scanned >= 0) NOT VALID,
    ADD CONSTRAINT repo_scans_finding_count_non_negative
        CHECK (finding_count >= 0) NOT VALID;

ALTER TABLE repo_scans VALIDATE CONSTRAINT repo_scans_status_valid;
ALTER TABLE repo_scans VALIDATE CONSTRAINT repo_scans_commits_scanned_non_negative;
ALTER TABLE repo_scans VALIDATE CONSTRAINT repo_scans_files_scanned_non_negative;
ALTER TABLE repo_scans VALIDATE CONSTRAINT repo_scans_finding_count_non_negative;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_finding_id_non_empty;

ALTER TABLE findings
    ADD CONSTRAINT findings_finding_id_non_empty
        CHECK (LENGTH(TRIM(finding_id)) > 0) NOT VALID;

ALTER TABLE findings VALIDATE CONSTRAINT findings_finding_id_non_empty;

ALTER TABLE repo_findings
    DROP CONSTRAINT IF EXISTS repo_findings_finding_id_non_empty;

ALTER TABLE repo_findings
    ADD CONSTRAINT repo_findings_finding_id_non_empty
        CHECK (LENGTH(TRIM(finding_id)) > 0) NOT VALID;

ALTER TABLE repo_findings VALIDATE CONSTRAINT repo_findings_finding_id_non_empty;

ALTER TABLE scan_events
    DROP CONSTRAINT IF EXISTS scan_events_level_valid;

ALTER TABLE scan_events
    ADD CONSTRAINT scan_events_level_valid
        CHECK (level IN ('debug', 'info', 'warn', 'error')) NOT VALID;

ALTER TABLE scan_events VALIDATE CONSTRAINT scan_events_level_valid;
