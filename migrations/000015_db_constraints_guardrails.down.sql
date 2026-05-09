ALTER TABLE scan_events
    DROP CONSTRAINT IF EXISTS scan_events_level_valid;

ALTER TABLE repo_findings
    DROP CONSTRAINT IF EXISTS repo_findings_finding_id_non_empty;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_finding_id_non_empty;

ALTER TABLE repo_scans
    DROP CONSTRAINT IF EXISTS repo_scans_status_valid,
    DROP CONSTRAINT IF EXISTS repo_scans_commits_scanned_non_negative,
    DROP CONSTRAINT IF EXISTS repo_scans_files_scanned_non_negative,
    DROP CONSTRAINT IF EXISTS repo_scans_finding_count_non_negative;

ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS scans_status_valid,
    DROP CONSTRAINT IF EXISTS scans_asset_count_non_negative,
    DROP CONSTRAINT IF EXISTS scans_finding_count_non_negative;
