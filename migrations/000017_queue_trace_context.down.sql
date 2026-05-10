ALTER TABLE repo_scans
	DROP COLUMN IF EXISTS trace_state,
	DROP COLUMN IF EXISTS trace_parent;

ALTER TABLE scans
	DROP COLUMN IF EXISTS trace_state,
	DROP COLUMN IF EXISTS trace_parent;
