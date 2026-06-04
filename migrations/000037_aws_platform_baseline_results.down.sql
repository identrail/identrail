DROP POLICY IF EXISTS aws_platform_baseline_results_scope_isolation ON aws_platform_baseline_results;
ALTER TABLE aws_platform_baseline_results NO FORCE ROW LEVEL SECURITY;
ALTER TABLE aws_platform_baseline_results DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS idx_aws_platform_baseline_results_scope_status;
DROP TABLE IF EXISTS aws_platform_baseline_results;
