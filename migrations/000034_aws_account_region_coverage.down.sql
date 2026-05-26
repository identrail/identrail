DROP POLICY IF EXISTS aws_account_region_coverages_scope_isolation ON aws_account_region_coverages;
ALTER TABLE aws_account_region_coverages NO FORCE ROW LEVEL SECURITY;
ALTER TABLE aws_account_region_coverages DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS idx_aws_account_region_coverages_account_region;
DROP INDEX IF EXISTS idx_aws_account_region_coverages_scope_status;
DROP TABLE IF EXISTS aws_account_region_coverages;
