DROP INDEX IF EXISTS idx_tenancy_scan_policies_schedule_due;

ALTER TABLE tenancy_scan_policies
  DROP COLUMN IF EXISTS last_scheduled_at;
