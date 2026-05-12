ALTER TABLE tenancy_scan_policies
  ADD COLUMN IF NOT EXISTS last_scheduled_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_tenancy_scan_policies_schedule_due
  ON tenancy_scan_policies (tenant_id, workspace_id, enabled, trigger_mode, last_scheduled_at);
