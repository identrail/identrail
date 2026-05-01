DROP INDEX IF EXISTS idx_tenancy_scan_policies_scope_updated;
DROP INDEX IF EXISTS idx_tenancy_scan_policies_scope_mode_enabled;
DROP INDEX IF EXISTS idx_tenancy_connector_states_scope_health;
DROP INDEX IF EXISTS idx_tenancy_connectors_scope_sync;
DROP INDEX IF EXISTS idx_tenancy_connectors_scope_status;

DROP TABLE IF EXISTS tenancy_scan_policies;
DROP TABLE IF EXISTS tenancy_connector_states;
DROP TABLE IF EXISTS tenancy_connectors;
