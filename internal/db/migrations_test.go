package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitialMigrationContainsCoreTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000001_init.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)

	required := []string{
		"CREATE TABLE IF NOT EXISTS scans",
		"CREATE TABLE IF NOT EXISTS identities",
		"CREATE TABLE IF NOT EXISTS relationships",
		"CREATE TABLE IF NOT EXISTS findings",
		"PRIMARY KEY (scan_id, finding_id)",
	}

	for _, needle := range required {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected migration to contain %q", needle)
		}
	}
}

func TestSecondMigrationContainsScanEvents(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000002_scan_events.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "CREATE TABLE IF NOT EXISTS scan_events") {
		t.Fatal("expected scan_events table creation in second migration")
	}
}

func TestThirdMigrationContainsRepoScanTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000003_repo_scans.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "CREATE TABLE IF NOT EXISTS repo_scans") {
		t.Fatal("expected repo_scans table creation in third migration")
	}
	if !strings.Contains(text, "CREATE TABLE IF NOT EXISTS repo_findings") {
		t.Fatal("expected repo_findings table creation in third migration")
	}
}

func TestFourthMigrationContainsPerformanceIndexes(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000004_performance_indexes.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"idx_findings_scan_severity_type_created",
		"idx_findings_created_at",
		"idx_repo_findings_scan_severity_type_created",
		"idx_repo_findings_created_at",
		"idx_scan_events_scan_level_created",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected performance index %q in fourth migration", item)
		}
	}
}

func TestFifthMigrationContainsFindingWorkflowTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000005_finding_workflow_maturity.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS finding_triage_states",
		"CREATE TABLE IF NOT EXISTS finding_triage_events",
		"idx_finding_triage_states_status",
		"idx_finding_triage_events_finding_created",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected workflow migration to contain %q", item)
		}
	}
}

func TestSixthMigrationContainsTenantWorkspaceScope(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000006_tenant_workspace_scope.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"ADD COLUMN IF NOT EXISTS tenant_id",
		"ADD COLUMN IF NOT EXISTS workspace_id",
		"idx_scans_scope_started_at",
		"idx_repo_scans_scope_started_at",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected tenant/workspace scope migration item %q", item)
		}
	}
}

func TestSeventhMigrationContainsScopedTriageGuardrails(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000007_scope_guardrails_for_triage.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"ADD COLUMN IF NOT EXISTS tenant_id",
		"ADD COLUMN IF NOT EXISTS workspace_id",
		"PRIMARY KEY (tenant_id, workspace_id, finding_id)",
		"idx_finding_triage_states_scope_status",
		"idx_finding_triage_events_scope_finding_created",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected scoped triage migration item %q", item)
		}
	}
}

func TestEighthMigrationContainsPostgresRLSGuardrails(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000008_postgres_rls_scope_guardrails.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE OR REPLACE FUNCTION identrail_rls_scope_matches",
		"ALTER TABLE scans ENABLE ROW LEVEL SECURITY",
		"CREATE POLICY scans_scope_isolation",
		"CREATE POLICY repo_scans_scope_isolation",
		"CREATE POLICY finding_triage_states_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected postgres rls migration item %q", item)
		}
	}
}

func TestNinthMigrationContainsAuthzABACAndReBACDataTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000009_authz_abac_rebac_data.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS authz_entity_attributes",
		"CREATE TABLE IF NOT EXISTS authz_relationships",
		"idx_authz_entity_attributes_scope_kind_type",
		"idx_authz_relationships_scope_subject_relation",
		"CREATE POLICY authz_entity_attributes_scope_isolation",
		"CREATE POLICY authz_relationships_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected authz data migration item %q", item)
		}
	}
}

func TestTenthMigrationContainsAuthzPolicyLifecycleTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000010_authz_policy_lifecycle_controls.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS authz_policy_sets",
		"CREATE TABLE IF NOT EXISTS authz_policy_versions",
		"CREATE TABLE IF NOT EXISTS authz_policy_rollouts",
		"CREATE TABLE IF NOT EXISTS authz_policy_events",
		"idx_authz_policy_versions_scope_set_created",
		"idx_authz_policy_rollouts_scope_mode",
		"idx_authz_policy_events_scope_set_created",
		"FORCE ROW LEVEL SECURITY",
		"DROP POLICY IF EXISTS authz_policy_sets_scope_isolation",
		"DROP POLICY IF EXISTS authz_policy_versions_scope_isolation",
		"DROP POLICY IF EXISTS authz_policy_rollouts_scope_isolation",
		"DROP POLICY IF EXISTS authz_policy_events_scope_isolation",
		"CREATE POLICY authz_policy_sets_scope_isolation",
		"CREATE POLICY authz_policy_versions_scope_isolation",
		"CREATE POLICY authz_policy_rollouts_scope_isolation",
		"CREATE POLICY authz_policy_events_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected authz policy lifecycle migration item %q", item)
		}
	}
}

func TestEleventhMigrationContainsAuthzRolloutStagedControls(t *testing.T) {
	upPath := filepath.Join("..", "..", "migrations", "000011_authz_policy_rollout_staged_controls.up.sql")
	upContent, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	upText := string(upContent)
	upRequired := []string{
		"ADD COLUMN IF NOT EXISTS tenant_allowlist JSONB NOT NULL DEFAULT '[]'::jsonb",
		"ADD COLUMN IF NOT EXISTS workspace_allowlist JSONB NOT NULL DEFAULT '[]'::jsonb",
		"ADD COLUMN IF NOT EXISTS canary_percentage INTEGER NOT NULL DEFAULT 100",
		"ADD COLUMN IF NOT EXISTS validated_versions JSONB NOT NULL DEFAULT '[]'::jsonb",
		"ADD CONSTRAINT authz_policy_rollouts_canary_percentage_valid",
		"ADD CONSTRAINT authz_policy_rollouts_tenant_allowlist_array",
		"ADD CONSTRAINT authz_policy_rollouts_workspace_allowlist_array",
		"ADD CONSTRAINT authz_policy_rollouts_validated_versions_array",
	}
	for _, item := range upRequired {
		if !strings.Contains(upText, item) {
			t.Fatalf("expected authz rollout staged controls migration item %q", item)
		}
	}

	downPath := filepath.Join("..", "..", "migrations", "000011_authz_policy_rollout_staged_controls.down.sql")
	downContent, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downText := string(downContent)
	downRequired := []string{
		"DROP CONSTRAINT IF EXISTS authz_policy_rollouts_validated_versions_array",
		"DROP CONSTRAINT IF EXISTS authz_policy_rollouts_workspace_allowlist_array",
		"DROP CONSTRAINT IF EXISTS authz_policy_rollouts_tenant_allowlist_array",
		"DROP CONSTRAINT IF EXISTS authz_policy_rollouts_canary_percentage_valid",
		"DROP COLUMN IF EXISTS validated_versions",
		"DROP COLUMN IF EXISTS canary_percentage",
		"DROP COLUMN IF EXISTS workspace_allowlist",
		"DROP COLUMN IF EXISTS tenant_allowlist",
	}
	for _, item := range downRequired {
		if !strings.Contains(downText, item) {
			t.Fatalf("expected authz rollout staged controls down migration item %q", item)
		}
	}
}

func TestTwelfthMigrationContainsTenancyCoreTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000012_tenancy_core_entities.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS tenancy_organizations",
		"CREATE TABLE IF NOT EXISTS tenancy_workspaces",
		"CREATE TABLE IF NOT EXISTS tenancy_workspace_members",
		"CREATE TABLE IF NOT EXISTS tenancy_projects",
		"FOREIGN KEY (tenant_id) REFERENCES tenancy_organizations(tenant_id)",
		"FOREIGN KEY (tenant_id, workspace_id) REFERENCES tenancy_workspaces(tenant_id, workspace_id)",
		"idx_tenancy_workspaces_scope_created",
		"idx_tenancy_members_scope_role_status",
		"idx_tenancy_members_scope_joined",
		"idx_tenancy_projects_scope_created",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected tenancy core migration item %q", item)
		}
	}
}

func TestSixteenthMigrationContainsFindingLookupIndexes(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000016_findings_lookup_indexes.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"idx_findings_finding_id_created_at",
		"idx_repo_findings_finding_id_created_at",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected finding lookup migration item %q", item)
		}
	}
}

func TestSeventeenthMigrationContainsQueueTraceContextColumns(t *testing.T) {
	upPath := filepath.Join("..", "..", "migrations", "000017_queue_trace_context.up.sql")
	upContent, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	upText := string(upContent)
	upRequired := []string{
		"ALTER TABLE scans",
		"ADD COLUMN IF NOT EXISTS trace_parent TEXT",
		"ADD COLUMN IF NOT EXISTS trace_state TEXT",
		"ALTER TABLE repo_scans",
	}
	for _, item := range upRequired {
		if !strings.Contains(upText, item) {
			t.Fatalf("expected queue trace context migration item %q", item)
		}
	}

	downPath := filepath.Join("..", "..", "migrations", "000017_queue_trace_context.down.sql")
	downContent, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downText := string(downContent)
	downRequired := []string{
		"DROP COLUMN IF EXISTS trace_state",
		"DROP COLUMN IF EXISTS trace_parent",
	}
	for _, item := range downRequired {
		if !strings.Contains(downText, item) {
			t.Fatalf("expected queue trace context down migration item %q", item)
		}
	}
}

func TestEighteenthMigrationContainsUsersAndSessions(t *testing.T) {
	upPath := filepath.Join("..", "..", "migrations", "000018_users_and_sessions.up.sql")
	upContent, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	upText := string(upContent)
	upRequired := []string{
		"CREATE EXTENSION IF NOT EXISTS citext",
		"CREATE TABLE IF NOT EXISTS users",
		"CREATE TABLE IF NOT EXISTS user_identities",
		"ADD COLUMN IF NOT EXISTS user_uuid UUID",
		"CREATE TABLE IF NOT EXISTS sessions",
		"CHECK (LENGTH(id) = 32)",
		"CHECK (auth_method IN ('workos', 'oidc', 'manual'))",
		"idx_tenancy_members_scope_user_uuid",
		"idx_sessions_user_id",
	}
	for _, item := range upRequired {
		if !strings.Contains(upText, item) {
			t.Fatalf("expected users and sessions migration item %q", item)
		}
	}

	downPath := filepath.Join("..", "..", "migrations", "000018_users_and_sessions.down.sql")
	downContent, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downText := string(downContent)
	downRequired := []string{
		"DROP TABLE IF EXISTS sessions",
		"DROP COLUMN IF EXISTS user_uuid",
		"DROP TABLE IF EXISTS user_identities",
		"DROP TABLE IF EXISTS users",
	}
	for _, item := range downRequired {
		if !strings.Contains(downText, item) {
			t.Fatalf("expected users and sessions down migration item %q", item)
		}
	}
}

func TestThirteenthMigrationContainsConnectorAndPolicyTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000013_connectors_state_scan_policies.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS tenancy_connectors",
		"CREATE TABLE IF NOT EXISTS tenancy_connector_states",
		"CREATE TABLE IF NOT EXISTS tenancy_scan_policies",
		"FOREIGN KEY (tenant_id, workspace_id, project_id)",
		"REFERENCES tenancy_projects(tenant_id, workspace_id, project_id)",
		"REFERENCES tenancy_connectors(tenant_id, workspace_id, project_id, connector_id)",
		"CHECK (type IN ('github', 'aws', 'kubernetes'))",
		"CHECK (trigger_mode IN ('manual', 'scheduled', 'event', 'hybrid'))",
		"CHECK (max_concurrent_scans > 0)",
		"idx_tenancy_connectors_scope_status",
		"idx_tenancy_connector_states_scope_health",
		"idx_tenancy_scan_policies_scope_mode_enabled",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected connector/policy migration item %q", item)
		}
	}
}

func TestFourteenthMigrationContainsConnectorSecretEnvelopeSchema(t *testing.T) {
	upPath := filepath.Join("..", "..", "migrations", "000014_connector_secret_envelopes.up.sql")
	upContent, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	upText := string(upContent)
	upRequired := []string{
		"CREATE TABLE IF NOT EXISTS tenancy_connector_secret_envelopes",
		"envelope_version INTEGER NOT NULL DEFAULT 1",
		"algorithm TEXT NOT NULL",
		"key_version TEXT NOT NULL",
		"nonce BYTEA NOT NULL",
		"ciphertext BYTEA NOT NULL",
		"secret_ref_id TEXT",
		"rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
		"rotation_due_at TIMESTAMPTZ",
		"CHECK (algorithm = 'AES-256-GCM')",
		"CHECK (LENGTH(nonce) = 12)",
		"idx_tenancy_connector_secret_envelopes_rotation",
	}
	for _, item := range upRequired {
		if !strings.Contains(upText, item) {
			t.Fatalf("expected connector secret envelope migration item %q", item)
		}
	}

	downPath := filepath.Join("..", "..", "migrations", "000014_connector_secret_envelopes.down.sql")
	downContent, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downText := string(downContent)
	downRequired := []string{
		"DROP INDEX IF EXISTS idx_tenancy_connector_secret_envelopes_rotation",
		"DROP TABLE IF EXISTS tenancy_connector_secret_envelopes",
	}
	for _, item := range downRequired {
		if !strings.Contains(downText, item) {
			t.Fatalf("expected connector secret envelope down migration item %q", item)
		}
	}
}

func TestFifteenthMigrationContainsDatabaseConstraintGuardrails(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000015_db_constraints_guardrails.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"ADD CONSTRAINT scans_status_valid",
		"CHECK (status IN ('queued', 'running', 'completed', 'succeeded', 'failed'))",
		"ADD CONSTRAINT repo_scans_commits_scanned_non_negative",
		"ADD CONSTRAINT findings_finding_id_non_empty",
		"ADD CONSTRAINT repo_findings_finding_id_non_empty",
		"ADD CONSTRAINT scan_events_level_valid",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected database constraint migration item %q", item)
		}
	}
	if strings.Contains(text, "SET status = 'completed'\nWHERE status = 'succeeded';") {
		t.Fatal("expected status guardrail migration to avoid rewriting succeeded scan statuses")
	}
}

func TestFifteenthMigrationContainsTenancyConnectorRLSGuardrails(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000015_tenancy_connector_rls_scope_guardrails.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE OR REPLACE FUNCTION identrail_rls_tenant_matches",
		"ALTER TABLE tenancy_organizations ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_workspaces ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_workspace_members ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_projects ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_connectors ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_connector_states ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_scan_policies ENABLE ROW LEVEL SECURITY",
		"CREATE POLICY tenancy_organizations_scope_isolation",
		"USING (identrail_rls_tenant_matches(tenant_id))",
		"CREATE POLICY tenancy_connector_states_scope_isolation",
		"CREATE POLICY tenancy_scan_policies_scope_isolation",
		"CREATE POLICY tenancy_connector_secret_envelopes_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected tenancy rls migration item %q", item)
		}
	}
}

func TestFifteenthMigrationEnforcesRLSForTenancyAndConnectorTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000015_tenancy_connector_rls_scope_enforcement.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE OR REPLACE FUNCTION identrail_rls_tenant_matches",
		"ALTER TABLE tenancy_organizations ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_workspaces ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_workspace_members ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_projects ENABLE ROW LEVEL SECURITY",
		"CREATE POLICY tenancy_organizations_scope_isolation",
		"ALTER TABLE tenancy_connectors ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_connector_states ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_scan_policies ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE tenancy_connector_secret_envelopes ENABLE ROW LEVEL SECURITY",
		"CREATE POLICY tenancy_connector_states_scope_isolation",
		"CREATE POLICY tenancy_scan_policies_scope_isolation",
		"CREATE POLICY tenancy_connector_secret_envelopes_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected tenancy/connector RLS migration item %q", item)
		}
	}
	if !strings.Contains(text, "CREATE POLICY tenancy_workspaces_scope_isolation ON tenancy_workspaces\nUSING (identrail_rls_tenant_matches(tenant_id))\nWITH CHECK (identrail_rls_tenant_matches(tenant_id));") {
		t.Fatal("expected tenancy_workspaces policy to remain tenant-scoped for tenant-level workspace discovery")
	}
}
