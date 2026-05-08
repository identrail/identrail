//go:build integration

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestMigrationCompatibilityWithExistingRows(t *testing.T) {
	databaseURL := os.Getenv("IDENTRAIL_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set IDENTRAIL_INTEGRATION_DATABASE_URL to run integration tests")
	}

	store, err := db.NewPostgresStore(databaseURL)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()

	migrationsDir := filepath.Clean(filepath.Join("..", "..", "migrations"))
	if err := store.ApplyMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()

	scanID := uuid.NewString()
	now := time.Now().UTC()
	provider := "aws-legacy-" + now.Format("150405")

	if _, err := sqlDB.ExecContext(
		context.Background(),
		`INSERT INTO scans (id, provider, status, started_at, finished_at, asset_count, finding_count, error_message)
		 VALUES ($1, $2, 'succeeded', $3, $4, 0, 1, NULL)`,
		scanID,
		provider,
		now.Add(-1*time.Minute),
		now,
	); err != nil {
		t.Fatalf("insert legacy scan row: %v", err)
	}

	if _, err := sqlDB.ExecContext(
		context.Background(),
		`INSERT INTO findings (scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, $7)`,
		scanID,
		"legacy-finding",
		"risky_trust_policy",
		"high",
		"Legacy risky trust",
		"Legacy persisted row with nullable fields.",
		now,
	); err != nil {
		t.Fatalf("insert legacy finding row: %v", err)
	}

	svc := api.NewService(store, integrationScanner{}, provider)

	scans, err := svc.ListScans(context.Background(), 20)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	foundScan := false
	for _, scan := range scans {
		if scan.ID == scanID {
			foundScan = true
			break
		}
	}
	if !foundScan {
		t.Fatalf("expected legacy scan %s in list", scanID)
	}

	findings, err := svc.ListFindingsFiltered(context.Background(), 20, api.FindingsFilter{
		ScanID: scanID,
	})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "legacy-finding" {
		t.Fatalf("unexpected findings from legacy row: %+v", findings)
	}

	exports, err := svc.GetFindingExports(context.Background(), "legacy-finding", scanID)
	if err != nil {
		t.Fatalf("get exports for legacy finding: %v", err)
	}
	if len(exports.OCSF) == 0 || len(exports.ASFF) == 0 {
		t.Fatalf("expected populated exports for legacy finding, got %+v", exports)
	}
}

func TestMigrationCompatibilityAuthzRolloutAndConnectorSecretMetadata(t *testing.T) {
	databaseURL := os.Getenv("IDENTRAIL_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set IDENTRAIL_INTEGRATION_DATABASE_URL to run integration tests")
	}

	store, err := db.NewPostgresStore(databaseURL)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()

	migrationsDir := filepath.Clean(filepath.Join("..", "..", "migrations"))
	if err := store.ApplyMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	suffix := time.Now().UTC().Format("20060102150405")
	tenantID := "tenant-compat-" + suffix
	workspaceID := "workspace-compat-" + suffix
	projectID := "project-compat-" + suffix
	connectorID := "github-compat-" + suffix
	scopeCtx := db.WithScope(context.Background(), db.Scope{
		TenantID:    tenantID,
		WorkspaceID: workspaceID,
	})

	if err := store.UpsertOrganization(scopeCtx, db.TenancyOrganization{
		DisplayName: "Compatibility Tenant",
		Slug:        "compat-tenant-" + suffix,
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopeCtx, db.TenancyWorkspace{
		WorkspaceID: workspaceID,
		DisplayName: "Compatibility Workspace",
		Slug:        "compat-workspace-" + suffix,
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(scopeCtx, db.TenancyProject{
		WorkspaceID: workspaceID,
		ProjectID:   projectID,
		Name:        "Compatibility Project",
		Slug:        "compat-project-" + suffix,
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	rotatedAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	if err := store.UpsertTenancyConnector(scopeCtx, db.TenancyConnector{
		WorkspaceID:         workspaceID,
		ProjectID:           projectID,
		ConnectorID:         connectorID,
		Type:                domain.ConnectorTypeGitHub,
		DisplayName:         "Compatibility GitHub",
		Status:              domain.ConnectorStatusActive,
		SecretProvider:      "vault",
		SecretRefID:         "vault://github/" + suffix,
		SecretRefVersion:    "v2",
		SecretLastRotatedAt: &rotatedAt,
	}, db.TenancyConnectorState{
		WorkspaceID:  workspaceID,
		ProjectID:    projectID,
		ConnectorID:  connectorID,
		HealthStatus: "healthy",
		Metadata:     map[string]any{"source": "compat"},
	}); err != nil {
		t.Fatalf("upsert tenancy connector: %v", err)
	}

	policySetID := fmt.Sprintf("compat_policy_%s", suffix)
	if err := store.UpsertAuthzPolicySet(scopeCtx, db.AuthzPolicySet{
		PolicySetID: policySetID,
		DisplayName: "Compatibility Policy",
		CreatedBy:   "integration",
	}); err != nil {
		t.Fatalf("upsert authz policy set: %v", err)
	}
	version, err := store.CreateAuthzPolicyVersion(scopeCtx, db.AuthzPolicyVersion{
		PolicySetID: policySetID,
		Version:     1,
		Bundle:      `{"version":"1","rules":[]}`,
		CreatedBy:   "integration",
	})
	if err != nil {
		t.Fatalf("create authz policy version: %v", err)
	}
	if err := store.UpsertAuthzPolicyRollout(scopeCtx, db.AuthzPolicyRollout{
		PolicySetID:        policySetID,
		ActiveVersion:      &version.Version,
		CandidateVersion:   &version.Version,
		Mode:               db.AuthzPolicyRolloutModeEnforce,
		TenantAllowlist:    []string{tenantID},
		WorkspaceAllowlist: []string{workspaceID},
		CanaryPercentage:   100,
		ValidatedVersions:  []int{version.Version},
		UpdatedBy:          "integration",
	}); err != nil {
		t.Fatalf("upsert authz rollout: %v", err)
	}

	rollout, err := store.GetAuthzPolicyRollout(scopeCtx, policySetID)
	if err != nil {
		t.Fatalf("get authz rollout: %v", err)
	}
	if rollout.ActiveVersion == nil || *rollout.ActiveVersion != version.Version {
		t.Fatalf("unexpected rollout active version: %+v", rollout)
	}
	if len(rollout.ValidatedVersions) != 1 || rollout.ValidatedVersions[0] != version.Version {
		t.Fatalf("unexpected rollout validated versions: %+v", rollout.ValidatedVersions)
	}

	connectorWithState, err := store.GetTenancyConnector(scopeCtx, workspaceID, projectID, connectorID)
	if err != nil {
		t.Fatalf("get tenancy connector: %v", err)
	}
	if connectorWithState.Connector.SecretRefVersion != "v2" {
		t.Fatalf("unexpected connector secret ref version: %+v", connectorWithState.Connector)
	}
	if connectorWithState.Connector.SecretLastRotatedAt == nil {
		t.Fatalf("expected connector secret rotation timestamp: %+v", connectorWithState.Connector)
	}
}
