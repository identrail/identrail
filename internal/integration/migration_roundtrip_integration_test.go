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

	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type roundtripScanner struct{}

func (roundtripScanner) Run(context.Context) (app.ScanResult, error) {
	now := time.Now().UTC()
	return app.ScanResult{
		Assets: 1,
		Bundle: providers.NormalizedBundle{},
		Findings: []domain.Finding{
			{
				ID:        "roundtrip-finding",
				Type:      domain.FindingOwnerless,
				Severity:  domain.SeverityHigh,
				Title:     "Ownerless identity",
				CreatedAt: now,
			},
		},
		Completed: now,
	}, nil
}

func TestPostgresIntegrationMigrationRoundTrip(t *testing.T) {
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
		t.Fatalf("apply up migrations: %v", err)
	}
	if err := store.ApplyDownMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("apply down migrations: %v", err)
	}
	if err := store.ApplyMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("re-apply up migrations: %v", err)
	}

	provider := "aws-roundtrip-" + time.Now().UTC().Format("150405")
	svc := api.NewService(store, roundtripScanner{}, provider)
	result, err := svc.RunScan(context.Background())
	if err != nil {
		t.Fatalf("run scan after migration roundtrip: %v", err)
	}
	if result.Scan.ID == "" || result.FindingCount != 1 {
		t.Fatalf("unexpected scan result after migration roundtrip: %+v", result)
	}
}

func TestPostgresIntegrationMigrationRoundTripAuthzRolloutAndConnectorSecrets(t *testing.T) {
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
		t.Fatalf("apply up migrations: %v", err)
	}
	if err := store.ApplyDownMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("apply down migrations: %v", err)
	}
	if err := store.ApplyMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("re-apply up migrations: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := "tenant-rt-" + suffix
	workspaceID := "workspace-rt-" + suffix
	projectID := "project-rt-" + suffix
	connectorID := "github-rt-" + suffix
	scopeCtx := db.WithScope(context.Background(), db.Scope{
		TenantID:    tenantID,
		WorkspaceID: workspaceID,
	})

	if err := store.UpsertOrganization(scopeCtx, db.TenancyOrganization{
		DisplayName: "Roundtrip Tenant",
		Slug:        "roundtrip-tenant-" + suffix,
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopeCtx, db.TenancyWorkspace{
		WorkspaceID: workspaceID,
		DisplayName: "Roundtrip Workspace",
		Slug:        "roundtrip-workspace-" + suffix,
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(scopeCtx, db.TenancyProject{
		WorkspaceID: workspaceID,
		ProjectID:   projectID,
		Name:        "Roundtrip Project",
		Slug:        "roundtrip-project-" + suffix,
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	rotatedAt := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	if err := store.UpsertTenancyConnector(scopeCtx, db.TenancyConnector{
		WorkspaceID:         workspaceID,
		ProjectID:           projectID,
		ConnectorID:         connectorID,
		Type:                domain.ConnectorTypeGitHub,
		DisplayName:         "Roundtrip GitHub",
		Status:              domain.ConnectorStatusActive,
		SecretProvider:      "vault",
		SecretRefID:         "vault://github/" + suffix,
		SecretRefVersion:    "v1",
		SecretLastRotatedAt: &rotatedAt,
	}, db.TenancyConnectorState{
		WorkspaceID:  workspaceID,
		ProjectID:    projectID,
		ConnectorID:  connectorID,
		HealthStatus: "healthy",
		Metadata:     map[string]any{"source": "integration"},
	}); err != nil {
		t.Fatalf("upsert tenancy connector: %v", err)
	}

	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()

	rotationDueAt := rotatedAt.Add(24 * time.Hour)
	if _, err := sqlDB.ExecContext(
		scopeCtx,
		`INSERT INTO tenancy_connector_secret_envelopes (
			tenant_id, workspace_id, project_id, connector_id, secret_name,
			envelope_version, algorithm, key_version, nonce, ciphertext, secret_ref_id, rotated_at, rotation_due_at
		) VALUES ($1, $2, $3, $4, $5, 1, 'AES-256-GCM', 'kms-v1', $6, $7, $8, $9, $10)`,
		tenantID,
		workspaceID,
		projectID,
		connectorID,
		"webhook_secret",
		[]byte("123456789012"),
		[]byte("encrypted-bytes"),
		"vault://github/"+suffix,
		rotatedAt,
		rotationDueAt,
	); err != nil {
		t.Fatalf("insert connector secret envelope row: %v", err)
	}

	var gotAlgorithm, gotKeyVersion string
	var gotRotationDueAt time.Time
	if err := sqlDB.QueryRowContext(
		scopeCtx,
		`SELECT algorithm, key_version, rotation_due_at
		 FROM tenancy_connector_secret_envelopes
		 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4 AND secret_name = $5`,
		tenantID,
		workspaceID,
		projectID,
		connectorID,
		"webhook_secret",
	).Scan(&gotAlgorithm, &gotKeyVersion, &gotRotationDueAt); err != nil {
		t.Fatalf("read connector secret envelope row: %v", err)
	}
	if gotAlgorithm != "AES-256-GCM" || gotKeyVersion != "kms-v1" {
		t.Fatalf("unexpected connector secret envelope metadata: algorithm=%s keyVersion=%s", gotAlgorithm, gotKeyVersion)
	}
	if !gotRotationDueAt.Equal(rotationDueAt) {
		t.Fatalf("unexpected rotation due at: got %s want %s", gotRotationDueAt, rotationDueAt)
	}

	policySetID := fmt.Sprintf("core_policy_%s", suffix)
	if err := store.UpsertAuthzPolicySet(scopeCtx, db.AuthzPolicySet{
		PolicySetID: policySetID,
		DisplayName: "Core Policy",
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
		t.Fatalf("upsert authz policy rollout: %v", err)
	}

	rollout, err := store.GetAuthzPolicyRollout(scopeCtx, policySetID)
	if err != nil {
		t.Fatalf("get authz policy rollout: %v", err)
	}
	if rollout.ActiveVersion == nil || *rollout.ActiveVersion != version.Version {
		t.Fatalf("unexpected authz rollout active version: %+v", rollout)
	}
	if rollout.Mode != db.AuthzPolicyRolloutModeEnforce {
		t.Fatalf("unexpected authz rollout mode: %s", rollout.Mode)
	}
}
