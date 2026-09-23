//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

type integrationScanner struct {
	findings []domain.Finding
}

func (s integrationScanner) Run(context.Context) (app.ScanResult, error) {
	now := time.Now().UTC()
	result := make([]domain.Finding, 0, len(s.findings))
	for _, finding := range s.findings {
		item := finding
		if item.CreatedAt.IsZero() {
			item.CreatedAt = now
		}
		result = append(result, item)
	}
	return app.ScanResult{Assets: 1, Findings: result, Completed: now}, nil
}

func TestPostgresIntegrationRunScanAndDiff(t *testing.T) {
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

	provider := "aws-integration-" + time.Now().UTC().Format("150405")
	svc := api.NewService(store, integrationScanner{findings: []domain.Finding{{ID: "persist", Severity: domain.SeverityHigh}, {ID: "resolved", Severity: domain.SeverityMedium}}}, provider)

	first, err := svc.RunScan(context.Background())
	if err != nil {
		t.Fatalf("run first scan: %v", err)
	}

	svc.Scanner = integrationScanner{findings: []domain.Finding{{ID: "persist", Severity: domain.SeverityHigh}, {ID: "added", Severity: domain.SeverityCritical}}}
	second, err := svc.RunScan(context.Background())
	if err != nil {
		t.Fatalf("run second scan: %v", err)
	}

	diff, err := svc.GetScanDiff(context.Background(), second.Scan.ID, 50)
	if err != nil {
		t.Fatalf("scan diff: %v", err)
	}
	if diff.PreviousScanID != first.Scan.ID {
		t.Fatalf("expected previous scan %s, got %s", first.Scan.ID, diff.PreviousScanID)
	}
	if diff.AddedCount == 0 || diff.ResolvedCount == 0 {
		t.Fatalf("expected non-empty added/resolved counts, got %+v", diff)
	}
}

func TestPostgresIntegrationHardDeletePreservesAmbiguousLegacySubjects(t *testing.T) {
	databaseURL := os.Getenv("IDENTRAIL_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set IDENTRAIL_INTEGRATION_DATABASE_URL to run integration tests")
	}
	store, err := db.NewPostgresStore(databaseURL)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.ApplyMigrations(context.Background(), filepath.Clean(filepath.Join("..", "..", "migrations"))); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	suffix := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	workspaceID := "workspace-hard-delete-" + suffix
	tenantID := "tenant-hard-delete-" + suffix
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: tenantID, WorkspaceID: workspaceID})
	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{TenantID: tenantID, DisplayName: tenantID, Slug: tenantID}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, db.TenancyWorkspace{TenantID: tenantID, WorkspaceID: workspaceID, DisplayName: workspaceID, Slug: workspaceID}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	target, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "hard-delete-target-" + suffix + "@example.com"})
	if err != nil {
		t.Fatalf("upsert target: %v", err)
	}
	other, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "hard-delete-other-" + suffix + "@example.com"})
	if err != nil {
		t.Fatalf("upsert other: %v", err)
	}
	for _, identity := range []db.UserIdentity{
		{UserID: target.ID, Provider: "provider-a", Subject: "target-hard-delete-subject"},
		{UserID: target.ID, Provider: "provider-a-alt", Subject: "shared-hard-delete-subject"},
		{UserID: other.ID, Provider: "provider-b", Subject: "shared-hard-delete-subject"},
	} {
		if _, err := store.UpsertUserIdentity(context.Background(), identity); err != nil {
			t.Fatalf("upsert identity: %v", err)
		}
	}
	for _, member := range []db.TenancyWorkspaceMember{
		{WorkspaceID: workspaceID, MemberID: "target-member", UserID: "target-hard-delete-subject", UserUUID: target.ID, Role: "viewer", Status: "active"},
		{WorkspaceID: workspaceID, MemberID: "other-member", UserID: "shared-hard-delete-subject", Role: "viewer", Status: "active"},
		{WorkspaceID: workspaceID, MemberID: "uuid-looking-orphan", UserID: target.ID, Role: "viewer", Status: "active"},
	} {
		if err := store.UpsertWorkspaceMember(ctx, member); err != nil {
			t.Fatalf("upsert member %s: %v", member.MemberID, err)
		}
	}
	now := time.Now().UTC()
	if _, err := store.SoftDeleteUser(context.Background(), target.ID, now); err != nil {
		t.Fatalf("soft delete target: %v", err)
	}
	if _, err := store.HardDeleteUser(context.Background(), target.ID, now.Add(db.UserDeletionGracePeriod+time.Hour)); err != nil {
		t.Fatalf("hard delete target: %v", err)
	}
	if _, err := store.GetWorkspaceMember(ctx, workspaceID, "target-member"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected UUID-bound target membership removed, got %v", err)
	}
	if _, err := store.GetWorkspaceMember(ctx, workspaceID, "other-member"); err != nil {
		t.Fatalf("expected shared legacy subject membership preserved, got %v", err)
	}
	if _, err := store.GetWorkspaceMember(ctx, workspaceID, "uuid-looking-orphan"); err != nil {
		t.Fatalf("expected unverified UUID-looking subject membership preserved, got %v", err)
	}
}
