//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
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
