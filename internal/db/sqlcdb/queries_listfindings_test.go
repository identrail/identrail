package sqlcdb

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestQueriesListFindings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock new: %v", err)
	}
	defer db.Close()

	queries := New(db)
	createdAt := time.Date(2026, 5, 12, 22, 10, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"scan_id",
		"finding_id",
		"type",
		"severity",
		"title",
		"human_summary",
		"path",
		"evidence",
		"remediation",
		"created_at",
	}).AddRow(
		"scan-1",
		"finding-1",
		"risky_trust_policy",
		"high",
		"Risky trust policy",
		"summary",
		[]byte(`{"resource":"role"}`),
		[]byte(`{"statement":"Allow"}`),
		"tighten policy",
		createdAt,
	)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, COALESCE(remediation, ''), created_at
		 FROM findings
		 ORDER BY created_at DESC
		 LIMIT $1`)).
		WithArgs(25).
		WillReturnRows(rows)

	findings, err := queries.ListFindings(context.Background(), 25)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding row, got %d", len(findings))
	}
	if findings[0].FindingID != "finding-1" || findings[0].Severity != "high" {
		t.Fatalf("unexpected finding row: %+v", findings[0])
	}
	if findings[0].CreatedAt != createdAt {
		t.Fatalf("expected created_at %s, got %s", createdAt.Format(time.RFC3339Nano), findings[0].CreatedAt.Format(time.RFC3339Nano))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
