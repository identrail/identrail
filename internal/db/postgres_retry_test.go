package db

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresStoreScheduleScanRetry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock new: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	queuedAt := time.Date(2026, 5, 12, 22, 30, 0, 0, time.UTC)
	nextRetryAt := queuedAt.Add(2 * time.Minute)

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE scans
		 SET status = 'queued',
		     started_at = $2,
		     finished_at = NULL,
		     error_message = $3,
		     retry_count = $4,
		     max_retry_count = $5,
		     failure_category = NULLIF($6, ''),
		     next_retry_at = $7,
		     dead_lettered = FALSE,
		     dead_lettered_at = NULL
		 WHERE id = $1
		   AND tenant_id = $8
		   AND workspace_id = $9`)).
		WithArgs(
			"scan-1",
			queuedAt.UTC(),
			"temporary timeout",
			1,
			3,
			"provider_transient",
			nextRetryAt.UTC(),
			"tenant-a",
			"workspace-a",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.ScheduleScanRetry(ctx, "scan-1", queuedAt, 1, 3, "provider_transient", "temporary timeout", nextRetryAt); err != nil {
		t.Fatalf("schedule scan retry: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestPostgresStoreDeadLetterScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock new: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	finishedAt := time.Date(2026, 5, 12, 22, 35, 0, 0, time.UTC)

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE scans
		 SET status = 'failed',
		     finished_at = $2,
		     error_message = $3,
		     retry_count = $4,
		     max_retry_count = $5,
		     asset_count = $6,
		     finding_count = $7,
		     failure_category = NULLIF($8, ''),
		     next_retry_at = NULL,
		     dead_lettered = TRUE,
		     dead_lettered_at = $2
		 WHERE id = $1
		   AND tenant_id = $9
		   AND workspace_id = $10`)).
		WithArgs(
			"scan-1",
			finishedAt.UTC(),
			"invalid credentials",
			3,
			3,
			12,
			2,
			"provider_auth",
			"tenant-a",
			"workspace-a",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.DeadLetterScan(ctx, "scan-1", finishedAt, 3, 3, 12, 2, "provider_auth", "invalid credentials"); err != nil {
		t.Fatalf("dead letter scan: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
