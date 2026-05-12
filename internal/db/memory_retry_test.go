package db

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStoreScheduleScanRetryAndDeadLetterScan(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	createdAt := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)

	record, err := store.CreateQueuedScan(ctx, "aws", createdAt)
	if err != nil {
		t.Fatalf("create queued scan: %v", err)
	}

	nextRetryAt := createdAt.Add(2 * time.Minute)
	if err := store.ScheduleScanRetry(ctx, record.ID, createdAt.Add(time.Minute), 1, 3, "provider_transient", "temporary timeout", nextRetryAt); err != nil {
		t.Fatalf("schedule scan retry: %v", err)
	}

	retried, err := store.GetScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get retried scan: %v", err)
	}
	if retried.Status != "queued" {
		t.Fatalf("expected queued status after retry scheduling, got %q", retried.Status)
	}
	if retried.RetryCount != 1 || retried.MaxRetryCount != 3 {
		t.Fatalf("unexpected retry metadata: %+v", retried)
	}
	if retried.FailureCategory != "provider_transient" {
		t.Fatalf("expected failure category to be preserved, got %q", retried.FailureCategory)
	}
	if retried.NextRetryAt == nil || !retried.NextRetryAt.Equal(nextRetryAt) {
		t.Fatalf("expected next retry at %s, got %+v", nextRetryAt.Format(time.RFC3339Nano), retried.NextRetryAt)
	}
	if retried.DeadLettered || retried.DeadLetteredAt != nil {
		t.Fatalf("did not expect retry-scheduled scan to be dead-lettered: %+v", retried)
	}

	finishedAt := createdAt.Add(5 * time.Minute)
	if err := store.DeadLetterScan(ctx, record.ID, finishedAt, 3, 3, 12, 2, "provider_auth", "invalid credentials"); err != nil {
		t.Fatalf("dead letter scan: %v", err)
	}

	deadLettered, err := store.GetScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get dead-lettered scan: %v", err)
	}
	if deadLettered.Status != "failed" {
		t.Fatalf("expected failed status after dead-lettering, got %q", deadLettered.Status)
	}
	if !deadLettered.DeadLettered || deadLettered.DeadLetteredAt == nil {
		t.Fatalf("expected dead-letter metadata to be set: %+v", deadLettered)
	}
	if !deadLettered.DeadLetteredAt.Equal(finishedAt) {
		t.Fatalf("expected dead-letter time %s, got %s", finishedAt.Format(time.RFC3339Nano), deadLettered.DeadLetteredAt.Format(time.RFC3339Nano))
	}
	if deadLettered.NextRetryAt != nil {
		t.Fatalf("expected next retry to be cleared after dead-lettering, got %+v", deadLettered.NextRetryAt)
	}
	if deadLettered.FailureCategory != "provider_auth" {
		t.Fatalf("expected dead-letter failure category provider_auth, got %q", deadLettered.FailureCategory)
	}
	if deadLettered.AssetCount != 12 || deadLettered.FindingCount != 2 {
		t.Fatalf("expected dead-letter counts to be preserved, got assets=%d findings=%d", deadLettered.AssetCount, deadLettered.FindingCount)
	}
	if deadLettered.ErrorMessage != "invalid credentials" {
		t.Fatalf("expected dead-letter error message to be preserved, got %q", deadLettered.ErrorMessage)
	}
}
