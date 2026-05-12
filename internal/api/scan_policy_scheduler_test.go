package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func TestEnqueueDueScanPoliciesRecoversLatestMissedTick(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 17, 30, 0, time.UTC)
	svc, store, ctx := newScanPolicySchedulerTestService(t, now, []string{"owner/repo-a", "owner/repo-b"})
	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	upsertTestScanPolicy(t, store, ctx, createdAt, 2)

	result, err := svc.EnqueueDueScanPolicies(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueScanPolicies returned error: %v", err)
	}
	if result.PoliciesChecked != 1 || result.PoliciesDue != 1 || result.PoliciesClaimed != 1 || result.QueuedScans != 2 {
		t.Fatalf("unexpected scheduler result: %+v", result)
	}
	count, err := store.CountQueuedRepoScans(ctx)
	if err != nil {
		t.Fatalf("CountQueuedRepoScans returned error: %v", err)
	}
	if count != 2 {
		t.Fatalf("queued repo scans = %d, want 2", count)
	}

	policy, err := store.GetTenancyScanPolicy(ctx, "default", "project-1", "default")
	if err != nil {
		t.Fatalf("GetTenancyScanPolicy returned error: %v", err)
	}
	wantScheduledAt := time.Date(2026, 5, 12, 12, 15, 0, 0, time.UTC)
	if policy.LastScheduledAt == nil || !policy.LastScheduledAt.Equal(wantScheduledAt) {
		t.Fatalf("last scheduled tick = %v, want %s", policy.LastScheduledAt, wantScheduledAt)
	}

	second, err := svc.EnqueueDueScanPolicies(ctx)
	if err != nil {
		t.Fatalf("second EnqueueDueScanPolicies returned error: %v", err)
	}
	if second.PoliciesClaimed != 0 || second.QueuedScans != 0 {
		t.Fatalf("duplicate scheduler pass enqueued work: %+v", second)
	}
}

func TestEnqueueDueScanPoliciesDoesNotDuplicateConcurrentWorkers(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	svc, store, ctx := newScanPolicySchedulerTestService(t, now, []string{"owner/repo-a"})
	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	upsertTestScanPolicy(t, store, ctx, createdAt, 1)

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.EnqueueDueScanPolicies(context.Background())
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent scheduler returned error: %v", err)
		}
	}

	count, err := store.CountQueuedRepoScans(ctx)
	if err != nil {
		t.Fatalf("CountQueuedRepoScans returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("queued repo scans = %d, want 1", count)
	}
}

func newScanPolicySchedulerTestService(t *testing.T, now time.Time, repositories []string) (*Service, *db.MemoryStore, context.Context) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.RepoScanEnabled = true
	svc.RepoScanAllowedTargets = []string{"*"}
	svc.RepoQueueMaxPending = 100
	svc.githubConnections[githubConnectionKey("default", "default", "project-1")] = githubProjectConnection{
		TenantID:             "default",
		WorkspaceID:          "default",
		ProjectID:            "project-1",
		AccountLogin:         "identrail",
		InstallationID:       1,
		TokenReference:       "secret://github/token",
		SelectedRepositories: repositories,
		CreatedAt:            now.Add(-time.Hour),
		UpdatedAt:            now.Add(-time.Hour),
	}
	return svc, store, ctx
}

func upsertTestScanPolicy(t *testing.T, store *db.MemoryStore, ctx context.Context, createdAt time.Time, maxConcurrent int) {
	t.Helper()
	err := store.UpsertTenancyScanPolicy(ctx, db.TenancyScanPolicy{
		WorkspaceID:        "default",
		ProjectID:          "project-1",
		PolicyID:           "default",
		Name:               "Default scheduled policy",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeScheduled,
		Cron:               "*/5 * * * *",
		MaxConcurrentScans: maxConcurrent,
		HistoryLimit:       20,
		MaxFindings:        10,
		CreatedAt:          createdAt,
		UpdatedAt:          createdAt,
	})
	if err != nil {
		t.Fatalf("UpsertTenancyScanPolicy returned error: %v", err)
	}
}
