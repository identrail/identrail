package api

import (
	"context"
	"errors"
	"fmt"
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

func TestEnqueueDueScanPoliciesSkipsWhenNoConnection(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	svc, _, ctx := newScanPolicySchedulerTestService(t, now, []string{"owner/repo-a"})
	delete(svc.githubConnections, githubConnectionKey("default", "default", "project-1"))

	store := svc.Store.(*db.MemoryStore)
	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	upsertTestScanPolicy(t, store, ctx, createdAt, 1)

	result, err := svc.EnqueueDueScanPolicies(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueScanPolicies returned error: %v", err)
	}
	if result.PoliciesClaimed != 1 || result.QueuedScans != 0 {
		t.Fatalf("unexpected scheduler result without connection: %+v", result)
	}
}

func TestEnqueueDueScanPoliciesDoesNotClaimWhileRepoScanDisabled(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	svc, store, ctx := newScanPolicySchedulerTestService(t, now, []string{"owner/repo-a"})
	svc.RepoScanEnabled = false

	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	upsertTestScanPolicy(t, store, ctx, createdAt, 1)

	result, err := svc.EnqueueDueScanPolicies(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueScanPolicies returned error: %v", err)
	}
	if result.PoliciesDue != 1 || result.PoliciesClaimed != 0 || result.SkippedScans != 1 || result.QueuedScans != 0 {
		t.Fatalf("unexpected scheduler result: %+v", result)
	}
	policy, err := store.GetTenancyScanPolicy(ctx, "default", "project-1", "default")
	if err != nil {
		t.Fatalf("GetTenancyScanPolicy returned error: %v", err)
	}
	if policy.LastScheduledAt != nil {
		t.Fatalf("expected last_scheduled_at to remain unset, got %v", policy.LastScheduledAt)
	}
}

func TestEnqueueDueScanPoliciesReturnsQueueErrorAfterClaim(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	svc, store, ctx := newScanPolicySchedulerTestService(t, now, []string{""})
	connection := svc.githubConnections[githubConnectionKey("default", "default", "project-1")]
	connection.SelectedRepositories = []string{""}
	svc.githubConnections[githubConnectionKey("default", "default", "project-1")] = connection

	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	upsertTestScanPolicy(t, store, ctx, createdAt, 1)

	if _, err := svc.EnqueueDueScanPolicies(ctx); err == nil || !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid repo scan request error, got %v", err)
	}

	policy, err := store.GetTenancyScanPolicy(ctx, "default", "project-1", "default")
	if err != nil {
		t.Fatalf("GetTenancyScanPolicy returned error: %v", err)
	}
	wantScheduledAt := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	if policy.LastScheduledAt == nil || !policy.LastScheduledAt.Equal(wantScheduledAt) {
		t.Fatalf("expected tick to be claimed as %s, got %v", wantScheduledAt, policy.LastScheduledAt)
	}

	count, err := store.CountQueuedRepoScans(ctx)
	if err != nil {
		t.Fatalf("CountQueuedRepoScans returned error: %v", err)
	}
	if count != 0 {
		t.Fatalf("queued repo scans = %d, want 0", count)
	}
}

func TestEnqueueDueScanPoliciesSkipsInvalidCronPolicyAndProcessesOthers(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	svc, store, ctx := newScanPolicySchedulerTestService(t, now, []string{"owner/repo-a"})

	upsertNamedTestScanPolicy(t, store, ctx, "invalid-cron", "Invalid policy", "not-a-cron", now.Add(-time.Hour), 1)
	upsertNamedTestScanPolicy(t, store, ctx, "valid", "Every minute", "* * * * *", now.Add(-time.Hour), 1)

	result, err := svc.EnqueueDueScanPolicies(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueScanPolicies returned error: %v", err)
	}
	if result.PoliciesChecked != 2 || result.PoliciesDue != 1 || result.PoliciesClaimed != 1 || result.SkippedScans != 1 {
		t.Fatalf("unexpected scheduler result: %+v", result)
	}

	count, err := store.CountQueuedRepoScans(ctx)
	if err != nil {
		t.Fatalf("CountQueuedRepoScans returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("queued repo scans = %d, want 1", count)
	}
}

func TestEnqueueDueScanPolicyCountsInProgressRepoTowardConcurrency(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	svc, store, ctx := newScanPolicySchedulerTestService(t, now, []string{"owner/repo-a", "owner/repo-b"})
	if _, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{Repository: "owner/repo-a"}); err != nil {
		t.Fatalf("prequeue repo scan: %v", err)
	}

	upsertTestScanPolicy(t, store, ctx, now.Add(-time.Hour), 1)

	result, err := svc.EnqueueDueScanPolicies(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueScanPolicies returned error: %v", err)
	}
	if result.PoliciesDue != 1 || result.PoliciesClaimed != 1 || result.SkippedScans != 1 || result.QueuedScans != 0 {
		t.Fatalf("unexpected scheduler result: %+v", result)
	}

	count, err := store.CountQueuedRepoScans(ctx)
	if err != nil {
		t.Fatalf("CountQueuedRepoScans returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("queued repo scans = %d, want 1", count)
	}
}

func TestDueScanPolicyTickHandlesNoHistoryAndInvalidCron(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	policy := db.TenancyScanPolicy{
		PolicyID: "default",
		Cron:     "*/5 * * * *",
	}
	tick, due, err := dueScanPolicyTick(policy, now)
	if err != nil {
		t.Fatalf("dueScanPolicyTick returned error: %v", err)
	}
	if !due {
		t.Fatal("expected policy to be due")
	}
	wantTick := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	if !tick.Equal(wantTick) {
		t.Fatalf("tick = %s, want %s", tick, wantTick)
	}

	_, _, err = dueScanPolicyTick(db.TenancyScanPolicy{PolicyID: "broken", Cron: "not-a-cron"}, now)
	if err == nil {
		t.Fatal("expected invalid cron to return error")
	}
}

func TestIsExpectedScheduledRepoSkip(t *testing.T) {
	if !isExpectedScheduledRepoSkip(ErrRepoScanInProgress) {
		t.Fatal("expected ErrRepoScanInProgress to be treated as skip")
	}
	if !isExpectedScheduledRepoSkip(ErrRepoScanQueueFull) {
		t.Fatal("expected ErrRepoScanQueueFull to be treated as skip")
	}
	if !isExpectedScheduledRepoSkip(errors.New("github app not connected")) {
		t.Fatal("expected not-connected error to be treated as skip")
	}
	if isExpectedScheduledRepoSkip(ErrInvalidRepoScanRequest) {
		t.Fatal("expected invalid repo scan request to be treated as failure")
	}
	if isExpectedScheduledRepoSkip(errors.New("unrelated failure")) {
		t.Fatal("expected unrelated error to be treated as non-skip")
	}
}

func TestEnqueueDueScanPoliciesPagesBeyondFirstBatch(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 1, 0, 0, time.UTC)
	svc, store, ctx := newScanPolicySchedulerTestService(t, now, []string{"owner/repo-a"})

	baseCreatedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 500; i++ {
		upsertNamedTestScanPolicy(t, store, ctx, fmt.Sprintf("weekly-%03d", i), fmt.Sprintf("Weekly %03d", i), "0 0 1 1 *", baseCreatedAt.Add(time.Duration(i)*time.Minute), 1)
	}
	upsertNamedTestScanPolicy(t, store, ctx, "minutely-501", "Minutely 501", "* * * * *", baseCreatedAt.Add(600*time.Minute), 1)

	result, err := svc.EnqueueDueScanPolicies(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueScanPolicies returned error: %v", err)
	}
	if result.PoliciesChecked != 501 {
		t.Fatalf("policies checked = %d, want 501", result.PoliciesChecked)
	}
	if result.QueuedScans != 1 {
		t.Fatalf("queued scans = %d, want 1", result.QueuedScans)
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
	upsertNamedTestScanPolicy(t, store, ctx, "default", "Default scheduled policy", "*/5 * * * *", createdAt, maxConcurrent)
}

func upsertNamedTestScanPolicy(t *testing.T, store *db.MemoryStore, ctx context.Context, policyID string, name string, cron string, createdAt time.Time, maxConcurrent int) {
	t.Helper()
	err := store.UpsertTenancyScanPolicy(ctx, db.TenancyScanPolicy{
		WorkspaceID:        "default",
		ProjectID:          "project-1",
		PolicyID:           policyID,
		Name:               name,
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeScheduled,
		Cron:               cron,
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
