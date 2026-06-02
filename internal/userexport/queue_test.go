package userexport_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/userexport"
)

func TestQueueRunnerDrainsQueuedJobs(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "queue@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	if _, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	}); err != nil {
		t.Fatalf("create job: %v", err)
	}

	queue := &userexport.QueueRunner{
		Store: store,
		Runner: &userexport.Runner{
			Source:  store,
			Store:   store,
			Storage: storage,
			Now:     func() time.Time { return now },
		},
		Now: func() time.Time { return now },
	}
	result, err := queue.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run queue: %v", err)
	}
	if result.Examined != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected queue result: %+v", result)
	}

	result, err = queue.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run empty queue: %v", err)
	}
	if result.Examined != 0 || result.Succeeded != 0 || result.Failed != 0 {
		t.Fatalf("empty queue should not process jobs: %+v", result)
	}
}

func TestQueueRunnerCountsFailedJobsAndContinues(t *testing.T) {
	queueStore := db.NewMemoryStore()
	sourceStore := db.NewMemoryStore()
	user := seedUserWithMembership(t, queueStore, "queue-failure@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	if _, err := queueStore.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	}); err != nil {
		t.Fatalf("create job: %v", err)
	}

	queue := &userexport.QueueRunner{
		Store: queueStore,
		Runner: &userexport.Runner{
			Source:  sourceStore,
			Store:   queueStore,
			Storage: storage,
			Now:     func() time.Time { return now },
		},
		BatchSize: 1,
		Now:       func() time.Time { return now },
	}
	result, err := queue.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run queue: %v", err)
	}
	if result.Examined != 1 || result.Succeeded != 0 || result.Failed != 1 {
		t.Fatalf("expected failed job to be counted, got %+v", result)
	}
	saved, err := queueStore.GetUserDataExportByID(context.Background(), resultJobID(t, queueStore, user.ID))
	if err != nil {
		t.Fatalf("get failed job: %v", err)
	}
	if saved.Status != db.UserDataExportStatusFailed {
		t.Fatalf("failed run should mark job failed, got %+v", saved)
	}
}

func TestQueueRunnerPropagatesStaleFailure(t *testing.T) {
	const staleFailure = "stale failed"
	queue := &userexport.QueueRunner{
		Store: &fakeQueueStore{failStaleErr: errors.New(staleFailure)},
		Runner: &userexport.Runner{
			Store:   db.NewMemoryStore(),
			Storage: &testStorage{},
		},
	}
	_, err := queue.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected stale reclaim failure")
	}
	if !strings.Contains(err.Error(), staleFailure) {
		t.Fatalf("expected stale reclaim failure, got %v", err)
	}
}

func TestQueueRunnerPropagatesClaimFailure(t *testing.T) {
	const claimFailure = "claim failed"
	queue := &userexport.QueueRunner{
		Store: &fakeQueueStore{claimErr: errors.New(claimFailure)},
		Runner: &userexport.Runner{
			Store:   db.NewMemoryStore(),
			Storage: &testStorage{},
		},
	}
	_, err := queue.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected claim failure")
	}
	if !strings.Contains(err.Error(), claimFailure) {
		t.Fatalf("expected claim failure, got %v", err)
	}
}

func TestQueueRunnerDeletesStaleBundlesBestEffort(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "queue-stale-delete-error@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create stale job: %v", err)
	}
	claimed, err := store.ClaimQueuedUserDataExport(context.Background(), job.ID, now.Add(-45*time.Minute))
	if err != nil {
		t.Fatalf("claim stale job: %v", err)
	}

	storage := &testStorage{
		stored:    map[string][]byte{userexport.StorageKey(claimed): []byte("stale")},
		deleteErr: errors.New("delete failed"),
	}

	queue := &userexport.QueueRunner{
		Store: store,
		Runner: &userexport.Runner{
			Source:  store,
			Store:   store,
			Storage: storage,
			Now:     func() time.Time { return now },
		},
		Now: func() time.Time { return now },
	}
	result, err := queue.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run stale queue: %v", err)
	}
	if result.StaleFailed != 1 || result.Examined != 0 {
		t.Fatalf("unexpected queue result: %+v", result)
	}
	if _, exists := storage.stored[userexport.StorageKey(claimed)]; !exists {
		t.Fatal("expected stale bundle to remain for retry when delete fails")
	}
	updated, err := store.GetUserDataExportByID(context.Background(), claimed.ID)
	if err != nil {
		t.Fatalf("get stale job: %v", err)
	}
	if updated.Status != db.UserDataExportStatusFailed {
		t.Fatalf("expected failed stale job, got %s", updated.Status)
	}
}

func TestQueueRunnerReclaimsStaleRunningJobs(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "queue-stale@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage := &testStorage{stored: map[string][]byte{}}
	storage.stored = map[string][]byte{}
	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create stale job: %v", err)
	}
	claimed, err := store.ClaimQueuedUserDataExport(context.Background(), job.ID, now.Add(-45*time.Minute))
	if err != nil {
		t.Fatalf("claim stale job: %v", err)
	}
	storage.stored[userexport.StorageKey(claimed)] = []byte("stale")
	queue := &userexport.QueueRunner{
		Store: store,
		Runner: &userexport.Runner{
			Source:  store,
			Store:   store,
			Storage: storage,
			Now:     func() time.Time { return now },
		},
		Now: func() time.Time { return now },
	}
	result, err := queue.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run stale queue: %v", err)
	}
	if result.StaleFailed != 1 || result.Examined != 0 {
		t.Fatalf("unexpected queue result: %+v", result)
	}
	if _, exists := storage.stored[userexport.StorageKey(claimed)]; exists {
		t.Fatal("expected stale bundle to be deleted")
	}
	updated, err := store.GetUserDataExportByID(context.Background(), claimed.ID)
	if err != nil {
		t.Fatalf("get stale job: %v", err)
	}
	if updated.Status != db.UserDataExportStatusFailed {
		t.Fatalf("expected failed stale job, got %s", updated.Status)
	}
}

type testStorage struct {
	stored    map[string][]byte
	deleteErr error
}

func (s *testStorage) Put(_ context.Context, key string, r io.Reader) (string, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	s.stored[key] = contents
	return key, nil
}

func (s *testStorage) Open(_ context.Context, key string) (io.ReadCloser, error) {
	contents, ok := s.stored[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(contents)), nil
}

func (s *testStorage) Delete(_ context.Context, key string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.stored, key)
	return nil
}

type fakeQueueStore struct {
	failStaleErr error
	claimErr     error
}

func (f *fakeQueueStore) ClaimNextQueuedUserDataExport(_ context.Context, _ time.Time) (db.UserDataExport, error) {
	if f.claimErr != nil {
		return db.UserDataExport{}, f.claimErr
	}
	return db.UserDataExport{}, db.ErrNotFound
}

func (f *fakeQueueStore) FailStaleRunningUserDataExports(_ context.Context, _ time.Time, _ time.Time, _ int, _ string) ([]db.UserDataExport, error) {
	return nil, f.failStaleErr
}

func TestQueueRunnerPropagatesCanceledRun(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "queue-canceled@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	if _, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	}); err != nil {
		t.Fatalf("create job: %v", err)
	}
	queue := &userexport.QueueRunner{
		Store: store,
		Runner: &userexport.Runner{
			Source:  canceledSource{source: store},
			Store:   store,
			Storage: storage,
			Now:     func() time.Time { return now },
		},
		Now: func() time.Time { return now },
	}
	result, err := queue.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected canceled run error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled run error, got %v", err)
	}
	if result.Examined != 1 || result.Failed != 0 || result.Succeeded != 0 {
		t.Fatalf("expected canceled run to be uncounted but examined: %+v", result)
	}
}

func TestQueueRunnerRejectsInvalidStateAndCanceledContext(t *testing.T) {
	var nilQueue *userexport.QueueRunner
	if _, err := nilQueue.RunOnce(context.Background()); err == nil {
		t.Fatal("expected nil queue error")
	}
	if _, err := (&userexport.QueueRunner{}).RunOnce(context.Background()); err == nil {
		t.Fatal("expected missing dependency error")
	}

	store := db.NewMemoryStore()
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = (&userexport.QueueRunner{
		Store: store,
		Runner: &userexport.Runner{
			Source:  store,
			Store:   store,
			Storage: storage,
		},
	}).RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

type canceledSource struct {
	source userexport.Source
}

func (s canceledSource) GetUser(ctx context.Context, userID string) (db.User, error) {
	return db.User{}, context.Canceled
}

func (s canceledSource) ListUserSessionHistory(ctx context.Context, userID string, _ int) ([]db.Session, error) {
	return s.source.ListUserSessionHistory(ctx, userID, 0)
}

func (s canceledSource) ListUserSessions(ctx context.Context, userID string, _ time.Time, limit int) ([]db.Session, error) {
	return s.source.ListUserSessionHistory(ctx, userID, limit)
}

func (s canceledSource) ListWorkspaceMembershipsByUserUUID(ctx context.Context, userUUID string) ([]db.TenancyWorkspaceMember, error) {
	return s.source.ListWorkspaceMembershipsByUserUUID(ctx, userUUID)
}

func (s canceledSource) GetOnboardingState(ctx context.Context, userID string) (db.OnboardingState, error) {
	return s.source.GetOnboardingState(ctx, userID)
}

func resultJobID(t *testing.T, store *db.MemoryStore, userID string) string {
	t.Helper()
	items, err := store.ListUserDataExports(context.Background(), userID, 1)
	if err != nil {
		t.Fatalf("list exports: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one export, got %+v", items)
	}
	return items[0].ID
}
