package userexport_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/userexport"
)

func TestGCRunnerPurgesExpiredBundles(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "gc@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now.Add(-10 * 24 * time.Hour),
		Status:      db.UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	runner := &userexport.Runner{Source: store, Store: store, Storage: storage, Now: func() time.Time { return now.Add(-10 * 24 * time.Hour) }}
	if _, err := runner.Run(context.Background(), job); err != nil {
		t.Fatalf("run: %v", err)
	}

	gc := &userexport.GCRunner{Store: store, Storage: storage, Now: func() time.Time { return now }}
	result, err := gc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.Purged != 1 {
		t.Fatalf("expected 1 purged, got %+v", result)
	}
	saved, err := store.GetUserDataExportByID(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if saved.Status != db.UserDataExportStatusExpired {
		t.Fatalf("expected expired, got %s", saved.Status)
	}
	if saved.PurgedAt == nil {
		t.Fatal("expected purged_at to be stamped")
	}
}

func TestGCRunnerSkipsRetainedBundles(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "retained@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	runner := &userexport.Runner{Source: store, Store: store, Storage: storage, Now: func() time.Time { return now }}
	if _, err := runner.Run(context.Background(), job); err != nil {
		t.Fatalf("run: %v", err)
	}
	gc := &userexport.GCRunner{Store: store, Storage: storage, Now: func() time.Time { return now }}
	result, err := gc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.Purged != 0 {
		t.Fatalf("expected 0 purged for fresh job, got %+v", result)
	}
}

func TestGCRunnerRejectsInvalidState(t *testing.T) {
	var nilRunner *userexport.GCRunner
	if _, err := nilRunner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected nil runner error")
	}

	store := db.NewMemoryStore()
	if _, err := (&userexport.GCRunner{Storage: &fakeStorage{}}).RunOnce(context.Background()); err == nil {
		t.Fatal("expected missing dependency error")
	}
	if _, err := (&userexport.GCRunner{Store: store}).RunOnce(context.Background()); err == nil {
		t.Fatal("expected missing storage dependency error")
	}
}

func TestGCRunnerSkipsRowsWhenPurgeListFails(t *testing.T) {
	gc := &userexport.GCRunner{
		Store:   &failingListPurgeStore{err: errors.New("list failed")},
		Storage: &fakeStorage{},
	}
	if _, err := gc.RunOnce(context.Background()); err == nil {
		t.Fatal("expected list error")
	}
}

func TestGCRunnerHandlesDeleteErrors(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "gc-delete-error@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now.Add(-10 * 24 * time.Hour),
		Status:      db.UserDataExportStatusReady,
		PurgeAfter:  &now,
		BundlePath:  "already/expired.zip",
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	result, err := (&userexport.GCRunner{
		Store:   &gcJobStore{store: store, returnPending: []db.UserDataExport{job}},
		Storage: &failingStorage{err: errors.New("delete failed")},
	}).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run gc: %v", err)
	}
	if result.Examined != 1 || result.Errors != 1 || result.Purged != 0 {
		t.Fatalf("unexpected gc result: %+v", result)
	}
}

func TestGCRunnerHandlesMarkErrors(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "gc-mark-error@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now.Add(-10 * 24 * time.Hour),
		Status:      db.UserDataExportStatusReady,
		PurgeAfter:  &now,
		BundlePath:  "already/expired.zip",
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	if err := storage.Delete(userexport.StorageKey(job)); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	result, err := (&userexport.GCRunner{
		Store:   &failingMarkStore{returnPending: []db.UserDataExport{job}, err: errors.New("mark failed")},
		Storage: storage,
	}).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run gc: %v", err)
	}
	if result.Examined != 1 || result.Errors != 1 || result.Purged != 0 {
		t.Fatalf("unexpected gc result: %+v", result)
	}
}

type gcJobStore struct {
	store         *db.MemoryStore
	returnPending []db.UserDataExport
}

func (s *gcJobStore) ListUserDataExportsPendingPurge(_ context.Context, _ time.Time, _ int) ([]db.UserDataExport, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if len(s.returnPending) > 0 {
		return s.returnPending, nil
	}
	return s.store.ListUserDataExportsPendingPurge(context.Background(), time.Time{}, 10)
}

func (s *gcJobStore) MarkUserDataExportPurged(_ context.Context, jobID string, _ time.Time) (db.UserDataExport, error) {
	return s.store.MarkUserDataExportPurged(context.Background(), jobID, time.Now())
}

type failingMarkStore struct {
	returnPending []db.UserDataExport
	err           error
}

func (f *failingMarkStore) ListUserDataExportsPendingPurge(ctx context.Context, now time.Time, limit int) ([]db.UserDataExport, error) {
	if f == nil {
		return nil, errors.New("store is nil")
	}
	if len(f.returnPending) > limit && limit > 0 {
		return append([]db.UserDataExport(nil), f.returnPending[:limit]...), nil
	}
	return append([]db.UserDataExport(nil), f.returnPending...), nil
}

func (f *failingMarkStore) MarkUserDataExportPurged(context.Context, string, time.Time) (db.UserDataExport, error) {
	return db.UserDataExport{}, f.err
}

type failingListPurgeStore struct {
	err error
}

func (s *failingListPurgeStore) ListUserDataExportsPendingPurge(context.Context, time.Time, int) ([]db.UserDataExport, error) {
	return nil, s.err
}

func (s *failingListPurgeStore) MarkUserDataExportPurged(context.Context, string, time.Time) (db.UserDataExport, error) {
	return db.UserDataExport{}, nil
}

type failingStorage struct {
	err error
}

func (s *failingStorage) Put(string, io.Reader) (string, error) {
	return "", s.err
}

func (s *failingStorage) Open(string) (io.ReadCloser, error) {
	return nil, s.err
}

func (s *failingStorage) Delete(string) error {
	return s.err
}

type fakeStorage struct{}

func (s *fakeStorage) Put(string, io.Reader) (string, error) {
	return "", nil
}

func (s *fakeStorage) Open(string) (io.ReadCloser, error) {
	return nil, nil
}

func (s *fakeStorage) Delete(string) error {
	return nil
}
