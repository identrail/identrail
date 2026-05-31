package userexport_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/userexport"
)

func TestRunnerHappyPath(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "runner@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	runner := &userexport.Runner{
		Source:  store,
		Store:   store,
		Storage: storage,
		Now:     func() time.Time { return now },
	}
	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	saved, err := runner.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if saved.Status != db.UserDataExportStatusReady {
		t.Fatalf("expected ready, got %s", saved.Status)
	}
	if saved.BundleSizeBytes == 0 || saved.BundleSHA256 == "" {
		t.Fatalf("bundle metadata not recorded: %+v", saved)
	}
	if saved.DownloadExpiresAt == nil || !saved.DownloadExpiresAt.After(now) {
		t.Fatalf("download expiry not set: %+v", saved.DownloadExpiresAt)
	}
	if saved.PurgeAfter == nil || !saved.PurgeAfter.After(*saved.DownloadExpiresAt) {
		t.Fatalf("purge after must be later than download expiry: %+v", saved)
	}
	rc, err := storage.Open(userexport.StorageKey(saved))
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	rc.Close()
}

func TestRunnerMarksFailedOnBuildError(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	runner := &userexport.Runner{Source: store, Store: store, Storage: storage, Now: func() time.Time { return now }}
	user, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "real@example.com"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	job.UserID = "00000000-0000-0000-0000-000000000000"
	if _, err := runner.Run(context.Background(), job); err == nil {
		t.Fatal("expected error for missing user")
	}
	saved, err := store.GetUserDataExportByID(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if saved.Status != db.UserDataExportStatusFailed {
		t.Fatalf("expected failed, got %s", saved.Status)
	}
}

func TestRunnerMarksFailedWhenCompletionWriteFails(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "runner-complete-failure@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusRunning,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	runner := &userexport.Runner{
		Source:  store,
		Store:   completeErrorStore{MemoryStore: store},
		Storage: storage,
		Now:     func() time.Time { return now },
	}
	if _, err := runner.Run(context.Background(), job); err == nil {
		t.Fatal("expected completion error")
	}
	saved, err := store.GetUserDataExportByID(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if saved.Status != db.UserDataExportStatusFailed {
		t.Fatalf("expected failed after completion write error, got %+v", saved)
	}
	if _, err := storage.Open(userexport.StorageKey(job)); err == nil {
		t.Fatal("expected bundle to be deleted after failed completion write")
	}
}

func TestRunnerDeletesBundleEvenWhenFailureMarkFails(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "runner-complete-mark-failure@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	job, err := store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      user.ID,
		RequestedAt: now,
		Status:      db.UserDataExportStatusRunning,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	runner := &userexport.Runner{
		Source:  store,
		Store:   failureMarkStore{MemoryStore: store},
		Storage: storage,
		Now:     func() time.Time { return now },
	}
	if _, err := runner.Run(context.Background(), job); err == nil {
		t.Fatal("expected completion write + mark error")
	}
	if _, err := storage.Open(userexport.StorageKey(job)); err == nil {
		t.Fatal("expected bundle to be deleted when failure marking also fails")
	}
}

type completeErrorStore struct {
	*db.MemoryStore
}

func (s completeErrorStore) CompleteUserDataExport(context.Context, string, string, int64, string, time.Time, time.Time, time.Time) (db.UserDataExport, error) {
	return db.UserDataExport{}, errors.New("complete failed")
}

type failureMarkStore struct {
	*db.MemoryStore
}

func (s failureMarkStore) CompleteUserDataExport(context.Context, string, string, int64, string, time.Time, time.Time, time.Time) (db.UserDataExport, error) {
	return db.UserDataExport{}, errors.New("complete failed")
}

func (s failureMarkStore) FailUserDataExport(context.Context, string, string, time.Time) (db.UserDataExport, error) {
	return db.UserDataExport{}, errors.New("fail write failed")
}
