package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeMigrationStore struct {
	applyDir string
	applyErr error
	closed   bool
}

func (f *fakeMigrationStore) ApplyMigrations(_ context.Context, dir string) error {
	f.applyDir = dir
	return f.applyErr
}

func (f *fakeMigrationStore) Close() error {
	f.closed = true
	return nil
}

func TestRunRequiresDatabaseURL(t *testing.T) {
	var opened bool
	var stderr strings.Builder

	code := run(context.Background(), mapGetenv(map[string]string{}), func(string) (migrationStore, error) {
		opened = true
		return &fakeMigrationStore{}, nil
	}, nil, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if opened {
		t.Fatal("store should not be opened without database URL")
	}
	if !strings.Contains(stderr.String(), "IDENTRAIL_DATABASE_URL is required") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestRunAppliesDefaultMigrationsDir(t *testing.T) {
	var stdout strings.Builder
	store := &fakeMigrationStore{}

	code := run(context.Background(), mapGetenv(map[string]string{
		"IDENTRAIL_DATABASE_URL": "postgres://example",
	}), func(databaseURL string) (migrationStore, error) {
		if databaseURL != "postgres://example" {
			t.Fatalf("unexpected database URL: %s", databaseURL)
		}
		return store, nil
	}, &stdout, nil)

	if code != 0 {
		t.Fatalf("expected success, got code %d", code)
	}
	if store.applyDir != defaultMigrationsDir {
		t.Fatalf("expected default migrations dir %q, got %q", defaultMigrationsDir, store.applyDir)
	}
	if !store.closed {
		t.Fatal("expected store to be closed")
	}
	if !strings.Contains(stdout.String(), "Applied migrations") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunAppliesConfiguredMigrationsDir(t *testing.T) {
	store := &fakeMigrationStore{}

	code := run(context.Background(), mapGetenv(map[string]string{
		"IDENTRAIL_DATABASE_URL":   "postgres://example",
		"IDENTRAIL_MIGRATIONS_DIR": "testdata/migrations",
	}), func(string) (migrationStore, error) {
		return store, nil
	}, nil, nil)

	if code != 0 {
		t.Fatalf("expected success, got code %d", code)
	}
	if store.applyDir != "testdata/migrations" {
		t.Fatalf("unexpected migrations dir: %s", store.applyDir)
	}
}

func TestRunPropagatesOpenErrorWithoutLeakingURL(t *testing.T) {
	var stderr strings.Builder

	code := run(context.Background(), mapGetenv(map[string]string{
		"IDENTRAIL_DATABASE_URL": "postgres://user:secret@example/db",
	}), func(string) (migrationStore, error) {
		return nil, errors.New("connection refused")
	}, nil, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if strings.Contains(stderr.String(), "secret@example") {
		t.Fatalf("stderr leaked database URL: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "connection refused") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestRunPropagatesMigrationError(t *testing.T) {
	var stderr strings.Builder
	store := &fakeMigrationStore{applyErr: errors.New("bad migration")}

	code := run(context.Background(), mapGetenv(map[string]string{
		"IDENTRAIL_DATABASE_URL": "postgres://example",
	}), func(string) (migrationStore, error) {
		return store, nil
	}, nil, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !store.closed {
		t.Fatal("expected store to be closed after migration error")
	}
	if !strings.Contains(stderr.String(), "bad migration") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func mapGetenv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}
