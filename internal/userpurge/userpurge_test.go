package userpurge_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/userpurge"
)

func TestRunOncePurgesAccountsPastGrace(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	gracePast := now.Add(-(db.UserDeletionGracePeriod + 24*time.Hour))
	graceFuture := now.Add(-(db.UserDeletionGracePeriod / 2))

	// Account A is past the grace window — must be purged.
	a, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "past@example.com",
		DisplayName:  "Past Grace",
		Status:       "deleted",
		DeletedAt:    &gracePast,
	})
	if err != nil {
		t.Fatalf("seed user A: %v", err)
	}
	// Account B is within the window — must NOT be purged.
	b, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "future@example.com",
		DisplayName:  "Within Grace",
		Status:       "deleted",
		DeletedAt:    &graceFuture,
	})
	if err != nil {
		t.Fatalf("seed user B: %v", err)
	}
	// Account C is active and untouched.
	c, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "active@example.com",
		DisplayName:  "Active",
	})
	if err != nil {
		t.Fatalf("seed user C: %v", err)
	}

	runner := &userpurge.Runner{Store: store, Now: func() time.Time { return now }, BatchSize: 100}
	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Examined != 1 || result.Purged != 1 || result.Errors != 0 {
		t.Fatalf("unexpected result %+v", result)
	}

	storedA, err := store.GetUser(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("get user A: %v", err)
	}
	if !db.IsHardDeletedTombstoneEmailForUser(storedA.PrimaryEmail, storedA.ID) {
		t.Fatalf("expected user A to be tombstoned, got email %q", storedA.PrimaryEmail)
	}
	if storedA.DisplayName != "" || storedA.AvatarURL != "" {
		t.Fatalf("expected PII cleared on user A, got %+v", storedA)
	}

	storedB, err := store.GetUser(context.Background(), b.ID)
	if err != nil {
		t.Fatalf("get user B: %v", err)
	}
	if storedB.PrimaryEmail != "future@example.com" {
		t.Fatalf("expected user B PII preserved within grace, got %q", storedB.PrimaryEmail)
	}

	storedC, err := store.GetUser(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("get user C: %v", err)
	}
	if storedC.PrimaryEmail != "active@example.com" {
		t.Fatalf("expected active user untouched, got %q", storedC.PrimaryEmail)
	}
}

func TestRunOnceIsIdempotent(t *testing.T) {
	// Re-running the worker after a successful purge must be a no-op: the
	// tombstoned row is filtered out of ListUsersPendingHardDelete by its
	// synthetic email, so subsequent passes do not re-purge it (and do not
	// emit duplicate audit events).
	store := db.NewMemoryStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-(db.UserDeletionGracePeriod + time.Hour))
	if _, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "tombstone@example.com",
		Status:       "deleted",
		DeletedAt:    &past,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	runner := &userpurge.Runner{Store: store, Now: func() time.Time { return now }}
	first, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.Purged != 1 {
		t.Fatalf("expected first run to purge 1, got %+v", first)
	}
	second, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.Examined != 0 || second.Purged != 0 {
		t.Fatalf("expected second run to be a no-op, got %+v", second)
	}
}

func TestRunOnceRequiresStore(t *testing.T) {
	runner := &userpurge.Runner{}
	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when Store is nil")
	}
}

// errStore is a Store stub that lets RunOnce reach HardDeleteUser, then
// always returns an error. Used to exercise the ctx-cancellation and
// hard-delete-failure branches of RunOnce without needing a real DB.
type errStore struct {
	pending     []db.User
	listErr     error
	hardDelErr  error
	hardDelHits int
	// onHardDel runs at the top of HardDeleteUser, before the canned error is
	// returned. Tests use it to simulate a context cancellation that arrives
	// *during* the call (after RunOnce passed the per-iteration ctx check),
	// which is the only way to exercise the post-write ctx-error branch.
	onHardDel func()
}

func (s *errStore) ListUsersPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]db.User, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.pending, nil
}

func (s *errStore) HardDeleteUser(ctx context.Context, userID string, now time.Time) (db.User, error) {
	s.hardDelHits++
	if s.onHardDel != nil {
		s.onHardDel()
	}
	return db.User{}, s.hardDelErr
}

func TestRunOnceListErrorWraps(t *testing.T) {
	// Use a distinct sentinel so the assertion can prove RunOnce *preserved*
	// (wrapped) the underlying error instead of swallowing or replacing it.
	// `err != nil` alone would pass even if the runner returned a generic
	// "list failed" string with no causal link to listErr.
	sentinel := errors.New("synthetic list failure")
	r := &userpurge.Runner{Store: &errStore{listErr: sentinel}}
	_, err := r.RunOnce(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
}

func TestRunOnceHardDeleteFailureCounted(t *testing.T) {
	now := time.Now().UTC()
	deletedAt := now.Add(-(db.UserDeletionGracePeriod + time.Hour))
	store := &errStore{
		pending:    []db.User{{ID: "u1", Status: "deleted", DeletedAt: &deletedAt}},
		hardDelErr: context.DeadlineExceeded,
	}
	r := &userpurge.Runner{Store: store, Now: func() time.Time { return now }}
	// Active context — the error counts as a runtime failure, not cancellation.
	result, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Errors != 1 || result.Purged != 0 {
		t.Fatalf("expected 1 error and 0 purged, got %+v", result)
	}
}

func TestRunOnceCanceledContextPropagates(t *testing.T) {
	// Exercises the post-write ctx-error branch in RunOnce: HardDeleteUser
	// fails AND the context was canceled mid-call. The runner must surface
	// the context error rather than counting the iteration as Errors++.
	// Cancelling the context BEFORE RunOnce would short-circuit on the
	// per-iteration ctx check and bypass HardDeleteUser entirely, which is
	// not the branch we want to exercise. Cancelling INSIDE HardDeleteUser
	// (via onHardDel) is the only way to land in the post-write branch.
	now := time.Now().UTC()
	deletedAt := now.Add(-(db.UserDeletionGracePeriod + time.Hour))
	forcedHardDelErr := errors.New("forced hard delete failure")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &errStore{
		pending:    []db.User{{ID: "u1", Status: "deleted", DeletedAt: &deletedAt}},
		hardDelErr: forcedHardDelErr,
		onHardDel:  cancel,
	}
	r := &userpurge.Runner{Store: store, Now: func() time.Time { return now }}
	result, err := r.RunOnce(ctx)
	if store.hardDelHits != 1 {
		t.Fatalf("expected HardDeleteUser to be invoked once, got %d", store.hardDelHits)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if errors.Is(err, forcedHardDelErr) {
		t.Fatalf("expected ctx error to take precedence over HardDeleteUser error, got %v", err)
	}
	if result.Errors != 0 {
		t.Fatalf("expected ctx-interrupted iteration not to count as an error, got %+v", result)
	}
}
