package workspacepurge_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/workspacepurge"
)

func seedTenancyWorkspace(t *testing.T, store *db.MemoryStore, tenantID, workspaceID, displayName string) {
	t.Helper()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: tenantID, WorkspaceID: workspaceID})
	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{TenantID: tenantID, DisplayName: displayName, Slug: tenantID}); err != nil {
		// Already-seeded organizations are fine — tests reuse the same tenant for multiple workspaces.
		if !errors.Is(err, db.ErrConflict) {
			// nothing extra to assert; the next workspace upsert will surface a real error if the tenant truly isn't there
		}
	}
	if err := store.UpsertWorkspace(ctx, db.TenancyWorkspace{
		TenantID:    tenantID,
		WorkspaceID: workspaceID,
		DisplayName: displayName,
		Slug:        workspaceID,
	}); err != nil {
		t.Fatalf("upsert workspace %s: %v", workspaceID, err)
	}
}

func softDelete(t *testing.T, store *db.MemoryStore, tenantID, workspaceID string, when time.Time) {
	t.Helper()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: tenantID, WorkspaceID: workspaceID})
	if _, err := store.SoftDeleteWorkspace(ctx, workspaceID, when); err != nil {
		t.Fatalf("soft delete %s: %v", workspaceID, err)
	}
}

func TestRunOncePurgesWorkspacesPastGrace(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	gracePast := now.Add(-(db.WorkspaceDeletionGracePeriod + 24*time.Hour))
	graceFuture := now.Add(-(db.WorkspaceDeletionGracePeriod / 2))

	// Workspace A — past grace, must be purged.
	seedTenancyWorkspace(t, store, "tenant-a", "ws-past", "Past Grace")
	softDelete(t, store, "tenant-a", "ws-past", gracePast)
	// Workspace B — within grace, must NOT be purged.
	seedTenancyWorkspace(t, store, "tenant-a", "ws-future", "Within Grace")
	softDelete(t, store, "tenant-a", "ws-future", graceFuture)
	// Workspace C — active, must NOT appear in pending list at all.
	seedTenancyWorkspace(t, store, "tenant-a", "ws-active", "Active")

	runner := &workspacepurge.Runner{Store: store, Now: func() time.Time { return now }, BatchSize: 100}
	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Examined != 1 || result.Purged != 1 || result.Errors != 0 {
		t.Fatalf("unexpected result %+v", result)
	}

	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "ws-past"})
	if _, err := store.GetWorkspace(scopedCtx, "ws-past"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ws-past to be purged, GetWorkspace returned %v", err)
	}

	// Workspaces B and C must still resolve — the worker is filtered by
	// the grace cutoff, so within-grace and active workspaces are
	// untouched.
	bCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "ws-future"})
	if _, err := store.GetWorkspace(bCtx, "ws-future"); err != nil {
		t.Fatalf("expected ws-future preserved within grace, got %v", err)
	}
	cCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "ws-active"})
	if _, err := store.GetWorkspace(cCtx, "ws-active"); err != nil {
		t.Fatalf("expected ws-active preserved (never deleted), got %v", err)
	}
}

func TestRunOnceIsIdempotent(t *testing.T) {
	// Re-running the worker after a successful purge must be a no-op: the
	// workspace row is gone, so the pending list is empty on the second
	// pass. This is the workspace analog of userpurge's tombstone-filter
	// idempotency check.
	store := db.NewMemoryStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-(db.WorkspaceDeletionGracePeriod + time.Hour))
	seedTenancyWorkspace(t, store, "tenant-a", "ws-1", "Tombstone")
	softDelete(t, store, "tenant-a", "ws-1", past)

	runner := &workspacepurge.Runner{Store: store, Now: func() time.Time { return now }}
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
	runner := &workspacepurge.Runner{}
	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when Store is nil")
	}
}

// errStore lets RunOnce reach HardDeleteWorkspace, then always returns an
// error. Used to exercise the cancellation and hard-delete-failure
// branches without standing up a real DB.
type errStore struct {
	pending     []db.TenancyWorkspace
	listErr     error
	hardDelErr  error
	hardDelHits int
	onHardDel   func()
}

func (s *errStore) ListWorkspacesPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]db.TenancyWorkspace, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.pending, nil
}

func (s *errStore) HardDeleteWorkspace(ctx context.Context, tenantID, workspaceID string, expectedDeletedAt time.Time, now time.Time) (db.TenancyWorkspace, error) {
	s.hardDelHits++
	if s.onHardDel != nil {
		s.onHardDel()
	}
	return db.TenancyWorkspace{}, s.hardDelErr
}

func TestRunOnceListErrorWraps(t *testing.T) {
	sentinel := errors.New("synthetic list failure")
	r := &workspacepurge.Runner{Store: &errStore{listErr: sentinel}}
	_, err := r.RunOnce(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
}

func TestRunOnceHardDeleteFailureCounted(t *testing.T) {
	now := time.Now().UTC()
	deletedAt := now.Add(-(db.WorkspaceDeletionGracePeriod + time.Hour))
	store := &errStore{
		pending:    []db.TenancyWorkspace{{TenantID: "tenant-a", WorkspaceID: "ws-1", Status: "deleted", DeletedAt: &deletedAt}},
		hardDelErr: errors.New("forced failure"),
	}
	r := &workspacepurge.Runner{Store: store, Now: func() time.Time { return now }}
	result, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Errors != 1 || result.Purged != 0 {
		t.Fatalf("expected 1 error and 0 purged, got %+v", result)
	}
}

func TestRunOnceCanceledContextPropagates(t *testing.T) {
	// Mirror of userpurge's post-write ctx branch: HardDeleteWorkspace
	// fails AND the context was canceled mid-call. The runner must
	// surface the context error rather than counting the iteration as
	// Errors++. Canceling BEFORE RunOnce would short-circuit on the
	// per-iteration ctx check and bypass HardDeleteWorkspace entirely;
	// canceling inside HardDeleteWorkspace (via onHardDel) is the only
	// way to reach the post-write branch.
	now := time.Now().UTC()
	deletedAt := now.Add(-(db.WorkspaceDeletionGracePeriod + time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &errStore{
		pending:    []db.TenancyWorkspace{{TenantID: "tenant-a", WorkspaceID: "ws-1", Status: "deleted", DeletedAt: &deletedAt}},
		hardDelErr: errors.New("forced failure"),
		onHardDel:  cancel,
	}
	r := &workspacepurge.Runner{Store: store, Now: func() time.Time { return now }}
	result, err := r.RunOnce(ctx)
	if store.hardDelHits != 1 {
		t.Fatalf("expected HardDeleteWorkspace to be invoked once, got %d", store.hardDelHits)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if result.Errors != 0 {
		t.Fatalf("expected ctx-interrupted iteration not to count as an error, got %+v", result)
	}
}

func TestRunOncePurgesProjectAndMemberRows(t *testing.T) {
	// End-to-end with the memory store: a soft-deleted workspace with
	// a project and an owner member must have those rows removed after
	// the purge. Broader child-row coverage (connectors, secret
	// envelopes, scan history, AWS coverage) is exercised at the store
	// layer in TestMemoryStoreHardDeleteWorkspacePurgesEveryChildTable;
	// the worker-level test sticks to the fixtures the worker itself
	// can seed without pulling in the full secret-store harness.
	store := db.NewMemoryStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-(db.WorkspaceDeletionGracePeriod + time.Hour))

	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "ws-1"})
	seedTenancyWorkspace(t, store, "tenant-a", "ws-1", "Production")
	if err := store.UpsertProject(scopedCtx, db.TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "ws-1", MemberID: "m-1", UserID: "subj-1", Role: "owner", Status: "active",
	}); err != nil {
		t.Fatalf("upsert member: %v", err)
	}
	softDelete(t, store, "tenant-a", "ws-1", past)

	runner := &workspacepurge.Runner{Store: store, Now: func() time.Time { return now }}
	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Purged != 1 {
		t.Fatalf("expected 1 purged, got %+v", result)
	}

	// Workspace gone.
	if _, err := store.GetWorkspace(scopedCtx, "ws-1"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after purge, got %v", err)
	}
	// Project gone.
	if _, err := store.GetProject(scopedCtx, "ws-1", "project-a"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected project purged with workspace, got %v", err)
	}
	// Member gone.
	if _, err := store.GetWorkspaceMember(scopedCtx, "ws-1", "m-1"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected member purged with workspace, got %v", err)
	}
}
