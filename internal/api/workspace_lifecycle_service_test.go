package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
)

// setupWorkspaceLifecycleServiceHarness seeds a memory-backed service with
// a single owner of workspace-a so individual service methods can be
// exercised directly. Returns the scoped context and owner UUID.
func setupWorkspaceLifecycleServiceHarness(t *testing.T) (*Service, context.Context, string) {
	t.Helper()
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.DefaultScope = db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}.Normalize()
	svc.Now = func() time.Time { return time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC) }
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "owner@example.com",
		DisplayName:  "Owner",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-owner",
		UserID:      "subj-owner",
		UserUUID:    user.ID,
		Email:       user.PrimaryEmail,
		Role:        "owner",
		Status:      "active",
	}); err != nil {
		t.Fatalf("upsert owner: %v", err)
	}
	return svc, scopedCtx, user.ID
}

func TestServiceWorkspaceLifecycleEmptyIDReturnsInvalid(t *testing.T) {
	// Every lifecycle entrypoint validates the workspace id at the
	// service boundary and refuses with ErrInvalidTenancyRequest before
	// touching the store. Pin the contract so a future caller that
	// passes a stray whitespace id cannot silently no-op against the
	// wrong workspace under a memory race.
	svc, ctx, ownerUUID := setupWorkspaceLifecycleServiceHarness(t)
	for _, id := range []string{"", "   "} {
		if _, _, err := svc.SuspendWorkspace(ctx, id, ownerUUID); !errors.Is(err, ErrInvalidTenancyRequest) {
			t.Fatalf("suspend %q: expected ErrInvalidTenancyRequest, got %v", id, err)
		}
		if _, err := svc.ReactivateWorkspace(ctx, id, ownerUUID); !errors.Is(err, ErrInvalidTenancyRequest) {
			t.Fatalf("reactivate %q: expected ErrInvalidTenancyRequest, got %v", id, err)
		}
		if _, _, err := svc.SoftDeleteWorkspace(ctx, id, ownerUUID); !errors.Is(err, ErrInvalidTenancyRequest) {
			t.Fatalf("soft delete %q: expected ErrInvalidTenancyRequest, got %v", id, err)
		}
		if _, err := svc.CancelWorkspaceDeletion(ctx, id, ownerUUID); !errors.Is(err, ErrInvalidTenancyRequest) {
			t.Fatalf("cancel %q: expected ErrInvalidTenancyRequest, got %v", id, err)
		}
	}
}

func TestServiceRequireWorkspaceOwnerBypassesForEmptyUUID(t *testing.T) {
	// Internal/test callers without a UserUUID are intentionally
	// bypassed by requireWorkspaceOwner. With the production route
	// grant now restricted to the "owner" role string, only the
	// in-process path can hit this branch, but it still has to work so
	// integration tests can drive the service without standing up a
	// full session-auth layer.
	svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
	if err := svc.requireWorkspaceOwner(ctx, "workspace-a", ""); err != nil {
		t.Fatalf("expected empty UUID to bypass, got %v", err)
	}
	if err := svc.requireWorkspaceOwner(ctx, "workspace-a", "   "); err != nil {
		t.Fatalf("expected whitespace UUID to bypass, got %v", err)
	}
}

func TestServiceRequireWorkspaceOwnerSurfacesNotFoundOverPermission(t *testing.T) {
	// Order matters: a missing workspace must produce ErrNotFound (404)
	// rather than ErrWorkspaceOwnerRequired (403). Otherwise an
	// authenticated caller would lose the ability to distinguish a
	// typo from a permissions issue, and the existing 404 contract on
	// the lifecycle routes would silently break.
	svc, ctx, ownerUUID := setupWorkspaceLifecycleServiceHarness(t)
	if err := svc.requireWorkspaceOwner(ctx, "nonexistent", ownerUUID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing workspace, got %v", err)
	}
}

func TestServiceRequireWorkspaceOwnerRefusesNonOwner(t *testing.T) {
	svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
	// Add a non-owner member.
	store := svc.Store.(*db.MemoryStore)
	otherUser, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "viewer@example.com",
		DisplayName:  "Viewer",
	})
	if err != nil {
		t.Fatalf("upsert viewer: %v", err)
	}
	if err := store.UpsertWorkspaceMember(ctx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-viewer",
		UserID:      "subj-viewer",
		UserUUID:    otherUser.ID,
		Email:       otherUser.PrimaryEmail,
		Role:        "viewer",
		Status:      "active",
	}); err != nil {
		t.Fatalf("upsert viewer: %v", err)
	}
	if err := svc.requireWorkspaceOwner(ctx, "workspace-a", otherUser.ID); !errors.Is(err, ErrWorkspaceOwnerRequired) {
		t.Fatalf("expected ErrWorkspaceOwnerRequired for viewer, got %v", err)
	}
	// An unknown user UUID hits the GetWorkspaceMemberByUserUUID
	// ErrNotFound branch and must also surface as owner-required so
	// the handler can return a consistent 403.
	if err := svc.requireWorkspaceOwner(ctx, "workspace-a", "33333333-3333-3333-3333-333333333333"); !errors.Is(err, ErrWorkspaceOwnerRequired) {
		t.Fatalf("expected ErrWorkspaceOwnerRequired for unknown user, got %v", err)
	}
}

func TestServiceRequireWorkspaceOwnerRefusesInactiveOwner(t *testing.T) {
	// An owner whose membership status is suspended/removed must not
	// satisfy the owner gate — they cannot perform destructive actions
	// any more than a viewer can. Pin both states so a future change
	// to MemberStatus values does not accidentally re-admit them.
	svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
	store := svc.Store.(*db.MemoryStore)
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "stale-owner@example.com",
		DisplayName:  "Stale Owner",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	for _, status := range []string{"suspended", "removed", "invited"} {
		if err := store.UpsertWorkspaceMember(ctx, db.TenancyWorkspaceMember{
			WorkspaceID: "workspace-a",
			MemberID:    "member-stale",
			UserID:      "subj-stale",
			UserUUID:    user.ID,
			Email:       user.PrimaryEmail,
			Role:        "owner",
			Status:      status,
		}); err != nil {
			t.Fatalf("upsert %s owner: %v", status, err)
		}
		if err := svc.requireWorkspaceOwner(ctx, "workspace-a", user.ID); !errors.Is(err, ErrWorkspaceOwnerRequired) {
			t.Fatalf("expected ErrWorkspaceOwnerRequired for %s owner, got %v", status, err)
		}
	}
}

func TestServiceCancelWorkspaceDeletionIsNoOpForActive(t *testing.T) {
	// Cancel-deletion on an already-active workspace is a documented
	// idempotent no-op: the handler returns 200 + the unchanged
	// workspace without touching the store. The branch matters because
	// stale UIs can hit cancel-deletion after a cross-tab cancel lands.
	svc, ctx, ownerUUID := setupWorkspaceLifecycleServiceHarness(t)
	saved, err := svc.CancelWorkspaceDeletion(ctx, "workspace-a", ownerUUID)
	if err != nil {
		t.Fatalf("cancel on active: %v", err)
	}
	if saved.Status != db.WorkspaceStatusActive || saved.DeletedAt != nil {
		t.Fatalf("expected unchanged active workspace, got %+v", saved)
	}
}

func TestServiceReactivateWorkspaceIsNoOpForActive(t *testing.T) {
	// Same idempotency contract as cancel-deletion: an already-active
	// workspace returns 200 unchanged. Without this, a UI race could
	// trigger an unnecessary UPDATE that drifts updated_at.
	svc, ctx, ownerUUID := setupWorkspaceLifecycleServiceHarness(t)
	saved, err := svc.ReactivateWorkspace(ctx, "workspace-a", ownerUUID)
	if err != nil {
		t.Fatalf("reactivate active: %v", err)
	}
	if saved.Status != db.WorkspaceStatusActive {
		t.Fatalf("expected active status unchanged, got %q", saved.Status)
	}
}

func TestServiceLegacyDeleteWorkspaceHardDeletes(t *testing.T) {
	// Service.DeleteWorkspace is the legacy hard-delete primitive kept
	// for the workspace hard-delete worker that ships in PR 2 of
	// #1420. It is no longer reachable from the HTTP DELETE route
	// (which now soft-deletes via SoftDeleteWorkspace), but the method
	// must keep working so the upcoming worker can drain past-grace
	// rows without re-implementing the cascade.
	svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
	if err := svc.DeleteWorkspace(ctx, "workspace-a"); err != nil {
		t.Fatalf("legacy hard delete: %v", err)
	}
	if _, err := svc.GetWorkspace(ctx, "workspace-a"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after hard delete, got %v", err)
	}
}

func TestServiceCheckWorkspaceSoleOwnerStrandingEmptyUUID(t *testing.T) {
	// Empty caller UUID short-circuits before the store lookup runs.
	// This branch is hit when the lifecycle endpoints are invoked via
	// an API-key path (now disallowed at the route grant, but the
	// service-level method has to handle it for forward compatibility
	// with platform-internal callers in future PRs).
	svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
	stranding, err := svc.checkWorkspaceSoleOwnerStranding(ctx, "workspace-a", "")
	if err != nil {
		t.Fatalf("empty UUID stranding: %v", err)
	}
	if len(stranding.StrandedMembers) != 0 {
		t.Fatalf("expected no stranded members for empty UUID, got %+v", stranding.StrandedMembers)
	}
	if stranding.Workspace.WorkspaceID != "workspace-a" {
		t.Fatalf("expected workspace returned for context, got %+v", stranding.Workspace)
	}
}

func TestWorkspaceDeletionGraceDeadlineZeroWhenNotDeleted(t *testing.T) {
	// The grace deadline helper returns time.Time{} for workspaces
	// that are not pending deletion. The handler relies on this to
	// omit `hard_delete_after` from non-delete responses.
	ws := db.TenancyWorkspace{TenantID: "t", WorkspaceID: "w", Status: db.WorkspaceStatusActive}
	if deadline := WorkspaceDeletionGraceDeadline(ws); !deadline.IsZero() {
		t.Fatalf("expected zero deadline for active workspace, got %v", deadline)
	}
	deletedAt := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	ws.DeletedAt = &deletedAt
	deadline := WorkspaceDeletionGraceDeadline(ws)
	expected := deletedAt.Add(db.WorkspaceDeletionGracePeriod)
	if !deadline.Equal(expected) {
		t.Fatalf("expected deadline=%v, got %v", expected, deadline)
	}
}
