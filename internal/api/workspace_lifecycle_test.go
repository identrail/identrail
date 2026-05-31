package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
)

// promoteMemberToOwner upgrades the harness's seeded "admin" member to "owner"
// so the owner-only authz check passes for workspace lifecycle endpoints.
// Returns the user UUID for downstream assertions.
func promoteMemberToOwner(t *testing.T, store *db.MemoryStore, email string) string {
	t.Helper()
	user, err := store.GetUserByPrimaryEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "oidc-subject-a",
		UserUUID:    user.ID,
		Email:       user.PrimaryEmail,
		Role:        "owner",
		Status:      "active",
	}); err != nil {
		t.Fatalf("promote to owner: %v", err)
	}
	return user.ID
}

func sessionRequest(method string, path string, cookieValue string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Origin", "http://localhost:8080")
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	return req
}

func TestWorkspaceSuspendHappyPath(t *testing.T) {
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/suspend", cookieValue))
	if w.Code != http.StatusOK {
		t.Fatalf("expected suspend 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"suspended"`) {
		t.Fatalf("expected suspended status in body, got %s", w.Body.String())
	}

	// Idempotency: repeat suspend preserves the original suspended_at.
	var first struct {
		Workspace db.TenancyWorkspace `json:"workspace"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("unmarshal first suspend: %v", err)
	}
	if first.Workspace.SuspendedAt == nil {
		t.Fatalf("expected suspended_at to be set on first suspend")
	}
	firstStamp := *first.Workspace.SuspendedAt

	// Advance the fake clock and re-suspend.
	harness.svc.Now = func() time.Time { return time.Date(2026, 5, 15, 9, 0, 0, 0, time.UTC) }
	w2 := httptest.NewRecorder()
	harness.router.ServeHTTP(w2, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/suspend", cookieValue))
	if w2.Code != http.StatusOK {
		t.Fatalf("expected second suspend 200, got %d body=%s", w2.Code, w2.Body.String())
	}
	var second struct {
		Workspace db.TenancyWorkspace `json:"workspace"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &second); err != nil {
		t.Fatalf("unmarshal second suspend: %v", err)
	}
	if second.Workspace.SuspendedAt == nil || !second.Workspace.SuspendedAt.Equal(firstStamp) {
		t.Fatalf("expected idempotent suspended_at=%v, got %v", firstStamp, second.Workspace.SuspendedAt)
	}
}

func TestWorkspaceReactivateAfterSuspend(t *testing.T) {
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	suspendResp := httptest.NewRecorder()
	harness.router.ServeHTTP(suspendResp, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/suspend", cookieValue))
	if suspendResp.Code != http.StatusOK {
		t.Fatalf("expected suspend 200, got %d body=%s", suspendResp.Code, suspendResp.Body.String())
	}

	reactResp := httptest.NewRecorder()
	harness.router.ServeHTTP(reactResp, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/reactivate", cookieValue))
	if reactResp.Code != http.StatusOK {
		t.Fatalf("expected reactivate 200, got %d body=%s", reactResp.Code, reactResp.Body.String())
	}
	if !strings.Contains(reactResp.Body.String(), `"status":"active"`) {
		t.Fatalf("expected active status after reactivate, got %s", reactResp.Body.String())
	}
}

func TestWorkspaceReactivateRefusesDeletedWorkspace(t *testing.T) {
	// Reactivate only flips suspended → active. A soft-deleted workspace
	// must go through cancel-deletion so the 30-day grace window stays
	// authoritative; otherwise reactivate could be used to sneak past the
	// purge deadline.
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	delResp := httptest.NewRecorder()
	harness.router.ServeHTTP(delResp, sessionRequest(http.MethodDelete, "/v1/workspaces/workspace-a", cookieValue))
	if delResp.Code != http.StatusOK {
		t.Fatalf("expected delete 200, got %d body=%s", delResp.Code, delResp.Body.String())
	}

	reactResp := httptest.NewRecorder()
	harness.router.ServeHTTP(reactResp, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/reactivate", cookieValue))
	if reactResp.Code != http.StatusConflict {
		t.Fatalf("expected reactivate 409 on deleted workspace, got %d body=%s", reactResp.Code, reactResp.Body.String())
	}
	if !strings.Contains(reactResp.Body.String(), `"code":"not_reactivatable"`) {
		t.Fatalf("expected not_reactivatable code in body, got %s", reactResp.Body.String())
	}

	// Workspace must remain in the deleted state so the cancel-deletion
	// path remains the only revival route.
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	refreshed, err := store.GetWorkspace(scopedCtx, "workspace-a")
	if err != nil {
		t.Fatalf("get workspace: %v", err)
	}
	if refreshed.Status != db.WorkspaceStatusDeleted || refreshed.DeletedAt == nil {
		t.Fatalf("expected workspace still deleted after refused reactivate, got %+v", refreshed)
	}
}

func TestWorkspaceSoftDeleteAndCancel(t *testing.T) {
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	delResp := httptest.NewRecorder()
	harness.router.ServeHTTP(delResp, sessionRequest(http.MethodDelete, "/v1/workspaces/workspace-a", cookieValue))
	if delResp.Code != http.StatusOK {
		t.Fatalf("expected delete 200, got %d body=%s", delResp.Code, delResp.Body.String())
	}
	if !strings.Contains(delResp.Body.String(), `"status":"deleted"`) {
		t.Fatalf("expected deleted status in body, got %s", delResp.Body.String())
	}
	if !strings.Contains(delResp.Body.String(), `"hard_delete_after"`) {
		t.Fatalf("expected hard_delete_after in body, got %s", delResp.Body.String())
	}

	cancelResp := httptest.NewRecorder()
	harness.router.ServeHTTP(cancelResp, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/cancel-deletion", cookieValue))
	if cancelResp.Code != http.StatusOK {
		t.Fatalf("expected cancel-deletion 200, got %d body=%s", cancelResp.Code, cancelResp.Body.String())
	}
	if !strings.Contains(cancelResp.Body.String(), `"status":"active"`) {
		t.Fatalf("expected active status after cancel, got %s", cancelResp.Body.String())
	}
}

func TestWorkspaceCancelDeletionPastGraceReturns410(t *testing.T) {
	// Past the grace window the worker is authoritative for the purge; the
	// API must refuse so a stale UI cannot resurrect a workspace the user
	// already lost the option to keep.
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	delResp := httptest.NewRecorder()
	harness.router.ServeHTTP(delResp, sessionRequest(http.MethodDelete, "/v1/workspaces/workspace-a", cookieValue))
	if delResp.Code != http.StatusOK {
		t.Fatalf("expected delete 200, got %d body=%s", delResp.Code, delResp.Body.String())
	}

	// Advance the harness clock past the grace window.
	pastGrace := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC).Add(db.WorkspaceDeletionGracePeriod + 24*time.Hour)
	harness.svc.Now = func() time.Time { return pastGrace }

	cancelResp := httptest.NewRecorder()
	harness.router.ServeHTTP(cancelResp, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/cancel-deletion", cookieValue))
	if cancelResp.Code != http.StatusGone {
		t.Fatalf("expected cancel-deletion 410, got %d body=%s", cancelResp.Code, cancelResp.Body.String())
	}
	if !strings.Contains(cancelResp.Body.String(), `"code":"grace_period_expired"`) {
		t.Fatalf("expected grace_period_expired code, got %s", cancelResp.Body.String())
	}
}

func TestWorkspaceSuspendSoleOwnerWithOtherMembers409(t *testing.T) {
	// Sole-owner guard: a single owner cannot suspend if other active
	// non-owner members would be stranded — the 409 surfaces the affected
	// member list so the UI can deep-link to the member-management screen.
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	// Add a second user as an active analyst so suspending would strand them.
	otherUser, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "analyst@example.com",
		DisplayName:  "Analyst One",
	})
	if err != nil {
		t.Fatalf("upsert analyst user: %v", err)
	}
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-b",
		UserID:      "oidc-subject-b",
		UserUUID:    otherUser.ID,
		Email:       otherUser.PrimaryEmail,
		Role:        "analyst",
		Status:      "active",
	}); err != nil {
		t.Fatalf("upsert analyst member: %v", err)
	}

	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/suspend", cookieValue))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected suspend 409 sole_owner, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"code":"sole_owner_requires_transfer"`) {
		t.Fatalf("expected sole_owner_requires_transfer code, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"member_id":"member-b"`) {
		t.Fatalf("expected affected member-b in body, got %s", w.Body.String())
	}

	// Workspace must remain active so the owner can transfer and retry.
	refreshed, err := store.GetWorkspace(scopedCtx, "workspace-a")
	if err != nil {
		t.Fatalf("get workspace: %v", err)
	}
	if refreshed.Status != db.WorkspaceStatusActive {
		t.Fatalf("expected workspace still active, got %q", refreshed.Status)
	}
}

func TestWorkspaceDeleteSoleOwnerWithOtherMembers409(t *testing.T) {
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	otherUser, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "viewer@example.com",
		DisplayName:  "Viewer One",
	})
	if err != nil {
		t.Fatalf("upsert viewer user: %v", err)
	}
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-v",
		UserID:      "oidc-subject-v",
		UserUUID:    otherUser.ID,
		Email:       otherUser.PrimaryEmail,
		Role:        "viewer",
		Status:      "active",
	}); err != nil {
		t.Fatalf("upsert viewer member: %v", err)
	}

	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, sessionRequest(http.MethodDelete, "/v1/workspaces/workspace-a", cookieValue))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected delete 409 sole_owner, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"code":"sole_owner_requires_transfer"`) {
		t.Fatalf("expected sole_owner_requires_transfer code, got %s", w.Body.String())
	}

	refreshed, err := store.GetWorkspace(scopedCtx, "workspace-a")
	if err != nil {
		t.Fatalf("get workspace: %v", err)
	}
	if refreshed.Status != db.WorkspaceStatusActive {
		t.Fatalf("expected workspace still active after sole-owner block, got %q", refreshed.Status)
	}
	if refreshed.DeletedAt != nil {
		t.Fatalf("expected deleted_at unset after sole-owner block, got %v", refreshed.DeletedAt)
	}
}

func TestWorkspaceSuspendSoleOwnerNoOtherMembersAllowed(t *testing.T) {
	// The sole-owner guard only blocks when other active members would be
	// stranded. An owner with no other members is allowed to proceed.
	harness, cookieValue, _ := setupSessionRouter(t)
	store := harness.manager.Store.(*db.MemoryStore)
	promoteMemberToOwner(t, store, "user@example.com")

	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, sessionRequest(http.MethodPost, "/v1/workspaces/workspace-a/suspend", cookieValue))
	if w.Code != http.StatusOK {
		t.Fatalf("expected suspend 200 (no other members to strand), got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWorkspaceLifecycleNonOwnerRolesForbidden(t *testing.T) {
	// Every non-owner workspace membership role must be refused. Analyst
	// and viewer are blocked at the authz route table; admin gets past the
	// route table (the "admin" string collides with the platform-scope
	// "admin" — see internal/api/authz_middleware.go) but the service-layer
	// `requireWorkspaceOwner` check is the authoritative gate and still
	// returns 403 with code=owner_required.
	for _, role := range []string{"admin", "analyst", "viewer"} {
		t.Run(role, func(t *testing.T) {
			harness, cookieValue, _ := setupSessionRouter(t)
			store := harness.manager.Store.(*db.MemoryStore)
			user, err := store.GetUserByPrimaryEmail(context.Background(), "user@example.com")
			if err != nil {
				t.Fatalf("get user: %v", err)
			}
			scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
			if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
				WorkspaceID: "workspace-a",
				MemberID:    "member-a",
				UserID:      "oidc-subject-a",
				UserUUID:    user.ID,
				Email:       user.PrimaryEmail,
				Role:        role,
				Status:      "active",
			}); err != nil {
				t.Fatalf("downgrade member to %s: %v", role, err)
			}
			paths := []struct {
				method string
				path   string
			}{
				{http.MethodPost, "/v1/workspaces/workspace-a/suspend"},
				{http.MethodPost, "/v1/workspaces/workspace-a/reactivate"},
				{http.MethodDelete, "/v1/workspaces/workspace-a"},
				{http.MethodPost, "/v1/workspaces/workspace-a/cancel-deletion"},
			}
			for _, p := range paths {
				w := httptest.NewRecorder()
				harness.router.ServeHTTP(w, sessionRequest(p.method, p.path, cookieValue))
				if w.Code != http.StatusForbidden {
					t.Fatalf("expected %s %s 403 for %s role, got %d body=%s", p.method, p.path, role, w.Code, w.Body.String())
				}
			}
		})
	}
}
