package api

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
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

func TestServiceRequireWorkspaceOwnerRefusesEmptyUUID(t *testing.T) {
	// Role claims alone are not enough for workspace lifecycle writes. A caller
	// must carry a verifiable user UUID that maps to an active owner membership.
	svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
	if err := svc.requireWorkspaceOwner(ctx, "workspace-a", ""); !errors.Is(err, ErrWorkspaceOwnerRequired) {
		t.Fatalf("expected empty UUID to be refused, got %v", err)
	}
	if err := svc.requireWorkspaceOwner(ctx, "workspace-a", "   "); !errors.Is(err, ErrWorkspaceOwnerRequired) {
		t.Fatalf("expected whitespace UUID to be refused, got %v", err)
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

func TestServiceCancelWorkspaceDeletionRequiresPendingDeletionForSuspended(t *testing.T) {
	svc, ctx, ownerUUID := setupWorkspaceLifecycleServiceHarness(t)
	if _, err := svc.Store.SuspendWorkspace(ctx, "workspace-a", svc.Now()); err != nil {
		t.Fatalf("seed suspend: %v", err)
	}
	if _, err := svc.CancelWorkspaceDeletion(ctx, "workspace-a", ownerUUID); !errors.Is(err, ErrWorkspaceDeletionNotPending) {
		t.Fatalf("expected ErrWorkspaceDeletionNotPending for suspended workspace, got %v", err)
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

// errConflictOnLifecycleStore wraps a memory store and forces ErrConflict
// on the named lifecycle method. Used to exercise the service-level
// translation of a race-window ErrConflict (the workspace flipped to
// deleted between GetWorkspace and the destructive UPDATE) into a clean
// ErrWorkspaceNotSuspendable / ErrWorkspaceNotReactivatable response.
type errConflictOnLifecycleStore struct {
	db.Store
	suspend bool
	react   bool
}

func (s errConflictOnLifecycleStore) SuspendWorkspace(ctx context.Context, workspaceID string, now time.Time) (db.TenancyWorkspace, error) {
	if s.suspend {
		return db.TenancyWorkspace{}, db.ErrConflict
	}
	return s.Store.SuspendWorkspace(ctx, workspaceID, now)
}

func (s errConflictOnLifecycleStore) ReactivateWorkspace(ctx context.Context, workspaceID string, now time.Time) (db.TenancyWorkspace, error) {
	if s.react {
		return db.TenancyWorkspace{}, db.ErrConflict
	}
	return s.Store.ReactivateWorkspace(ctx, workspaceID, now)
}

func TestServiceSuspendWorkspaceTranslatesStoreConflict(t *testing.T) {
	// Race window: the workspace passed the service-level Get check but
	// was soft-deleted before the store UPDATE landed. The atomic
	// `AND status <> 'deleted'` clause in SuspendWorkspace's SQL then
	// returns ErrConflict; the service must surface that as the same
	// ErrWorkspaceNotSuspendable shape the handler maps to
	// 409 not_suspendable, so a stale UI client never sees a confusing
	// raw conflict error.
	svc, ctx, owner := setupWorkspaceLifecycleServiceHarness(t)
	svc.Store = errConflictOnLifecycleStore{Store: svc.Store, suspend: true}
	if _, _, err := svc.SuspendWorkspace(ctx, "workspace-a", owner); !errors.Is(err, ErrWorkspaceNotSuspendable) {
		t.Fatalf("expected ErrWorkspaceNotSuspendable for store ErrConflict, got %v", err)
	}
}

func TestServiceReactivateWorkspaceTranslatesStoreConflict(t *testing.T) {
	// Mirror of the suspend race: a soft-delete that landed between the
	// service's GetWorkspace and the store's UPDATE must surface as
	// ErrWorkspaceNotReactivatable (409 not_reactivatable) rather than
	// a raw conflict.
	svc, ctx, owner := setupWorkspaceLifecycleServiceHarness(t)
	// Put the workspace into suspended state so the Reactivate path
	// reaches the store call (otherwise the service's pre-check would
	// short-circuit with ErrWorkspaceNotReactivatable directly).
	if _, err := svc.Store.SuspendWorkspace(ctx, "workspace-a", time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("suspend workspace: %v", err)
	}
	svc.Store = errConflictOnLifecycleStore{Store: svc.Store, react: true}
	if _, err := svc.ReactivateWorkspace(ctx, "workspace-a", owner); !errors.Is(err, ErrWorkspaceNotReactivatable) {
		t.Fatalf("expected ErrWorkspaceNotReactivatable for store ErrConflict, got %v", err)
	}
}

func TestParseKubernetesEnrollmentTokenRejectsMalformed(t *testing.T) {
	// parseKubernetesEnrollmentToken decodes a public-route payload, so
	// every malformed-token branch must return ErrKubernetesConnectorTokenInvalid
	// without leaking any other state. Cover each branch so a future
	// edit that loosens validation fails here instead of in production.
	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no_separator", "onlypayload"},
		{"empty_payload_segment", ".secret"},
		{"empty_secret_segment", "cGF5bG9hZA."},
		{"non_base64_payload", "not!base64.secret"},
		{"non_json_payload", base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".secret"},
		{"missing_tenant",
			base64.RawURLEncoding.EncodeToString([]byte(`{"workspace_id":"w","project_id":"p","connector_id":"c"}`)) + ".secret"},
		{"missing_workspace",
			base64.RawURLEncoding.EncodeToString([]byte(`{"tenant_id":"t","project_id":"p","connector_id":"c"}`)) + ".secret"},
		{"missing_project",
			base64.RawURLEncoding.EncodeToString([]byte(`{"tenant_id":"t","workspace_id":"w","connector_id":"c"}`)) + ".secret"},
		{"missing_connector",
			base64.RawURLEncoding.EncodeToString([]byte(`{"tenant_id":"t","workspace_id":"w","project_id":"p"}`)) + ".secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKubernetesEnrollmentToken(tc.token); !errors.Is(err, ErrKubernetesConnectorTokenInvalid) {
				t.Fatalf("expected ErrKubernetesConnectorTokenInvalid for %s, got %v", tc.name, err)
			}
		})
	}
}

func TestBuildKubernetesEnrollmentTokenRoundTripsLocator(t *testing.T) {
	// Build/parse round-trip pin: the public agent route reads the
	// locator out of an enrollment token by parsing what build produced,
	// so any future edit that changes the encoding shape must keep
	// round-trip parity. Without this an attacker who could nudge the
	// build format would also break parse, and the routes would surface
	// as 401 invalid credentials with no clear signal in tests.
	token, err := buildKubernetesEnrollmentToken("tenant-a", "workspace-a", "project-1", "kubernetes-prod", "secret-payload")
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	if !strings.Contains(token, ".") {
		t.Fatalf("expected payload.secret shape, got %q", token)
	}
	locator, err := parseKubernetesEnrollmentToken(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if locator.TenantID != "tenant-a" || locator.WorkspaceID != "workspace-a" || locator.ProjectID != "project-1" || locator.ConnectorID != "kubernetes-prod" {
		t.Fatalf("round-trip locator mismatch: %+v", locator)
	}
}

func TestKubernetesHelmCommandDefaultsAPIURL(t *testing.T) {
	// Public start-connector handlers feed `apiURL` into the helm
	// command emitted to operators. An empty url must fall back to the
	// production endpoint so the rendered command is always runnable.
	out := kubernetesHelmCommand("", "tok")
	if !strings.Contains(out, "api.identrail.com") {
		t.Fatalf("expected default api url, got %q", out)
	}
	custom := kubernetesHelmCommand("https://api.example.test/", "tok")
	if !strings.Contains(custom, "api.example.test") || strings.Contains(custom, "api.example.test/ ") {
		t.Fatalf("expected trimmed custom api url, got %q", custom)
	}
}

func TestServiceSoftDeleteWorkspaceReturnsLifecycleResponse(t *testing.T) {
	// Round-trip the soft-delete service method: verify the saved
	// workspace carries the deleted_at timestamp and status flip, and
	// that WorkspaceDeletionGraceDeadline computes the expected
	// hard-delete cutoff exactly 30 days out. Pins the entire
	// soft-delete contract in one direct unit test so a handler-level
	// regression cannot silently drop either piece of the response.
	svc, ctx, owner := setupWorkspaceLifecycleServiceHarness(t)
	_, saved, err := svc.SoftDeleteWorkspace(ctx, "workspace-a", owner)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if saved.Status != db.WorkspaceStatusDeleted || saved.DeletedAt == nil {
		t.Fatalf("expected deleted status with timestamp, got %+v", saved)
	}
	deadline := WorkspaceDeletionGraceDeadline(saved)
	expected := saved.DeletedAt.UTC().Add(db.WorkspaceDeletionGracePeriod)
	if !deadline.Equal(expected) {
		t.Fatalf("expected deadline=%v, got %v", expected, deadline)
	}
}

func TestServiceSoftDeleteWorkspaceRejectsEmptyID(t *testing.T) {
	// Whitespace and empty workspace ids are normalized at the service
	// boundary so a stray trim cannot reach the store with a partial id
	// and silently soft-delete the wrong tenant scope.
	svc, ctx, owner := setupWorkspaceLifecycleServiceHarness(t)
	for _, id := range []string{"", "   ", "\t"} {
		if _, _, err := svc.SoftDeleteWorkspace(ctx, id, owner); !errors.Is(err, ErrInvalidTenancyRequest) {
			t.Fatalf("expected ErrInvalidTenancyRequest for %q, got %v", id, err)
		}
	}
}

func TestServiceCancelWorkspaceDeletionRejectsEmptyID(t *testing.T) {
	svc, ctx, owner := setupWorkspaceLifecycleServiceHarness(t)
	for _, id := range []string{"", "   ", "\t"} {
		if _, err := svc.CancelWorkspaceDeletion(ctx, id, owner); !errors.Is(err, ErrInvalidTenancyRequest) {
			t.Fatalf("expected ErrInvalidTenancyRequest for %q, got %v", id, err)
		}
	}
}

func TestServiceSuspendAndReactivateRoundTrip(t *testing.T) {
	// End-to-end suspend → reactivate happy path at the service layer.
	// The router-level tests already exercise the full HTTP flow but
	// they go through the rate limiter and authz middleware, so a
	// direct service round-trip is the cheapest way to pin the
	// idempotent shape — suspended_at preserved across a second
	// suspend, cleared after reactivate — without paying the harness
	// startup cost in N table-driven cases.
	svc, ctx, owner := setupWorkspaceLifecycleServiceHarness(t)
	_, first, err := svc.SuspendWorkspace(ctx, "workspace-a", owner)
	if err != nil {
		t.Fatalf("first suspend: %v", err)
	}
	if first.SuspendedAt == nil {
		t.Fatalf("expected suspended_at on first suspend")
	}
	firstStamp := *first.SuspendedAt
	_, second, err := svc.SuspendWorkspace(ctx, "workspace-a", owner)
	if err != nil {
		t.Fatalf("second suspend: %v", err)
	}
	if second.SuspendedAt == nil || !second.SuspendedAt.Equal(firstStamp) {
		t.Fatalf("expected idempotent suspended_at=%v, got %v", firstStamp, second.SuspendedAt)
	}
	saved, err := svc.ReactivateWorkspace(ctx, "workspace-a", owner)
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if saved.Status != db.WorkspaceStatusActive || saved.SuspendedAt != nil {
		t.Fatalf("expected reactivate to restore active with no suspended_at, got %+v", saved)
	}
}

func TestServiceProcessNextQueuedScanSkipsInactiveWorkspace(t *testing.T) {
	// A scan queued BEFORE the workspace was suspended/soft-deleted
	// still surfaces through ClaimNextQueuedScanAnyScope (the claim
	// SQL filters only on scan status). Without the lifecycle gate
	// inside ProcessNextQueuedScan, the worker would execute scans for
	// an inactive workspace and contradict the lifecycle pause contract
	// flagged by codex round-6 on #1445.
	for _, state := range []string{"suspended", "deleted"} {
		t.Run(state, func(t *testing.T) {
			svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
			// Enqueue a scan while the workspace is still active.
			record, err := svc.EnqueueScan(ctx)
			if err != nil {
				t.Fatalf("enqueue scan: %v", err)
			}
			// Flip the workspace lifecycle out of active.
			now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
			switch state {
			case "suspended":
				if _, err := svc.Store.SuspendWorkspace(ctx, "workspace-a", now); err != nil {
					t.Fatalf("suspend: %v", err)
				}
			case "deleted":
				if _, err := svc.Store.SoftDeleteWorkspace(ctx, "workspace-a", now); err != nil {
					t.Fatalf("soft delete: %v", err)
				}
			}
			processed, err := svc.ProcessNextQueuedScan(ctx)
			if err != nil {
				t.Fatalf("process queued scan: %v", err)
			}
			if !processed {
				t.Fatal("expected processed=true when skipping an inactive workspace scan")
			}
			// The scan must be in a terminal failed state with the
			// workspace_inactive marker visible in the error message.
			persisted, err := svc.Store.GetScan(ctx, record.ID)
			if err != nil {
				t.Fatalf("get scan: %v", err)
			}
			if persisted.Status != scanLifecycleFailed {
				t.Fatalf("expected scan status=failed, got %q", persisted.Status)
			}
			if !strings.Contains(persisted.ErrorMessage, "workspace lifecycle") {
				t.Fatalf("expected workspace lifecycle reason in error, got %q", persisted.ErrorMessage)
			}
		})
	}
}

func TestServiceProcessNextQueuedRepoScanSkipsInactiveWorkspace(t *testing.T) {
	// Round-8 codex P1 mirror of the regular-scan gate: a repo scan
	// queued BEFORE the workspace was suspended/soft-deleted must be
	// refused by the worker, not executed against the paused workspace.
	// ClaimNextQueuedRepoScanAnyScope filters only on
	// repo_scans.status='queued', so the lifecycle gate inside
	// ProcessNextQueuedRepoScan is the authoritative check.
	for _, state := range []string{"suspended", "deleted"} {
		t.Run(state, func(t *testing.T) {
			svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)
			svc.RepoScanEnabled = true
			svc.RepoScanAllowedTargets = []string{"https://github.com/*"}
			record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
				Repository:  "https://github.com/owner/repo",
				MaxFindings: 1,
			})
			if err != nil {
				t.Fatalf("enqueue repo scan: %v", err)
			}

			now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
			switch state {
			case "suspended":
				if _, err := svc.Store.SuspendWorkspace(ctx, "workspace-a", now); err != nil {
					t.Fatalf("suspend: %v", err)
				}
			case "deleted":
				if _, err := svc.Store.SoftDeleteWorkspace(ctx, "workspace-a", now); err != nil {
					t.Fatalf("soft delete: %v", err)
				}
			}

			processed, err := svc.ProcessNextQueuedRepoScan(ctx)
			if err != nil {
				t.Fatalf("process queued repo scan: %v", err)
			}
			if !processed {
				t.Fatal("expected processed=true when skipping an inactive workspace repo scan")
			}

			persisted, err := svc.Store.GetRepoScan(ctx, record.ID)
			if err != nil {
				t.Fatalf("get repo scan: %v", err)
			}
			if persisted.Status != "failed" {
				t.Fatalf("expected repo scan status=failed, got %q", persisted.Status)
			}
			if !strings.Contains(persisted.ErrorMessage, "workspace lifecycle") {
				t.Fatalf("expected workspace lifecycle reason in error, got %q", persisted.ErrorMessage)
			}
		})
	}
}

func TestServiceRequireActiveWorkspaceForConnectorBranches(t *testing.T) {
	// Direct unit test of the helper used by the public Kubernetes
	// agent routes (#1445 round 4 + 5). The integration tests cover
	// the suspended/deleted happy paths via the agent routes; this
	// test pins the remaining branches the integration coverage
	// cannot exercise without a full enrollment fixture:
	//
	//   1. Active workspace → nil (allow).
	//   2. Missing workspace → ErrNotFound, which the agent-route
	//      handler then maps to 404 — exactly the contract for an
	//      unauthenticated probe that forged a locator pointing at a
	//      workspace that never existed.
	//   3. Suspended workspace → ErrKubernetesConnectorWorkspaceInactive,
	//      the inactive-lifecycle gate.
	svc, ctx, _ := setupWorkspaceLifecycleServiceHarness(t)

	if err := svc.requireActiveWorkspaceForConnector(ctx, "tenant-a", "workspace-a"); err != nil {
		t.Fatalf("expected nil for active workspace, got %v", err)
	}
	if err := svc.requireActiveWorkspaceForConnector(ctx, "tenant-a", "nonexistent"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing workspace, got %v", err)
	}
	if _, err := svc.Store.SuspendWorkspace(ctx, "workspace-a", time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("suspend workspace: %v", err)
	}
	if err := svc.requireActiveWorkspaceForConnector(ctx, "tenant-a", "workspace-a"); !errors.Is(err, ErrKubernetesConnectorWorkspaceInactive) {
		t.Fatalf("expected ErrKubernetesConnectorWorkspaceInactive for suspended workspace, got %v", err)
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
