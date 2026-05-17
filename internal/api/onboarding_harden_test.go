package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
)

// scopedOnboardingRequest is onboardingRequest plus the explicit tenant and
// workspace scope headers the product-shell APIs require.
func scopedOnboardingRequest(router http.Handler, cookieValue, method, path, body, tenantID, workspaceID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Identrail-Tenant-ID", tenantID)
	req.Header.Set("X-Identrail-Workspace-ID", workspaceID)
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func decodeOnboarding(t *testing.T, w *httptest.ResponseRecorder) OnboardingStateResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var body OnboardingStateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode onboarding response: %v body=%s", err, w.Body.String())
	}
	return body
}

// A brand-new user must be able to go all the way from no workspace to a
// usable, scoped workspace: /v1/me, the workspaces list, the members list, and
// the projects list must all agree, and completion must redirect into the
// scoped app. Re-running start must not fork a second tenant/workspace.
func TestOnboardingFirstUseProducesUsableWorkspace(t *testing.T) {
	store, router, cookie := setupOnboardingRouter(t, true)

	decodeOnboarding(t, onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/start", ""))
	orgResp := decodeOnboarding(t, onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/state",
		`{"current_step":"org","org_name":"Aurelius Security"}`))
	orgID := orgResp.State.OrgID
	if orgID == "" || orgResp.State.CurrentStep != "workspace" {
		t.Fatalf("unexpected org step: %+v", orgResp.State)
	}

	wsResp := decodeOnboarding(t, onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/state",
		`{"current_step":"workspace","workspace_name":"Production"}`))
	if wsResp.State.WorkspaceID != "production" || wsResp.State.ProjectID != "production" {
		t.Fatalf("unexpected workspace step: %+v", wsResp.State)
	}

	me := onboardingRequest(router, cookie, http.MethodGet, "/v1/me", "")
	if me.Code != http.StatusOK {
		t.Fatalf("/v1/me status %d body=%s", me.Code, me.Body.String())
	}
	for _, want := range []string{`"org_id":"` + orgID + `"`, `"workspace_id":"production"`, `"project_id":"production"`, `"role":"owner"`} {
		if !strings.Contains(me.Body.String(), want) {
			t.Fatalf("/v1/me missing %s: %s", want, me.Body.String())
		}
	}

	workspaces := scopedOnboardingRequest(router, cookie, http.MethodGet, "/v1/workspaces", "", orgID, "production")
	if workspaces.Code != http.StatusOK || !strings.Contains(workspaces.Body.String(), `"workspace_id":"production"`) {
		t.Fatalf("workspaces list missing onboarded workspace: %d %s", workspaces.Code, workspaces.Body.String())
	}

	members := scopedOnboardingRequest(router, cookie, http.MethodGet, "/v1/workspaces/production/members", "", orgID, "production")
	if members.Code != http.StatusOK {
		t.Fatalf("members list status %d body=%s", members.Code, members.Body.String())
	}
	if !strings.Contains(members.Body.String(), `"role":"owner"`) || !strings.Contains(members.Body.String(), `"status":"active"`) {
		t.Fatalf("members list does not show active owner: %s", members.Body.String())
	}

	projects := scopedOnboardingRequest(router, cookie, http.MethodGet, "/v1/workspaces/production/projects", "", orgID, "production")
	if projects.Code != http.StatusOK || !strings.Contains(projects.Body.String(), `"project_id":"production"`) {
		t.Fatalf("projects list missing default project: %d %s", projects.Code, projects.Body.String())
	}

	complete := decodeOnboarding(t, onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/complete", ""))
	if complete.RedirectPath != "/app/"+orgID+"/production" {
		t.Fatalf("expected scoped app redirect, got %q", complete.RedirectPath)
	}

	// Re-running start for the same user must resume, not fork a new tenant.
	resume := decodeOnboarding(t, onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/start", ""))
	if resume.State.OrgID != orgID || resume.State.WorkspaceID != "production" {
		t.Fatalf("resume forked scope: %+v", resume.State)
	}
	if _, err := store.GetOrganization(db.WithScope(context.Background(), db.Scope{TenantID: orgID, WorkspaceID: db.DefaultWorkspaceID})); err != nil {
		t.Fatalf("original organization missing after resume: %v", err)
	}
}

// Editing the organization name again before the workspace exists is a normal
// first-use action (the user corrects a typo on the org screen). It must not be
// rejected as a workspace-access violation.
func TestOnboardingOrgStepReeditAllowedBeforeWorkspace(t *testing.T) {
	store, router, cookie := setupOnboardingRouter(t, true)

	decodeOnboarding(t, onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/start", ""))
	first := decodeOnboarding(t, onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/state",
		`{"current_step":"org","org_name":"Typo Inc"}`))
	orgID := first.State.OrgID

	reedit := onboardingRequest(router, cookie, http.MethodPost, "/v1/onboarding/state",
		`{"current_step":"org","org_name":"Aurelius Security"}`)
	if reedit.Code != http.StatusOK {
		t.Fatalf("expected org re-edit to succeed, got %d body=%s", reedit.Code, reedit.Body.String())
	}
	body := decodeOnboarding(t, reedit)
	if body.State.OrgID != orgID {
		t.Fatalf("org re-edit must not fork the tenant: was %q now %q", orgID, body.State.OrgID)
	}

	org, err := store.GetOrganization(db.WithScope(context.Background(), db.Scope{TenantID: orgID, WorkspaceID: db.DefaultWorkspaceID}))
	if err != nil {
		t.Fatalf("get organization: %v", err)
	}
	if org.DisplayName != "Aurelius Security" {
		t.Fatalf("expected updated display name, got %q", org.DisplayName)
	}
}

// If the user already has an active workspace membership but their onboarding
// row is still an empty "org" step (e.g. a partial first attempt, or admin
// pre-provisioned them), start must reconcile onto the existing workspace
// instead of sending them back to create a duplicate tenant/workspace.
func TestStartOnboardingReconcilesIncompleteStateWithExistingWorkspace(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "rejoin@example.com",
		DisplayName:  "Rejoin",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	scoped := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scoped, db.TenancyOrganization{TenantID: "tenant-a", DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(scoped, db.TenancyWorkspace{TenantID: "tenant-a", WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(scoped, db.TenancyProject{TenantID: "tenant-a", WorkspaceID: "workspace-a", ProjectID: "default", Name: "Default", Slug: "default"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scoped, db.TenancyWorkspaceMember{
		TenantID: "tenant-a", WorkspaceID: "workspace-a", MemberID: "member-rejoin",
		UserID: user.ID, UserUUID: user.ID, Email: user.PrimaryEmail, Role: "owner", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert member: %v", err)
	}
	// Seed a stale, unbound onboarding state for this user.
	if _, err := store.UpsertOnboardingState(context.Background(), db.OnboardingState{
		UserID: user.ID, CurrentStep: "org", StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed onboarding state: %v", err)
	}

	resp, err := svc.StartOnboarding(context.Background(), sessionauth.CurrentSession{
		IDHash:  []byte("session-hash"),
		Session: db.Session{UserID: user.ID, AuthMethod: "manual"},
	})
	if err != nil {
		t.Fatalf("start onboarding: %v", err)
	}
	if resp.State.OrgID != "tenant-a" || resp.State.WorkspaceID != "workspace-a" {
		t.Fatalf("expected reconciliation onto existing workspace, got %+v", resp.State)
	}
	if resp.State.CurrentStep == onboardingStepOrg {
		t.Fatalf("expected resume past the org step, got %q", resp.State.CurrentStep)
	}

	// Idempotent: a second start must not change scope or fork records.
	again, err := svc.StartOnboarding(context.Background(), sessionauth.CurrentSession{
		IDHash:  []byte("session-hash"),
		Session: db.Session{UserID: user.ID, AuthMethod: "manual"},
	})
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if again.State.OrgID != "tenant-a" || again.State.WorkspaceID != "workspace-a" {
		t.Fatalf("second start changed scope: %+v", again.State)
	}
}

// A user whose only membership in the tenant has been deactivated/removed is
// no longer a member. With stale onboarding state they must NOT be able to
// re-edit (rename) the organization, even though no *active* membership row is
// returned.
func TestOnboardingOrgStepDeniesRevokedMemberRename(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "revoked@example.com",
		DisplayName:  "Revoked",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	scoped := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scoped, db.TenancyOrganization{TenantID: "tenant-a", DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(scoped, db.TenancyWorkspace{TenantID: "tenant-a", WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scoped, db.TenancyWorkspaceMember{
		TenantID: "tenant-a", WorkspaceID: "workspace-a", MemberID: "member-revoked",
		UserID: user.ID, UserUUID: user.ID, Email: user.PrimaryEmail, Role: "owner", Status: "removed", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert member: %v", err)
	}
	// Stale onboarding row already bound to the tenant (so the org step is a
	// repeat write), but no active membership remains.
	if _, err := store.UpsertOnboardingState(context.Background(), db.OnboardingState{
		UserID: user.ID, CurrentStep: onboardingStepWorkspace, OrgID: "tenant-a", StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed onboarding state: %v", err)
	}

	_, err = svc.UpdateOnboardingState(context.Background(), sessionauth.CurrentSession{
		IDHash:  []byte("session-hash"),
		Session: db.Session{UserID: user.ID, AuthMethod: "manual"},
	}, OnboardingStateUpdateRequest{CurrentStep: "org", OrgName: "Hijacked Name"})
	if !errors.Is(err, ErrOnboardingWorkspaceAccessDenied) {
		t.Fatalf("expected revoked member to be denied org rename, got %v", err)
	}
	org, getErr := store.GetOrganization(db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: db.DefaultWorkspaceID}))
	if getErr != nil {
		t.Fatalf("get organization: %v", getErr)
	}
	if org.DisplayName != "Tenant A" {
		t.Fatalf("organization name must be unchanged, got %q", org.DisplayName)
	}
}

// A user who is only a viewer in their newest workspace but still an owner in
// an earlier workspace of the same tenant must still be allowed to re-edit the
// organization (membership creation order must not decide authorization).
func TestOnboardingOrgStepAllowsAdminInAnotherWorkspace(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "multi@example.com",
		DisplayName:  "Multi",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	owned := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "owned-ws"})
	viewed := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "viewed-ws"})
	if err := store.UpsertOrganization(owned, db.TenancyOrganization{TenantID: "tenant-a", DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(owned, db.TenancyWorkspace{TenantID: "tenant-a", WorkspaceID: "owned-ws", DisplayName: "Owned", Slug: "owned"}); err != nil {
		t.Fatalf("upsert owned workspace: %v", err)
	}
	if err := store.UpsertWorkspace(viewed, db.TenancyWorkspace{TenantID: "tenant-a", WorkspaceID: "viewed-ws", DisplayName: "Viewed", Slug: "viewed"}); err != nil {
		t.Fatalf("upsert viewed workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(owned, db.TenancyWorkspaceMember{
		TenantID: "tenant-a", WorkspaceID: "owned-ws", MemberID: "member-owner",
		UserID: user.ID, UserUUID: user.ID, Email: user.PrimaryEmail, Role: "owner", Status: "active",
		JoinedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("upsert owner member: %v", err)
	}
	if err := store.UpsertWorkspaceMember(viewed, db.TenancyWorkspaceMember{
		TenantID: "tenant-a", WorkspaceID: "viewed-ws", MemberID: "member-viewer",
		UserID: user.ID, UserUUID: user.ID, Email: user.PrimaryEmail, Role: "viewer", Status: "active",
		JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert viewer member: %v", err)
	}
	if _, err := store.UpsertOnboardingState(context.Background(), db.OnboardingState{
		UserID: user.ID, CurrentStep: onboardingStepWorkspace, OrgID: "tenant-a", StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed onboarding state: %v", err)
	}

	resp, err := svc.UpdateOnboardingState(context.Background(), sessionauth.CurrentSession{
		IDHash:  []byte("session-hash"),
		Session: db.Session{UserID: user.ID, AuthMethod: "manual"},
	}, OnboardingStateUpdateRequest{CurrentStep: "org", OrgName: "Renamed By Owner"})
	if err != nil {
		t.Fatalf("expected owner-in-another-workspace to be allowed, got %v", err)
	}
	if resp.State.OrgID != "tenant-a" {
		t.Fatalf("org re-edit must not fork the tenant: %+v", resp.State)
	}
	org, getErr := store.GetOrganization(db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: db.DefaultWorkspaceID}))
	if getErr != nil {
		t.Fatalf("get organization: %v", getErr)
	}
	if org.DisplayName != "Renamed By Owner" {
		t.Fatalf("expected updated display name, got %q", org.DisplayName)
	}
}
