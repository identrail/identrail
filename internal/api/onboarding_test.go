package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func setupOnboardingRouter(t *testing.T, featureEnabled bool) (*db.MemoryStore, http.Handler, string) {
	t.Helper()
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "founder@example.com",
		DisplayName:  "Founder",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	manager := sessionauth.Manager{Store: store, PublicBaseURL: "https://app.identrail.com", Now: svc.Now}
	cookieValue, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:     user.ID,
		AuthMethod: "manual",
		IP:         "127.0.0.1",
		UserAgent:  "onboarding-test",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:          true,
		FeatureOnboardingWizard: featureEnabled,
		PublicBaseURL:           "https://app.identrail.com",
		RequireExplicitScope:    true,
		RateLimitRPM:            1000,
		RateLimitBurst:          1000,
	})
	return store, router, cookieValue
}

func onboardingRequest(router http.Handler, cookieValue string, method string, path string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// Simulate a real browser: the SPA always sends a first-party Origin on
	// session-authenticated writes, which the browser-write CSRF guard
	// requires.
	req.Header.Set("Origin", "https://app.identrail.com")
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestOnboardingRoutesReturnJSONWhenFeatureDisabled(t *testing.T) {
	_, router, cookieValue := setupOnboardingRouter(t, false)

	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "/v1/onboarding/start", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated onboarding request 401, got %d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}
	if !strings.Contains(unauthenticated.Body.String(), `"error":"unauthorized"`) {
		t.Fatalf("expected JSON unauthorized error, got %s", unauthenticated.Body.String())
	}

	w := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/start", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected disabled onboarding route to return 503 JSON, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"error":"onboarding disabled"`) {
		t.Fatalf("expected disabled onboarding error, got %s", w.Body.String())
	}
}

func TestOnboardingCreatesWorkspaceAndSessionScope(t *testing.T) {
	store, router, cookieValue := setupOnboardingRouter(t, true)

	start := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/start", "")
	if start.Code != http.StatusOK {
		t.Fatalf("expected start 200, got %d body=%s", start.Code, start.Body.String())
	}
	if !strings.Contains(start.Body.String(), `"current_step":"org"`) {
		t.Fatalf("expected org step, got %s", start.Body.String())
	}

	org := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"org","org_name":"Aurelius Security"}`)
	if org.Code != http.StatusOK {
		t.Fatalf("expected org update 200, got %d body=%s", org.Code, org.Body.String())
	}
	var orgBody OnboardingStateResponse
	if err := json.Unmarshal(org.Body.Bytes(), &orgBody); err != nil {
		t.Fatalf("decode org response: %v", err)
	}
	if orgBody.State.CurrentStep != "workspace" || !strings.HasPrefix(orgBody.State.OrgID, "aurelius-security-") {
		t.Fatalf("unexpected org response: %+v", orgBody.State)
	}
	organization, err := store.GetOrganization(db.WithScope(context.Background(), db.Scope{
		TenantID:    orgBody.State.OrgID,
		WorkspaceID: db.DefaultWorkspaceID,
	}))
	if err != nil {
		t.Fatalf("get organization: %v", err)
	}
	if organization.Slug == "aurelius-security" || !strings.HasPrefix(organization.Slug, "aurelius-security-") {
		t.Fatalf("expected generated organization slug to carry unique suffix, got %q", organization.Slug)
	}

	workspace := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"workspace","workspace_name":"Production"}`)
	if workspace.Code != http.StatusOK {
		t.Fatalf("expected workspace update 200, got %d body=%s", workspace.Code, workspace.Body.String())
	}
	var workspaceBody OnboardingStateResponse
	if err := json.Unmarshal(workspace.Body.Bytes(), &workspaceBody); err != nil {
		t.Fatalf("decode workspace response: %v", err)
	}
	if workspaceBody.State.CurrentStep != "connect" || workspaceBody.State.WorkspaceID != "production" || workspaceBody.State.ProjectID != "production" {
		t.Fatalf("unexpected workspace response: %+v", workspaceBody.State)
	}

	me := onboardingRequest(router, cookieValue, http.MethodGet, "/v1/me", "")
	if me.Code != http.StatusOK {
		t.Fatalf("expected /me 200, got %d body=%s", me.Code, me.Body.String())
	}
	if !strings.Contains(me.Body.String(), `"workspace_id":"production"`) ||
		!strings.Contains(me.Body.String(), `"project_id":"production"`) ||
		!strings.Contains(me.Body.String(), `"role":"owner"`) {
		t.Fatalf("expected owner session context after onboarding workspace, got %s", me.Body.String())
	}
}

func TestStartOnboardingExistingWorkspaceWithoutProjectReturnsWorkspaceStep(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "workspace-only@example.com",
		DisplayName:  "Workspace Only",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}

	response, err := svc.StartOnboarding(context.Background(), sessionauth.CurrentSession{
		IDHash: []byte("session-hash"),
		Session: db.Session{
			UserID:             user.ID,
			CurrentOrgID:       "tenant-a",
			CurrentWorkspaceID: "workspace-a",
			AuthMethod:         "manual",
		},
	})
	if err != nil {
		t.Fatalf("start onboarding: %v", err)
	}
	if response.State.CurrentStep != "workspace" || response.RedirectPath != "/onboarding/workspace" {
		t.Fatalf("expected workspace repair step, got %+v", response)
	}
	if response.State.ProjectID != "" {
		t.Fatalf("expected project to remain unset until workspace step, got %q", response.State.ProjectID)
	}
}

func TestOnboardingRejectsExistingViewerWrites(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "viewer@example.com",
		DisplayName:  "Viewer",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		MemberID:    "member-viewer",
		UserID:      user.ID,
		UserUUID:    user.ID,
		Email:       user.PrimaryEmail,
		Role:        "viewer",
		Status:      "active",
	}); err != nil {
		t.Fatalf("upsert member: %v", err)
	}
	manager := sessionauth.Manager{Store: store, PublicBaseURL: "https://app.identrail.com", Now: svc.Now}
	cookieValue, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:             user.ID,
		AuthMethod:         "manual",
		CurrentOrgID:       "tenant-a",
		CurrentWorkspaceID: "workspace-a",
		IP:                 "127.0.0.1",
		UserAgent:          "onboarding-test",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:          true,
		FeatureOnboardingWizard: true,
		PublicBaseURL:           "https://app.identrail.com",
		RequireExplicitScope:    true,
		RateLimitRPM:            1000,
		RateLimitBurst:          1000,
	})

	org := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"org","org_name":"Changed","org_slug":"changed"}`)
	if org.Code != http.StatusForbidden {
		t.Fatalf("expected existing viewer org step 403, got %d body=%s", org.Code, org.Body.String())
	}
	organization, err := store.GetOrganization(scopedCtx)
	if err != nil {
		t.Fatalf("get organization: %v", err)
	}
	if organization.DisplayName != "Tenant A" || organization.Slug != "tenant-a" {
		t.Fatalf("expected organization metadata to be preserved, got %+v", organization)
	}

	workspace := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"workspace","workspace_name":"Production"}`)
	if workspace.Code != http.StatusForbidden {
		t.Fatalf("expected existing viewer workspace step 403, got %d body=%s", workspace.Code, workspace.Body.String())
	}
	member, err := store.GetWorkspaceMemberByUserUUID(scopedCtx, "workspace-a", user.ID)
	if err != nil {
		t.Fatalf("get member: %v", err)
	}
	if member.Role != "viewer" {
		t.Fatalf("expected viewer role to be preserved, got %q", member.Role)
	}
}

func TestOnboardingSkipAndCompletePersistsState(t *testing.T) {
	store, router, cookieValue := setupOnboardingRouter(t, true)
	if w := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"org","org_name":"Aurelius Security"}`); w.Code != http.StatusOK {
		t.Fatalf("expected org update 200, got %d body=%s", w.Code, w.Body.String())
	}
	if w := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"workspace","workspace_name":"Production"}`); w.Code != http.StatusOK {
		t.Fatalf("expected workspace update 200, got %d body=%s", w.Code, w.Body.String())
	}
	connect := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"connect","connector_skipped":true}`)
	if connect.Code != http.StatusOK {
		t.Fatalf("expected connect skip 200, got %d body=%s", connect.Code, connect.Body.String())
	}
	scan := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{"current_step":"scan"}`)
	if scan.Code != http.StatusOK {
		t.Fatalf("expected scan skip 200, got %d body=%s", scan.Code, scan.Body.String())
	}
	complete := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/complete", "")
	if complete.Code != http.StatusOK {
		t.Fatalf("expected complete 200, got %d body=%s", complete.Code, complete.Body.String())
	}
	var completeBody OnboardingStateResponse
	if err := json.Unmarshal(complete.Body.Bytes(), &completeBody); err != nil {
		t.Fatalf("decode complete response: %v", err)
	}
	if completeBody.State.CurrentStep != "complete" || completeBody.State.CompletedAt == nil || completeBody.RedirectPath == "" {
		t.Fatalf("unexpected complete response: %+v", completeBody)
	}
	state, err := store.GetOnboardingState(context.Background(), completeBody.State.UserID)
	if err != nil {
		t.Fatalf("get persisted state: %v", err)
	}
	if !state.ConnectorSkipped || !state.ScanSkipped {
		t.Fatalf("expected skip decisions to persist, got %+v", state)
	}
}

func TestOnboardingGetStateAndDashboardDismissal(t *testing.T) {
	_, router, cookieValue := setupOnboardingRouter(t, true)

	start := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/start", "")
	if start.Code != http.StatusOK {
		t.Fatalf("expected start 200, got %d body=%s", start.Code, start.Body.String())
	}
	getState := onboardingRequest(router, cookieValue, http.MethodGet, "/v1/onboarding/state", "")
	if getState.Code != http.StatusOK {
		t.Fatalf("expected get state 200, got %d body=%s", getState.Code, getState.Body.String())
	}
	var body OnboardingStateResponse
	if err := json.Unmarshal(getState.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode get state: %v", err)
	}
	if body.State.CurrentStep != "org" || body.RedirectPath != "/onboarding/org" {
		t.Fatalf("unexpected initial state: %+v", body)
	}

	update := onboardingRequest(
		router,
		cookieValue,
		http.MethodPost,
		"/v1/onboarding/state",
		`{"connector_type":"github","connector_id":"conn-1","dashboard_tour_dismissed":true}`,
	)
	if update.Code != http.StatusOK {
		t.Fatalf("expected metadata update 200, got %d body=%s", update.Code, update.Body.String())
	}
	if err := json.Unmarshal(update.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode metadata update: %v", err)
	}
	if body.State.ConnectorType != "github" || body.State.ConnectorID != "conn-1" || body.State.DashboardTourDismissedAt == nil {
		t.Fatalf("expected connector metadata and dismissed tour, got %+v", body.State)
	}
}

func TestOnboardingRejectsInvalidRequests(t *testing.T) {
	_, router, cookieValue := setupOnboardingRouter(t, true)

	cases := []struct {
		name string
		body string
	}{
		{name: "missing organization name", body: `{"current_step":"org"}`},
		{name: "unsupported step", body: `{"current_step":"billing"}`},
		{name: "unsupported connector", body: `{"connector_type":"bitbucket"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}

	w := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/state", `{`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid JSON 400, got %d body=%s", w.Code, w.Body.String())
	}
	complete := onboardingRequest(router, cookieValue, http.MethodPost, "/v1/onboarding/complete", "")
	if complete.Code != http.StatusBadRequest {
		t.Fatalf("expected incomplete onboarding 400, got %d body=%s", complete.Code, complete.Body.String())
	}
}

func TestOnboardingRoutesRequireSessionAndService(t *testing.T) {
	store := db.NewMemoryStore()
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), NewService(store, fakeScanner{}, "aws"), RouterOptions{
		FeatureNewAuth:          true,
		FeatureOnboardingWizard: true,
		PublicBaseURL:           "https://app.identrail.com",
		RateLimitRPM:            1000,
		RateLimitBurst:          1000,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/onboarding/start", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated onboarding request 401, got %d body=%s", w.Code, w.Body.String())
	}

	serviceUnavailable := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(serviceUnavailable)
	if requireOnboardingService(c, nil) {
		t.Fatal("expected nil onboarding service to fail")
	}
	if serviceUnavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable onboarding service 503, got %d body=%s", serviceUnavailable.Code, serviceUnavailable.Body.String())
	}

	featureDisabled := httptest.NewRecorder()
	c, _ = gin.CreateTestContext(featureDisabled)
	if requireOnboardingFeature(c, false) {
		t.Fatal("expected disabled onboarding feature to fail")
	}
	if featureDisabled.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected disabled onboarding feature 503, got %d body=%s", featureDisabled.Code, featureDisabled.Body.String())
	}
}

func TestOnboardingRedirectPathEscapesScopedAppTarget(t *testing.T) {
	complete := onboardingRedirectPath(db.OnboardingState{
		CurrentStep: onboardingStepComplete,
		OrgID:       "tenant/with slash",
		WorkspaceID: "prod space",
	})
	if complete != "/app/tenant%2Fwith%20slash/prod%20space" {
		t.Fatalf("expected escaped app path, got %q", complete)
	}
	if path := onboardingRedirectPath(db.OnboardingState{CurrentStep: onboardingStepComplete}); path != "/app" {
		t.Fatalf("expected bare app path, got %q", path)
	}
	if path := onboardingRedirectPath(db.OnboardingState{CurrentStep: "unknown"}); path != "/onboarding/org" {
		t.Fatalf("expected org fallback, got %q", path)
	}
	if path := onboardingRedirectPath(db.OnboardingState{CurrentStep: onboardingStepInvite}); path != "/onboarding/invite" {
		t.Fatalf("expected invite route, got %q", path)
	}
}

func TestOnboardingStepForExistingWorkspaceBranches(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := context.Background()
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	projectID := "existing-project"
	if step := onboardingStepForExistingWorkspace(ctx, store, "tenant-a", "workspace-a", &projectID); step != onboardingStepConnect {
		t.Fatalf("expected connect step with explicit project, got %q", step)
	}
	projectID = ""
	if step := onboardingStepForExistingWorkspace(ctx, store, "", "workspace-a", &projectID); step != onboardingStepOrg {
		t.Fatalf("expected org step without tenant, got %q", step)
	}
	if step := onboardingStepForExistingWorkspace(ctx, store, "tenant-a", "workspace-a", nil); step != onboardingStepWorkspace {
		t.Fatalf("expected workspace step without project, got %q", step)
	}
	if err := store.UpsertProject(scopedCtx, db.TenancyProject{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Name:        "Project A",
		Slug:        "project-a",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	projectID = ""
	if step := onboardingStepForExistingWorkspace(ctx, store, "tenant-a", "workspace-a", &projectID); step != onboardingStepConnect || projectID != "project-a" {
		t.Fatalf("expected discovered project connect step, got step=%q project=%q", step, projectID)
	}
}

func TestOnboardingMemberIDFallback(t *testing.T) {
	memberID := onboardingMemberID("")
	if !strings.HasPrefix(memberID, "member-") || len(strings.TrimPrefix(memberID, "member-")) != 12 {
		t.Fatalf("expected generated member id, got %q", memberID)
	}
}

func TestOnboardingGeneratedOrganizationSlugKeepsUniqueSuffix(t *testing.T) {
	slug := onboardingGeneratedOrganizationSlug(strings.Repeat("a", 100), "org-abcdef12")
	if len(slug) > 64 {
		t.Fatalf("expected slug length <= 64, got %d for %q", len(slug), slug)
	}
	if !strings.HasSuffix(slug, "-abcdef12") {
		t.Fatalf("expected slug to keep generated token suffix, got %q", slug)
	}
}
