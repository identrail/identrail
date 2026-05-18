package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func setupSessionRouter(t *testing.T) (*ginlessSessionHarness, string, string) {
	t.Helper()
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	scope := db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	scopedCtx := db.WithScope(context.Background(), scope)
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "user@example.com",
		DisplayName:  "User One",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(scopedCtx, db.TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "oidc-subject-a",
		UserUUID:    user.ID,
		Email:       user.PrimaryEmail,
		Role:        "admin",
		Status:      "active",
	}); err != nil {
		t.Fatalf("upsert member: %v", err)
	}

	manager := sessionauth.Manager{Store: store, PublicBaseURL: "http://localhost:8080", Now: svc.Now}
	cookieValue, current, err := manager.CreateSession(context.Background(), db.Session{
		UserID:             user.ID,
		CurrentOrgID:       "tenant-a",
		CurrentWorkspaceID: "workspace-a",
		CurrentProjectID:   "project-a",
		AuthMethod:         "manual",
		IP:                 "127.0.0.1",
		UserAgent:          "test-agent",
	})
	if err != nil {
		t.Fatalf("create current session: %v", err)
	}
	otherCookie, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:             user.ID,
		CurrentOrgID:       "tenant-a",
		CurrentWorkspaceID: "workspace-a",
		CurrentProjectID:   "project-a",
		AuthMethod:         "manual",
		IP:                 "127.0.0.2",
		UserAgent:          "other-agent",
	})
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}
	_ = otherCookie

	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth: true,
		PublicBaseURL:  "http://localhost:8080",
		RateLimitRPM:   1000,
		RateLimitBurst: 1000,
	})
	return &ginlessSessionHarness{router: router, manager: manager}, cookieValue, sessionauth.EncodePublicSessionID(current.ID)
}

type ginlessSessionHarness struct {
	router  http.Handler
	manager sessionauth.Manager
}

func TestCurrentSessionMeAndSessionList(t *testing.T) {
	harness, cookieValue, currentPublicID := setupSessionRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected /v1/me 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"role":"admin"`) || !strings.Contains(w.Body.String(), `"project_id":"project-a"`) {
		t.Fatalf("unexpected /v1/me body: %s", w.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/me/sessions", nil)
	listReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	listW := httptest.NewRecorder()
	harness.router.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected session list 200, got %d body=%s", listW.Code, listW.Body.String())
	}
	if !strings.Contains(listW.Body.String(), currentPublicID) || !strings.Contains(listW.Body.String(), `"current":true`) {
		t.Fatalf("session list did not include current session: %s", listW.Body.String())
	}
}

func TestCookieBackedWorkspaceSwitchUpdatesSessionContext(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 18, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "switcher@example.com",
		DisplayName:  "Workspace Switcher",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	scopeA := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scopeA, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	for _, workspaceID := range []string{"workspace-a", "workspace-b"} {
		scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: workspaceID})
		if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: workspaceID, DisplayName: workspaceID, Slug: workspaceID}); err != nil {
			t.Fatalf("upsert workspace %s: %v", workspaceID, err)
		}
		role := "viewer"
		if workspaceID == "workspace-a" {
			role = "admin"
		}
		if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
			WorkspaceID: workspaceID,
			MemberID:    "member-" + workspaceID,
			UserID:      "switcher-subject",
			UserUUID:    user.ID,
			Email:       user.PrimaryEmail,
			Role:        role,
			Status:      "active",
			JoinedAt:    now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("upsert workspace member %s: %v", workspaceID, err)
		}
	}

	manager := sessionauth.Manager{Store: store, PublicBaseURL: "http://localhost:8080", Now: svc.Now}
	cookieValue, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:             user.ID,
		CurrentOrgID:       "tenant-a",
		CurrentWorkspaceID: "workspace-a",
		AuthMethod:         "manual",
		CreatedAt:          now,
		LastSeenAt:         now,
		IdleExpiresAt:      now.Add(sessionauth.IdleTimeout),
		AbsoluteExpiresAt:  now.Add(sessionauth.AbsoluteTimeout),
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth: true,
		PublicBaseURL:  "http://localhost:8080",
		RateLimitRPM:   1000,
		RateLimitBurst: 1000,
	})

	switchReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces/active", strings.NewReader(`{"workspace_id":"workspace-b"}`))
	switchReq.Header.Set("Content-Type", "application/json")
	switchReq.Header.Set("Origin", "http://localhost:8080")
	switchReq.Header.Set("Content-Type", "application/json")
	switchReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	switchResp := httptest.NewRecorder()
	router.ServeHTTP(switchResp, switchReq)
	if switchResp.Code != http.StatusOK {
		t.Fatalf("expected workspace switch 200, got %d body=%s", switchResp.Code, switchResp.Body.String())
	}
	if !strings.Contains(switchResp.Body.String(), `"workspace_id":"workspace-b"`) {
		t.Fatalf("expected switch response to target workspace-b, got %s", switchResp.Body.String())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	meResp := httptest.NewRecorder()
	router.ServeHTTP(meResp, meReq)
	if meResp.Code != http.StatusOK {
		t.Fatalf("expected /v1/me 200 after switch, got %d body=%s", meResp.Code, meResp.Body.String())
	}
	if !strings.Contains(meResp.Body.String(), `"workspace_id":"workspace-b"`) || !strings.Contains(meResp.Body.String(), `"role":"viewer"`) {
		t.Fatalf("expected session context to persist switched workspace, got %s", meResp.Body.String())
	}
}

func TestManualLoginCreatesCookieBackedSessionWhenEnabled(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 16, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth: true,
		AuthManualMode: true,
		PublicBaseURL:  "http://localhost:8080",
		RateLimitRPM:   1000,
		RateLimitBurst: 1000,
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/manual", strings.NewReader(`{
		"tenant_id":"tenant-a",
		"workspace_id":"workspace-a",
		"project_id":"project-a",
		"email":"dev@example.com",
		"display_name":"Dev User"
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected manual login 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), sessionauth.CookieName+"=") {
		t.Fatalf("expected manual login to set session cookie, got %q", w.Header().Get("Set-Cookie"))
	}
	if !strings.Contains(w.Body.String(), `"redirect_to":"/app/tenant-a/workspace-a/projects/project-a"`) {
		t.Fatalf("unexpected manual login body: %s", w.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionauth.CookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("manual login did not return a parseable session cookie")
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(sessionCookie)
	meW := httptest.NewRecorder()
	router.ServeHTTP(meW, meReq)
	if meW.Code != http.StatusOK {
		t.Fatalf("expected cookie-backed /v1/me 200, got %d body=%s", meW.Code, meW.Body.String())
	}
	if !strings.Contains(meW.Body.String(), `"primary_email":"dev@example.com"`) ||
		!strings.Contains(meW.Body.String(), `"org_id":"tenant-a"`) ||
		!strings.Contains(meW.Body.String(), `"workspace_id":"workspace-a"`) ||
		!strings.Contains(meW.Body.String(), `"project_id":"project-a"`) {
		t.Fatalf("unexpected /v1/me body after manual login: %s", meW.Body.String())
	}
}

func TestManualLoginRejectsNonLoopbackClientUnlessAllowUnsafe(t *testing.T) {
	body := `{"tenant_id":"tenant-a","workspace_id":"workspace-a","email":"dev@example.com"}`
	newRouter := func(allowUnsafe bool) http.Handler {
		store := db.NewMemoryStore()
		svc := NewService(store, fakeScanner{}, "aws")
		return NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
			FeatureNewAuth:            true,
			AuthManualMode:            true,
			AuthManualModeAllowUnsafe: allowUnsafe,
			PublicBaseURL:             "http://localhost:8080",
			RateLimitRPM:              1000,
			RateLimitBurst:            1000,
		})
	}
	post := func(router http.Handler, remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/manual", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// Non-loopback caller is rejected with 403 when the unsafe override is off.
	guarded := newRouter(false)
	if w := post(guarded, "203.0.113.7:40000"); w.Code != http.StatusForbidden {
		t.Fatalf("expected non-loopback manual login to be forbidden, got %d body=%s", w.Code, w.Body.String())
	}
	if w := post(guarded, "[::1]:40000"); w.Code != http.StatusOK {
		t.Fatalf("expected IPv6 loopback manual login to succeed, got %d body=%s", w.Code, w.Body.String())
	}
	if w := post(guarded, "127.0.0.5:40000"); w.Code != http.StatusOK {
		t.Fatalf("expected 127.0.0.0/8 loopback manual login to succeed, got %d body=%s", w.Code, w.Body.String())
	}

	// With the explicit unsafe override (e.g. loopback-published container),
	// a non-loopback client IP is accepted again.
	unsafe := newRouter(true)
	if w := post(unsafe, "203.0.113.7:40000"); w.Code != http.StatusOK {
		t.Fatalf("expected unsafe override to permit non-loopback manual login, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestManualLoginRouteIsHiddenWhenManualModeDisabled(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth: true,
		AuthManualMode: false,
		PublicBaseURL:  "http://localhost:8080",
		RateLimitRPM:   1000,
		RateLimitBurst: 1000,
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/manual", strings.NewReader(`{"tenant_id":"tenant-a","workspace_id":"workspace-a"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected disabled manual login route to be hidden, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestManualLoginRejectsInvalidRequests(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth: true,
		AuthManualMode: true,
		PublicBaseURL:  "http://localhost:8080",
		RateLimitRPM:   1000,
		RateLimitBurst: 1000,
	})

	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "malformed json",
			body: `{"tenant_id":`,
			want: "invalid manual login payload",
		},
		{
			name: "missing workspace",
			body: `{"tenant_id":"tenant-a"}`,
			want: "tenant_id and workspace_id are required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/manual", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "127.0.0.1:54321"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected manual login rejection 400, got %d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tt.want) {
				t.Fatalf("expected rejection body to contain %q, got %s", tt.want, w.Body.String())
			}
		})
	}
}

func TestUpsertManualUserSessionContextDefaultsAndUpdates(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 17, 30, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.UpsertManualUserSessionContext(context.Background(), ManualLoginInput{
		TenantID:    " Tenant!A ",
		WorkspaceID: "Workspace A",
	})
	if err != nil {
		t.Fatalf("manual context with defaults: %v", err)
	}
	if result.User.PrimaryEmail != "manual+tenant-a-workspace-a@local.identrail.test" {
		t.Fatalf("unexpected default manual email: %q", result.User.PrimaryEmail)
	}
	if result.User.DisplayName != "Manual developer" {
		t.Fatalf("unexpected default display name: %q", result.User.DisplayName)
	}
	if result.RedirectPath != "/app/Tenant%21A/Workspace%20A" {
		t.Fatalf("unexpected redirect path: %q", result.RedirectPath)
	}

	updated, err := svc.UpsertManualUserSessionContext(context.Background(), ManualLoginInput{
		TenantID:    "Tenant!A",
		WorkspaceID: "Workspace A",
		Email:       result.User.PrimaryEmail,
		DisplayName: "Updated Manual User",
	})
	if err != nil {
		t.Fatalf("manual context update: %v", err)
	}
	if updated.User.ID != result.User.ID {
		t.Fatalf("expected manual update to keep user %q, got %q", result.User.ID, updated.User.ID)
	}
	if updated.User.DisplayName != "Updated Manual User" {
		t.Fatalf("expected updated display name, got %q", updated.User.DisplayName)
	}
}

func TestCurrentSessionMeAllowsScopelessOnboardingWithExplicitScopeRequired(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 15, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "new-user@example.com",
		DisplayName:  "New User",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	manager := sessionauth.Manager{Store: store, PublicBaseURL: "https://app.identrail.com", Now: svc.Now}
	cookieValue, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:     user.ID,
		AuthMethod: "manual",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:       true,
		PublicBaseURL:        "https://app.identrail.com",
		RequireExplicitScope: true,
		RateLimitRPM:         1000,
		RateLimitBurst:       1000,
	})

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	meW := httptest.NewRecorder()
	router.ServeHTTP(meW, meReq)
	if meW.Code != http.StatusOK {
		t.Fatalf("expected scopeless /v1/me to reach onboarding context, got %d body=%s", meW.Code, meW.Body.String())
	}
	if strings.Contains(meW.Body.String(), "workspace_id") {
		t.Fatalf("expected no workspace in scopeless onboarding context, got %s", meW.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/me/sessions", nil)
	listReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	listW := httptest.NewRecorder()
	router.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected scopeless session list to bypass explicit scope requirement, got %d body=%s", listW.Code, listW.Body.String())
	}
}

func TestCurrentSessionRejectsTamperedCookie(t *testing.T) {
	harness, _, _ := setupSessionRouter(t)
	tampered := base64.RawURLEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: tampered})
	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected tampered cookie 401, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestCurrentSessionRevokeOthersKeepsCurrentSession(t *testing.T) {
	harness, cookieValue, _ := setupSessionRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/me/sessions/revoke-others", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected revoke-others 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"revoked":1`) {
		t.Fatalf("expected one revoked session, got %s", w.Body.String())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	meW := httptest.NewRecorder()
	harness.router.ServeHTTP(meW, meReq)
	if meW.Code != http.StatusOK {
		t.Fatalf("expected current session to survive, got %d body=%s", meW.Code, meW.Body.String())
	}
}

func TestCurrentSessionDeleteCurrentSessionClearsCookie(t *testing.T) {
	harness, cookieValue, currentPublicID := setupSessionRouter(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/me/sessions/"+currentPublicID, nil)
	req.Header.Set("Origin", "http://localhost:8080")
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected current session delete 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), sessionauth.CookieName+"=;") {
		t.Fatalf("expected delete to clear current session cookie, got %q", w.Header().Get("Set-Cookie"))
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	meW := httptest.NewRecorder()
	harness.router.ServeHTTP(meW, meReq)
	if meW.Code != http.StatusUnauthorized {
		t.Fatalf("expected deleted session to be rejected, got %d body=%s", meW.Code, meW.Body.String())
	}
}

func TestLogoutRevokesCurrentSession(t *testing.T) {
	harness, cookieValue, _ := setupSessionRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookieValue})
	w := httptest.NewRecorder()
	harness.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected logout 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), sessionauth.CookieName+"=;") {
		t.Fatalf("expected logout to clear session cookie, got %q", w.Header().Get("Set-Cookie"))
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w = httptest.NewRecorder()
	harness.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected logout without session to be unauthorized, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestCurrentUserContextLoadsUserAndHandlesMissingScopeObjects(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: "scopeless@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	contextSnapshot, err := svc.GetCurrentUserContext(context.Background(), sessionauth.CurrentSession{
		Session: db.Session{UserID: user.ID},
	})
	if err != nil {
		t.Fatalf("get current user context without scope: %v", err)
	}
	if contextSnapshot.User.ID != user.ID || contextSnapshot.Organization != nil || contextSnapshot.Workspace != nil {
		t.Fatalf("unexpected scopeless context: %+v", contextSnapshot)
	}

	scopedContext, err := svc.GetCurrentUserContext(context.Background(), sessionauth.CurrentSession{
		Session: db.Session{
			UserID:             user.ID,
			User:               &user,
			CurrentOrgID:       "missing-tenant",
			CurrentWorkspaceID: "missing-workspace",
		},
	})
	if err != nil {
		t.Fatalf("expected missing tenancy objects to be tolerated, got %v", err)
	}
	if scopedContext.OrgID != "missing-tenant" || scopedContext.WorkspaceID != "missing-workspace" || scopedContext.Role != "" {
		t.Fatalf("unexpected missing-object context: %+v", scopedContext)
	}

	scope := db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	scopedCtx := db.WithScope(context.Background(), scope)
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "legacy-user-a",
		UserUUID:    user.ID,
		Email:       user.PrimaryEmail,
		Role:        "admin",
		Status:      "removed",
	}); err != nil {
		t.Fatalf("upsert removed member: %v", err)
	}
	removedMemberContext, err := svc.GetCurrentUserContext(context.Background(), sessionauth.CurrentSession{
		Session: db.Session{
			UserID:             user.ID,
			User:               &user,
			CurrentOrgID:       "tenant-a",
			CurrentWorkspaceID: "workspace-a",
		},
	})
	if err != nil {
		t.Fatalf("get removed-member context: %v", err)
	}
	if removedMemberContext.Role != "" {
		t.Fatalf("expected removed member role to be omitted, got %+v", removedMemberContext)
	}

	if _, err := (*Service)(nil).GetCurrentUserContext(context.Background(), sessionauth.CurrentSession{}); err == nil {
		t.Fatal("expected nil service to fail")
	}
	if _, err := (*Service)(nil).ListCurrentUserSessions(context.Background(), sessionauth.CurrentSession{}); err == nil {
		t.Fatal("expected nil service session list to fail")
	}
}
