package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

type fakeWorkOSClient struct {
	authorizationInput sessionauth.WorkOSAuthorizationRequest
	authentication     sessionauth.WorkOSAuthentication
	authURLErr         error
	err                error
}

func (f *fakeWorkOSClient) AuthorizationURL(input sessionauth.WorkOSAuthorizationRequest) (string, error) {
	f.authorizationInput = input
	if f.authURLErr != nil {
		return "", f.authURLErr
	}
	values := url.Values{}
	values.Set("state", input.State)
	values.Set("redirect_uri", input.RedirectURI)
	if input.ScreenHint != "" {
		values.Set("screen_hint", input.ScreenHint)
	}
	return "https://authkit.example/authorize?" + values.Encode(), nil
}

func (f *fakeWorkOSClient) AuthenticateWithCode(ctx context.Context, input sessionauth.WorkOSAuthenticationRequest) (sessionauth.WorkOSAuthentication, error) {
	if f.err != nil {
		return sessionauth.WorkOSAuthentication{}, f.err
	}
	return f.authentication, nil
}

func TestWorkOSHostedLoginCreatesSessionAndIdentity(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	workOS := &fakeWorkOSClient{
		authentication: sessionauth.WorkOSAuthentication{
			User: sessionauth.WorkOSProfile{
				ID:                "user_workos_1",
				Email:             "new@example.com",
				FirstName:         "New",
				LastName:          "User",
				EmailVerified:     true,
				ProfilePictureURL: "https://cdn.example/avatar.png",
			},
			AuthenticationMethod: "GitHubOAuth",
		},
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    workOS,
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})

	configResp := httptest.NewRecorder()
	router.ServeHTTP(configResp, httptest.NewRequest(http.MethodGet, "/v1/auth/config", nil))
	if configResp.Code != http.StatusOK || !strings.Contains(configResp.Body.String(), `"workos_login_enabled":true`) {
		t.Fatalf("unexpected auth config response: code=%d body=%s", configResp.Code, configResp.Body.String())
	}

	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/app/welcome", nil))
	if startResp.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	if workOS.authorizationInput.RedirectURI != "https://app.identrail.test/auth/callback" {
		t.Fatalf("unexpected callback url: %q", workOS.authorizationInput.RedirectURI)
	}

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(workOS.authorizationInput.State), nil)
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, callbackReq)
	if callbackResp.Code != http.StatusFound {
		t.Fatalf("expected callback redirect, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
	if got := callbackResp.Header().Get("Location"); got != "/app/welcome" {
		t.Fatalf("unexpected post-login redirect: %q", got)
	}
	if callbackResp.Result().Cookies()[0].Name != sessionauth.CookieName {
		t.Fatalf("expected session cookie, got %+v", callbackResp.Result().Cookies())
	}
	identity, err := store.GetUserIdentity(context.Background(), sessionauth.WorkOSProvider, "user_workos_1")
	if err != nil {
		t.Fatalf("expected workos identity: %v", err)
	}
	user, err := store.GetUser(context.Background(), identity.UserID)
	if err != nil {
		t.Fatalf("expected workos user: %v", err)
	}
	if user.PrimaryEmail != "new@example.com" || user.DisplayName != "New User" {
		t.Fatalf("unexpected user: %+v", user)
	}
}

func TestWorkOSCallbackPreservesSelectedOrganization(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{PrimaryEmail: "multi@example.com", DisplayName: "Multi Org"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_multi",
		Email:               "multi@example.com",
		LastAuthenticatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	tenantA := db.WithScope(ctx, db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(tenantA, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed tenant a: %v", err)
	}
	if err := store.UpsertWorkspace(tenantA, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("seed workspace a: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantA, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "subject-a",
		UserUUID:    user.ID,
		Email:       "multi@example.com",
		Role:        "admin",
		Status:      "active",
		JoinedAt:    now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed member a: %v", err)
	}
	tenantB := db.WithScope(ctx, db.Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	if err := store.UpsertOrganization(tenantB, db.TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("seed tenant b: %v", err)
	}
	if err := store.UpsertWorkspace(tenantB, db.TenancyWorkspace{WorkspaceID: "workspace-b", DisplayName: "Workspace B", Slug: "workspace-b"}); err != nil {
		t.Fatalf("seed workspace b: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantB, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-b",
		MemberID:    "member-b",
		UserID:      "subject-b",
		UserUUID:    user.ID,
		Email:       "multi@example.com",
		Role:        "viewer",
		Status:      "active",
		JoinedAt:    now,
	}); err != nil {
		t.Fatalf("seed member b: %v", err)
	}
	workOS := &fakeWorkOSClient{
		authentication: sessionauth.WorkOSAuthentication{
			User: sessionauth.WorkOSProfile{
				ID:            "user_workos_multi",
				Email:         "multi@example.com",
				EmailVerified: true,
			},
			OrganizationID:       "tenant-a",
			AuthenticationMethod: "GitHubOAuth",
		},
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    workOS,
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(workOS.authorizationInput.State), nil)
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, callbackReq)
	if callbackResp.Code != http.StatusFound {
		t.Fatalf("expected callback redirect, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
	if got := callbackResp.Header().Get("Location"); got != "/app/tenant-a/workspace-a" {
		t.Fatalf("expected selected organization redirect, got %q", got)
	}
	cookies := callbackResp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(cookies[0])
	meResp := httptest.NewRecorder()
	router.ServeHTTP(meResp, meReq)
	if meResp.Code != http.StatusOK {
		t.Fatalf("expected me response 200, got %d body=%s", meResp.Code, meResp.Body.String())
	}
	if body := meResp.Body.String(); !strings.Contains(body, `"org_id":"tenant-a"`) || !strings.Contains(body, `"workspace_id":"workspace-a"`) {
		t.Fatalf("expected session to preserve selected org context, got %s", body)
	}
}

func TestWorkOSStartHandlesUnavailableServiceAndProvider(t *testing.T) {
	routerWithoutService := NewRouter(zap.NewNop(), telemetry.NewMetrics(), nil, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    &fakeWorkOSClient{},
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	noServiceResp := httptest.NewRecorder()
	routerWithoutService.ServeHTTP(noServiceResp, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if noServiceResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected no service 503, got %d", noServiceResp.Code)
	}

	routerWithProviderFailure := NewRouter(zap.NewNop(), telemetry.NewMetrics(), NewService(db.NewMemoryStore(), fakeScanner{}, "aws"), RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    &fakeWorkOSClient{authURLErr: sessionauth.ErrWorkOSUnavailable},
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	providerResp := httptest.NewRecorder()
	routerWithProviderFailure.ServeHTTP(providerResp, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if providerResp.Code != http.StatusServiceUnavailable || providerResp.Header().Get("Retry-After") == "" {
		t.Fatalf("expected provider 503 with retry header, got %d headers=%v", providerResp.Code, providerResp.Header())
	}
}

func TestWorkOSCallbackRejectsEmailIdentityConflict(t *testing.T) {
	store := db.NewMemoryStore()
	if _, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "taken@example.com"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	svc := NewService(store, fakeScanner{}, "aws")
	workOS := &fakeWorkOSClient{authentication: sessionauth.WorkOSAuthentication{
		User: sessionauth.WorkOSProfile{ID: "user_workos_2", Email: "taken@example.com", EmailVerified: true},
	}}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    workOS,
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(workOS.authorizationInput.State), nil))
	if callbackResp.Code != http.StatusConflict {
		t.Fatalf("expected identity conflict, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
}

func TestWorkOSSignupUsesScreenHintAndFallsBackToOnboarding(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	workOS := &fakeWorkOSClient{authentication: sessionauth.WorkOSAuthentication{
		User: sessionauth.WorkOSProfile{ID: "user_workos_signup", Email: "signup@example.com", EmailVerified: true},
	}}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    workOS,
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/signup?return_to=https://evil.example/app", nil))
	if startResp.Code != http.StatusFound {
		t.Fatalf("expected signup redirect, got %d", startResp.Code)
	}
	if workOS.authorizationInput.ScreenHint != "sign-up" {
		t.Fatalf("expected signup screen hint, got %q", workOS.authorizationInput.ScreenHint)
	}
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(workOS.authorizationInput.State), nil))
	if callbackResp.Code != http.StatusFound {
		t.Fatalf("expected callback redirect, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
	if got := callbackResp.Header().Get("Location"); got != "/onboarding/org" {
		t.Fatalf("expected sanitized return_to to fall back to onboarding, got %q", got)
	}
}

func TestWorkOSCallbackRejectsInvalidStateAndUnavailableProvider(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	workOS := &fakeWorkOSClient{err: sessionauth.ErrWorkOSUnavailable}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    workOS,
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	invalidResp := httptest.NewRecorder()
	router.ServeHTTP(invalidResp, httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state=tampered", nil))
	if invalidResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid state 400, got %d", invalidResp.Code)
	}
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	unavailableResp := httptest.NewRecorder()
	router.ServeHTTP(unavailableResp, httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(workOS.authorizationInput.State), nil))
	if unavailableResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable provider 503, got %d body=%s", unavailableResp.Code, unavailableResp.Body.String())
	}
	if unavailableResp.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header for provider outage")
	}

	missingCodeResp := httptest.NewRecorder()
	router.ServeHTTP(missingCodeResp, httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(workOS.authorizationInput.State), nil))
	if missingCodeResp.Code != http.StatusBadRequest {
		t.Fatalf("expected missing code 400, got %d", missingCodeResp.Code)
	}
}

func TestWorkOSUserDeletedWebhookRevokesSessions(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	user, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "delete@example.com"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(context.Background(), db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_delete",
		LastAuthenticatedAt: now,
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	manager := sessionauth.Manager{Store: store, PublicBaseURL: "https://app.identrail.test", Now: svc.Now}
	cookieValue, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:            user.ID,
		AuthMethod:        sessionauth.WorkOSProvider,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(sessionauth.IdleTimeout),
		AbsoluteExpiresAt: now.Add(sessionauth.AbsoluteTimeout),
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	secret := "whsec_123"
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: secret,
		WorkOSAuthClient:    &fakeWorkOSClient{},
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	payload := `{"event":"user.deleted","id":"event_1","data":{"object":"user","id":"user_workos_delete","email":"delete@example.com"}}`
	req := httptest.NewRequest(http.MethodPost, "/auth/webhooks/workos", strings.NewReader(payload))
	req.Header.Set("WorkOS-Signature", workOSTestSignature(time.Now().UTC(), secret, payload))
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected webhook 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(manager.Cookie(cookieValue))
	meResp := httptest.NewRecorder()
	router.ServeHTTP(meResp, meReq)
	if meResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected revoked session to be unauthorized, got %d body=%s", meResp.Code, meResp.Body.String())
	}
}

func TestWorkOSWebhookRejectsBadSignatureAndIgnoresUnknownEvents(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	secret := "whsec_123"
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: secret,
		WorkOSAuthClient:    &fakeWorkOSClient{},
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	payload := `{"event":"user.created","id":"event_ignored","data":{"id":"user_ignored"}}`
	badReq := httptest.NewRequest(http.MethodPost, "/auth/webhooks/workos", strings.NewReader(payload))
	badReq.Header.Set("WorkOS-Signature", "t=1, v1=bad")
	badResp := httptest.NewRecorder()
	router.ServeHTTP(badResp, badReq)
	if badResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid signature 401, got %d", badResp.Code)
	}

	okReq := httptest.NewRequest(http.MethodPost, "/auth/webhooks/workos", strings.NewReader(payload))
	okReq.Header.Set("WorkOS-Signature", workOSTestSignature(time.Now().UTC(), secret, payload))
	okResp := httptest.NewRecorder()
	router.ServeHTTP(okResp, okReq)
	if okResp.Code != http.StatusOK || !strings.Contains(okResp.Body.String(), `"ignored":true`) {
		t.Fatalf("expected ignored webhook success, got %d body=%s", okResp.Code, okResp.Body.String())
	}

	malformedPayload := `{`
	badJSONReq := httptest.NewRequest(http.MethodPost, "/auth/webhooks/workos", strings.NewReader(malformedPayload))
	badJSONReq.Header.Set("WorkOS-Signature", workOSTestSignature(time.Now().UTC(), secret, malformedPayload))
	badJSONResp := httptest.NewRecorder()
	router.ServeHTTP(badJSONResp, badJSONReq)
	if badJSONResp.Code != http.StatusBadRequest {
		t.Fatalf("expected malformed payload 400, got %d", badJSONResp.Code)
	}

	missingUserPayload := `{"event":"user.deleted","id":"event_missing","data":{"object":"user"}}`
	missingUserReq := httptest.NewRequest(http.MethodPost, "/auth/webhooks/workos", strings.NewReader(missingUserPayload))
	missingUserReq.Header.Set("WorkOS-Signature", workOSTestSignature(time.Now().UTC(), secret, missingUserPayload))
	missingUserResp := httptest.NewRecorder()
	router.ServeHTTP(missingUserResp, missingUserReq)
	if missingUserResp.Code != http.StatusBadRequest {
		t.Fatalf("expected missing user id 400, got %d", missingUserResp.Code)
	}

	notFoundPayload := `{"event":"user.deleted","id":"event_not_found","data":{"object":"user","id":"missing_workos_user"}}`
	notFoundReq := httptest.NewRequest(http.MethodPost, "/auth/webhooks/workos", strings.NewReader(notFoundPayload))
	notFoundReq.Header.Set("WorkOS-Signature", workOSTestSignature(time.Now().UTC(), secret, notFoundPayload))
	notFoundResp := httptest.NewRecorder()
	router.ServeHTTP(notFoundResp, notFoundReq)
	if notFoundResp.Code != http.StatusOK {
		t.Fatalf("expected missing local user webhook to be idempotent 200, got %d", notFoundResp.Code)
	}
}

func TestWorkOSUserUpdatedWebhookUpdatesEmail(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	user, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "old@example.com"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(context.Background(), db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_update",
		Email:               "old@example.com",
		LastAuthenticatedAt: now,
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	secret := "whsec_123"
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://app.identrail.test",
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: secret,
		WorkOSAuthClient:    &fakeWorkOSClient{},
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})
	payload := `{"event":"user.updated","id":"event_2","data":{"object":"user","id":"user_workos_update","email":"new@example.com"}}`
	req := httptest.NewRequest(http.MethodPost, "/auth/webhooks/workos", strings.NewReader(payload))
	req.Header.Set("WorkOS-Signature", workOSTestSignature(time.Now().UTC(), secret, payload))
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected webhook 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	updated, err := store.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("get updated user: %v", err)
	}
	if updated.PrimaryEmail != "new@example.com" {
		t.Fatalf("expected email update, got %+v", updated)
	}
	identity, err := store.GetUserIdentity(context.Background(), sessionauth.WorkOSProvider, "user_workos_update")
	if err != nil {
		t.Fatalf("get updated identity: %v", err)
	}
	if identity.Email != "new@example.com" {
		t.Fatalf("expected identity email update, got %+v", identity)
	}
}

func workOSTestSignature(now time.Time, secret string, body string) string {
	timestamp := strconv.FormatInt(now.Unix()*1000, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "." + body))
	return "t=" + timestamp + ", v1=" + hex.EncodeToString(mac.Sum(nil))
}
