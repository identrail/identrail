package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

type fakeWorkOSClient struct {
	authorizationInput sessionauth.WorkOSAuthorizationRequest
	verifyInput        sessionauth.WorkOSMFAVerifyRequest
	authentication     sessionauth.WorkOSAuthentication
	enrollResponse     sessionauth.WorkOSMFAEnrollResponse
	challengeResponse  sessionauth.WorkOSMFAChallengeResponse
	authURLErr         error
	err                error
	enrollErr          error
	challengeErr       error
	verifyErr          error
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
	if input.Provider != "" {
		values.Set("provider", input.Provider)
	}
	return "https://authkit.example/authorize?" + values.Encode(), nil
}

func (f *fakeWorkOSClient) AuthenticateWithCode(ctx context.Context, input sessionauth.WorkOSAuthenticationRequest) (sessionauth.WorkOSAuthentication, error) {
	if f.err != nil {
		return sessionauth.WorkOSAuthentication{}, f.err
	}
	return f.authentication, nil
}

func (f *fakeWorkOSClient) EnrollAuthFactor(ctx context.Context, input sessionauth.WorkOSMFAEnrollRequest) (sessionauth.WorkOSMFAEnrollResponse, error) {
	if f.enrollErr != nil {
		return sessionauth.WorkOSMFAEnrollResponse{}, f.enrollErr
	}
	if f.enrollResponse.FactorID != "" {
		return f.enrollResponse, nil
	}
	return sessionauth.WorkOSMFAEnrollResponse{
		FactorID:    "auth_factor_1",
		FactorType:  "totp",
		ChallengeID: "auth_challenge_1",
		TOTPQRCode:  "data:image/png;base64,qr",
		TOTPSecret:  "secret",
		TOTPURI:     "otpauth://totp/Identrail:user@example.com",
	}, nil
}

func (f *fakeWorkOSClient) ChallengeAuthFactor(ctx context.Context, input sessionauth.WorkOSMFAChallengeRequest) (sessionauth.WorkOSMFAChallengeResponse, error) {
	if f.challengeErr != nil {
		return sessionauth.WorkOSMFAChallengeResponse{}, f.challengeErr
	}
	if f.challengeResponse.ChallengeID != "" {
		return f.challengeResponse, nil
	}
	return sessionauth.WorkOSMFAChallengeResponse{ChallengeID: "auth_challenge_1", FactorID: input.FactorID}, nil
}

func (f *fakeWorkOSClient) AuthenticateWithTOTP(ctx context.Context, input sessionauth.WorkOSMFAVerifyRequest) (sessionauth.WorkOSAuthentication, error) {
	f.verifyInput = input
	if f.verifyErr != nil {
		return sessionauth.WorkOSAuthentication{}, f.verifyErr
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
	if workOS.authorizationInput.Provider != "authkit" {
		t.Fatalf("expected default authkit provider, got %q", workOS.authorizationInput.Provider)
	}

	callbackReq := workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp))
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, callbackReq)
	if callbackResp.Code != http.StatusFound {
		t.Fatalf("expected callback redirect, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
	if got := callbackResp.Header().Get("Location"); got != "/app/welcome" {
		t.Fatalf("unexpected post-login redirect: %q", got)
	}
	if findTestCookie(callbackResp.Result().Cookies(), sessionauth.CookieName) == nil {
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

func TestWorkOSStartRoutesConfiguredSocialProviders(t *testing.T) {
	for _, tc := range []struct {
		name       string
		provider   string
		want       string
		wantScopes string
	}{
		{name: "google", provider: "google_oauth", want: "GoogleOAuth"},
		{name: "github", provider: "github_oauth", want: "GitHubOAuth", wantScopes: "user:email"},
		{name: "authkit", provider: "authkit", want: "authkit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := db.NewMemoryStore()
			svc := NewService(store, fakeScanner{}, "aws")
			workOS := &fakeWorkOSClient{}
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

			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/auth/login?provider="+tc.provider, nil))
			if resp.Code != http.StatusFound {
				t.Fatalf("expected login redirect, got %d body=%s", resp.Code, resp.Body.String())
			}
			if workOS.authorizationInput.Provider != tc.want {
				t.Fatalf("expected provider %q, got %q", tc.want, workOS.authorizationInput.Provider)
			}
			if gotScopes := strings.Join(workOS.authorizationInput.ProviderScopes, ","); gotScopes != tc.wantScopes {
				t.Fatalf("expected provider scopes %q, got %q", tc.wantScopes, gotScopes)
			}
		})
	}
}

func TestWorkOSSignupOnlySendsScreenHintForAuthKit(t *testing.T) {
	for _, tc := range []struct {
		name           string
		provider       string
		wantProvider   string
		wantScreenHint string
	}{
		{name: "google", provider: "google_oauth", wantProvider: "GoogleOAuth"},
		{name: "github", provider: "github_oauth", wantProvider: "GitHubOAuth"},
		{name: "authkit", provider: "authkit", wantProvider: "authkit", wantScreenHint: "sign-up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := db.NewMemoryStore()
			svc := NewService(store, fakeScanner{}, "aws")
			workOS := &fakeWorkOSClient{}
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

			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/auth/signup?provider="+tc.provider, nil))
			if resp.Code != http.StatusFound {
				t.Fatalf("expected signup redirect, got %d body=%s", resp.Code, resp.Body.String())
			}
			if workOS.authorizationInput.Provider != tc.wantProvider {
				t.Fatalf("expected provider %q, got %q", tc.wantProvider, workOS.authorizationInput.Provider)
			}
			if workOS.authorizationInput.ScreenHint != tc.wantScreenHint {
				t.Fatalf("expected screen hint %q, got %q", tc.wantScreenHint, workOS.authorizationInput.ScreenHint)
			}
		})
	}
}

func TestWorkOSStartRejectsUnsupportedProvider(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
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

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/auth/login?provider=apple_oauth", nil))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected unsupported provider 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestWorkOSHostedLoginAllowsConfiguredWebReturnOrigin(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	workOS := &fakeWorkOSClient{
		authentication: sessionauth.WorkOSAuthentication{
			User: sessionauth.WorkOSProfile{
				ID:            "user_workos_split_origin",
				Email:         "split@example.com",
				EmailVerified: true,
			},
			AuthenticationMethod: "GoogleOAuth",
		},
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		PublicBaseURL:       "https://api.identrail.test",
		CORSAllowedOrigins:  []string{"https://app.identrail.test"},
		SessionKey:          strings.Repeat("a", 64),
		WorkOSClientID:      "client_123",
		WorkOSWebhookSecret: "whsec_123",
		WorkOSAuthClient:    workOS,
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
	})

	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=https%3A%2F%2Fapp.identrail.test%2Fapp%2Fwelcome", nil))
	if startResp.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	if workOS.authorizationInput.RedirectURI != "https://api.identrail.test/auth/callback" {
		t.Fatalf("expected API callback URL, got %q", workOS.authorizationInput.RedirectURI)
	}

	callbackReq := workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp))
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, callbackReq)
	if callbackResp.Code != http.StatusFound {
		t.Fatalf("expected callback redirect, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
	if got := callbackResp.Header().Get("Location"); got != "https://app.identrail.test/app/welcome" {
		t.Fatalf("expected configured web-origin redirect, got %q", got)
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
	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	callbackReq := workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp))
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, callbackReq)
	if callbackResp.Code != http.StatusFound {
		t.Fatalf("expected callback redirect, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
	if got := callbackResp.Header().Get("Location"); got != "/app/tenant-a/workspace-a" {
		t.Fatalf("expected selected organization redirect, got %q", got)
	}
	sessionCookie := findTestCookie(callbackResp.Result().Cookies(), sessionauth.CookieName)
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}
	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(sessionCookie)
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
	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp)))
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
	router.ServeHTTP(callbackResp, workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp)))
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
	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	unavailableResp := httptest.NewRecorder()
	router.ServeHTTP(unavailableResp, workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp)))
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

func TestWorkOSCallbackContinuesMFAEnrollment(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 16, 18, 45, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	sink := &recordingAuditSink{}
	workOS := &fakeWorkOSClient{
		err: &sessionauth.WorkOSMFARequired{
			Mode:                       sessionauth.WorkOSMFAModeEnrollment,
			PendingAuthenticationToken: "pending-token",
			User: sessionauth.WorkOSProfile{
				ID:            "user_workos_mfa",
				Email:         "mfa@example.com",
				EmailVerified: true,
			},
		},
		authentication: sessionauth.WorkOSAuthentication{
			User: sessionauth.WorkOSProfile{
				ID:            "user_workos_mfa",
				Email:         "mfa@example.com",
				EmailVerified: true,
			},
			AuthenticationMethod: "GitHubOAuth",
		},
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:     true,
		FeatureWorkOSLogin: true,
		PublicBaseURL:      "https://api.identrail.test",
		CORSAllowedOrigins: []string{"https://app.identrail.test"},
		AuditSink:          sink,
		SessionKey:         strings.Repeat("a", 64),
		WorkOSClientID:     "client_123",
		WorkOSAuthClient:   workOS,
		RateLimitRPM:       1000,
		RateLimitBurst:     1000,
	})

	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login?provider=github_oauth&return_to=https%3A%2F%2Fapp.identrail.test%2Fapp", nil))
	if startResp.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d body=%s", startResp.Code, startResp.Body.String())
	}

	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp)))
	if callbackResp.Code != http.StatusFound {
		t.Fatalf("expected mfa redirect, got %d body=%s", callbackResp.Code, callbackResp.Body.String())
	}
	if got := callbackResp.Header().Get("Location"); !strings.HasPrefix(got, "https://app.identrail.test/auth/mfa?") || !strings.Contains(got, "return_to=https%3A%2F%2Fapp.identrail.test%2Fapp") {
		t.Fatalf("unexpected mfa redirect: %q", got)
	}
	pendingCookie := findTestCookie(callbackResp.Result().Cookies(), sessionauth.PendingMFACookieName)
	if pendingCookie == nil || pendingCookie.Value == "" {
		t.Fatalf("expected pending mfa cookie, got %+v", callbackResp.Result().Cookies())
	}
	if strings.Contains(pendingCookie.Value, "pending-token") {
		t.Fatalf("pending mfa cookie must not expose the raw workos token: %q", pendingCookie.Value)
	}

	pendingReq := httptest.NewRequest(http.MethodGet, "/auth/mfa/pending", nil)
	pendingReq.AddCookie(pendingCookie)
	pendingResp := httptest.NewRecorder()
	router.ServeHTTP(pendingResp, pendingReq)
	if pendingResp.Code != http.StatusOK || !strings.Contains(pendingResp.Body.String(), `"mode":"enrollment"`) {
		t.Fatalf("unexpected pending response: code=%d body=%s", pendingResp.Code, pendingResp.Body.String())
	}

	enrollReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/enroll", nil)
	enrollReq.AddCookie(pendingCookie)
	enrollResp := httptest.NewRecorder()
	router.ServeHTTP(enrollResp, enrollReq)
	if enrollResp.Code != http.StatusOK || !strings.Contains(enrollResp.Body.String(), `"qr_code":"data:image/png;base64,qr"`) {
		t.Fatalf("unexpected enroll response: code=%d body=%s", enrollResp.Code, enrollResp.Body.String())
	}
	updatedPendingCookie := findTestCookie(enrollResp.Result().Cookies(), sessionauth.PendingMFACookieName)
	if updatedPendingCookie == nil || updatedPendingCookie.Value == "" {
		t.Fatalf("expected refreshed pending mfa cookie, got %+v", enrollResp.Result().Cookies())
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", strings.NewReader(`{"code":"123456"}`))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(updatedPendingCookie)
	verifyResp := httptest.NewRecorder()
	router.ServeHTTP(verifyResp, verifyReq)
	if verifyResp.Code != http.StatusOK || !strings.Contains(verifyResp.Body.String(), `"redirect_to":"https://app.identrail.test/app"`) {
		t.Fatalf("unexpected verify response: code=%d body=%s", verifyResp.Code, verifyResp.Body.String())
	}
	if workOS.verifyInput.PendingAuthenticationToken != "pending-token" || workOS.verifyInput.AuthenticationChallengeID != "auth_challenge_1" || workOS.verifyInput.Code != "123456" {
		t.Fatalf("unexpected verify input: %+v", workOS.verifyInput)
	}
	if findTestCookie(verifyResp.Result().Cookies(), sessionauth.CookieName) == nil {
		t.Fatalf("expected session cookie after mfa verify, got %+v", verifyResp.Result().Cookies())
	}
	clearedPending := findTestCookie(verifyResp.Result().Cookies(), sessionauth.PendingMFACookieName)
	if clearedPending == nil || clearedPending.MaxAge >= 0 {
		t.Fatalf("expected pending mfa cookie to be cleared, got %+v", verifyResp.Result().Cookies())
	}
	if _, err := store.GetUserIdentity(context.Background(), sessionauth.WorkOSProvider, "user_workos_mfa"); err != nil {
		t.Fatalf("expected workos identity after mfa verify: %v", err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, event := range sink.events {
		if event.Action == "auth.login.failure" {
			t.Fatalf("mfa continuation must not write denied login failure audit event: %+v", event)
		}
	}
}

func TestWorkOSCallbackContinuesExistingMFAChallenge(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 16, 18, 45, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	workOS := &fakeWorkOSClient{
		err: &sessionauth.WorkOSMFARequired{
			Mode:                       sessionauth.WorkOSMFAModeChallenge,
			PendingAuthenticationToken: "pending-token",
			User: sessionauth.WorkOSProfile{
				ID:            "user_workos_challenge",
				Email:         "challenge@example.com",
				EmailVerified: true,
			},
			AuthenticationFactors: []sessionauth.WorkOSMFAFactor{{ID: "auth_factor_existing", Type: "totp"}},
		},
		challengeResponse: sessionauth.WorkOSMFAChallengeResponse{
			ChallengeID: "auth_challenge_existing",
			FactorID:    "auth_factor_existing",
			ExpiresAt:   "2026-05-16T19:30:00Z",
		},
		authentication: sessionauth.WorkOSAuthentication{
			User: sessionauth.WorkOSProfile{
				ID:            "user_workos_challenge",
				Email:         "challenge@example.com",
				EmailVerified: true,
			},
			AuthenticationMethod: "GitHubOAuth",
		},
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:     true,
		FeatureWorkOSLogin: true,
		PublicBaseURL:      "https://api.identrail.test",
		CORSAllowedOrigins: []string{"https://app.identrail.test"},
		SessionKey:         strings.Repeat("a", 64),
		WorkOSClientID:     "client_123",
		WorkOSAuthClient:   workOS,
		RateLimitRPM:       1000,
		RateLimitBurst:     1000,
	})

	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login?provider=github_oauth&return_to=https%3A%2F%2Fapp.identrail.test%2Fapp", nil))
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp)))
	pendingCookie := findTestCookie(callbackResp.Result().Cookies(), sessionauth.PendingMFACookieName)
	if callbackResp.Code != http.StatusFound || pendingCookie == nil {
		t.Fatalf("expected mfa redirect and cookie, code=%d cookies=%+v body=%s", callbackResp.Code, callbackResp.Result().Cookies(), callbackResp.Body.String())
	}

	challengeReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/challenge", strings.NewReader(`{"factor_id":"auth_factor_existing"}`))
	challengeReq.Header.Set("Content-Type", "application/json")
	challengeReq.AddCookie(pendingCookie)
	challengeResp := httptest.NewRecorder()
	router.ServeHTTP(challengeResp, challengeReq)
	if challengeResp.Code != http.StatusOK || !strings.Contains(challengeResp.Body.String(), `"challenge_started":true`) {
		t.Fatalf("unexpected challenge response: code=%d body=%s", challengeResp.Code, challengeResp.Body.String())
	}
	updatedPendingCookie := findTestCookie(challengeResp.Result().Cookies(), sessionauth.PendingMFACookieName)
	if updatedPendingCookie == nil || updatedPendingCookie.Value == "" {
		t.Fatalf("expected refreshed pending mfa cookie, got %+v", challengeResp.Result().Cookies())
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", strings.NewReader(`{"code":"654321"}`))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(updatedPendingCookie)
	verifyResp := httptest.NewRecorder()
	router.ServeHTTP(verifyResp, verifyReq)
	if verifyResp.Code != http.StatusOK || !strings.Contains(verifyResp.Body.String(), `"redirect_to":"https://app.identrail.test/app"`) {
		t.Fatalf("unexpected verify response: code=%d body=%s", verifyResp.Code, verifyResp.Body.String())
	}
	if workOS.verifyInput.PendingAuthenticationToken != "pending-token" || workOS.verifyInput.AuthenticationChallengeID != "auth_challenge_existing" || workOS.verifyInput.Code != "654321" {
		t.Fatalf("unexpected verify input: %+v", workOS.verifyInput)
	}
}

func TestWorkOSMFAChallengeRejectsBadFactorAndInvalidCode(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	workOS := &fakeWorkOSClient{
		err: &sessionauth.WorkOSMFARequired{
			Mode:                       sessionauth.WorkOSMFAModeChallenge,
			PendingAuthenticationToken: "pending-token",
			User:                       sessionauth.WorkOSProfile{ID: "user_workos_challenge", Email: "challenge@example.com", EmailVerified: true},
			AuthenticationFactors:      []sessionauth.WorkOSMFAFactor{{ID: "auth_factor_existing", Type: "totp"}},
		},
		challengeResponse: sessionauth.WorkOSMFAChallengeResponse{ChallengeID: "auth_challenge_existing", FactorID: "auth_factor_existing"},
		verifyErr:         errors.New("invalid code"),
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:     true,
		FeatureWorkOSLogin: true,
		PublicBaseURL:      "https://api.identrail.test",
		CORSAllowedOrigins: []string{"https://app.identrail.test"},
		SessionKey:         strings.Repeat("a", 64),
		WorkOSClientID:     "client_123",
		WorkOSAuthClient:   workOS,
		RateLimitRPM:       1000,
		RateLimitBurst:     1000,
	})

	noCookieResp := httptest.NewRecorder()
	router.ServeHTTP(noCookieResp, httptest.NewRequest(http.MethodGet, "/auth/mfa/pending", nil))
	if noCookieResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected pending mfa without cookie to be unauthorized, got %d", noCookieResp.Code)
	}

	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login?provider=github_oauth&return_to=https%3A%2F%2Fapp.identrail.test%2Fapp", nil))
	callbackResp := httptest.NewRecorder()
	router.ServeHTTP(callbackResp, workOSCallbackRequest(workOS.authorizationInput.State, oauthTxnCookieFromStart(t, startResp)))
	pendingCookie := findTestCookie(callbackResp.Result().Cookies(), sessionauth.PendingMFACookieName)
	if pendingCookie == nil {
		t.Fatalf("expected pending cookie, got %+v", callbackResp.Result().Cookies())
	}

	badChallengeReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/challenge", strings.NewReader(`{"factor_id":"missing"}`))
	badChallengeReq.Header.Set("Content-Type", "application/json")
	badChallengeReq.AddCookie(pendingCookie)
	badChallengeResp := httptest.NewRecorder()
	router.ServeHTTP(badChallengeResp, badChallengeReq)
	if badChallengeResp.Code != http.StatusBadRequest || !strings.Contains(badChallengeResp.Body.String(), "unsupported mfa factor") {
		t.Fatalf("unexpected bad challenge response: code=%d body=%s", badChallengeResp.Code, badChallengeResp.Body.String())
	}

	challengeReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/challenge", strings.NewReader(`{"factor_id":"auth_factor_existing"}`))
	challengeReq.Header.Set("Content-Type", "application/json")
	challengeReq.AddCookie(pendingCookie)
	challengeResp := httptest.NewRecorder()
	router.ServeHTTP(challengeResp, challengeReq)
	updatedPendingCookie := findTestCookie(challengeResp.Result().Cookies(), sessionauth.PendingMFACookieName)
	if challengeResp.Code != http.StatusOK || updatedPendingCookie == nil {
		t.Fatalf("expected challenge to start, code=%d cookies=%+v body=%s", challengeResp.Code, challengeResp.Result().Cookies(), challengeResp.Body.String())
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", strings.NewReader(`{"code":"000000"}`))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(updatedPendingCookie)
	verifyResp := httptest.NewRecorder()
	router.ServeHTTP(verifyResp, verifyReq)
	if verifyResp.Code != http.StatusUnauthorized || !strings.Contains(verifyResp.Body.String(), "invalid verification code") {
		t.Fatalf("unexpected invalid verify response: code=%d body=%s", verifyResp.Code, verifyResp.Body.String())
	}
}

func newWorkOSTestRouter(t *testing.T, store db.Store, workOS sessionauth.WorkOSClient) http.Handler {
	t.Helper()
	svc := NewService(store, fakeScanner{}, "aws")
	return NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
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
}

func TestWorkOSCallbackRequiresBrowserBoundTransaction(t *testing.T) {
	store := db.NewMemoryStore()
	workOS := &fakeWorkOSClient{authentication: sessionauth.WorkOSAuthentication{
		User: sessionauth.WorkOSProfile{ID: "user_txn_1", Email: "txn@example.com", EmailVerified: true},
	}}
	router := newWorkOSTestRouter(t, store, workOS)

	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/app/welcome", nil))
	if startResp.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d", startResp.Code)
	}
	state := workOS.authorizationInput.State
	txnCookie := oauthTxnCookieFromStart(t, startResp)

	// A callback without the issued transaction cookie is rejected even
	// though the signed state is valid.
	noCookieResp := httptest.NewRecorder()
	router.ServeHTTP(noCookieResp, workOSCallbackRequest(state, nil))
	if noCookieResp.Code != http.StatusBadRequest {
		t.Fatalf("expected missing-cookie callback to be rejected, got %d body=%s", noCookieResp.Code, noCookieResp.Body.String())
	}

	// A second, independent login produces a different transaction cookie;
	// pairing it with the first state must be rejected (state/cookie
	// mismatch).
	otherStart := httptest.NewRecorder()
	router.ServeHTTP(otherStart, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/app/other", nil))
	otherCookie := oauthTxnCookieFromStart(t, otherStart)
	mismatchResp := httptest.NewRecorder()
	router.ServeHTTP(mismatchResp, workOSCallbackRequest(state, otherCookie))
	if mismatchResp.Code != http.StatusBadRequest {
		t.Fatalf("expected mismatched state/cookie to be rejected, got %d body=%s", mismatchResp.Code, mismatchResp.Body.String())
	}

	// The genuine pair succeeds exactly once.
	okResp := httptest.NewRecorder()
	router.ServeHTTP(okResp, workOSCallbackRequest(state, txnCookie))
	if okResp.Code != http.StatusFound || okResp.Header().Get("Location") != "/app/welcome" {
		t.Fatalf("expected successful callback redirect, got %d loc=%q body=%s", okResp.Code, okResp.Header().Get("Location"), okResp.Body.String())
	}

	// Replaying the same state + cookie fails because the row is consumed.
	replayResp := httptest.NewRecorder()
	router.ServeHTTP(replayResp, workOSCallbackRequest(state, txnCookie))
	if replayResp.Code != http.StatusBadRequest {
		t.Fatalf("expected reused state to be rejected, got %d body=%s", replayResp.Code, replayResp.Body.String())
	}
}

// TestWorkOSConcurrentStartsKeepIndependentTransactions proves a second
// in-flight login (double-click, two tabs, switching provider) does not
// invalidate the first: each start sets a nonce-scoped transaction cookie,
// so both callbacks complete independently.
func TestWorkOSConcurrentStartsKeepIndependentTransactions(t *testing.T) {
	store := db.NewMemoryStore()
	workOS := &fakeWorkOSClient{authentication: sessionauth.WorkOSAuthentication{
		User: sessionauth.WorkOSProfile{ID: "user_txn_concurrent", Email: "concurrent@example.com", EmailVerified: true},
	}}
	router := newWorkOSTestRouter(t, store, workOS)

	startA := httptest.NewRecorder()
	router.ServeHTTP(startA, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/app/a", nil))
	stateA := workOS.authorizationInput.State
	cookieA := oauthTxnCookieFromStart(t, startA)

	// Second flow starts before the first callback returns.
	startB := httptest.NewRecorder()
	router.ServeHTTP(startB, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/app/b", nil))
	stateB := workOS.authorizationInput.State
	cookieB := oauthTxnCookieFromStart(t, startB)

	if cookieA.Name == cookieB.Name {
		t.Fatalf("expected nonce-scoped cookie names, both were %q", cookieA.Name)
	}

	// The first flow's callback still succeeds even though a second flow
	// started in between.
	respA := httptest.NewRecorder()
	router.ServeHTTP(respA, workOSCallbackRequest(stateA, cookieA))
	if respA.Code != http.StatusFound || respA.Header().Get("Location") != "/app/a" {
		t.Fatalf("expected first concurrent flow to complete, got %d loc=%q body=%s", respA.Code, respA.Header().Get("Location"), respA.Body.String())
	}

	respB := httptest.NewRecorder()
	router.ServeHTTP(respB, workOSCallbackRequest(stateB, cookieB))
	if respB.Code != http.StatusFound || respB.Header().Get("Location") != "/app/b" {
		t.Fatalf("expected second concurrent flow to complete, got %d loc=%q body=%s", respB.Code, respB.Header().Get("Location"), respB.Body.String())
	}
}

// TestWorkOSCallbackReplayFailsAcrossInstances proves the single-use guarantee
// holds across API instances that share a database, which the previous
// process-local replay map could not provide.
func TestWorkOSCallbackReplayFailsAcrossInstances(t *testing.T) {
	store := db.NewMemoryStore()
	workOS := &fakeWorkOSClient{authentication: sessionauth.WorkOSAuthentication{
		User: sessionauth.WorkOSProfile{ID: "user_txn_xinst", Email: "xinst@example.com", EmailVerified: true},
	}}
	// Two routers with the same SessionKey (so signed state validates on
	// both) backed by the same store, simulating a multi-instance fleet.
	instanceA := newWorkOSTestRouter(t, store, workOS)
	instanceB := newWorkOSTestRouter(t, store, workOS)

	startResp := httptest.NewRecorder()
	instanceA.ServeHTTP(startResp, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/app/welcome", nil))
	state := workOS.authorizationInput.State
	txnCookie := oauthTxnCookieFromStart(t, startResp)

	// Callback lands on instance B (different node than issued the redirect)
	// and still succeeds because the transaction row is store-backed.
	bResp := httptest.NewRecorder()
	instanceB.ServeHTTP(bResp, workOSCallbackRequest(state, txnCookie))
	if bResp.Code != http.StatusFound {
		t.Fatalf("expected cross-instance callback to succeed, got %d body=%s", bResp.Code, bResp.Body.String())
	}

	// Replaying the captured state + cookie against instance A fails: the
	// shared row is already consumed, even though A's process-local replay
	// map never saw this nonce consumed.
	aReplay := httptest.NewRecorder()
	instanceA.ServeHTTP(aReplay, workOSCallbackRequest(state, txnCookie))
	if aReplay.Code != http.StatusBadRequest {
		t.Fatalf("expected cross-instance replay to be rejected, got %d body=%s", aReplay.Code, aReplay.Body.String())
	}
}

// oauthTxnCookieFromStart extracts the browser-bound OAuth transaction cookie
// the start handler set. The callback now requires it: OAuth state is
// store-backed and bound to the browser that initiated the login.
func oauthTxnCookieFromStart(t *testing.T, resp *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range resp.Result().Cookies() {
		if c.Value != "" && strings.HasPrefix(c.Name, sessionauth.OAuthTransactionCookiePrefix+"_") {
			return &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	t.Fatalf("expected oauth transaction cookie on start response (code=%d), got %+v", resp.Code, resp.Result().Cookies())
	return nil
}

// workOSCallbackRequest builds a /auth/callback request carrying the
// browser-bound transaction cookie issued at login start.
func workOSCallbackRequest(state string, txn *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(state), nil)
	if txn != nil {
		req.AddCookie(txn)
	}
	return req
}

func findTestCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func sealedPendingMFACookie(t *testing.T, secret string, state sessionauth.WorkOSMFAPendingState) *http.Cookie {
	t.Helper()
	manager := sessionauth.NewMFAPendingStateManager(secret, nil)
	value, err := manager.Seal(state)
	if err != nil {
		t.Fatalf("seal pending mfa state: %v", err)
	}
	return &http.Cookie{Name: sessionauth.PendingMFACookieName, Value: value}
}

func TestWorkOSMFAEndpointErrorBranches(t *testing.T) {
	secret := strings.Repeat("a", 64)
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	workOS := &fakeWorkOSClient{
		enrollErr:    sessionauth.ErrWorkOSUnavailable,
		challengeErr: errors.New("challenge provider failed"),
		verifyErr:    sessionauth.ErrWorkOSUnavailable,
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNewAuth:     true,
		FeatureWorkOSLogin: true,
		PublicBaseURL:      "https://api.identrail.test",
		CORSAllowedOrigins: []string{"https://app.identrail.test"},
		SessionKey:         secret,
		WorkOSClientID:     "client_123",
		WorkOSAuthClient:   workOS,
		RateLimitRPM:       1000,
		RateLimitBurst:     1000,
	})
	postWithCookie := func(path string, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		return resp
	}
	baseState := sessionauth.WorkOSMFAPendingState{
		ReturnTo:                   "https://app.identrail.test/app",
		PendingAuthenticationToken: "pending-token",
		User:                       sessionauth.WorkOSProfile{ID: "user_workos_mfa", Email: "mfa@example.com", EmailVerified: true},
	}

	existingEnrollment := baseState
	existingEnrollment.Mode = sessionauth.WorkOSMFAModeEnrollment
	existingEnrollment.ChallengeID = "auth_challenge_existing"
	existingEnrollment.TOTP = &sessionauth.WorkOSPendingTOTP{FactorID: "auth_factor_existing", QRCode: "qr", Secret: "secret", URI: "otpauth://totp/Identrail:mfa@example.com"}
	resp := postWithCookie("/auth/mfa/enroll", "", sealedPendingMFACookie(t, secret, existingEnrollment))
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"factor_id":"auth_factor_existing"`) {
		t.Fatalf("expected cached enrollment response, got code=%d body=%s", resp.Code, resp.Body.String())
	}

	challengeState := baseState
	challengeState.Mode = sessionauth.WorkOSMFAModeChallenge
	challengeState.AuthenticationFactors = []sessionauth.WorkOSMFAFactor{{ID: "auth_factor_existing", Type: "totp"}}
	resp = postWithCookie("/auth/mfa/enroll", "", sealedPendingMFACookie(t, secret, challengeState))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "mfa enrollment is not pending") {
		t.Fatalf("expected wrong-mode enrollment rejection, got code=%d body=%s", resp.Code, resp.Body.String())
	}

	missingUserEnrollment := baseState
	missingUserEnrollment.Mode = sessionauth.WorkOSMFAModeEnrollment
	missingUserEnrollment.User = sessionauth.WorkOSProfile{}
	resp = postWithCookie("/auth/mfa/enroll", "", sealedPendingMFACookie(t, secret, missingUserEnrollment))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "mfa enrollment cannot be started") {
		t.Fatalf("expected missing-user enrollment rejection, got code=%d body=%s", resp.Code, resp.Body.String())
	}

	newEnrollment := baseState
	newEnrollment.Mode = sessionauth.WorkOSMFAModeEnrollment
	resp = postWithCookie("/auth/mfa/enroll", "", sealedPendingMFACookie(t, secret, newEnrollment))
	if resp.Code != http.StatusServiceUnavailable || resp.Header().Get("Retry-After") == "" {
		t.Fatalf("expected enrollment provider outage, got code=%d headers=%v body=%s", resp.Code, resp.Header(), resp.Body.String())
	}

	resp = postWithCookie("/auth/mfa/challenge", "{", sealedPendingMFACookie(t, secret, challengeState))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "invalid challenge request") {
		t.Fatalf("expected invalid challenge request, got code=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = postWithCookie("/auth/mfa/challenge", `{"factor_id":"auth_factor_existing"}`, sealedPendingMFACookie(t, secret, challengeState))
	if resp.Code != http.StatusBadGateway || !strings.Contains(resp.Body.String(), "mfa provider failed") {
		t.Fatalf("expected challenge provider failure, got code=%d body=%s", resp.Code, resp.Body.String())
	}

	startedChallengeState := challengeState
	startedChallengeState.ChallengeID = "auth_challenge_existing"
	resp = postWithCookie("/auth/mfa/verify", `{"code":" "}`, sealedPendingMFACookie(t, secret, startedChallengeState))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "verification code is required") {
		t.Fatalf("expected empty verification rejection, got code=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = postWithCookie("/auth/mfa/verify", `{"code":"123456"}`, sealedPendingMFACookie(t, secret, challengeState))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "mfa challenge has not started") {
		t.Fatalf("expected missing challenge rejection, got code=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = postWithCookie("/auth/mfa/verify", `{"code":"123456"}`, sealedPendingMFACookie(t, secret, startedChallengeState))
	if resp.Code != http.StatusServiceUnavailable || resp.Header().Get("Retry-After") == "" {
		t.Fatalf("expected verify provider outage, got code=%d headers=%v body=%s", resp.Code, resp.Header(), resp.Body.String())
	}
}

func TestWorkOSMFAHelperErrorPaths(t *testing.T) {
	target := workOSMFARedirectURL("", "https://api.identrail.test", []string{"https://api.identrail.test", "https://app.identrail.test"})
	if target != "https://app.identrail.test/auth/mfa?return_to=%2Fapp" {
		t.Fatalf("unexpected fallback mfa redirect: %q", target)
	}
	if !workOSMFAFactorAllowed([]sessionauth.WorkOSMFAFactor{{ID: "factor-1", Type: "totp"}}, "factor-1") {
		t.Fatal("expected totp factor to be allowed")
	}
	if workOSMFAFactorAllowed([]sessionauth.WorkOSMFAFactor{{ID: "factor-1", Type: "sms"}}, "factor-1") {
		t.Fatal("expected non-totp factor to be rejected")
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	writeWorkOSMFAProviderError(c, zap.NewNop(), sessionauth.ErrWorkOSUnavailable, "provider")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected unavailable provider response, code=%d body=%s", w.Code, w.Body.String())
	}

	verifyW := httptest.NewRecorder()
	verifyC, _ := gin.CreateTestContext(verifyW)
	writeWorkOSMFAVerifyError(verifyC, zap.NewNop(), errors.New("invalid"))
	if verifyW.Code != http.StatusUnauthorized || !strings.Contains(verifyW.Body.String(), "invalid verification code") {
		t.Fatalf("expected invalid verification response, code=%d body=%s", verifyW.Code, verifyW.Body.String())
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
