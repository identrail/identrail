package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/workos_errors"
)

func TestWorkOSSDKClientAuthorizationURL(t *testing.T) {
	client := NewWorkOSSDKClient("sk_test", "client_123")
	got, err := client.AuthorizationURL(WorkOSAuthorizationRequest{
		RedirectURI: "https://app.example.com/auth/callback",
		State:       "state-1",
		ScreenHint:  "sign-up",
	})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	if !strings.Contains(got, "provider=authkit") || !strings.Contains(got, "screen_hint=sign-up") || !strings.Contains(got, "state=state-1") {
		t.Fatalf("unexpected authorization url: %s", got)
	}
}

func TestWorkOSSDKClientAuthorizationURLIncludesProviderScopes(t *testing.T) {
	client := NewWorkOSSDKClient("sk_test", "client_123")
	got, err := client.AuthorizationURL(WorkOSAuthorizationRequest{
		RedirectURI:    "https://app.example.com/auth/callback",
		State:          "state-1",
		Provider:       "GitHubOAuth",
		ProviderScopes: []string{"user:email"},
	})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	if !strings.Contains(got, "provider=GitHubOAuth") || !strings.Contains(got, "provider_scopes=user%3Aemail") {
		t.Fatalf("expected github email provider scope in authorization url: %s", got)
	}
}

func TestWorkOSSDKClientAuthenticateWithCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/user_management/authenticate" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if payload["client_id"] != "client_123" || payload["client_secret"] != "sk_test" || payload["code"] != "code-1" {
			t.Fatalf("unexpected request payload: %+v", payload)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]any{
				"id":                  "user_123",
				"email":               "user@example.com",
				"first_name":          "User",
				"last_name":           "One",
				"email_verified":      true,
				"profile_picture_url": "https://cdn.example/avatar.png",
			},
			"organization_id":       "org_123",
			"authentication_method": "GitHubOAuth",
			"access_token":          "access",
			"refresh_token":         "refresh",
		})
	}))
	defer server.Close()

	client := NewWorkOSSDKClient("sk_test", "client_123")
	client.client.Endpoint = server.URL
	client.client.HTTPClient = server.Client()
	authenticated, err := client.AuthenticateWithCode(context.Background(), WorkOSAuthenticationRequest{
		Code:      "code-1",
		IPAddress: "192.0.2.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("authenticate with code: %v", err)
	}
	if authenticated.User.ID != "user_123" || authenticated.User.Email != "user@example.com" || authenticated.OrganizationID != "org_123" || authenticated.User.OrganizationID != "org_123" {
		t.Fatalf("unexpected authentication: %+v", authenticated)
	}
	if len(authenticated.User.RawClaims) == 0 || !strings.Contains(string(authenticated.User.RawClaims), "user@example.com") {
		t.Fatalf("expected raw claims to include user payload, got %s", authenticated.User.RawClaims)
	}
}

func TestWorkOSSDKClientAuthenticateWithCodeProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad code", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewWorkOSSDKClient("sk_test", "client_123")
	client.client.Endpoint = server.URL
	client.client.HTTPClient = server.Client()
	if _, err := client.AuthenticateWithCode(context.Background(), WorkOSAuthenticationRequest{Code: "bad"}); err == nil {
		t.Fatal("expected provider error")
	}
}

func TestWorkOSSDKClientAuthenticateWithCodeNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	endpoint := server.URL
	server.Close()
	client := NewWorkOSSDKClient("sk_test", "client_123")
	client.client.Endpoint = endpoint
	client.client.HTTPClient = server.Client()
	if _, err := client.AuthenticateWithCode(context.Background(), WorkOSAuthenticationRequest{Code: "code"}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable network error, got %v", err)
	}
}

func TestWorkOSSDKClientMFAFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/user_management/users/user_123/auth_factors":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode enroll request: %v", err)
			}
			if payload["type"] != "totp" || payload["totp_issuer"] != "Identrail" || payload["totp_user"] != "user@example.com" {
				t.Fatalf("unexpected enroll request: %+v", payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authentication_factor": map[string]any{
					"id":   "auth_factor_123",
					"type": "totp",
					"totp": map[string]any{
						"qr_code": "data:image/png;base64,qr",
						"secret":  "SECRET",
						"uri":     "otpauth://totp/Identrail:user@example.com",
					},
				},
				"authentication_challenge": map[string]any{
					"id":         "auth_challenge_123",
					"expires_at": "2026-05-16T19:30:00Z",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/auth/factors/auth_factor_123/challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                       "auth_challenge_456",
				"authentication_factor_id": "auth_factor_123",
				"expires_at":               "2026-05-16T19:35:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/user_management/authenticate":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode verify request: %v", err)
			}
			if payload["grant_type"] != "urn:workos:oauth:grant-type:mfa-totp" || payload["pending_authentication_token"] != "pending-token" || payload["authentication_challenge_id"] != "auth_challenge_123" || payload["code"] != "123456" {
				t.Fatalf("unexpected verify request: %+v", payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{
					"id":             "user_123",
					"email":          "user@example.com",
					"email_verified": true,
				},
				"organization_id":       "org_123",
				"authentication_method": "GitHubOAuth",
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewWorkOSSDKClient("sk_test", "client_123")
	client.client.Endpoint = server.URL
	client.client.HTTPClient = server.Client()
	client.mfa.Endpoint = server.URL
	client.mfa.HTTPClient = server.Client()

	enrolled, err := client.EnrollAuthFactor(context.Background(), WorkOSMFAEnrollRequest{
		UserID:     "user_123",
		TOTPIssuer: "Identrail",
		TOTPUser:   "user@example.com",
	})
	if err != nil {
		t.Fatalf("enroll auth factor: %v", err)
	}
	if enrolled.FactorID != "auth_factor_123" || enrolled.ChallengeID != "auth_challenge_123" || enrolled.TOTPSecret != "SECRET" {
		t.Fatalf("unexpected enrollment: %+v", enrolled)
	}

	challenge, err := client.ChallengeAuthFactor(context.Background(), WorkOSMFAChallengeRequest{FactorID: "auth_factor_123"})
	if err != nil {
		t.Fatalf("challenge auth factor: %v", err)
	}
	if challenge.ChallengeID != "auth_challenge_456" || challenge.FactorID != "auth_factor_123" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}

	authenticated, err := client.AuthenticateWithTOTP(context.Background(), WorkOSMFAVerifyRequest{
		PendingAuthenticationToken: "pending-token",
		AuthenticationChallengeID:  "auth_challenge_123",
		Code:                       "123456",
	})
	if err != nil {
		t.Fatalf("authenticate with totp: %v", err)
	}
	if authenticated.User.ID != "user_123" || authenticated.OrganizationID != "org_123" || authenticated.AuthenticationMethod != "GitHubOAuth" {
		t.Fatalf("unexpected authentication: %+v", authenticated)
	}
}

func TestAsWorkOSMFARequiredMapsStructuredChallenge(t *testing.T) {
	required, ok := AsWorkOSMFARequired(&workos_errors.MFAChallengeError{
		Code:                       workos_errors.MFAChallengeCode,
		Message:                    "MFA required",
		User:                       common.User{ID: "user_123", Email: "user@example.com", EmailVerified: true},
		AuthenticationFactors:      []workos_errors.AuthenticationFactor{{ID: "auth_factor_123", Type: workos_errors.TOTP}},
		PendingAuthenticationToken: "pending-token",
	})
	if !ok {
		t.Fatal("expected mfa required error")
	}
	if required.Mode != WorkOSMFAModeChallenge || required.User.ID != "user_123" || len(required.AuthenticationFactors) != 1 || required.AuthenticationFactors[0].ID != "auth_factor_123" {
		t.Fatalf("unexpected mfa requirement: %+v", required)
	}
	if strings.Contains(required.Error(), "pending-token") {
		t.Fatalf("mfa required error must not expose pending token: %q", required.Error())
	}
}

func TestAsWorkOSMFARequiredMapsGenericHTTPError(t *testing.T) {
	required, ok := AsWorkOSMFARequired(workos_errors.HTTPError{
		ErrorCode:                  workos_errors.MFAEnrollmentCode,
		PendingAuthenticationToken: "pending-token",
		User:                       &common.User{ID: "user_123", Email: "user@example.com", EmailVerified: true},
	})
	if !ok {
		t.Fatal("expected mfa enrollment requirement")
	}
	if required.Mode != WorkOSMFAModeEnrollment || required.User.Email != "user@example.com" || required.PendingAuthenticationToken != "pending-token" {
		t.Fatalf("unexpected enrollment requirement: %+v", required)
	}
}

func TestWorkOSSDKClientUnavailable(t *testing.T) {
	if _, err := (*WorkOSSDKClient)(nil).AuthorizationURL(WorkOSAuthorizationRequest{}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable auth url error, got %v", err)
	}
	if _, err := (*WorkOSSDKClient)(nil).AuthenticateWithCode(context.Background(), WorkOSAuthenticationRequest{}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable authenticate error, got %v", err)
	}
	if _, err := (*WorkOSSDKClient)(nil).EnrollAuthFactor(context.Background(), WorkOSMFAEnrollRequest{}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable enroll error, got %v", err)
	}
	if _, err := (*WorkOSSDKClient)(nil).ChallengeAuthFactor(context.Background(), WorkOSMFAChallengeRequest{}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable challenge error, got %v", err)
	}
	if _, err := (*WorkOSSDKClient)(nil).AuthenticateWithTOTP(context.Background(), WorkOSMFAVerifyRequest{}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable totp error, got %v", err)
	}
}
