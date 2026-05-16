package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestWorkOSSDKClientUnavailable(t *testing.T) {
	if _, err := (*WorkOSSDKClient)(nil).AuthorizationURL(WorkOSAuthorizationRequest{}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable auth url error, got %v", err)
	}
	if _, err := (*WorkOSSDKClient)(nil).AuthenticateWithCode(context.Background(), WorkOSAuthenticationRequest{}); err != ErrWorkOSUnavailable {
		t.Fatalf("expected unavailable authenticate error, got %v", err)
	}
}
