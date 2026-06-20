package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// newOAuthTestServer serves the token exchange and /user/installations endpoints.
// ownedInstallationIDs are the installations the authorizing user can access.
func newOAuthTestServer(t *testing.T, expectedCode string, ownedInstallationIDs ...int64) *httptest.Server {
	t.Helper()
	body := strings.Builder{}
	body.WriteString(`{"total_count":` + strconv.Itoa(len(ownedInstallationIDs)) + `,"installations":[`)
	for i, id := range ownedInstallationIDs {
		if i > 0 {
			body.WriteString(",")
		}
		body.WriteString(`{"id":` + strconv.FormatInt(id, 10) + `,"account":{"login":"victim-org","type":"Organization"}}`)
	}
	body.WriteString("]}")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if r.Form.Get("code") != expectedCode {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"user-token","token_type":"bearer"}`))
		case "/user/installations":
			if r.Header.Get("Authorization") != "Bearer user-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body.String()))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
}

func newOAuthTestClient(server *httptest.Server) UserOAuthClient {
	return UserOAuthClient{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		OAuthBaseURL: server.URL,
		APIBaseURL:   server.URL,
	}
}

func TestUserOAuthClientVerifiesOwnedInstallation(t *testing.T) {
	server := newOAuthTestServer(t, "good-code", 555, 12345)
	defer server.Close()

	verified, err := newOAuthTestClient(server).VerifyInstallationOwnership(context.Background(), "good-code", 12345)
	if err != nil {
		t.Fatalf("verify owned installation: %v", err)
	}
	if verified.InstallationID != 12345 {
		t.Fatalf("expected installation 12345, got %d", verified.InstallationID)
	}
	if verified.AccountLogin != "victim-org" || verified.AccountType != "Organization" {
		t.Fatalf("expected account from GitHub, got %+v", verified)
	}
}

// TestUserOAuthClientRejectsUnownedInstallation is the core security case: the
// authorizing user does not have access to the supplied installation id.
func TestUserOAuthClientRejectsUnownedInstallation(t *testing.T) {
	server := newOAuthTestServer(t, "good-code", 555) // user only owns 555
	defer server.Close()

	_, err := newOAuthTestClient(server).VerifyInstallationOwnership(context.Background(), "good-code", 12345)
	if !errors.Is(err, ErrInstallationNotOwned) {
		t.Fatalf("expected ErrInstallationNotOwned, got %v", err)
	}
}

func TestUserOAuthClientRejectsBadCode(t *testing.T) {
	server := newOAuthTestServer(t, "good-code", 12345)
	defer server.Close()

	_, err := newOAuthTestClient(server).VerifyInstallationOwnership(context.Background(), "attacker-code", 12345)
	if err == nil || errors.Is(err, ErrInstallationNotOwned) {
		t.Fatalf("expected token exchange failure, got %v", err)
	}
}

func TestUserOAuthClientRequiresConfigAndInputs(t *testing.T) {
	unconfigured := UserOAuthClient{}
	if unconfigured.Configured() {
		t.Fatal("zero-value client must not be considered configured")
	}
	if _, err := unconfigured.VerifyInstallationOwnership(context.Background(), "code", 1); err == nil {
		t.Fatal("expected error for unconfigured client")
	}

	configured := UserOAuthClient{ClientID: "id", ClientSecret: "secret"}
	if _, err := configured.VerifyInstallationOwnership(context.Background(), "", 1); err == nil {
		t.Fatal("expected error for empty code")
	}
	if _, err := configured.VerifyInstallationOwnership(context.Background(), "code", 0); err == nil {
		t.Fatal("expected error for non-positive installation id")
	}
}
