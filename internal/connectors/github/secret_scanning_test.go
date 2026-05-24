package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRepositoryClientListSecretScanningAlerts(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer inst-token" {
			t.Fatalf("missing installation token")
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Fatalf("missing GitHub API version header")
		}
		switch calls {
		case 1:
			if r.URL.Path != "/repos/owner/repo/secret-scanning/alerts" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			query := r.URL.Query()
			if query.Get("state") != "open" || query.Get("per_page") != "100" || query.Get("hide_secret") != "true" {
				t.Fatalf("unexpected first page query %s", r.URL.RawQuery)
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/owner/repo/secret-scanning/alerts?state=open&per_page=100&page=2>; rel="next"`, serverURLFromRequest(r)))
			_, _ = w.Write([]byte(`[{
				"number": 1,
				"state": "open",
				"secret_type": "github_personal_access_token",
				"secret_type_display_name": "GitHub Personal Access Token",
				"secret": "placeholder_secret_value",
				"validity": "active",
				"html_url": "https://github.com/owner/repo/security/secret-scanning/1"
			}]`))
		case 2:
			if r.URL.Query().Get("page") != "2" {
				t.Fatalf("unexpected second page query %s", r.URL.RawQuery)
			}
			if r.URL.Query().Get("hide_secret") != "true" {
				t.Fatalf("second page did not preserve hide_secret=true: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{
				"number": 2,
				"state": "open",
				"secret_type": "aws_access_key_id",
				"secret_type_display_name": "Amazon AWS Access Key ID",
				"validity": "unknown"
			}]`))
		default:
			t.Fatalf("unexpected extra page")
		}
	}))
	defer server.Close()

	alerts, err := (RepositoryClient{
		TokenClient: minter,
		APIBaseURL:  server.URL,
	}).ListSecretScanningAlerts(context.Background(), 456, "Owner/Repo")
	if err != nil {
		t.Fatalf("list secret scanning alerts: %v", err)
	}
	if minter.seenInstallationID != 456 {
		t.Fatalf("unexpected installation id %d", minter.seenInstallationID)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected two alerts, got %+v", alerts)
	}
	if alerts[0].SecretType != "github_personal_access_token" || alerts[0].Validity != "active" {
		t.Fatalf("unexpected first alert %+v", alerts[0])
	}
	if alerts[1].Number != 2 || alerts[1].SecretType != "aws_access_key_id" {
		t.Fatalf("unexpected second alert %+v", alerts[1])
	}
}

func TestRepositoryClientListSecretScanningAlertsErrors(t *testing.T) {
	if _, err := (RepositoryClient{}).ListSecretScanningAlerts(context.Background(), 1, "owner/repo"); err == nil {
		t.Fatal("expected missing token client error")
	}
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	if _, err := (RepositoryClient{TokenClient: minter}).ListSecretScanningAlerts(context.Background(), 1, "not-a-repo"); err == nil || !strings.Contains(err.Error(), "owner/name") {
		t.Fatalf("expected owner/name validation error, got %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"permission denied"}`, http.StatusForbidden)
	}))
	defer server.Close()
	_, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).ListSecretScanningAlerts(context.Background(), 1, "owner/repo")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected status error, got %v", err)
	}
}
