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

func TestRepositoryClientListCodeScanningAlerts(t *testing.T) {
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
			if r.URL.Path != "/repos/owner/repo/code-scanning/alerts" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			if r.URL.Query().Get("state") != "open" || r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("unexpected first page query %s", r.URL.RawQuery)
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/owner/repo/code-scanning/alerts?state=open&per_page=100&page=2>; rel="next"`, serverURLFromRequest(r)))
			_, _ = w.Write([]byte(`[{
				"number": 1,
				"state": "open",
				"rule": {"id": "js/sql-injection", "name": "SQL injection", "severity": "warning", "security_severity_level": "high", "tags": ["security"]},
				"tool": {"name": "CodeQL", "version": "2.17.0"},
				"most_recent_instance": {
					"state": "open",
					"commit_sha": "abc123",
					"message": {"text": "Query includes user input."},
					"location": {"path": "src/db.ts", "start_line": 88, "start_column": 11}
				},
				"html_url": "https://github.com/owner/repo/security/code-scanning/1"
			}]`))
		case 2:
			if r.URL.Query().Get("page") != "2" {
				t.Fatalf("unexpected second page query %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{
				"number": 2,
				"state": "open",
				"rule": {"id": "go/path-injection", "name": "Path injection", "severity": "error"},
				"tool": {"name": "CodeQL"},
				"most_recent_instance": {
					"commit_sha": "def456",
					"message": {"text": "Path includes user input."},
					"location": {"path": "main.go", "start_line": 12}
				}
			}]`))
		default:
			t.Fatalf("unexpected extra page")
		}
	}))
	defer server.Close()

	alerts, err := (RepositoryClient{
		TokenClient: minter,
		APIBaseURL:  server.URL,
	}).ListCodeScanningAlerts(context.Background(), 456, "Owner/Repo")
	if err != nil {
		t.Fatalf("list code scanning alerts: %v", err)
	}
	if minter.seenInstallationID != 456 {
		t.Fatalf("unexpected installation id %d", minter.seenInstallationID)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected two alerts, got %+v", alerts)
	}
	if alerts[0].Rule.ID != "js/sql-injection" || alerts[0].Tool.Name != "CodeQL" || alerts[0].MostRecentInstance.Location.Path != "src/db.ts" {
		t.Fatalf("unexpected first alert %+v", alerts[0])
	}
	if alerts[1].Number != 2 || alerts[1].MostRecentInstance.CommitSHA != "def456" {
		t.Fatalf("unexpected second alert %+v", alerts[1])
	}
}

func TestRepositoryClientListCodeScanningAlertsErrors(t *testing.T) {
	if _, err := (RepositoryClient{}).ListCodeScanningAlerts(context.Background(), 1, "owner/repo"); err == nil {
		t.Fatal("expected missing token client error")
	}
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	if _, err := (RepositoryClient{TokenClient: minter}).ListCodeScanningAlerts(context.Background(), 1, "not-a-repo"); err == nil || !strings.Contains(err.Error(), "owner/name") {
		t.Fatalf("expected owner/name validation error, got %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"permission denied"}`, http.StatusForbidden)
	}))
	defer server.Close()
	_, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).ListCodeScanningAlerts(context.Background(), 1, "owner/repo")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected status error, got %v", err)
	}
}
