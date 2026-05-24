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

func TestRepositoryClientListDependabotAlerts(t *testing.T) {
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
			if r.URL.Path != "/repos/owner/repo/dependabot/alerts" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			if r.URL.Query().Get("state") != "open" || r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("unexpected first page query %s", r.URL.RawQuery)
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/owner/repo/dependabot/alerts?state=open&per_page=100&page=2>; rel="next"`, serverURLFromRequest(r)))
			_, _ = w.Write([]byte(`[{
				"number": 1,
				"state": "open",
				"dependency": {"package": {"ecosystem": "pip", "name": "django"}, "manifest_path": "requirements.txt", "scope": "runtime"},
				"security_advisory": {
					"ghsa_id": "GHSA-xxxx-yyyy-zzzz",
					"cve_id": "CVE-2024-0001",
					"summary": "SQL injection in django",
					"severity": "high",
					"identifiers": [{"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"}, {"type": "CVE", "value": "CVE-2024-0001"}]
				},
				"security_vulnerability": {
					"package": {"ecosystem": "pip", "name": "django"},
					"severity": "high",
					"vulnerable_version_range": "< 4.2.1",
					"first_patched_version": {"identifier": "4.2.1"}
				},
				"html_url": "https://github.com/owner/repo/security/dependabot/1"
			}]`))
		case 2:
			if r.URL.Query().Get("page") != "2" {
				t.Fatalf("unexpected second page query %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{
				"number": 2,
				"state": "open",
				"dependency": {"package": {"ecosystem": "npm", "name": "lodash"}, "manifest_path": "package.json"},
				"security_advisory": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "severity": "critical"},
				"security_vulnerability": {"severity": "critical", "vulnerable_version_range": "< 4.17.21"}
			}]`))
		default:
			t.Fatalf("unexpected extra page")
		}
	}))
	defer server.Close()

	alerts, err := (RepositoryClient{
		TokenClient: minter,
		APIBaseURL:  server.URL,
	}).ListDependabotAlerts(context.Background(), 456, "Owner/Repo")
	if err != nil {
		t.Fatalf("list dependabot alerts: %v", err)
	}
	if minter.seenInstallationID != 456 {
		t.Fatalf("unexpected installation id %d", minter.seenInstallationID)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected two alerts, got %+v", alerts)
	}
	if alerts[0].Dependency.Package.Name != "django" || alerts[0].SecurityAdvisory.GHSAID != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("unexpected first alert %+v", alerts[0])
	}
	if alerts[0].SecurityVulnerability.FirstPatchedVersion.Identifier != "4.2.1" {
		t.Fatalf("expected fixed version, got %+v", alerts[0].SecurityVulnerability)
	}
	if alerts[1].Number != 2 || alerts[1].SecurityAdvisory.Severity != "critical" {
		t.Fatalf("unexpected second alert %+v", alerts[1])
	}
}

func TestRepositoryClientListDependabotAlertsErrors(t *testing.T) {
	if _, err := (RepositoryClient{}).ListDependabotAlerts(context.Background(), 1, "owner/repo"); err == nil {
		t.Fatal("expected missing token client error")
	}
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	if _, err := (RepositoryClient{TokenClient: minter}).ListDependabotAlerts(context.Background(), 1, "not-a-repo"); err == nil || !strings.Contains(err.Error(), "owner/name") {
		t.Fatalf("expected owner/name validation error, got %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"permission denied"}`, http.StatusForbidden)
	}))
	defer server.Close()
	_, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).ListDependabotAlerts(context.Background(), 1, "owner/repo")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected status error, got %v", err)
	}
}
