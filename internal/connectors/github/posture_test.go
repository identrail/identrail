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

func TestRepositoryClientCollectRepositoryPostureHappyPath(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer inst-token" {
			t.Errorf("missing installation token for %s", r.URL.String())
			return
		}
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4990")
		switch r.URL.Path {
		case "/repos/owner/repo":
			_, _ = w.Write([]byte(`{
				"full_name":"owner/repo",
				"private":true,
				"visibility":"private",
				"default_branch":"main",
				"archived":false,
				"disabled":false,
				"fork":false,
				"has_security_policy":true,
				"security_and_analysis":{"secret_scanning":{"status":"enabled"}}
			}`))
		case "/repos/owner/repo/branches/main/protection":
			_, _ = w.Write([]byte(`{
				"required_pull_request_reviews":{"required_approving_review_count":2,"dismiss_stale_reviews":true,"require_code_owner_reviews":true},
				"required_status_checks":{"strict":true,"contexts":["test"],"checks":[{"context":"lint"}]},
				"enforce_admins":{"enabled":true},
				"allow_force_pushes":{"enabled":false},
				"allow_deletions":{"enabled":false}
			}`))
		case "/repos/owner/repo/rulesets":
			if r.URL.Query().Get("targets") != "branch" {
				t.Errorf("expected branch ruleset target, got %s", r.URL.RawQuery)
				return
			}
			_, _ = w.Write([]byte(`[{"id":1,"name":"main","target":"branch","enforcement":"active","rules":[{"type":"pull_request"}]}]`))
		case "/repos/owner/repo/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled":true,"allowed_actions":"selected","default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/repos/owner/repo/vulnerability-alerts", "/repos/owner/repo/automated-security-fixes":
			w.WriteHeader(http.StatusNoContent)
		case "/repos/owner/repo/code-scanning/alerts", "/repos/owner/repo/secret-scanning/alerts":
			_, _ = w.Write([]byte(`[]`))
		case "/repos/owner/repo/keys":
			if r.URL.Query().Get("page") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s/repos/owner/repo/keys?per_page=100&page=2>; rel="next"`, serverURLFromRequest(r)))
				_, _ = w.Write([]byte(`[{"id":1,"title":"readonly","read_only":true}]`))
				return
			}
			_, _ = w.Write([]byte(`[]`))
		case "/repos/owner/repo/hooks":
			_, _ = w.Write([]byte(`[{"id":1,"name":"web","active":true,"events":["push"],"config":{"insecure_ssl":"0"},"last_response":{"code":200,"status":"ok"}}]`))
		case "/repos/owner/repo/environments":
			if r.URL.Query().Get("page") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s/repos/owner/repo/environments?per_page=100&page=2>; rel="next"`, serverURLFromRequest(r)))
				_, _ = w.Write([]byte(`{"total_count":2,"environments":[{"name":"production","protection_rules":[{"type":"required_reviewers"}]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"total_count":2,"environments":[{"name":"staging","protection_rules":[{"type":"required_reviewers"}]}]}`))
		default:
			t.Errorf("unexpected posture path %s", r.URL.String())
			return
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{
		TokenClient: minter,
		APIBaseURL:  server.URL,
		Now:         func() time.Time { return time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC) },
	}).CollectRepositoryPosture(context.Background(), 123, "Owner/Repo")
	if err != nil {
		t.Fatalf("collect posture: %v", err)
	}
	if minter.seenInstallationID != 123 {
		t.Fatalf("expected installation 123, got %d", minter.seenInstallationID)
	}
	if posture.Repository != "owner/repo" || posture.InstallationID != 123 || len(posture.Checks) != 10 {
		t.Fatalf("unexpected posture summary: %+v", posture)
	}
	for _, id := range []string{
		"repository_metadata",
		"default_branch_protection",
		"repository_rulesets",
		"actions_permissions",
		"dependabot_security",
		"code_scanning",
		"secret_scanning",
		"deploy_keys",
		"webhooks",
		"deployment_environments",
	} {
		if check := postureCheckByID(posture, id); check.State != RepositoryPostureStateSecure {
			t.Fatalf("expected %s to be secure, got %+v", id, check)
		}
	}
	if posture.RateLimit == nil || posture.RateLimit.Remaining != 4990 {
		t.Fatalf("expected rate limit headers to be captured, got %+v", posture.RateLimit)
	}
}

func TestRepositoryClientCollectRepositoryPostureClassifiesWeakSettings(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo":
			_, _ = w.Write([]byte(`{"full_name":"owner/repo","private":false,"visibility":"public","default_branch":"main","has_security_policy":false}`))
		case "/repos/owner/repo/branches/main/protection":
			http.Error(w, `{"message":"Branch not protected"}`, http.StatusNotFound)
		case "/repos/owner/repo/rulesets":
			_, _ = w.Write([]byte(`[]`))
		case "/repos/owner/repo/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled":true,"allowed_actions":"all","default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`))
		case "/repos/owner/repo/vulnerability-alerts", "/repos/owner/repo/automated-security-fixes":
			http.Error(w, `{"message":"disabled"}`, http.StatusNotFound)
		case "/repos/owner/repo/code-scanning/alerts", "/repos/owner/repo/secret-scanning/alerts":
			_, _ = w.Write([]byte(`[{"number":1,"state":"open"}]`))
		case "/repos/owner/repo/keys":
			_, _ = w.Write([]byte(`[{"id":1,"title":"write-key","read_only":false}]`))
		case "/repos/owner/repo/hooks":
			_, _ = w.Write([]byte(`[{"id":1,"active":true,"config":{"insecure_ssl":"1"},"last_response":{"code":500,"status":"failed"}}]`))
		case "/repos/owner/repo/environments":
			_, _ = w.Write([]byte(`{"total_count":1,"environments":[{"name":"production","protection_rules":[]}]}`))
		default:
			t.Errorf("unexpected posture path %s", r.URL.String())
			return
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectRepositoryPosture(context.Background(), 123, "owner/repo")
	if err != nil {
		t.Fatalf("collect posture: %v", err)
	}
	for _, id := range []string{
		"repository_metadata",
		"default_branch_protection",
		"repository_rulesets",
		"actions_permissions",
		"dependabot_security",
		"code_scanning",
		"secret_scanning",
		"deploy_keys",
		"webhooks",
		"deployment_environments",
	} {
		if check := postureCheckByID(posture, id); check.State != RepositoryPostureStateInsecure {
			t.Fatalf("expected %s to be insecure, got %+v", id, check)
		}
	}
}

func TestRepositoryClientCollectRepositoryPosturePermissionAndRateLimitStates(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo":
			_, _ = w.Write([]byte(`{"full_name":"owner/repo","default_branch":"main","has_security_policy":true}`))
		case "/repos/owner/repo/branches/main/protection":
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		case "/repos/owner/repo/rulesets":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1770000000")
			http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
		case "/repos/owner/repo/actions/permissions":
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"message":"You have exceeded a secondary rate limit. Please wait before you try again."}`, http.StatusForbidden)
		case "/repos/owner/repo/vulnerability-alerts", "/repos/owner/repo/automated-security-fixes":
			w.WriteHeader(http.StatusNoContent)
		case "/repos/owner/repo/code-scanning/alerts", "/repos/owner/repo/secret-scanning/alerts", "/repos/owner/repo/keys", "/repos/owner/repo/hooks":
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		case "/repos/owner/repo/environments":
			_, _ = w.Write([]byte(`{"total_count":0,"environments":[]}`))
		default:
			t.Errorf("unexpected posture path %s", r.URL.String())
			return
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectRepositoryPosture(context.Background(), 123, "owner/repo")
	if err != nil {
		t.Fatalf("collect posture: %v", err)
	}
	if check := postureCheckByID(posture, "default_branch_protection"); check.State != RepositoryPostureStatePermissionLimited {
		t.Fatalf("expected branch protection permission-limited, got %+v", check)
	}
	if check := postureCheckByID(posture, "repository_rulesets"); check.State != RepositoryPostureStateUnavailable || check.Reason != "rate_limited" {
		t.Fatalf("expected rulesets rate limited, got %+v", check)
	}
	if check := postureCheckByID(posture, "actions_permissions"); check.State != RepositoryPostureStateUnavailable || check.Reason != "rate_limited" {
		t.Fatalf("expected actions secondary rate limit, got %+v", check)
	}
}

func TestRepositoryClientCollectRepositoryPostureInputErrors(t *testing.T) {
	if _, err := (RepositoryClient{}).CollectRepositoryPosture(context.Background(), 1, "owner/repo"); err == nil {
		t.Fatal("expected missing token client error")
	}
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	if _, err := (RepositoryClient{TokenClient: minter}).CollectRepositoryPosture(context.Background(), 1, "not-a-repo"); err == nil || !strings.Contains(err.Error(), "owner/name") {
		t.Fatalf("expected repository validation error, got %v", err)
	}
}

func postureCheckByID(posture RepositoryPosture, id string) RepositoryPostureCheck {
	for _, check := range posture.Checks {
		if check.ID == id {
			return check
		}
	}
	return RepositoryPostureCheck{}
}
