package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const pinnedSelectedActionPattern = "acme/reusable@0123456789abcdef0123456789abcdef01234567"

func TestCollectOrganizationPostureSecure(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	codeSecurityCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer inst-token" {
			t.Errorf("missing installation token for %s", r.URL.String())
			return
		}
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4990")
		switch r.URL.Path {
		case "/orgs/acme":
			_, _ = w.Write([]byte(`{
				"login":"acme",
				"secret_scanning_enabled_for_new_repositories":true,
				"secret_scanning_push_protection_enabled_for_new_repositories":true,
				"secret_scanning_validity_checks_enabled":true,
				"advanced_security_enabled_for_new_repositories":true
			}`))
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"selected"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			_, _ = w.Write([]byte(`{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["` + pinnedSelectedActionPattern + `"]}`))
		case "/orgs/acme/code-security/configurations":
			codeSecurityCalls++
			_, _ = w.Write([]byte(`[{"id":1,"name":"baseline","target_type":"organization","enforcement":"enforced","secret_scanning":"enabled","secret_scanning_push_protection":"enabled","dependabot_alerts":"enabled"}]`))
		case "/repos/acme/repo/code-security-configuration":
			_, _ = w.Write([]byte(`{"status":"attached","configuration":{"id":1,"name":"baseline","target_type":"organization","enforcement":"enforced","secret_scanning":"enabled","secret_scanning_push_protection":"enabled","dependabot_alerts":"enabled"}}`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{
		TokenClient: minter,
		APIBaseURL:  server.URL,
		Now:         func() time.Time { return time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC) },
	}).CollectOrganizationPosture(context.Background(), 321, "ACME", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if posture.Organization != "acme" || posture.InstallationID != 321 || len(posture.Checks) != 5 {
		t.Fatalf("unexpected org posture summary: %+v", posture)
	}
	for _, id := range []string{
		"org_secret_scanning_policy",
		"org_actions_policy",
		"org_workflow_permissions",
		"org_reusable_workflow_policy",
		"org_code_security_configuration",
	} {
		if check := orgPostureCheckByID(posture, id); check.State != RepositoryPostureStateSecure {
			t.Fatalf("expected %s secure, got %+v", id, check)
		}
	}
	if posture.RateLimit == nil || posture.RateLimit.Remaining != 4990 {
		t.Fatalf("expected rate limit headers captured, got %+v", posture.RateLimit)
	}
	if codeSecurityCalls != 1 {
		t.Fatalf("expected code security configurations to be fetched once, got %d calls", codeSecurityCalls)
	}
}

func TestCollectOrganizationPostureParsesNestedCodeSecurityConfigurations(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"selected"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			_, _ = w.Write([]byte(`{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["` + pinnedSelectedActionPattern + `"]}`))
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[{
				"id": 100,
				"configuration": {
					"id": 1,
					"name": "baseline",
					"target_type": "organization",
					"enforcement": "enforced",
					"secret_scanning": "enabled",
					"secret_scanning_push_protection": "enabled",
					"dependabot_alerts": "enabled"
				}
			}]`))
		case "/repos/acme/repo/code-security-configuration":
			_, _ = w.Write([]byte(`{"status":"attached","configuration":{"id":1,"name":"baseline","target_type":"organization","enforcement":"enforced","secret_scanning":"enabled","secret_scanning_push_protection":"enabled","dependabot_alerts":"enabled"}}`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_code_security_configuration"); check.State != RepositoryPostureStateSecure {
		t.Fatalf("expected nested code security configuration to be secure, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_secret_scanning_policy"); check.State != RepositoryPostureStateSecure {
		t.Fatalf("expected nested code security configuration to prove secret scanning policy, got %+v", check)
	}
}

func TestCollectOrganizationPostureFlagsBroadSelectedActionPatterns(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"selected"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			_, _ = w.Write([]byte(`{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["acme/*@main","partner/action@v1"]}`))
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	check := orgPostureCheckByID(posture, "org_reusable_workflow_policy")
	if check.State != RepositoryPostureStateInsecure || check.Reason != "broad_action_allowlist" {
		t.Fatalf("expected broad selected-actions patterns to be insecure, got %+v", check)
	}
	if count, ok := check.Evidence["risky_pattern_count"].(int); !ok || count != 2 {
		t.Fatalf("expected risky pattern count evidence, got %+v", check.Evidence)
	}
}

func TestCollectOrganizationPostureRequiresRepositoryCodeSecurityConfiguration(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"selected"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			_, _ = w.Write([]byte(`{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["` + pinnedSelectedActionPattern + `"]}`))
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[{"id":1,"name":"baseline","target_type":"organization","enforcement":"enforced","secret_scanning":"enabled","secret_scanning_push_protection":"enabled","default_for_new_repos":"public"}]`))
		case "/repos/acme/repo/code-security-configuration":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_code_security_configuration"); check.State != RepositoryPostureStateInsecure || check.Reason != "configuration_not_applied" {
		t.Fatalf("expected unattached repository config not to count as secure, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_secret_scanning_policy"); check.State != RepositoryPostureStateInsecure || check.Reason != "secret_scanning_policy_weak" {
		t.Fatalf("expected unattached repository config not to prove secret scanning policy, got %+v", check)
	}
}

func TestCollectOrganizationPostureInsecure(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			_, _ = w.Write([]byte(`{"login":"acme","secret_scanning_enabled_for_new_repositories":true,"secret_scanning_push_protection_enabled_for_new_repositories":false}`))
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"all","allowed_actions":"all"}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			t.Errorf("selected-actions allowlist should not be requested when allowed_actions is all")
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[{"id":1,"name":"baseline","target_type":"organization","enforcement":"enforced","secret_scanning":"disabled","secret_scanning_push_protection":"disabled"}]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	for _, id := range []string{
		"org_secret_scanning_policy",
		"org_actions_policy",
		"org_workflow_permissions",
		"org_code_security_configuration",
	} {
		if check := orgPostureCheckByID(posture, id); check.State != RepositoryPostureStateInsecure {
			t.Fatalf("expected %s insecure, got %+v", id, check)
		}
	}
	if check := orgPostureCheckByID(posture, "org_reusable_workflow_policy"); check.State != RepositoryPostureStateSecure || check.Reason != "not_applicable" {
		t.Fatalf("expected reusable workflow secure/not_applicable, got %+v", check)
	}
}

func TestCollectOrganizationPostureActionsDisabledIsNotBroadActionsRisk(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			_, _ = w.Write([]byte(`{"login":"acme","secret_scanning_enabled_for_new_repositories":true,"secret_scanning_push_protection_enabled_for_new_repositories":true}`))
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"none","allowed_actions":"all"}`))
		case "/orgs/acme/actions/permissions/workflow":
			t.Errorf("workflow permissions should not be requested when Actions is disabled")
		case "/orgs/acme/actions/permissions/selected-actions":
			t.Errorf("selected-actions allowlist should not be requested when Actions is disabled")
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_actions_policy"); check.State != RepositoryPostureStateSecure || check.Reason != "actions_disabled" {
		t.Fatalf("expected disabled actions to be secure/actions_disabled, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_workflow_permissions"); check.State != RepositoryPostureStateSecure || check.Reason != "actions_disabled" {
		t.Fatalf("expected disabled actions to skip workflow risk scoring, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_reusable_workflow_policy"); check.State != RepositoryPostureStateSecure || check.Reason != "not_applicable" {
		t.Fatalf("expected disabled actions to skip reusable workflow risk scoring, got %+v", check)
	}
}

func TestCollectOrganizationPostureSelectedActionsRepoMembershipGatesActionsRisk(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			_, _ = w.Write([]byte(`{"login":"acme","secret_scanning_enabled_for_new_repositories":true,"secret_scanning_push_protection_enabled_for_new_repositories":true}`))
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"all"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/other"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			t.Errorf("workflow permissions should not be requested when repository is not selected for Actions")
		case "/orgs/acme/actions/permissions/selected-actions":
			t.Errorf("selected-actions allowlist should not be requested when repository is not selected for Actions")
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_actions_policy"); check.State != RepositoryPostureStateSecure || check.Reason != "actions_not_enabled_for_repository" {
		t.Fatalf("expected unselected repository to skip org actions risk, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_workflow_permissions"); check.State != RepositoryPostureStateSecure || check.Reason != "actions_not_enabled_for_repository" {
		t.Fatalf("expected unselected repository to skip workflow risk scoring, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_reusable_workflow_policy"); check.State != RepositoryPostureStateSecure || check.Reason != "not_applicable" {
		t.Fatalf("expected unselected repository to skip reusable workflow risk scoring, got %+v", check)
	}
}

func TestCollectOrganizationPostureSelectedActionsRepoMembershipStopsAfterMatch(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	selectedRepoCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			_, _ = w.Write([]byte(`{"login":"acme","secret_scanning_enabled_for_new_repositories":true,"secret_scanning_push_protection_enabled_for_new_repositories":true}`))
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"all"}`))
		case "/orgs/acme/actions/permissions/repositories":
			selectedRepoCalls++
			if selectedRepoCalls > 1 {
				t.Errorf("selected repository pagination should stop after the repository is found")
			}
			w.Header().Set("Link", `<`+serverURLFromRequest(r)+`/orgs/acme/actions/permissions/repositories?per_page=100&page=2>; rel="next"`)
			_, _ = w.Write([]byte(`{"total_count":2,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if selectedRepoCalls != 1 {
		t.Fatalf("expected one selected repository page request, got %d", selectedRepoCalls)
	}
	if check := orgPostureCheckByID(posture, "org_actions_policy"); check.Reason == "actions_not_enabled_for_repository" {
		t.Fatalf("expected matched repository to keep actions policy applicable, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_workflow_permissions"); check.State != RepositoryPostureStateSecure || check.Reason != "least_privilege_workflows" {
		t.Fatalf("expected matched repository to keep workflow policy applicable, got %+v", check)
	}
}

func TestCollectOrganizationPosturePermissionAndRateLimitStates(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		case "/orgs/acme/actions/permissions":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1780000000")
			http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
		case "/orgs/acme/actions/permissions/workflow":
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		case "/orgs/acme/actions/permissions/selected-actions":
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		case "/orgs/acme/code-security/configurations":
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_secret_scanning_policy"); check.State != RepositoryPostureStatePermissionLimited {
		t.Fatalf("expected secret scanning permission limited, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_actions_policy"); check.State != RepositoryPostureStateUnavailable || check.Reason != "rate_limited" {
		t.Fatalf("expected actions policy rate limited, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_code_security_configuration"); check.State != RepositoryPostureStatePermissionLimited {
		t.Fatalf("expected code security permission limited, got %+v", check)
	}
}

func TestCollectOrganizationPostureUnsupportedAndUnknownStates(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"all","allowed_actions":""}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			http.Error(w, `{"message":"Allowed actions must be set to selected"}`, http.StatusConflict)
		case "/orgs/acme/code-security/configurations":
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_secret_scanning_policy"); check.State != RepositoryPostureStateUnsupported || check.Reason != "plan_unavailable" {
		t.Fatalf("expected secret scanning unsupported/plan_unavailable, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_actions_policy"); check.State != RepositoryPostureStateUnknown {
		t.Fatalf("expected actions policy unknown, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_workflow_permissions"); check.State != RepositoryPostureStateUnknown {
		t.Fatalf("expected workflow permissions unknown, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_reusable_workflow_policy"); check.State != RepositoryPostureStateSecure || check.Reason != "not_applicable" {
		t.Fatalf("expected reusable workflow secure/not_applicable, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_code_security_configuration"); check.State != RepositoryPostureStateUnsupported || check.Reason != "plan_unavailable" {
		t.Fatalf("expected code security unsupported/plan_unavailable, got %+v", check)
	}
}

func TestCollectOrganizationPostureSecretScanningPolicyWeakWithoutCentralConfiguration(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			_, _ = w.Write([]byte(`{"login":"acme"}`))
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"local_only"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read"}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			t.Errorf("selected-actions allowlist should not be requested when allowed_actions is local_only")
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_secret_scanning_policy"); check.State != RepositoryPostureStateInsecure || check.Reason != "secret_scanning_policy_weak" {
		t.Fatalf("expected secret scanning insecure/secret_scanning_policy_weak, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_reusable_workflow_policy"); check.State != RepositoryPostureStateSecure || check.Reason != "not_applicable" {
		t.Fatalf("expected reusable workflow secure/not_applicable, got %+v", check)
	}
}

func TestCollectOrganizationPostureIgnoresGlobalCodeSecurityTemplates(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"selected"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			_, _ = w.Write([]byte(`{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["` + pinnedSelectedActionPattern + `"]}`))
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[{"id":1,"name":"recommended","target_type":"global","enforcement":"enforced","secret_scanning":"enabled","secret_scanning_push_protection":"enabled"}]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_code_security_configuration"); check.State != RepositoryPostureStateInsecure || check.Reason != "no_central_configuration" {
		t.Fatalf("expected global template not to count as central config, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_secret_scanning_policy"); check.State != RepositoryPostureStateInsecure {
		t.Fatalf("expected global template not to prove secret scanning policy, got %+v", check)
	}
}

func TestCollectOrganizationPostureRequiresEnforcedCodeSecurityConfiguration(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_repositories":"selected","allowed_actions":"selected"}`))
		case "/orgs/acme/actions/permissions/repositories":
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"full_name":"acme/repo"}]}`))
		case "/orgs/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`))
		case "/orgs/acme/actions/permissions/selected-actions":
			_, _ = w.Write([]byte(`{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["` + pinnedSelectedActionPattern + `"]}`))
		case "/orgs/acme/code-security/configurations":
			_, _ = w.Write([]byte(`[{"id":1,"name":"baseline","target_type":"organization","enforcement":"unenforced","secret_scanning":"enabled","secret_scanning_push_protection":"enabled"}]`))
		default:
			t.Errorf("unexpected org posture path %s", r.URL.String())
		}
	}))
	defer server.Close()

	posture, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).CollectOrganizationPosture(context.Background(), 321, "acme", "acme/repo")
	if err != nil {
		t.Fatalf("collect org posture: %v", err)
	}
	if check := orgPostureCheckByID(posture, "org_code_security_configuration"); check.State != RepositoryPostureStateInsecure || check.Reason != "configuration_not_enforced" {
		t.Fatalf("expected unenforced config not to count as secure, got %+v", check)
	}
	if check := orgPostureCheckByID(posture, "org_secret_scanning_policy"); check.State != RepositoryPostureStateInsecure {
		t.Fatalf("expected unenforced config not to prove secret scanning policy, got %+v", check)
	}
}

func TestCollectOrganizationPostureInputErrors(t *testing.T) {
	if _, err := (RepositoryClient{}).CollectOrganizationPosture(context.Background(), 1, "acme", "acme/repo"); err == nil {
		t.Fatal("expected missing token client error")
	}
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	if _, err := (RepositoryClient{TokenClient: minter}).CollectOrganizationPosture(context.Background(), 1, "owner/repo", "owner/repo"); err == nil || !strings.Contains(err.Error(), "single login") {
		t.Fatalf("expected organization validation error, got %v", err)
	}
}

func orgPostureCheckByID(posture OrganizationPosture, id string) RepositoryPostureCheck {
	for _, check := range posture.Checks {
		if check.ID == id {
			return check
		}
	}
	return RepositoryPostureCheck{}
}
