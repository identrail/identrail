package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

type fakeGitHubPATValidator struct {
	result      githubconnector.PATValidationResult
	err         error
	seenBaseURL string
	seenToken   string
}

func (f *fakeGitHubPATValidator) ValidateGitHubPAT(ctx context.Context, baseURL string, token string) (githubconnector.PATValidationResult, error) {
	f.seenBaseURL = baseURL
	f.seenToken = token
	return f.result, f.err
}

// fakeGitHubInstallationVerifier stands in for the OAuth ownership verifier in
// tests. A zero value accepts any installation id (reporting account "identrail");
// set owned to restrict which ids are considered owned, or err to force failures.
type fakeGitHubInstallationVerifier struct {
	owned        map[int64]bool
	accountLogin string
	accountType  string
	err          error
	seenCode     string
}

func (f *fakeGitHubInstallationVerifier) VerifyInstallationOwnership(ctx context.Context, code string, installationID int64) (githubconnector.VerifiedInstallation, error) {
	f.seenCode = code
	if f.err != nil {
		return githubconnector.VerifiedInstallation{}, f.err
	}
	if f.owned != nil && !f.owned[installationID] {
		return githubconnector.VerifiedInstallation{}, githubconnector.ErrInstallationNotOwned
	}
	login := f.accountLogin
	if login == "" {
		login = "identrail"
	}
	return githubconnector.VerifiedInstallation{
		InstallationID: installationID,
		AccountLogin:   login,
		AccountType:    f.accountType,
	}, nil
}

type fakeGitHubRepositoryLister struct {
	seenInstallationID int64
	repositories       []githubconnector.Repository
	err                error
}

func (f *fakeGitHubRepositoryLister) ListInstallationRepositories(ctx context.Context, installationID int64) ([]githubconnector.Repository, error) {
	f.seenInstallationID = installationID
	return f.repositories, f.err
}

type fakeGitHubRepositoryPostureCollector struct {
	seenInstallationID   int64
	seenRepository       string
	seenOrganization     string
	seenOrganizationRepo string
	posture              githubconnector.RepositoryPosture
	organizationPosture  githubconnector.OrganizationPosture
	err                  error
	organizationErr      error
}

func (f *fakeGitHubRepositoryPostureCollector) CollectRepositoryPosture(ctx context.Context, installationID int64, repository string) (githubconnector.RepositoryPosture, error) {
	f.seenInstallationID = installationID
	f.seenRepository = repository
	if f.err != nil {
		return githubconnector.RepositoryPosture{}, f.err
	}
	return f.posture, nil
}

func (f *fakeGitHubRepositoryPostureCollector) CollectOrganizationPosture(ctx context.Context, installationID int64, organization string, repository string) (githubconnector.OrganizationPosture, error) {
	f.seenInstallationID = installationID
	f.seenOrganization = organization
	f.seenOrganizationRepo = repository
	if f.organizationErr != nil {
		return githubconnector.OrganizationPosture{}, f.organizationErr
	}
	return f.organizationPosture, nil
}

func TestRouterGitHubConnectorV2StartsAppInstall(t *testing.T) {
	r := newGitHubConnectorV2TestRouter(t, &fakeGitHubPATValidator{}, nil)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"display_name":"GitHub production",
		"redirect_uri":"https://app.identrail.com/app/tenant-a/workspace-a/projects/project-1",
		"install_account_type":"personal"
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body GitHubConnectorStartResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ConnectorID != githubConnectorID || body.State == "" {
		t.Fatalf("expected connector id and state, got %+v", body)
	}
	if body.Connection.Connected || body.Connection.Status != "pending" {
		t.Fatalf("expected pending connection, got %+v", body.Connection)
	}
	if body.InstallURL == "" || body.WebhookURL != "/auth/webhooks/github" {
		t.Fatalf("expected install and webhook urls, got %+v", body)
	}
	if body.InstallAccountType != "personal" {
		t.Fatalf("expected personal account install type, got %q", body.InstallAccountType)
	}
	if !strings.Contains(body.InstallURL, "/installations/select_target?") {
		t.Fatalf("install url must start at GitHub's account picker, got %q", body.InstallURL)
	}
	if strings.Contains(body.InstallURL, "/organizations/") {
		t.Fatalf("install url must use GitHub's account picker, got %q", body.InstallURL)
	}
}

func TestRouterGitHubConnectorV2RejectsInvalidInstallAccountType(t *testing.T) {
	r := newGitHubConnectorV2TestRouter(t, &fakeGitHubPATValidator{}, nil)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"install_account_type":"enterprise"
	}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected github connector start 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestRouterGitHubConnectorV2RejectsUnownedInstallation is the V2 regression
// test for GHSA-cp3j-m783-3ph5: completion must reject an installation the
// authorizing GitHub user does not own, before any installation token is minted.
func TestRouterGitHubConnectorV2RejectsUnownedInstallation(t *testing.T) {
	lister := &fakeGitHubRepositoryLister{}
	store := db.NewMemoryStore()
	r, svc := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, store, &fakeGitHubPATValidator{}, lister)
	// The authorizing user owns installation 999, not the victim's 12345.
	svc.GitHubInstallationVerifier = &fakeGitHubInstallationVerifier{owned: map[int64]bool{999: true}}

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody GitHubConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", fmt.Sprintf(`{
		"state":%q,
		"installation_id":12345,
		"code":"oauth-code"
	}`, startBody.State))
	if completeResp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unowned installation, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}
	if lister.seenInstallationID != 0 {
		t.Fatalf("repository lister must not run for an unowned installation, saw id %d", lister.seenInstallationID)
	}
}

func TestRouterGitHubConnectorV2CompletesAppInstall(t *testing.T) {
	lister := &fakeGitHubRepositoryLister{
		repositories: []githubconnector.Repository{
			{FullName: "Identrail/Platform", Private: true},
			{FullName: "identrail/API", Private: true},
		},
	}
	store := db.NewMemoryStore()
	r := newGitHubConnectorV2TestRouterWithStore(t, store, &fakeGitHubPATValidator{}, lister)

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"display_name":"GitHub production",
		"redirect_uri":"https://app.identrail.com/app/github/callback"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody GitHubConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", fmt.Sprintf(`{
		"state":%q,
		"installation_id":12345,
		"code":"oauth-code",
		"setup_action":"install"
	}`, startBody.State))
	if completeResp.Code != http.StatusOK {
		t.Fatalf("expected github connector complete 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}
	var completeBody GitHubConnectorCompleteResponse
	if err := json.Unmarshal(completeResp.Body.Bytes(), &completeBody); err != nil {
		t.Fatalf("decode complete response: %v", err)
	}
	if lister.seenInstallationID != 12345 {
		t.Fatalf("expected repository lister to use installation id, got %d", lister.seenInstallationID)
	}
	if !completeBody.Connection.Connected || completeBody.Connection.InstallationID != 12345 {
		t.Fatalf("expected active github app connector, got %+v", completeBody.Connection)
	}
	if completeBody.RedirectPath != "/app/tenant-a/workspace-a/github/connect?environment=project-1" {
		t.Fatalf("unexpected redirect path %q", completeBody.RedirectPath)
	}
	if len(completeBody.Connection.SelectedRepositories) != 2 || completeBody.Connection.SelectedRepositories[0] != "identrail/api" {
		t.Fatalf("expected normalized installation repositories, got %+v", completeBody.Connection.SelectedRepositories)
	}
	secret, err := store.GetTenancyConnectorSecretEnvelope(
		db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}),
		"workspace-a",
		"project-1",
		githubConnectorID,
		githubWebhookSecretName,
	)
	if err != nil {
		t.Fatalf("load github app webhook envelope: %v", err)
	}
	if bytes.Contains(secret.Envelope.Ciphertext, []byte("global-webhook-secret")) {
		t.Fatal("github app webhook secret should not be stored in plaintext")
	}

	statusResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github?workspace_id=workspace-a&project_id=project-1", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected github connector status 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !statusBody.Connection.Connected || statusBody.Connection.DisplayName != "GitHub production" {
		t.Fatalf("expected active status from stored connector, got %+v", statusBody.Connection)
	}

	repoResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/github-app/repos?workspace_id=workspace-a&project_id=project-1", "")
	if repoResp.Code != http.StatusOK {
		t.Fatalf("expected github repo list 200, got %d body=%s", repoResp.Code, repoResp.Body.String())
	}
	var repoBody GitHubRepositoryListResponse
	if err := json.Unmarshal(repoResp.Body.Bytes(), &repoBody); err != nil {
		t.Fatalf("decode repositories response: %v", err)
	}
	if repoBody.Provider != "github_app" || len(repoBody.Repositories) != 2 {
		t.Fatalf("expected github app repositories, got %+v", repoBody)
	}
}

func TestRouterGitHubConnectorV2CollectsRepositoryPosture(t *testing.T) {
	lister := &fakeGitHubRepositoryLister{
		repositories: []githubconnector.Repository{{FullName: "identrail/api", Private: true}},
	}
	collector := &fakeGitHubRepositoryPostureCollector{
		posture: githubconnector.RepositoryPosture{
			Repository:     "identrail/api",
			InstallationID: 12345,
			CollectedAt:    time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
			Checks: []githubconnector.RepositoryPostureCheck{
				{
					ID:       "default_branch_protection",
					Category: "branch_protection",
					State:    githubconnector.RepositoryPostureStateSecure,
					Reason:   "protection_enforced",
					Summary:  "Default branch protection requires reviews and status checks.",
				},
			},
		},
		organizationPosture: githubconnector.OrganizationPosture{
			Organization:   "identrail",
			InstallationID: 12345,
			CollectedAt:    time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
			Checks: []githubconnector.RepositoryPostureCheck{
				{
					ID:       "org_secret_scanning_policy",
					Category: "secret_scanning",
					State:    githubconnector.RepositoryPostureStateInsecure,
					Reason:   "secret_scanning_policy_weak",
					Summary:  "Organization does not enforce secret scanning and push protection for new repositories.",
				},
			},
		},
	}
	store := db.NewMemoryStore()
	r, svc := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, store, &fakeGitHubPATValidator{}, lister)
	svc.GitHubRepositoryPostureCollector = collector

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"redirect_uri":"https://app.identrail.com/app/github/callback"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody GitHubConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", fmt.Sprintf(`{
		"state":%q,
		"installation_id":12345,
		"code":"oauth-code"
	}`, startBody.State))
	if completeResp.Code != http.StatusOK {
		t.Fatalf("expected github connector complete 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}

	postureResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/github-app/posture?workspace_id=workspace-a&project_id=project-1&repository=Identrail/API", "")
	if postureResp.Code != http.StatusOK {
		t.Fatalf("expected github posture 200, got %d body=%s", postureResp.Code, postureResp.Body.String())
	}
	var postureBody GitHubRepositoryPostureResponse
	if err := json.Unmarshal(postureResp.Body.Bytes(), &postureBody); err != nil {
		t.Fatalf("decode posture response: %v", err)
	}
	if collector.seenInstallationID != 12345 || collector.seenRepository != "identrail/api" || collector.seenOrganization != "identrail" || collector.seenOrganizationRepo != "identrail/api" {
		t.Fatalf("unexpected collector call installation=%d repository=%q organization=%q organizationRepo=%q", collector.seenInstallationID, collector.seenRepository, collector.seenOrganization, collector.seenOrganizationRepo)
	}
	if postureBody.ConnectorID != githubConnectorID || postureBody.Provider != "github_app" || postureBody.Posture.Repository != "identrail/api" {
		t.Fatalf("unexpected posture response %+v", postureBody)
	}
	if postureBody.OrganizationPosture == nil || postureBody.OrganizationPosture.Organization != "identrail" || len(postureBody.OrganizationPosture.Checks) != 1 {
		t.Fatalf("expected organization posture in response, got %+v", postureBody.OrganizationPosture)
	}
	if postureBody.OrganizationPosture.Checks[0].State != githubconnector.RepositoryPostureStateInsecure {
		t.Fatalf("expected org secret scanning insecure, got %+v", postureBody.OrganizationPosture.Checks[0])
	}

	collector.organizationPosture = githubconnector.OrganizationPosture{
		Organization:   "identrail",
		InstallationID: 12345,
		CollectedAt:    time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		Checks: []githubconnector.RepositoryPostureCheck{
			{
				ID:       "org_secret_scanning_policy",
				Category: "secret_scanning",
				State:    githubconnector.RepositoryPostureStateUnsupported,
				Reason:   "not_an_organization",
				Summary:  "Repository owner is a user account, so organization secret scanning policy does not apply.",
			},
		},
	}
	userOwnedResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/github-app/posture?workspace_id=workspace-a&project_id=project-1&repository=Identrail/API", "")
	if userOwnedResp.Code != http.StatusOK {
		t.Fatalf("expected user-owned github posture 200, got %d body=%s", userOwnedResp.Code, userOwnedResp.Body.String())
	}
	var userOwnedBody GitHubRepositoryPostureResponse
	if err := json.Unmarshal(userOwnedResp.Body.Bytes(), &userOwnedBody); err != nil {
		t.Fatalf("decode user-owned posture response: %v", err)
	}
	if userOwnedBody.OrganizationPosture != nil {
		t.Fatalf("expected unsupported organization posture to be omitted, got %+v", userOwnedBody.OrganizationPosture)
	}

	collector.organizationPosture = githubconnector.OrganizationPosture{
		Organization:   "identrail",
		InstallationID: 12345,
		CollectedAt:    time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		Checks: []githubconnector.RepositoryPostureCheck{
			{
				ID:       "org_secret_scanning_policy",
				Category: "secret_scanning",
				State:    githubconnector.RepositoryPostureStateUnsupported,
				Reason:   "plan_unavailable",
				Summary:  "Organization code security configurations are not available for this account or plan.",
			},
		},
	}
	planLimitedResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/github-app/posture?workspace_id=workspace-a&project_id=project-1&repository=Identrail/API", "")
	if planLimitedResp.Code != http.StatusOK {
		t.Fatalf("expected plan-limited github posture 200, got %d body=%s", planLimitedResp.Code, planLimitedResp.Body.String())
	}
	var planLimitedBody GitHubRepositoryPostureResponse
	if err := json.Unmarshal(planLimitedResp.Body.Bytes(), &planLimitedBody); err != nil {
		t.Fatalf("decode plan-limited posture response: %v", err)
	}
	if planLimitedBody.OrganizationPosture == nil || planLimitedBody.OrganizationPosture.Checks[0].Reason != "plan_unavailable" {
		t.Fatalf("expected plan-limited organization posture to be preserved, got %+v", planLimitedBody.OrganizationPosture)
	}

	unselectedResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/github-app/posture?workspace_id=workspace-a&project_id=project-1&repository=identrail/other", "")
	if unselectedResp.Code != http.StatusForbidden {
		t.Fatalf("expected unselected repository 403, got %d body=%s", unselectedResp.Code, unselectedResp.Body.String())
	}

	collector.err = errors.New("github temporarily unavailable")
	unavailableResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/github-app/posture?workspace_id=workspace-a&project_id=project-1&repository=identrail/api", "")
	if unavailableResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected posture collector failure 503, got %d body=%s", unavailableResp.Code, unavailableResp.Body.String())
	}
}

func TestRouterGitHubConnectorV2HydratesCustomAppConnector(t *testing.T) {
	lister := &fakeGitHubRepositoryLister{
		repositories: []githubconnector.Repository{{FullName: "identrail/api", Private: true}},
	}
	store := db.NewMemoryStore()
	r, svc := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, store, &fakeGitHubPATValidator{}, lister)

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"github-prod",
		"display_name":"GitHub production",
		"redirect_uri":"https://app.identrail.com/app/github/callback"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody GitHubConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", fmt.Sprintf(`{
		"state":%q,
		"installation_id":12345,
		"code":"oauth-code"
	}`, startBody.State))
	if completeResp.Code != http.StatusOK {
		t.Fatalf("expected github connector complete 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}

	svc.githubConnectMu.Lock()
	svc.githubConnections = nil
	svc.githubConnectMu.Unlock()
	svc.hydrateGitHubConnections(context.Background())

	pushPayload := []byte(`{"repository":{"full_name":"identrail/api"},"installation":{"id":12345}}`)
	pushResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "push", "delivery-custom", "global-webhook-secret", pushPayload)
	if pushResp.Code != http.StatusAccepted {
		t.Fatalf("expected github push webhook 202, got %d body=%s", pushResp.Code, pushResp.Body.String())
	}
	var pushBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(pushResp.Body.Bytes(), &pushBody); err != nil {
		t.Fatalf("decode push webhook response: %v", err)
	}
	if pushBody.Webhook.MatchedProjects != 1 {
		t.Fatalf("expected hydrated custom connector to match webhook, got %+v", pushBody.Webhook)
	}
}

func TestRouterGitHubConnectorV2DoesNotActivateWhenRepoListingFails(t *testing.T) {
	lister := &fakeGitHubRepositoryLister{err: errors.New("github timeout")}
	r := newGitHubConnectorV2TestRouter(t, &fakeGitHubPATValidator{}, lister)

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"redirect_uri":"https://app.identrail.com/app/github/callback"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody GitHubConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", fmt.Sprintf(`{
		"state":%q,
		"installation_id":12345,
		"code":"oauth-code"
	}`, startBody.State))
	if completeResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected repository listing failure 503, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}

	statusResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github?workspace_id=workspace-a&project_id=project-1", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected github connector status 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if statusBody.Connection.Connected || statusBody.Connection.Status != domain.ConnectorStatusPending {
		t.Fatalf("expected connector to remain pending after failed completion, got %+v", statusBody.Connection)
	}
}

func TestRouterGitHubConnectorV2WebhookQueuesAndDisconnects(t *testing.T) {
	lister := &fakeGitHubRepositoryLister{
		repositories: []githubconnector.Repository{{FullName: "identrail/api", Private: true}},
	}
	store := db.NewMemoryStore()
	r, svc := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, store, &fakeGitHubPATValidator{}, lister)
	svc.RepoScanEnabled = true
	svc.RepoScanAllowedTargets = []string{"identrail/*"}

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"redirect_uri":"https://app.identrail.com/app/github/callback"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody GitHubConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", fmt.Sprintf(`{
		"state":%q,
		"installation_id":12345,
		"code":"oauth-code"
	}`, startBody.State))
	if completeResp.Code != http.StatusOK {
		t.Fatalf("expected github connector complete 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}

	pushPayload := []byte(`{"repository":{"full_name":"identrail/api"},"installation":{"id":12345}}`)
	pushResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "push", "delivery-push", "global-webhook-secret", pushPayload)
	if pushResp.Code != http.StatusAccepted {
		t.Fatalf("expected github push webhook 202, got %d body=%s", pushResp.Code, pushResp.Body.String())
	}
	var pushBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(pushResp.Body.Bytes(), &pushBody); err != nil {
		t.Fatalf("decode push webhook response: %v", err)
	}
	if pushBody.Webhook.MatchedProjects != 1 || pushBody.Webhook.Repository != "identrail/api" {
		t.Fatalf("expected matched github app webhook, got %+v", pushBody.Webhook)
	}

	addedPayload := []byte(`{"action":"added","installation":{"id":12345},"repositories_added":[{"full_name":"identrail/new"}]}`)
	addedResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "installation_repositories", "delivery-added", "global-webhook-secret", addedPayload)
	if addedResp.Code != http.StatusAccepted {
		t.Fatalf("expected github repository added webhook 202, got %d body=%s", addedResp.Code, addedResp.Body.String())
	}
	newRepoPayload := []byte(`{"repository":{"full_name":"identrail/new"},"installation":{"id":12345}}`)
	newRepoResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "push", "delivery-new-repo", "global-webhook-secret", newRepoPayload)
	if newRepoResp.Code != http.StatusAccepted {
		t.Fatalf("expected github new repo push webhook 202, got %d body=%s", newRepoResp.Code, newRepoResp.Body.String())
	}
	var newRepoBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(newRepoResp.Body.Bytes(), &newRepoBody); err != nil {
		t.Fatalf("decode new repo webhook response: %v", err)
	}
	if newRepoBody.Webhook.MatchedProjects != 1 {
		t.Fatalf("expected added repository to match webhook, got %+v", newRepoBody.Webhook)
	}
	removedPayload := []byte(`{"action":"removed","installation":{"id":12345},"repositories_removed":[{"full_name":"identrail/new"}]}`)
	removedResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "installation_repositories", "delivery-removed", "global-webhook-secret", removedPayload)
	if removedResp.Code != http.StatusAccepted {
		t.Fatalf("expected github repository removed webhook 202, got %d body=%s", removedResp.Code, removedResp.Body.String())
	}
	removedRepoResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "push", "delivery-removed-repo", "global-webhook-secret", newRepoPayload)
	if removedRepoResp.Code != http.StatusAccepted {
		t.Fatalf("expected github removed repo push webhook 202, got %d body=%s", removedRepoResp.Code, removedRepoResp.Body.String())
	}
	var removedRepoBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(removedRepoResp.Body.Bytes(), &removedRepoBody); err != nil {
		t.Fatalf("decode removed repo webhook response: %v", err)
	}
	if removedRepoBody.Webhook.MatchedProjects != 0 {
		t.Fatalf("expected removed repository to stop matching webhook, got %+v", removedRepoBody.Webhook)
	}

	deletedPayload := []byte(`{"action":"deleted","installation":{"id":12345,"account":{"login":"identrail"}}}`)
	deletedResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "installation", "delivery-delete", "global-webhook-secret", deletedPayload)
	if deletedResp.Code != http.StatusAccepted {
		t.Fatalf("expected github installation webhook 202, got %d body=%s", deletedResp.Code, deletedResp.Body.String())
	}
	var deletedBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(deletedResp.Body.Bytes(), &deletedBody); err != nil {
		t.Fatalf("decode deleted webhook response: %v", err)
	}
	if deletedBody.Webhook.MatchedProjects != 1 {
		t.Fatalf("expected disconnected connector match, got %+v", deletedBody.Webhook)
	}

	postDeleteResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "push", "delivery-after-delete", "global-webhook-secret", pushPayload)
	if postDeleteResp.Code != http.StatusAccepted {
		t.Fatalf("expected post-delete push webhook 202, got %d body=%s", postDeleteResp.Code, postDeleteResp.Body.String())
	}
	var postDeleteBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(postDeleteResp.Body.Bytes(), &postDeleteBody); err != nil {
		t.Fatalf("decode post-delete webhook response: %v", err)
	}
	if postDeleteBody.Webhook.MatchedProjects != 0 {
		t.Fatalf("expected deleted installation to stop matching webhook, got %+v", postDeleteBody.Webhook)
	}
}

func TestRouterGitHubConnectorV2ReviewCommandQueuesScan(t *testing.T) {
	lister := &fakeGitHubRepositoryLister{
		repositories: []githubconnector.Repository{{FullName: "identrail/api", Private: true}},
	}
	store := db.NewMemoryStore()
	r, svc := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, store, &fakeGitHubPATValidator{}, lister)
	svc.RepoScanEnabled = true
	svc.RepoScanAllowedTargets = []string{"identrail/*"}

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"redirect_uri":"https://app.identrail.com/app/github/callback"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected github connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody GitHubConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", fmt.Sprintf(`{
		"state":%q,
		"installation_id":12345,
		"code":"oauth-code"
	}`, startBody.State))
	if completeResp.Code != http.StatusOK {
		t.Fatalf("expected github connector complete 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}

	commentPayload := []byte(`{
		"action":"created",
		"repository":{"full_name":"identrail/api"},
		"installation":{"id":12345},
		"issue":{"number":17,"pull_request":{"url":"https://api.github.com/repos/identrail/api/pulls/17"}},
		"comment":{"body":"@identrail review"}
	}`)
	commentResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "issue_comment", "delivery-review-command", "global-webhook-secret", commentPayload)
	if commentResp.Code != http.StatusAccepted {
		t.Fatalf("expected github review command webhook 202, got %d body=%s", commentResp.Code, commentResp.Body.String())
	}
	var commentBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(commentResp.Body.Bytes(), &commentBody); err != nil {
		t.Fatalf("decode review command webhook response: %v", err)
	}
	if commentBody.Webhook.MatchedProjects != 1 || commentBody.Webhook.QueuedScans != 1 || commentBody.Webhook.SkippedScans != 0 {
		t.Fatalf("expected review command to queue one scan, got %+v", commentBody.Webhook)
	}

	scansResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/repo-scans", "")
	if scansResp.Code != http.StatusOK {
		t.Fatalf("expected repo scan list 200, got %d body=%s", scansResp.Code, scansResp.Body.String())
	}
	var scansBody struct {
		Items []db.RepoScanRecord `json:"items"`
	}
	if err := json.Unmarshal(scansResp.Body.Bytes(), &scansBody); err != nil {
		t.Fatalf("decode repo scans response: %v", err)
	}
	if len(scansBody.Items) != 1 || scansBody.Items[0].Repository != "identrail/api" || scansBody.Items[0].ScanMode != db.RepoScanModeQuick {
		t.Fatalf("expected queued quick scan for review command, got %+v", scansBody.Items)
	}
}

func TestRouterGitHubConnectorV2PATStoresEncryptedToken(t *testing.T) {
	validator := &fakeGitHubPATValidator{
		result: githubconnector.PATValidationResult{Login: "sec-eng", Scopes: []string{"repo"}},
	}
	store := db.NewMemoryStore()
	r, svc := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, store, validator, nil)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/pat", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"base_url":"https://github.example.com",
		"token":"ghp_abcdefghijklmnopqrstuvwxyz",
		"selected_repositories":["Identrail/Platform","identrail/platform"]
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected github pat connector 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	if validator.seenBaseURL != "https://github.example.com" || validator.seenToken == "" {
		t.Fatalf("validator did not receive normalized PAT request: %+v", validator)
	}
	var body struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Connection.Connected || body.Connection.Provider != "github_pat" || body.Connection.BaseURL != "https://github.example.com" {
		t.Fatalf("expected active github pat connector, got %+v", body.Connection)
	}
	if len(body.Connection.SelectedRepositories) != 1 || body.Connection.SelectedRepositories[0] != "identrail/platform" {
		t.Fatalf("expected normalized repository allowlist, got %+v", body.Connection.SelectedRepositories)
	}
	secret, err := store.GetTenancyConnectorSecretEnvelope(
		db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}),
		"workspace-a",
		"project-1",
		"github-pat",
		githubPATSecretName,
	)
	if err != nil {
		t.Fatalf("load github pat envelope: %v", err)
	}
	if bytes.Contains(secret.Envelope.Ciphertext, []byte("ghp_")) {
		t.Fatal("pat token should not be stored in plaintext")
	}

	statusResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github?workspace_id=workspace-a&project_id=project-1", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected github status 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if statusBody.Connection.Provider != "github_pat" || statusBody.Connection.BaseURL != "https://github.example.com" {
		t.Fatalf("expected github pat status, got %+v", statusBody.Connection)
	}

	repoResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/github-pat/repos?workspace_id=workspace-a&project_id=project-1", "")
	if repoResp.Code != http.StatusOK {
		t.Fatalf("expected github pat repositories 200, got %d body=%s", repoResp.Code, repoResp.Body.String())
	}
	var repoBody GitHubRepositoryListResponse
	if err := json.Unmarshal(repoResp.Body.Bytes(), &repoBody); err != nil {
		t.Fatalf("decode repository response: %v", err)
	}
	if repoBody.Provider != "github_pat" || len(repoBody.Repositories) != 1 || repoBody.Repositories[0].FullName != "identrail/platform" {
		t.Fatalf("unexpected pat repositories %+v", repoBody)
	}

	policyStatus, err := svc.GetGitHubConnection(
		db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}),
		"workspace-a",
		"project-1",
	)
	if err != nil {
		t.Fatalf("load pat connector through policy path: %v", err)
	}
	if policyStatus.Provider != "github_pat" || !policyStatus.Connected || len(policyStatus.SelectedRepositories) != 1 {
		t.Fatalf("expected policy path to see active pat connector, got %+v", policyStatus)
	}
}

func TestRouterGitHubAppWebhookUsesGlobalSecret(t *testing.T) {
	r := newGitHubConnectorV2TestRouter(t, &fakeGitHubPATValidator{}, nil)
	payload := []byte(`{"action":"deleted","installation":{"id":123,"account":{"login":"identrail"}}}`)
	resp := doGitHubWebhook(t, r, "/auth/webhooks/github", "installation", "delivery-1", "global-webhook-secret", payload)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected github app webhook 202, got %d body=%s", resp.Code, resp.Body.String())
	}
	badResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "installation", "delivery-2", "wrong", payload)
	if badResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected github app webhook bad secret 401, got %d body=%s", badResp.Code, badResp.Body.String())
	}
}

func TestRouterGitHubConnectorV2EmptyAndInvalidStates(t *testing.T) {
	r := newGitHubConnectorV2TestRouter(t, &fakeGitHubPATValidator{}, nil)

	statusResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github?workspace_id=workspace-a&project_id=project-1", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected empty github status 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode empty status response: %v", err)
	}
	if statusBody.Connection.Connected || statusBody.Connection.Provider != "github_app" {
		t.Fatalf("expected empty github app status, got %+v", statusBody.Connection)
	}

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{"workspace_id":"workspace-a"}`)
	if startResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid start 400, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", `{
		"state":"missing",
		"installation_id":123
	}`)
	if completeResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid complete 400, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}
	repoResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/github/missing/repos?workspace_id=workspace-a&project_id=project-1", "")
	if repoResp.Code != http.StatusNotFound {
		t.Fatalf("expected missing repository list 404, got %d body=%s", repoResp.Code, repoResp.Body.String())
	}
	ignoredPayload := []byte(`{"repository":{"full_name":"identrail/nope"},"installation":{"id":999}}`)
	ignoredResp := doGitHubWebhook(t, r, "/auth/webhooks/github", "push", "delivery-ignored", "global-webhook-secret", ignoredPayload)
	if ignoredResp.Code != http.StatusAccepted {
		t.Fatalf("expected ignored github webhook 202, got %d body=%s", ignoredResp.Code, ignoredResp.Body.String())
	}
}

func TestRouterGitHubConnectorV2RejectsInvalidPATRequests(t *testing.T) {
	validator := &fakeGitHubPATValidator{
		result: githubconnector.PATValidationResult{Login: "sec-eng", Scopes: []string{"repo"}},
	}
	r := newGitHubConnectorV2TestRouter(t, validator, nil)

	missingTokenResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/pat", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"token":""
	}`)
	if missingTokenResp.Code != http.StatusBadRequest {
		t.Fatalf("expected missing token 400, got %d body=%s", missingTokenResp.Code, missingTokenResp.Body.String())
	}
	badRepoResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/pat", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"token":"ghp_abcdefghijklmnopqrstuvwxyz",
		"selected_repositories":["not-a-repo"]
	}`)
	if badRepoResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid repository 400, got %d body=%s", badRepoResp.Code, badRepoResp.Body.String())
	}
}

func TestRouterGitHubConnectorV2RequiresAppConfig(t *testing.T) {
	r, svc := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, db.NewMemoryStore(), &fakeGitHubPATValidator{}, nil)
	svc.GitHubAppWebhookSecret = ""

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1"
	}`)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected missing github app config 503, got %d body=%s", resp.Code, resp.Body.String())
	}

	completeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/complete", `{
		"state":"pending",
		"installation_id":123
	}`)
	if completeResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected missing github app config on complete 503, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}
}

func TestRouterGitHubConnectorV2RequiresPATValidator(t *testing.T) {
	r := newGitHubConnectorV2TestRouter(t, nil, nil)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github/pat", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"token":"ghp_abcdefghijklmnopqrstuvwxyz"
	}`)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected missing github pat validator 503, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterGitHubConnectorV2FeatureFlagDisabled(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), routerScanner{}, "aws")
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	paths := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/v1/connectors/github", body: "{}"},
		{method: http.MethodPost, path: "/v1/connectors/github/complete", body: "{}"},
		{method: http.MethodGet, path: "/v1/connectors/github?workspace_id=workspace-a&project_id=project-1"},
		{method: http.MethodPost, path: "/v1/connectors/github/pat", body: "{}"},
		{method: http.MethodGet, path: "/v1/connectors/github/github-app/repos?workspace_id=workspace-a&project_id=project-1"},
	}
	for _, tc := range paths {
		resp := doAWSConnectionAPI(t, r, tc.method, tc.path, tc.body)
		if resp.Code != http.StatusNotFound {
			t.Fatalf("expected feature-gated %s %s to be 404, got %d body=%s", tc.method, tc.path, resp.Code, resp.Body.String())
		}
	}
}

func newGitHubConnectorV2TestRouter(t *testing.T, validator GitHubPATValidator, repoLister GitHubRepositoryLister) ginEngineForTest {
	t.Helper()
	return newGitHubConnectorV2TestRouterWithStore(t, db.NewMemoryStore(), validator, repoLister)
}

func newGitHubConnectorV2TestRouterWithStore(t *testing.T, store db.Store, validator GitHubPATValidator, repoLister GitHubRepositoryLister) ginEngineForTest {
	t.Helper()
	r, _ := newGitHubConnectorV2ConfiguredTestRouterWithStore(t, store, validator, repoLister)
	return r
}

func newGitHubConnectorV2ConfiguredTestRouterWithStore(t *testing.T, store db.Store, validator GitHubPATValidator, repoLister GitHubRepositoryLister) (ginEngineForTest, *Service) {
	t.Helper()
	svc := NewService(store, routerScanner{}, "aws")
	svc.GitHubAppName = "identrail"
	svc.GitHubAppWebhookSecret = "global-webhook-secret"
	svc.GitHubPATValidator = validator
	svc.GitHubRepositoryLister = repoLister
	svc.GitHubInstallationVerifier = &fakeGitHubInstallationVerifier{}
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{9}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc.ConnectorSecretManager = manager
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		APIKeys:                  []string{"writer-key"},
		WriteAPIKeys:             []string{"writer-key"},
		DefaultTenantID:          "tenant-a",
		DefaultWorkspaceID:       "workspace-a",
		FeatureConnectorGitHubV2: true,
	})
	_ = doAWSConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	projectResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("seed project failed: %d body=%s", projectResp.Code, projectResp.Body.String())
	}
	return r, svc
}

func doGitHubWebhook(t *testing.T, r ginEngineForTest, path string, event string, delivery string, secret string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", gitHubWebhookSignatureForSecret(secret, payload))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func gitHubWebhookSignatureForSecret(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
