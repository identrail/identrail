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
	"testing"

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

type fakeGitHubRepositoryLister struct {
	seenInstallationID int64
	repositories       []githubconnector.Repository
	err                error
}

func (f *fakeGitHubRepositoryLister) ListInstallationRepositories(ctx context.Context, installationID int64) ([]githubconnector.Repository, error) {
	f.seenInstallationID = installationID
	return f.repositories, f.err
}

func TestRouterGitHubConnectorV2StartsAppInstall(t *testing.T) {
	r := newGitHubConnectorV2TestRouter(t, &fakeGitHubPATValidator{}, nil)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/github", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"display_name":"GitHub production",
		"redirect_uri":"https://app.identrail.com/app/tenant-a/workspace-a/projects/project-1"
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
	if completeBody.RedirectPath != "/app/tenant-a/workspace-a/projects/project-1" {
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
		"installation_id":12345
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
		"installation_id":12345
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
	r := newGitHubConnectorV2TestRouterWithStore(t, store, &fakeGitHubPATValidator{}, lister)

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
		"installation_id":12345
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
