package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
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
}

func TestRouterGitHubConnectorV2PATStoresEncryptedToken(t *testing.T) {
	validator := &fakeGitHubPATValidator{
		result: githubconnector.PATValidationResult{Login: "sec-eng", Scopes: []string{"repo"}},
	}
	store := db.NewMemoryStore()
	r := newGitHubConnectorV2TestRouterWithStore(t, store, validator, nil)

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

func newGitHubConnectorV2TestRouter(t *testing.T, validator GitHubPATValidator, repoLister GitHubRepositoryLister) ginEngineForTest {
	t.Helper()
	return newGitHubConnectorV2TestRouterWithStore(t, db.NewMemoryStore(), validator, repoLister)
}

func newGitHubConnectorV2TestRouterWithStore(t *testing.T, store db.Store, validator GitHubPATValidator, repoLister GitHubRepositoryLister) ginEngineForTest {
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
	return r
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
