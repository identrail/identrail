package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestParseGitHubInstallationID(t *testing.T) {
	tests := []struct {
		input   string
		wantID  int64
		wantErr bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"123", 123, false},
		{" 456 ", 456, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
		{"1.5", 0, true},
	}
	for _, tc := range tests {
		got, err := parseGitHubInstallationID(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("parseGitHubInstallationID(%q) expected error, got %d", tc.input, got)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("parseGitHubInstallationID(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.wantID {
			t.Errorf("parseGitHubInstallationID(%q) = %d, want %d", tc.input, got, tc.wantID)
		}
	}
}

func TestGitHubWebhookTriggersScan(t *testing.T) {
	scanEvents := []string{"push", "pull_request", "repository_dispatch", "workflow_dispatch", "PUSH", " Pull_Request "}
	for _, event := range scanEvents {
		if !githubWebhookTriggersScan(event) {
			t.Errorf("githubWebhookTriggersScan(%q) = false, want true", event)
		}
	}
	nonScanEvents := []string{"installation", "ping", "star", "fork", "issues", ""}
	for _, event := range nonScanEvents {
		if githubWebhookTriggersScan(event) {
			t.Errorf("githubWebhookTriggersScan(%q) = true, want false", event)
		}
	}
}

func TestValidateGitHubWebhookSignature(t *testing.T) {
	payload := []byte(`{"test":true}`)

	validSig := githubWebhookSignature("my-secret", payload)

	if !validateGitHubWebhookSignature("my-secret", payload, validSig) {
		t.Fatal("valid signature should pass")
	}
	if validateGitHubWebhookSignature("wrong-secret", payload, validSig) {
		t.Fatal("wrong secret should fail")
	}
	if validateGitHubWebhookSignature("", payload, validSig) {
		t.Fatal("empty secret should fail")
	}
	if validateGitHubWebhookSignature("my-secret", payload, "") {
		t.Fatal("empty signature should fail")
	}
	if validateGitHubWebhookSignature("my-secret", payload, "md5=abc123") {
		t.Fatal("non-sha256 prefix should fail")
	}
	if validateGitHubWebhookSignature("my-secret", payload, "sha256=") {
		t.Fatal("sha256 with empty hash should fail")
	}
	if validateGitHubWebhookSignature("my-secret", payload, "noequalssign") {
		t.Fatal("signature without = separator should fail")
	}
}

func TestGitHubConnectionEncryptsAndRotatesWebhookSecret(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
		AuditSink:          sink,
	})

	doAPI := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	_ = doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)

	startResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/start", `{}`)
	var startBody struct {
		Connection GitHubConnectionStartResponse `json:"connection"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	secret := "very-secret-webhook-value"
	completeJSON := `{"state":"` + startBody.Connection.State + `","installation_id":77,"account_login":"identrail","token_reference":"vault://token","webhook_secret":"` + secret + `","webhook_secret_reference":"vault://secret/v1","selected_repositories":["owner/repo"]}`
	completeResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete", completeJSON)
	if completeResp.Code != http.StatusOK {
		t.Fatalf("complete connection expected 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}
	var completeBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(completeResp.Body.Bytes(), &completeBody); err != nil {
		t.Fatalf("decode complete response: %v", err)
	}
	if completeBody.Connection.WebhookSecretKeyVersion == "" || completeBody.Connection.WebhookSecretAlgorithm != "AES-256-GCM" {
		t.Fatalf("expected encrypted secret metadata, got %+v", completeBody.Connection)
	}
	if completeBody.Connection.WebhookSecretRotatedAt == nil || completeBody.Connection.WebhookSecretRotationDueAt == nil {
		t.Fatalf("expected webhook secret rotation timestamps after initial connect, got %+v", completeBody.Connection)
	}
	if completeBody.Connection.WebhookSecretRotationRequired {
		t.Fatalf("expected newly connected secret to not require immediate rotation, got %+v", completeBody.Connection)
	}
	if strings.Contains(completeResp.Body.String(), secret) {
		t.Fatalf("response exposed webhook secret: %s", completeResp.Body.String())
	}

	key := githubConnectionKey("tenant-a", "workspace-a", "project-1")
	svc.githubConnectMu.RLock()
	connection := svc.githubConnections[key]
	svc.githubConnectMu.RUnlock()
	if len(connection.WebhookSecretEnvelope.Ciphertext) == 0 {
		t.Fatal("expected encrypted webhook secret ciphertext")
	}
	if strings.Contains(string(connection.WebhookSecretEnvelope.Ciphertext), secret) {
		t.Fatal("ciphertext should not contain plaintext secret")
	}

	newSecret := "rotated-webhook-value"
	rotateResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/secret/rotate", `{"webhook_secret":"`+newSecret+`","webhook_secret_reference":"vault://secret/v2"}`)
	if rotateResp.Code != http.StatusOK {
		t.Fatalf("rotate secret expected 200, got %d body=%s", rotateResp.Code, rotateResp.Body.String())
	}
	if strings.Contains(rotateResp.Body.String(), newSecret) {
		t.Fatalf("rotation response exposed webhook secret: %s", rotateResp.Body.String())
	}
	var rotateBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(rotateResp.Body.Bytes(), &rotateBody); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if rotateBody.Connection.WebhookSecretReference != "vault://secret/v2" {
		t.Fatalf("expected rotated secret reference, got %+v", rotateBody.Connection)
	}
	if rotateBody.Connection.WebhookSecretRotatedAt == nil || rotateBody.Connection.WebhookSecretRotationDueAt == nil {
		t.Fatalf("expected rotation metadata after rotate, got %+v", rotateBody.Connection)
	}
	if rotateBody.Connection.WebhookSecretRotatedAt.Before(*completeBody.Connection.WebhookSecretRotatedAt) {
		t.Fatalf("expected rotated_at to stay monotonic after rotation, before=%s after=%s", *completeBody.Connection.WebhookSecretRotatedAt, *rotateBody.Connection.WebhookSecretRotatedAt)
	}
	if rotateBody.Connection.WebhookSecretRotationRequired {
		t.Fatalf("expected freshly rotated secret to not require immediate rotation, got %+v", rotateBody.Connection)
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":77}}`)
	if _, err := svc.HandleGitHubWebhook(
		httptest.NewRequest(http.MethodPost, "/webhooks/github", nil).Context(),
		"installation",
		"delivery-old",
		githubWebhookSignature(secret, webhookPayload),
		webhookPayload,
	); err == nil {
		t.Fatal("old webhook secret should fail after rotation")
	}
	result, err := svc.HandleGitHubWebhook(
		httptest.NewRequest(http.MethodPost, "/webhooks/github", nil).Context(),
		"installation",
		"delivery-new",
		githubWebhookSignature(newSecret, webhookPayload),
		webhookPayload,
	)
	if err != nil {
		t.Fatalf("new webhook secret should pass: %v", err)
	}
	if result.MatchedProjects != 1 {
		t.Fatalf("expected rotated secret to match one project, got %+v", result)
	}

	auditPayload, err := json.Marshal(sink.events)
	if err != nil {
		t.Fatalf("marshal audit events: %v", err)
	}
	if strings.Contains(string(auditPayload), secret) || strings.Contains(string(auditPayload), newSecret) {
		t.Fatalf("audit events exposed webhook secret: %s", string(auditPayload))
	}
	actionEvents := 0
	for _, event := range sink.events {
		if event.Kind != "action" {
			continue
		}
		actionEvents++
		if event.TenantID == "tenant-a" || event.WorkspaceID == "workspace-a" || event.ResourceID == "project-1" {
			t.Fatalf("action audit event exposed raw scope identifiers: %+v", event)
		}
	}
	if actionEvents == 0 {
		t.Fatal("expected action audit events")
	}
	if !strings.Contains(string(auditPayload), "connector.github.webhook_secret.rotate") {
		t.Fatalf("expected rotation audit event, got %s", string(auditPayload))
	}

	svc.githubConnectMu.Lock()
	connection = svc.githubConnections[key]
	connection.WebhookSecretEnvelope.KeyVersion = "legacy-v1"
	svc.githubConnections[key] = connection
	svc.githubConnectMu.Unlock()

	statusResp := doAPI(http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/github/connection", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("status expected 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !statusBody.Connection.WebhookSecretRotationRequired {
		t.Fatalf("expected legacy key version to require rotation, got %+v", statusBody.Connection)
	}
	if strings.Contains(statusResp.Body.String(), newSecret) {
		t.Fatalf("status response exposed webhook secret: %s", statusResp.Body.String())
	}
}

func TestGitHubConnectionPersistsAcrossServiceInstances(t *testing.T) {
	store := db.NewMemoryStore()
	manager := secretstore.NewEphemeralManager()

	ctx := db.WithScope(context.Background(), db.Scope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	})
	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, db.TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, db.TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	svcA := NewService(store, routerScanner{}, "aws")
	svcA.ConnectorSecretManager = manager
	start, err := svcA.StartGitHubConnection(ctx, "workspace-a", "project-1", GitHubConnectionStartRequest{})
	if err != nil {
		t.Fatalf("start github connection: %v", err)
	}
	_, err = svcA.CompleteGitHubConnection(ctx, "workspace-a", "project-1", GitHubConnectionCompleteRequest{
		State:                  start.State,
		InstallationID:         77,
		AccountLogin:           "identrail",
		TokenReference:         "vault://token",
		WebhookSecret:          "persisted-secret",
		WebhookSecretReference: "vault://secret/v1",
		SelectedRepositories:   []string{"owner/repo"},
	})
	if err != nil {
		t.Fatalf("complete github connection: %v", err)
	}

	svcB := NewService(store, routerScanner{}, "aws")
	svcB.ConnectorSecretManager = manager
	connection, err := svcB.GetGitHubConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get github connection: %v", err)
	}
	if !connection.Connected {
		t.Fatalf("expected persisted connection to be connected, got %+v", connection)
	}
	if connection.InstallationID != 77 {
		t.Fatalf("expected installation id 77, got %+v", connection)
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":77}}`)
	webhookResult, err := svcB.HandleGitHubWebhook(
		ctx,
		"installation",
		"delivery-persisted",
		githubWebhookSignature("persisted-secret", webhookPayload),
		webhookPayload,
	)
	if err != nil {
		t.Fatalf("handle github webhook from persisted connection: %v", err)
	}
	if webhookResult.MatchedProjects != 1 {
		t.Fatalf("expected matched persisted project, got %+v", webhookResult)
	}
}

type countingConnectorListStore struct {
	db.Store
	mu        sync.Mutex
	listCalls int
}

func (s *countingConnectorListStore) ListTenancyConnectorsUnscoped(ctx context.Context, connectorType domain.ConnectorType, limit int) ([]db.TenancyConnectorWithState, error) {
	s.mu.Lock()
	s.listCalls++
	s.mu.Unlock()
	return s.Store.ListTenancyConnectorsUnscoped(ctx, connectorType, limit)
}

func (s *countingConnectorListStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listCalls
}

func TestHandleGitHubWebhookDoesNotHydrateConnectorsPerRequest(t *testing.T) {
	baseStore := db.NewMemoryStore()
	store := &countingConnectorListStore{Store: baseStore}
	manager := secretstore.NewEphemeralManager()

	ctx := db.WithScope(context.Background(), db.Scope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	})
	if err := baseStore.UpsertOrganization(ctx, db.TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := baseStore.UpsertWorkspace(ctx, db.TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := baseStore.UpsertProject(ctx, db.TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	seed := NewService(baseStore, routerScanner{}, "aws")
	seed.ConnectorSecretManager = manager
	start, err := seed.StartGitHubConnection(ctx, "workspace-a", "project-1", GitHubConnectionStartRequest{})
	if err != nil {
		t.Fatalf("start github connection: %v", err)
	}
	if _, err := seed.CompleteGitHubConnection(ctx, "workspace-a", "project-1", GitHubConnectionCompleteRequest{
		State:                  start.State,
		InstallationID:         88,
		AccountLogin:           "identrail",
		TokenReference:         "vault://token",
		WebhookSecret:          "persisted-secret",
		WebhookSecretReference: "vault://secret/v1",
		SelectedRepositories:   []string{"owner/repo"},
	}); err != nil {
		t.Fatalf("complete github connection: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	if got := store.callCount(); got != 1 {
		t.Fatalf("expected constructor hydration exactly once, got %d calls", got)
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":88}}`)
	if _, err := svc.HandleGitHubWebhook(
		ctx,
		"push",
		"delivery-1",
		githubWebhookSignature("wrong-secret", webhookPayload),
		webhookPayload,
	); !errors.Is(err, ErrGitHubWebhookSignatureInvalid) {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
	if got := store.callCount(); got != 1 {
		t.Fatalf("expected webhook handling to avoid extra hydration reads, got %d calls", got)
	}
}

func TestGitHubConnectionReloadUpdateAndRotateAfterCacheMiss(t *testing.T) {
	store := db.NewMemoryStore()
	manager := secretstore.NewEphemeralManager()
	ctx := db.WithScope(context.Background(), db.Scope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	})

	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, db.TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, db.TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	seed := NewService(store, routerScanner{}, "aws")
	seed.ConnectorSecretManager = manager
	start, err := seed.StartGitHubConnection(ctx, "workspace-a", "project-1", GitHubConnectionStartRequest{})
	if err != nil {
		t.Fatalf("start github connection: %v", err)
	}
	if _, err := seed.CompleteGitHubConnection(ctx, "workspace-a", "project-1", GitHubConnectionCompleteRequest{
		State:                  start.State,
		InstallationID:         101,
		AccountLogin:           "identrail",
		TokenReference:         "vault://token",
		WebhookSecret:          "initial-secret",
		WebhookSecretReference: "vault://secret/v1",
		SelectedRepositories:   []string{"owner/repo"},
	}); err != nil {
		t.Fatalf("complete github connection: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager

	svc.githubConnectMu.Lock()
	svc.githubConnections = map[string]githubProjectConnection{}
	svc.githubConnectMu.Unlock()
	status, err := svc.GetGitHubConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get github connection after cache miss: %v", err)
	}
	if !status.Connected || status.InstallationID != 101 {
		t.Fatalf("expected persisted connection to reload, got %+v", status)
	}

	svc.githubConnectMu.Lock()
	svc.githubConnections = map[string]githubProjectConnection{}
	svc.githubConnectMu.Unlock()
	status, err = svc.UpdateGitHubConnectionRepositories(ctx, "workspace-a", "project-1", GitHubConnectionRepositorySelectionRequest{
		Repositories: []string{"owner/repo", "owner/infra"},
	})
	if err != nil {
		t.Fatalf("update repositories after cache miss: %v", err)
	}
	if len(status.SelectedRepositories) != 2 {
		t.Fatalf("expected two repositories after update, got %+v", status.SelectedRepositories)
	}

	svc.githubConnectMu.Lock()
	svc.githubConnections = map[string]githubProjectConnection{}
	svc.githubConnectMu.Unlock()
	status, err = svc.RotateGitHubConnectionSecret(ctx, "workspace-a", "project-1", GitHubConnectionSecretRotationRequest{
		WebhookSecret:          "rotated-secret",
		WebhookSecretReference: "vault://secret/v2",
	})
	if err != nil {
		t.Fatalf("rotate secret after cache miss: %v", err)
	}
	if status.WebhookSecretReference != "vault://secret/v2" {
		t.Fatalf("expected rotated secret reference, got %+v", status)
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/infra"},"installation":{"id":101}}`)
	if _, err := svc.HandleGitHubWebhook(
		ctx,
		"push",
		"delivery-rotated",
		githubWebhookSignature("rotated-secret", webhookPayload),
		webhookPayload,
	); err != nil {
		t.Fatalf("expected rotated secret webhook to validate: %v", err)
	}
}

func TestGitHubMetadataHelpers(t *testing.T) {
	metadata := map[string]any{
		"string":            "  identrail  ",
		"repos":             []any{" owner/repo ", 12, nil},
		"repos_strings":     []string{" owner/infra "},
		"installation_str":  "42",
		"installation_num":  float64(77),
		"timestamp_string":  "2026-05-05T12:00:00Z",
		"timestamp_invalid": "not-a-time",
		"timestamp_numeric": int64(123),
	}

	if got := metadataString(nil, "missing"); got != "" {
		t.Fatalf("expected empty metadata string for nil map, got %q", got)
	}
	if got := metadataString(metadata, "string"); got != "identrail" {
		t.Fatalf("unexpected metadata string: %q", got)
	}

	repos := metadataStringSlice(metadata, "repos")
	if len(repos) != 1 || repos[0] != "owner/repo" {
		t.Fatalf("unexpected repos slice: %+v", repos)
	}
	repos = metadataStringSlice(metadata, "repos_strings")
	if len(repos) != 1 || repos[0] != " owner/infra " {
		t.Fatalf("unexpected repos_strings slice: %+v", repos)
	}
	if repos := metadataStringSlice(metadata, "missing"); len(repos) != 0 {
		t.Fatalf("expected missing repos slice to be empty, got %+v", repos)
	}

	if got := metadataInt64(metadata, "installation_str"); got != 42 {
		t.Fatalf("expected string installation id 42, got %d", got)
	}
	if got := metadataInt64(metadata, "installation_num"); got != 77 {
		t.Fatalf("expected numeric installation id 77, got %d", got)
	}
	if got := metadataInt64(metadata, "missing"); got != 0 {
		t.Fatalf("expected missing installation id 0, got %d", got)
	}

	if got := metadataTime(metadata, "timestamp_string"); !got.Equal(time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected parsed timestamp string: %v", got)
	}
	if got := metadataTime(metadata, "timestamp_invalid"); !got.IsZero() {
		t.Fatalf("expected invalid timestamp string to produce zero value, got %v", got)
	}
	if got := metadataTime(metadata, "timestamp_numeric"); !got.IsZero() {
		t.Fatalf("expected unsupported timestamp type to produce zero value, got %v", got)
	}

	if got := firstNonEmptyString("", "fallback", "ignored"); got != "fallback" {
		t.Fatalf("expected fallback string, got %q", got)
	}
	if got := firstNonEmptyString("", ""); got != "" {
		t.Fatalf("expected empty fallback result, got %q", got)
	}

	nilService := (*Service)(nil)
	if nilService.connectorSecretManager() == nil {
		t.Fatal("expected connector secret manager fallback for nil service")
	}
}

func TestGitHubConnectionMissingConnectorPaths(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	ctx := db.WithScope(context.Background(), db.Scope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	})

	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, db.TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, db.TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	status, err := svc.GetGitHubConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get missing github connection: %v", err)
	}
	if status.Connected || len(status.SelectedRepositories) != 0 {
		t.Fatalf("expected disconnected status for missing connector, got %+v", status)
	}

	if _, err := svc.UpdateGitHubConnectionRepositories(ctx, "workspace-a", "project-1", GitHubConnectionRepositorySelectionRequest{
		Repositories: []string{"owner/repo"},
	}); !errors.Is(err, ErrGitHubConnectionNotFound) {
		t.Fatalf("expected missing connector update error, got %v", err)
	}

	if _, err := svc.RotateGitHubConnectionSecret(ctx, "workspace-a", "project-1", GitHubConnectionSecretRotationRequest{}); !errors.Is(err, ErrInvalidGitHubConnectionRequest) {
		t.Fatalf("expected invalid rotation request error, got %v", err)
	}

	if _, err := svc.RotateGitHubConnectionSecret(ctx, "workspace-a", "project-1", GitHubConnectionSecretRotationRequest{
		WebhookSecret:          "new-secret",
		WebhookSecretReference: "vault://secret/v2",
	}); !errors.Is(err, ErrGitHubConnectionNotFound) {
		t.Fatalf("expected missing connector rotate error, got %v", err)
	}

	loaded, err := svc.loadGitHubConnection(ctx, db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("load missing github connection: %v", err)
	}
	if loaded {
		t.Fatal("expected missing connector load to report false")
	}
}

func TestRouterGitHubWebhookNonScanEvent(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doAPI := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	_ = doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)

	startResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/start", `{}`)
	var startBody struct {
		Connection GitHubConnectionStartResponse `json:"connection"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	completeJSON := `{"state":"` + startBody.Connection.State + `","installation_id":99,"account_login":"identrail","token_reference":"vault://token","webhook_secret":"ping-secret","webhook_secret_reference":"vault://secret","selected_repositories":["owner/repo"]}`
	if resp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete", completeJSON); resp.Code != http.StatusOK {
		t.Fatalf("complete connection expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":99}}`)
	webhookReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(webhookPayload))
	webhookReq.Header.Set("X-GitHub-Event", "installation")
	webhookReq.Header.Set("X-GitHub-Delivery", "delivery-ping")
	webhookReq.Header.Set("X-Hub-Signature-256", githubWebhookSignature("ping-secret", webhookPayload))
	webhookResp := httptest.NewRecorder()
	r.ServeHTTP(webhookResp, webhookReq)
	if webhookResp.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for non-scan event, got %d body=%s", webhookResp.Code, webhookResp.Body.String())
	}
	var webhookBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(webhookResp.Body.Bytes(), &webhookBody); err != nil {
		t.Fatalf("decode webhook response: %v", err)
	}
	if webhookBody.Webhook.QueuedScans != 0 {
		t.Fatalf("non-scan event should not queue scans, got %d", webhookBody.Webhook.QueuedScans)
	}
	if webhookBody.Webhook.MatchedProjects != 1 {
		t.Fatalf("expected 1 matched project, got %d", webhookBody.Webhook.MatchedProjects)
	}
}

func TestRouterGitHubConnectCompleteWithInstallationIDHeader(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doAPI := func(method string, path string, body string, extraHeaders map[string]string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	_ = doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`, nil)
	_ = doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`, nil)
	_ = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`, nil)

	startResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/start", `{}`, nil)
	var startBody struct {
		Connection GitHubConnectionStartResponse `json:"connection"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	completeJSON := `{"state":"` + startBody.Connection.State + `","installation_id":0,"account_login":"identrail","token_reference":"vault://token","webhook_secret":"test-secret","webhook_secret_reference":"vault://secret","selected_repositories":["owner/repo"]}`
	resp := doAPI(
		http.MethodPost,
		"/v1/workspaces/workspace-a/projects/project-1/github/connect/complete",
		completeJSON,
		map[string]string{"X-GitHub-Installation-ID": "789"},
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("complete with header installation_id expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	statusResp := doAPI(http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/github/connection", "", nil)
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if statusBody.Connection.InstallationID != 789 {
		t.Fatalf("expected installation_id=789 from header, got %d", statusBody.Connection.InstallationID)
	}
}

func TestRouterGitHubConnectCompleteWithInvalidInstallationIDHeader(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doAPI := func(method string, path string, body string, extraHeaders map[string]string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	_ = doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`, nil)
	_ = doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`, nil)
	_ = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`, nil)

	startResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/start", `{}`, nil)
	var startBody struct {
		Connection GitHubConnectionStartResponse `json:"connection"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	completeJSON := `{"state":"` + startBody.Connection.State + `","installation_id":0,"account_login":"identrail","token_reference":"vault://token","webhook_secret":"test-secret","webhook_secret_reference":"vault://secret","selected_repositories":["owner/repo"]}`
	resp := doAPI(
		http.MethodPost,
		"/v1/workspaces/workspace-a/projects/project-1/github/connect/complete",
		completeJSON,
		map[string]string{"X-GitHub-Installation-ID": "not-a-number"},
	)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("complete with invalid header installation_id expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestNormalizeGitHubRepositories(t *testing.T) {
	repos, err := normalizeGitHubRepositories([]string{"Owner/Repo", " owner/repo ", "Owner/Other"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 unique repos after dedup, got %d: %v", len(repos), repos)
	}

	_, err = normalizeGitHubRepositories([]string{"invalid"})
	if err == nil {
		t.Fatal("expected error for invalid repository name")
	}

	repos, err = normalizeGitHubRepositories(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil: %v", err)
	}
	if len(repos) != 0 {
		t.Fatalf("expected empty slice for nil input, got %v", repos)
	}
}

func TestRepositorySelected(t *testing.T) {
	selected := []string{"owner/repo", "owner/other"}
	if !repositorySelected(selected, "Owner/Repo") {
		t.Error("expected case-insensitive match")
	}
	if repositorySelected(selected, "owner/missing") {
		t.Error("expected no match for unselected repo")
	}
	if repositorySelected(nil, "owner/repo") {
		t.Error("expected no match for nil selected list")
	}
}

func TestRouterGitHubUpdateReposWithoutConnection(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doAPI := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	_ = doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)

	resp := doAPI(http.MethodPut, "/v1/workspaces/workspace-a/projects/project-1/github/repositories", `{"repositories":["owner/repo"]}`)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for update repos without connection, got %d body=%s", resp.Code, resp.Body.String())
	}

	resp = doAPI(http.MethodPut, "/v1/workspaces/workspace-a/projects/project-1/github/repositories", `{"repositories":[]}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty repos, got %d body=%s", resp.Code, resp.Body.String())
	}

	resp = doAPI(http.MethodPut, "/v1/workspaces/workspace-a/projects/project-1/github/repositories", `{"repositories":["invalid"]}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid repo format, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterGitHubWebhookEdgeCases(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":1}}`)
	webhookReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(webhookPayload))
	webhookReq.Header.Set("X-GitHub-Event", "push")
	webhookReq.Header.Set("X-Hub-Signature-256", githubWebhookSignature("any-secret", webhookPayload))
	webhookResp := httptest.NewRecorder()
	r.ServeHTTP(webhookResp, webhookReq)
	if webhookResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no connections exist, got %d body=%s", webhookResp.Code, webhookResp.Body.String())
	}

	emptyReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(nil))
	emptyReq.Header.Set("X-GitHub-Event", "push")
	emptyResp := httptest.NewRecorder()
	r.ServeHTTP(emptyResp, emptyReq)
	if emptyResp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty payload, got %d", emptyResp.Code)
	}

	noEventReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(webhookPayload))
	noEventReq.Header.Set("X-Hub-Signature-256", "sha256=abc")
	noEventResp := httptest.NewRecorder()
	r.ServeHTTP(noEventResp, noEventReq)
	if noEventResp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing event type, got %d", noEventResp.Code)
	}

	emptyRepoPayload := []byte(`{"repository":{"full_name":""},"installation":{"id":1}}`)
	emptyRepoReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(emptyRepoPayload))
	emptyRepoReq.Header.Set("X-GitHub-Event", "push")
	emptyRepoResp := httptest.NewRecorder()
	r.ServeHTTP(emptyRepoResp, emptyRepoReq)
	if emptyRepoResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unsigned payload with empty repository, got %d body=%s", emptyRepoResp.Code, emptyRepoResp.Body.String())
	}

	badJSONReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewBufferString("not-json"))
	badJSONReq.Header.Set("X-GitHub-Event", "push")
	badJSONReq.Header.Set("X-Hub-Signature-256", "sha256=abc")
	badJSONResp := httptest.NewRecorder()
	r.ServeHTTP(badJSONResp, badJSONReq)
	if badJSONResp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", badJSONResp.Code)
	}

	noRepoPayload := []byte(`{"installation":{"id":1}}`)
	noRepoReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(noRepoPayload))
	noRepoReq.Header.Set("X-GitHub-Event", "push")
	noRepoReq.Header.Set("X-Hub-Signature-256", "sha256=abc")
	noRepoResp := httptest.NewRecorder()
	r.ServeHTTP(noRepoResp, noRepoReq)
	if noRepoResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unsigned webhook payload without repository, got %d body=%s", noRepoResp.Code, noRepoResp.Body.String())
	}
}

func TestRouterGitHubConnectCompleteErrorPaths(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doAPI := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	_ = doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)

	resp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete",
		`{"state":"nonexistent-state","installation_id":123,"account_login":"test","token_reference":"ref","webhook_secret":"sec","webhook_secret_reference":"secref","selected_repositories":["owner/repo"]}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid state, got %d body=%s", resp.Code, resp.Body.String())
	}

	resp = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete",
		`{"state":"","installation_id":123,"account_login":"test","token_reference":"ref","webhook_secret":"sec","webhook_secret_reference":"secref"}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty state, got %d body=%s", resp.Code, resp.Body.String())
	}

	resp = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete",
		`not valid json`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestGitHubConnectionKey(t *testing.T) {
	key := githubConnectionKey("Tenant", "Workspace", "Project")
	if key != "tenant::workspace::project" {
		t.Fatalf("expected lowercase key, got %q", key)
	}
}

func TestToGitHubConnectionStatus(t *testing.T) {
	conn := githubProjectConnection{
		AccountLogin:         "testuser",
		InstallationID:       42,
		TokenReference:       "ref",
		SelectedRepositories: nil,
	}
	status := toGitHubConnectionStatus(conn)
	if status.Provider != "github_app" {
		t.Fatalf("expected provider github_app, got %s", status.Provider)
	}
	if !status.Connected {
		t.Fatal("expected connected=true")
	}
	if status.SelectedRepositories == nil {
		t.Fatal("expected non-nil SelectedRepositories")
	}
}

func TestServiceGitHubConnectionStatusUsesServiceClockForRotation(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), routerScanner{}, "aws")
	now := time.Date(2035, 1, 1, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }

	scope := db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	envelope, err := svc.ConnectorSecretManager.Encrypt([]byte("webhook-secret"), githubWebhookSecretAAD(scope, "project-1"))
	if err != nil {
		t.Fatalf("encrypt webhook secret: %v", err)
	}
	conn := githubProjectConnection{
		TenantID:               scope.TenantID,
		WorkspaceID:            scope.WorkspaceID,
		ProjectID:              "project-1",
		AccountLogin:           "identrail",
		InstallationID:         42,
		TokenReference:         "vault://token",
		WebhookSecretReference: "vault://secret",
		WebhookSecretEnvelope:  envelope,
		WebhookSecretRotatedAt: now.Add(-githubWebhookSecretRotationWindow - time.Minute),
		CreatedAt:              now.Add(-time.Hour),
		UpdatedAt:              now,
	}

	status := svc.toGitHubConnectionStatus(conn)
	if !status.WebhookSecretRotationRequired {
		t.Fatal("expected rotation to be required using service clock")
	}
}
