package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
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

	badJSONReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewBufferString("not-json"))
	badJSONReq.Header.Set("X-GitHub-Event", "push")
	badJSONReq.Header.Set("X-Hub-Signature-256", "sha256=abc")
	badJSONResp := httptest.NewRecorder()
	r.ServeHTTP(badJSONResp, badJSONReq)
	if badJSONResp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", badJSONResp.Code)
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
