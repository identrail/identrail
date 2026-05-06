package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestRouterGitHubWebhookInvalidSignatureDoesNotQueueOrMutateDeliveryState(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.DefaultScope = db.Scope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	}.Normalize()
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	scopeCtx := db.WithScope(context.Background(), db.Scope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	})
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
	if startResp.Code != http.StatusOK {
		t.Fatalf("connect start expected 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody struct {
		Connection GitHubConnectionStartResponse `json:"connection"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	completePayload := `{"state":"` + startBody.Connection.State + `","installation_id":101,"account_login":"identrail","token_reference":"vault://token","webhook_secret":"expected-secret","webhook_secret_reference":"vault://secret","selected_repositories":["owner/repo"]}`
	completeResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete", completePayload)
	if completeResp.Code != http.StatusOK {
		t.Fatalf("connect complete expected 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":101}}`)
	webhookReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(webhookPayload))
	webhookReq.Header.Set("X-GitHub-Event", "push")
	webhookReq.Header.Set("X-GitHub-Delivery", "delivery-1")
	webhookReq.Header.Set("X-Hub-Signature-256", githubWebhookSignature("wrong-secret", webhookPayload))
	webhookResp := httptest.NewRecorder()
	r.ServeHTTP(webhookResp, webhookReq)
	if webhookResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected webhook 401 for invalid signature, got %d body=%s", webhookResp.Code, webhookResp.Body.String())
	}

	statusResp := doAPI(http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/github/connection", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("connection status expected 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if statusBody.Connection.LastWebhookDeliveryID != "" || statusBody.Connection.LastWebhookEventType != "" || statusBody.Connection.LastWebhookEventAt != nil {
		t.Fatalf("expected delivery state unchanged on signature failure, got %+v", statusBody.Connection)
	}

	repoScans, err := svc.ListRepoScans(scopeCtx, 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(repoScans) != 0 {
		t.Fatalf("expected no queued/persisted repo scans, got %d", len(repoScans))
	}
}
