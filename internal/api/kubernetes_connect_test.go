package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/connectors"
	k8sconnector "github.com/identrail/identrail/internal/connectors/kubernetes"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	k8sprovider "github.com/identrail/identrail/internal/providers/kubernetes"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

type fakeKubernetesPreflightRunner struct {
	result k8sprovider.KubernetesPreflightResult
}

func (f fakeKubernetesPreflightRunner) Preflight(context.Context) k8sprovider.KubernetesPreflightResult {
	return f.result
}

func TestRouterKubernetesConnectionOnboardingActive(t *testing.T) {
	var seenContext string
	r := newKubernetesConnectionTestRouter(t, func(contextName string) KubernetesConnectorPreflightRunner {
		seenContext = contextName
		return fakeKubernetesPreflightRunner{result: k8sprovider.KubernetesPreflightResult{
			Health: connectors.HealthStatusHealthy,
			Cluster: k8sprovider.KubernetesClusterIdentity{
				Context:    "prod",
				Cluster:    "prod-cluster",
				Server:     "https://kubernetes.example",
				GitVersion: "v1.30.4",
			},
			Checks: []k8sprovider.KubernetesPermissionCheckResult{{
				KubernetesPermissionCheck: k8sprovider.KubernetesPermissionCheck{Verb: "list", Resource: "serviceaccounts", Scope: "cluster"},
				Allowed:                   true,
			}},
			ObservedAt: time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		}}
	})

	resp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", `{
		"connector_id":"kubernetes-prod",
		"display_name":"Production Cluster",
		"context":"prod"
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected kubernetes connection 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	if seenContext != "prod" {
		t.Fatalf("expected request context to reach preflight factory, got %q", seenContext)
	}
	var body struct {
		Connection KubernetesConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Connection.Connected || body.Connection.Status != "active" || body.Connection.HealthStatus != "healthy" {
		t.Fatalf("expected active healthy connection, got %+v", body.Connection)
	}
	if body.Connection.Cluster != "prod-cluster" || body.Connection.GitVersion != "v1.30.4" {
		t.Fatalf("expected cluster identity metadata, got %+v", body.Connection)
	}

	statusResp := doKubernetesConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected get connection 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
}

func TestRouterKubernetesConnectionReturnsPermissionDiagnostics(t *testing.T) {
	r := newKubernetesConnectionTestRouter(t, func(contextName string) KubernetesConnectorPreflightRunner {
		return fakeKubernetesPreflightRunner{result: k8sprovider.KubernetesPreflightResult{
			Health: connectors.HealthStatusError,
			Cluster: k8sprovider.KubernetesClusterIdentity{
				Context: contextName,
			},
			Checks: []k8sprovider.KubernetesPermissionCheckResult{{
				KubernetesPermissionCheck: k8sprovider.KubernetesPermissionCheck{Verb: "list", Resource: "roles", Scope: "cluster"},
				Allowed:                   false,
				Diagnostic:                "missing Kubernetes permission: list roles",
				Remediation:               "Bind the Identrail Kubernetes identity to a ClusterRole that allows list on roles.",
			}},
			Diagnostics: []k8sprovider.KubernetesPreflightDiagnostic{{
				Code:        "kubernetes_permission_denied",
				Severity:    "error",
				Message:     "missing Kubernetes permission: list roles",
				Remediation: "Bind the Identrail Kubernetes identity to a ClusterRole that allows list on roles.",
			}},
			ObservedAt: time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		}}
	})

	resp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", `{"context":"prod"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected kubernetes connection 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Connection KubernetesConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Connection.Connected || body.Connection.Status != "degraded" || body.Connection.HealthStatus != "error" {
		t.Fatalf("expected degraded connection, got %+v", body.Connection)
	}
	if len(body.Connection.Diagnostics) != 1 || body.Connection.RemediationMessage == "" {
		t.Fatalf("expected actionable diagnostics, got %+v", body.Connection)
	}
}

func TestKubernetesConnectionPersistsAcrossServiceInstances(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")

	first := NewService(store, routerScanner{}, "kubernetes")
	first.KubernetesPreflightFactory = func(contextName string) KubernetesConnectorPreflightRunner {
		return fakeKubernetesPreflightRunner{result: k8sprovider.KubernetesPreflightResult{
			Health: connectors.HealthStatusHealthy,
			Cluster: k8sprovider.KubernetesClusterIdentity{
				Context:    contextName,
				Cluster:    "prod-cluster",
				Server:     "https://kubernetes.example",
				GitVersion: "v1.30.4",
				Platform:   "linux/amd64",
			},
			Checks: []k8sprovider.KubernetesPermissionCheckResult{{
				KubernetesPermissionCheck: k8sprovider.KubernetesPermissionCheck{Verb: "list", Resource: "serviceaccounts", Scope: "cluster"},
				Allowed:                   true,
			}},
			ObservedAt: time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		}}
	}
	if _, err := first.UpsertKubernetesConnection(ctx, "workspace-a", "project-1", KubernetesConnectionUpsertRequest{
		ConnectorID: "kubernetes-prod",
		DisplayName: "Production Cluster",
		Context:     "prod",
	}); err != nil {
		t.Fatalf("upsert kubernetes connection: %v", err)
	}

	second := NewService(store, routerScanner{}, "kubernetes")
	status, err := second.GetKubernetesConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get kubernetes connection after service restart: %v", err)
	}
	if !status.Connected || status.ConnectorID != "kubernetes-prod" {
		t.Fatalf("expected persisted kubernetes connection, got %+v", status)
	}
	if status.Context != "prod" || status.Cluster != "prod-cluster" || status.Server != "https://kubernetes.example" {
		t.Fatalf("expected persisted kubernetes metadata, got %+v", status)
	}
}

func TestKubernetesLegacyPreflightPreservesAgentMetadata(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	lastHeartbeatAt := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	enrollmentUsedAt := lastHeartbeatAt.Add(-time.Hour)
	enrollmentExpiresAt := lastHeartbeatAt.Add(time.Hour)
	metadata, err := persistedKubernetesConnectorState{
		ConnectionMode:        k8sconnector.AgentMode,
		EnrollmentTokenHash:   "enrollment-hash",
		EnrollmentExpiresAt:   &enrollmentExpiresAt,
		EnrollmentTokenUsedAt: &enrollmentUsedAt,
		AgentCredentialHash:   k8sconnector.HashCredential("agent-token"),
		AgentID:               "agent-a",
		LastHeartbeatAt:       &lastHeartbeatAt,
	}.toMap()
	if err != nil {
		t.Fatalf("encode metadata: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "kubernetes-agent",
		Type:        domain.ConnectorTypeKubernetes,
		DisplayName: "Agent cluster",
		Status:      domain.ConnectorStatusActive,
		CreatedAt:   lastHeartbeatAt,
		UpdatedAt:   lastHeartbeatAt,
	}, db.TenancyConnectorState{
		TenantID:     "tenant-a",
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "kubernetes-agent",
		HealthStatus: string(connectors.HealthStatusHealthy),
		Metadata:     metadata,
		ObservedAt:   lastHeartbeatAt,
		UpdatedAt:    lastHeartbeatAt,
	}); err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	svc := NewService(store, routerScanner{}, "kubernetes")
	svc.KubernetesPreflightFactory = func(string) KubernetesConnectorPreflightRunner {
		return fakeKubernetesPreflightRunner{result: k8sprovider.KubernetesPreflightResult{
			Health:     connectors.HealthStatusHealthy,
			ObservedAt: lastHeartbeatAt.Add(time.Minute),
			Cluster: k8sprovider.KubernetesClusterIdentity{
				Context: "prod",
				Cluster: "prod-cluster",
				Server:  "https://kubernetes.example",
			},
		}}
	}

	status, err := svc.UpsertKubernetesConnection(ctx, "workspace-a", "project-1", KubernetesConnectionUpsertRequest{})
	if err != nil {
		t.Fatalf("legacy preflight: %v", err)
	}
	if status.ConnectionMode != k8sconnector.AgentMode || status.AgentID != "agent-a" || status.LastHeartbeatAt == nil {
		t.Fatalf("expected agent mode status to survive legacy preflight, got %+v", status)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "kubernetes-agent")
	if err != nil {
		t.Fatalf("load connector: %v", err)
	}
	reloaded, err := decodePersistedKubernetesConnectorState(stored.State.Metadata)
	if err != nil {
		t.Fatalf("decode reloaded metadata: %v", err)
	}
	if reloaded.ConnectionMode != k8sconnector.AgentMode ||
		reloaded.AgentCredentialHash != k8sconnector.HashCredential("agent-token") ||
		reloaded.AgentID != "agent-a" ||
		reloaded.LastHeartbeatAt == nil ||
		!reloaded.LastHeartbeatAt.Equal(lastHeartbeatAt) {
		t.Fatalf("legacy preflight must preserve agent credentials and heartbeat metadata: %+v", reloaded)
	}
	if reloaded.Cluster != "prod-cluster" || reloaded.Server != "https://kubernetes.example" {
		t.Fatalf("legacy preflight should still refresh cluster metadata: %+v", reloaded)
	}
}

func TestRouterKubernetesConnectionPendingBeforeOnboarding(t *testing.T) {
	r := newKubernetesConnectionTestRouter(t, func(contextName string) KubernetesConnectorPreflightRunner {
		t.Fatalf("preflight should not run for read-only pending status request")
		return nil
	})

	resp := doKubernetesConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected pending connection 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Connection KubernetesConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Connection.Connected || body.Connection.Status != "pending" || body.Connection.HealthStatus != "unknown" {
		t.Fatalf("expected pending unknown connection, got %+v", body.Connection)
	}
	if len(body.Connection.PermissionChecks) != 0 || len(body.Connection.Diagnostics) != 0 {
		t.Fatalf("expected empty diagnostics for untouched connection, got %+v", body.Connection)
	}
}

func TestRouterKubernetesConnectionRejectsMalformedBody(t *testing.T) {
	r := newKubernetesConnectionTestRouter(t, func(contextName string) KubernetesConnectorPreflightRunner {
		t.Fatalf("preflight should not run for malformed request body")
		return nil
	})

	resp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", `{`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected malformed body 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterKubernetesConnectionPreflightUnavailable(t *testing.T) {
	r := newKubernetesConnectionTestRouter(t, nil)
	resp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", `{}`)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected preflight unavailable 503, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterKubernetesAgentEnrollmentSingleUseAndHeartbeat(t *testing.T) {
	r, _ := newKubernetesConnectorV2TestRouter(t)
	startResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"kubernetes-prod",
		"display_name":"Production Cluster",
		"api_url":"https://api.identrail.test"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected start connector 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody KubernetesConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if startBody.EnrollmentToken == "" || startBody.Connection.ConnectionMode != "agent" {
		t.Fatalf("expected single-use enrollment token and agent mode, got %+v", startBody)
	}
	if !bytes.Contains([]byte(startBody.HelmCommand), []byte("helm upgrade --install identrail-agent")) {
		t.Fatalf("expected helm install command, got %q", startBody.HelmCommand)
	}

	enrollResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s/enroll", `{
		"enrollment_token":`+quoteJSON(startBody.EnrollmentToken)+`,
		"agent_id":"agent-a",
		"cluster":"prod-cluster",
		"server":"https://kubernetes.example",
		"git_version":"v1.30.4",
		"platform":"linux/amd64",
		"permission_checks":[
			{"verb":"list","resource":"serviceaccounts","scope":"cluster","allowed":true},
			{"verb":"list","resource":"rolebindings","scope":"cluster","allowed":true},
			{"verb":"list","resource":"clusterrolebindings","scope":"cluster","allowed":true},
			{"verb":"list","resource":"roles","scope":"cluster","allowed":true},
			{"verb":"list","resource":"clusterroles","scope":"cluster","allowed":true},
			{"verb":"list","resource":"pods","scope":"cluster","allowed":true}
		]
	}`)
	if enrollResp.Code != http.StatusOK {
		t.Fatalf("expected enroll 200, got %d body=%s", enrollResp.Code, enrollResp.Body.String())
	}
	var enrollBody KubernetesAgentEnrollResponse
	if err := json.Unmarshal(enrollResp.Body.Bytes(), &enrollBody); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	if enrollBody.AgentToken == "" || enrollBody.HeartbeatURL != "https://api.identrail.test/v1/connectors/k8s/heartbeat" {
		t.Fatalf("expected agent token and heartbeat URL, got %+v", enrollBody)
	}
	if enrollBody.AgentToken == startBody.EnrollmentToken {
		t.Fatal("agent token must be distinct from the single-use enrollment token")
	}

	reuseResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s/enroll", `{"enrollment_token":`+quoteJSON(startBody.EnrollmentToken)+`}`)
	if reuseResp.Code != http.StatusGone {
		t.Fatalf("expected reused token 410, got %d body=%s", reuseResp.Code, reuseResp.Body.String())
	}

	enrollmentTokenHeartbeatResp := doKubernetesAgentAPI(t, r, http.MethodPost, "/v1/connectors/k8s/heartbeat", `{
		"connector_id":"kubernetes-prod",
		"agent_id":"agent-a"
	}`, startBody.EnrollmentToken)
	if enrollmentTokenHeartbeatResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected enrollment token heartbeat 401, got %d body=%s", enrollmentTokenHeartbeatResp.Code, enrollmentTokenHeartbeatResp.Body.String())
	}

	heartbeatResp := doKubernetesAgentAPI(t, r, http.MethodPost, "/v1/connectors/k8s/heartbeat", `{
		"connector_id":"kubernetes-prod",
		"agent_id":"agent-a",
		"cluster":"prod-cluster",
		"server":"https://kubernetes.example",
		"git_version":"v1.30.4",
		"platform":"linux/amd64",
		"permission_checks":[
			{"verb":"list","resource":"serviceaccounts","scope":"cluster","allowed":true},
			{"verb":"list","resource":"rolebindings","scope":"cluster","allowed":true},
			{"verb":"list","resource":"clusterrolebindings","scope":"cluster","allowed":true},
			{"verb":"list","resource":"roles","scope":"cluster","allowed":true},
			{"verb":"list","resource":"clusterroles","scope":"cluster","allowed":true},
			{"verb":"list","resource":"pods","scope":"cluster","allowed":true}
		]
	}`, enrollBody.AgentToken)
	if heartbeatResp.Code != http.StatusOK {
		t.Fatalf("expected heartbeat 200, got %d body=%s", heartbeatResp.Code, heartbeatResp.Body.String())
	}
	var heartbeatBody KubernetesAgentHeartbeatResponse
	if err := json.Unmarshal(heartbeatResp.Body.Bytes(), &heartbeatBody); err != nil {
		t.Fatalf("decode heartbeat response: %v", err)
	}
	if !heartbeatBody.Connection.Connected || heartbeatBody.Connection.LastHeartbeatAt == nil {
		t.Fatalf("expected active heartbeat connection, got %+v", heartbeatBody.Connection)
	}

	statusResp := doKubernetesConnectionAPI(t, r, http.MethodGet, "/v1/connectors/k8s?workspace_id=workspace-a&project_id=project-1", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected connector status 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection KubernetesConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if statusBody.Connection.ConnectorID != "kubernetes-prod" || statusBody.Connection.AgentID != "agent-a" {
		t.Fatalf("expected persisted agent status, got %+v", statusBody.Connection)
	}
}

func TestKubernetesConnectorStartReusesExistingConnectorWhenIDEmpty(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, routerScanner{}, "kubernetes")

	first, err := svc.StartKubernetesConnector(ctx, KubernetesConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		DisplayName: "Production Cluster",
		APIURL:      "https://api.identrail.test",
	})
	if err != nil {
		t.Fatalf("start first kubernetes connector: %v", err)
	}
	second, err := svc.StartKubernetesConnector(ctx, KubernetesConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		APIURL:      "https://api.identrail.test",
	})
	if err != nil {
		t.Fatalf("restart kubernetes connector: %v", err)
	}
	if second.Connection.ConnectorID != first.Connection.ConnectorID {
		t.Fatalf("expected retry without connector_id to reuse %q, got %q", first.Connection.ConnectorID, second.Connection.ConnectorID)
	}
	if second.Connection.DisplayName != "Production Cluster" {
		t.Fatalf("expected retry to preserve display name, got %q", second.Connection.DisplayName)
	}
	if second.EnrollmentToken == first.EnrollmentToken {
		t.Fatal("expected retry to rotate the enrollment token")
	}
	items, err := store.ListTenancyConnectors(ctx, "workspace-a", "project-1", domain.ConnectorTypeKubernetes, 10)
	if err != nil {
		t.Fatalf("list kubernetes connectors: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one reused kubernetes connector, got %d", len(items))
	}
}

func TestKubernetesKubeconfigFallbackReusesExistingConnectorWhenIDEmpty(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, routerScanner{}, "kubernetes")

	start, err := svc.StartKubernetesConnector(ctx, KubernetesConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		DisplayName: "Production Cluster",
		APIURL:      "https://api.identrail.test",
	})
	if err != nil {
		t.Fatalf("start kubernetes connector: %v", err)
	}
	kubeconfig := `apiVersion: v1
clusters:
- name: prod
  cluster:
    server: https://kubernetes.example
contexts:
- name: prod
  context:
    cluster: prod
    user: identrail
current-context: prod
users:
- name: identrail
  user:
    token: super-secret-token
`
	status, err := svc.UpsertKubernetesKubeconfigConnector(ctx, KubernetesConnectorKubeconfigRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Kubeconfig:  kubeconfig,
	})
	if err != nil {
		t.Fatalf("upsert kubeconfig connector: %v", err)
	}
	if status.ConnectorID != start.Connection.ConnectorID {
		t.Fatalf("expected kubeconfig fallback without connector_id to reuse %q, got %q", start.Connection.ConnectorID, status.ConnectorID)
	}
	if status.DisplayName != "Production Cluster" {
		t.Fatalf("expected kubeconfig fallback to preserve display name, got %q", status.DisplayName)
	}
	items, err := store.ListTenancyConnectors(ctx, "workspace-a", "project-1", domain.ConnectorTypeKubernetes, 10)
	if err != nil {
		t.Fatalf("list kubernetes connectors: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one reused kubernetes connector, got %d", len(items))
	}
	if _, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", start.Connection.ConnectorID, "kubeconfig"); err != nil {
		t.Fatalf("expected kubeconfig secret under reused connector id: %v", err)
	}
}

func TestRouterKubernetesConnectorUsesForwardedBaseURL(t *testing.T) {
	r, _ := newKubernetesConnectorV2TestRouterWithPublicBaseURL(t, "")
	req := httptest.NewRequest(http.MethodPost, "/v1/connectors/k8s", bytes.NewBufferString(`{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"kubernetes-forwarded"
	}`))
	req.Header.Set("X-API-Key", "writer-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "api.forwarded.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected start connector 200, got %d body=%s", w.Code, w.Body.String())
	}
	var body KubernetesConnectorStartResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if !bytes.Contains([]byte(body.HelmCommand), []byte(`api.url='http://api.forwarded.test'`)) {
		t.Fatalf("helm command did not use forwarded base URL: %q", body.HelmCommand)
	}
}

func TestRouterKubernetesConnectorUsesPlainRequestBaseURL(t *testing.T) {
	r, _ := newKubernetesConnectorV2TestRouterWithPublicBaseURL(t, "")
	startReq := httptest.NewRequest(http.MethodPost, "http://api.local.test/v1/connectors/k8s", bytes.NewBufferString(`{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"kubernetes-local"
	}`))
	startReq.Header.Set("X-API-Key", "writer-key")
	startReq.Header.Set("Content-Type", "application/json")
	startResp := httptest.NewRecorder()
	r.ServeHTTP(startResp, startReq)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected start connector 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody KubernetesConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if !bytes.Contains([]byte(startBody.HelmCommand), []byte(`api.url='http://api.local.test'`)) {
		t.Fatalf("helm command did not use plain request base URL: %q", startBody.HelmCommand)
	}

	enrollReq := httptest.NewRequest(http.MethodPost, "http://api.local.test/v1/connectors/k8s/enroll", bytes.NewBufferString(`{
		"enrollment_token":`+quoteJSON(startBody.EnrollmentToken)+`,
		"agent_id":"agent-local"
	}`))
	enrollReq.Header.Set("Content-Type", "application/json")
	enrollResp := httptest.NewRecorder()
	r.ServeHTTP(enrollResp, enrollReq)
	if enrollResp.Code != http.StatusOK {
		t.Fatalf("expected enroll 200, got %d body=%s", enrollResp.Code, enrollResp.Body.String())
	}
	var enrollBody KubernetesAgentEnrollResponse
	if err := json.Unmarshal(enrollResp.Body.Bytes(), &enrollBody); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	if enrollBody.HeartbeatURL != "http://api.local.test/v1/connectors/k8s/heartbeat" {
		t.Fatalf("expected plain request heartbeat URL, got %+v", enrollBody)
	}
}

func TestRouterKubernetesAgentHeartbeatWithoutProbeDegradesConnector(t *testing.T) {
	r, _ := newKubernetesConnectorV2TestRouter(t)
	startResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"kubernetes-prod"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected start connector 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody KubernetesConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	enrollResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s/enroll", `{
		"enrollment_token":`+quoteJSON(startBody.EnrollmentToken)+`,
		"agent_id":"agent-a",
		"cluster":"prod-cluster",
		"server":"https://kubernetes.example",
		"permission_checks":[{"verb":"list","resource":"pods","scope":"cluster","allowed":true}]
	}`)
	if enrollResp.Code != http.StatusOK {
		t.Fatalf("expected enroll 200, got %d body=%s", enrollResp.Code, enrollResp.Body.String())
	}
	var enrollBody KubernetesAgentEnrollResponse
	if err := json.Unmarshal(enrollResp.Body.Bytes(), &enrollBody); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}

	heartbeatResp := doKubernetesAgentAPI(t, r, http.MethodPost, "/v1/connectors/k8s/heartbeat", `{
		"connector_id":"kubernetes-prod",
		"agent_id":"agent-a"
	}`, enrollBody.AgentToken)
	if heartbeatResp.Code != http.StatusOK {
		t.Fatalf("expected degraded heartbeat 200, got %d body=%s", heartbeatResp.Code, heartbeatResp.Body.String())
	}
	var heartbeatBody KubernetesAgentHeartbeatResponse
	if err := json.Unmarshal(heartbeatResp.Body.Bytes(), &heartbeatBody); err != nil {
		t.Fatalf("decode heartbeat response: %v", err)
	}
	if heartbeatBody.Connection.Connected || heartbeatBody.Connection.Status != domain.ConnectorStatusDegraded {
		t.Fatalf("expected heartbeat without probe to degrade connector, got %+v", heartbeatBody.Connection)
	}
	assertKubernetesDiagnosticCode(t, heartbeatBody.Connection.Diagnostics, "kubernetes_agent_rbac_probe_missing")
}

func TestKubernetesAgentStatusRequiresCompleteRBACProbe(t *testing.T) {
	metadata := persistedKubernetesConnectorState{
		Cluster: "prod-cluster",
		Server:  "https://kubernetes.example",
		PermissionChecks: []k8sprovider.KubernetesPermissionCheckResult{{
			KubernetesPermissionCheck: k8sprovider.KubernetesPermissionCheck{
				Verb:     "list",
				Resource: "pods",
				Scope:    "cluster",
			},
			Allowed: true,
		}},
	}

	status, health := kubernetesAgentStatus(&metadata)
	if status != domain.ConnectorStatusDegraded || health != string(connectors.HealthStatusError) {
		t.Fatalf("expected partial RBAC probe to degrade connector, got status=%q health=%q metadata=%+v", status, health, metadata)
	}
	assertKubernetesDiagnosticCode(t, metadata.Diagnostics, "kubernetes_agent_rbac_probe_missing")
}

func TestKubernetesHelmCommandShellQuotesValues(t *testing.T) {
	command := kubernetesHelmCommand("https://api.example/$(touch bad)'x", "token'$(whoami)")
	if bytes.Contains([]byte(command), []byte(`api.url="`)) || bytes.Contains([]byte(command), []byte(`enrollment.token="`)) {
		t.Fatalf("helm command must not use shell-interpolating double quotes: %q", command)
	}
	if !bytes.Contains([]byte(command), []byte(`api.url='https://api.example/$(touch bad)'"'"'x'`)) {
		t.Fatalf("helm command did not shell-quote api URL: %q", command)
	}
	if !bytes.Contains([]byte(command), []byte(`enrollment.token='token'"'"'$(whoami)'`)) {
		t.Fatalf("helm command did not shell-quote enrollment token: %q", command)
	}
}

func TestRouterKubernetesConnectorRejectsInvalidAgentRequests(t *testing.T) {
	r, _ := newKubernetesConnectorV2TestRouter(t)

	malformedEnroll := doKubernetesAgentAPI(t, r, http.MethodPost, "/v1/connectors/k8s/enroll", `{`, "")
	if malformedEnroll.Code != http.StatusBadRequest {
		t.Fatalf("expected malformed enroll 400, got %d body=%s", malformedEnroll.Code, malformedEnroll.Body.String())
	}

	invalidHeartbeat := doKubernetesAgentAPI(t, r, http.MethodPost, "/v1/connectors/k8s/heartbeat", `{"connector_id":"kubernetes-prod"}`, "not-a-token")
	if invalidHeartbeat.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid heartbeat 401, got %d body=%s", invalidHeartbeat.Code, invalidHeartbeat.Body.String())
	}

	invalidKubeconfig := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s/kubeconfig", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"kubernetes-kubeconfig",
		"kubeconfig":"not a kubeconfig"
	}`)
	if invalidKubeconfig.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid kubeconfig 400, got %d body=%s", invalidKubeconfig.Code, invalidKubeconfig.Body.String())
	}
}

func TestRouterKubernetesConnectorFeatureFlagDisabled(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "kubernetes")
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})
	resp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s", `{}`)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled connector 404, got %d body=%s", resp.Code, resp.Body.String())
	}

	legacyPostResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", `{}`)
	if legacyPostResp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled legacy connector POST 404, got %d body=%s", legacyPostResp.Code, legacyPostResp.Body.String())
	}

	legacyGetResp := doKubernetesConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection", "")
	if legacyGetResp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled legacy connector GET 404, got %d body=%s", legacyGetResp.Code, legacyGetResp.Body.String())
	}
}

func TestKubernetesKubeconfigFallbackEncryptsSecret(t *testing.T) {
	r, store := newKubernetesConnectorV2TestRouter(t)
	kubeconfig := `apiVersion: v1
clusters:
- name: prod
  cluster:
    server: https://kubernetes.example
contexts:
- name: prod
  context:
    cluster: prod
    user: identrail
current-context: prod
users:
- name: identrail
  user:
    token: super-secret-token
`
	resp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/connectors/k8s/kubeconfig", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"kubernetes-kubeconfig",
		"display_name":"Kubeconfig fallback",
		"kubeconfig":`+quoteJSON(kubeconfig)+`
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected kubeconfig 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	secret, err := store.GetTenancyConnectorSecretEnvelope(
		db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}),
		"workspace-a",
		"project-1",
		"kubernetes-kubeconfig",
		"kubeconfig",
	)
	if err != nil {
		t.Fatalf("expected encrypted kubeconfig envelope: %v", err)
	}
	if bytes.Contains(secret.Envelope.Ciphertext, []byte("super-secret-token")) {
		t.Fatalf("kubeconfig secret ciphertext must not contain plaintext token")
	}
}

func TestKubernetesKubeconfigFallbackDoesNotActivateWithoutSecret(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(failingKubernetesSecretStore{Store: store}, routerScanner{}, "kubernetes")

	kubeconfig := `apiVersion: v1
clusters:
- name: prod
  cluster:
    server: https://kubernetes.example
contexts:
- name: prod
  context:
    cluster: prod
    user: identrail
current-context: prod
users:
- name: identrail
  user:
    token: super-secret-token
`
	_, err := svc.UpsertKubernetesKubeconfigConnector(ctx, KubernetesConnectorKubeconfigRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "kubernetes-kubeconfig",
		DisplayName: "Kubeconfig fallback",
		Kubeconfig:  kubeconfig,
	})
	if err == nil {
		t.Fatal("expected kubeconfig secret persistence failure")
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "kubernetes-kubeconfig")
	if err != nil {
		t.Fatalf("expected pending connector record for retry visibility: %v", err)
	}
	if stored.Connector.Status == domain.ConnectorStatusActive || stored.Connector.SecretRefID != "" || stored.Connector.SecretProvider != "" {
		t.Fatalf("connector must not be active or point at a missing secret: %+v", stored.Connector)
	}
	if _, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "kubernetes-kubeconfig", "kubeconfig"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected no persisted kubeconfig secret, got %v", err)
	}
}

func TestKubernetesKubeconfigFallbackPreservesExistingConnectorWhenRotationSecretFails(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	oldRotatedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	oldSecretRef := k8sconnector.SecretRef("kubernetes-kubeconfig", k8sconnector.KubeconfigSecretName)
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		TenantID:            "tenant-a",
		WorkspaceID:         "workspace-a",
		ProjectID:           "project-1",
		ConnectorID:         "kubernetes-kubeconfig",
		Type:                domain.ConnectorTypeKubernetes,
		DisplayName:         "Existing kubeconfig",
		Status:              domain.ConnectorStatusActive,
		SecretProvider:      "identrail",
		SecretRefID:         oldSecretRef,
		SecretLastRotatedAt: &oldRotatedAt,
		CreatedAt:           oldRotatedAt,
		UpdatedAt:           oldRotatedAt,
	}, db.TenancyConnectorState{
		TenantID:     "tenant-a",
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "kubernetes-kubeconfig",
		HealthStatus: string(connectors.HealthStatusHealthy),
		Metadata:     map[string]any{"connection_mode": "kubeconfig", "context": "old"},
		ObservedAt:   oldRotatedAt,
		UpdatedAt:    oldRotatedAt,
	}); err != nil {
		t.Fatalf("seed existing connector: %v", err)
	}
	svc := NewService(failingKubernetesSecretStore{Store: store}, routerScanner{}, "kubernetes")

	kubeconfig := `apiVersion: v1
clusters:
- name: prod
  cluster:
    server: https://kubernetes.example
contexts:
- name: prod
  context:
    cluster: prod
    user: identrail
current-context: prod
users:
- name: identrail
  user:
    token: replacement-token
`
	_, err := svc.UpsertKubernetesKubeconfigConnector(ctx, KubernetesConnectorKubeconfigRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "kubernetes-kubeconfig",
		DisplayName: "Replacement kubeconfig",
		Kubeconfig:  kubeconfig,
	})
	if err == nil {
		t.Fatal("expected kubeconfig secret persistence failure")
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "kubernetes-kubeconfig")
	if err != nil {
		t.Fatalf("expected existing connector to remain readable: %v", err)
	}
	if stored.Connector.Status != domain.ConnectorStatusActive ||
		stored.Connector.SecretProvider != "identrail" ||
		stored.Connector.SecretRefID != oldSecretRef ||
		stored.Connector.DisplayName != "Existing kubeconfig" ||
		stored.Connector.SecretLastRotatedAt == nil ||
		!stored.Connector.SecretLastRotatedAt.Equal(oldRotatedAt) {
		t.Fatalf("failed rotation must preserve existing connector: %+v", stored.Connector)
	}
}

type failingKubernetesSecretStore struct {
	db.Store
}

func (f failingKubernetesSecretStore) UpsertTenancyConnectorSecretEnvelope(context.Context, db.TenancyConnectorSecretEnvelope) error {
	return errors.New("persist connector secret envelope")
}

func newKubernetesConnectionTestRouter(t *testing.T, factory KubernetesConnectorPreflightFactory) *gin.Engine {
	t.Helper()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "kubernetes")
	svc.KubernetesPreflightFactory = factory
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		APIKeys:             []string{"writer-key"},
		WriteAPIKeys:        []string{"writer-key"},
		DefaultTenantID:     "tenant-a",
		DefaultWorkspaceID:  "workspace-a",
		FeatureConnectorK8S: true,
	})

	_ = doKubernetesConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	projectResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("seed project failed %d body=%s", projectResp.Code, projectResp.Body.String())
	}
	return r
}

func newKubernetesConnectorV2TestRouter(t *testing.T) (*gin.Engine, *db.MemoryStore) {
	return newKubernetesConnectorV2TestRouterWithPublicBaseURL(t, "https://api.identrail.test")
}

func newKubernetesConnectorV2TestRouterWithPublicBaseURL(t *testing.T, publicBaseURL string) (*gin.Engine, *db.MemoryStore) {
	t.Helper()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "kubernetes")
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		APIKeys:             []string{"writer-key"},
		WriteAPIKeys:        []string{"writer-key"},
		DefaultTenantID:     "tenant-a",
		DefaultWorkspaceID:  "workspace-a",
		FeatureConnectorK8S: true,
		PublicBaseURL:       publicBaseURL,
	})
	_ = doKubernetesConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	projectResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("seed project failed %d body=%s", projectResp.Code, projectResp.Body.String())
	}
	return r, store
}

func doKubernetesConnectionAPI(t *testing.T, r *gin.Engine, method string, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", "writer-key")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func doKubernetesAgentAPI(t *testing.T, r *gin.Engine, method string, path string, body string, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func assertKubernetesDiagnosticCode(t *testing.T, diagnostics []k8sprovider.KubernetesPreflightDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("expected diagnostic %q in %+v", code, diagnostics)
}

func quoteJSON(value string) string {
	payload, _ := json.Marshal(value)
	return string(payload)
}
