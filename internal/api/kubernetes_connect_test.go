package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/connectors"
	"github.com/identrail/identrail/internal/db"
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

func newKubernetesConnectionTestRouter(t *testing.T, factory KubernetesConnectorPreflightFactory) *gin.Engine {
	t.Helper()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "kubernetes")
	svc.KubernetesPreflightFactory = factory
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	_ = doKubernetesConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	projectResp := doKubernetesConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("seed project failed %d body=%s", projectResp.Code, projectResp.Body.String())
	}
	return r
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
