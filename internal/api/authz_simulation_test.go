package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestRouterAuthzPolicySimulationTargetVersionReturnsDecisionAndTrace(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	sink := &recordingAuditSink{}

	ctx := defaultScopeContext()
	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{
			{Method: "GET", Path: "/v1/findings", Action: policyActionFindingsRead, ResourceType: "finding"},
		},
		RBACActionRole: map[string][]string{
			policyActionFindingsRead: {scopeRead, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsRead: {AnyOf: []abacClause{{}}},
		},
	}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal policy bundle: %v", err)
	}
	createdVersion, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	router := NewRouter(logger, metrics, svc, RouterOptions{
		AuditSink: sink,
		APIKeyScopes: map[string][]string{
			"admin-key": {scopeAdmin},
		},
	})

	requestBody := `{
		"subject":{"type":"subject","id":"user-1","tenant_id":"default","workspace_id":"default","roles":["admin"]},
		"action":"findings.read",
		"resource":{"type":"finding","id":"finding-1","tenant_id":"default","workspace_id":"default"},
		"context":{"request_path":"/v1/findings","request_method":"GET"},
		"policy_set_id":"central_authorization",
		"target_version":1,
		"audit_event":true
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/authz/policies/simulate", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "admin-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	var response authzPolicySimulationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode simulation response: %v", err)
	}
	if !response.Decision.Allowed {
		t.Fatalf("expected allowed simulation decision, got %+v", response.Decision)
	}
	if response.Policy.Source != "persisted_target_version" {
		t.Fatalf("expected persisted target version source, got %q", response.Policy.Source)
	}
	if response.Policy.Version != createdVersion.Version {
		t.Fatalf("expected policy version %d, got %d", createdVersion.Version, response.Policy.Version)
	}
	if len(response.Trace) != 5 {
		t.Fatalf("expected full 5-step trace, got %d", len(response.Trace))
	}
	if response.Trace[0].Stage != PolicyStageTenantIsolation ||
		response.Trace[1].Stage != PolicyStageRBAC ||
		response.Trace[2].Stage != PolicyStageABAC ||
		response.Trace[3].Stage != PolicyStageReBAC ||
		response.Trace[4].Stage != PolicyStageDefaultDeny {
		t.Fatalf("unexpected trace ordering: %+v", response.Trace)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	foundSimulationAudit := false
	for _, event := range sink.events {
		if event.Method == "SIMULATE" && event.Path == "/v1/authz/policies/simulate" {
			foundSimulationAudit = true
			break
		}
	}
	if !foundSimulationAudit {
		t.Fatalf("expected optional simulation audit event, got %+v", sink.events)
	}
}

func TestRouterAuthzPolicySimulationRequiresAdminRole(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")

	router := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeyScopes: map[string][]string{
			"reader-key": {scopeRead},
		},
	})

	requestBody := `{
		"subject":{"type":"subject","id":"user-1","roles":["read"]},
		"action":"findings.read",
		"resource":{"type":"finding","id":"finding-1"},
		"context":{"request_path":"/v1/findings","request_method":"GET"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/authz/policies/simulate", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "reader-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for non-admin simulation caller, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRouterAuthzPolicySimulationValidatesInput(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")

	router := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeyScopes: map[string][]string{
			"admin-key": {scopeAdmin},
		},
	})

	requestBody := `{
		"subject":{"type":"subject","id":"user-1","roles":["admin"]},
		"action":"findings.read",
		"resource":{"type":"finding","id":"finding-1"},
		"context":{"request_path":"/v1/findings","request_method":"GET"},
		"target_version":0
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/authz/policies/simulate", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "admin-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid target_version, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestNormalizeSimulationHelpers(t *testing.T) {
	if got := normalizeSimulationList(nil, true); got != nil {
		t.Fatalf("expected nil normalized list for empty input, got %+v", got)
	}
	roles := normalizeSimulationList([]string{" Admin ", "admin", "WRITE", " "}, true)
	if len(roles) != 2 || roles[0] != "admin" || roles[1] != "write" {
		t.Fatalf("unexpected normalized role list: %+v", roles)
	}

	emptyAttrs := normalizeSimulationAttributes(nil)
	if len(emptyAttrs) != 0 {
		t.Fatalf("expected empty normalized attribute map, got %+v", emptyAttrs)
	}
	attrs := normalizeSimulationAttributes(map[string]string{
		" Owner_Team ": " platform ",
		"":             "ignored",
		"env":          " ",
	})
	if len(attrs) != 1 || attrs["owner_team"] != "platform" {
		t.Fatalf("unexpected normalized attributes: %+v", attrs)
	}
}

func TestResolveSimulationRuntimeTargetVersionBranches(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "default", WorkspaceID: "default"})
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/authz/policies/simulate", nil).WithContext(ctx)

	targetVersion := 1
	if _, err := resolveSimulationRuntime(c, nil, nil, defaultCentralPolicySetID, &targetVersion); err == nil {
		t.Fatal("expected error when resolving target version without policy store")
	}

	store := db.NewMemoryStore()
	if _, err := resolveSimulationRuntime(c, store, nil, defaultCentralPolicySetID, &targetVersion); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing target version, got %v", err)
	}

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}
	if _, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      `{"schema_version":"invalid"}`,
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("create invalid policy version: %v", err)
	}
	if _, err := resolveSimulationRuntime(c, store, nil, defaultCentralPolicySetID, &targetVersion); err == nil {
		t.Fatal("expected compile error for invalid target policy bundle")
	}
}
