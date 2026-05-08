package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestAuthzSecurityRegressionCrossTenantLeakageDenied(t *testing.T) {
	sink := &middlewareRecordingAuditSink{}
	router := newAuthzSecurityRegressionRouter(t, nil, newCentralPolicyRuntimeResolver(nil), sink)

	testCases := []struct {
		name       string
		headers    map[string]string
		reasonText string
	}{
		{
			name: "tenant mismatch",
			headers: map[string]string{
				"X-Test-Scope":       scopeWrite,
				"X-Test-Auth-Tenant": "tenant-b",
			},
			reasonText: "tenant scope mismatch",
		},
		{
			name: "workspace mismatch",
			headers: map[string]string{
				"X-Test-Scope":          scopeWrite,
				"X-Test-Auth-Workspace": "workspace-b",
			},
			reasonText: "workspace scope mismatch",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, decision := runAuthzSecurityRequest(t, router, sink, http.MethodPost, "/v1/scans", tc.headers)
			if status != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", status)
			}
			if decision.Allowed {
				t.Fatalf("expected denied decision, got %+v", decision)
			}
			if decision.Stage != string(PolicyStageTenantIsolation) {
				t.Fatalf("expected stage %q, got %q", PolicyStageTenantIsolation, decision.Stage)
			}
			if !strings.Contains(strings.ToLower(decision.Reason), strings.ToLower(tc.reasonText)) {
				t.Fatalf("expected reason to contain %q, got %q", tc.reasonText, decision.Reason)
			}
		})
	}
}

func TestAuthzSecurityRegressionPrivilegeEscalationDenied(t *testing.T) {
	sink := &middlewareRecordingAuditSink{}
	router := newAuthzSecurityRegressionRouter(t, nil, newCentralPolicyRuntimeResolver(nil), sink)

	testCases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
	}{
		{
			name:   "read-only subject cannot run write action",
			method: http.MethodPost,
			path:   "/v1/scans",
			headers: map[string]string{
				"X-Test-Scope": scopeRead,
			},
		},
		{
			name:   "unbound subject cannot run admin action",
			method: http.MethodPost,
			path:   "/v1/authz/policies/simulate",
			headers: map[string]string{
				"X-Test-Scope": "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, decision := runAuthzSecurityRequest(t, router, sink, tc.method, tc.path, tc.headers)
			if status != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", status)
			}
			if decision.Allowed {
				t.Fatalf("expected denied decision, got %+v", decision)
			}
			if decision.Stage != string(PolicyStageRBAC) {
				t.Fatalf("expected stage %q, got %q", PolicyStageRBAC, decision.Stage)
			}
			if !strings.Contains(strings.ToLower(decision.Reason), "rbac") {
				t.Fatalf("expected rbac reason, got %q", decision.Reason)
			}
		})
	}
}

func TestAuthzSecurityRegressionStaleClaimsScopeDowngradeDeniedImmediately(t *testing.T) {
	sink := &middlewareRecordingAuditSink{}
	router := newAuthzSecurityRegressionRouter(t, nil, newCentralPolicyRuntimeResolver(nil), sink)

	allowStatus, allowDecision := runAuthzSecurityRequest(t, router, sink, http.MethodPost, "/v1/scans", map[string]string{
		"X-Test-Scope": scopeWrite,
	})
	if allowStatus != http.StatusNoContent {
		t.Fatalf("expected first request 204, got %d", allowStatus)
	}
	if !allowDecision.Allowed {
		t.Fatalf("expected first request allow decision, got %+v", allowDecision)
	}

	denyStatus, denyDecision := runAuthzSecurityRequest(t, router, sink, http.MethodPost, "/v1/scans", map[string]string{
		"X-Test-Scope": scopeRead,
	})
	if denyStatus != http.StatusForbidden {
		t.Fatalf("expected second request 403 after scope downgrade, got %d", denyStatus)
	}
	if denyDecision.Allowed {
		t.Fatalf("expected second request denied decision, got %+v", denyDecision)
	}
	if denyDecision.Stage != string(PolicyStageRBAC) {
		t.Fatalf("expected stage %q, got %q", PolicyStageRBAC, denyDecision.Stage)
	}
	if !strings.Contains(strings.ToLower(denyDecision.Reason), "rbac") {
		t.Fatalf("expected rbac deny reason, got %q", denyDecision.Reason)
	}
}

func TestAuthzSecurityRegressionStaleABACAttributesTakeEffectImmediately(t *testing.T) {
	store := db.NewMemoryStore()
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertAuthzEntityAttributes(scopeCtx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(scopeCtx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "platform",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}

	resolver := newABACStrictTriageResolver(t, store)
	sink := &middlewareRecordingAuditSink{}
	router := newAuthzSecurityRegressionRouter(t, store, resolver, sink)

	allowStatus, allowDecision := runAuthzSecurityRequest(t, router, sink, http.MethodPatch, "/v1/findings/finding-1/triage", map[string]string{
		"X-Test-Scope": scopeWrite,
	})
	if allowStatus != http.StatusNoContent {
		t.Fatalf("expected first request 204, got %d", allowStatus)
	}
	if !allowDecision.Allowed {
		t.Fatalf("expected first request allow decision, got %+v", allowDecision)
	}

	if err := store.UpsertAuthzEntityAttributes(scopeCtx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "security",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("update resource attributes: %v", err)
	}

	denyStatus, denyDecision := runAuthzSecurityRequest(t, router, sink, http.MethodPatch, "/v1/findings/finding-1/triage", map[string]string{
		"X-Test-Scope": scopeWrite,
	})
	if denyStatus != http.StatusForbidden {
		t.Fatalf("expected second request 403 after attribute update, got %d", denyStatus)
	}
	if denyDecision.Allowed {
		t.Fatalf("expected second request denied decision, got %+v", denyDecision)
	}
	if denyDecision.Stage != string(PolicyStageABAC) {
		t.Fatalf("expected stage %q, got %q", PolicyStageABAC, denyDecision.Stage)
	}
	if !strings.Contains(strings.ToLower(denyDecision.Reason), "abac") {
		t.Fatalf("expected abac deny reason, got %q", denyDecision.Reason)
	}
}

func TestAuthzSecurityRegressionStaleRelationshipsTakeEffectImmediately(t *testing.T) {
	store := db.NewMemoryStore()
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertAuthzEntityAttributes(scopeCtx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(scopeCtx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "security",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}
	if err := store.UpsertAuthzRelationship(scopeCtx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipDelegatedAdmin,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert delegated_admin relationship: %v", err)
	}

	sink := &middlewareRecordingAuditSink{}
	router := newAuthzSecurityRegressionRouter(t, store, newCentralPolicyRuntimeResolver(store), sink)

	allowStatus, allowDecision := runAuthzSecurityRequest(t, router, sink, http.MethodPatch, "/v1/findings/finding-1/triage", map[string]string{
		"X-Test-Scope": scopeWrite,
	})
	if allowStatus != http.StatusNoContent {
		t.Fatalf("expected first request 204, got %d", allowStatus)
	}
	if !allowDecision.Allowed {
		t.Fatalf("expected first request allow decision, got %+v", allowDecision)
	}

	expiredAt := time.Now().UTC().Add(-time.Minute)
	if err := store.UpsertAuthzRelationship(scopeCtx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipDelegatedAdmin,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
		ExpiresAt:   &expiredAt,
	}); err != nil {
		t.Fatalf("expire delegated_admin relationship: %v", err)
	}

	denyStatus, denyDecision := runAuthzSecurityRequest(t, router, sink, http.MethodPatch, "/v1/findings/finding-1/triage", map[string]string{
		"X-Test-Scope": scopeWrite,
	})
	if denyStatus != http.StatusForbidden {
		t.Fatalf("expected second request 403 after relationship expiry, got %d", denyStatus)
	}
	if denyDecision.Allowed {
		t.Fatalf("expected second request denied decision, got %+v", denyDecision)
	}
	if denyDecision.Stage != string(PolicyStageReBAC) {
		t.Fatalf("expected stage %q, got %q", PolicyStageReBAC, denyDecision.Stage)
	}
	if !strings.Contains(strings.ToLower(denyDecision.Reason), "rebac") {
		t.Fatalf("expected rebac deny reason, got %q", denyDecision.Reason)
	}
}

func TestAuthzSecurityRegressionDefaultDenyExplainable(t *testing.T) {
	resolver := newDefaultDenyScansReadResolver(t, nil)
	sink := &middlewareRecordingAuditSink{}
	router := newAuthzSecurityRegressionRouter(t, nil, resolver, sink)

	status, decision := runAuthzSecurityRequest(t, router, sink, http.MethodGet, "/v1/scans/scan-1/events", map[string]string{
		"X-Test-Scope": scopeRead,
	})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", status)
	}
	if decision.Allowed {
		t.Fatalf("expected denied decision, got %+v", decision)
	}
	if decision.Stage != string(PolicyStageDefaultDeny) {
		t.Fatalf("expected stage %q, got %q", PolicyStageDefaultDeny, decision.Stage)
	}
	if !strings.Contains(strings.ToLower(decision.Reason), "no policy granted access") {
		t.Fatalf("expected explainable default-deny reason, got %q", decision.Reason)
	}
}

func newAuthzSecurityRegressionRouter(t *testing.T, store db.Store, resolver centralPolicyRuntimeResolver, sink audit.AuditSink) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		tenantID := strings.TrimSpace(c.GetHeader("X-Test-Scope-Tenant"))
		if tenantID == "" {
			tenantID = "tenant-a"
		}
		workspaceID := strings.TrimSpace(c.GetHeader("X-Test-Scope-Workspace"))
		if workspaceID == "" {
			workspaceID = "workspace-a"
		}
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: tenantID, WorkspaceID: workspaceID}))

		subjectID := strings.TrimSpace(c.GetHeader("X-Test-Subject"))
		if subjectID == "" {
			subjectID = "principal-1"
		}
		c.Set("auth.subject", subjectID)
		c.Set("auth.principal_type", "subject")
		c.Set("auth.principal_id", subjectID)

		if authTenant := strings.TrimSpace(c.GetHeader("X-Test-Auth-Tenant")); authTenant != "" {
			c.Set("auth.tenant_id", authTenant)
		}
		if authWorkspace := strings.TrimSpace(c.GetHeader("X-Test-Auth-Workspace")); authWorkspace != "" {
			c.Set("auth.workspace_id", authWorkspace)
		}

		rawScope := strings.TrimSpace(c.GetHeader("X-Test-Scope"))
		if rawScope != "" {
			c.Set("auth.scope_set", newScopeSet(strings.Split(rawScope, ",")))
		}
		c.Next()
	})
	r.Use(auditLogMiddleware(zap.NewNop(), sink, nil))
	r.Use(requireCentralPolicyMiddleware(resolver, nil, nil, store, telemetry.NewMetrics(), nil))

	r.POST("/v1/scans", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	r.GET("/v1/scans/:scan_id/events", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	r.PATCH("/v1/findings/:finding_id/triage", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	r.POST("/v1/authz/policies/simulate", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func runAuthzSecurityRequest(t *testing.T, router *gin.Engine, sink *middlewareRecordingAuditSink, method string, path string, headers map[string]string) (int, audit.AuditAuthzDecision) {
	t.Helper()

	before := authzSecurityEventCount(sink)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	router.ServeHTTP(w, req)

	decision := latestAuthzDecisionAfter(t, sink, before)
	return w.Code, decision
}

func authzSecurityEventCount(sink *middlewareRecordingAuditSink) int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return len(sink.events)
}

func latestAuthzDecisionAfter(t *testing.T, sink *middlewareRecordingAuditSink, previousCount int) audit.AuditAuthzDecision {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) <= previousCount {
		t.Fatalf("expected new audit event, previous=%d current=%d", previousCount, len(sink.events))
	}
	event := sink.events[len(sink.events)-1]
	if event.Authz == nil {
		t.Fatalf("expected authz decision in audit event, got %+v", event)
	}
	return *event.Authz
}

func newABACStrictTriageResolver(t *testing.T, store db.Store) centralPolicyRuntimeResolver {
	t.Helper()
	bundle := defaultBuiltInRouteAuthorizationPolicyBundle()
	bundle.ABACPolicies[policyActionFindingsTriage] = abacActionPolicy{
		OnNoMatch: PolicyOutcomeDeny,
		AnyOf: []abacClause{
			{
				AllOf: []abacPredicate{
					{
						Source:        abacAttributeSourceSubject,
						Key:           policyAttributeOwnerTeam,
						Operator:      abacOperatorEqualsAttribute,
						CompareSource: abacAttributeSourceResource,
						CompareKey:    policyAttributeOwnerTeam,
					},
					{
						Source:   abacAttributeSourceResource,
						Key:      policyAttributeEnvironment,
						Operator: abacOperatorOneOf,
						Values:   []string{db.AuthzAttributeEnvProd, db.AuthzAttributeEnvStaging},
					},
				},
			},
		},
	}

	compiled, err := compileRouteAuthorizationPolicyBundle(bundle)
	if err != nil {
		t.Fatalf("compile strict abac bundle: %v", err)
	}
	return staticPolicyRuntimeResolver{runtime: resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngineFromCompiled(store, compiled),
		Registry:    compiled.RouteRegistry,
		Source:      "security_regression_abac_strict",
		PolicySetID: defaultCentralPolicySetID,
		RolloutMode: db.AuthzPolicyRolloutModeDisabled,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID:      defaultCentralPolicySetID,
			Mode:             db.AuthzPolicyRolloutModeDisabled,
			CanaryPercentage: 100,
		},
	}}
}

func newDefaultDenyScansReadResolver(t *testing.T, store db.Store) centralPolicyRuntimeResolver {
	t.Helper()
	bundle := defaultBuiltInRouteAuthorizationPolicyBundle()
	bundle.ABACPolicies[policyActionScansRead] = abacActionPolicy{
		OnNoMatch: PolicyOutcomeNoOpinion,
		AnyOf: []abacClause{
			{
				AllOf: []abacPredicate{
					{
						Source:   abacAttributeSourceContext,
						Key:      "security_probe",
						Operator: abacOperatorEquals,
						Value:    "allow",
					},
				},
			},
		},
	}
	delete(bundle.ReBACPolicies, policyActionScansRead)

	compiled, err := compileRouteAuthorizationPolicyBundle(bundle)
	if err != nil {
		t.Fatalf("compile default-deny bundle: %v", err)
	}
	return staticPolicyRuntimeResolver{runtime: resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngineFromCompiled(store, compiled),
		Registry:    compiled.RouteRegistry,
		Source:      "security_regression_default_deny",
		PolicySetID: defaultCentralPolicySetID,
		RolloutMode: db.AuthzPolicyRolloutModeDisabled,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID:      defaultCentralPolicySetID,
			Mode:             db.AuthzPolicyRolloutModeDisabled,
			CanaryPercentage: 100,
		},
	}}
}
