package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestRoutePolicyRegistryLookup(t *testing.T) {
	registry := newRoutePolicyRegistry()
	policy, exists := registry.lookup(http.MethodPost, "/v1/scans")
	if !exists {
		t.Fatal("expected policy for POST /v1/scans")
	}
	if policy.Action != policyActionScansRun {
		t.Fatalf("expected scans.run action, got %q", policy.Action)
	}

	tenancyPolicy, exists := registry.lookup(http.MethodGet, "/v1/organizations/current")
	if !exists {
		t.Fatal("expected policy for GET /v1/organizations/current")
	}
	if tenancyPolicy.Action != policyActionTenancyRead {
		t.Fatalf("expected tenancy.read action, got %q", tenancyPolicy.Action)
	}
}

func TestPolicyRolesFromScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("auth.scope_set", newScopeSet([]string{scopeWrite}))
	roles := policyRolesFromAuth(c, nil, nil)
	if len(roles) != 2 {
		t.Fatalf("expected read+write roles, got %+v", roles)
	}
}

func TestPolicyRolesFromAuthLegacyKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("auth.api_key", "writer-key")
	roles := policyRolesFromAuth(c, []string{"writer-key"}, nil)
	if len(roles) != 2 {
		t.Fatalf("expected legacy writer to map to read+write roles, got %+v", roles)
	}
}

func TestPolicyRolesFromAuthClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("auth.roles", []string{"owner", "viewer", "ignored_role"})
	roles := policyRolesFromAuth(c, nil, nil)
	if len(roles) != 2 {
		t.Fatalf("expected owner+viewer claim roles, got %+v", roles)
	}
	if roles[0] != "owner" || roles[1] != "viewer" {
		t.Fatalf("unexpected claim role mapping %+v", roles)
	}
}

func TestRequireCentralPolicyMiddlewareWriteDeniedForReadRole(t *testing.T) {
	r := newPolicyTestRouter(newScopeSet([]string{scopeRead}), true, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareWriteAllowedForWriteRole(t *testing.T) {
	r := newPolicyTestRouter(newScopeSet([]string{scopeWrite}), true, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareBypassWhenAuthDisabled(t *testing.T) {
	r := newPolicyTestRouter(nil, false, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when auth is disabled, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareTenancyRoleMatrix(t *testing.T) {
	testCases := []struct {
		name        string
		role        string
		readStatus  int
		writeStatus int
	}{
		{
			name:        "owner can read and write tenancy",
			role:        "owner",
			readStatus:  http.StatusNoContent,
			writeStatus: http.StatusNoContent,
		},
		{
			name:        "admin can read and write tenancy",
			role:        "admin",
			readStatus:  http.StatusNoContent,
			writeStatus: http.StatusNoContent,
		},
		{
			name:        "analyst can read but cannot write tenancy",
			role:        "analyst",
			readStatus:  http.StatusNoContent,
			writeStatus: http.StatusForbidden,
		},
		{
			name:        "viewer can read but cannot write tenancy",
			role:        "viewer",
			readStatus:  http.StatusNoContent,
			writeStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := newPolicyTenancyRoleRouter(tc.role)

			readReq := httptest.NewRequest(http.MethodGet, "/v1/workspaces", nil)
			readW := httptest.NewRecorder()
			r.ServeHTTP(readW, readReq)
			if readW.Code != tc.readStatus {
				t.Fatalf("expected read status %d for role %q, got %d", tc.readStatus, tc.role, readW.Code)
			}

			writeReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces", nil)
			writeW := httptest.NewRecorder()
			r.ServeHTTP(writeW, writeReq)
			if writeW.Code != tc.writeStatus {
				t.Fatalf("expected write status %d for role %q, got %d", tc.writeStatus, tc.role, writeW.Code)
			}
		})
	}
}

func TestRequireCentralPolicyMiddlewareSetsAuditDecisionContextOnDeny(t *testing.T) {
	sink := &middlewareRecordingAuditSink{}
	router := newPolicyAuditTestRouter(newScopeSet([]string{scopeRead}), true, newCentralPolicyRuntimeResolver(nil), telemetry.NewMetrics(), sink)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected denied request to be audited")
	}
	event := sink.events[len(sink.events)-1]
	if event.Authz == nil {
		t.Fatal("expected authz decision in audit event")
	}
	if event.Authz.Allowed {
		t.Fatalf("expected denied decision, got %+v", event.Authz)
	}
	if event.Authz.Reason == "" || event.Authz.Stage == "" {
		t.Fatalf("expected decision reason and stage, got %+v", event.Authz)
	}
	if event.Authz.Input.SubjectIDHash == "" {
		t.Fatal("expected subject_id_hash in authz input summary")
	}
	if event.Authz.Input.SubjectIDHash == "principal-1" {
		t.Fatal("expected subject identifier to be hashed")
	}
}

func TestRequireCentralPolicyMiddlewareSetsAuditDecisionContextOnAllow(t *testing.T) {
	sink := &middlewareRecordingAuditSink{}
	router := newPolicyAuditTestRouter(newScopeSet([]string{scopeRead}), true, newCentralPolicyRuntimeResolver(nil), telemetry.NewMetrics(), sink)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/scans/scan-1/events", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected allowed request to be audited")
	}
	event := sink.events[len(sink.events)-1]
	if event.Authz == nil {
		t.Fatal("expected authz decision in audit event")
	}
	if !event.Authz.Allowed {
		t.Fatalf("expected allowed decision, got %+v", event.Authz)
	}
	if event.Authz.Input.ResourceIDHash == "" {
		t.Fatal("expected resource_id_hash in authz input summary")
	}
	if event.Authz.Input.ResourceIDHash == "scan-1" {
		t.Fatal("expected resource identifier to be hashed")
	}
}

func TestRoutePolicyRegistryCoversAllV1Routes(t *testing.T) {
	registry := newRoutePolicyRegistry()
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), nil, RouterOptions{})
	for _, route := range router.Routes() {
		if !strings.HasPrefix(route.Path, "/v1/") {
			continue
		}
		if _, exists := registry.lookup(route.Method, route.Path); !exists {
			t.Fatalf("missing route policy for %s %s", route.Method, route.Path)
		}
	}
}

func TestRequireCentralPolicyMiddlewareDeniesWhenRoutePolicyMissing(t *testing.T) {
	metrics := telemetry.NewMetrics()
	runtime := resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngine(nil),
		Registry:    routePolicyRegistry{},
		Source:      "persisted_active_version",
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		RolloutMode: db.AuthzPolicyRolloutModeDisabled,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID: defaultCentralPolicySetID,
			Mode:        db.AuthzPolicyRolloutModeDisabled,
		},
	}
	router := newPolicyTestRouterWithResolver(
		newScopeSet([]string{scopeWrite}),
		true,
		staticPolicyRuntimeResolver{runtime: runtime},
		metrics,
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when route policy is missing, got %d", w.Code)
	}
	if got := testutil.ToFloat64(metrics.AuthzPolicyDecisionsByVersionTotal.WithLabelValues(
		defaultCentralPolicySetID,
		"1",
		"persisted_active_version",
		db.AuthzPolicyRolloutModeDisabled,
		"false",
	)); got != 1 {
		t.Fatalf("expected one denied metric entry for missing route policy, got %v", got)
	}
}

func TestRequireCentralPolicyMiddlewareSetsAuditDecisionContextWhenRoutePolicyMissing(t *testing.T) {
	sink := &middlewareRecordingAuditSink{}
	metrics := telemetry.NewMetrics()
	runtime := resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngine(nil),
		Registry:    routePolicyRegistry{},
		Source:      "persisted_active_version",
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		RolloutMode: db.AuthzPolicyRolloutModeDisabled,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID: defaultCentralPolicySetID,
			Mode:        db.AuthzPolicyRolloutModeDisabled,
		},
	}
	router := newPolicyAuditTestRouter(
		newScopeSet([]string{scopeWrite}),
		true,
		staticPolicyRuntimeResolver{runtime: runtime},
		metrics,
		sink,
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when route policy is missing, got %d", w.Code)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected denied request to be audited")
	}
	event := sink.events[len(sink.events)-1]
	if event.Authz == nil {
		t.Fatal("expected authz decision in audit event")
	}
	if event.Authz.Allowed {
		t.Fatalf("expected denied decision, got %+v", event.Authz)
	}
	if event.Authz.Stage != string(PolicyStageDefaultDeny) {
		t.Fatalf("expected default_deny stage, got %q", event.Authz.Stage)
	}
	if !strings.Contains(strings.ToLower(event.Authz.Reason), "route authorization policy missing") {
		t.Fatalf("expected missing-policy reason, got %q", event.Authz.Reason)
	}
	if !strings.Contains(event.Authz.Input.Action, "/v1/scans") {
		t.Fatalf("expected authz input action to include request route, got %q", event.Authz.Input.Action)
	}
	if event.Authz.Input.ResourceType != "route" {
		t.Fatalf("expected route resource type for missing policy decision, got %q", event.Authz.Input.ResourceType)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenTrustedAttributesMatch(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
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

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageDeniesWhenOwnerTeamMismatch(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
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

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenOwnerTeamMismatchAndReBACDirectGrant(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
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
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipDelegatedAdmin,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert delegated_admin relationship: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenOwnerTeamMismatchAndReBACMemberOfGrant(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
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
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipMemberOf,
		ObjectType:  "team",
		ObjectID:    "platform-admins",
	}); err != nil {
		t.Fatalf("upsert member_of relationship: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "team",
		SubjectID:   "platform-admins",
		Relation:    db.AuthzRelationshipManages,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert manages relationship: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageDeniesWhenMemberDelegationRelationshipExistsButConditionsFail(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "security",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationPublic,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipMemberOf,
		ObjectType:  "team",
		ObjectID:    "platform-admins",
	}); err != nil {
		t.Fatalf("upsert member_of relationship: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "team",
		SubjectID:   "platform-admins",
		Relation:    db.AuthzRelationshipManages,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert manages relationship: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageDeniesWhenMemberDelegationRiskTierTooLow(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "security",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierMedium,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipMemberOf,
		ObjectType:  "team",
		ObjectID:    "platform-admins",
	}); err != nil {
		t.Fatalf("upsert member_of relationship: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "team",
		SubjectID:   "platform-admins",
		Relation:    db.AuthzRelationshipManages,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert manages relationship: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageDeniesWhenDirectDelegationExpired(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
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
	expiredAt := time.Now().UTC().Add(-30 * time.Minute)
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipDelegatedAdmin,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
		ExpiresAt:   &expiredAt,
	}); err != nil {
		t.Fatalf("upsert expired delegated_admin relationship: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageDeniesWhenDelegationExistsInDifferentWorkspace(t *testing.T) {
	store := db.NewMemoryStore()
	scopeA := db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	scopeB := db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-b"}
	ctxA := db.WithScope(context.Background(), scopeA)
	ctxB := db.WithScope(context.Background(), scopeB)
	if err := store.UpsertAuthzEntityAttributes(ctxA, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctxA, db.AuthzEntityAttributes{
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
	if err := store.UpsertAuthzRelationship(ctxB, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipDelegatedAdmin,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert delegated_admin relationship in workspace-b: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenTrustedAttributesMissing(t *testing.T) {
	store := db.NewMemoryStore()
	if err := store.UpsertAuthzEntityAttributes(policyTestScopeContext(), db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestTrustedAttributesFromStoreNormalizesEnumCasing(t *testing.T) {
	store := authzOverrideStore{
		Store: db.NewMemoryStore(),
		records: map[string]db.AuthzEntityAttributes{
			"resource|finding|finding-1": {
				EntityKind:     db.AuthzEntityKindResource,
				EntityType:     "finding",
				EntityID:       "finding-1",
				OwnerTeam:      "Platform_Sec",
				Environment:    "Prod",
				RiskTier:       "High",
				Classification: "Confidential",
			},
		},
	}

	attributes, err := trustedAttributesFromStore(policyTestScopeContext(), store, db.AuthzEntityKindResource, "finding", "finding-1")
	if err != nil {
		t.Fatalf("trusted attributes from store: %v", err)
	}
	if got := attributes[policyAttributeOwnerTeam]; got != "platform_sec" {
		t.Fatalf("expected normalized owner_team, got %q", got)
	}
	if got := attributes[policyAttributeEnvironment]; got != "prod" {
		t.Fatalf("expected normalized env, got %q", got)
	}
	if got := attributes[policyAttributeRiskTier]; got != "high" {
		t.Fatalf("expected normalized risk_tier, got %q", got)
	}
	if got := attributes[policyAttributeClassification]; got != "confidential" {
		t.Fatalf("expected normalized classification, got %q", got)
	}
}

func TestShouldTargetRolloutRequestDeterministicCanary(t *testing.T) {
	rollout := db.AuthzPolicyRollout{
		PolicySetID:        defaultCentralPolicySetID,
		Mode:               db.AuthzPolicyRolloutModeEnforce,
		CanaryPercentage:   25,
		TenantAllowlist:    []string{"tenant-a"},
		WorkspaceAllowlist: []string{"workspace-a"},
	}
	input := PolicyInput{
		Subject: PolicySubject{
			Type:        "subject",
			ID:          "principal-1",
			TenantID:    "tenant-a",
			WorkspaceID: "workspace-a",
		},
		Action: "scans.run",
		Resource: PolicyResource{
			Type:        "scan",
			ID:          "scan-1",
			TenantID:    "tenant-a",
			WorkspaceID: "workspace-a",
		},
		Context: PolicyContext{
			Attributes: map[string]string{
				policyContextTenantIDKey:    "tenant-a",
				policyContextWorkspaceIDKey: "workspace-a",
			},
		},
	}
	first := shouldTargetRolloutRequest(rollout, input)
	second := shouldTargetRolloutRequest(rollout, input)
	if first != second {
		t.Fatal("expected deterministic rollout targeting result")
	}
	input.Subject.TenantID = "tenant-b"
	if shouldTargetRolloutRequest(rollout, input) {
		t.Fatal("expected tenant allowlist mismatch to skip rollout targeting")
	}
}

func TestRequireCentralPolicyMiddlewareShadowEvaluatesCandidateAndTracksDivergence(t *testing.T) {
	currentCompiled, err := compileRouteAuthorizationPolicyBundle(defaultBuiltInRouteAuthorizationPolicyBundle())
	if err != nil {
		t.Fatalf("compile current policy bundle: %v", err)
	}
	candidateBundle := defaultBuiltInRouteAuthorizationPolicyBundle()
	candidateBundle.RBACActionRole[policyActionScansRun] = []string{scopeAdmin}
	candidateCompiled, err := compileRouteAuthorizationPolicyBundle(candidateBundle)
	if err != nil {
		t.Fatalf("compile candidate policy bundle: %v", err)
	}

	activeVersion := 1
	candidateVersion := 2
	runtime := resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngineFromCompiled(nil, currentCompiled),
		Registry:    currentCompiled.RouteRegistry,
		Source:      "persisted_active_version",
		PolicySetID: defaultCentralPolicySetID,
		Version:     activeVersion,
		RolloutMode: db.AuthzPolicyRolloutModeShadow,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID:        defaultCentralPolicySetID,
			ActiveVersion:      &activeVersion,
			CandidateVersion:   &candidateVersion,
			Mode:               db.AuthzPolicyRolloutModeShadow,
			CanaryPercentage:   100,
			TenantAllowlist:    []string{"tenant-a"},
			WorkspaceAllowlist: []string{"workspace-a"},
			ValidatedVersions:  []int{activeVersion, candidateVersion},
		},
		CandidateEngine:  newCentralPolicyEngineFromCompiled(nil, candidateCompiled),
		CandidateSource:  "persisted_candidate_version",
		CandidateVersion: candidateVersion,
	}
	metrics := telemetry.NewMetrics()
	router := newPolicyTestRouterWithResolver(newScopeSet([]string{scopeWrite}), true, staticPolicyRuntimeResolver{runtime: runtime}, metrics)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if got := testutil.ToFloat64(metrics.AuthzPolicyShadowEvaluationsTotal); got != 1 {
		t.Fatalf("expected one shadow evaluation, got %v", got)
	}
	if got := testutil.ToFloat64(metrics.AuthzPolicyShadowDivergencesTotal); got != 1 {
		t.Fatalf("expected one shadow divergence, got %v", got)
	}
}

func TestRequireCentralPolicyMiddlewareEnforceUsesCandidateWhenTargeted(t *testing.T) {
	currentCompiled, err := compileRouteAuthorizationPolicyBundle(defaultBuiltInRouteAuthorizationPolicyBundle())
	if err != nil {
		t.Fatalf("compile current policy bundle: %v", err)
	}
	candidateBundle := defaultBuiltInRouteAuthorizationPolicyBundle()
	candidateBundle.RBACActionRole[policyActionScansRun] = []string{scopeAdmin}
	candidateCompiled, err := compileRouteAuthorizationPolicyBundle(candidateBundle)
	if err != nil {
		t.Fatalf("compile candidate policy bundle: %v", err)
	}

	activeVersion := 1
	candidateVersion := 2
	runtime := resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngineFromCompiled(nil, currentCompiled),
		Registry:    currentCompiled.RouteRegistry,
		Source:      "persisted_active_version",
		PolicySetID: defaultCentralPolicySetID,
		Version:     activeVersion,
		RolloutMode: db.AuthzPolicyRolloutModeEnforce,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID:        defaultCentralPolicySetID,
			ActiveVersion:      &activeVersion,
			CandidateVersion:   &candidateVersion,
			Mode:               db.AuthzPolicyRolloutModeEnforce,
			CanaryPercentage:   100,
			TenantAllowlist:    []string{"tenant-a"},
			WorkspaceAllowlist: []string{"workspace-a"},
			ValidatedVersions:  []int{activeVersion, candidateVersion},
		},
		CandidateEngine:  newCentralPolicyEngineFromCompiled(nil, candidateCompiled),
		CandidateSource:  "persisted_candidate_version",
		CandidateVersion: candidateVersion,
	}
	router := newPolicyTestRouterWithResolver(newScopeSet([]string{scopeWrite}), true, staticPolicyRuntimeResolver{runtime: runtime}, telemetry.NewMetrics())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when candidate policy is enforced, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareEnforceFallsBackWhenCandidateNotValidated(t *testing.T) {
	currentCompiled, err := compileRouteAuthorizationPolicyBundle(defaultBuiltInRouteAuthorizationPolicyBundle())
	if err != nil {
		t.Fatalf("compile current policy bundle: %v", err)
	}
	candidateBundle := defaultBuiltInRouteAuthorizationPolicyBundle()
	candidateBundle.RBACActionRole[policyActionScansRun] = []string{scopeAdmin}
	candidateCompiled, err := compileRouteAuthorizationPolicyBundle(candidateBundle)
	if err != nil {
		t.Fatalf("compile candidate policy bundle: %v", err)
	}

	activeVersion := 1
	candidateVersion := 2
	runtime := resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngineFromCompiled(nil, currentCompiled),
		Registry:    currentCompiled.RouteRegistry,
		Source:      "persisted_active_version",
		PolicySetID: defaultCentralPolicySetID,
		Version:     activeVersion,
		RolloutMode: db.AuthzPolicyRolloutModeEnforce,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID:        defaultCentralPolicySetID,
			ActiveVersion:      &activeVersion,
			CandidateVersion:   &candidateVersion,
			Mode:               db.AuthzPolicyRolloutModeEnforce,
			CanaryPercentage:   100,
			TenantAllowlist:    []string{"tenant-a"},
			WorkspaceAllowlist: []string{"workspace-a"},
			ValidatedVersions:  []int{activeVersion},
		},
		CandidateEngine:  newCentralPolicyEngineFromCompiled(nil, candidateCompiled),
		CandidateSource:  "persisted_candidate_version",
		CandidateVersion: candidateVersion,
	}
	router := newPolicyTestRouterWithResolver(newScopeSet([]string{scopeWrite}), true, staticPolicyRuntimeResolver{runtime: runtime}, telemetry.NewMetrics())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when unvalidated candidate cannot be enforced, got %d", w.Code)
	}
}

func newPolicyTestRouter(scopes scopeSet, setPrincipal bool, store db.Store) *gin.Engine {
	return newPolicyTestRouterWithResolver(scopes, setPrincipal, newCentralPolicyRuntimeResolver(store), telemetry.NewMetrics())
}

func newPolicyTestRouterWithResolver(scopes scopeSet, setPrincipal bool, resolver centralPolicyRuntimeResolver, metrics *telemetry.Metrics) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}))
		if scopes != nil {
			c.Set("auth.scope_set", scopes)
		}
		if setPrincipal {
			c.Set("auth.principal_type", "subject")
			c.Set("auth.principal_id", "principal-1")
		}
		c.Next()
	})
	r.Use(requireCentralPolicyMiddleware(resolver, nil, nil, nil, metrics, nil))
	r.POST("/v1/scans", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func newPolicyTriageRouter(scopes scopeSet, setPrincipal bool, store db.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}))
		if scopes != nil {
			c.Set("auth.scope_set", scopes)
		}
		if setPrincipal {
			c.Set("auth.principal_type", "subject")
			c.Set("auth.principal_id", "principal-1")
		}
		c.Next()
	})
	r.Use(requireCentralPolicyMiddleware(newCentralPolicyRuntimeResolver(store), nil, nil, store, telemetry.NewMetrics(), nil))
	r.PATCH("/v1/findings/:finding_id/triage", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func newPolicyTenancyRoleRouter(role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}))
		c.Set("auth.subject", "subject-1")
		c.Set("auth.roles", []string{role})
		c.Set("auth.principal_type", "subject")
		c.Set("auth.principal_id", "subject-1")
		c.Next()
	})
	r.Use(requireCentralPolicyMiddleware(newCentralPolicyRuntimeResolver(nil), nil, nil, nil, telemetry.NewMetrics(), nil))
	r.GET("/v1/workspaces", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	r.POST("/v1/workspaces", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func newPolicyAuditTestRouter(scopes scopeSet, setPrincipal bool, resolver centralPolicyRuntimeResolver, metrics *telemetry.Metrics, sink audit.AuditSink) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}))
		if scopes != nil {
			c.Set("auth.scope_set", scopes)
		}
		if setPrincipal {
			c.Set("auth.principal_type", "subject")
			c.Set("auth.principal_id", "principal-1")
		}
		c.Next()
	})
	r.Use(auditLogMiddleware(zap.NewNop(), sink, nil))
	r.Use(requireCentralPolicyMiddleware(resolver, nil, nil, nil, metrics, nil))
	r.POST("/v1/scans", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	r.GET("/v1/scans/:scan_id/events", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func policyTestScopeContext() context.Context {
	return db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
}

type authzOverrideStore struct {
	db.Store
	records map[string]db.AuthzEntityAttributes
}

type staticPolicyRuntimeResolver struct {
	runtime resolvedCentralPolicyRuntime
	err     error
}

type middlewareRecordingAuditSink struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (s *middlewareRecordingAuditSink) Write(_ context.Context, event audit.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (*middlewareRecordingAuditSink) Close() error { return nil }

func (s staticPolicyRuntimeResolver) Resolve(_ context.Context) (resolvedCentralPolicyRuntime, error) {
	return s.runtime, s.err
}

func (s authzOverrideStore) GetAuthzEntityAttributes(_ context.Context, entityKind string, entityType string, entityID string) (db.AuthzEntityAttributes, error) {
	key := strings.ToLower(strings.TrimSpace(entityKind)) + "|" + strings.ToLower(strings.TrimSpace(entityType)) + "|" + strings.TrimSpace(entityID)
	if record, exists := s.records[key]; exists {
		return record, nil
	}
	return db.AuthzEntityAttributes{}, db.ErrNotFound
}
