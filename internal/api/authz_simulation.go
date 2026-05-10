package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

type policySimulationSubjectInput struct {
	Type        string            `json:"type"`
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	WorkspaceID string            `json:"workspace_id"`
	Groups      []string          `json:"groups"`
	Roles       []string          `json:"roles"`
	Attributes  map[string]string `json:"attributes"`
}

type policySimulationResourceInput struct {
	Type        string            `json:"type"`
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	WorkspaceID string            `json:"workspace_id"`
	Attributes  map[string]string `json:"attributes"`
}

type policySimulationContextInput struct {
	RequestPath   string            `json:"request_path"`
	RequestMethod string            `json:"request_method"`
	Attributes    map[string]string `json:"attributes"`
}

type authzPolicySimulationRequest struct {
	Subject       policySimulationSubjectInput  `json:"subject"`
	Action        string                        `json:"action"`
	Resource      policySimulationResourceInput `json:"resource"`
	Context       policySimulationContextInput  `json:"context"`
	PolicySetID   string                        `json:"policy_set_id"`
	TargetVersion *int                          `json:"target_version"`
	AuditEvent    bool                          `json:"audit_event"`
}

type authzPolicySimulationPolicyResponse struct {
	Source        string `json:"source"`
	PolicySetID   string `json:"policy_set_id"`
	Version       int    `json:"version,omitempty"`
	RolloutMode   string `json:"rollout_mode,omitempty"`
	TargetVersion *int   `json:"target_version,omitempty"`
}

type authzPolicySimulationResponse struct {
	Decision PolicyDecision                      `json:"decision"`
	Trace    []PolicyTraceStep                   `json:"trace"`
	Policy   authzPolicySimulationPolicyResponse `json:"policy"`
}

func authzPolicySimulationHandler(logger *zap.Logger, store db.Store, resolver centralPolicyRuntimeResolver, sink audit.AuditSink, fingerprinter *audit.Fingerprinter) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(c *gin.Context) {
		start := time.Now()
		var request authzPolicySimulationRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		policySetID := strings.TrimSpace(request.PolicySetID)
		if policySetID == "" {
			policySetID = defaultCentralPolicySetID
		}
		if request.TargetVersion != nil && *request.TargetVersion <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_version must be greater than zero"})
			return
		}

		input := toSimulationPolicyInput(c, request)
		if strings.TrimSpace(input.Action) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "action is required"})
			return
		}

		runtimePolicy, err := resolveSimulationRuntime(c, store, resolver, policySetID, request.TargetVersion)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "policy version not found"})
				return
			}
			logger.Error("resolve authz simulation runtime", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve policy runtime"})
			return
		}

		decision, trace, err := runtimePolicy.Engine.DecideWithTrace(c.Request.Context(), input)
		if err != nil {
			logger.Error("simulate authz decision", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to simulate policy decision"})
			return
		}

		response := authzPolicySimulationResponse{
			Decision: decision,
			Trace:    trace,
			Policy: authzPolicySimulationPolicyResponse{
				Source:        runtimePolicy.Source,
				PolicySetID:   runtimePolicy.PolicySetID,
				Version:       runtimePolicy.Version,
				RolloutMode:   runtimePolicy.RolloutMode,
				TargetVersion: request.TargetVersion,
			},
		}
		c.JSON(http.StatusOK, response)

		if request.AuditEvent {
			writeSimulationAuditEvent(logger, sink, fingerprinter, c, start)
		}
	}
}

func toSimulationPolicyInput(c *gin.Context, request authzPolicySimulationRequest) PolicyInput {
	scope := db.ScopeFromContext(c.Request.Context())

	subjectTenant := firstNonEmpty(request.Subject.TenantID, scope.TenantID)
	subjectWorkspace := firstNonEmpty(request.Subject.WorkspaceID, scope.WorkspaceID)
	resourceTenant := firstNonEmpty(request.Resource.TenantID, scope.TenantID)
	resourceWorkspace := firstNonEmpty(request.Resource.WorkspaceID, scope.WorkspaceID)

	contextAttributes := normalizeSimulationAttributes(request.Context.Attributes)
	contextAttributes[policyContextTenantIDKey] = firstNonEmpty(contextAttributes[policyContextTenantIDKey], scope.TenantID)
	contextAttributes[policyContextWorkspaceIDKey] = firstNonEmpty(contextAttributes[policyContextWorkspaceIDKey], scope.WorkspaceID)

	return PolicyInput{
		Subject: PolicySubject{
			Type:        strings.ToLower(strings.TrimSpace(request.Subject.Type)),
			ID:          strings.TrimSpace(request.Subject.ID),
			TenantID:    subjectTenant,
			WorkspaceID: subjectWorkspace,
			Groups:      normalizeSimulationList(request.Subject.Groups, false),
			Roles:       normalizeSimulationList(request.Subject.Roles, true),
			Attributes:  normalizeSimulationAttributes(request.Subject.Attributes),
		},
		Action: strings.ToLower(strings.TrimSpace(request.Action)),
		Resource: PolicyResource{
			Type:        strings.ToLower(strings.TrimSpace(request.Resource.Type)),
			ID:          strings.TrimSpace(request.Resource.ID),
			TenantID:    resourceTenant,
			WorkspaceID: resourceWorkspace,
			Attributes:  normalizeSimulationAttributes(request.Resource.Attributes),
		},
		Context: PolicyContext{
			RequestPath:   strings.TrimSpace(request.Context.RequestPath),
			RequestMethod: strings.ToUpper(strings.TrimSpace(request.Context.RequestMethod)),
			Now:           time.Now().UTC(),
			Attributes:    contextAttributes,
		},
	}
}

func normalizeSimulationList(values []string, lower bool) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if lower {
			item = strings.ToLower(item)
		}
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeSimulationAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return map[string]string{}
	}
	normalized := make(map[string]string, len(attributes))
	for key, value := range attributes {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedValue := strings.TrimSpace(value)
		if normalizedKey == "" || normalizedValue == "" {
			continue
		}
		normalized[normalizedKey] = normalizedValue
	}
	return normalized
}

func resolveSimulationRuntime(c *gin.Context, store db.Store, resolver centralPolicyRuntimeResolver, policySetID string, targetVersion *int) (resolvedCentralPolicyRuntime, error) {
	if targetVersion == nil {
		if resolver == nil {
			resolver = newCentralPolicyRuntimeResolverWithPolicySet(store, policySetID)
		}
		return resolver.Resolve(c.Request.Context())
	}
	if store == nil {
		return resolvedCentralPolicyRuntime{}, fmt.Errorf("policy store is not configured")
	}
	version, err := store.GetAuthzPolicyVersion(c.Request.Context(), policySetID, *targetVersion)
	if err != nil {
		return resolvedCentralPolicyRuntime{}, err
	}
	compiled, err := compileRouteAuthorizationPolicyBundleJSON(version.Bundle)
	if err != nil {
		return resolvedCentralPolicyRuntime{}, fmt.Errorf("compile target policy version: %w", err)
	}
	rolloutMode := db.AuthzPolicyRolloutModeDisabled
	if rollout, err := store.GetAuthzPolicyRollout(c.Request.Context(), policySetID); err == nil {
		rolloutMode = strings.TrimSpace(rollout.Mode)
	}
	return resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngineFromCompiled(store, compiled),
		Registry:    compiled.RouteRegistry,
		Source:      "persisted_target_version",
		PolicySetID: policySetID,
		Version:     version.Version,
		RolloutMode: rolloutMode,
	}, nil
}

func writeSimulationAuditEvent(logger *zap.Logger, sink audit.AuditSink, fingerprinter *audit.Fingerprinter, c *gin.Context, start time.Time) {
	if sink == nil {
		return
	}
	ctx, correlationID := audit.EnsureCorrelationID(c.Request.Context())
	actor := triageActorFromContext(c, fingerprinter)
	ctx = audit.WithActor(ctx, actor)
	event := audit.AuditEvent{
		Timestamp:     time.Now().UTC(),
		Kind:          "api_request",
		Component:     "api",
		Category:      "simulation",
		Actor:         actor,
		CorrelationID: correlationID,
		Method:        "SIMULATE",
		Path:          "/v1/authz/policies/simulate",
		Status:        http.StatusOK,
		ClientIP:      c.ClientIP(),
		DurationMS:    time.Since(start).Milliseconds(),
		UserAgent:     c.Request.UserAgent(),
	}
	if apiKey := authContextString(c, "auth.api_key"); apiKey != "" {
		event.APIKeyID = fingerprintAPIKeyWith(fingerprinter, apiKey)
	}
	if err := sink.Write(ctx, audit.NormalizeEvent(ctx, event)); err != nil {
		logger.Warn("authz simulation audit write failed", telemetry.ZapError(err))
	}
}
