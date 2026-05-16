package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	defaultFindingsLimit   = 100
	defaultScansLimit      = 20
	defaultEventsLimit     = 100
	maxListLimit           = 500
	maxCursorFetchLimit    = 5000
	rateLimiterEntryTTL    = 15 * time.Minute
	rateLimiterMaxEntries  = 10000
	rateLimiterCleanupTick = 256
	defaultJSONBodyLimit   = int64(1 << 20)
	corsAllowMethods       = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
	corsAllowHeaders       = "Authorization,Content-Type,X-API-Key,X-Identrail-Tenant-ID,X-Identrail-Workspace-ID,traceparent,tracestate,baggage"
	corsMaxAgeSeconds      = "600"
	scopeRead              = "read"
	scopeWrite             = "write"
	scopeAdmin             = "admin"
	apiKeyScopeTenant      = "tenant:"
	apiKeyScopeWorkspace   = "workspace:"
	scopeHeaderTenantID    = "X-Identrail-Tenant-ID"
	scopeHeaderWorkspaceID = "X-Identrail-Workspace-ID"
	authAPIKeyTenantID     = "auth.api_key_tenant_id"
	authAPIKeyWorkspaceID  = "auth.api_key_workspace_id"
)

// RouterOptions controls API middleware behavior.
type RouterOptions struct {
	APIKeys                  []string
	WriteAPIKeys             []string
	APIKeyScopes             map[string][]string
	APIKeyScopeBindings      map[string]db.Scope
	OIDCTokenVerifier        TokenVerifier
	OIDCWriteScopes          []string
	RateLimitRPM             int
	RateLimitBurst           int
	AuditSink                audit.AuditSink
	AuditFingerprinter       *audit.Fingerprinter
	TrustedProxies           []string
	CORSAllowedOrigins       []string
	DefaultTenantID          string
	DefaultWorkspaceID       string
	RequireExplicitScope     bool
	FeatureNewAuth           bool
	FeatureWorkOSLogin       bool
	FeatureConnectorAWS      bool
	FeatureConnectorGitHubV2 bool
	FeatureConnectorK8S      bool
	FeatureOnboardingWizard  bool
	FeatureNativeSSO         bool
	PublicBaseURL            string
	SessionKey               string
	AuthManualMode           bool
	WorkOSClientID           string
	WorkOSAPIKey             string
	WorkOSWebhookSecret      string
	WorkOSAuthClient         sessionauth.WorkOSClient
}

type scopedAPIKeyAuthConfig struct {
	Scopes      scopeSet
	TenantID    string
	WorkspaceID string
}

// VerifiedToken contains normalized claims extracted from a validated OIDC token.
type VerifiedToken struct {
	Subject     string
	Issuer      string
	Audiences   []string
	TenantID    string
	WorkspaceID string
	Groups      []string
	Roles       []string
	Scopes      []string
}

// TokenVerifier validates bearer tokens and returns normalized claims.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, rawToken string) (VerifiedToken, error)
}

// NewRouter builds the REST surface area and observability endpoints.
func NewRouter(logger *zap.Logger, metrics *telemetry.Metrics, svc *Service, opts RouterOptions) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	configureTrustedProxies(r, logger, opts.TrustedProxies)
	r.Use(gin.Recovery())
	r.Use(tracingMiddleware())
	r.Use(securityHeadersMiddleware())
	r.Use(corsMiddleware(opts.CORSAllowedOrigins))

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		metrics.ScanRunsTotal,
		metrics.ScanEnqueueTotal,
		metrics.ScanEnqueueFailureTotal,
		metrics.ScanEnqueueDurationMS,
		metrics.ScanSuccessTotal,
		metrics.ScanFailureTotal,
		metrics.ScanPartialTotal,
		metrics.ScanInFlight,
		metrics.ScanDurationMS,
		metrics.FindingsGenerated,
		metrics.RepoScanRunsTotal,
		metrics.RepoScanEnqueueTotal,
		metrics.RepoScanEnqueueFailureTotal,
		metrics.RepoScanEnqueueDurationMS,
		metrics.RepoScanSuccessTotal,
		metrics.RepoScanFailureTotal,
		metrics.RepoScanTruncatedTotal,
		metrics.RepoScanDurationMS,
		metrics.ServiceAuthzDenialsTotal,
		metrics.QueueDepth,
		metrics.WorkerJobsTotal,
		metrics.WorkerRequeuesTotal,
		metrics.WorkerDeadLettersTotal,
		metrics.WorkerRetriesTotal,
		metrics.AutomationRunsTotal,
		metrics.AutomationLagMS,
		metrics.RepoFindingsGenerated,
		metrics.APIDeniedRequestsTotal,
		metrics.AuthzPolicyShadowEvaluationsTotal,
		metrics.AuthzPolicyShadowDivergencesTotal,
		metrics.AuthzPolicyShadowEvaluationErrorsTotal,
		metrics.AuthzPolicyShadowDivergenceRate,
		metrics.AuthzPolicyRollbacksTotal,
		metrics.AuthzPolicyDecisionsByVersionTotal,
	)

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "identrail",
		})
	})

	r.GET("/readyz", func(c *gin.Context) {
		if svc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":     "not_ready",
				"service":    "identrail",
				"dependency": "scan_service",
			})
			return
		}
		readyCtx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := svc.CheckReadiness(readyCtx); err != nil {
			if logger != nil {
				logger.Warn("readiness check failed", telemetry.ZapError(err))
			}
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":     "not_ready",
				"service":    "identrail",
				"dependency": "runtime",
				"error":      err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":     "ready",
			"service":    "identrail",
			"dependency": "runtime",
		})
	})

	r.GET(
		"/metrics",
		rateLimitMiddleware(opts.RateLimitRPM, opts.RateLimitBurst),
		apiKeyAuthMiddleware(
			opts.APIKeys,
			opts.APIKeyScopes,
			opts.APIKeyScopeBindings,
			opts.OIDCTokenVerifier,
			opts.OIDCWriteScopes,
			opts.AuditSink,
			opts.AuditFingerprinter,
			logger,
			false,
		),
		requireMetricsScopeMiddleware(opts.WriteAPIKeys, opts.APIKeyScopes),
		gin.WrapH(promhttp.HandlerFor(registry, promhttp.HandlerOpts{})),
	)

	r.POST("/webhooks/github", func(c *gin.Context) {
		if svc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service unavailable"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, defaultJSONBodyLimit)
		payload, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
			return
		}
		result, err := svc.HandleGitHubWebhook(
			c.Request.Context(),
			c.GetHeader("X-GitHub-Event"),
			c.GetHeader("X-GitHub-Delivery"),
			c.GetHeader("X-Hub-Signature-256"),
			payload,
		)
		if err != nil {
			switch {
			case errors.Is(err, ErrGitHubWebhookSignatureInvalid):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid webhook signature"})
			case errors.Is(err, ErrInvalidGitHubWebhookPayload):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
			default:
				if logger != nil {
					logger.Error("handle github webhook", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process webhook"})
			}
			return
		}
		c.JSON(http.StatusAccepted, gin.H{
			"webhook": result,
		})
	})

	r.POST("/auth/webhooks/github", func(c *gin.Context) {
		if svc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service unavailable"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, defaultJSONBodyLimit)
		payload, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
			return
		}
		result, err := svc.HandleGitHubAppWebhook(
			c.Request.Context(),
			c.GetHeader("X-GitHub-Event"),
			c.GetHeader("X-GitHub-Delivery"),
			c.GetHeader("X-Hub-Signature-256"),
			payload,
		)
		if err != nil {
			switch {
			case errors.Is(err, ErrGitHubWebhookSignatureInvalid):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid webhook signature"})
			case errors.Is(err, ErrInvalidGitHubWebhookPayload):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
			default:
				if logger != nil {
					logger.Error("handle github app webhook", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process webhook"})
			}
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"webhook": result})
	})

	var authzStore db.Store
	if svc != nil {
		authzStore = svc.Store
		svc.Metrics = metrics
	}
	sessionManager := sessionauth.Manager{
		PublicBaseURL: opts.PublicBaseURL,
	}
	if svc != nil {
		sessionManager.Store = svc.Store
		sessionManager.Now = svc.Now
	}
	if opts.FeatureNewAuth {
		workOSClient := opts.WorkOSAuthClient
		if workOSClient == nil && opts.FeatureWorkOSLogin {
			workOSClient = sessionauth.NewWorkOSSDKClient(opts.WorkOSAPIKey, opts.WorkOSClientID)
		}
		registerAuthSessionRoutes(r, logger, svc, sessionManager, authSessionRouteOptions{
			AuditSink:           opts.AuditSink,
			AuditFingerprinter:  opts.AuditFingerprinter,
			ManualMode:          opts.AuthManualMode,
			WorkOSEnabled:       opts.FeatureWorkOSLogin,
			WorkOSClientID:      opts.WorkOSClientID,
			WorkOSClient:        workOSClient,
			WorkOSWebhookSecret: opts.WorkOSWebhookSecret,
			StateManager:        sessionauth.NewOAuthStateManager(opts.SessionKey, nil),
			PendingMFAManager:   sessionauth.NewMFAPendingStateManager(opts.SessionKey, nil),
			PublicBaseURL:       opts.PublicBaseURL,
			ReturnToOrigins:     authReturnToOrigins(opts.PublicBaseURL, opts.CORSAllowedOrigins),
		})
	}

	publicV1 := r.Group("/v1")
	publicV1.Use(auditLogMiddleware(logger, opts.AuditSink, opts.AuditFingerprinter))
	publicV1.Use(rateLimitMiddleware(opts.RateLimitRPM, opts.RateLimitBurst))
	publicV1.Use(jsonBodyLimitMiddleware(defaultJSONBodyLimit))
	if opts.FeatureNewAuth {
		registerAuthConfigRoute(publicV1, opts.AuthManualMode, opts.FeatureWorkOSLogin)
	}
	registerKubernetesAgentRoutes(publicV1, logger, svc, opts.FeatureConnectorK8S, opts.PublicBaseURL)

	v1 := r.Group("/v1")
	v1.Use(auditLogMiddleware(logger, opts.AuditSink, opts.AuditFingerprinter))
	v1.Use(apiDenialMetricsMiddleware(metrics))
	v1.Use(rateLimitMiddleware(opts.RateLimitRPM, opts.RateLimitBurst))
	v1.Use(jsonBodyLimitMiddleware(defaultJSONBodyLimit))
	if opts.FeatureNewAuth {
		v1.Use(sessionManager.Middleware())
	}
	v1.Use(apiKeyAuthMiddleware(
		opts.APIKeys,
		opts.APIKeyScopes,
		opts.APIKeyScopeBindings,
		opts.OIDCTokenVerifier,
		opts.OIDCWriteScopes,
		opts.AuditSink,
		opts.AuditFingerprinter,
		logger,
		opts.FeatureNewAuth,
	))
	v1.Use(requestScopeMiddleware(opts.DefaultTenantID, opts.DefaultWorkspaceID, opts.RequireExplicitScope))
	centralPolicyResolver := newCentralPolicyRuntimeResolver(authzStore)
	v1.Use(requireCentralPolicyMiddleware(centralPolicyResolver, opts.WriteAPIKeys, opts.APIKeyScopes, authzStore, metrics, opts.AuditFingerprinter))
	v1.POST("/authz/policies/simulate", authzPolicySimulationHandler(logger, authzStore, centralPolicyResolver, opts.AuditSink, opts.AuditFingerprinter))
	v1.POST("/authz/policies/rollback", authzPolicyRollbackHandler(logger, authzStore, metrics, opts.AuditFingerprinter))
	if opts.FeatureNewAuth {
		registerMeRoutes(v1, logger, svc, sessionManager)
		registerOnboardingRoutes(v1, logger, svc, opts.FeatureOnboardingWizard)
	}
	registerEnterpriseAuthPrepRoutes(v1)
	// Native SAML admin routes depend on session-auth middleware to populate
	// `auth.session`. Without FeatureNewAuth the middleware is not installed,
	// so the handlers would always return 401 — register only when the new
	// auth stack is on, regardless of the native-SSO feature flag.
	if opts.FeatureNewAuth {
		registerNativeSAMLAdminRoutes(v1, logger, svc, nativeSAMLRouteOptions{
			Enabled: opts.FeatureNativeSSO,
		})
	}
	registerTenancyRoutes(v1, logger, svc, opts.FeatureConnectorAWS, opts.FeatureConnectorGitHubV2)
	registerKubernetesConnectionRoutes(v1, logger, svc, opts.FeatureConnectorK8S, opts.PublicBaseURL)

	if svc == nil {
		v1.GET("/findings", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/findings/:finding_id", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.GET("/findings/:finding_id/history", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/findings/:finding_id/exports", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.GET("/findings/baseline/export", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.POST("/findings/baseline/import", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.GET("/findings/trends", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/repo-findings/trends", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/findings/summary", func(c *gin.Context) {
			c.JSON(http.StatusOK, FindingsSummary{
				Total:      0,
				BySeverity: map[string]int{},
				ByType:     map[string]int{},
			})
		})
		v1.GET("/identities", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/relationships", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/ownership/signals", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/scans", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/scans/:scan_id/diff", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.GET("/scans/:scan_id/events", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/repo-scans", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/repo-scans/:repo_scan_id", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "repo scan service unavailable"})
		})
		v1.GET("/repo-findings", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/repo-finding-clusters", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.POST("/scans", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.POST("/scans/:scan_id/replay", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.PATCH("/findings/:finding_id/triage", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.POST("/repo-scans", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "repo scan service unavailable"})
		})
		return r
	}

	v1.GET("/findings", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		items, err := svc.ListFindingsFiltered(c.Request.Context(), maxCursorFetchLimit, FindingsFilter{
			ScanID:          scanID,
			Severity:        strings.TrimSpace(c.Query("severity")),
			Type:            strings.TrimSpace(c.Query("type")),
			LifecycleStatus: strings.TrimSpace(c.Query("lifecycle_status")),
			Assignee:        strings.TrimSpace(c.Query("assignee")),
			SortBy:          sortBy,
			SortDesc:        sortDesc,
			Offset:          offset,
		})
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list findings", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list findings"})
			return
		}
		c.JSON(http.StatusOK, paginatedItemsResponseWithBaseOffset(items, offset, limit))
	})

	v1.GET("/findings/summary", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		summary, err := svc.GetFindingsSummary(c.Request.Context(), limit)
		if err != nil {
			logger.Error("findings summary", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build findings summary"})
			return
		}
		c.JSON(http.StatusOK, summary)
	})

	v1.GET("/findings/baseline/export", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		baseline, err := svc.ExportFindingBaseline(c.Request.Context(), scanID, limit)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("export finding baseline", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export finding baseline"})
			return
		}
		c.JSON(http.StatusOK, baseline)
	})

	v1.POST("/findings/baseline/import", func(c *gin.Context) {
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		var request FindingBaselineImportRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid finding baseline request"})
			return
		}
		request.ScanID = scanID
		result, err := svc.ImportFindingBaseline(
			c.Request.Context(),
			request,
			triageActorFromContext(c, opts.AuditFingerprinter),
		)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidFindingBaselineRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid finding baseline request"})
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			default:
				logger.Error("import finding baseline", telemetry.ZapError(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to import finding baseline"})
			}
			return
		}
		c.JSON(http.StatusOK, result)
	})

	v1.GET("/findings/:finding_id", func(c *gin.Context) {
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		item, err := svc.GetFinding(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			scanID,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			logger.Error("get finding", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get finding"})
			return
		}
		c.JSON(http.StatusOK, item)
	})

	v1.GET("/findings/:finding_id/history", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultEventsLimit, maxListLimit)
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		items, err := svc.ListFindingTriageHistory(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			scanID,
			limit,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			logger.Error("list finding history", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list finding history"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	v1.GET("/findings/:finding_id/exports", func(c *gin.Context) {
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		exports, err := svc.GetFindingExports(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			scanID,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			logger.Error("get finding exports", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export finding"})
			return
		}
		c.JSON(http.StatusOK, exports)
	})

	v1.GET("/findings/trends", func(c *gin.Context) {
		points := parseLimit(c.Query("points"), 10, 100)
		items, err := svc.GetFindingsTrendFiltered(
			c.Request.Context(),
			points,
			strings.TrimSpace(c.Query("severity")),
			strings.TrimSpace(c.Query("type")),
		)
		if err != nil {
			logger.Error("findings trends", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build findings trends"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	v1.GET("/repo-findings/trends", func(c *gin.Context) {
		points := parseLimit(c.Query("points"), 10, 100)
		items, err := svc.GetRepoFindingsTrendFiltered(
			c.Request.Context(),
			points,
			strings.TrimSpace(c.Query("severity")),
			strings.TrimSpace(c.Query("type")),
		)
		if err != nil {
			logger.Error("repo findings trends", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build repository findings trends"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	v1.PATCH("/findings/:finding_id/triage", func(c *gin.Context) {
		var request FindingTriageRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		item, err := svc.TriageFinding(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			scanID,
			request,
			triageActorFromContext(c, opts.AuditFingerprinter),
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			if errors.Is(err, ErrInvalidFindingTriageRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid triage request"})
				return
			}
			logger.Error("triage finding", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to triage finding"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"finding": item})
	})

	v1.GET("/identities", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "name")
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		items, err := svc.ListIdentities(
			c.Request.Context(),
			scanID,
			strings.TrimSpace(c.Query("provider")),
			strings.TrimSpace(c.Query("type")),
			strings.TrimSpace(c.Query("name_prefix")),
			maxCursorFetchLimit,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list identities", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list identities"})
			return
		}
		sortIdentities(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.GET("/relationships", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "discovered_at")
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		items, err := svc.ListRelationships(
			c.Request.Context(),
			scanID,
			strings.TrimSpace(c.Query("type")),
			strings.TrimSpace(c.Query("from_node_id")),
			strings.TrimSpace(c.Query("to_node_id")),
			maxCursorFetchLimit,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list relationships", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list relationships"})
			return
		}
		sortRelationships(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.GET("/ownership/signals", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "confidence")
		scanID, ok := optionalUUIDParam(c, c.Query("scan_id"), "scan_id")
		if !ok {
			return
		}
		items, err := svc.ListOwnershipSignals(
			c.Request.Context(),
			maxCursorFetchLimit,
			OwnershipFilter{ScanID: scanID},
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list ownership signals", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list ownership signals"})
			return
		}
		sortOwnershipSignals(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.GET("/scans", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "started_at")
		items, err := svc.ListScans(c.Request.Context(), maxCursorFetchLimit)
		if err != nil {
			logger.Error("list scans", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scans"})
			return
		}
		sortScans(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.GET("/scans/:scan_id/diff", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		scanID, ok := requiredUUIDParam(c, c.Param("scan_id"), "scan_id")
		if !ok {
			return
		}
		diff, err := svc.GetScanDiffAgainst(
			c.Request.Context(),
			scanID,
			strings.TrimSpace(c.Query("previous_scan_id")),
			limit,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			if errors.Is(err, ErrInvalidScanDiffBaseline) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid previous_scan_id"})
				return
			}
			logger.Error("scan diff", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build scan diff"})
			return
		}
		c.JSON(http.StatusOK, diff)
	})

	v1.GET("/scans/:scan_id/events", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultEventsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		scanID, ok := requiredUUIDParam(c, c.Param("scan_id"), "scan_id")
		if !ok {
			return
		}
		items, err := svc.ListScanEventsFiltered(
			c.Request.Context(),
			scanID,
			strings.TrimSpace(c.Query("level")),
			maxCursorFetchLimit,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("scan events", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scan events"})
			return
		}
		sortScanEvents(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.GET("/repo-scans", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "started_at")
		items, err := svc.ListRepoScans(c.Request.Context(), maxCursorFetchLimit)
		if err != nil {
			logger.Error("list repo scans", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list repo scans"})
			return
		}
		sortRepoScans(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.GET("/repo-scans/:repo_scan_id", func(c *gin.Context) {
		repoScanID := strings.TrimSpace(c.Param("repo_scan_id"))
		if !isValidUUID(repoScanID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_scan_id"})
			return
		}
		item, err := svc.GetRepoScan(c.Request.Context(), repoScanID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "repo scan not found"})
				return
			}
			logger.Error("get repo scan", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repo scan"})
			return
		}
		c.JSON(http.StatusOK, item)
	})

	v1.GET("/repo-findings", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		repoScanID := strings.TrimSpace(c.Query("repo_scan_id"))
		if repoScanID != "" && !isValidUUID(repoScanID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_scan_id"})
			return
		}
		items, err := svc.ListRepoFindings(
			c.Request.Context(),
			pageFetchLimit(offset, limit),
			db.RepoFindingFilter{
				RepoScanID:      repoScanID,
				Severity:        strings.TrimSpace(c.Query("severity")),
				Type:            strings.TrimSpace(c.Query("type")),
				LifecycleStatus: strings.TrimSpace(c.Query("lifecycle_status")),
				Assignee:        strings.TrimSpace(c.Query("assignee")),
				SortBy:          sortBy,
				SortDesc:        sortDesc,
			},
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "repo scan not found"})
				return
			}
			logger.Error("list repo findings", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list repo findings"})
			return
		}
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.GET("/repo-finding-clusters", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "last_seen_at")
		repoScanID := strings.TrimSpace(c.Query("repo_scan_id"))
		if repoScanID != "" && !isValidUUID(repoScanID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_scan_id"})
			return
		}
		items, err := svc.ListRepoFindingClusters(
			c.Request.Context(),
			limit,
			RepoFindingClusterFilter{
				RepoScanID: repoScanID,
				Severity:   strings.TrimSpace(c.Query("severity")),
				Type:       strings.TrimSpace(c.Query("type")),
				SortBy:     sortBy,
				SortDesc:   sortDesc,
				Offset:     offset,
			},
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "repo scan not found"})
				return
			}
			logger.Error("list repo finding clusters", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list repo finding clusters"})
			return
		}
		c.JSON(http.StatusOK, paginatedItemsResponseWithBaseOffset(items, offset, limit))
	})

	v1.POST("/scans", func(c *gin.Context) {
		start := time.Now()
		metrics.ScanEnqueueTotal.Inc()
		defer func() {
			metrics.ScanEnqueueDurationMS.Observe(float64(time.Since(start).Milliseconds()))
		}()

		scan, err := svc.EnqueueScan(c.Request.Context())
		if err != nil {
			metrics.ScanEnqueueFailureTotal.Inc()
			if errors.Is(err, ErrScanInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "scan already in progress"})
				return
			}
			if errors.Is(err, ErrScanQueueFull) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "scan queue is full"})
				return
			}
			logger.Error("enqueue scan", requestErrorLogFields(c, opts.AuditFingerprinter, "enqueue_scan", telemetry.ZapError(err))...)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue scan"})
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"scan": scan,
		})
	})

	v1.POST("/scans/:scan_id/replay", func(c *gin.Context) {
		start := time.Now()
		metrics.ScanEnqueueTotal.Inc()
		defer func() {
			metrics.ScanEnqueueDurationMS.Observe(float64(time.Since(start).Milliseconds()))
		}()

		scanID, ok := requiredUUIDParam(c, c.Param("scan_id"), "scan_id")
		if !ok {
			metrics.ScanEnqueueFailureTotal.Inc()
			return
		}

		scan, err := svc.ReplayScan(c.Request.Context(), scanID)
		if err != nil {
			metrics.ScanEnqueueFailureTotal.Inc()
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			case errors.Is(err, ErrScanReplayUnavailable):
				c.JSON(http.StatusConflict, gin.H{"error": "scan cannot be replayed"})
			case errors.Is(err, ErrScanInProgress):
				c.JSON(http.StatusConflict, gin.H{"error": "scan already in progress"})
			case errors.Is(err, ErrScanQueueFull):
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "scan queue is full"})
			default:
				logger.Error("replay scan", requestErrorLogFields(c, opts.AuditFingerprinter, "replay_scan", telemetry.ZapError(err))...)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to replay scan"})
			}
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"scan": scan,
		})
	})

	v1.POST("/repo-scans", func(c *gin.Context) {
		start := time.Now()
		metrics.RepoScanEnqueueTotal.Inc()
		defer func() {
			metrics.RepoScanEnqueueDurationMS.Observe(float64(time.Since(start).Milliseconds()))
		}()

		var request RepoScanRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			metrics.RepoScanEnqueueFailureTotal.Inc()
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		record, err := svc.EnqueueRepoScan(c.Request.Context(), request)
		if err != nil {
			metrics.RepoScanEnqueueFailureTotal.Inc()
			if errors.Is(err, ErrInvalidRepoScanRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo scan request"})
				return
			}
			if errors.Is(err, ErrRepoScanInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "repo scan already in progress"})
				return
			}
			if errors.Is(err, ErrRepoTargetNotAllowed) {
				c.JSON(http.StatusForbidden, gin.H{"error": "repo target not allowed"})
				return
			}
			if errors.Is(err, ErrRepoScanDisabled) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "repo scan is disabled"})
				return
			}
			if errors.Is(err, ErrRepoScanQueueFull) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "repo scan queue is full"})
				return
			}
			logger.Error("enqueue repo scan", requestErrorLogFields(c, opts.AuditFingerprinter, "enqueue_repo_scan", telemetry.ZapError(err))...)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue repo scan"})
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"repo_scan": record,
		})
	})

	return r
}

func registerTenancyRoutes(v1 *gin.RouterGroup, logger *zap.Logger, svc *Service, featureConnectorAWS bool, featureConnectorGitHubV2 bool) {
	v1.GET("/organizations/current", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetOrganization(c.Request.Context())
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
				return
			}
			if logger != nil {
				logger.Error("get organization", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get organization"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"organization": record})
	})

	v1.PUT("/organizations/current", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request OrganizationUpsertRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertOrganization(c.Request.Context(), request)
		if err != nil {
			if errors.Is(err, ErrInvalidTenancyRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization request"})
				return
			}
			if logger != nil {
				logger.Error("upsert organization", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert organization"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"organization": record})
	})

	v1.GET("/workspaces", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		items, err := svc.ListWorkspaces(c.Request.Context(), pageFetchLimit(offset, limit))
		if err != nil {
			if logger != nil {
				logger.Error("list workspaces", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workspaces"})
			return
		}
		sortWorkspaces(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.POST("/workspaces", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request WorkspaceUpsertRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertWorkspace(c.Request.Context(), request)
		if err != nil {
			if errors.Is(err, ErrInvalidTenancyRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace request"})
				return
			}
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
				return
			}
			if logger != nil {
				logger.Error("upsert workspace", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert workspace"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"workspace": record})
	})

	v1.GET("/whoami", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		subject := authContextString(c, "auth.subject")
		contextSnapshot, err := svc.ResolveWhoAmIContext(c.Request.Context(), subject)
		if err != nil {
			if logger != nil {
				logger.Error("resolve whoami context", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve workspace context"})
			return
		}
		principalType := "anonymous"
		principalID := ""
		if normalizedSubject := strings.TrimSpace(subject); normalizedSubject != "" {
			principalType = "subject"
			principalID = normalizedSubject
		} else if apiKey := authContextString(c, "auth.api_key"); apiKey != "" {
			principalType = "api_key"
			principalID = fingerprintAPIKeyWith(nil, apiKey)
		}
		roles := authContextStringSlice(c, "auth.roles")
		scopes := authContextScopes(c)
		c.JSON(http.StatusOK, gin.H{
			"principal": gin.H{
				"type": principalType,
				"id":   principalID,
			},
			"roles":  roles,
			"scopes": scopes,
			"scope": gin.H{
				"tenant_id":    contextSnapshot.Scope.TenantID,
				"workspace_id": contextSnapshot.Scope.WorkspaceID,
			},
			"active_workspace": contextSnapshot.ActiveWorkspace,
			"workspaces":       contextSnapshot.Workspaces,
		})
	})

	v1.POST("/workspaces/active", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		activeWorkspace, err := svc.ResolveActiveWorkspace(c.Request.Context(), authContextString(c, "auth.subject"), request.WorkspaceID)
		if err != nil {
			if errors.Is(err, ErrInvalidTenancyRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace request"})
				return
			}
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
				return
			}
			if errors.Is(err, ErrWorkspaceAccessDenied) {
				c.JSON(http.StatusForbidden, gin.H{"error": "workspace access denied"})
				return
			}
			if logger != nil {
				logger.Error("resolve active workspace", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve active workspace"})
			return
		}
		if current, ok := sessionauth.CurrentFromGin(c); ok {
			now := time.Now().UTC()
			if svc.Now != nil {
				now = svc.Now().UTC()
			}
			updated, updateErr := svc.Store.UpdateSessionContext(
				c.Request.Context(),
				current.Session.UserID,
				current.IDHash,
				activeWorkspace.Workspace.TenantID,
				activeWorkspace.Workspace.WorkspaceID,
				"",
				now,
			)
			if updateErr != nil {
				if errors.Is(updateErr, db.ErrNotFound) {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
					return
				}
				if logger != nil {
					logger.Error("update session workspace context", telemetry.ZapError(updateErr))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session context"})
				return
			}
			current.Session = updated
			c.Set("auth.session", current)
			c.Set("auth.tenant_id", updated.CurrentOrgID)
			c.Set("auth.workspace_id", updated.CurrentWorkspaceID)
			if activeWorkspace.Member != nil && activeWorkspace.Member.Role != "" {
				c.Set("auth.roles", []string{"authenticated", activeWorkspace.Member.Role})
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"active_workspace": activeWorkspace,
			"scope": gin.H{
				"tenant_id":    activeWorkspace.Workspace.TenantID,
				"workspace_id": activeWorkspace.Workspace.WorkspaceID,
			},
			"scope_headers": gin.H{
				scopeHeaderTenantID:    activeWorkspace.Workspace.TenantID,
				scopeHeaderWorkspaceID: activeWorkspace.Workspace.WorkspaceID,
			},
		})
	})

	v1.GET("/workspaces/:workspace_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetWorkspace(c.Request.Context(), c.Param("workspace_id"))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
				return
			}
			if logger != nil {
				logger.Error("get workspace", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get workspace"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"workspace": record})
	})

	v1.DELETE("/workspaces/:workspace_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		if err := svc.DeleteWorkspace(c.Request.Context(), c.Param("workspace_id")); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
				return
			}
			if logger != nil {
				logger.Error("delete workspace", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete workspace"})
			return
		}
		c.Status(http.StatusNoContent)
	})

	v1.GET("/workspaces/:workspace_id/members", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		role := strings.ToLower(strings.TrimSpace(c.Query("role")))
		status := strings.ToLower(strings.TrimSpace(c.Query("status")))
		if role != "" && !isValidWorkspaceMemberRole(role) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace member role"})
			return
		}
		if status != "" && !isValidWorkspaceMemberStatus(status) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace member status"})
			return
		}
		items, err := svc.ListWorkspaceMembers(
			c.Request.Context(),
			c.Param("workspace_id"),
			role,
			status,
			pageFetchLimit(offset, limit),
		)
		if err != nil {
			if logger != nil {
				logger.Error("list workspace members", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workspace members"})
			return
		}
		sortWorkspaceMembers(items)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.POST("/workspaces/:workspace_id/members", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request WorkspaceMemberUpsertRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertWorkspaceMember(c.Request.Context(), c.Param("workspace_id"), request)
		if err != nil {
			if errors.Is(err, ErrInvalidTenancyRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace member request"})
				return
			}
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
				return
			}
			if logger != nil {
				logger.Error("upsert workspace member", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert workspace member"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"member": record})
	})

	v1.GET("/workspaces/:workspace_id/members/:member_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetWorkspaceMember(c.Request.Context(), c.Param("workspace_id"), c.Param("member_id"))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "workspace member not found"})
				return
			}
			if logger != nil {
				logger.Error("get workspace member", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get workspace member"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"member": record})
	})

	v1.DELETE("/workspaces/:workspace_id/members/:member_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		if err := svc.DeleteWorkspaceMember(c.Request.Context(), c.Param("workspace_id"), c.Param("member_id")); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "workspace member not found"})
				return
			}
			if logger != nil {
				logger.Error("delete workspace member", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete workspace member"})
			return
		}
		c.Status(http.StatusNoContent)
	})

	v1.GET("/workspaces/:workspace_id/projects", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		includeArchived, err := parseIncludeArchived(c.Query("include_archived"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid include_archived query parameter"})
			return
		}
		items, err := svc.ListProjects(c.Request.Context(), c.Param("workspace_id"), includeArchived, pageFetchLimit(offset, limit))
		if err != nil {
			if logger != nil {
				logger.Error("list projects", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list projects"})
			return
		}
		sortProjects(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.POST("/workspaces/:workspace_id/projects", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request ProjectUpsertRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertProject(c.Request.Context(), c.Param("workspace_id"), request)
		if err != nil {
			if errors.Is(err, ErrInvalidTenancyRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project request"})
				return
			}
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
				return
			}
			if logger != nil {
				logger.Error("upsert project", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert project"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"project": record})
	})

	v1.GET("/workspaces/:workspace_id/projects/:project_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetProject(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
				return
			}
			if logger != nil {
				logger.Error("get project", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get project"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"project": record})
	})

	v1.DELETE("/workspaces/:workspace_id/projects/:project_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		if err := svc.DeleteProject(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id")); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
				return
			}
			if logger != nil {
				logger.Error("delete project", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete project"})
			return
		}
		c.Status(http.StatusNoContent)
	})

	v1.GET("/workspaces/:workspace_id/projects/:project_id/scan-policies", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		triggerMode := strings.ToLower(strings.TrimSpace(c.Query("trigger_mode")))

		var enabled *bool
		if raw := strings.TrimSpace(c.Query("enabled")); raw != "" {
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enabled query parameter"})
				return
			}
			enabled = &parsed
		}

		items, err := svc.ListScanPolicies(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), ScanPolicyListFilter{
			TriggerMode: triggerMode,
			Enabled:     enabled,
			SortBy:      sortBy,
			SortDesc:    sortDesc,
			Limit:       pageFetchLimit(offset, limit),
		})
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidScanPolicyRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan policy query"})
			case errors.Is(err, ErrScanPolicyStoreUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan policy service unavailable"})
			default:
				if logger != nil {
					logger.Error("list scan policies", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scan policies"})
			}
			return
		}
		sortScanPolicies(items, sortBy, sortDesc)
		c.JSON(http.StatusOK, paginatedItemsResponse(items, offset, limit))
	})

	v1.POST("/workspaces/:workspace_id/projects/:project_id/scan-policies", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request ScanPolicyUpsertRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertScanPolicy(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidScanPolicyRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan policy request"})
			case errors.Is(err, db.ErrConflict):
				c.JSON(http.StatusConflict, gin.H{"error": "scan policy conflicts with an existing policy"})
			case errors.Is(err, ErrScanPolicyStoreUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan policy service unavailable"})
			default:
				if logger != nil {
					logger.Error("upsert scan policy", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert scan policy"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"policy": record})
	})

	v1.GET("/workspaces/:workspace_id/projects/:project_id/scan-policies/:policy_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetScanPolicy(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), c.Param("policy_id"))
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "scan policy not found"})
			case errors.Is(err, ErrScanPolicyStoreUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan policy service unavailable"})
			default:
				if logger != nil {
					logger.Error("get scan policy", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get scan policy"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"policy": record})
	})

	v1.DELETE("/workspaces/:workspace_id/projects/:project_id/scan-policies/:policy_id", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		if err := svc.DeleteScanPolicy(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), c.Param("policy_id")); err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "scan policy not found"})
			case errors.Is(err, ErrScanPolicyStoreUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan policy service unavailable"})
			default:
				if logger != nil {
					logger.Error("delete scan policy", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete scan policy"})
			}
			return
		}
		c.Status(http.StatusNoContent)
	})

	v1.POST("/workspaces/:workspace_id/projects/:project_id/github/connect/start", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request GitHubConnectionStartRequest
		if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.StartGitHubConnection(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), request)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
				return
			}
			if errors.Is(err, ErrInvalidGitHubConnectionRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connection request"})
				return
			}
			if logger != nil {
				logger.Error("start github connection", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start github connection"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": response})
	})

	v1.POST("/connectors/aws", func(c *gin.Context) {
		if !featureConnectorAWS {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request AWSConnectorStartRequest
		if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.StartAWSConnector(c.Request.Context(), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidAWSConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid aws connector request"})
			case errors.Is(err, ErrAWSConnectorConfigUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "aws connector cloudformation flow is not configured"})
			default:
				if logger != nil {
					logger.Error("start aws connector", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start aws connector"})
			}
			return
		}
		c.JSON(http.StatusOK, response)
	})

	v1.POST("/connectors/aws/:connector_id/validate", func(c *gin.Context) {
		if !featureConnectorAWS {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request AWSConnectorValidateRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.ValidateAWSConnector(c.Request.Context(), c.Param("connector_id"), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "aws connector not found"})
			case errors.Is(err, ErrInvalidAWSConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid aws connection request"})
			case errors.Is(err, ErrAWSConnectionValidatorUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "aws connection validator unavailable"})
			default:
				if logger != nil {
					logger.Error("validate aws connector", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate aws connector"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.GET("/connectors/aws/:connector_id/poll", func(c *gin.Context) {
		if !featureConnectorAWS {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		request := AWSConnectorPollRequest{
			WorkspaceID: c.Query("workspace_id"),
			ProjectID:   c.Query("project_id"),
		}
		record, err := svc.PollAWSConnector(c.Request.Context(), c.Param("connector_id"), request)
		if err != nil {
			if errors.Is(err, ErrInvalidAWSConnectionRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid aws connector request"})
				return
			}
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "aws connector not found"})
				return
			}
			if logger != nil {
				logger.Error("poll aws connector", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to poll aws connector"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.POST("/connectors/aws/:connector_id/refresh-policy", func(c *gin.Context) {
		if !featureConnectorAWS {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request AWSConnectorPollRequest
		if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.AWSConnectorPolicy(c.Request.Context(), c.Param("connector_id"), request)
		if err != nil {
			if errors.Is(err, ErrInvalidAWSConnectionRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid aws connector request"})
				return
			}
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "aws connector not found"})
				return
			}
			if logger != nil {
				logger.Error("refresh aws connector policy", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh aws connector policy"})
			return
		}
		c.JSON(http.StatusOK, response)
	})

	v1.POST("/connectors/github", func(c *gin.Context) {
		if !featureConnectorGitHubV2 {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request GitHubConnectorStartRequest
		if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.StartGitHubConnector(c.Request.Context(), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connector request"})
			case errors.Is(err, ErrGitHubAppConfigUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "github app connector is not configured"})
			default:
				if logger != nil {
					logger.Error("start github connector", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start github connector"})
			}
			return
		}
		c.JSON(http.StatusOK, response)
	})

	v1.POST("/connectors/github/complete", func(c *gin.Context) {
		if !featureConnectorGitHubV2 {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request GitHubConnectorCompleteRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		if request.InstallationID == 0 {
			parsed, err := parseGitHubInstallationID(c.GetHeader("X-GitHub-Installation-ID"))
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connector request"})
				return
			}
			request.InstallationID = parsed
		}
		response, err := svc.CompleteGitHubConnector(c.Request.Context(), request)
		if err != nil {
			switch {
			case errors.Is(err, ErrGitHubConnectStateNotFound):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired github connector state"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connector request"})
			case errors.Is(err, ErrGitHubAppConfigUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "github app connector is not configured"})
			case errors.Is(err, ErrGitHubRepositoryListUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "github repositories unavailable"})
			default:
				if logger != nil {
					logger.Error("complete github connector", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete github connector"})
			}
			return
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/connectors/github", func(c *gin.Context) {
		if !featureConnectorGitHubV2 {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		response, err := svc.GetGitHubConnectorStatus(c.Request.Context(), c.Query("workspace_id"), c.Query("project_id"))
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connector request"})
			default:
				if logger != nil {
					logger.Error("get github connector", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get github connector"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": response})
	})

	v1.POST("/connectors/github/pat", func(c *gin.Context) {
		if !featureConnectorGitHubV2 {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request GitHubPATConnectorRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.UpsertGitHubPATConnector(c.Request.Context(), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github pat connector request"})
			case errors.Is(err, ErrGitHubPATValidatorUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "github pat validator unavailable"})
			case errors.Is(err, ErrGitHubConnectorSecretUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "github connector secret manager unavailable"})
			default:
				if logger != nil {
					logger.Error("upsert github pat connector", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save github pat connector"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": response})
	})

	v1.GET("/connectors/github/:connector_id/repos", func(c *gin.Context) {
		if !featureConnectorGitHubV2 {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		response, err := svc.GetGitHubConnectorRepositories(
			c.Request.Context(),
			c.Param("connector_id"),
			c.Query("workspace_id"),
			c.Query("project_id"),
		)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "github connector not found"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connector request"})
			default:
				if logger != nil {
					logger.Error("list github connector repositories", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list github repositories"})
			}
			return
		}
		c.JSON(http.StatusOK, response)
	})

	v1.POST("/workspaces/:workspace_id/projects/:project_id/aws/connection", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request AWSConnectionUpsertRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertAWSConnection(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidAWSConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid aws connection request"})
			case errors.Is(err, ErrAWSConnectionValidatorUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "aws connection validator unavailable"})
			default:
				if logger != nil {
					logger.Error("upsert aws connection", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate aws connection"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.GET("/workspaces/:workspace_id/projects/:project_id/aws/connection", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetAWSConnection(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
				return
			}
			if logger != nil {
				logger.Error("get aws connection", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get aws connection"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.POST("/workspaces/:workspace_id/projects/:project_id/github/connect/complete", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request GitHubConnectionCompleteRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		if request.InstallationID == 0 {
			parsed, err := parseGitHubInstallationID(c.GetHeader("X-GitHub-Installation-ID"))
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connection request"})
				return
			}
			request.InstallationID = parsed
		}
		record, err := svc.CompleteGitHubConnection(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrGitHubConnectStateNotFound):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired connection state"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github connection request"})
			default:
				if logger != nil {
					logger.Error("complete github connection", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete github connection"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.GET("/workspaces/:workspace_id/projects/:project_id/github/connection", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetGitHubConnection(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
				return
			}
			if logger != nil {
				logger.Error("get github connection", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get github connection"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.PUT("/workspaces/:workspace_id/projects/:project_id/github/repositories", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request GitHubConnectionRepositorySelectionRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpdateGitHubConnectionRepositories(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrGitHubConnectionNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "github connection not found"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github repository selection"})
			default:
				if logger != nil {
					logger.Error("update github repositories", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update github repositories"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.POST("/workspaces/:workspace_id/projects/:project_id/github/secret/rotate", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request GitHubConnectionSecretRotationRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.RotateGitHubConnectionSecret(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrGitHubConnectionNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "github connection not found"})
			case errors.Is(err, ErrInvalidGitHubConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid github secret rotation request"})
			default:
				if logger != nil {
					logger.Error("rotate github webhook secret", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate github webhook secret"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})
}

func tenancyServiceUnavailable(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service unavailable"})
}

func configureTrustedProxies(r *gin.Engine, logger *zap.Logger, proxies []string) {
	normalized := normalizeTrustedProxies(proxies)
	var err error
	if len(normalized) == 0 {
		err = r.SetTrustedProxies(nil)
	} else {
		err = r.SetTrustedProxies(normalized)
	}
	if err != nil {
		if logger != nil {
			logger.Warn("invalid trusted proxy configuration; disabling proxy trust", telemetry.ZapError(err))
		}
		_ = r.SetTrustedProxies(nil)
	}
}

func normalizeTrustedProxies(proxies []string) []string {
	if len(proxies) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(proxies))
	normalized := make([]string, 0, len(proxies))
	for _, item := range proxies {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func parseLimit(raw string, fallback int, max int) int {
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}
	if max > 0 && parsed > max {
		return max
	}
	return parsed
}

func parseCursor(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func parseSortParams(rawBy string, rawOrder string, fallbackBy string) (string, bool) {
	by := strings.ToLower(strings.TrimSpace(rawBy))
	if by == "" {
		by = fallbackBy
	}
	order := strings.ToLower(strings.TrimSpace(rawOrder))
	if order == "asc" {
		return by, false
	}
	return by, true
}

func parseIncludeArchived(raw string) (bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(trimmed)
	if err != nil {
		return false, err
	}
	return value, nil
}

func isValidUUID(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	_, err := uuid.Parse(strings.TrimSpace(raw))
	return err == nil
}

func optionalUUIDParam(c *gin.Context, raw string, field string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", true
	}
	if !isValidUUID(trimmed) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid " + field})
		return "", false
	}
	return trimmed, true
}

func requiredUUIDParam(c *gin.Context, raw string, field string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if !isValidUUID(trimmed) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid " + field})
		return "", false
	}
	return trimmed, true
}

func sortFindings(items []domain.Finding, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "severity":
			cmp = compareInt(severityOrder(left.Severity), severityOrder(right.Severity))
		case "type":
			cmp = compareString(string(left.Type), string(right.Type))
		case "title":
			cmp = compareString(left.Title, right.Title)
		default:
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortRepoFindingClusters(items []domain.RepoFindingCluster, sortBy string, desc bool) {
	domain.SortRepoFindingClusters(items, sortBy, desc)
}

func sortScans(items []db.ScanRecord, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "finding_count":
			cmp = compareInt(left.FindingCount, right.FindingCount)
		case "asset_count":
			cmp = compareInt(left.AssetCount, right.AssetCount)
		case "status":
			cmp = compareString(left.Status, right.Status)
		default:
			cmp = compareTime(left.StartedAt, right.StartedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortScanEvents(items []db.ScanEvent, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "level":
			cmp = compareInt(scanEventLevelRank(left.Level), scanEventLevelRank(right.Level))
		case "message":
			cmp = compareString(left.Message, right.Message)
		default:
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortRepoScans(items []db.RepoScanRecord, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "finding_count":
			cmp = compareInt(left.FindingCount, right.FindingCount)
		case "commits_scanned":
			cmp = compareInt(left.CommitsScanned, right.CommitsScanned)
		case "repository":
			cmp = compareString(left.Repository, right.Repository)
		case "status":
			cmp = compareString(left.Status, right.Status)
		default:
			cmp = compareTime(left.StartedAt, right.StartedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortIdentities(items []domain.Identity, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "type":
			cmp = compareString(string(left.Type), string(right.Type))
		case "provider":
			cmp = compareString(string(left.Provider), string(right.Provider))
		case "created_at":
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		default:
			cmp = compareString(left.Name, right.Name)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortRelationships(items []domain.Relationship, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "type":
			cmp = compareString(string(left.Type), string(right.Type))
		case "from_node_id":
			cmp = compareString(left.FromNodeID, right.FromNodeID)
		case "to_node_id":
			cmp = compareString(left.ToNodeID, right.ToNodeID)
		default:
			cmp = compareTime(left.DiscoveredAt, right.DiscoveredAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortOwnershipSignals(items []domain.OwnershipSignal, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "team":
			cmp = compareString(left.Team, right.Team)
		case "source":
			cmp = compareString(left.Source, right.Source)
		default:
			cmp = compareFloat(left.Confidence, right.Confidence)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortWorkspaces(items []db.TenancyWorkspace, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "workspace_id":
			cmp = compareString(left.WorkspaceID, right.WorkspaceID)
		case "display_name":
			cmp = compareString(left.DisplayName, right.DisplayName)
		case "slug":
			cmp = compareString(left.Slug, right.Slug)
		default:
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.WorkspaceID, right.WorkspaceID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortWorkspaceMembers(items []db.TenancyWorkspaceMember) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		cmp := compareTime(left.JoinedAt, right.JoinedAt)
		if cmp == 0 {
			cmp = compareString(left.MemberID, right.MemberID)
		}
		return cmp < 0
	})
}

func sortProjects(items []db.TenancyProject, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "project_id":
			cmp = compareString(left.ProjectID, right.ProjectID)
		case "name":
			cmp = compareString(left.Name, right.Name)
		case "slug":
			cmp = compareString(left.Slug, right.Slug)
		case "updated_at":
			cmp = compareTime(left.UpdatedAt, right.UpdatedAt)
		default:
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ProjectID, right.ProjectID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortScanPolicies(items []db.TenancyScanPolicy, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "policy_id":
			cmp = compareString(left.PolicyID, right.PolicyID)
		case "name":
			cmp = compareString(left.Name, right.Name)
		case "trigger_mode":
			cmp = compareString(string(left.TriggerMode), string(right.TriggerMode))
		case "updated_at":
			cmp = compareTime(left.UpdatedAt, right.UpdatedAt)
		default:
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			return compareString(left.PolicyID, right.PolicyID) < 0
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func isValidWorkspaceMemberRole(role string) bool {
	switch role {
	case "owner", "admin", "analyst", "viewer":
		return true
	default:
		return false
	}
}

func isValidWorkspaceMemberStatus(status string) bool {
	switch status {
	case "invited", "active", "suspended", "removed":
		return true
	default:
		return false
	}
}

func compareTime(left time.Time, right time.Time) int {
	switch {
	case left.Before(right):
		return -1
	case left.After(right):
		return 1
	default:
		return 0
	}
}

func compareString(left string, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareInt(left int, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareFloat(left float64, right float64) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func severityOrder(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func scanEventLevelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case db.ScanEventLevelError:
		return 4
	case db.ScanEventLevelWarn:
		return 3
	case db.ScanEventLevelInfo:
		return 2
	case db.ScanEventLevelDebug:
		return 1
	default:
		return 0
	}
}

func pageFetchLimit(offset int, limit int) int {
	if limit <= 0 {
		limit = defaultFindingsLimit
	}
	fetch := offset + limit + 1
	if fetch > maxCursorFetchLimit {
		return maxCursorFetchLimit
	}
	return fetch
}

func pageWithCursor[T any](items []T, offset int, limit int) ([]T, string) {
	if limit <= 0 {
		limit = defaultFindingsLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return []T{}, ""
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return items[offset:end], next
}

func paginatedItemsResponse[T any](items []T, offset int, limit int) gin.H {
	page, next := pageWithCursor(items, offset, limit)
	response := gin.H{"items": page}
	if next != "" {
		response["next_cursor"] = next
	}
	return response
}

func paginatedItemsResponseWithBaseOffset[T any](items []T, baseOffset int, limit int) gin.H {
	page, next := pageWithCursor(items, 0, limit)
	response := gin.H{"items": page}
	if next == "" {
		return response
	}
	nextPageOffset, err := strconv.Atoi(next)
	if err != nil {
		return response
	}
	response["next_cursor"] = strconv.Itoa(baseOffset + nextPageOffset)
	return response
}

func requestScopeMiddleware(defaultTenantID string, defaultWorkspaceID string, requireExplicitScope ...bool) gin.HandlerFunc {
	explicitScope := false
	if len(requireExplicitScope) > 0 {
		explicitScope = requireExplicitScope[0]
	}
	defaultScope := db.Scope{
		TenantID:    defaultTenantID,
		WorkspaceID: defaultWorkspaceID,
	}.Normalize()
	return func(c *gin.Context) {
		apiKeyAuth := authContextString(c, "auth.api_key") != ""
		tenantID := authContextString(c, "auth.tenant_id")
		workspaceID := authContextString(c, "auth.workspace_id")
		tenantHeader := strings.TrimSpace(c.GetHeader(scopeHeaderTenantID))
		workspaceHeader := strings.TrimSpace(c.GetHeader(scopeHeaderWorkspaceID))

		if apiKeyAuth {
			boundTenantID := authContextString(c, authAPIKeyTenantID)
			boundWorkspaceID := authContextString(c, authAPIKeyWorkspaceID)
			if boundTenantID != "" || boundWorkspaceID != "" {
				if tenantHeader != "" && (boundTenantID == "" || tenantHeader != boundTenantID) {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
					return
				}
				if workspaceHeader != "" && (boundWorkspaceID == "" || workspaceHeader != boundWorkspaceID) {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
					return
				}
				if tenantID == "" {
					tenantID = boundTenantID
				}
				if workspaceID == "" {
					workspaceID = boundWorkspaceID
				}
			}
		}
		if tenantID == "" && !apiKeyAuth {
			tenantID = tenantHeader
		}
		tenantProvided := tenantID != ""
		if tenantID == "" {
			tenantID = defaultScope.TenantID
		}
		if workspaceID == "" && !apiKeyAuth {
			workspaceID = workspaceHeader
		}
		workspaceProvided := workspaceID != ""
		if workspaceID == "" {
			workspaceID = defaultScope.WorkspaceID
		}
		if explicitScope && !isScopelessSessionRoute(c.FullPath()) && (!tenantProvided || !workspaceProvided) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "explicit tenant and workspace scope are required",
			})
			return
		}
		scopedCtx := db.WithScope(c.Request.Context(), db.Scope{
			TenantID:    tenantID,
			WorkspaceID: workspaceID,
		})
		c.Request = c.Request.WithContext(scopedCtx)
		c.Next()
	}
}

func isScopelessSessionRoute(path string) bool {
	switch path {
	case "/v1/me",
		"/v1/me/sessions",
		"/v1/me/sessions/:session_id",
		"/v1/me/sessions/revoke-others",
		"/v1/onboarding/start",
		"/v1/onboarding/state",
		"/v1/onboarding/complete":
		return true
	default:
		return false
	}
}

func jsonBodyLimitMiddleware(limit int64) gin.HandlerFunc {
	if limit <= 0 {
		limit = defaultJSONBodyLimit
	}
	return func(c *gin.Context) {
		if c.Request == nil || c.Request.Body == nil {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
		default:
			c.Next()
			return
		}
		if c.Request.ContentLength < 0 {
			limited := http.MaxBytesReader(c.Writer, c.Request.Body, limit)
			body, err := io.ReadAll(limited)
			if err != nil {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
					return
				}
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
			c.Request.ContentLength = int64(len(body))
			c.Next()
			return
		}
		if c.Request.ContentLength > limit {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowAll := false
	allowed := map[string]struct{}{}
	for _, origin := range allowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		if trimmed == "*" {
			allowAll = true
			continue
		}
		allowed[trimmed] = struct{}{}
	}

	if !allowAll && len(allowed) == 0 {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin == "" {
			c.Next()
			return
		}

		allowedOrigin := ""
		if allowAll {
			allowedOrigin = "*"
		} else if _, ok := allowed[origin]; ok {
			allowedOrigin = origin
		}
		if allowedOrigin == "" {
			c.Next()
			return
		}

		addVaryHeader(c.Writer.Header(), "Origin")
		c.Header("Access-Control-Allow-Origin", allowedOrigin)
		c.Header("Access-Control-Allow-Methods", corsAllowMethods)
		c.Header("Access-Control-Allow-Headers", corsAllowHeaders)
		c.Header("Access-Control-Max-Age", corsMaxAgeSeconds)
		if allowedOrigin != "*" {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if c.Request.Method == http.MethodOptions && strings.TrimSpace(c.GetHeader("Access-Control-Request-Method")) != "" {
			addVaryHeader(c.Writer.Header(), "Access-Control-Request-Method")
			addVaryHeader(c.Writer.Header(), "Access-Control-Request-Headers")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func addVaryHeader(headers http.Header, value string) {
	if headers == nil {
		return
	}
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return
	}
	for _, existing := range strings.Split(headers.Get("Vary"), ",") {
		if strings.EqualFold(strings.TrimSpace(existing), normalized) {
			return
		}
	}
	current := strings.TrimSpace(headers.Get("Vary"))
	if current == "" {
		headers.Set("Vary", normalized)
		return
	}
	headers.Set("Vary", current+", "+normalized)
}

func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		c.Next()
	}
}

func tracingMiddleware() gin.HandlerFunc {
	tracer := otel.Tracer("identrail/api")
	return func(c *gin.Context) {
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))
		spanName := c.Request.Method
		if route := c.FullPath(); route != "" {
			spanName = c.Request.Method + " " + route
		}
		ctx, span := tracer.Start(ctx, spanName)
		c.Request = c.Request.WithContext(ctx)
		defer func() {
			status := c.Writer.Status()
			route := c.FullPath()
			if route == "" {
				route = c.Request.URL.Path
			}
			span.SetAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.route", route),
				attribute.Int("http.status_code", status),
			)
			if status >= http.StatusInternalServerError {
				span.SetStatus(codes.Error, http.StatusText(status))
			}
			span.End()
		}()
		c.Next()
	}
}

func apiKeyAuthMiddleware(
	keys []string,
	scopedKeys map[string][]string,
	scopedKeyBindings map[string]db.Scope,
	tokenVerifier TokenVerifier,
	oidcWriteScopes []string,
	sink audit.AuditSink,
	fingerprinter *audit.Fingerprinter,
	logger *zap.Logger,
	requireAuth bool,
) gin.HandlerFunc {
	oidcWriteScopeSet := newScopeSet(oidcWriteScopes)
	if sink == nil {
		sink = audit.NopAuditSink{}
	}

	scopedAllowed := map[string]scopedAPIKeyAuthConfig{}
	for key, scopes := range scopedKeys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		scopedAllowed[trimmed] = parseScopedAPIKeyAuthConfig(scopes)
	}
	normalizedScopedBindings := map[string]db.Scope{}
	for key, scope := range scopedKeyBindings {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		normalized := scope.Normalize()
		if normalized.TenantID == "" || normalized.WorkspaceID == "" {
			continue
		}
		normalizedScopedBindings[trimmed] = normalized
	}

	// Scoped keys are the source of truth when configured.
	legacyAllowed := []string{}
	if len(scopedAllowed) == 0 {
		for _, key := range keys {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" {
				continue
			}
			legacyAllowed = append(legacyAllowed, trimmed)
		}
	}

	if len(scopedAllowed) == 0 && len(legacyAllowed) == 0 && tokenVerifier == nil && !requireAuth {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		if _, exists := c.Get("auth.session"); exists {
			setAuditActorOnRequestContext(c, fingerprinter)
			c.Next()
			return
		}

		if candidate := readAPIKey(c); candidate != "" {
			if config, ok := scopedKeyLookup(scopedAllowed, candidate); ok {
				if binding, hasBinding := scopedKeyBindingLookup(normalizedScopedBindings, candidate); hasBinding {
					if !applyScopedKeyBinding(c, binding, config.TenantID, config.WorkspaceID) {
						recordAuthenticationFailure(c, sink, fingerprinter, logger)
						c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
						return
					}
				} else if len(normalizedScopedBindings) > 0 {
					recordAuthenticationFailure(c, sink, fingerprinter, logger)
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
					return
				} else if config.TenantID != "" || config.WorkspaceID != "" {
					if !applyScopedKeyBinding(
						c,
						db.Scope{
							TenantID:    config.TenantID,
							WorkspaceID: config.WorkspaceID,
						},
						"",
						"",
					) {
						recordAuthenticationFailure(c, sink, fingerprinter, logger)
						c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
						return
					}
				}
				c.Set("auth.api_key", candidate)
				c.Set("auth.scope_set", config.Scopes)
				setAuditActorOnRequestContext(c, fingerprinter)
				c.Next()
				return
			}
			if keyInList(legacyAllowed, candidate) {
				c.Set("auth.api_key", candidate)
				setAuditActorOnRequestContext(c, fingerprinter)
				c.Next()
				return
			}
		}

		rawBearer := readBearerToken(c)
		if tokenVerifier != nil && rawBearer != "" {
			token, err := tokenVerifier.VerifyToken(c.Request.Context(), rawBearer)
			if err == nil {
				c.Set("auth.subject", token.Subject)
				c.Set("auth.issuer", token.Issuer)
				c.Set("auth.audiences", token.Audiences)
				c.Set("auth.groups", token.Groups)
				c.Set("auth.roles", token.Roles)
				c.Set("auth.tenant_id", token.TenantID)
				c.Set("auth.workspace_id", token.WorkspaceID)
				c.Set("auth.scope_set", scopeSetFromOIDCToken(token, oidcWriteScopeSet))
				setAuditActorOnRequestContext(c, fingerprinter)
				c.Next()
				return
			}
			recordAuthenticationFailure(c, sink, fingerprinter, logger)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		recordAuthenticationFailure(c, sink, fingerprinter, logger)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func recordAuthenticationFailure(c *gin.Context, sink audit.AuditSink, fingerprinter *audit.Fingerprinter, logger *zap.Logger) {
	if c == nil || sink == nil {
		return
	}
	ctx := context.Background()
	if c.Request != nil {
		ctx = c.Request.Context()
	}
	ctx, correlationID := audit.EnsureCorrelationID(ctx)
	if c.Request != nil {
		c.Request = c.Request.WithContext(ctx)
	}
	event := audit.AuditEvent{
		Timestamp:     time.Now().UTC(),
		Kind:          "api_auth_failure",
		Method:        c.Request.Method,
		Path:          c.Request.URL.Path,
		Status:        http.StatusUnauthorized,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		Actor:         "unknown",
		Outcome:       "denied",
		Error:         "unauthorized",
		CorrelationID: correlationID,
	}
	if apiKey := readAPIKey(c); apiKey != "" {
		event.APIKeyID = fingerprintAPIKeyWith(fingerprinter, apiKey)
	}
	if err := sink.Write(ctx, event); err != nil && logger != nil {
		logger.Warn("auth failure audit sink write failed", telemetry.ZapError(err))
	}
}

func apiDenialMetricsMiddleware(metrics *telemetry.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if metrics == nil || metrics.APIDeniedRequestsTotal == nil {
			return
		}
		switch c.Writer.Status() {
		case http.StatusUnauthorized:
			metrics.APIDeniedRequestsTotal.WithLabelValues("unauthorized", "auth").Inc()
		case http.StatusForbidden:
			metrics.APIDeniedRequestsTotal.WithLabelValues("forbidden", "authz").Inc()
		case http.StatusTooManyRequests:
			metrics.APIDeniedRequestsTotal.WithLabelValues("rate_limited", "rate_limit").Inc()
		case http.StatusBadRequest:
			metrics.APIDeniedRequestsTotal.WithLabelValues("validation_denied", "validation").Inc()
		}
	}
}

func keyInList(keys []string, candidate string) bool {
	for _, key := range keys {
		if secureKeyEquals(key, candidate) {
			return true
		}
	}
	return false
}

func scopedKeyBindingLookup(bindings map[string]db.Scope, candidate string) (db.Scope, bool) {
	for key, binding := range bindings {
		if secureKeyEquals(key, candidate) {
			return binding, true
		}
	}
	return db.Scope{}, false
}

func applyScopedKeyBinding(c *gin.Context, binding db.Scope, tenantID string, workspaceID string) bool {
	normalizedBinding := binding.Normalize()
	normalizedBinding.TenantID = strings.TrimSpace(normalizedBinding.TenantID)
	normalizedBinding.WorkspaceID = strings.TrimSpace(normalizedBinding.WorkspaceID)
	if normalizedBinding.TenantID == "" {
		normalizedBinding.TenantID = strings.TrimSpace(tenantID)
	}
	if normalizedBinding.WorkspaceID == "" {
		normalizedBinding.WorkspaceID = strings.TrimSpace(workspaceID)
	}
	if normalizedBinding.TenantID == "" || normalizedBinding.WorkspaceID == "" {
		return false
	}
	tenantIDHeader := strings.TrimSpace(c.GetHeader(scopeHeaderTenantID))
	if tenantIDHeader != "" && tenantIDHeader != normalizedBinding.TenantID {
		return false
	}
	workspaceIDHeader := strings.TrimSpace(c.GetHeader(scopeHeaderWorkspaceID))
	if workspaceIDHeader != "" && workspaceIDHeader != normalizedBinding.WorkspaceID {
		return false
	}
	c.Set(authAPIKeyTenantID, normalizedBinding.TenantID)
	c.Set(authAPIKeyWorkspaceID, normalizedBinding.WorkspaceID)
	c.Set("auth.tenant_id", normalizedBinding.TenantID)
	c.Set("auth.workspace_id", normalizedBinding.WorkspaceID)
	return true
}

func parseScopedAPIKeyAuthConfig(scopes []string) scopedAPIKeyAuthConfig {
	config := scopedAPIKeyAuthConfig{Scopes: scopeSet{}}
	for _, rawScope := range scopes {
		trimmed := strings.TrimSpace(rawScope)
		if trimmed == "" {
			continue
		}
		normalized := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(normalized, apiKeyScopeTenant):
			config.TenantID = strings.TrimSpace(trimmed[len(apiKeyScopeTenant):])
		case strings.HasPrefix(normalized, apiKeyScopeWorkspace):
			config.WorkspaceID = strings.TrimSpace(trimmed[len(apiKeyScopeWorkspace):])
		default:
			config.Scopes[normalized] = struct{}{}
		}
	}
	return config
}

func scopedKeyLookup(scoped map[string]scopedAPIKeyAuthConfig, candidate string) (scopedAPIKeyAuthConfig, bool) {
	for key, config := range scoped {
		if secureKeyEquals(key, candidate) {
			return config, true
		}
	}
	return scopedAPIKeyAuthConfig{}, false
}

func secureKeyEquals(expected string, candidate string) bool {
	if len(expected) != len(candidate) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(candidate)) == 1
}

type ipRateLimiter struct {
	mu           sync.Mutex
	limiters     map[string]ipLimiterEntry
	rate         rate.Limit
	burst        int
	now          func() time.Time
	entryTTL     time.Duration
	maxEntries   int
	cleanupEvery uint64
	allowCount   uint64
}

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(rpm int, burst int) *ipRateLimiter {
	return newIPRateLimiterWithClock(rpm, burst, time.Now, rateLimiterEntryTTL, rateLimiterMaxEntries, rateLimiterCleanupTick)
}

func newIPRateLimiterWithClock(
	rpm int,
	burst int,
	now func() time.Time,
	entryTTL time.Duration,
	maxEntries int,
	cleanupEvery uint64,
) *ipRateLimiter {
	if rpm <= 0 {
		rpm = 120
	}
	if burst <= 0 {
		burst = 20
	}
	if now == nil {
		now = time.Now
	}
	if entryTTL <= 0 {
		entryTTL = rateLimiterEntryTTL
	}
	if maxEntries <= 0 {
		maxEntries = rateLimiterMaxEntries
	}
	if cleanupEvery == 0 {
		cleanupEvery = rateLimiterCleanupTick
	}
	return &ipRateLimiter{
		limiters:     map[string]ipLimiterEntry{},
		rate:         rate.Every(time.Minute / time.Duration(rpm)),
		burst:        burst,
		now:          now,
		entryTTL:     entryTTL,
		maxEntries:   maxEntries,
		cleanupEvery: cleanupEvery,
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.allowCount++
	if l.cleanupEvery > 0 && l.allowCount%l.cleanupEvery == 0 {
		l.evictExpiredLocked(now)
	}

	entry, ok := l.limiters[ip]
	if !ok {
		if len(l.limiters) >= l.maxEntries {
			l.evictExpiredLocked(now)
		}
		if len(l.limiters) >= l.maxEntries {
			l.evictOldestLocked()
		}
		entry = ipLimiterEntry{
			limiter:  rate.NewLimiter(l.rate, l.burst),
			lastSeen: now,
		}
		l.limiters[ip] = entry
	} else {
		entry.lastSeen = now
		l.limiters[ip] = entry
	}
	return entry.limiter.Allow()
}

func (l *ipRateLimiter) evictExpiredLocked(now time.Time) {
	if len(l.limiters) == 0 {
		return
	}
	cutoff := now.Add(-l.entryTTL)
	for ip, entry := range l.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(l.limiters, ip)
		}
	}
}

func (l *ipRateLimiter) evictOldestLocked() {
	if len(l.limiters) == 0 {
		return
	}
	var oldestIP string
	var oldestTime time.Time
	for ip, entry := range l.limiters {
		if oldestIP == "" || entry.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = entry.lastSeen
		}
	}
	if oldestIP != "" {
		delete(l.limiters, oldestIP)
	}
}

func rateLimitMiddleware(rpm int, burst int) gin.HandlerFunc {
	limiter := newIPRateLimiter(rpm, burst)
	return func(c *gin.Context) {
		if !limiter.allow(rateLimitKey(c)) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

func rateLimitKey(c *gin.Context) string {
	ip := "unknown"
	if c != nil {
		if clientIP := strings.TrimSpace(c.ClientIP()); clientIP != "" {
			ip = clientIP
		}
	}
	if c == nil {
		return ip + "|anon"
	}
	if apiKey := readAPIKey(c); apiKey != "" {
		return ip + "|api"
	}
	if bearer := readBearerToken(c); bearer != "" {
		if isKubernetesAgentHeartbeatRequest(c) {
			return ip + "|k8s-heartbeat|" + shortRateLimitCredentialHash(bearer)
		}
		return ip + "|bearer"
	}
	return ip + "|anon"
}

func isKubernetesAgentHeartbeatRequest(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	if c.Request.Method != http.MethodPost {
		return false
	}
	if c.FullPath() == "/v1/connectors/k8s/heartbeat" {
		return true
	}
	return c.Request.URL != nil && c.Request.URL.Path == "/v1/connectors/k8s/heartbeat"
}

func shortRateLimitCredentialHash(credential string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(credential)))
	return hex.EncodeToString(sum[:8])
}

func requireMetricsScopeMiddleware(writeKeys []string, scopedKeys map[string][]string) gin.HandlerFunc {
	normalizedWriteKeys := normalizeKeyList(writeKeys)
	return func(c *gin.Context) {
		roles := policyRolesFromAuth(c, normalizedWriteKeys, scopedKeys)
		allowed := false
		for _, role := range roles {
			if role == scopeWrite || role == scopeAdmin {
				allowed = true
				break
			}
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func auditLogMiddleware(logger *zap.Logger, sink audit.AuditSink, fingerprinter *audit.Fingerprinter) gin.HandlerFunc {
	if sink == nil {
		sink = audit.NopAuditSink{}
	}
	return func(c *gin.Context) {
		ctx := audit.WithSink(c.Request.Context(), sink)
		ctx = audit.WithFingerprinter(ctx, fingerprinter)

		// Prefer upstream request IDs when present, otherwise generate a new ID.
		if headerID := strings.TrimSpace(c.GetHeader("X-Request-Id")); headerID != "" {
			ctx = audit.WithCorrelationID(ctx, headerID)
		}
		ctx, correlationID := audit.EnsureCorrelationID(ctx)
		c.Request = c.Request.WithContext(ctx)
		c.Writer.Header().Set("X-Request-Id", correlationID)

		start := time.Now()
		c.Next()
		actor := triageActorFromContext(c, fingerprinter)
		if actor != "" {
			ctx = audit.WithActor(c.Request.Context(), actor)
			c.Request = c.Request.WithContext(ctx)
		}
		event := audit.AuditEvent{
			Timestamp:  time.Now().UTC(),
			Kind:       "api_request",
			Component:  "api",
			Category:   "request",
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			Status:     c.Writer.Status(),
			ClientIP:   c.ClientIP(),
			DurationMS: time.Since(start).Milliseconds(),
			UserAgent:  c.Request.UserAgent(),
			Actor:      actor,
			// CorrelationID is used by action-level audit events as well.
			CorrelationID: correlationID,
		}
		if apiKeyValue, exists := c.Get("auth.api_key"); exists {
			if apiKey, ok := apiKeyValue.(string); ok {
				event.APIKeyID = fingerprintAPIKeyWith(fingerprinter, apiKey)
			}
		}
		if authzDecision, exists := c.Get("authz.audit_decision"); exists {
			switch typed := authzDecision.(type) {
			case audit.AuditAuthzDecision:
				decision := typed
				event.Authz = &decision
			case *audit.AuditAuthzDecision:
				if typed != nil {
					decision := *typed
					event.Authz = &decision
				}
			}
		}
		logger.Info(
			"api request",
			telemetry.StandardLogFields("api", "api_request",
				zap.String("request_id", event.CorrelationID),
				zap.String("method", event.Method),
				zap.String("path", event.Path),
				zap.Int("status", event.Status),
				zap.String("client_ip", event.ClientIP),
				zap.Int64("duration_ms", event.DurationMS),
				zap.String("user_agent", event.UserAgent),
				zap.String("actor", event.Actor),
			)...,
		)
		if event.Status == http.StatusUnauthorized || event.Status == http.StatusForbidden {
			logger.Warn(
				"security-sensitive request denied",
				zap.String("method", event.Method),
				zap.String("path", event.Path),
				zap.Int("status", event.Status),
				zap.String("actor", event.Actor),
				zap.String("correlation_id", event.CorrelationID),
			)
		}
		if err := sink.Write(c.Request.Context(), audit.NormalizeEvent(c.Request.Context(), event)); err != nil {
			logger.Warn("audit sink write failed", telemetry.ZapError(err))
		}
	}
}

func setAuditActorOnRequestContext(c *gin.Context, fingerprinter *audit.Fingerprinter) {
	if c == nil || c.Request == nil {
		return
	}
	actor := actionAuditActorFromContext(c, fingerprinter)
	if actor == "unknown" {
		return
	}
	c.Request = c.Request.WithContext(audit.WithActor(c.Request.Context(), actor))
}

func actionAuditActorFromContext(c *gin.Context, fingerprinter *audit.Fingerprinter) string {
	if c == nil {
		return "unknown"
	}
	if subjectValue, exists := c.Get("auth.subject"); exists {
		if subject, ok := subjectValue.(string); ok {
			normalizedSubject := strings.TrimSpace(subject)
			if normalizedSubject != "" {
				// Keep request-scoped OIDC subjects raw here so WriteAction can apply
				// exactly one fingerprint pass and preserve cross-event correlation.
				return "subject:" + normalizedSubject
			}
		}
	}
	if apiKeyValue, exists := c.Get("auth.api_key"); exists {
		if apiKey, ok := apiKeyValue.(string); ok {
			normalizedKey := strings.TrimSpace(apiKey)
			if normalizedKey != "" {
				return "api_key:" + fingerprintAPIKeyWith(fingerprinter, normalizedKey)
			}
		}
	}
	return "unknown"
}

func requestErrorLogFields(c *gin.Context, fingerprinter *audit.Fingerprinter, operation string, fields ...zap.Field) []zap.Field {
	base := []zap.Field{
		zap.String("component", "api"),
		zap.String("operation", operation),
	}
	if c == nil {
		return append(base, fields...)
	}
	scope := db.ScopeFromContext(c.Request.Context())
	requestID := ""
	if id, ok := audit.CorrelationIDFromContext(c.Request.Context()); ok {
		requestID = id
	}
	base = append(base,
		zap.String("request_id", requestID),
		zap.String("method", c.Request.Method),
		zap.String("path", c.Request.URL.Path),
		zap.String("route", c.FullPath()),
		zap.String("tenant_id", scope.TenantID),
		zap.String("workspace_id", scope.WorkspaceID),
		zap.String("actor", triageActorFromContext(c, fingerprinter)),
	)
	return append(base, fields...)
}

func readAPIKey(c *gin.Context) string {
	return strings.TrimSpace(c.GetHeader("X-API-Key"))
}

func authContextString(c *gin.Context, key string) string {
	if c == nil {
		return ""
	}
	value, exists := c.Get(key)
	if !exists {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func authContextStringSlice(c *gin.Context, key string) []string {
	if c == nil {
		return nil
	}
	value, exists := c.Get(key)
	if !exists {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return normalizeStringList(typed)
	case []any:
		raw := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				continue
			}
			raw = append(raw, text)
		}
		return normalizeStringList(raw)
	default:
		return nil
	}
}

func authContextScopes(c *gin.Context) []string {
	if c == nil {
		return nil
	}
	value, exists := c.Get("auth.scope_set")
	if !exists {
		return nil
	}
	scopes, ok := value.(scopeSet)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(scopes))
	for scope := range scopes {
		normalized := strings.TrimSpace(scope)
		if normalized == "" {
			continue
		}
		values = append(values, normalized)
	}
	sort.Strings(values)
	return values
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
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
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func triageActorFromContext(c *gin.Context, fingerprinter *audit.Fingerprinter) string {
	if c == nil {
		return "unknown"
	}
	if subjectValue, exists := c.Get("auth.subject"); exists {
		if subject, ok := subjectValue.(string); ok {
			normalizedSubject := strings.TrimSpace(subject)
			if normalizedSubject != "" {
				return "subject:" + fingerprintIdentifierWith(fingerprinter, normalizedSubject)
			}
		}
	}
	if apiKeyValue, exists := c.Get("auth.api_key"); exists {
		if apiKey, ok := apiKeyValue.(string); ok {
			normalizedKey := strings.TrimSpace(apiKey)
			if normalizedKey != "" {
				return "api_key:" + fingerprintAPIKeyWith(fingerprinter, normalizedKey)
			}
		}
	}
	return "unknown"
}

func fingerprintAPIKeyWith(fingerprinter *audit.Fingerprinter, raw string) string {
	if fingerprinter != nil {
		return fingerprinter.APIKey(raw)
	}
	return audit.FingerprintAPIKey(raw)
}

func fingerprintIdentifierWith(fingerprinter *audit.Fingerprinter, raw string) string {
	if fingerprinter != nil {
		return fingerprinter.Identifier(raw)
	}
	return audit.FingerprintIdentifier(raw)
}

func readBearerToken(c *gin.Context) string {
	authz := strings.TrimSpace(c.GetHeader("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

type scopeSet map[string]struct{}

func newScopeSet(scopes []string) scopeSet {
	set := scopeSet{}
	for _, raw := range scopes {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}

func (s scopeSet) has(required string) bool {
	if len(s) == 0 {
		return false
	}
	if _, ok := s[scopeAdmin]; ok {
		return true
	}
	if required == scopeRead {
		if _, ok := s[scopeWrite]; ok {
			return true
		}
	}
	_, ok := s[required]
	return ok
}

func scopeSetFromOIDCToken(token VerifiedToken, writeScopeOverrides scopeSet) scopeSet {
	set := scopeSet{}
	for _, scope := range token.Scopes {
		normalized := strings.ToLower(strings.TrimSpace(scope))
		if normalized == "" {
			continue
		}
		switch normalized {
		case scopeAdmin, "identrail.admin":
			set[scopeAdmin] = struct{}{}
			set[scopeWrite] = struct{}{}
			set[scopeRead] = struct{}{}
		case scopeWrite, "identrail.write":
			set[scopeWrite] = struct{}{}
		case scopeRead, "identrail.read":
			set[scopeRead] = struct{}{}
		}
		if _, ok := writeScopeOverrides[normalized]; ok {
			set[scopeWrite] = struct{}{}
		}
	}
	return set
}
