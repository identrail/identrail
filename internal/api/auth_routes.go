package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/workos/workos-go/v6/pkg/webhooks"
	"go.uber.org/zap"
)

type authSessionRouteOptions struct {
	AuditSink           audit.AuditSink
	AuditFingerprinter  *audit.Fingerprinter
	ManualMode          bool
	WorkOSEnabled       bool
	WorkOSClientID      string
	WorkOSClient        sessionauth.WorkOSClient
	WorkOSWebhookSecret string
	StateManager        *sessionauth.OAuthStateManager
	PublicBaseURL       string
	ReturnToOrigins     []string
}

func registerAuthSessionRoutes(r *gin.Engine, logger *zap.Logger, svc *Service, manager sessionauth.Manager, opts authSessionRouteOptions) {
	authGroup := r.Group("/auth")
	authGroup.Use(auditLogMiddleware(logger, opts.AuditSink, opts.AuditFingerprinter))
	authGroup.Use(jsonBodyLimitMiddleware(defaultJSONBodyLimit))

	if opts.WorkOSEnabled {
		authGroup.GET("/login", rateLimitMiddleware(10, 10), workOSStartHandler(logger, svc, opts, "login"))
		authGroup.GET("/signup", rateLimitMiddleware(10, 10), workOSStartHandler(logger, svc, opts, "signup"))
		authGroup.GET("/callback", rateLimitMiddleware(30, 30), workOSCallbackHandler(logger, svc, manager, opts))
		authGroup.POST("/webhooks/workos", rateLimitMiddleware(60, 60), workOSWebhookHandler(logger, svc, opts))
	}
	if opts.ManualMode {
		authGroup.POST("/manual", rateLimitMiddleware(10, 10), manualLoginHandler(logger, svc, manager))
	}

	authGroup.POST("/logout", rateLimitMiddleware(100, 100), manager.Middleware(), func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if svc == nil || svc.Store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service unavailable"})
			return
		}
		now := time.Now().UTC()
		if svc.Now != nil {
			now = svc.Now().UTC()
		}
		if _, err := svc.Store.RevokeUserSession(c.Request.Context(), current.Session.UserID, current.IDHash, now); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			if logger != nil {
				logger.Error("logout session", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to log out"})
			return
		}
		auditAuthAction(c.Request.Context(), "auth.logout", current.Session.UserID, "success")
		http.SetCookie(c.Writer, manager.ClearCookie())
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}

func registerAuthConfigRoute(v1 *gin.RouterGroup, manualMode bool, workOSEnabled bool) {
	v1.GET("/auth/config", func(c *gin.Context) {
		providers := []string{}
		if workOSEnabled {
			providers = append(providers, "github_oauth", "google_oauth", "authkit")
		}
		c.JSON(http.StatusOK, gin.H{
			"auth": gin.H{
				"manual_mode":          manualMode,
				"workos_login_enabled": workOSEnabled,
				"providers":            providers,
			},
		})
	})
}

func workOSStartHandler(logger *zap.Logger, svc *Service, opts authSessionRouteOptions, intent string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil || opts.WorkOSClient == nil || opts.StateManager == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth service unavailable"})
			return
		}
		returnTo := sanitizeAuthReturnTo(c.Query("return_to"), opts.ReturnToOrigins)
		state, err := opts.StateManager.Issue(intent, returnTo)
		if err != nil {
			if logger != nil {
				logger.Error("issue workos state", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start login"})
			return
		}
		screenHint := ""
		action := "auth.login.start"
		if intent == "signup" {
			screenHint = "sign-up"
			action = "auth.signup"
		}
		auditAuthAction(c.Request.Context(), action, "", "success")
		authorizationURL, err := opts.WorkOSClient.AuthorizationURL(sessionauth.WorkOSAuthorizationRequest{
			RedirectURI: workOSCallbackURL(opts.PublicBaseURL),
			State:       state,
			ScreenHint:  screenHint,
		})
		if err != nil {
			auditAuthAction(c.Request.Context(), "auth.login.failure", "", "denied")
			if logger != nil {
				logger.Warn("create workos authorization url", telemetry.ZapError(err))
			}
			c.Header("Retry-After", "30")
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth provider unavailable"})
			return
		}
		c.Redirect(http.StatusFound, authorizationURL)
	}
}

func workOSCallbackHandler(logger *zap.Logger, svc *Service, manager sessionauth.Manager, opts authSessionRouteOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil || svc.Store == nil || opts.WorkOSClient == nil || opts.StateManager == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth service unavailable"})
			return
		}
		code := strings.TrimSpace(c.Query("code"))
		if code == "" {
			auditAuthAction(c.Request.Context(), "auth.login.failure", "", "denied")
			c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
			return
		}
		state, err := opts.StateManager.Consume(c.Query("state"))
		if err != nil {
			auditAuthAction(c.Request.Context(), "auth.login.failure", "", "denied")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
			return
		}
		authenticated, err := opts.WorkOSClient.AuthenticateWithCode(c.Request.Context(), sessionauth.WorkOSAuthenticationRequest{
			Code:      code,
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		if err != nil {
			auditAuthAction(c.Request.Context(), "auth.login.failure", "", "denied")
			if errors.Is(err, sessionauth.ErrWorkOSUnavailable) {
				c.Header("Retry-After", "30")
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth provider unavailable"})
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "login failed"})
			return
		}
		profile := authenticated.User
		if strings.TrimSpace(profile.OrganizationID) == "" {
			profile.OrganizationID = authenticated.OrganizationID
		}
		result, err := svc.UpsertWorkOSUser(c.Request.Context(), profile)
		if err != nil {
			if errors.Is(err, ErrAuthIdentityConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "identity conflict"})
				return
			}
			if logger != nil {
				logger.Error("upsert workos user", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete login"})
			return
		}
		now := time.Now().UTC()
		if svc.Now != nil {
			now = svc.Now().UTC()
		}
		cookieValue, _, err := manager.CreateSession(c.Request.Context(), db.Session{
			UserID:             result.User.ID,
			CurrentOrgID:       result.CurrentOrgID,
			CurrentWorkspaceID: result.CurrentWorkspace,
			AuthMethod:         sessionauth.WorkOSProvider,
			IP:                 c.ClientIP(),
			UserAgent:          c.Request.UserAgent(),
			CreatedAt:          now,
			LastSeenAt:         now,
			IdleExpiresAt:      now.Add(sessionauth.IdleTimeout),
			AbsoluteExpiresAt:  now.Add(sessionauth.AbsoluteTimeout),
		})
		if err != nil {
			if logger != nil {
				logger.Error("create workos session", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
			return
		}
		auditAuthAction(c.Request.Context(), "auth.login.success", result.User.ID, "success")
		http.SetCookie(c.Writer, manager.Cookie(cookieValue))
		redirectTo := sanitizeAuthReturnTo(state.ReturnTo, opts.ReturnToOrigins)
		if redirectTo == "" || redirectTo == "/" {
			redirectTo = result.RedirectPath
		}
		c.Redirect(http.StatusFound, redirectTo)
	}
}

type manualLoginRequest struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

func manualLoginHandler(logger *zap.Logger, svc *Service, manager sessionauth.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil || svc.Store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth service unavailable"})
			return
		}
		var request manualLoginRequest
		if err := json.NewDecoder(c.Request.Body).Decode(&request); err != nil {
			auditAuthAction(c.Request.Context(), "auth.login.failure", "", "denied")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid manual login payload"})
			return
		}
		result, err := svc.UpsertManualUserSessionContext(c.Request.Context(), ManualLoginInput{
			TenantID:    request.TenantID,
			WorkspaceID: request.WorkspaceID,
			ProjectID:   request.ProjectID,
			Email:       request.Email,
			DisplayName: request.DisplayName,
		})
		if err != nil {
			auditAuthAction(c.Request.Context(), "auth.login.failure", "", "denied")
			if errors.Is(err, ErrAuthInvalidManualLogin) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id and workspace_id are required"})
				return
			}
			if errors.Is(err, ErrAuthIdentityConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "identity conflict"})
				return
			}
			if logger != nil {
				logger.Error("manual login", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete login"})
			return
		}
		now := time.Now().UTC()
		if svc.Now != nil {
			now = svc.Now().UTC()
		}
		cookieValue, _, err := manager.CreateSession(c.Request.Context(), db.Session{
			UserID:             result.User.ID,
			CurrentOrgID:       result.CurrentOrgID,
			CurrentWorkspaceID: result.CurrentWorkspaceID,
			CurrentProjectID:   result.CurrentProjectID,
			AuthMethod:         "manual",
			IP:                 c.ClientIP(),
			UserAgent:          c.Request.UserAgent(),
			CreatedAt:          now,
			LastSeenAt:         now,
			IdleExpiresAt:      now.Add(sessionauth.IdleTimeout),
			AbsoluteExpiresAt:  now.Add(sessionauth.AbsoluteTimeout),
		})
		if err != nil {
			if logger != nil {
				logger.Error("create manual session", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
			return
		}
		auditAuthAction(c.Request.Context(), "auth.login.success", result.User.ID, "success")
		http.SetCookie(c.Writer, manager.Cookie(cookieValue))
		c.JSON(http.StatusOK, gin.H{"ok": true, "redirect_to": result.RedirectPath})
	}
}

type workOSWebhookEvent struct {
	ID    string          `json:"id"`
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type workOSWebhookUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func workOSWebhookHandler(logger *zap.Logger, svc *Service, opts authSessionRouteOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil || svc.Store == nil || strings.TrimSpace(opts.WorkOSWebhookSecret) == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth service unavailable"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, defaultJSONBodyLimit)
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
			return
		}
		if _, err := webhooks.NewClient(opts.WorkOSWebhookSecret).ValidatePayload(c.GetHeader("WorkOS-Signature"), string(body)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid webhook signature"})
			return
		}
		var event workOSWebhookEvent
		if err := json.Unmarshal(body, &event); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
			return
		}
		var user workOSWebhookUser
		if len(event.Data) > 0 {
			_ = json.Unmarshal(event.Data, &user)
		}
		switch event.Event {
		case "user.deleted":
			if strings.TrimSpace(user.ID) == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
				return
			}
			revoked, err := svc.DeactivateWorkOSUser(c.Request.Context(), user.ID)
			if err != nil && !errors.Is(err, db.ErrNotFound) {
				if logger != nil {
					logger.Error("handle workos user deleted", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process webhook"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"ok": true, "revoked_sessions": revoked})
		case "user.email_changed", "user.updated":
			if strings.TrimSpace(user.ID) == "" || strings.TrimSpace(user.Email) == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
				return
			}
			if err := svc.UpdateWorkOSUserEmail(c.Request.Context(), user.ID, user.Email); err != nil && !errors.Is(err, db.ErrNotFound) {
				if errors.Is(err, ErrAuthIdentityConflict) {
					c.JSON(http.StatusConflict, gin.H{"error": "identity conflict"})
					return
				}
				if logger != nil {
					logger.Error("handle workos user email change", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process webhook"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"ok": true})
		default:
			c.JSON(http.StatusOK, gin.H{"ok": true, "ignored": true})
		}
	}
}

func workOSCallbackURL(publicBaseURL string) string {
	return strings.TrimRight(publicBaseURL, "/") + "/auth/callback"
}

func sanitizeAuthReturnTo(raw string, allowedOrigins []string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.IsAbs() || parsed.Host != "" {
		if !authReturnToOriginAllowed(parsed, allowedOrigins) {
			return ""
		}
		if parsed.Path == "" {
			parsed.Path = "/"
		}
		parsed.Fragment = ""
		if !authReturnToPathAllowed(parsed.Path) {
			return ""
		}
		return strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/") + parsed.RequestURI()
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return ""
	}
	if !authReturnToPathAllowed(parsed.Path) {
		return ""
	}
	return parsed.RequestURI()
}

func authReturnToPathAllowed(path string) bool {
	if strings.HasPrefix(path, "//") || strings.HasPrefix(path, "/auth/") {
		return false
	}
	return true
}

func authReturnToOriginAllowed(parsed *url.URL, allowedOrigins []string) bool {
	if parsed == nil {
		return false
	}
	origin, ok := authReturnToOrigin(parsed.String())
	if !ok {
		return false
	}
	for _, allowed := range allowedOrigins {
		allowedOrigin, allowedOK := authReturnToOrigin(allowed)
		if allowedOK && strings.EqualFold(origin, allowedOrigin) {
			return true
		}
	}
	return false
}

func authReturnToOrigins(publicBaseURL string, corsAllowedOrigins []string) []string {
	origins := make([]string, 0, len(corsAllowedOrigins)+1)
	if origin, ok := authReturnToOrigin(publicBaseURL); ok {
		origins = append(origins, origin)
	}
	for _, raw := range corsAllowedOrigins {
		if strings.TrimSpace(raw) == "*" {
			continue
		}
		if origin, ok := authReturnToOrigin(raw); ok {
			origins = append(origins, origin)
		}
	}
	return origins
}

func authReturnToOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", false
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host), true
}

func registerMeRoutes(v1 *gin.RouterGroup, logger *zap.Logger, svc *Service, manager sessionauth.Manager) {
	v1.GET("/me", func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		contextSnapshot, err := svc.GetCurrentUserContext(c.Request.Context(), current)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			if logger != nil {
				logger.Error("get current user", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get current user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"me": contextSnapshot})
	})

	v1.GET("/me/sessions", func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		sessions, err := svc.ListCurrentUserSessions(c.Request.Context(), current)
		if err != nil {
			if logger != nil {
				logger.Error("list current user sessions", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": sessions})
	})

	v1.DELETE("/me/sessions/:session_id", func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		targetHash, err := sessionauth.DecodePublicSessionID(c.Param("session_id"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
		now := time.Now().UTC()
		if svc.Now != nil {
			now = svc.Now().UTC()
		}
		revoked, err := svc.Store.RevokeUserSession(c.Request.Context(), current.Session.UserID, targetHash, now)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
				return
			}
			if logger != nil {
				logger.Error("revoke current user session", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
			return
		}
		if revoked.ID != nil && sessionauth.EncodePublicSessionID(revoked.ID) == sessionauth.EncodePublicSessionID(current.IDHash) {
			http.SetCookie(c.Writer, manager.ClearCookie())
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	v1.POST("/me/sessions/revoke-others", func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		now := time.Now().UTC()
		if svc.Now != nil {
			now = svc.Now().UTC()
		}
		count, err := svc.Store.RevokeOtherUserSessions(c.Request.Context(), current.Session.UserID, current.IDHash, now)
		if err != nil {
			if logger != nil {
				logger.Error("revoke other current user sessions", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke sessions"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"revoked": count})
	})
}
