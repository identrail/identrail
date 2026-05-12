package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func registerAuthSessionRoutes(r *gin.Engine, logger *zap.Logger, svc *Service, manager sessionauth.Manager) {
	authGroup := r.Group("/auth")
	authGroup.Use(auditLogMiddleware(logger, nil, nil))
	authGroup.Use(jsonBodyLimitMiddleware(defaultJSONBodyLimit))
	authGroup.Use(manager.Middleware())
	authGroup.POST("/logout", func(c *gin.Context) {
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
		http.SetCookie(c.Writer, manager.ClearCookie())
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
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
