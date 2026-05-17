package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func registerOnboardingRoutes(v1 *gin.RouterGroup, logger *zap.Logger, svc *Service, featureEnabled bool) {
	v1.POST("/onboarding/start", func(c *gin.Context) {
		current, ok := requireOnboardingSession(c)
		if !ok {
			return
		}
		if !requireOnboardingFeature(c, featureEnabled) || !requireOnboardingService(c, svc) {
			return
		}
		response, err := svc.StartOnboarding(c.Request.Context(), current)
		writeOnboardingResponse(c, logger, err, response, "start onboarding")
	})

	v1.GET("/onboarding/state", func(c *gin.Context) {
		current, ok := requireOnboardingSession(c)
		if !ok {
			return
		}
		if !requireOnboardingFeature(c, featureEnabled) || !requireOnboardingService(c, svc) {
			return
		}
		response, err := svc.GetOnboardingState(c.Request.Context(), current)
		writeOnboardingResponse(c, logger, err, response, "get onboarding state")
	})

	v1.POST("/onboarding/state", func(c *gin.Context) {
		current, ok := requireOnboardingSession(c)
		if !ok {
			return
		}
		if !requireOnboardingFeature(c, featureEnabled) || !requireOnboardingService(c, svc) {
			return
		}
		var request OnboardingStateUpdateRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.UpdateOnboardingState(c.Request.Context(), current, request)
		writeOnboardingResponse(c, logger, err, response, "update onboarding state")
	})

	v1.POST("/onboarding/complete", func(c *gin.Context) {
		current, ok := requireOnboardingSession(c)
		if !ok {
			return
		}
		if !requireOnboardingFeature(c, featureEnabled) || !requireOnboardingService(c, svc) {
			return
		}
		response, err := svc.CompleteOnboarding(c.Request.Context(), current)
		writeOnboardingResponse(c, logger, err, response, "complete onboarding")
	})
}

func requireOnboardingFeature(c *gin.Context, featureEnabled bool) bool {
	if !featureEnabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "onboarding disabled"})
		return false
	}
	return true
}

func requireOnboardingService(c *gin.Context, svc *Service) bool {
	if svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "onboarding service unavailable"})
		return false
	}
	return true
}

func requireOnboardingSession(c *gin.Context) (sessionauth.CurrentSession, bool) {
	current, ok := sessionauth.CurrentFromGin(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
		return sessionauth.CurrentSession{}, false
	}
	return current, true
}

func writeOnboardingResponse(c *gin.Context, logger *zap.Logger, err error, response OnboardingStateResponse, action string) {
	if err == nil {
		c.JSON(http.StatusOK, response)
		return
	}
	switch {
	case errors.Is(err, db.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "onboarding state not found"})
	case errors.Is(err, ErrInvalidOnboardingRequest):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid onboarding request"})
	case errors.Is(err, ErrOnboardingWorkspaceAccessDenied):
		c.JSON(http.StatusForbidden, gin.H{"error": "workspace access denied"})
	default:
		if logger != nil {
			logger.Error(action, telemetry.ZapError(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update onboarding"})
	}
}
