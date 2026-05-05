package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func registerKubernetesConnectionRoutes(v1 *gin.RouterGroup, logger *zap.Logger, svc *Service) {
	v1.POST("/workspaces/:workspace_id/projects/:project_id/kubernetes/connection", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request KubernetesConnectionUpsertRequest
		if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertKubernetesConnection(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"), request)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			case errors.Is(err, ErrInvalidKubernetesConnectionRequest):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid kubernetes connection request"})
			case errors.Is(err, ErrKubernetesPreflightUnavailable):
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "kubernetes preflight unavailable"})
			default:
				if logger != nil {
					logger.Error("upsert kubernetes connection", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate kubernetes connection"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.GET("/workspaces/:workspace_id/projects/:project_id/kubernetes/connection", func(c *gin.Context) {
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetKubernetesConnection(c.Request.Context(), c.Param("workspace_id"), c.Param("project_id"))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
				return
			}
			if logger != nil {
				logger.Error("get kubernetes connection", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes connection"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})
}
