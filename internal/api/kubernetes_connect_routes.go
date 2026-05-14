package api

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	k8sconnector "github.com/identrail/identrail/internal/connectors/kubernetes"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func registerKubernetesConnectionRoutes(v1 *gin.RouterGroup, logger *zap.Logger, svc *Service, featureConnectorK8S bool, publicBaseURL string) {
	v1.POST("/connectors/k8s", func(c *gin.Context) {
		if !featureConnectorK8S {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request KubernetesConnectorStartRequest
		if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		if strings.TrimSpace(request.APIURL) == "" {
			request.APIURL = requestBaseURL(c, publicBaseURL)
		}
		response, err := svc.StartKubernetesConnector(c.Request.Context(), request)
		if err != nil {
			writeKubernetesConnectorError(c, logger, "start kubernetes connector", err)
			return
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/connectors/k8s", func(c *gin.Context) {
		if !featureConnectorK8S {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		record, err := svc.GetKubernetesConnectorStatus(c.Request.Context(), c.Query("workspace_id"), c.Query("project_id"))
		if err != nil {
			writeKubernetesConnectorError(c, logger, "get kubernetes connector", err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.POST("/connectors/k8s/kubeconfig", func(c *gin.Context) {
		if !featureConnectorK8S {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request KubernetesConnectorKubeconfigRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		record, err := svc.UpsertKubernetesKubeconfigConnector(c.Request.Context(), request)
		if err != nil {
			writeKubernetesConnectorError(c, logger, "save kubernetes kubeconfig connector", err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"connection": record})
	})

	v1.POST("/workspaces/:workspace_id/projects/:project_id/kubernetes/connection", func(c *gin.Context) {
		if !featureConnectorK8S {
			c.Status(http.StatusNotFound)
			return
		}
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
		if !featureConnectorK8S {
			c.Status(http.StatusNotFound)
			return
		}
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

func registerKubernetesAgentRoutes(publicV1 *gin.RouterGroup, logger *zap.Logger, svc *Service, featureConnectorK8S bool, publicBaseURL string) {
	publicV1.POST("/connectors/k8s/enroll", func(c *gin.Context) {
		if !featureConnectorK8S {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request k8sconnector.AgentEnrollRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.EnrollKubernetesAgent(c.Request.Context(), request, requestBaseURL(c, publicBaseURL))
		if err != nil {
			writeKubernetesAgentError(c, logger, "enroll kubernetes agent", err)
			return
		}
		c.JSON(http.StatusOK, response)
	})

	publicV1.POST("/connectors/k8s/heartbeat", func(c *gin.Context) {
		if !featureConnectorK8S {
			c.Status(http.StatusNotFound)
			return
		}
		if svc == nil {
			tenancyServiceUnavailable(c)
			return
		}
		var request k8sconnector.AgentHeartbeatRequest
		if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		response, err := svc.HeartbeatKubernetesAgent(c.Request.Context(), request, c.GetHeader("Authorization"))
		if err != nil {
			writeKubernetesAgentError(c, logger, "heartbeat kubernetes agent", err)
			return
		}
		c.JSON(http.StatusOK, response)
	})
}

func writeKubernetesConnectorError(c *gin.Context, logger *zap.Logger, operation string, err error) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "kubernetes connector not found"})
	case errors.Is(err, ErrInvalidKubernetesConnectionRequest):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid kubernetes connector request"})
	case errors.Is(err, ErrKubernetesConnectorSecretUnavailable):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "kubernetes connector secret manager unavailable"})
	default:
		if logger != nil {
			logger.Error(operation, telemetry.ZapError(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process kubernetes connector"})
	}
}

func writeKubernetesAgentError(c *gin.Context, logger *zap.Logger, operation string, err error) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "kubernetes connector not found"})
	case errors.Is(err, ErrKubernetesConnectorTokenInvalid), errors.Is(err, ErrKubernetesConnectorCredentialDenied):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid kubernetes connector credential"})
	case errors.Is(err, ErrKubernetesConnectorTokenExpired), errors.Is(err, ErrKubernetesConnectorTokenUsed):
		c.JSON(http.StatusGone, gin.H{"error": "kubernetes enrollment token is no longer usable"})
	default:
		if logger != nil {
			logger.Error(operation, telemetry.ZapError(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process kubernetes agent request"})
	}
}

func requestBaseURL(c *gin.Context, publicBaseURL string) string {
	if trimmed := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/"); trimmed != "" {
		return trimmed
	}
	scheme := "http"
	if forwardedProto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); strings.EqualFold(forwardedProto, "http") || strings.EqualFold(forwardedProto, "https") {
		scheme = strings.ToLower(forwardedProto)
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	if host := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); host != "" {
		return scheme + "://" + host
	}
	return scheme + "://" + c.Request.Host
}
