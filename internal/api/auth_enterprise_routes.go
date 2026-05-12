package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func registerEnterpriseAuthPrepRoutes(v1 *gin.RouterGroup) {
	v1.POST("/invitations", enterpriseAuthPrepNotImplemented)
	v1.GET("/me/invitations", enterpriseAuthPrepNotImplemented)
	v1.POST("/orgs/:id/domains", enterpriseAuthPrepNotImplemented)
	v1.POST("/orgs/:id/domains/:domain_id/verify", enterpriseAuthPrepNotImplemented)
	v1.GET("/orgs/:id/sso", enterpriseAuthPrepNotImplemented)
}

func enterpriseAuthPrepNotImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}
