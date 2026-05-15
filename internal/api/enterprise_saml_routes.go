package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/enterprise"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

// nativeSAMLRouteOptions controls registration of the native SAML
// administration routes. Routes are gated behind the FeatureNativeSSO flag,
// defaulted off, so the new surface area is opt-in per deployment.
type nativeSAMLRouteOptions struct {
	Enabled        bool
	MetadataClient *enterpriseSAMLMetadataFetcher
}

// enterpriseSAMLMetadataFetcher abstracts the metadata fetch so tests can
// inject a fixture without going through the network.
type enterpriseSAMLMetadataFetcher struct {
	fetch func(ctx context.Context, url string) ([]byte, error)
}

func defaultEnterpriseSAMLMetadataFetcher() *enterpriseSAMLMetadataFetcher {
	return &enterpriseSAMLMetadataFetcher{
		fetch: func(ctx context.Context, url string) ([]byte, error) {
			return FetchSAMLMetadataXML(ctx, nil, url)
		},
	}
}

// samlConnectionRequest is the inbound shape for native SAML CRUD calls.
// Provider/Type/Status defaults and the SCIM bearer token are managed by the
// handler so the admin payload stays focused on connection-specific fields.
type samlConnectionRequest struct {
	Type                   string            `json:"type"`
	DisplayName            string            `json:"display_name,omitempty"`
	EntityID               string            `json:"entity_id"`
	SSOURL                 string            `json:"sso_url"`
	CertificatePEM         string            `json:"certificate_pem"`
	AttributeMapping       map[string]string `json:"attribute_mapping,omitempty"`
	JITProvisioningEnabled bool              `json:"jit_provisioning_enabled"`
	SSORequired            bool              `json:"sso_required"`
	GroupRoleMap           map[string]string `json:"group_role_map,omitempty"`
}

// samlConnectionResponse is the outbound shape, augmented with the one-time
// SCIM bearer token returned only on create.
type samlConnectionResponse struct {
	Connection      samlConnectionView `json:"connection"`
	SCIMBearerToken string             `json:"scim_bearer_token,omitempty"`
}

type samlConnectionView struct {
	ID                     string            `json:"id"`
	OrgID                  string            `json:"org_id"`
	Type                   string            `json:"type"`
	Status                 string            `json:"status"`
	EntityID               string            `json:"entity_id,omitempty"`
	SSOURL                 string            `json:"sso_url,omitempty"`
	CertificatePEM         string            `json:"certificate_pem,omitempty"`
	AttributeMapping       map[string]string `json:"attribute_mapping,omitempty"`
	GroupRoleMap           map[string]string `json:"group_role_map,omitempty"`
	JITProvisioningEnabled bool              `json:"jit_provisioning_enabled"`
	SSORequired            bool              `json:"sso_required"`
	HasSCIMBearerToken     bool              `json:"has_scim_bearer_token"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
}

func toSAMLConnectionView(c db.IdentityConnection) samlConnectionView {
	return samlConnectionView{
		ID:                     c.ID,
		OrgID:                  c.OrgID,
		Type:                   c.Type,
		Status:                 c.Status,
		EntityID:               c.EntityID,
		SSOURL:                 c.SSOURL,
		CertificatePEM:         c.CertificatePEM,
		AttributeMapping:       c.AttributeMapping,
		GroupRoleMap:           c.GroupRoleMap,
		JITProvisioningEnabled: c.JITProvisioningEnabled,
		SSORequired:            c.SSORequired,
		HasSCIMBearerToken:     c.SCIMBearerTokenHash != "",
		CreatedAt:              c.CreatedAt,
		UpdatedAt:              c.UpdatedAt,
	}
}

func registerNativeSAMLAdminRoutes(v1 *gin.RouterGroup, logger *zap.Logger, svc *Service, opts nativeSAMLRouteOptions) {
	if !opts.Enabled {
		return
	}
	if opts.MetadataClient == nil {
		opts.MetadataClient = defaultEnterpriseSAMLMetadataFetcher()
	}
	base := v1.Group("/enterprise/identity-connections/saml")
	base.POST("", createNativeSAMLConnection(logger, svc))
	base.GET("", listNativeSAMLConnections(logger, svc))
	base.GET("/:id", getNativeSAMLConnection(logger, svc))
	base.PUT("/:id", updateNativeSAMLConnection(logger, svc))
	base.DELETE("/:id", deleteNativeSAMLConnection(logger, svc))
	base.POST("/from-metadata", samlMetadataImport(logger, opts.MetadataClient))
}

func createNativeSAMLConnection(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := requireEnterpriseSession(c)
		if !ok {
			return
		}
		orgID := strings.TrimSpace(current.Session.CurrentOrgID)
		if orgID == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "org context required"})
			return
		}
		var req samlConnectionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		plain, hash, err := NewSCIMBearerToken()
		if err != nil {
			if logger != nil {
				logger.Error("generate scim bearer token", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue scim token"})
			return
		}

		connection := db.IdentityConnection{
			OrgID:                  orgID,
			Provider:               "saml",
			Type:                   defaultSAMLConnectionType(req.Type),
			Status:                 "pending",
			EntityID:               req.EntityID,
			SSOURL:                 req.SSOURL,
			CertificatePEM:         req.CertificatePEM,
			AttributeMapping:       req.AttributeMapping,
			GroupRoleMap:           req.GroupRoleMap,
			JITProvisioningEnabled: req.JITProvisioningEnabled,
			SSORequired:            req.SSORequired,
			SCIMBearerTokenHash:    hash,
		}
		// Defense in depth: also validate the SAML attribute mapping with the
		// enterprise package so the resulting connection is acceptable to the
		// PR-3 ACS handler. The CHECK constraint and Go normalizer in PR-1
		// guarantee structural completeness; this additional pass checks the
		// X.509 certificate parses and the email attribute mapping is set.
		if err := preflightNativeSAML(connection); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		saved, err := svc.Store.CreateIdentityConnection(c.Request.Context(), connection)
		if err != nil {
			writeIdentityConnectionError(c, logger, err, "create native saml connection")
			return
		}
		c.JSON(http.StatusCreated, samlConnectionResponse{
			Connection:      toSAMLConnectionView(saved),
			SCIMBearerToken: plain,
		})
	}
}

func listNativeSAMLConnections(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := requireEnterpriseSession(c)
		if !ok {
			return
		}
		orgID := strings.TrimSpace(current.Session.CurrentOrgID)
		if orgID == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "org context required"})
			return
		}
		raw, err := svc.Store.ListIdentityConnections(c.Request.Context(), orgID, 100)
		if err != nil {
			if logger != nil {
				logger.Error("list native saml connections", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list saml connections"})
			return
		}
		out := make([]samlConnectionView, 0, len(raw))
		for _, conn := range raw {
			if !conn.IsNativeSAML() {
				continue
			}
			out = append(out, toSAMLConnectionView(conn))
		}
		c.JSON(http.StatusOK, gin.H{"connections": out})
	}
}

func getNativeSAMLConnection(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := requireEnterpriseSession(c)
		if !ok {
			return
		}
		orgID := strings.TrimSpace(current.Session.CurrentOrgID)
		if orgID == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "org context required"})
			return
		}
		conn, err := svc.Store.GetIdentityConnection(c.Request.Context(), orgID, c.Param("id"))
		if err != nil {
			writeIdentityConnectionError(c, logger, err, "get native saml connection")
			return
		}
		if !conn.IsNativeSAML() {
			c.JSON(http.StatusNotFound, gin.H{"error": "native saml connection not found"})
			return
		}
		c.JSON(http.StatusOK, samlConnectionResponse{Connection: toSAMLConnectionView(conn)})
	}
}

func updateNativeSAMLConnection(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := requireEnterpriseSession(c)
		if !ok {
			return
		}
		orgID := strings.TrimSpace(current.Session.CurrentOrgID)
		if orgID == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "org context required"})
			return
		}
		existing, err := svc.Store.GetIdentityConnection(c.Request.Context(), orgID, c.Param("id"))
		if err != nil {
			writeIdentityConnectionError(c, logger, err, "load native saml connection for update")
			return
		}
		if !existing.IsNativeSAML() {
			c.JSON(http.StatusNotFound, gin.H{"error": "native saml connection not found"})
			return
		}
		var req samlConnectionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		updated := existing
		if req.Type != "" {
			updated.Type = defaultSAMLConnectionType(req.Type)
		}
		if req.EntityID != "" {
			updated.EntityID = req.EntityID
		}
		if req.SSOURL != "" {
			updated.SSOURL = req.SSOURL
		}
		if req.CertificatePEM != "" {
			updated.CertificatePEM = req.CertificatePEM
		}
		if len(req.AttributeMapping) > 0 {
			updated.AttributeMapping = req.AttributeMapping
		}
		if len(req.GroupRoleMap) > 0 {
			updated.GroupRoleMap = req.GroupRoleMap
		}
		updated.JITProvisioningEnabled = req.JITProvisioningEnabled
		updated.SSORequired = req.SSORequired
		updated.UpdatedAt = time.Now().UTC()

		if err := preflightNativeSAML(updated); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		saved, err := svc.Store.UpdateIdentityConnection(c.Request.Context(), updated)
		if err != nil {
			writeIdentityConnectionError(c, logger, err, "update native saml connection")
			return
		}
		c.JSON(http.StatusOK, samlConnectionResponse{Connection: toSAMLConnectionView(saved)})
	}
}

func deleteNativeSAMLConnection(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := requireEnterpriseSession(c)
		if !ok {
			return
		}
		orgID := strings.TrimSpace(current.Session.CurrentOrgID)
		if orgID == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "org context required"})
			return
		}
		existing, err := svc.Store.GetIdentityConnection(c.Request.Context(), orgID, c.Param("id"))
		if err != nil {
			writeIdentityConnectionError(c, logger, err, "load native saml connection for delete")
			return
		}
		if !existing.IsNativeSAML() {
			c.JSON(http.StatusNotFound, gin.H{"error": "native saml connection not found"})
			return
		}
		if err := svc.Store.DeleteIdentityConnection(c.Request.Context(), orgID, existing.ID); err != nil {
			writeIdentityConnectionError(c, logger, err, "delete native saml connection")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func samlMetadataImport(logger *zap.Logger, fetcher *enterpriseSAMLMetadataFetcher) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := requireEnterpriseSession(c)
		if !ok {
			return
		}
		if strings.TrimSpace(current.Session.CurrentOrgID) == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "org context required"})
			return
		}
		var req struct {
			MetadataURL string `json:"metadata_url,omitempty"`
			MetadataXML string `json:"metadata_xml,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		raw := []byte(strings.TrimSpace(req.MetadataXML))
		switch {
		case len(raw) > 0:
			// inline body, no fetch required
		case strings.TrimSpace(req.MetadataURL) != "":
			body, err := fetcher.fetch(c.Request.Context(), req.MetadataURL)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			raw = body
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "metadata_url or metadata_xml is required"})
			return
		}
		draft, err := ParseSAMLMetadataXML(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, draft)
	}
}

// --- helpers ---

func defaultSAMLConnectionType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "sso"
	}
	return value
}

func preflightNativeSAML(c db.IdentityConnection) error {
	// Parsing the certificate at admin time fails fast if the operator pasted
	// a malformed PEM, instead of waiting for the first ACS round-trip.
	if _, err := enterprise.ParseSAMLCertificate(c.CertificatePEM); err != nil {
		return err
	}
	if _, ok := c.AttributeMapping["email"]; !ok || strings.TrimSpace(c.AttributeMapping["email"]) == "" {
		return errMissingEmailAttributeMapping
	}
	return nil
}

var errMissingEmailAttributeMapping = errors.New("attribute_mapping.email is required")

func requireEnterpriseSession(c *gin.Context) (sessionauth.CurrentSession, bool) {
	current, ok := sessionauth.CurrentFromGin(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
		return sessionauth.CurrentSession{}, false
	}
	return current, true
}

func writeIdentityConnectionError(c *gin.Context, logger *zap.Logger, err error, action string) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "identity connection not found"})
	case errors.Is(err, db.ErrConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "identity connection conflict"})
	case isClientValidationError(err):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		if logger != nil {
			logger.Error(action, telemetry.ZapError(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "identity connection operation failed"})
	}
}

// isClientValidationError returns true for errors that originate from input
// validation (Go normalizer or Postgres CHECK constraint). These bubble up as
// plain errors today; the heuristic is sufficient until a sentinel is added.
func isClientValidationError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "saml") || strings.Contains(msg, "https") || strings.Contains(msg, "required") || strings.Contains(msg, "invalid")
}
