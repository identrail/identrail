package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/enterprise"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

// nativeSAMLLoginRouteOptions controls registration of the SP-initiated
// AuthnRequest + ACS endpoints. Routes are gated behind FeatureNativeSSO and
// FeatureNewAuth so the new auth surface stays opt-in per deployment.
//
// RelayStore is the server-side cache that maps the short opaque RelayState
// handle (which fits inside the SAML 2.0 80-byte limit) to the full SP-side
// state: the originating connection id, the AuthnRequest id used for
// InResponseTo replay protection, and the post-login return_to URL.
type nativeSAMLLoginRouteOptions struct {
	Enabled            bool
	AuditSink          audit.AuditSink
	AuditFingerprinter *audit.Fingerprinter
	StateManager       *sessionauth.OAuthStateManager
	RelayStore         *sessionauth.SAMLRelayStore
	PublicBaseURL      string
	ReturnToOrigins    []string
	// Now is injectable so the ACS handler's clock-skew window can be
	// exercised deterministically in tests.
	Now func() time.Time
}

// SAMLDefaultClockSkew is the asserted-NotOnOrAfter tolerance applied to
// incoming SAML responses. Matches the de-facto Okta/Azure AD default and is
// large enough to absorb modest server-to-server clock drift without opening
// a meaningful replay window.
const SAMLDefaultClockSkew = 60 * time.Second

func registerNativeSAMLLoginRoutes(r *gin.Engine, logger *zap.Logger, svc *Service, manager sessionauth.Manager, opts nativeSAMLLoginRouteOptions) {
	if !opts.Enabled {
		return
	}
	if opts.StateManager == nil || svc == nil {
		return
	}
	if opts.RelayStore == nil {
		opts.RelayStore = sessionauth.NewSAMLRelayStore(svc.Store, nil)
	}
	// Match the rate-limit profile of the other /auth login surfaces. An
	// unauthenticated attacker who guesses a valid connection id should
	// not be able to flood SAMLRelayStore or hammer the IdP redirect.
	group := r.Group("/auth/saml")
	auditLogger := logger
	if auditLogger == nil {
		auditLogger = zap.NewNop()
	}
	group.Use(auditLogMiddleware(auditLogger, opts.AuditSink, opts.AuditFingerprinter))
	group.Use(rateLimitMiddleware(30, 30))
	group.GET("/login/:connection_id", samlLoginStartHandler(logger, svc, opts))
	group.POST("/acs/:connection_id", samlACSHandler(logger, svc, manager, opts))
}

// samlLoginStartHandler initiates an SP-initiated AuthnRequest. The handler
// builds the crewjam ServiceProvider from the stored connection, mints an
// AuthnRequest, signs it (when the deployment has an SP key — v1 ships
// unsigned), stores the request id in our HMAC-signed state token, and
// redirects the browser to the IdP's SSO URL with RelayState carrying the
// state token.
func samlLoginStartHandler(logger *zap.Logger, svc *Service, opts nativeSAMLLoginRouteOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		conn, ok := loadNativeSAMLConnectionForLogin(c, svc, logger)
		if !ok {
			return
		}
		sp, err := buildSAMLServiceProvider(conn, opts.PublicBaseURL)
		if err != nil {
			if logger != nil {
				logger.Error("build saml service provider", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "saml service provider unavailable"})
			return
		}

		req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
		if err != nil {
			if logger != nil {
				logger.Error("make saml authn request", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start saml login"})
			return
		}

		returnTo := sanitizeAuthReturnTo(c.Query("return_to"), opts.ReturnToOrigins)
		// Use a short opaque handle for RelayState (the SAML 2.0 HTTP
		// Redirect binding caps RelayState at 80 bytes). The full state —
		// connection id, AuthnRequest id, return_to — lives in the
		// server-side SAMLRelayStore, looked up on the ACS callback.
		relayHandle, err := opts.RelayStore.Issue(c.Request.Context(), sessionauth.SAMLRelayEntry{
			ConnectionID:  conn.ID,
			SAMLRequestID: req.ID,
			ReturnTo:      returnTo,
			Intent:        "login",
		})
		if err != nil {
			if logger != nil {
				logger.Error("issue saml relay handle", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start saml login"})
			return
		}

		redirectURL, err := req.Redirect(relayHandle, sp)
		if err != nil {
			if logger != nil {
				logger.Error("build saml redirect url", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start saml login"})
			return
		}
		auditAuthAction(c.Request.Context(), "auth.saml.login.start", "", "success")
		c.Redirect(http.StatusFound, redirectURL.String())
	}
}

// samlACSHandler processes an incoming SAML response from the IdP, validates
// it via crewjam (signature, audience, recipient, NotOnOrAfter with the
// configured clock skew, InResponseTo match), applies the connection's
// attribute mapping, resolves or provisions the user, and creates a session.
func samlACSHandler(logger *zap.Logger, svc *Service, manager sessionauth.Manager, opts nativeSAMLLoginRouteOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		conn, ok := loadNativeSAMLConnectionForLogin(c, svc, logger)
		if !ok {
			return
		}
		sp, err := buildSAMLServiceProvider(conn, opts.PublicBaseURL)
		if err != nil {
			if logger != nil {
				logger.Error("build saml service provider", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "saml service provider unavailable"})
			return
		}

		if err := c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid saml form body"})
			return
		}

		relay := strings.TrimSpace(c.Request.PostFormValue("RelayState"))
		var allowedRequestIDs []string
		var relayEntry sessionauth.SAMLRelayEntry
		if relay != "" {
			entry, relayErr := opts.RelayStore.Consume(c.Request.Context(), relay)
			if relayErr != nil {
				auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid relay state"})
				return
			}
			relayEntry = entry
			if entry.ConnectionID != "" && entry.ConnectionID != conn.ID {
				auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
				c.JSON(http.StatusBadRequest, gin.H{"error": "relay state does not match connection"})
				return
			}
			if entry.SAMLRequestID != "" {
				allowedRequestIDs = []string{entry.SAMLRequestID}
			}
		}

		now := time.Now().UTC()
		if opts.Now != nil {
			now = opts.Now().UTC()
		}
		sp.AllowIDPInitiated = false // SP-initiated only in v1
		// crewjam consults sp.Clock; setting it lets tests fix time.
		// Skew tolerance is handled by setting NotOnOrAfter checks via the
		// library's internal clock.
		assertion, err := sp.ParseResponse(c.Request, allowedRequestIDs)
		if err != nil {
			// Surface a redacted error to clients; the full reason lives in
			// the logs for operators to diagnose IdP misconfiguration.
			if logger != nil {
				detail := err.Error()
				if ipe, ok := err.(*saml.InvalidResponseError); ok && ipe.PrivateErr != nil {
					detail = ipe.PrivateErr.Error()
				}
				logger.Warn("parse saml response",
					telemetry.ZapError(err),
					zap.String("connection_id", conn.ID),
					zap.String("detail", detail),
				)
			}
			auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "saml login failed"})
			return
		}
		// Defensive double-check on every assertion validity window, bounded
		// by our configured 60s skew. crewjam's default tolerance is wider
		// than our policy, so enforce Conditions and SubjectConfirmationData
		// ourselves before issuing a session.
		if conditions := assertion.Conditions; conditions != nil {
			if !conditions.NotBefore.IsZero() && now.Add(SAMLDefaultClockSkew).Before(conditions.NotBefore) {
				auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "saml assertion not yet valid"})
				return
			}
			if !conditions.NotOnOrAfter.IsZero() && now.After(conditions.NotOnOrAfter.Add(SAMLDefaultClockSkew)) {
				auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "saml assertion expired"})
				return
			}
		}
		if assertion.Subject != nil {
			for _, confirm := range assertion.Subject.SubjectConfirmations {
				if confirm.SubjectConfirmationData == nil {
					continue
				}
				notBefore := confirm.SubjectConfirmationData.NotBefore
				if !notBefore.IsZero() && now.Add(SAMLDefaultClockSkew).Before(notBefore) {
					auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
					c.JSON(http.StatusUnauthorized, gin.H{"error": "saml assertion not yet valid"})
					return
				}
				notOnOrAfter := confirm.SubjectConfirmationData.NotOnOrAfter
				if !notOnOrAfter.IsZero() && now.After(notOnOrAfter.Add(SAMLDefaultClockSkew)) {
					auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
					c.JSON(http.StatusUnauthorized, gin.H{"error": "saml assertion expired"})
					return
				}
			}
		}

		profile, err := samlProfileFromAssertion(conn, assertion)
		if err != nil {
			if logger != nil {
				logger.Warn("extract saml profile", telemetry.ZapError(err))
			}
			auditAuthAction(c.Request.Context(), "auth.saml.login.failure", "", "denied")
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		result, err := svc.UpsertSAMLAssertedUser(c.Request.Context(), conn, profile)
		if err != nil {
			switch {
			case errors.Is(err, ErrSAMLUnprovisionedUser):
				c.JSON(http.StatusForbidden, gin.H{"error": "ask your admin to provision your account before signing in via SAML"})
			case errors.Is(err, ErrAuthIdentityConflict):
				c.JSON(http.StatusConflict, gin.H{"error": "identity conflict"})
			default:
				if logger != nil {
					logger.Error("upsert saml user", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete saml login"})
			}
			return
		}

		cookieValue, _, err := manager.CreateSession(c.Request.Context(), db.Session{
			UserID:             result.User.ID,
			CurrentOrgID:       result.CurrentOrgID,
			CurrentWorkspaceID: result.CurrentWorkspace,
			AuthMethod:         "saml",
			IP:                 c.ClientIP(),
			UserAgent:          c.Request.UserAgent(),
			CreatedAt:          now,
			LastSeenAt:         now,
			IdleExpiresAt:      now.Add(sessionauth.IdleTimeout),
			AbsoluteExpiresAt:  now.Add(sessionauth.AbsoluteTimeout),
		})
		if err != nil {
			if logger != nil {
				logger.Error("create saml session", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
			return
		}
		auditAuthAction(c.Request.Context(), "auth.saml.login.success", result.User.ID, "success")
		http.SetCookie(c.Writer, manager.Cookie(cookieValue))

		redirectTo := sanitizeAuthReturnTo(relayEntry.ReturnTo, opts.ReturnToOrigins)
		if redirectTo == "" || redirectTo == "/" {
			redirectTo = result.RedirectPath
		}
		if redirectTo == "" {
			redirectTo = "/"
		}
		c.Redirect(http.StatusFound, redirectTo)
	}
}

// loadNativeSAMLConnectionForLogin resolves the connection id from the URL,
// fetches the row, and rejects any non-native (WorkOS-backed) row so the SAML
// protocol code never runs against a connection it cannot complete.
func loadNativeSAMLConnectionForLogin(c *gin.Context, svc *Service, logger *zap.Logger) (db.IdentityConnection, bool) {
	connectionID := strings.TrimSpace(c.Param("connection_id"))
	if connectionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "connection_id is required"})
		return db.IdentityConnection{}, false
	}
	if _, err := uuid.Parse(connectionID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "connection_id must be a valid uuid"})
		return db.IdentityConnection{}, false
	}
	// The route is reachable without a session (it is the start of the auth
	// flow), so we look the connection up by its globally unique UUID
	// rather than requiring an org scope the caller does not have yet.
	conn, err := svc.Store.GetIdentityConnectionByID(c.Request.Context(), connectionID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "saml connection not found"})
			return db.IdentityConnection{}, false
		}
		if logger != nil {
			logger.Error("load saml connection", telemetry.ZapError(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load saml connection"})
		return db.IdentityConnection{}, false
	}
	if !conn.IsNativeSAML() {
		c.JSON(http.StatusNotFound, gin.H{"error": "saml connection not found"})
		return db.IdentityConnection{}, false
	}
	// Only `active` connections are usable for login. Pending connections
	// (the post-create default) must be promoted by an admin before the
	// unauthenticated /auth/saml/login route will accept them — otherwise
	// a half-configured trust could be exploited before the operator has
	// verified the IdP handshake. Disabled connections are also rejected.
	if conn.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "saml connection is not active"})
		return db.IdentityConnection{}, false
	}
	return conn, true
}

// buildSAMLServiceProvider constructs the crewjam ServiceProvider from a
// native SAML connection row. The SP-side ACS URL is derived from
// PublicBaseURL; the IdP metadata is synthesized from the stored entity id,
// SSO URL, and PEM certificate.
//
// v1 ships without an SP signing key — Key is left nil so AuthnRequests are
// unsigned. This is acceptable for the common case (Okta, Azure AD do not
// require signed requests by default). A follow-up will introduce per-tenant
// SP key material.
func buildSAMLServiceProvider(conn db.IdentityConnection, publicBaseURL string) (*saml.ServiceProvider, error) {
	cert, err := enterprise.ParseSAMLCertificate(conn.CertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("parse idp certificate: %w", err)
	}
	ssoURL, err := url.Parse(strings.TrimSpace(conn.SSOURL))
	if err != nil {
		return nil, fmt.Errorf("parse idp sso url: %w", err)
	}

	baseURL := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("public base url is required for native saml")
	}
	acs, err := url.Parse(baseURL + "/auth/saml/acs/" + conn.ID)
	if err != nil {
		return nil, fmt.Errorf("parse acs url: %w", err)
	}
	sp := &saml.ServiceProvider{
		EntityID:    baseURL + "/auth/saml/metadata/" + conn.ID,
		AcsURL:      *acs,
		MetadataURL: *acs,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: conn.EntityID,
			IDPSSODescriptors: []saml.IDPSSODescriptor{
				{
					SSODescriptor: saml.SSODescriptor{
						RoleDescriptor: saml.RoleDescriptor{
							KeyDescriptors: []saml.KeyDescriptor{
								{
									Use: "signing",
									KeyInfo: saml.KeyInfo{
										X509Data: saml.X509Data{
											X509Certificates: []saml.X509Certificate{{
												Data: base64.StdEncoding.EncodeToString(cert.Raw),
											}},
										},
									},
								},
							},
						},
					},
					SingleSignOnServices: []saml.Endpoint{
						{Binding: saml.HTTPRedirectBinding, Location: ssoURL.String()},
						{Binding: saml.HTTPPostBinding, Location: ssoURL.String()},
					},
				},
			},
		},
		AllowIDPInitiated: false,
		SignatureMethod:   "", // unsigned AuthnRequest in v1
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
	}
	_ = cert
	return sp, nil
}

// samlProfileFromAssertion extracts the email, NameID, display name, and
// groups from a SAML assertion using the connection's configured attribute
// mapping. Falls back to the assertion's NameID when no explicit mapping is
// declared.
func samlProfileFromAssertion(conn db.IdentityConnection, assertion *saml.Assertion) (SAMLAssertedProfile, error) {
	if assertion == nil {
		return SAMLAssertedProfile{}, fmt.Errorf("saml assertion is nil")
	}
	nameID := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = strings.TrimSpace(assertion.Subject.NameID.Value)
	}
	attrs := flattenSAMLAttributes(assertion)
	mapping := conn.AttributeMapping
	if mapping == nil {
		mapping = map[string]string{}
	}
	email := pickFromAttributes(attrs, mapping["email"])
	if email == "" {
		// Many IdPs use NameID-format=emailAddress; fall back to that.
		email = nameID
	}
	displayName := pickFromAttributes(attrs, mapping["name"])
	groupsKey := mapping["groups"]
	groups := []string{}
	if groupsKey != "" {
		groups = attrs[groupsKey]
	}
	if strings.TrimSpace(email) == "" {
		return SAMLAssertedProfile{}, fmt.Errorf("saml assertion missing email attribute or NameID")
	}
	return SAMLAssertedProfile{
		ConnectionID: conn.ID,
		OrgID:        conn.OrgID,
		NameID:       nameID,
		Email:        email,
		DisplayName:  displayName,
		Groups:       groups,
	}, nil
}

// flattenSAMLAttributes returns a map of attribute name -> values for every
// AttributeStatement in the assertion. Both AttributeName and FriendlyName
// keys are populated so attribute_mapping can refer to either form.
func flattenSAMLAttributes(assertion *saml.Assertion) map[string][]string {
	out := map[string][]string{}
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			values := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				values = append(values, v.Value)
			}
			if attr.Name != "" {
				out[attr.Name] = append(out[attr.Name], values...)
			}
			if attr.FriendlyName != "" {
				out[attr.FriendlyName] = append(out[attr.FriendlyName], values...)
			}
		}
	}
	return out
}

func pickFromAttributes(attrs map[string][]string, key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	values, ok := attrs[key]
	if !ok {
		return ""
	}
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
