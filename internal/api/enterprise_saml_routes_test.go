package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
)

// ---------- helpers ----------

func newSAMLTestRig(t *testing.T) (*Service, gin.HandlerFunc, *enterpriseSAMLMetadataFetcher) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(seedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	injectSession := func(c *gin.Context) {
		// Surface the same scope to downstream store calls.
		ctx := db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
		c.Request = c.Request.WithContext(ctx)
		c.Set("auth.session", sessionauth.CurrentSession{
			Session: db.Session{
				UserID:             "11111111-1111-1111-1111-111111111111",
				CurrentOrgID:       "tenant-a",
				CurrentWorkspaceID: "workspace-a",
			},
		})
	}
	fetcher := &enterpriseSAMLMetadataFetcher{
		fetch: func(ctx context.Context, url string) ([]byte, error) {
			return []byte(oktaMetadataFixture), nil
		},
	}
	return svc, injectSession, fetcher
}

func generateTestCertPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "identrail-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func validSAMLRequest(t *testing.T) samlConnectionRequest {
	mapping := map[string]string{"email": "urn:oid:0.9.2342.19200300.100.1.3"}
	return samlConnectionRequest{
		Type:             "sso",
		EntityID:         "https://idp.example.com/entity",
		SSOURL:           "https://idp.example.com/sso",
		CertificatePEM:   generateTestCertPEM(t),
		AttributeMapping: &mapping,
	}
}

func newTestRouterFor(t *testing.T, svc *Service, inject gin.HandlerFunc, fetcher *enterpriseSAMLMetadataFetcher, enabled bool) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.Use(inject)
	v1 := r.Group("/v1")
	registerNativeSAMLAdminRoutes(v1, nil, svc, nativeSAMLRouteOptions{Enabled: enabled, MetadataClient: fetcher})
	return r
}

func doJSON(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody []byte
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reqBody = raw
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ---------- feature flag ----------

func TestNativeSAMLRoutes_DisabledByDefault(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, false)
	w := doJSON(t, r, http.MethodGet, "/v1/enterprise/identity-connections/saml", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("with flag off the routes should not be registered; got %d", w.Code)
	}
}

// ---------- create ----------

func TestNativeSAMLRoutes_CreateReturnsTokenOnceAndPersistsHashOnly(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)

	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", validSAMLRequest(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: code %d body %s", w.Code, w.Body.String())
	}
	var resp samlConnectionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SCIMBearerToken == "" {
		t.Fatal("create response must include the one-time SCIM bearer token")
	}
	if !strings.HasPrefix(resp.SCIMBearerToken, "idntr_scim_") {
		t.Errorf("token prefix: %q", resp.SCIMBearerToken)
	}
	if !resp.Connection.HasSCIMBearerToken {
		t.Error("response should indicate token was stored")
	}

	// Re-read the connection: token must not be returned again, and the stored
	// CertificatePEM should be preserved.
	w = doJSON(t, r, http.MethodGet, "/v1/enterprise/identity-connections/saml/"+resp.Connection.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: code %d body %s", w.Code, w.Body.String())
	}
	var fetched samlConnectionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fetched.SCIMBearerToken != "" {
		t.Error("subsequent reads must not return the plaintext token")
	}
	if !fetched.Connection.HasSCIMBearerToken {
		t.Error("subsequent reads should still surface that a token is configured")
	}
}

func TestNativeSAMLRoutes_CreateRejectsMissingEmailAttributeMapping(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	req := validSAMLRequest(t)
	req.AttributeMapping = nil
	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNativeSAMLRoutes_CreateRejectsMalformedCertificate(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	req := validSAMLRequest(t)
	req.CertificatePEM = "not-a-pem-block"
	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNativeSAMLRoutes_CreateRejectsHTTPSSOURL(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	req := validSAMLRequest(t)
	req.SSOURL = "http://idp.example.com/sso"
	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------- list / list filters out WorkOS rows ----------

func TestNativeSAMLRoutes_ListExcludesWorkOSConnections(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)

	// Native row via the API.
	doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", validSAMLRequest(t))

	// WorkOS-managed SAML row directly via the store — must not appear in /saml list.
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if _, err := svc.Store.CreateIdentityConnection(seedCtx, db.IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "directory_sync",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_xyz",
	}); err != nil {
		t.Fatalf("seed workos-managed row: %v", err)
	}

	w := doJSON(t, r, http.MethodGet, "/v1/enterprise/identity-connections/saml", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Connections []samlConnectionView `json:"connections"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Connections) != 1 {
		t.Fatalf("expected one native connection, got %d", len(resp.Connections))
	}
	if !strings.HasPrefix(resp.Connections[0].EntityID, "https://idp.example.com") {
		t.Errorf("unexpected entity id %q", resp.Connections[0].EntityID)
	}
}

// ---------- update / delete ----------

func TestNativeSAMLRoutes_UpdateSetsSSORequiredAndPreservesToken(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	createResp := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", validSAMLRequest(t))
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", createResp.Code, createResp.Body.String())
	}
	var created samlConnectionResponse
	_ = json.Unmarshal(createResp.Body.Bytes(), &created)

	update := validSAMLRequest(t)
	ssoRequired := true
	update.SSORequired = &ssoRequired
	w := doJSON(t, r, http.MethodPut, "/v1/enterprise/identity-connections/saml/"+created.Connection.ID, update)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	var updated samlConnectionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &updated)
	if !updated.Connection.SSORequired {
		t.Error("sso_required should be true after update")
	}
	if !updated.Connection.HasSCIMBearerToken {
		t.Error("scim bearer token must survive update")
	}
}

func TestNativeSAMLRoutes_UpdatePreservesBooleansWhenOmitted(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)

	// Create a connection with sso_required=true and jit_provisioning_enabled=true.
	createReq := validSAMLRequest(t)
	ssoRequired := true
	jitEnabled := true
	createReq.SSORequired = &ssoRequired
	createReq.JITProvisioningEnabled = &jitEnabled
	createResp := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", createResp.Code, createResp.Body.String())
	}
	var created samlConnectionResponse
	_ = json.Unmarshal(createResp.Body.Bytes(), &created)
	if !created.Connection.SSORequired || !created.Connection.JITProvisioningEnabled {
		t.Fatalf("seed: expected both toggles enabled, got sso=%v jit=%v", created.Connection.SSORequired, created.Connection.JITProvisioningEnabled)
	}

	// Send a routine cert rotation that omits the boolean fields. Regression
	// against Codex review feedback: previously the zero-value bools would
	// silently flip both toggles back to false.
	rotateMapping := map[string]string{"email": "urn:oid:0.9.2342.19200300.100.1.3"}
	rotate := samlConnectionRequest{
		EntityID:         created.Connection.EntityID,
		SSOURL:           created.Connection.SSOURL,
		CertificatePEM:   generateTestCertPEM(t),
		AttributeMapping: &rotateMapping,
	}
	w := doJSON(t, r, http.MethodPut, "/v1/enterprise/identity-connections/saml/"+created.Connection.ID, rotate)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	var after samlConnectionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &after)
	if !after.Connection.SSORequired {
		t.Error("sso_required must be preserved when omitted from PUT body")
	}
	if !after.Connection.JITProvisioningEnabled {
		t.Error("jit_provisioning_enabled must be preserved when omitted from PUT body")
	}
}

func TestNativeSAMLRoutes_UpdateAllowsExplicitFalse(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)

	createReq := validSAMLRequest(t)
	ssoRequired := true
	createReq.SSORequired = &ssoRequired
	createResp := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", createReq)
	var created samlConnectionResponse
	_ = json.Unmarshal(createResp.Body.Bytes(), &created)

	// Explicit false in the payload still works — admins can flip toggles off.
	off := false
	update := validSAMLRequest(t)
	update.SSORequired = &off
	w := doJSON(t, r, http.MethodPut, "/v1/enterprise/identity-connections/saml/"+created.Connection.ID, update)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	var after samlConnectionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &after)
	if after.Connection.SSORequired {
		t.Error("sso_required must honor an explicit false in the payload")
	}
}

func TestNativeSAMLRoutes_UpdateClearsGroupRoleMapOnExplicitEmpty(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)

	createReq := validSAMLRequest(t)
	groups := map[string]string{"Engineering": "admin", "Support": "viewer"}
	createReq.GroupRoleMap = &groups
	createResp := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", createResp.Code, createResp.Body.String())
	}
	var created samlConnectionResponse
	_ = json.Unmarshal(createResp.Body.Bytes(), &created)
	if len(created.Connection.GroupRoleMap) != 2 {
		t.Fatalf("seed: expected 2 group bindings, got %v", created.Connection.GroupRoleMap)
	}

	// Regression: an explicit empty map must clear all bindings, not be
	// confused with "field omitted".
	empty := map[string]string{}
	update := validSAMLRequest(t)
	update.GroupRoleMap = &empty
	w := doJSON(t, r, http.MethodPut, "/v1/enterprise/identity-connections/saml/"+created.Connection.ID, update)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	var after samlConnectionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &after)
	if len(after.Connection.GroupRoleMap) != 0 {
		t.Errorf("explicit empty group_role_map must clear all bindings, got %v", after.Connection.GroupRoleMap)
	}
}

func TestNativeSAMLRoutes_CreateReturnsActionableConflictWhenWorkOSExists(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)

	// Seed a WorkOS-managed SAML SSO row directly via the store.
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if _, err := svc.Store.CreateIdentityConnection(seedCtx, db.IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_existing",
	}); err != nil {
		t.Fatalf("seed workos row: %v", err)
	}

	// Now an admin trying to create a native SAML SSO connection should get a
	// 409 with an actionable message, not the bare uniqueness violation.
	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", validSAMLRequest(t))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "WorkOS-managed") {
		t.Errorf("expected admin-actionable error mentioning WorkOS, got: %s", w.Body.String())
	}
}

func TestNativeSAMLRoutes_DeleteRemovesConnection(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	createResp := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml", validSAMLRequest(t))
	var created samlConnectionResponse
	_ = json.Unmarshal(createResp.Body.Bytes(), &created)

	w := doJSON(t, r, http.MethodDelete, "/v1/enterprise/identity-connections/saml/"+created.Connection.ID, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	get := doJSON(t, r, http.MethodGet, "/v1/enterprise/identity-connections/saml/"+created.Connection.ID, nil)
	if get.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", get.Code)
	}
}

// ---------- metadata import ----------

func TestNativeSAMLRoutes_MetadataImportFromInlineXML(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml/from-metadata", gin.H{
		"metadata_xml": oktaMetadataFixture,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("import inline: %d %s", w.Code, w.Body.String())
	}
	var draft SAMLMetadataDraft
	if err := json.Unmarshal(w.Body.Bytes(), &draft); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(draft.SSOURL, "https://acme.okta.com") {
		t.Errorf("unexpected sso_url: %q", draft.SSOURL)
	}
}

func TestNativeSAMLRoutes_MetadataImportFromURLUsesFetcher(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml/from-metadata", gin.H{
		"metadata_url": "https://idp.example.com/metadata",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("import url: %d %s", w.Code, w.Body.String())
	}
}

func TestNativeSAMLRoutes_MetadataImportRequiresInput(t *testing.T) {
	svc, inject, fetcher := newSAMLTestRig(t)
	r := newTestRouterFor(t, svc, inject, fetcher, true)
	w := doJSON(t, r, http.MethodPost, "/v1/enterprise/identity-connections/saml/from-metadata", gin.H{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when no input provided, got %d", w.Code)
	}
}

// ---------- session required ----------

func TestNativeSAMLRoutes_RejectsUnauthenticatedRequest(t *testing.T) {
	svc, _, fetcher := newSAMLTestRig(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// No session injector — handler must return 401.
	v1 := r.Group("/v1")
	registerNativeSAMLAdminRoutes(v1, nil, svc, nativeSAMLRouteOptions{Enabled: true, MetadataClient: fetcher})
	w := doJSON(t, r, http.MethodGet, "/v1/enterprise/identity-connections/saml", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without session, got %d", w.Code)
	}
}
