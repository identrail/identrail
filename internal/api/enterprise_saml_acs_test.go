package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	dsig "github.com/russellhaering/goxmldsig"
)

// ---------- SAML fixture IdP ----------

// samlFixtureIdP holds an in-memory IdP key + cert. The same struct mints
// SAMLResponse XML for the ACS handler tests so we exercise the real
// crewjam parser + signature path end-to-end.
type samlFixtureIdP struct {
	key   *rsa.PrivateKey
	cert  *x509.Certificate
	certB string // base64 DER for embedding in the connection
	pem   string
}

func newSAMLFixtureIdP(t *testing.T) *samlFixtureIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("idp keygen: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return &samlFixtureIdP{
		key:   key,
		cert:  cert,
		certB: base64.StdEncoding.EncodeToString(der),
		pem:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

// mintSignedSAMLResponse produces a signed SAML 2.0 Response document that
// crewjam will accept: the assertion is signed (enveloped XML-DSig), the
// audience matches the SP's EntityID, recipient matches the ACS URL,
// InResponseTo matches the supplied request ID, and the conditions window is
// generous enough to ignore the test clock.
func (i *samlFixtureIdP) mintSignedSAMLResponse(t *testing.T, requestID, audience, recipient, nameID, email string) string {
	t.Helper()
	now := time.Now().UTC()
	notBefore := now.Add(-time.Minute)
	notOnOrAfter := now.Add(10 * time.Minute)
	return i.mintSignedSAMLResponseWithTiming(t, requestID, audience, recipient, nameID, email, notBefore, notOnOrAfter, time.Time{})
}

func (i *samlFixtureIdP) mintSignedSAMLResponseWithTiming(t *testing.T, requestID, audience, recipient, nameID, email string, notBefore, notOnOrAfter, subjectNotBefore time.Time) string {
	t.Helper()
	now := time.Now().UTC()
	subjectNotBeforeAttr := ""
	if !subjectNotBefore.IsZero() {
		subjectNotBeforeAttr = ` NotBefore="` + subjectNotBefore.Format(time.RFC3339) + `"`
	}

	assertionID := "_assertion-" + randomHex(t, 8)
	responseID := "_response-" + randomHex(t, 8)
	tpl := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="` + responseID + `" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `"
  Destination="` + recipient + `" InResponseTo="` + requestID + `">
  <saml:Issuer>https://idp.example.com/entity</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="` + assertionID + `" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `">
    <saml:Issuer>https://idp.example.com/entity</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + nameID + `</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData` + subjectNotBeforeAttr + ` NotOnOrAfter="` + notOnOrAfter.Format(time.RFC3339) + `" Recipient="` + recipient + `" InResponseTo="` + requestID + `"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="` + notBefore.Format(time.RFC3339) + `" NotOnOrAfter="` + notOnOrAfter.Format(time.RFC3339) + `">
      <saml:AudienceRestriction><saml:Audience>` + audience + `</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="` + now.Format(time.RFC3339) + `" SessionIndex="_session">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
        <saml:AttributeValue>` + email + `</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
        <saml:AttributeValue>Test User</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	// Sign the assertion as its own self-contained document so the saml:
	// namespace prefix is in scope during canonicalisation, then splice the
	// signed element back into the response.
	assertionDoc := etree.NewDocument()
	if err := assertionDoc.ReadFromString(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `">
  <saml:Issuer>https://idp.example.com/entity</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + nameID + `</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData` + subjectNotBeforeAttr + ` NotOnOrAfter="` + notOnOrAfter.Format(time.RFC3339) + `" Recipient="` + recipient + `" InResponseTo="` + requestID + `"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="` + notBefore.Format(time.RFC3339) + `" NotOnOrAfter="` + notOnOrAfter.Format(time.RFC3339) + `">
    <saml:AudienceRestriction><saml:Audience>` + audience + `</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="` + now.Format(time.RFC3339) + `" SessionIndex="_session">
    <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
      <saml:AttributeValue>` + email + `</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
      <saml:AttributeValue>Test User</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`); err != nil {
		t.Fatalf("parse assertion template: %v", err)
	}
	signed, err := signXMLElement(i.key, i.cert, assertionDoc.Root())
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	// Wrap the signed assertion in the SAML response envelope.
	respDoc := etree.NewDocument()
	if err := respDoc.ReadFromString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + responseID + `" Version="2.0" IssueInstant="` + now.Format(time.RFC3339) + `" Destination="` + recipient + `" InResponseTo="` + requestID + `">
  <saml:Issuer>https://idp.example.com/entity</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:Response>`); err != nil {
		t.Fatalf("parse response envelope: %v", err)
	}
	respDoc.Root().AddChild(signed)

	out, err := respDoc.WriteToString()
	if err != nil {
		t.Fatalf("serialize response: %v", err)
	}
	_ = tpl
	return out
}

func signXMLElement(key *rsa.PrivateKey, cert *x509.Certificate, el *etree.Element) (*etree.Element, error) {
	keyStore := dsig.TLSCertKeyStore{PrivateKey: key, Certificate: [][]byte{cert.Raw}}
	signCtx := dsig.NewDefaultSigningContext(keyStore)
	signCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	return signCtx.SignEnveloped(el)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return strings.ToLower(strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(b), "_", ""))
}

// ---------- ACS handler tests ----------

func newSAMLACSRig(t *testing.T, jit bool) (*Service, db.IdentityConnection, *samlFixtureIdP, sessionauth.Manager, *sessionauth.OAuthStateManager, *sessionauth.SAMLRelayStore) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(seedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")

	idp := newSAMLFixtureIdP(t)
	connection, err := store.CreateIdentityConnection(seedCtx, db.IdentityConnection{
		OrgID:                  "tenant-a",
		Provider:               "saml",
		Type:                   "sso",
		Status:                 "active",
		EntityID:               "https://idp.example.com/entity",
		SSOURL:                 "https://idp.example.com/sso",
		CertificatePEM:         idp.pem,
		AttributeMapping:       map[string]string{"email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"},
		JITProvisioningEnabled: jit,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	sessionManager := sessionauth.Manager{Store: store}
	stateManager := sessionauth.NewOAuthStateManager("test-session-key-must-be-at-least-32-bytes-long", nil)
	relayStore := sessionauth.NewSAMLRelayStore(store, nil)
	return svc, connection, idp, sessionManager, stateManager, relayStore
}

func TestSAMLACSHandler_HappyPath_JITCreatesUser(t *testing.T) {
	svc, conn, idp, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	requestID := "_authnreq-" + randomHex(t, 8)
	relay, err := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  conn.ID,
		SAMLRequestID: requestID,
		ReturnTo:      "/app/tenant-a/workspace-a",
		Intent:        "login",
	})
	if err != nil {
		t.Fatalf("issue state: %v", err)
	}
	audience := "https://api.example.com/auth/saml/metadata/" + conn.ID
	recipient := "https://api.example.com/auth/saml/acs/" + conn.ID
	signedResponse := idp.mintSignedSAMLResponse(t, requestID, audience, recipient, "alice@example.com", "alice@example.com")
	encoded := base64.StdEncoding.EncodeToString([]byte(signedResponse))

	form := url.Values{
		"SAMLResponse": {encoded},
		"RelayState":   {relay},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/"+conn.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d body=%s", w.Code, w.Body.String())
	}
	// JIT created the user — verify the persistence side-effect.
	if _, err := svc.Store.GetUserByPrimaryEmail(context.Background(), "alice@example.com"); err != nil {
		t.Errorf("JIT did not create the asserted user: %v", err)
	}
}

func TestSAMLLoginRoutesAttachAuditMiddleware(t *testing.T) {
	svc, conn, _, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	sink := &recordingAuditSink{}
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		AuditSink:     sink,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/saml/login/"+conn.ID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d body=%s", w.Code, w.Body.String())
	}
	if countAuditEventsByKind(sink.events, "api_request") == 0 {
		t.Fatalf("expected SAML login request to be audited, got %+v", sink.events)
	}
	if countAuditEventsByKind(sink.events, "action") == 0 {
		t.Fatalf("expected SAML login action audit event, got %+v", sink.events)
	}
}

func TestSAMLLoginStartPreservesAllowedAbsoluteReturnTo(t *testing.T) {
	svc, conn, _, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:         true,
		StateManager:    stateMgr,
		RelayStore:      relayStore,
		PublicBaseURL:   "https://api.example.com",
		ReturnToOrigins: []string{"https://api.example.com", "https://app.example.com"},
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/saml/login/"+conn.ID+"?return_to=https%3A%2F%2Fapp.example.com%2Fapp%2Ftenant-a%2Fworkspace-a%3Ftab%3Dsaml", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d body=%s", w.Code, w.Body.String())
	}
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	relayHandle := redirectURL.Query().Get("RelayState")
	if relayHandle == "" {
		t.Fatalf("redirect did not include RelayState: %s", redirectURL.String())
	}
	relayEntry, err := relayStore.Consume(context.Background(), relayHandle)
	if err != nil {
		t.Fatalf("consume relay: %v", err)
	}
	if relayEntry.ReturnTo != "https://app.example.com/app/tenant-a/workspace-a?tab=saml" {
		t.Fatalf("allowed absolute return_to was not preserved: %q", relayEntry.ReturnTo)
	}
}

func TestSAMLACSHandler_RejectsConditionsNotBeforeBeyondSkew(t *testing.T) {
	svc, conn, idp, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	requestID := "_authnreq-" + randomHex(t, 8)
	relay, err := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  conn.ID,
		SAMLRequestID: requestID,
		Intent:        "login",
	})
	if err != nil {
		t.Fatalf("issue state: %v", err)
	}
	audience := "https://api.example.com/auth/saml/metadata/" + conn.ID
	recipient := "https://api.example.com/auth/saml/acs/" + conn.ID
	now := time.Now().UTC()
	signedResponse := idp.mintSignedSAMLResponseWithTiming(
		t,
		requestID,
		audience,
		recipient,
		"alice@example.com",
		"alice@example.com",
		now.Add(2*time.Minute),
		now.Add(10*time.Minute),
		time.Time{},
	)
	encoded := base64.StdEncoding.EncodeToString([]byte(signedResponse))

	form := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/"+conn.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for future Conditions.NotBefore, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not yet valid") {
		t.Fatalf("expected not-yet-valid error, got %s", w.Body.String())
	}
}

func TestSAMLACSHandler_RejectsSubjectConfirmationNotBeforeBeyondSkew(t *testing.T) {
	svc, conn, idp, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	requestID := "_authnreq-" + randomHex(t, 8)
	relay, err := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  conn.ID,
		SAMLRequestID: requestID,
		Intent:        "login",
	})
	if err != nil {
		t.Fatalf("issue state: %v", err)
	}
	audience := "https://api.example.com/auth/saml/metadata/" + conn.ID
	recipient := "https://api.example.com/auth/saml/acs/" + conn.ID
	now := time.Now().UTC()
	signedResponse := idp.mintSignedSAMLResponseWithTiming(
		t,
		requestID,
		audience,
		recipient,
		"alice@example.com",
		"alice@example.com",
		now.Add(-time.Minute),
		now.Add(10*time.Minute),
		now.Add(2*time.Minute),
	)
	encoded := base64.StdEncoding.EncodeToString([]byte(signedResponse))

	form := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/"+conn.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for future SubjectConfirmationData.NotBefore, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not yet valid") {
		t.Fatalf("expected not-yet-valid error, got %s", w.Body.String())
	}
}

func TestSAMLACSHandler_JITDisabledRejectsUnknownUser(t *testing.T) {
	svc, conn, idp, manager, stateMgr, relayStore := newSAMLACSRig(t, false)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	requestID := "_authnreq-" + randomHex(t, 8)
	relay, _ := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  conn.ID,
		SAMLRequestID: requestID,
		ReturnTo:      "",
		Intent:        "login",
	})
	audience := "https://api.example.com/auth/saml/metadata/" + conn.ID
	recipient := "https://api.example.com/auth/saml/acs/" + conn.ID
	signed := idp.mintSignedSAMLResponse(t, requestID, audience, recipient, "stranger@example.com", "stranger@example.com")
	encoded := base64.StdEncoding.EncodeToString([]byte(signed))

	form := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/"+conn.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "provision") {
		t.Errorf("expected provisioning hint in error body, got %s", w.Body.String())
	}
}

func TestSAMLACSHandler_RejectsTamperedSignature(t *testing.T) {
	svc, conn, idp, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	requestID := "_authnreq-" + randomHex(t, 8)
	relay, _ := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  conn.ID,
		SAMLRequestID: requestID,
		ReturnTo:      "",
		Intent:        "login",
	})
	audience := "https://api.example.com/auth/saml/metadata/" + conn.ID
	recipient := "https://api.example.com/auth/saml/acs/" + conn.ID
	signed := idp.mintSignedSAMLResponse(t, requestID, audience, recipient, "alice@example.com", "alice@example.com")
	// Flip a single attribute value to invalidate the signature.
	tampered := strings.Replace(signed, "alice@example.com", "evil@example.com", -1)
	encoded := base64.StdEncoding.EncodeToString([]byte(tampered))

	form := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/"+conn.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on tampered signature, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSAMLACSHandler_RejectsRelayStateForWrongConnection(t *testing.T) {
	svc, conn, idp, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	if err := svc.Store.UpsertOrganization(seedCtx, db.TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("seed second org: %v", err)
	}
	otherConn, err := svc.Store.CreateIdentityConnection(seedCtx, db.IdentityConnection{
		OrgID:                  "tenant-b",
		Provider:               "saml",
		Type:                   "sso",
		Status:                 "active",
		EntityID:               "https://idp.other.example.com/entity",
		SSOURL:                 "https://idp.other.example.com/sso",
		CertificatePEM:         idp.pem,
		AttributeMapping:       map[string]string{"email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
		JITProvisioningEnabled: true,
	})
	if err != nil {
		t.Fatalf("seed second connection: %v", err)
	}
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	requestID := "_authnreq-" + randomHex(t, 8)
	// RelayState carries a real but DIFFERENT connection id than the URL path.
	otherRelay, err := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  otherConn.ID,
		SAMLRequestID: requestID,
		ReturnTo:      "",
		Intent:        "login",
	})
	if err != nil {
		t.Fatalf("issue mismatched relay: %v", err)
	}
	audience := "https://api.example.com/auth/saml/metadata/" + conn.ID
	recipient := "https://api.example.com/auth/saml/acs/" + conn.ID
	signed := idp.mintSignedSAMLResponse(t, requestID, audience, recipient, "alice@example.com", "alice@example.com")
	encoded := base64.StdEncoding.EncodeToString([]byte(signed))

	form := url.Values{"SAMLResponse": {encoded}, "RelayState": {otherRelay}}
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/"+conn.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSAMLACSHandler_RejectsUnknownConnection(t *testing.T) {
	svc, _, _, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/99999999-9999-9999-9999-999999999999", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown connection, got %d", w.Code)
	}
}

func TestSAMLLoginRoutesRejectMalformedConnectionID(t *testing.T) {
	svc, _, _, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "login", method: http.MethodGet, path: "/auth/saml/login/not-a-uuid"},
		{name: "acs", method: http.MethodPost, path: "/auth/saml/acs/not-a-uuid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for malformed connection id, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSAMLACSHandler_DisabledByFeatureFlag(t *testing.T) {
	svc, conn, _, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	_ = relayStore
	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       false, // feature off
		StateManager:  stateMgr,
		PublicBaseURL: "https://api.example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs/"+conn.ID, strings.NewReader(""))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected route to be unregistered when flag is off; got %d", w.Code)
	}
}

func TestUpsertSAMLAssertedUser_RefusesCrossTenantEmailMatch(t *testing.T) {
	// Path-3 (email match) must verify the matched user is a member of the
	// connection's org. A user who happens to share an email but has no
	// membership in tenant-saml must NOT get bound to the SAML assertion —
	// they may belong to a different tenant, or to no tenant at all.
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-saml", WorkspaceID: "workspace-saml"})
	if err := store.UpsertOrganization(seedCtx, db.TenancyOrganization{DisplayName: "Tenant SAML", Slug: "tenant-saml"}); err != nil {
		t.Fatalf("seed org saml: %v", err)
	}
	// Seed a user with NO membership in tenant-saml.
	if _, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "alice@example.com", DisplayName: "Alice"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	conn := db.IdentityConnection{
		ID:                     "saml-conn-x",
		OrgID:                  "tenant-saml",
		Provider:               "saml",
		JITProvisioningEnabled: true,
	}
	_, err := svc.UpsertSAMLAssertedUser(context.Background(), conn, SAMLAssertedProfile{
		NameID:      "alice-nameid",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	})
	if !errors.Is(err, ErrSAMLUnprovisionedUser) {
		t.Errorf("expected ErrSAMLUnprovisionedUser when matched user lacks membership in conn.OrgID, got: %v", err)
	}
}

func TestUpsertSAMLAssertedUser_FallsBackNameIDToEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(seedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	conn := db.IdentityConnection{
		ID:                     "conn-fallback",
		OrgID:                  "tenant-a",
		Provider:               "saml",
		JITProvisioningEnabled: true,
	}
	// NameID intentionally empty — must fall back to email instead of failing.
	result, err := svc.UpsertSAMLAssertedUser(context.Background(), conn, SAMLAssertedProfile{
		NameID:      "",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("expected NameID fallback, got: %v", err)
	}
	if result.User.PrimaryEmail != "alice@example.com" {
		t.Errorf("user not provisioned: %+v", result.User)
	}
}

func TestUpsertSAMLAssertedUser_RefreshesExistingSAMLIdentity(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, routerScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "old@example.com",
		DisplayName:  "Old Name",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            "saml:conn-refresh",
		Subject:             "nameid-refresh",
		Email:               "old@example.com",
		LastAuthenticatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "subject-a",
		UserUUID:    user.ID,
		Email:       "new@example.com",
		Role:        "admin",
		Status:      "active",
		JoinedAt:    now,
	}); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	result, err := svc.UpsertSAMLAssertedUser(ctx, db.IdentityConnection{
		ID:                     "conn-refresh",
		OrgID:                  "tenant-a",
		Provider:               "saml",
		JITProvisioningEnabled: true,
	}, SAMLAssertedProfile{
		NameID:      "nameid-refresh",
		Email:       "new@example.com",
		DisplayName: "New Name",
	})
	if err != nil {
		t.Fatalf("upsert saml user: %v", err)
	}
	if result.NewUser {
		t.Fatal("expected existing identity to refresh, not create a new user")
	}
	if result.CurrentOrgID != "tenant-a" || result.CurrentWorkspace != "workspace-a" || result.RedirectPath != "/app/tenant-a/workspace-a" {
		t.Fatalf("unexpected session context: %+v", result)
	}
	if result.User.PrimaryEmail != "new@example.com" || result.User.DisplayName != "New Name" {
		t.Fatalf("profile was not refreshed: %+v", result.User)
	}
	if result.Identity.Email != "new@example.com" || !result.Identity.EmailVerified || result.Identity.LastAuthenticatedAt != now {
		t.Fatalf("identity was not refreshed: %+v", result.Identity)
	}
}

func TestUpsertSAMLAssertedUser_AttachesFromSCIMIdentity(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC)
	svc := NewService(store, routerScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "scim@example.com",
		DisplayName:  "SCIM User",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:   user.ID,
		Provider: "scim:conn-scim",
		Subject:  "opaque-scim-username",
		Email:    "scim@example.com",
	}); err != nil {
		t.Fatalf("seed scim identity: %v", err)
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: "tenant-scim", WorkspaceID: "workspace-scim"})
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{DisplayName: "Tenant SCIM", Slug: "tenant-scim"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: "workspace-scim", DisplayName: "Workspace SCIM", Slug: "workspace-scim"}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-scim",
		MemberID:    "member-scim",
		UserID:      "subject-scim",
		UserUUID:    user.ID,
		Email:       "scim@example.com",
		Role:        "viewer",
		Status:      "active",
		JoinedAt:    now,
	}); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	result, err := svc.UpsertSAMLAssertedUser(ctx, db.IdentityConnection{
		ID:                     "conn-scim",
		OrgID:                  "tenant-scim",
		Provider:               "saml",
		JITProvisioningEnabled: false,
	}, SAMLAssertedProfile{
		NameID:      "saml-nameid",
		Email:       "scim@example.com",
		DisplayName: "Attached User",
	})
	if err != nil {
		t.Fatalf("upsert saml user: %v", err)
	}
	if result.NewUser {
		t.Fatal("expected SAML identity to attach to pre-provisioned user")
	}
	if result.User.ID != user.ID {
		t.Fatalf("attached wrong user: got %q want %q", result.User.ID, user.ID)
	}
	if result.Identity.Provider != "saml:conn-scim" || result.Identity.Subject != "saml-nameid" {
		t.Fatalf("unexpected attached identity: %+v", result.Identity)
	}
	if result.RedirectPath != "/app/tenant-scim/workspace-scim" {
		t.Fatalf("unexpected redirect path: %q", result.RedirectPath)
	}
}

func TestUpsertSAMLAssertedUser_RejectsDeactivatedSCIMUser(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "disabled@example.com",
		DisplayName:  "Disabled User",
		Status:       "deactivated",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:   user.ID,
		Provider: "scim:conn-disabled",
		Subject:  "disabled-nameid",
		Email:    "disabled@example.com",
	}); err != nil {
		t.Fatalf("seed scim identity: %v", err)
	}

	_, err = svc.UpsertSAMLAssertedUser(ctx, db.IdentityConnection{
		ID:                     "conn-disabled",
		OrgID:                  "tenant-disabled",
		Provider:               "saml",
		JITProvisioningEnabled: false,
	}, SAMLAssertedProfile{
		NameID:      "disabled-nameid",
		Email:       "disabled@example.com",
		DisplayName: "Disabled User",
	})
	if !errors.Is(err, ErrSAMLUnprovisionedUser) {
		t.Fatalf("expected deactivated SCIM user to be denied, got %v", err)
	}
	if _, err := store.GetUserIdentity(ctx, "saml:conn-disabled", "disabled-nameid"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("deactivated user should not receive a SAML identity, got %v", err)
	}
	gotUser, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if gotUser.Status != "deactivated" {
		t.Fatalf("deactivated user should not be reactivated: %+v", gotUser)
	}
}

func TestSAMLRelayStore_RoundTripAndOneShotConsume(t *testing.T) {
	memStore := db.NewMemoryStore()
	relayStore := sessionauth.NewSAMLRelayStore(memStore, nil)
	// Seed an identity connection so the relay state's FK to
	// identity_connections(id) is satisfied in the memory layer's
	// org-scoped lookups.
	seedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := memStore.UpsertOrganization(seedCtx, db.TenancyOrganization{DisplayName: "T", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	conn, err := memStore.CreateIdentityConnection(seedCtx, db.IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_seed",
	})
	if err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	handle, err := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  conn.ID,
		SAMLRequestID: "_request-1",
		ReturnTo:      "/app/tenant-a/workspace-a",
		Intent:        "login",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(handle) > 80 {
		t.Errorf("relay handle is %d bytes; SAML RelayState limit is 80", len(handle))
	}
	entry, err := relayStore.Consume(context.Background(), handle)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if entry.ConnectionID != conn.ID || entry.SAMLRequestID != "_request-1" {
		t.Errorf("entry round-tripped incorrectly: %+v", entry)
	}
	// Second consume must fail — one-shot semantics prevent replay.
	if _, err := relayStore.Consume(context.Background(), handle); !errors.Is(err, sessionauth.ErrSAMLRelayHandleInvalid) {
		t.Errorf("expected ErrSAMLRelayHandleInvalid on replay, got: %v", err)
	}
}

func TestSAMLRelayStore_IssueRequiresExistingConnection(t *testing.T) {
	memStore := db.NewMemoryStore()
	relayStore := sessionauth.NewSAMLRelayStore(memStore, nil)

	_, err := relayStore.Issue(context.Background(), sessionauth.SAMLRelayEntry{
		ConnectionID:  "00000000-0000-0000-0000-000000000000",
		SAMLRequestID: "_request-1",
		Intent:        "login",
	})
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected missing relay connection to return ErrNotFound, got %v", err)
	}
}

func TestSAMLACSHandler_RejectsPendingConnection(t *testing.T) {
	// Connections in the post-create `pending` state must not accept logins
	// until an admin has validated the IdP handshake and promoted them to
	// `active`. Without this gate a half-configured trust could be exploited
	// before the operator has verified it works.
	svc, conn, _, manager, stateMgr, relayStore := newSAMLACSRig(t, true)
	// Downgrade the seeded connection to pending.
	conn.Status = "pending"
	if _, err := svc.Store.UpdateIdentityConnection(context.Background(), conn); err != nil {
		t.Fatalf("downgrade connection: %v", err)
	}

	router := gin.New()
	registerNativeSAMLLoginRoutes(router, nil, svc, manager, nativeSAMLLoginRouteOptions{
		Enabled:       true,
		StateManager:  stateMgr,
		RelayStore:    relayStore,
		PublicBaseURL: "https://api.example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/saml/login/"+conn.ID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for pending connection, got %d body=%s", w.Code, w.Body.String())
	}
}

// ---------- attribute mapping ----------

func TestSAMLProfileFromAssertion_FallsBackToNameIDWhenEmailUnmapped(t *testing.T) {
	conn := db.IdentityConnection{
		ID:               "conn-1",
		AttributeMapping: map[string]string{}, // no email mapping
	}
	assertion := &saml.Assertion{
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "alice@example.com"}},
	}
	profile, err := samlProfileFromAssertion(conn, assertion)
	if err != nil {
		t.Fatalf("extract profile: %v", err)
	}
	if profile.Email != "alice@example.com" {
		t.Errorf("expected NameID fallback for email, got %q", profile.Email)
	}
}

// xmlMatches keeps the linter happy; the constant in newSAMLFixtureIdP relies
// on it through the etree-driven mint path.
var _ = xml.NewDecoder

// bytesBufferAlias silences the strictly-unused import bytes when the
// generator removes one of the helpers. Keeping it here removes the test
// from being brittle to fixture changes.
var _ = bytes.NewBuffer
