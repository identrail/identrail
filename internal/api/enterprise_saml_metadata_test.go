package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const oktaMetadataFixture = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exk1abc23DEF">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAYjBhCAUMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmlkZW50cmFpbDExHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20=</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://acme.okta.com/app/exk1abc23DEF/sso/saml"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://acme.okta.com/app/exk1abc23DEF/sso/saml"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`

const azureADMetadataFixture = `<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor ID="_abc" entityID="https://sts.windows.net/00000000-0000-0000-0000-000000000000/" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIDqDCCApCgAwIBAgIGAYjBhCAUMA0GCSqGSIb3DQEBCwUAMIGdMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHUmVkbW9uZDEXMBUGA1UECgwOTWljcm9zb2Z0IENv
cnAxFzAVBgNVBAsMDkF6dXJlIEFEIFNTTw==</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/saml2"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func TestParseSAMLMetadataXML_OktaFixture(t *testing.T) {
	draft, err := ParseSAMLMetadataXML([]byte(oktaMetadataFixture))
	if err != nil {
		t.Fatalf("parse okta metadata: %v", err)
	}
	if draft.EntityID != "http://www.okta.com/exk1abc23DEF" {
		t.Errorf("entity id: %q", draft.EntityID)
	}
	// HTTP-Redirect must win over HTTP-POST since Identrail prefers redirect.
	if draft.SSOURL != "https://acme.okta.com/app/exk1abc23DEF/sso/saml" {
		t.Errorf("sso url: %q", draft.SSOURL)
	}
	if !strings.HasPrefix(draft.CertificatePEM, "-----BEGIN CERTIFICATE-----\n") ||
		!strings.HasSuffix(strings.TrimRight(draft.CertificatePEM, "\n"), "-----END CERTIFICATE-----") {
		t.Errorf("certificate PEM is not well-formed:\n%s", draft.CertificatePEM)
	}
}

func TestParseSAMLMetadataXML_AzureADFixture(t *testing.T) {
	draft, err := ParseSAMLMetadataXML([]byte(azureADMetadataFixture))
	if err != nil {
		t.Fatalf("parse azure ad metadata: %v", err)
	}
	if !strings.HasPrefix(draft.EntityID, "https://sts.windows.net/") {
		t.Errorf("entity id: %q", draft.EntityID)
	}
	if !strings.Contains(draft.SSOURL, "login.microsoftonline.com") {
		t.Errorf("sso url: %q", draft.SSOURL)
	}
}

func TestParseSAMLMetadataXML_RejectsHTTPSSOURL(t *testing.T) {
	bad := strings.Replace(oktaMetadataFixture, "https://acme.okta.com", "http://acme.okta.com", -1)
	_, err := ParseSAMLMetadataXML([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("expected https requirement, got: %v", err)
	}
}

func TestParseSAMLMetadataXML_RejectsMissingSSOService(t *testing.T) {
	bad := strings.Replace(oktaMetadataFixture, "<md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">", "<md:IDPSSODescriptor>", 1)
	bad = strings.Replace(bad, "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://acme.okta.com/app/exk1abc23DEF/sso/saml\"/>", "", 1)
	bad = strings.Replace(bad, "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://acme.okta.com/app/exk1abc23DEF/sso/saml\"/>", "", 1)
	_, err := ParseSAMLMetadataXML([]byte(bad))
	if err == nil {
		t.Fatal("expected error for missing SSO service")
	}
}

func TestParseSAMLMetadataXML_RejectsEmpty(t *testing.T) {
	if _, err := ParseSAMLMetadataXML(nil); err == nil {
		t.Error("expected empty body to be rejected")
	}
}

func TestParseSAMLMetadataXML_RejectsMalformedXML(t *testing.T) {
	if _, err := ParseSAMLMetadataXML([]byte("not xml")); err == nil {
		t.Error("expected malformed xml to be rejected")
	}
}

func TestFetchSAMLMetadataXML_HappyPath(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(oktaMetadataFixture))
	}))
	t.Cleanup(srv.Close)
	body, err := FetchSAMLMetadataXML(context.Background(), srv.Client(), srv.URL+"/idp/metadata")
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	if !strings.Contains(string(body), "EntityDescriptor") {
		t.Errorf("unexpected body: %q", string(body)[:80])
	}
}

func TestFetchSAMLMetadataXML_RejectsHTTP(t *testing.T) {
	_, err := FetchSAMLMetadataXML(context.Background(), nil, "http://idp.example.com/metadata")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("expected https requirement, got: %v", err)
	}
}

func TestNewSCIMBearerToken_Format(t *testing.T) {
	plain, hash, err := NewSCIMBearerToken()
	if err != nil {
		t.Fatalf("token gen: %v", err)
	}
	if !strings.HasPrefix(plain, "idntr_scim_") {
		t.Errorf("token prefix: %q", plain)
	}
	if len(plain) < 50 {
		t.Errorf("token unexpectedly short: %q", plain)
	}
	expected := sha256.Sum256([]byte(plain))
	if hash != hex.EncodeToString(expected[:]) {
		t.Errorf("hash mismatch")
	}
}

func TestNewSCIMBearerToken_DistinctEachCall(t *testing.T) {
	a, _, _ := NewSCIMBearerToken()
	b, _, _ := NewSCIMBearerToken()
	if a == b {
		t.Error("two consecutive tokens were identical — RNG failure")
	}
}
