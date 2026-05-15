package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SAML 2.0 metadata bindings ordered by preference. Identrail's ACS is a
// service-provider POST flow, so an IdP that exposes either binding is
// acceptable; HTTP-Redirect is the more interoperable default.
const (
	samlBindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	samlBindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// samlIdPMetadata is the subset of the SAML 2.0 metadata schema Identrail
// reads from an IdP-issued document. encoding/xml ignores namespace prefixes
// in tag matching when the local name matches, which lets one struct shape
// decode payloads from Okta, Azure AD, OneLogin, JumpCloud, and Google
// Workspace without per-vendor branching.
type samlIdPMetadata struct {
	XMLName          xml.Name `xml:"EntityDescriptor"`
	EntityID         string   `xml:"entityID,attr"`
	IDPSSODescriptor struct {
		KeyDescriptors []struct {
			Use     string `xml:"use,attr"`
			KeyInfo struct {
				X509Data struct {
					X509Certificates []string `xml:"X509Certificate"`
				} `xml:"X509Data"`
			} `xml:"KeyInfo"`
		} `xml:"KeyDescriptor"`
		SSOServices []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
	} `xml:"IDPSSODescriptor"`
}

// SAMLMetadataDraft is the validated, normalized output of metadata import.
// The handler returns this so the admin can review the auto-filled values
// before persisting via POST /identity-connections/saml.
type SAMLMetadataDraft struct {
	EntityID       string `json:"entity_id"`
	SSOURL         string `json:"sso_url"`
	CertificatePEM string `json:"certificate_pem"`
}

// ParseSAMLMetadataXML decodes one IdP metadata XML document and returns the
// fields Identrail needs. Errors are descriptive so an admin pasting the
// wrong document (e.g., an SP metadata file instead of an IdP one) gets a
// clear message about what went wrong.
func ParseSAMLMetadataXML(raw []byte) (SAMLMetadataDraft, error) {
	if len(raw) == 0 {
		return SAMLMetadataDraft{}, fmt.Errorf("metadata document is empty")
	}
	var doc samlIdPMetadata
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	// Disable external entity loading. encoding/xml does not follow DTDs and
	// does not resolve external entities, but be explicit so a future stdlib
	// change cannot silently introduce an XXE surface.
	decoder.Entity = nil
	decoder.Strict = true
	if err := decoder.Decode(&doc); err != nil {
		return SAMLMetadataDraft{}, fmt.Errorf("parse metadata xml: %w", err)
	}
	if strings.TrimSpace(doc.EntityID) == "" {
		return SAMLMetadataDraft{}, fmt.Errorf("metadata is missing EntityDescriptor entityID — is this an IdP metadata document?")
	}
	if len(doc.IDPSSODescriptor.SSOServices) == 0 {
		return SAMLMetadataDraft{}, fmt.Errorf("metadata is missing IDPSSODescriptor/SingleSignOnService — is this an IdP metadata document?")
	}

	ssoURL := pickPreferredSSO(doc)
	if ssoURL == "" {
		return SAMLMetadataDraft{}, fmt.Errorf("metadata has no SingleSignOnService for HTTP-Redirect or HTTP-POST bindings")
	}
	if !strings.HasPrefix(strings.ToLower(ssoURL), "https://") {
		return SAMLMetadataDraft{}, fmt.Errorf("metadata SingleSignOnService Location %q must be https://", ssoURL)
	}

	cert := pickSigningCertificate(doc)
	if cert == "" {
		return SAMLMetadataDraft{}, fmt.Errorf("metadata is missing a signing X509Certificate")
	}
	pemEncoded, err := wrapCertAsPEM(cert)
	if err != nil {
		return SAMLMetadataDraft{}, fmt.Errorf("metadata certificate invalid: %w", err)
	}

	return SAMLMetadataDraft{
		EntityID:       strings.TrimSpace(doc.EntityID),
		SSOURL:         ssoURL,
		CertificatePEM: pemEncoded,
	}, nil
}

// pickPreferredSSO returns the SingleSignOnService Location matching the most
// preferred binding. Identrail's ACS handler (PR-3) speaks both HTTP-Redirect
// and HTTP-POST; picking Redirect first matches the common SP-initiated flow.
func pickPreferredSSO(doc samlIdPMetadata) string {
	for _, binding := range []string{samlBindingHTTPRedirect, samlBindingHTTPPost} {
		for _, svc := range doc.IDPSSODescriptor.SSOServices {
			if strings.EqualFold(strings.TrimSpace(svc.Binding), binding) {
				if trimmed := strings.TrimSpace(svc.Location); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

// pickSigningCertificate returns the first X509Certificate value, preferring
// KeyDescriptors marked use="signing". Some IdPs (notably Azure AD) omit the
// use attribute and emit a single descriptor that serves both signing and
// encryption, so the fallback returns the first available certificate.
func pickSigningCertificate(doc samlIdPMetadata) string {
	var fallback string
	for _, kd := range doc.IDPSSODescriptor.KeyDescriptors {
		if len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
			continue
		}
		cert := strings.TrimSpace(kd.KeyInfo.X509Data.X509Certificates[0])
		if cert == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(kd.Use), "signing") || kd.Use == "" {
			if strings.EqualFold(strings.TrimSpace(kd.Use), "signing") {
				return cert
			}
			if fallback == "" {
				fallback = cert
			}
		}
	}
	return fallback
}

// wrapCertAsPEM converts a base64-encoded DER certificate body (the form
// X509Certificate elements use) into a canonical PEM block. Whitespace inside
// the base64 body is collapsed so the resulting PEM is parseable by
// crypto/x509 without further preprocessing.
func wrapCertAsPEM(b64Body string) (string, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, b64Body)
	if cleaned == "" {
		return "", fmt.Errorf("certificate body is empty")
	}
	if _, err := base64.StdEncoding.DecodeString(cleaned); err != nil {
		return "", fmt.Errorf("certificate base64 is invalid: %w", err)
	}
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	// PEM bodies are 64-column wrapped per RFC 7468.
	for i := 0; i < len(cleaned); i += 64 {
		end := i + 64
		if end > len(cleaned) {
			end = len(cleaned)
		}
		b.WriteString(cleaned[i:end])
		b.WriteString("\n")
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return b.String(), nil
}

// FetchSAMLMetadataXML retrieves an IdP metadata document over HTTPS. The
// caller is expected to validate the returned draft via ParseSAMLMetadataXML.
// A 10-second timeout and a 256 KiB response cap keep an untrusted URL from
// stalling or overwhelming the API server.
func FetchSAMLMetadataXML(ctx context.Context, client *http.Client, metadataURL string) ([]byte, error) {
	parsed, err := url.Parse(strings.TrimSpace(metadataURL))
	if err != nil {
		return nil, fmt.Errorf("metadata_url is invalid: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("metadata_url must use https://")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("metadata_url has no host")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("metadata_url responded %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	if err != nil {
		return nil, fmt.Errorf("read metadata body: %w", err)
	}
	return body, nil
}

// NewSCIMBearerToken generates a fresh per-connection SCIM bearer token and
// returns both the plain token (returned once to the admin) and the SHA-256
// hex hash (persisted on the identity_connections row).
func NewSCIMBearerToken() (plain string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("read random bytes for scim token: %w", err)
	}
	plain = "idntr_scim_" + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(sum[:])
	return plain, hash, nil
}
