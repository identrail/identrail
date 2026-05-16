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
	"net"
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
// stalling or overwhelming the API server. The host is resolved up-front and
// any address resolving to loopback, link-local, multicast, broadcast,
// unspecified, or RFC1918/RFC4193 private ranges is refused — without that
// guard, an enterprise-write caller could turn this endpoint into an SSRF
// primitive against the API server's internal network.
func FetchSAMLMetadataXML(ctx context.Context, client *http.Client, metadataURL string) ([]byte, error) {
	parsed, err := url.Parse(strings.TrimSpace(metadataURL))
	if err != nil {
		return nil, fmt.Errorf("metadata_url is invalid: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("metadata_url must use https://")
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("metadata_url has no host")
	}
	if err := metadataHostGuard(ctx, host); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// Shallow-clone the client so installing CheckRedirect does not mutate
	// the caller's instance, then enforce the same scheme + host guard on
	// every redirect hop. Without this, a public-facing https endpoint could
	// 30x to a plain-http URL or to a private IP and bypass the up-front
	// guard, restoring the SSRF surface this fetcher is meant to close.
	guardedClient := *client
	guardedClient.CheckRedirect = checkMetadataRedirect
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	res, err := guardedClient.Do(req)
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

// checkMetadataRedirect runs the same scheme + host guard that gates the
// initial metadata_url request on every redirect hop. Without this, an
// attacker-controlled public https endpoint could 302 to plain http or to a
// private/loopback address and bypass the up-front SSRF guard. The standard
// library follows up to 10 redirects by default; we cap at 5 since IdP
// metadata endpoints in practice never redirect more than once.
func checkMetadataRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("metadata_url followed too many redirects (%d)", len(via))
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("metadata_url redirect to non-https scheme %q is not allowed", req.URL.Scheme)
	}
	host := req.URL.Hostname()
	if host == "" {
		return fmt.Errorf("metadata_url redirect has no host")
	}
	return metadataHostGuard(req.Context(), host)
}

// metadataResolver is the DNS resolver used by assertMetadataHostIsExternal.
// Tests override it with a deterministic in-memory resolver so the SSRF guard
// can be exercised without depending on real DNS.
var metadataResolver = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// metadataHostGuard is the SSRF guard called before issuing the metadata
// fetch. Production wiring uses assertMetadataHostIsExternal; tests that need
// to point at a httptest server (which binds to 127.0.0.1) swap in a no-op
// for the duration of the test.
var metadataHostGuard = assertMetadataHostIsExternal

// assertMetadataHostIsExternal refuses to fetch from a host that resolves to
// any address Identrail considers internal: loopback, link-local, multicast,
// broadcast, unspecified, or RFC1918/RFC4193 private ranges. The metadata
// fetcher is callable by enterprise.write actors, so without this an admin
// could probe the API server's internal network by pasting a metadata URL
// pointing at e.g. 169.254.169.254 (cloud metadata) or a private subnet.
func assertMetadataHostIsExternal(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		return rejectInternalIP(ip, host)
	}
	addrs, err := metadataResolver(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve metadata_url host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("metadata_url host %q resolved to no addresses", host)
	}
	for _, ip := range addrs {
		if err := rejectInternalIP(ip, host); err != nil {
			return err
		}
	}
	return nil
}

func rejectInternalIP(ip net.IP, host string) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("metadata_url host %q resolves to a loopback address (%s)", host, ip)
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return fmt.Errorf("metadata_url host %q resolves to a link-local address (%s)", host, ip)
	case ip.IsMulticast():
		return fmt.Errorf("metadata_url host %q resolves to a multicast address (%s)", host, ip)
	case ip.IsUnspecified():
		return fmt.Errorf("metadata_url host %q resolves to the unspecified address (%s)", host, ip)
	case ip.IsPrivate():
		return fmt.Errorf("metadata_url host %q resolves to a private address (%s)", host, ip)
	}
	// Reject IPv4 broadcast 255.255.255.255 explicitly; IsMulticast catches
	// only 224.0.0.0/4.
	if v4 := ip.To4(); v4 != nil && v4.Equal(net.IPv4bcast) {
		return fmt.Errorf("metadata_url host %q resolves to the broadcast address", host)
	}
	return nil
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
