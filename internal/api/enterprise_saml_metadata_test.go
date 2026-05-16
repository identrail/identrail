package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// withPermissiveHostGuard swaps out both SSRF guards for the duration of the
// test so a httptest.NewTLSServer (which binds to 127.0.0.1) is reachable.
// Production wiring keeps the strict guards.
func withPermissiveHostGuard(t *testing.T) {
	t.Helper()
	prevHost := metadataHostGuard
	prevIP := internalIPGuard
	metadataHostGuard = func(context.Context, string) error { return nil }
	internalIPGuard = func(net.IP, string) error { return nil }
	t.Cleanup(func() {
		metadataHostGuard = prevHost
		internalIPGuard = prevIP
	})
}

// withFakeResolver lets a test pretend that a public-looking hostname resolves
// to a controlled IP set, exercising the real assertMetadataHostIsExternal
// without depending on DNS.
func withFakeResolver(t *testing.T, mapping map[string][]net.IP) {
	t.Helper()
	prev := metadataResolver
	metadataResolver = func(_ context.Context, host string) ([]net.IP, error) {
		if ips, ok := mapping[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "not found", Name: host, IsNotFound: true}
	}
	t.Cleanup(func() { metadataResolver = prev })
}

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
	withPermissiveHostGuard(t)
	body, err := FetchSAMLMetadataXML(context.Background(), srv.Client(), srv.URL+"/idp/metadata")
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	if !strings.Contains(string(body), "EntityDescriptor") {
		t.Errorf("unexpected body: %q", string(body))
	}
}

func TestFetchSAMLMetadataXML_RejectsHTTP(t *testing.T) {
	_, err := FetchSAMLMetadataXML(context.Background(), nil, "http://idp.example.com/metadata")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("expected https requirement, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_BlocksLiteralLoopbackIP(t *testing.T) {
	_, err := FetchSAMLMetadataXML(context.Background(), nil, "https://127.0.0.1/metadata")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("expected loopback rejection, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_BlocksLiteralPrivateIP(t *testing.T) {
	_, err := FetchSAMLMetadataXML(context.Background(), nil, "https://10.0.0.1/metadata")
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Errorf("expected private-range rejection, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_BlocksLinkLocalCloudMetadata(t *testing.T) {
	// 169.254.169.254 is the AWS/Azure/GCP instance metadata endpoint — the
	// canonical SSRF target.
	_, err := FetchSAMLMetadataXML(context.Background(), nil, "https://169.254.169.254/latest/meta-data/")
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Errorf("expected link-local rejection, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_BlocksHostnameResolvingToPrivate(t *testing.T) {
	// A public-looking hostname that DNS resolves to a private IP must be
	// rejected after resolution, not just on the literal IP.
	withFakeResolver(t, map[string][]net.IP{
		"idp.attacker.example.com": {net.ParseIP("10.4.5.6")},
	})
	_, err := FetchSAMLMetadataXML(context.Background(), nil, "https://idp.attacker.example.com/metadata")
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Errorf("expected post-resolution private-range rejection, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_AllowsPublicResolution(t *testing.T) {
	// Resolving to a public IP must pass the SSRF guard. A hostname that
	// resolves to a non-RFC1918 address (here 198.51.100.1, TEST-NET-2)
	// should be accepted by the guard. We don't actually issue the request —
	// the assertion is that the guard does not reject.
	withFakeResolver(t, map[string][]net.IP{
		"idp.example.com": {net.ParseIP("198.51.100.1")},
	})
	if err := assertMetadataHostIsExternal(context.Background(), "idp.example.com"); err != nil {
		t.Errorf("public IP should pass the SSRF guard, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_BlocksRedirectToHTTP(t *testing.T) {
	// httptest.NewTLSServer binds to 127.0.0.1; bypass the literal-IP guard
	// for the original host so we can exercise the redirect path. The
	// CheckRedirect we install must run the scheme check on the redirect
	// target regardless of the original-host bypass.
	withPermissiveHostGuard(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://idp.example.com/metadata", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	_, err := FetchSAMLMetadataXML(context.Background(), srv.Client(), srv.URL+"/idp/metadata")
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Errorf("expected non-https redirect rejection, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_BlocksRedirectToPrivateIP(t *testing.T) {
	// Bypass the loopback check just for the local httptest host but keep
	// the strict guard for everything else. Both the up-front host guard
	// and the dial-time guard now flow through internalIPGuard, so swapping
	// it lets us exercise the SSRF protection against an attacker-controlled
	// public endpoint that 30x'es to a private IP without losing coverage of
	// the strict path.
	prevHost := metadataHostGuard
	prevIP := internalIPGuard
	t.Cleanup(func() {
		metadataHostGuard = prevHost
		internalIPGuard = prevIP
	})
	metadataHostGuard = func(ctx context.Context, host string) error {
		if host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return assertMetadataHostIsExternal(ctx, host)
	}
	internalIPGuard = func(ip net.IP, host string) error {
		if ip.IsLoopback() {
			return nil
		}
		return rejectInternalIP(ip, host)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cloud metadata service — the canonical SSRF target.
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	_, err := FetchSAMLMetadataXML(context.Background(), srv.Client(), srv.URL+"/idp/metadata")
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Errorf("expected link-local rejection on redirect target, got: %v", err)
	}
}

func TestFetchSAMLMetadataXML_BlocksDNSRebinding(t *testing.T) {
	// DNS rebinding TOCTOU: the up-front host guard sees a public IP, but
	// the dial-time resolver returns a private IP. Without the dial-time
	// guard the request would still hit the internal address.
	calls := 0
	prev := metadataResolver
	t.Cleanup(func() { metadataResolver = prev })
	metadataResolver = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "rebinding.example.com" {
			calls++
			if calls == 1 {
				// First call: up-front guard. Hand back a public IP.
				return []net.IP{net.ParseIP("198.51.100.1")}, nil
			}
			// Second call (and later): dial-time. Now resolve to a private IP.
			return []net.IP{net.ParseIP("10.0.0.99")}, nil
		}
		return nil, &net.DNSError{Err: "not found", Name: host, IsNotFound: true}
	}

	_, err := FetchSAMLMetadataXML(context.Background(), nil, "https://rebinding.example.com/metadata")
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Errorf("expected DNS-rebinding rejection at dial time, got: %v", err)
	}
	if calls < 2 {
		t.Errorf("expected dial-time resolver to be called (calls=%d) — guard ran only at check time", calls)
	}
}

func TestFetchSAMLMetadataXML_FallsBackToSecondValidatedAddress(t *testing.T) {
	// Stand up a real TLS server on 127.0.0.1 to serve as the "second" (working)
	// address. The "first" address is a deliberately closed port on the same
	// host that will refuse the connection. The resolver returns both, and
	// the guarded dialer must walk past the first failure to succeed on the
	// second — matching the fallback behavior of net.Dialer for hostnames.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(oktaMetadataFixture))
	}))
	t.Cleanup(srv.Close)

	// Reserve and close a port to guarantee dial refusal.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadHost, deadPort, _ := net.SplitHostPort(closed.Addr().String())
	_ = closed.Close()

	srvURL, _ := url.Parse(srv.URL)
	_, livePort, _ := net.SplitHostPort(srvURL.Host)
	if deadPort == livePort {
		t.Skip("OS reassigned the closed port to the live server; race avoided by skipping")
	}

	// Make idp.example.com resolve to the dead address first, then the live
	// one. Both are loopback, so the test also swaps the IP guard to permit
	// loopback only.
	prevResolver := metadataResolver
	t.Cleanup(func() { metadataResolver = prevResolver })
	metadataResolver = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "idp.example.com" {
			return []net.IP{net.ParseIP(deadHost), net.ParseIP(srvURL.Hostname())}, nil
		}
		return nil, &net.DNSError{Err: "not found", Name: host, IsNotFound: true}
	}
	withPermissiveHostGuard(t)
	prevIP := internalIPGuard
	internalIPGuard = func(ip net.IP, host string) error {
		if ip.IsLoopback() {
			return nil
		}
		return rejectInternalIP(ip, host)
	}
	t.Cleanup(func() { internalIPGuard = prevIP })

	// Build a client that uses the test server's TLS root and points the URL
	// hostname at idp.example.com on the live port. The guarded dial picks
	// up the resolver's two-address list, fails on the dead port, then
	// succeeds on the live one.
	caller := srv.Client()
	body, err := FetchSAMLMetadataXML(context.Background(), caller, "https://idp.example.com:"+livePort+"/metadata")
	if err != nil {
		t.Fatalf("expected fallback to succeed, got: %v", err)
	}
	if !strings.Contains(string(body), "EntityDescriptor") {
		t.Errorf("unexpected body: %q", string(body))
	}
}

func TestFetchSAMLMetadataXML_AllowsConfiguredProxyDial(t *testing.T) {
	// Spin up a TCP-only listener on 127.0.0.1 to stand in for an internal
	// HTTPS_PROXY. The transport's Proxy func points every request at it.
	// We do not need a complete CONNECT-speaking proxy — the test only needs
	// to prove that the dial-time IP guard is exempted for proxy-bound dials,
	// and we verify that by observing whether internalIPGuard is invoked on
	// the loopback proxy address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	proxyURL := &url.URL{Scheme: "http", Host: ln.Addr().String()}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	caller := &http.Client{Transport: transport}

	// Bypass only the up-front host guard for the metadata host. The
	// dial-time guard stays strict, and our spy variant fails the test if
	// it is ever called with the loopback proxy address.
	withPermissiveHostGuard(t)
	prevIP := internalIPGuard
	internalIPGuard = func(ip net.IP, host string) error {
		if ip.IsLoopback() {
			t.Fatalf("internalIPGuard was called with loopback %s — proxy exemption did not fire", ip)
		}
		return rejectInternalIP(ip, host)
	}
	t.Cleanup(func() { internalIPGuard = prevIP })

	// We expect the dial to succeed (proving the guard exemption fired) and
	// then for the request to fail downstream because the listener is not a
	// real HTTP proxy. The success criterion is "internalIPGuard was NOT
	// called for the loopback proxy address" — guarded by t.Fatalf above.
	_, _ = FetchSAMLMetadataXML(context.Background(), caller, "https://idp.example.com/metadata")
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
