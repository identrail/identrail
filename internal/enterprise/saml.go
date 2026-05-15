package enterprise

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SAMLConnectionStatus tracks the rollout state of a SAML connection.
type SAMLConnectionStatus string

const (
	SAMLConnectionPending  SAMLConnectionStatus = "pending"
	SAMLConnectionActive   SAMLConnectionStatus = "active"
	SAMLConnectionDisabled SAMLConnectionStatus = "disabled"
)

// SAMLConnection models a federated SAML identity provider trust between an
// Identrail organization and an external IdP. The certificate is stored as a
// PEM-encoded X.509 string so the operator can hot-rotate via update without
// touching DER blobs.
type SAMLConnection struct {
	ID               string               `json:"id"`
	OrganizationID   string               `json:"organization_id"`
	DisplayName      string               `json:"display_name"`
	EntityID         string               `json:"entity_id"`
	SSOURL           string               `json:"sso_url"`
	CertificatePEM   string               `json:"certificate_pem"`
	AttributeMapping AttributeMapping     `json:"attribute_mapping"`
	Status           SAMLConnectionStatus `json:"status"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

// AttributeMapping describes how IdP-provided SAML attributes map onto
// Identrail's internal user attributes. Empty values fall back to sensible
// defaults at the consumer.
type AttributeMapping struct {
	Email  string `json:"email"`
	Name   string `json:"name,omitempty"`
	Groups string `json:"groups,omitempty"`
}

// Validate enforces SAML connection invariants relevant for safe federation.
// The SSO URL must use https (the SAML POST binding embeds the assertion in
// the response body; plaintext transport would leak credentials), and the
// certificate must be a parseable X.509 PEM block.
func (c SAMLConnection) Validate() error {
	if strings.TrimSpace(c.OrganizationID) == "" {
		return fmt.Errorf("saml connection organization_id is required")
	}
	if strings.TrimSpace(c.EntityID) == "" {
		return fmt.Errorf("saml connection entity_id is required")
	}
	if err := validateHTTPSURL(c.SSOURL); err != nil {
		return fmt.Errorf("saml sso_url %q is invalid: %w", c.SSOURL, err)
	}
	if strings.TrimSpace(c.AttributeMapping.Email) == "" {
		return fmt.Errorf("saml attribute_mapping.email is required")
	}
	if !validSAMLConnectionStatus(c.Status) {
		return fmt.Errorf("saml connection status %q is not recognized", c.Status)
	}
	if _, err := ParseSAMLCertificate(c.CertificatePEM); err != nil {
		return fmt.Errorf("saml certificate invalid: %w", err)
	}
	return nil
}

// ParseSAMLCertificate parses a PEM-encoded X.509 certificate and returns it.
// Exported so API and persistence layers can reuse the same parse path.
func ParseSAMLCertificate(pemEncoded string) (*x509.Certificate, error) {
	pemEncoded = strings.TrimSpace(pemEncoded)
	if pemEncoded == "" {
		return nil, fmt.Errorf("certificate_pem is empty")
	}
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, fmt.Errorf("certificate_pem is not a valid PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate_pem must contain a CERTIFICATE block, got %q", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x509 certificate: %w", err)
	}
	return cert, nil
}

// CanTransitionSAMLStatus reports whether a SAML connection may move from one
// status to another. Connections must enroll via pending → active before they
// can be disabled/re-enabled; jumping straight from pending to disabled is
// rejected so that a connection cannot be parked in a disabled state without
// ever having proved a successful IdP handshake.
func CanTransitionSAMLStatus(from, to SAMLConnectionStatus) bool {
	if !validSAMLConnectionStatus(from) || !validSAMLConnectionStatus(to) {
		return false
	}
	if from == to {
		return true
	}
	switch from {
	case SAMLConnectionPending:
		return to == SAMLConnectionActive
	case SAMLConnectionActive:
		return to == SAMLConnectionDisabled
	case SAMLConnectionDisabled:
		return to == SAMLConnectionActive
	}
	return false
}

func validSAMLConnectionStatus(s SAMLConnectionStatus) bool {
	switch s {
	case SAMLConnectionPending, SAMLConnectionActive, SAMLConnectionDisabled:
		return true
	}
	return false
}

func validateHTTPSURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("url is empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("url scheme must be https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("url host is empty")
	}
	return nil
}
