package urlpolicy

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateAuditForwardURL validates outbound audit forward endpoints.
// HTTPS is always allowed; HTTP is only allowed for localhost loopback hosts.
func ValidateAuditForwardURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse audit forward url: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("insecure audit forward url scheme http is only allowed for localhost")
	default:
		return fmt.Errorf("unsupported audit forward url scheme %q", parsed.Scheme)
	}
}
