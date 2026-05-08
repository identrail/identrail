package config

import (
	"strings"
	"testing"
)

func TestValidateSecurityAcceptsNormalizedScopedAPIKeyScopes(t *testing.T) {
	cfg := Config{
		APIKeyScopes: map[string][]string{
			"reader-key": {" READ "},
			"writer-key": {" write ", "ADMIN"},
		},
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected mixed-case and padded scopes to validate, got %v", err)
	}
}

func TestValidateSecurityInvalidScopedAPIKeyErrorDoesNotLeakKeyOrScopeValue(t *testing.T) {
	const apiKey = "sensitive-api-key-value"
	const invalidScope = "dangerous-scope-value"

	cfg := Config{
		APIKeyScopes: map[string][]string{
			apiKey: {invalidScope},
		},
	}
	err := ValidateSecurity(cfg)
	if err == nil {
		t.Fatal("expected validation error")
	}
	errText := err.Error()
	if strings.Contains(errText, apiKey) {
		t.Fatalf("validation error leaked api key: %q", errText)
	}
	if strings.Contains(errText, invalidScope) {
		t.Fatalf("validation error leaked invalid scope value: %q", errText)
	}
}

func TestValidateSecurityScopedAPIKeyWithoutValidScopeErrorDoesNotLeakKey(t *testing.T) {
	const apiKey = "sensitive-empty-scope-key"

	cfg := Config{
		APIKeyScopes: map[string][]string{
			apiKey: {"   "},
		},
	}
	err := ValidateSecurity(cfg)
	if err == nil {
		t.Fatal("expected validation error")
	}
	errText := err.Error()
	if strings.Contains(errText, apiKey) {
		t.Fatalf("validation error leaked api key: %q", errText)
	}
}
