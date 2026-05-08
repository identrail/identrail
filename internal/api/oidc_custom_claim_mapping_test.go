package api

import (
	"context"
	"strings"
	"testing"
)

func TestOIDCTokenVerifierUsesConfiguredCustomClaimNames(t *testing.T) {
	verifier := &OIDCTokenVerifier{
		expectedIssuer: "https://issuer.example.com",
		expectedAud:    "identrail-api",
		tenantClaim:    "https://identrail.example/tenant",
		workspaceClaim: "https://identrail.example/workspace",
		groupsClaim:    "realm_groups",
		rolesClaim:     "realm_roles",
		verifier: fakeRawTokenVerifier{
			token: fakeClaimsDecoder{
				claims: map[string]any{
					"sub":                                 "subject-1",
					"iss":                                 "https://issuer.example.com",
					"aud":                                 []any{"identrail-api"},
					"https://identrail.example/tenant":    "tenant-custom",
					"https://identrail.example/workspace": "workspace-custom",
					"tenant_id":                           "tenant-default",
					"workspace_id":                        "workspace-default",
					"realm_groups":                        []any{"platform"},
					"realm_roles":                         []any{"owner"},
					"groups":                              []any{"ignored-group"},
					"roles":                               []any{"ignored-role"},
					"scope":                               "read write",
				},
			},
		},
	}

	token, err := verifier.VerifyToken(context.Background(), "token")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if token.TenantID != "tenant-custom" || token.WorkspaceID != "workspace-custom" {
		t.Fatalf("expected custom scope claims, got tenant=%q workspace=%q", token.TenantID, token.WorkspaceID)
	}
	if len(token.Groups) != 1 || token.Groups[0] != "platform" {
		t.Fatalf("expected custom groups claim, got %+v", token.Groups)
	}
	if len(token.Roles) != 1 || token.Roles[0] != "owner" {
		t.Fatalf("expected custom roles claim, got %+v", token.Roles)
	}
}

func TestOIDCTokenVerifierFailsWhenConfiguredCustomScopeClaimsAreMissing(t *testing.T) {
	verifier := &OIDCTokenVerifier{
		expectedIssuer: "https://issuer.example.com",
		expectedAud:    "identrail-api",
		tenantClaim:    "https://identrail.example/tenant",
		workspaceClaim: "https://identrail.example/workspace",
		groupsClaim:    "groups",
		rolesClaim:     "roles",
		verifier: fakeRawTokenVerifier{
			token: fakeClaimsDecoder{
				claims: map[string]any{
					"sub":          "subject-1",
					"iss":          "https://issuer.example.com",
					"aud":          "identrail-api",
					"tenant_id":    "tenant-default",
					"workspace_id": "workspace-default",
				},
			},
		},
	}

	_, err := verifier.VerifyToken(context.Background(), "token")
	if err == nil {
		t.Fatal("expected validation error for missing configured custom claims")
	}
	if !strings.Contains(err.Error(), "https://identrail.example/tenant") {
		t.Fatalf("expected missing custom tenant claim in error, got %v", err)
	}
}
