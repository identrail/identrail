package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestMemoryEnterpriseAuthLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	user, err := store.UpsertUser(context.Background(), User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "admin@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert inviter: %v", err)
	}

	tokenHash := sha256.Sum256([]byte("invite-token"))
	invitation, err := store.CreateInvitation(ctx, Invitation{
		ID:              "22222222-2222-2222-2222-222222222222",
		OrgID:           "tenant-a",
		Email:           " New.User@Example.COM ",
		Role:            "admin",
		InvitedByUserID: user.ID,
		TokenHash:       tokenHash[:],
		ExpiresAt:       now.Add(24 * time.Hour),
		CreatedAt:       now,
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if invitation.Email != "new.user@example.com" || invitation.Role != "admin" {
		t.Fatalf("invitation was not normalized: %+v", invitation)
	}
	gotInvitation, err := store.GetInvitation(ctx, "tenant-a", invitation.ID)
	if err != nil {
		t.Fatalf("get invitation: %v", err)
	}
	if gotInvitation.ID != invitation.ID {
		t.Fatalf("unexpected invitation: %+v", gotInvitation)
	}
	invitations, err := store.ListInvitations(ctx, "tenant-a", 1)
	if err != nil {
		t.Fatalf("list invitations: %v", err)
	}
	if len(invitations) != 1 || invitations[0].ID != invitation.ID {
		t.Fatalf("unexpected invitations: %+v", invitations)
	}
	revoked, err := store.RevokeInvitation(ctx, "tenant-a", invitation.ID, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("expected revoked_at")
	}
	if _, err := store.RevokeInvitation(ctx, "tenant-a", invitation.ID, now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected already revoked invitation to be hidden, got %v", err)
	}
	if _, err := store.CreateInvitation(ctx, Invitation{
		ID:        "55555555-5555-5555-5555-555555555555",
		OrgID:     "tenant-a",
		Email:     "new.user@example.com",
		Role:      "admin",
		TokenHash: tokenHash[:],
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("create replacement invitation after revoke: %v", err)
	}
	if _, err := store.CreateInvitation(ctx, Invitation{
		ID:        "66666666-6666-6666-6666-666666666666",
		OrgID:     "tenant-a",
		Email:     "new.user@example.com",
		Role:      "viewer",
		TokenHash: tokenHash[:],
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now.Add(2 * time.Minute),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate pending invitation to return ErrConflict, got %v", err)
	}

	domain, err := store.CreateVerifiedDomain(ctx, VerifiedDomain{
		ID:                "33333333-3333-3333-3333-333333333333",
		OrgID:             "tenant-a",
		Domain:            ".Example.COM.",
		VerificationToken: "verify-token",
		CreatedAt:         now,
	})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	if domain.Domain != "example.com" || domain.VerificationMethod != "dns_txt" {
		t.Fatalf("domain was not normalized: %+v", domain)
	}
	domains, err := store.ListVerifiedDomains(ctx, "tenant-a", 0)
	if err != nil {
		t.Fatalf("list domains: %v", err)
	}
	if len(domains) != 1 || domains[0].ID != domain.ID {
		t.Fatalf("unexpected domains: %+v", domains)
	}
	gotDomain, err := store.GetVerifiedDomain(ctx, "tenant-a", domain.ID)
	if err != nil {
		t.Fatalf("get verified domain: %v", err)
	}
	if gotDomain.ID != domain.ID {
		t.Fatalf("unexpected verified domain: %+v", gotDomain)
	}
	if _, err := store.CreateVerifiedDomain(ctx, VerifiedDomain{
		ID:                "77777777-7777-7777-7777-777777777777",
		OrgID:             "tenant-a",
		Domain:            "example.com",
		VerificationToken: "verify-token-2",
		CreatedAt:         now.Add(time.Minute),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate verified domain to return ErrConflict, got %v", err)
	}

	connection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		ID:           "44444444-4444-4444-4444-444444444444",
		OrgID:        "tenant-a",
		Provider:     "WorkOS",
		Type:         "sso",
		Status:       "active",
		GroupRoleMap: map[string]string{" Engineering ": "admin", "bad": "nope"},
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create identity connection: %v", err)
	}
	if connection.Provider != "workos" || connection.GroupRoleMap["Engineering"] != "admin" {
		t.Fatalf("connection was not normalized: %+v", connection)
	}
	connections, err := store.ListIdentityConnections(ctx, "tenant-a", 0)
	if err != nil {
		t.Fatalf("list identity connections: %v", err)
	}
	if len(connections) != 1 || connections[0].ID != connection.ID {
		t.Fatalf("unexpected identity connections: %+v", connections)
	}
	gotConnection, err := store.GetIdentityConnection(ctx, "tenant-a", connection.ID)
	if err != nil {
		t.Fatalf("get identity connection: %v", err)
	}
	if gotConnection.ID != connection.ID {
		t.Fatalf("unexpected identity connection: %+v", gotConnection)
	}
	if _, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		ID:           "88888888-8888-8888-8888-888888888888",
		OrgID:        "tenant-a",
		Provider:     "workos",
		Type:         "sso",
		Status:       "pending",
		GroupRoleMap: map[string]string{},
		CreatedAt:    now.Add(time.Minute),
		UpdatedAt:    now.Add(time.Minute),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate identity connection to return ErrConflict, got %v", err)
	}

	scimConnection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		ID:                  "99999999-9999-9999-9999-999999999999",
		OrgID:               "tenant-a",
		Provider:            "saml",
		Type:                "directory_sync",
		Status:              "active",
		EntityID:            "https://idp.example.com/entity",
		SSOURL:              "https://idp.example.com/sso",
		CertificatePEM:      "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----",
		SCIMBearerTokenHash: "scim-token-hash",
		CreatedAt:           now.Add(2 * time.Minute),
		UpdatedAt:           now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create scim identity connection: %v", err)
	}
	gotSCIMConnection, err := store.GetIdentityConnectionBySCIMBearerTokenHash(ctx, " scim-token-hash ")
	if err != nil {
		t.Fatalf("get identity connection by scim hash: %v", err)
	}
	if gotSCIMConnection.ID != scimConnection.ID {
		t.Fatalf("unexpected scim connection: %+v", gotSCIMConnection)
	}
	if _, err := store.GetIdentityConnectionBySCIMBearerTokenHash(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing scim hash to return ErrNotFound, got %v", err)
	}
}

func TestEnterpriseAuthNormalizationRejectsInvalidInputs(t *testing.T) {
	now := time.Date(2026, 5, 12, 15, 0, 0, 0, time.UTC)
	tokenHash := sha256.Sum256([]byte("invite-token"))

	if _, err := NormalizeInvitationForWrite(Invitation{OrgID: "tenant-a", Email: "bad", Role: "admin", TokenHash: tokenHash[:], ExpiresAt: now}); err == nil {
		t.Fatal("expected invalid invitation email to fail")
	}
	if _, err := NormalizeInvitationForWrite(Invitation{OrgID: "tenant-a", Email: "user@example.com", Role: "owner", TokenHash: []byte("short"), ExpiresAt: now}); err == nil {
		t.Fatal("expected short invitation token hash to fail")
	}
	if _, err := NormalizeVerifiedDomainForWrite(VerifiedDomain{OrgID: "tenant-a", Domain: "https://example.com", VerificationToken: "token"}); err == nil {
		t.Fatal("expected invalid domain to fail")
	}
	if _, err := NormalizeIdentityConnectionForWrite(IdentityConnection{OrgID: "tenant-a", Provider: "unknown", Type: "sso"}); err == nil {
		t.Fatal("expected invalid identity provider to fail")
	}
}
