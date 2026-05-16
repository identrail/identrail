package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresEnterpriseAuthStores(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 16, 0, 0, 0, time.UTC)
	tokenHash := sha256.Sum256([]byte("invite-token"))

	mock.ExpectQuery("INSERT INTO invitations").
		WithArgs("11111111-1111-1111-1111-111111111111", "tenant-a", "user@example.com", "admin", "22222222-2222-2222-2222-222222222222", tokenHash[:], now.Add(24*time.Hour), sqlmock.AnyArg(), sqlmock.AnyArg(), now).
		WillReturnRows(postgresEnterpriseInvitationRows().AddRow("11111111-1111-1111-1111-111111111111", "tenant-a", "user@example.com", "admin", "22222222-2222-2222-2222-222222222222", tokenHash[:], now.Add(24*time.Hour), nil, nil, now))
	invitation, err := store.CreateInvitation(ctx, Invitation{
		ID:              "11111111-1111-1111-1111-111111111111",
		OrgID:           "tenant-a",
		Email:           "user@example.com",
		Role:            "admin",
		InvitedByUserID: "22222222-2222-2222-2222-222222222222",
		TokenHash:       tokenHash[:],
		ExpiresAt:       now.Add(24 * time.Hour),
		CreatedAt:       now,
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if invitation.ID == "" || invitation.InvitedByUserID == "" {
		t.Fatalf("unexpected invitation: %+v", invitation)
	}

	mock.ExpectQuery("FROM invitations").
		WithArgs("tenant-a", invitation.ID).
		WillReturnRows(postgresEnterpriseInvitationRows().AddRow(invitation.ID, "tenant-a", "user@example.com", "admin", "22222222-2222-2222-2222-222222222222", tokenHash[:], now.Add(24*time.Hour), nil, nil, now))
	gotInvitation, err := store.GetInvitation(ctx, "tenant-a", invitation.ID)
	if err != nil {
		t.Fatalf("get invitation: %v", err)
	}
	if gotInvitation.ID != invitation.ID {
		t.Fatalf("unexpected fetched invitation: %+v", gotInvitation)
	}

	mock.ExpectQuery("FROM invitations").
		WithArgs("tenant-a", 2).
		WillReturnRows(postgresEnterpriseInvitationRows().AddRow(invitation.ID, "tenant-a", "user@example.com", "admin", "22222222-2222-2222-2222-222222222222", tokenHash[:], now.Add(24*time.Hour), nil, nil, now))
	invitations, err := store.ListInvitations(ctx, "tenant-a", 2)
	if err != nil {
		t.Fatalf("list invitations: %v", err)
	}
	if len(invitations) != 1 || invitations[0].ID != invitation.ID {
		t.Fatalf("unexpected invitations: %+v", invitations)
	}

	mock.ExpectQuery("UPDATE invitations").
		WithArgs("tenant-a", invitation.ID, now.Add(time.Hour)).
		WillReturnRows(postgresEnterpriseInvitationRows().AddRow(invitation.ID, "tenant-a", "user@example.com", "admin", "22222222-2222-2222-2222-222222222222", tokenHash[:], now.Add(24*time.Hour), nil, now.Add(time.Hour), now))
	revoked, err := store.RevokeInvitation(ctx, "tenant-a", invitation.ID, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("expected revoked_at")
	}

	mock.ExpectQuery("INSERT INTO verified_domains").
		WithArgs("33333333-3333-3333-3333-333333333333", "tenant-a", "example.com", "verify-token", "dns_txt", sqlmock.AnyArg(), now).
		WillReturnRows(postgresEnterpriseDomainRows().AddRow("33333333-3333-3333-3333-333333333333", "tenant-a", "example.com", "verify-token", "dns_txt", nil, now))
	domain, err := store.CreateVerifiedDomain(ctx, VerifiedDomain{
		ID:                "33333333-3333-3333-3333-333333333333",
		OrgID:             "tenant-a",
		Domain:            "example.com",
		VerificationToken: "verify-token",
		CreatedAt:         now,
	})
	if err != nil {
		t.Fatalf("create verified domain: %v", err)
	}
	if domain.VerificationMethod != "dns_txt" {
		t.Fatalf("unexpected domain: %+v", domain)
	}

	mock.ExpectQuery("FROM verified_domains").
		WithArgs("tenant-a", domain.ID).
		WillReturnRows(postgresEnterpriseDomainRows().AddRow(domain.ID, "tenant-a", "example.com", "verify-token", "dns_txt", nil, now))
	gotDomain, err := store.GetVerifiedDomain(ctx, "tenant-a", domain.ID)
	if err != nil {
		t.Fatalf("get verified domain: %v", err)
	}
	if gotDomain.ID != domain.ID {
		t.Fatalf("unexpected fetched domain: %+v", gotDomain)
	}

	mock.ExpectQuery("FROM verified_domains").
		WithArgs("tenant-a", 5).
		WillReturnRows(postgresEnterpriseDomainRows().AddRow(domain.ID, "tenant-a", "example.com", "verify-token", "dns_txt", nil, now))
	domains, err := store.ListVerifiedDomains(ctx, "tenant-a", 5)
	if err != nil {
		t.Fatalf("list verified domains: %v", err)
	}
	if len(domains) != 1 || domains[0].ID != domain.ID {
		t.Fatalf("unexpected domains: %+v", domains)
	}

	mock.ExpectQuery("INSERT INTO identity_connections").
		WithArgs("44444444-4444-4444-4444-444444444444", "tenant-a", "workos", "sso", sqlmock.AnyArg(), "active", `{"Engineering":"admin"}`, true, false, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), `{}`, sqlmock.AnyArg(), now, now).
		WillReturnRows(postgresEnterpriseConnectionRows().AddRow("44444444-4444-4444-4444-444444444444", "tenant-a", "workos", "sso", nil, "active", []byte(`{"Engineering":"admin"}`), true, false, nil, nil, nil, []byte(`{}`), nil, now, now))
	connection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		ID:           "44444444-4444-4444-4444-444444444444",
		OrgID:        "tenant-a",
		Provider:     "workos",
		Type:         "sso",
		Status:       "active",
		GroupRoleMap: map[string]string{"Engineering": "admin"},
		SSORequired:  true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create identity connection: %v", err)
	}
	if connection.GroupRoleMap["Engineering"] != "admin" || !connection.SSORequired {
		t.Fatalf("unexpected connection: %+v", connection)
	}

	mock.ExpectQuery("FROM identity_connections").
		WithArgs("tenant-a", connection.ID).
		WillReturnRows(postgresEnterpriseConnectionRows().AddRow(connection.ID, "tenant-a", "workos", "sso", nil, "active", []byte(`{"Engineering":"admin"}`), true, false, nil, nil, nil, []byte(`{}`), nil, now, now))
	gotConnection, err := store.GetIdentityConnection(ctx, "tenant-a", connection.ID)
	if err != nil {
		t.Fatalf("get identity connection: %v", err)
	}
	if gotConnection.ID != connection.ID {
		t.Fatalf("unexpected fetched connection: %+v", gotConnection)
	}

	mock.ExpectQuery("FROM identity_connections").
		WithArgs("tenant-a", 10).
		WillReturnRows(postgresEnterpriseConnectionRows().AddRow(connection.ID, "tenant-a", "workos", "sso", nil, "active", []byte(`{"Engineering":"admin"}`), true, false, nil, nil, nil, []byte(`{}`), nil, now, now))
	connections, err := store.ListIdentityConnections(ctx, "tenant-a", 10)
	if err != nil {
		t.Fatalf("list identity connections: %v", err)
	}
	if len(connections) != 1 || connections[0].ID != connection.ID {
		t.Fatalf("unexpected connections: %+v", connections)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresEnterpriseAuthMissingRecordsReturnNotFound(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()

	mock.ExpectQuery("FROM invitations").
		WithArgs("tenant-a", "11111111-1111-1111-1111-111111111111").
		WillReturnRows(postgresEnterpriseInvitationRows())
	if _, err := store.GetInvitation(ctx, "tenant-a", "11111111-1111-1111-1111-111111111111"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing invitation to return ErrNotFound, got %v", err)
	}

	mock.ExpectQuery("FROM verified_domains").
		WithArgs("tenant-a", "22222222-2222-2222-2222-222222222222").
		WillReturnRows(postgresEnterpriseDomainRows())
	if _, err := store.GetVerifiedDomain(ctx, "tenant-a", "22222222-2222-2222-2222-222222222222"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing verified domain to return ErrNotFound, got %v", err)
	}

	mock.ExpectQuery("FROM identity_connections").
		WithArgs("tenant-a", "33333333-3333-3333-3333-333333333333").
		WillReturnRows(postgresEnterpriseConnectionRows())
	if _, err := store.GetIdentityConnection(ctx, "tenant-a", "33333333-3333-3333-3333-333333333333"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing identity connection to return ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresEnterpriseAuthUniqueViolationsReturnConflict(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 17, 0, 0, 0, time.UTC)
	tokenHash := sha256.Sum256([]byte("invite-token"))

	mock.ExpectQuery("INSERT INTO invitations").
		WithArgs("11111111-1111-1111-1111-111111111111", "tenant-a", "user@example.com", "admin", "", tokenHash[:], now.Add(24*time.Hour), sqlmock.AnyArg(), sqlmock.AnyArg(), now).
		WillReturnError(testSQLStateError("23505"))
	if _, err := store.CreateInvitation(ctx, Invitation{
		ID:        "11111111-1111-1111-1111-111111111111",
		OrgID:     "tenant-a",
		Email:     "user@example.com",
		Role:      "admin",
		TokenHash: tokenHash[:],
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate invitation to return ErrConflict, got %v", err)
	}

	mock.ExpectQuery("INSERT INTO verified_domains").
		WithArgs("22222222-2222-2222-2222-222222222222", "tenant-a", "example.com", "verify-token", "dns_txt", sqlmock.AnyArg(), now).
		WillReturnError(testSQLStateError("23505"))
	if _, err := store.CreateVerifiedDomain(ctx, VerifiedDomain{
		ID:                "22222222-2222-2222-2222-222222222222",
		OrgID:             "tenant-a",
		Domain:            "example.com",
		VerificationToken: "verify-token",
		CreatedAt:         now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate verified domain to return ErrConflict, got %v", err)
	}

	mock.ExpectQuery("INSERT INTO identity_connections").
		WithArgs("33333333-3333-3333-3333-333333333333", "tenant-a", "workos", "sso", sqlmock.AnyArg(), "pending", `{}`, false, false, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), `{}`, sqlmock.AnyArg(), now, now).
		WillReturnError(testSQLStateError("23505"))
	if _, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		ID:        "33333333-3333-3333-3333-333333333333",
		OrgID:     "tenant-a",
		Provider:  "workos",
		Type:      "sso",
		CreatedAt: now,
		UpdatedAt: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate identity connection to return ErrConflict, got %v", err)
	}

	// UPDATE that violates the same UNIQUE constraint must also surface as
	// ErrConflict so the API can return 409 instead of 500.
	mock.ExpectQuery("UPDATE identity_connections").
		WillReturnError(testSQLStateError("23505"))
	if _, err := store.UpdateIdentityConnection(ctx, IdentityConnection{
		ID:        "33333333-3333-3333-3333-333333333333",
		OrgID:     "tenant-a",
		Provider:  "workos",
		Type:      "sso",
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected update unique-violation to return ErrConflict, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func postgresEnterpriseInvitationRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "org_id", "email", "role", "invited_by_user_id", "token_hash", "expires_at", "accepted_at", "revoked_at", "created_at"})
}

func postgresEnterpriseDomainRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "org_id", "domain", "verification_token", "verification_method", "verified_at", "created_at"})
}

func postgresEnterpriseConnectionRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "org_id", "provider", "type", "workos_connection_id", "status", "group_role_map",
		"sso_required", "jit_provisioning_enabled", "entity_id", "sso_url", "certificate_pem",
		"attribute_mapping", "scim_bearer_token_hash", "created_at", "updated_at",
	})
}

func postgresSCIMProvisioningEventRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "org_id", "connection_id", "op", "external_id", "user_id", "payload", "occurred_at"})
}
