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

func TestPostgresConsumeSAMLRelayStatePrunesConsumedAndExpiredRows(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)
	createdAt := now.Add(-time.Minute)

	mock.ExpectQuery("UPDATE saml_relay_states").
		WithArgs("relay-handle", now).
		WillReturnRows(postgresSAMLRelayStateRows().AddRow(
			"relay-handle",
			"11111111-1111-1111-1111-111111111111",
			"_request-1",
			"/app",
			"login",
			expiresAt,
			now,
			createdAt,
		))
	mock.ExpectExec("DELETE FROM saml_relay_states").
		WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 2))

	state, err := store.ConsumeSAMLRelayState(ctx, "relay-handle", now)
	if err != nil {
		t.Fatalf("consume relay state: %v", err)
	}
	if state.Handle != "relay-handle" || state.ConsumedAt == nil {
		t.Fatalf("unexpected relay state: %+v", state)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresCreateSAMLRelayStateBypassesScopeAndMapsConflict(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 17, 11, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)

	mock.ExpectQuery("INSERT INTO saml_relay_states").
		WithArgs("relay-handle", "11111111-1111-1111-1111-111111111111", "_request-1", "/app", "login", expiresAt, now).
		WillReturnRows(postgresSAMLRelayStateRows().AddRow(
			"relay-handle",
			"11111111-1111-1111-1111-111111111111",
			"_request-1",
			"/app",
			"login",
			expiresAt,
			nil,
			now,
		))
	state, err := store.CreateSAMLRelayState(ctx, SAMLRelayState{
		Handle:        " relay-handle ",
		ConnectionID:  " 11111111-1111-1111-1111-111111111111 ",
		SAMLRequestID: " _request-1 ",
		ReturnTo:      "/app",
		Intent:        " login ",
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatalf("create relay state: %v", err)
	}
	if state.Handle != "relay-handle" || state.ConsumedAt != nil {
		t.Fatalf("unexpected relay state: %+v", state)
	}

	mock.ExpectQuery("INSERT INTO saml_relay_states").
		WillReturnError(testSQLStateError("23505"))
	if _, err := store.CreateSAMLRelayState(ctx, SAMLRelayState{
		Handle:        "duplicate",
		ConnectionID:  "11111111-1111-1111-1111-111111111111",
		SAMLRequestID: "_request-2",
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate relay should map to ErrConflict, got %v", err)
	}
	if _, err := store.CreateSAMLRelayState(ctx, SAMLRelayState{}); err == nil {
		t.Fatal("missing relay handle should be rejected")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresGetIdentityConnectionByIDBypassesScope(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 17, 11, 30, 0, 0, time.UTC)

	mock.ExpectQuery("FROM identity_connections").
		WithArgs("44444444-4444-4444-4444-444444444444").
		WillReturnRows(postgresEnterpriseConnectionRows().AddRow(
			"44444444-4444-4444-4444-444444444444",
			"tenant-a",
			"saml",
			"sso",
			nil,
			"active",
			[]byte(`{}`),
			false,
			true,
			"https://idp.example.com/entity",
			"https://idp.example.com/sso",
			"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
			[]byte(`{"email":"mail"}`),
			nil,
			now,
			now,
		))
	connection, err := store.GetIdentityConnectionByID(ctx, " 44444444-4444-4444-4444-444444444444 ")
	if err != nil {
		t.Fatalf("get identity connection by id: %v", err)
	}
	if connection.ID != "44444444-4444-4444-4444-444444444444" || connection.OrgID != "tenant-a" {
		t.Fatalf("unexpected connection: %+v", connection)
	}
	mock.ExpectQuery("FROM identity_connections").
		WithArgs("scim-token-hash").
		WillReturnRows(postgresEnterpriseConnectionRows().AddRow(
			"44444444-4444-4444-4444-444444444444",
			"tenant-a",
			"saml",
			"sso",
			nil,
			"active",
			[]byte(`{}`),
			false,
			true,
			"https://idp.example.com/entity",
			"https://idp.example.com/sso",
			"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
			[]byte(`{"email":"mail"}`),
			"scim-token-hash",
			now,
			now,
		))
	scimConnection, err := store.GetIdentityConnectionBySCIMBearerTokenHash(ctx, " scim-token-hash ")
	if err != nil {
		t.Fatalf("get identity connection by scim hash: %v", err)
	}
	if scimConnection.SCIMBearerTokenHash != "scim-token-hash" {
		t.Fatalf("unexpected scim connection: %+v", scimConnection)
	}
	mock.ExpectQuery("FROM identity_connections").
		WithArgs("duplicate-hash").
		WillReturnRows(postgresEnterpriseConnectionRows().
			AddRow(
				"55555555-5555-5555-5555-555555555555",
				"tenant-a",
				"saml",
				"sso",
				nil,
				"active",
				[]byte(`{}`),
				false,
				true,
				"https://idp.example.com/entity",
				"https://idp.example.com/sso",
				"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
				[]byte(`{"email":"mail"}`),
				"duplicate-hash",
				now,
				now,
			).
			AddRow(
				"66666666-6666-6666-6666-666666666666",
				"tenant-b",
				"saml",
				"sso",
				nil,
				"active",
				[]byte(`{}`),
				false,
				true,
				"https://idp2.example.com/entity",
				"https://idp2.example.com/sso",
				"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
				[]byte(`{"email":"mail"}`),
				"duplicate-hash",
				now,
				now,
			))
	if _, err := store.GetIdentityConnectionBySCIMBearerTokenHash(ctx, "duplicate-hash"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate scim hash should return ErrConflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresSCIMProvisioningEvents(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	eventID := "55555555-5555-5555-5555-555555555555"
	connectionID := "44444444-4444-4444-4444-444444444444"
	userID := "66666666-6666-6666-6666-666666666666"

	mock.ExpectQuery("INSERT INTO scim_provisioning_events").
		WithArgs(eventID, "tenant-a", connectionID, "create", sqlmock.AnyArg(), userID, `{"userName":"alice@example.com"}`, now).
		WillReturnRows(postgresSCIMProvisioningEventRows().AddRow(eventID, "tenant-a", connectionID, "create", "external-alice", userID, []byte(`{"userName":"alice@example.com"}`), now))
	event, err := store.CreateSCIMProvisioningEvent(ctx, SCIMProvisioningEventRecord{
		ID:           eventID,
		OrgID:        "tenant-a",
		ConnectionID: connectionID,
		Op:           "create",
		ExternalID:   "external-alice",
		UserID:       userID,
		Payload:      map[string]any{"userName": "alice@example.com"},
		OccurredAt:   now,
	})
	if err != nil {
		t.Fatalf("create scim event: %v", err)
	}
	if event.Payload["userName"] != "alice@example.com" {
		t.Fatalf("unexpected event: %+v", event)
	}

	mock.ExpectQuery("FROM scim_provisioning_events").
		WithArgs("tenant-a", connectionID, 5).
		WillReturnRows(postgresSCIMProvisioningEventRows().AddRow(eventID, "tenant-a", connectionID, "create", "external-alice", userID, []byte(`{"userName":"alice@example.com"}`), now))
	events, err := store.ListSCIMProvisioningEvents(ctx, "tenant-a", connectionID, 5)
	if err != nil {
		t.Fatalf("list scim events: %v", err)
	}
	if len(events) != 1 || events[0].ID != eventID {
		t.Fatalf("unexpected scim events: %+v", events)
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

func postgresSAMLRelayStateRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"handle", "connection_id", "saml_request_id", "return_to", "intent", "expires_at", "consumed_at", "created_at"})
}

func postgresOAuthTransactionRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"nonce", "cookie_token", "intent", "return_to", "expected_user_id", "expected_session_id", "expires_at", "consumed_at", "created_at"})
}

func TestPostgresConsumeOAuthTransactionMatchesCookieAndPrunes(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(10 * time.Minute)
	createdAt := now.Add(-time.Minute)

	mock.ExpectQuery("UPDATE oauth_transactions").
		WithArgs("nonce-1", "cookie-token-1", now).
		WillReturnRows(postgresOAuthTransactionRows().AddRow(
			"nonce-1", "cookie-token-1", "login", "/app/welcome", "", "", expiresAt, now, createdAt,
		))
	mock.ExpectExec("DELETE FROM oauth_transactions").
		WithArgs(now).
		WillReturnResult(sqlmock.NewResult(0, 3))

	txn, err := store.ConsumeOAuthTransaction(ctx, " nonce-1 ", " cookie-token-1 ", now)
	if err != nil {
		t.Fatalf("consume oauth transaction: %v", err)
	}
	if txn.Nonce != "nonce-1" || txn.ConsumedAt == nil || txn.ReturnTo != "/app/welcome" {
		t.Fatalf("unexpected oauth transaction: %+v", txn)
	}
	if _, err := store.ConsumeOAuthTransaction(ctx, "nonce-1", "", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty cookie token should return ErrNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresCreateOAuthTransactionBypassesScopeAndMapsConflict(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 11, 0, 0, 0, time.UTC)
	expiresAt := now.Add(10 * time.Minute)

	mock.ExpectQuery("INSERT INTO oauth_transactions").
		WithArgs("nonce-1", "cookie-token-1", "login", "/app", "", "", expiresAt, now).
		WillReturnRows(postgresOAuthTransactionRows().AddRow(
			"nonce-1", "cookie-token-1", "login", "/app", "", "", expiresAt, nil, now,
		))
	txn, err := store.CreateOAuthTransaction(ctx, OAuthTransaction{
		Nonce:       " nonce-1 ",
		CookieToken: " cookie-token-1 ",
		Intent:      " login ",
		ReturnTo:    "/app",
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create oauth transaction: %v", err)
	}
	if txn.Nonce != "nonce-1" || txn.ConsumedAt != nil {
		t.Fatalf("unexpected oauth transaction: %+v", txn)
	}

	mock.ExpectQuery("INSERT INTO oauth_transactions").
		WillReturnError(testSQLStateError("23505"))
	if _, err := store.CreateOAuthTransaction(ctx, OAuthTransaction{
		Nonce:       "duplicate",
		CookieToken: "cookie-token-2",
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate nonce should map to ErrConflict, got %v", err)
	}
	if _, err := store.CreateOAuthTransaction(ctx, OAuthTransaction{}); err == nil {
		t.Fatal("missing nonce should be rejected")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func postgresSCIMProvisioningEventRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "org_id", "connection_id", "op", "external_id", "user_id", "payload", "occurred_at"})
}
