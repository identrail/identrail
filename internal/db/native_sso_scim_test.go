package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------- NormalizeIdentityConnectionForWrite: SAML completeness ----------

func TestNormalize_AcceptsLegacyWorkOSSAML(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	connection, err := NormalizeIdentityConnectionForWrite(IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_123",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("legacy WorkOS-SAML row rejected: %v", err)
	}
	if connection.EntityID != "" || connection.SSOURL != "" || connection.CertificatePEM != "" {
		t.Errorf("native fields should remain zero for WorkOS-SAML row: %+v", connection)
	}
}

func TestNormalize_AcceptsNativeSAML(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	connection, err := NormalizeIdentityConnectionForWrite(IdentityConnection{
		OrgID:          "tenant-a",
		Provider:       "saml",
		Type:           "sso",
		Status:         "pending",
		EntityID:       "https://idp.example.com/entity",
		SSOURL:         "https://idp.example.com/sso",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
		AttributeMapping: map[string]string{
			"email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("native SAML row rejected: %v", err)
	}
	if !connection.IsNativeSAML() {
		t.Errorf("IsNativeSAML should be true, got: %+v", connection)
	}
	if connection.AttributeMapping["email"] == "" {
		t.Errorf("attribute mapping not preserved: %+v", connection.AttributeMapping)
	}
}

func TestNormalize_RejectsHalfConfiguredNativeSAML(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		mutate  func(*IdentityConnection)
		wantMsg string
	}{
		{
			"missing_entity_id",
			func(c *IdentityConnection) { c.EntityID = "" },
			"entity_id",
		},
		{
			"missing_cert",
			func(c *IdentityConnection) { c.CertificatePEM = "" },
			"certificate_pem",
		},
		{
			"missing_sso_url",
			func(c *IdentityConnection) { c.SSOURL = "" },
			"sso_url",
		},
		{
			"http_sso_url",
			func(c *IdentityConnection) { c.SSOURL = "http://idp.example.com/sso" },
			"https",
		},
		{
			// Without a host, the URL is unusable for SAML redirects even
			// though it has the https:// prefix.
			"https_no_host",
			func(c *IdentityConnection) { c.SSOURL = "https:///path" },
			"host",
		},
		{
			// Malformed percent-encoding: parses as an error, not a usable URL.
			"https_invalid_url",
			func(c *IdentityConnection) { c.SSOURL = "https://%zz" },
			"valid",
		},
		{
			// Port-only authority: parsed.Host == ":443" is non-empty, but
			// parsed.Hostname() correctly returns "" so we reject it.
			"https_port_only_authority",
			func(c *IdentityConnection) { c.SSOURL = "https://:443/sso" },
			"host",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := IdentityConnection{
				OrgID:          "tenant-a",
				Provider:       "saml",
				Type:           "sso",
				Status:         "pending",
				EntityID:       "https://idp.example.com/entity",
				SSOURL:         "https://idp.example.com/sso",
				CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
				CreatedAt:      now,
			}
			tc.mutate(&base)
			_, err := NormalizeIdentityConnectionForWrite(base)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error should mention %q, got: %v", tc.wantMsg, err)
			}
		})
	}
}

func TestNormalize_RejectsMixedModeSAML(t *testing.T) {
	// A WorkOS-backed SAML row must not also carry native fields, otherwise it
	// is ambiguous which protocol path owns the connection at runtime.
	_, err := NormalizeIdentityConnectionForWrite(IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_123",
		EntityID:           "https://idp.example.com/entity",
	})
	if err == nil {
		t.Fatal("expected mixed-mode SAML row to be rejected")
	}
	if !strings.Contains(err.Error(), "cannot set native fields") {
		t.Errorf("error should call out mixed mode, got: %v", err)
	}
}

func TestNormalize_NonSAMLProvidersIgnoreNativeFields(t *testing.T) {
	// A workos or oidc provider does not need native SAML fields, so leaving
	// them empty must remain valid.
	for _, provider := range []string{"workos", "oidc"} {
		t.Run(provider, func(t *testing.T) {
			_, err := NormalizeIdentityConnectionForWrite(IdentityConnection{
				OrgID:    "tenant-a",
				Provider: provider,
				Type:     "sso",
				Status:   "pending",
			})
			if err != nil {
				t.Errorf("%s provider rejected: %v", provider, err)
			}
		})
	}
}

func TestNormalize_DefaultsJITProvisioningDisabled(t *testing.T) {
	connection, err := NormalizeIdentityConnectionForWrite(IdentityConnection{
		OrgID:    "tenant-a",
		Provider: "workos",
		Type:     "sso",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if connection.JITProvisioningEnabled {
		t.Error("JIT provisioning must default to false")
	}
}

func TestNormalize_AttributeMappingTrimsAndDropsEmptyEntries(t *testing.T) {
	connection, err := NormalizeIdentityConnectionForWrite(IdentityConnection{
		OrgID:    "tenant-a",
		Provider: "workos",
		Type:     "sso",
		AttributeMapping: map[string]string{
			"email":  "  http://schemas/email  ",
			"":       "discarded",
			"name":   "",
			"groups": "http://schemas/groups",
		},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if connection.AttributeMapping["email"] != "http://schemas/email" {
		t.Errorf("email mapping should be trimmed: %q", connection.AttributeMapping["email"])
	}
	if _, ok := connection.AttributeMapping[""]; ok {
		t.Error("empty key should be dropped")
	}
	if _, ok := connection.AttributeMapping["name"]; ok {
		t.Error("empty value should be dropped")
	}
}

// ---------- SCIM provisioning events: memory CRUD ----------

func TestMemoryStore_SCIMProvisioningEventLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	connection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "directory_sync",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_123",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	first, err := store.CreateSCIMProvisioningEvent(ctx, SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: connection.ID,
		Op:           "create",
		ExternalID:   "okta-user-1",
		Payload:      map[string]any{"userName": "alice@example.com"},
		OccurredAt:   now,
	})
	if err != nil {
		t.Fatalf("create scim event: %v", err)
	}
	second, err := store.CreateSCIMProvisioningEvent(ctx, SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: connection.ID,
		Op:           "deactivate",
		ExternalID:   "okta-user-1",
		OccurredAt:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create second scim event: %v", err)
	}

	events, err := store.ListSCIMProvisioningEvents(ctx, "tenant-a", connection.ID, 10)
	if err != nil {
		t.Fatalf("list scim events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("event count: want 2, got %d", len(events))
	}
	// Newest first.
	if events[0].ID != second.ID {
		t.Errorf("expected newest event first, got %+v", events[0])
	}
	if events[1].ID != first.ID {
		t.Errorf("expected oldest event second, got %+v", events[1])
	}
}

func TestMemoryStore_SCIMProvisioningEvent_RejectsUnknownUser(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	connection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "directory_sync",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_123",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	// Postgres FK on users(id) rejects events that reference a non-existent
	// user; memory store must enforce the same contract.
	_, err = store.CreateSCIMProvisioningEvent(ctx, SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: connection.ID,
		Op:           "create",
		UserID:       "99999999-9999-9999-9999-999999999999",
		OccurredAt:   now,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown user, got: %v", err)
	}
}

func TestMemoryStore_SCIMProvisioningEvent_RejectsCrossTenantConnection(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	ctxA := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	ctxB := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	if err := store.UpsertOrganization(ctxA, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org A: %v", err)
	}
	if err := store.UpsertOrganization(ctxB, TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("upsert org B: %v", err)
	}
	connectionB, err := store.CreateIdentityConnection(ctxB, IdentityConnection{
		OrgID:              "tenant-b",
		Provider:           "saml",
		Type:               "directory_sync",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_b",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create connection B: %v", err)
	}

	// Attempt to forge an event under tenant A that references tenant B's
	// connection. Must be rejected — this is the cross-tenant exploit the
	// composite FK closes in Postgres.
	_, err = store.CreateSCIMProvisioningEvent(ctxA, SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: connectionB.ID,
		Op:           "create",
		OccurredAt:   now,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected cross-tenant connection reference to be rejected, got: %v", err)
	}
}

func TestMemoryStore_SCIMProvisioningEvent_RejectsUnknownConnection(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	_, err := store.CreateSCIMProvisioningEvent(ctx, SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: "99999999-9999-9999-9999-999999999999",
		Op:           "create",
		OccurredAt:   time.Now(),
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown connection, got: %v", err)
	}
}

func TestMemoryStore_UpdateIdentityConnection_PreservesSCIMTokenWhenOmitted(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	created, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:               "tenant-a",
		Provider:            "saml",
		Type:                "sso",
		Status:              "active",
		WorkOSConnectionID:  "conn_workos_abc",
		SCIMBearerTokenHash: "test-hash-placeholder",
		CreatedAt:           now,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// PUT-style update that does not carry the token hash — must NOT clear it.
	updateInput := created
	updateInput.SCIMBearerTokenHash = ""
	updated, err := store.UpdateIdentityConnection(ctx, updateInput)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.SCIMBearerTokenHash != "test-hash-placeholder" {
		t.Errorf("update must preserve existing SCIM token hash when caller omits it, got %q", updated.SCIMBearerTokenHash)
	}
}

func TestMemoryStore_UpdateIdentityConnection_RejectsUniquenessCollision(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	first, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_first",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	second, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "directory_sync",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_second",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	// Try to update `second` to collide with `first` on workos_connection_id.
	collision := second
	collision.WorkOSConnectionID = first.WorkOSConnectionID
	if _, err := store.UpdateIdentityConnection(ctx, collision); !errors.Is(err, ErrConflict) {
		t.Errorf("update colliding workos_connection_id must return ErrConflict, got %v", err)
	}
	// And the (org+provider+type) tuple.
	tupleCollision := second
	tupleCollision.Type = first.Type
	if _, err := store.UpdateIdentityConnection(ctx, tupleCollision); !errors.Is(err, ErrConflict) {
		t.Errorf("update colliding (org+provider+type) must return ErrConflict, got %v", err)
	}
}

func TestMemoryStore_GetIdentityConnectionByID(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	created, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_lookup",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	found, err := store.GetIdentityConnectionByID(context.Background(), " "+created.ID+" ")
	if err != nil {
		t.Fatalf("lookup by id: %v", err)
	}
	if found.ID != created.ID || found.OrgID != "tenant-a" {
		t.Fatalf("unexpected lookup result: %+v", found)
	}
	if _, err := store.GetIdentityConnectionByID(context.Background(), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty id should return ErrNotFound, got %v", err)
	}
	if _, err := store.GetIdentityConnectionByID(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id should return ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_SAMLRelayStateLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	connection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_relay",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	created, err := store.CreateSAMLRelayState(context.Background(), SAMLRelayState{
		Handle:        " relay-handle ",
		ConnectionID:  connection.ID,
		SAMLRequestID: " _request-1 ",
		ReturnTo:      "/app/tenant-a/workspace-a",
		Intent:        "login",
		ExpiresAt:     now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create relay state: %v", err)
	}
	if created.Handle != "relay-handle" || created.SAMLRequestID != "_request-1" || created.CreatedAt.IsZero() {
		t.Fatalf("relay state was not normalized: %+v", created)
	}
	if _, err := store.CreateSAMLRelayState(context.Background(), created); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate relay handle should return ErrConflict, got %v", err)
	}

	consumed, err := store.ConsumeSAMLRelayState(context.Background(), " relay-handle ", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("consume relay state: %v", err)
	}
	if consumed.ConsumedAt == nil || !consumed.ConsumedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("consume timestamp not recorded: %+v", consumed)
	}
	if _, err := store.ConsumeSAMLRelayState(context.Background(), "relay-handle", now.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay should return ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_SAMLRelayStateRejectsUnknownConnectionAndExpiredRows(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	connection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_relay_expired",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := store.CreateSAMLRelayState(context.Background(), SAMLRelayState{
		Handle:        "orphan",
		ConnectionID:  "missing",
		SAMLRequestID: "_request-missing",
		ExpiresAt:     now.Add(10 * time.Minute),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown connection should return ErrNotFound, got %v", err)
	}
	if _, err := store.CreateSAMLRelayState(context.Background(), SAMLRelayState{
		Handle:        "expired",
		ConnectionID:  connection.ID,
		SAMLRequestID: "_request-expired",
		ExpiresAt:     now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("create expired relay state: %v", err)
	}
	if _, err := store.ConsumeSAMLRelayState(context.Background(), "expired", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired relay state should be pruned, got %v", err)
	}
}

func TestMemoryStore_OAuthTransactionLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	created, err := store.CreateOAuthTransaction(context.Background(), OAuthTransaction{
		Nonce:       " nonce-1 ",
		CookieToken: " cookie-token-1 ",
		Intent:      "login",
		ReturnTo:    "/app/welcome",
		ExpiresAt:   now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create oauth transaction: %v", err)
	}
	if created.Nonce != "nonce-1" || created.CookieToken != "cookie-token-1" || created.CreatedAt.IsZero() {
		t.Fatalf("oauth transaction was not normalized: %+v", created)
	}
	if _, err := store.CreateOAuthTransaction(context.Background(), created); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate nonce should return ErrConflict, got %v", err)
	}

	if _, err := store.ConsumeOAuthTransaction(context.Background(), "nonce-1", "wrong-cookie", now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cookie-token mismatch should return ErrNotFound, got %v", err)
	}

	consumed, err := store.ConsumeOAuthTransaction(context.Background(), " nonce-1 ", " cookie-token-1 ", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("consume oauth transaction: %v", err)
	}
	if consumed.ConsumedAt == nil || !consumed.ConsumedAt.Equal(now.Add(time.Minute)) || consumed.ReturnTo != "/app/welcome" {
		t.Fatalf("consume did not record state: %+v", consumed)
	}
	if _, err := store.ConsumeOAuthTransaction(context.Background(), "nonce-1", "cookie-token-1", now.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay should return ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_OAuthTransactionRejectsExpiredAndInvalidInput(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := store.CreateOAuthTransaction(context.Background(), OAuthTransaction{Nonce: "n", ExpiresAt: now.Add(time.Minute)}); err == nil {
		t.Fatal("missing cookie token should error")
	}
	if _, err := store.CreateOAuthTransaction(context.Background(), OAuthTransaction{Nonce: "n", CookieToken: "c"}); err == nil {
		t.Fatal("missing expires_at should error")
	}
	if _, err := store.CreateOAuthTransaction(context.Background(), OAuthTransaction{
		Nonce:       "expired",
		CookieToken: "cookie",
		ExpiresAt:   now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("create expired transaction: %v", err)
	}
	if _, err := store.ConsumeOAuthTransaction(context.Background(), "expired", "cookie", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired transaction should be pruned, got %v", err)
	}
}

func TestMemoryStore_WebhookEventIdempotency(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	wkEvent := func(provider, id string) WebhookEvent {
		return WebhookEvent{Provider: provider, EventID: id, EventType: "user.deleted"}
	}

	// First delivery claims the row and gets a non-empty claim token.
	st, tok1, err := store.BeginWebhookEvent(ctx, wkEvent("workos", " event_1 "), now)
	if err != nil || st != WebhookEventClaimed || tok1 == "" {
		t.Fatalf("first delivery should be claimed with a token, got %q tok=%q err=%v", st, tok1, err)
	}
	// A concurrent duplicate while still processing must be told to retry.
	st, tok, err := store.BeginWebhookEvent(ctx, wkEvent("workos", "event_1"), now.Add(time.Second))
	if err != nil || st != WebhookEventProcessing || tok != "" {
		t.Fatalf("in-flight duplicate should be processing with no token, got %q tok=%q err=%v", st, tok, err)
	}
	// A different provider with the same event id is independent.
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("github", "event_1"), now)
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("different provider should be claimed, got %q err=%v", st, err)
	}

	// A stale handler whose token no longer matches cannot complete the row.
	if err := store.CompleteWebhookEvent(ctx, "workos", "event_1", "not-the-token", now.Add(2*time.Second)); err != nil {
		t.Fatalf("complete with wrong token: %v", err)
	}
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("workos", "event_1"), now.Add(2*time.Second))
	if err != nil || st != WebhookEventProcessing {
		t.Fatalf("wrong-token complete must not mark processed, got %q err=%v", st, err)
	}
	// The real token completes it; duplicates then no-op.
	if err := store.CompleteWebhookEvent(ctx, "workos", "event_1", tok1, now.Add(2*time.Second)); err != nil {
		t.Fatalf("complete webhook event: %v", err)
	}
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("workos", "event_1"), now.Add(3*time.Second))
	if err != nil || st != WebhookEventProcessed {
		t.Fatalf("completed duplicate should be processed, got %q err=%v", st, err)
	}

	// A stale handler whose token no longer matches cannot delete the
	// successor's claim.
	st, tokA, err := store.BeginWebhookEvent(ctx, wkEvent("workos", "event_fence"), now)
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("expected claim, got %q err=%v", st, err)
	}
	st, tokB, err := store.BeginWebhookEvent(ctx, wkEvent("workos", "event_fence"), now.Add(WebhookProcessingReclaimAfter+time.Second))
	if err != nil || st != WebhookEventClaimed || tokB == tokA {
		t.Fatalf("stale reclaim should mint a new token, got %q tokA=%q tokB=%q err=%v", st, tokA, tokB, err)
	}
	if err := store.DeleteWebhookEvent(ctx, "workos", "event_fence", tokA); err != nil {
		t.Fatalf("delete with superseded token: %v", err)
	}
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("workos", "event_fence"), now.Add(WebhookProcessingReclaimAfter+2*time.Second))
	if err != nil || st != WebhookEventProcessing {
		t.Fatalf("superseded delete must not erase the successor's claim, got %q err=%v", st, err)
	}

	// Rolling back with the active token lets a retry reprocess.
	st, tokRB, err := store.BeginWebhookEvent(ctx, wkEvent("workos", "event_rollback"), now)
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("expected claim, got %q err=%v", st, err)
	}
	if err := store.DeleteWebhookEvent(ctx, "workos", "event_rollback", tokRB); err != nil {
		t.Fatalf("delete webhook event: %v", err)
	}
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("workos", "event_rollback"), now.Add(time.Second))
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("after rollback the event should be claimable again, got %q err=%v", st, err)
	}

	// A 'processing' row left by a crashed instance is reclaimable once stale.
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("workos", "event_stale"), now)
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("expected claim, got %q err=%v", st, err)
	}
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("workos", "event_stale"), now.Add(WebhookProcessingReclaimAfter-time.Second))
	if err != nil || st != WebhookEventProcessing {
		t.Fatalf("not-yet-stale claim should still be processing, got %q err=%v", st, err)
	}
	st, _, err = store.BeginWebhookEvent(ctx, wkEvent("workos", "event_stale"), now.Add(WebhookProcessingReclaimAfter+time.Second))
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("stale claim should be reclaimable, got %q err=%v", st, err)
	}

	if _, _, err := store.BeginWebhookEvent(ctx, WebhookEvent{Provider: "", EventID: "x"}, now); err == nil {
		t.Fatal("missing provider should error")
	}
	if _, _, err := store.BeginWebhookEvent(ctx, WebhookEvent{Provider: "workos", EventID: " "}, now); err == nil {
		t.Fatal("missing event id should error")
	}
}

func TestMemoryStore_WebhookEventRetentionPrune(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	// Claim and complete an event well in the past.
	st, tok, err := store.BeginWebhookEvent(ctx, WebhookEvent{Provider: "workos", EventID: "old"}, now)
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("seed old claim: %q err=%v", st, err)
	}
	if err := store.CompleteWebhookEvent(ctx, "workos", "old", tok, now); err != nil {
		t.Fatalf("complete old: %v", err)
	}

	// A later claim past the retention window prunes the stale row.
	later := now.Add(WebhookEventRetention + time.Hour)
	if st, _, err := store.BeginWebhookEvent(ctx, WebhookEvent{Provider: "workos", EventID: "new"}, later); err != nil || st != WebhookEventClaimed {
		t.Fatalf("later claim: %q err=%v", st, err)
	}

	// The pruned event id is treated as a fresh first delivery again, not as
	// an already-processed duplicate.
	st, _, err = store.BeginWebhookEvent(ctx, WebhookEvent{Provider: "workos", EventID: "old"}, later.Add(time.Minute))
	if err != nil || st != WebhookEventClaimed {
		t.Fatalf("expected pruned event to be claimable again, got %q err=%v", st, err)
	}
}

func TestMemoryStore_DeleteIdentityConnection_CascadesSCIMEvents(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	connection, err := store.CreateIdentityConnection(ctx, IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "directory_sync",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_abc",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := store.CreateSCIMProvisioningEvent(ctx, SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: connection.ID,
		Op:           "create",
		ExternalID:   "okta-1",
		OccurredAt:   now,
	}); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	if err := store.DeleteIdentityConnection(ctx, "tenant-a", connection.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	events, err := store.ListSCIMProvisioningEvents(ctx, "tenant-a", connection.ID, 10)
	if err != nil {
		t.Fatalf("list events post-delete: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("delete must cascade to SCIM events (Postgres ON DELETE CASCADE parity); got %d remaining", len(events))
	}
}

func TestNormalizeSCIMProvisioningEvent_RejectsUnknownOp(t *testing.T) {
	_, err := NormalizeSCIMProvisioningEventForWrite(SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: "33333333-3333-3333-3333-333333333333",
		Op:           "rename",
		OccurredAt:   time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid scim provisioning op") {
		t.Errorf("expected invalid op error, got: %v", err)
	}
}

func TestNormalizeSCIMProvisioningEvent_AssignsIDAndDefaultsPayload(t *testing.T) {
	event, err := NormalizeSCIMProvisioningEventForWrite(SCIMProvisioningEventRecord{
		OrgID:        "tenant-a",
		ConnectionID: "33333333-3333-3333-3333-333333333333",
		Op:           "create",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if event.ID == "" {
		t.Error("expected normalizer to assign id")
	}
	if event.Payload == nil {
		t.Error("expected payload to default to empty map")
	}
	if event.OccurredAt.IsZero() {
		t.Error("expected occurred_at to default to now")
	}
}
