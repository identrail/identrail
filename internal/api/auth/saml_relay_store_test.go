package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
)

func TestSAMLRelayStoreIssueAndConsume(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 17, 11, 0, 0, 0, time.UTC)
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	connection, err := store.CreateIdentityConnection(ctx, db.IdentityConnection{
		OrgID:              "tenant-a",
		Provider:           "saml",
		Type:               "sso",
		Status:             "active",
		WorkOSConnectionID: "conn_workos_relay_auth",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	relayStore := NewSAMLRelayStore(store, func() time.Time { return now })
	handle, err := relayStore.Issue(context.Background(), SAMLRelayEntry{
		ConnectionID:  connection.ID,
		SAMLRequestID: "_request-1",
		ReturnTo:      "/app/tenant-a/workspace-a",
		Intent:        "login",
	})
	if err != nil {
		t.Fatalf("issue relay: %v", err)
	}
	if len(handle) == 0 || len(handle) > 80 {
		t.Fatalf("unexpected relay handle length %d", len(handle))
	}
	entry, err := relayStore.Consume(context.Background(), handle)
	if err != nil {
		t.Fatalf("consume relay: %v", err)
	}
	if entry.ConnectionID != connection.ID || entry.SAMLRequestID != "_request-1" || entry.Intent != "login" {
		t.Fatalf("unexpected relay entry: %+v", entry)
	}
	if !entry.ExpiresAt.Equal(now.Add(defaultSAMLRelayTTL)) {
		t.Fatalf("unexpected default expiry: %v", entry.ExpiresAt)
	}
	if _, err := relayStore.Consume(context.Background(), handle); !errors.Is(err, ErrSAMLRelayHandleInvalid) {
		t.Fatalf("replayed relay should be invalid, got %v", err)
	}
}

func TestSAMLRelayStoreRejectsInvalidState(t *testing.T) {
	if _, err := (*SAMLRelayStore)(nil).Issue(context.Background(), SAMLRelayEntry{}); !errors.Is(err, ErrSAMLRelayHandleInvalid) {
		t.Fatalf("nil store issue should be invalid, got %v", err)
	}
	if _, err := (*SAMLRelayStore)(nil).Consume(context.Background(), "handle"); !errors.Is(err, ErrSAMLRelayHandleInvalid) {
		t.Fatalf("nil store consume should be invalid, got %v", err)
	}

	relayStore := NewSAMLRelayStore(db.NewMemoryStore(), nil)
	if _, err := relayStore.Consume(context.Background(), "missing"); !errors.Is(err, ErrSAMLRelayHandleInvalid) {
		t.Fatalf("missing relay should be invalid, got %v", err)
	}
}
