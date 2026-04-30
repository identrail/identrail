package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/audit"
)

type recordingAuditSink struct {
	events []audit.AuditEvent
}

func (s *recordingAuditSink) Write(_ context.Context, event audit.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (*recordingAuditSink) Close() error { return nil }

func TestTenancyStoreEmitsAuditEventsWithoutSecrets(t *testing.T) {
	store := NewMemoryStore()
	sink := &recordingAuditSink{}

	ctx := context.Background()
	ctx = WithScope(ctx, Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	ctx = audit.WithSink(ctx, sink)
	ctx = audit.WithActor(ctx, "subject:test-user")

	secretMarker := "super-secret-value"

	if err := store.UpsertOrganization(ctx, TenancyOrganization{
		DisplayName: secretMarker,
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: secretMarker,
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}

	if len(sink.events) < 2 {
		t.Fatalf("expected audit events, got %d", len(sink.events))
	}

	for _, event := range sink.events {
		if strings.TrimSpace(event.Kind) != "action" {
			t.Fatalf("expected action audit kind, got %+v", event)
		}
		if event.CorrelationID == "" {
			t.Fatalf("expected correlation id, got %+v", event)
		}
		if event.Actor != "subject:test-user" {
			t.Fatalf("expected actor, got %+v", event)
		}
	}

	payload, err := json.Marshal(sink.events)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	if strings.Contains(string(payload), secretMarker) {
		t.Fatalf("expected audit payload to omit secrets, got %s", string(payload))
	}
}
