package audit

import (
	"context"
	"strings"
	"testing"
)

func TestWithSinkAndSinkFromContext(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)
	got, ok := SinkFromContext(ctx)
	if !ok {
		t.Fatal("expected sink present")
	}
	if got != sink {
		t.Fatal("expected same sink instance")
	}
}

func TestWithSinkNilContext(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(nil, sink)
	got, ok := SinkFromContext(ctx)
	if !ok {
		t.Fatal("expected sink present")
	}
	if got != sink {
		t.Fatal("expected same sink instance")
	}
}

func TestWithSinkNilSinkFallsToNop(t *testing.T) {
	ctx := WithSink(context.Background(), nil)
	got, ok := SinkFromContext(ctx)
	if !ok {
		t.Fatal("expected sink present (NopAuditSink)")
	}
	if _, isNop := got.(NopAuditSink); !isNop {
		t.Fatal("expected NopAuditSink")
	}
}

func TestSinkFromContextNilContext(t *testing.T) {
	_, ok := SinkFromContext(nil)
	if ok {
		t.Fatal("expected no sink from nil context")
	}
}

func TestSinkFromContextMissing(t *testing.T) {
	_, ok := SinkFromContext(context.Background())
	if ok {
		t.Fatal("expected no sink from empty context")
	}
}

func TestWithCorrelationIDAndFromContext(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "req-123")
	id, ok := CorrelationIDFromContext(ctx)
	if !ok {
		t.Fatal("expected correlation id present")
	}
	if id != "req-123" {
		t.Fatalf("expected 'req-123', got %q", id)
	}
}

func TestWithCorrelationIDNilContext(t *testing.T) {
	ctx := WithCorrelationID(nil, "req-456")
	id, ok := CorrelationIDFromContext(ctx)
	if !ok {
		t.Fatal("expected correlation id present")
	}
	if id != "req-456" {
		t.Fatalf("expected 'req-456', got %q", id)
	}
}

func TestWithCorrelationIDEmptyIgnored(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "")
	_, ok := CorrelationIDFromContext(ctx)
	if ok {
		t.Fatal("expected no correlation id for empty input")
	}
}

func TestWithCorrelationIDWhitespaceIgnored(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "   ")
	_, ok := CorrelationIDFromContext(ctx)
	if ok {
		t.Fatal("expected no correlation id for whitespace input")
	}
}

func TestCorrelationIDFromContextNilContext(t *testing.T) {
	_, ok := CorrelationIDFromContext(nil)
	if ok {
		t.Fatal("expected no correlation id from nil context")
	}
}

func TestEnsureCorrelationIDPreservesExisting(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "existing-id")
	newCtx, id := EnsureCorrelationID(ctx)
	if id != "existing-id" {
		t.Fatalf("expected existing id, got %q", id)
	}
	got, ok := CorrelationIDFromContext(newCtx)
	if !ok || got != "existing-id" {
		t.Fatalf("expected existing id on context, got %q", got)
	}
}

func TestEnsureCorrelationIDGeneratesNew(t *testing.T) {
	ctx := context.Background()
	newCtx, id := EnsureCorrelationID(ctx)
	if id == "" {
		t.Fatal("expected non-empty generated id")
	}
	if len(id) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%q)", len(id), id)
	}
	got, ok := CorrelationIDFromContext(newCtx)
	if !ok || got != id {
		t.Fatalf("expected generated id on context, got %q", got)
	}
}

func TestEnsureCorrelationIDIsUnique(t *testing.T) {
	_, id1 := EnsureCorrelationID(context.Background())
	_, id2 := EnsureCorrelationID(context.Background())
	if id1 == id2 {
		t.Fatal("expected unique correlation ids")
	}
}

func TestWithActorAndActorFromContext(t *testing.T) {
	ctx := WithActor(context.Background(), "user:abc")
	actor, ok := ActorFromContext(ctx)
	if !ok {
		t.Fatal("expected actor present")
	}
	if actor != "user:abc" {
		t.Fatalf("expected 'user:abc', got %q", actor)
	}
}

func TestWithActorNilContext(t *testing.T) {
	ctx := WithActor(nil, "user:def")
	actor, ok := ActorFromContext(ctx)
	if !ok {
		t.Fatal("expected actor present")
	}
	if actor != "user:def" {
		t.Fatalf("expected 'user:def', got %q", actor)
	}
}

func TestWithActorEmptyIgnored(t *testing.T) {
	ctx := WithActor(context.Background(), "")
	_, ok := ActorFromContext(ctx)
	if ok {
		t.Fatal("expected no actor for empty input")
	}
}

func TestWithActorWhitespaceIgnored(t *testing.T) {
	ctx := WithActor(context.Background(), "   ")
	_, ok := ActorFromContext(ctx)
	if ok {
		t.Fatal("expected no actor for whitespace input")
	}
}

func TestActorFromContextNilContext(t *testing.T) {
	_, ok := ActorFromContext(nil)
	if ok {
		t.Fatal("expected no actor from nil context")
	}
}

func TestWriteActionWithSink(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)
	ctx = WithCorrelationID(ctx, "corr-001")
	ctx = WithActor(ctx, "user:test")

	WriteAction(ctx, AuditEvent{
		Action:      "tenancy.organization.upsert",
		TenantID:    "tenant-1",
		WorkspaceID: "workspace-1",
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Kind != "action" {
		t.Fatalf("expected kind=action, got %q", ev.Kind)
	}
	if ev.SchemaVersion != AuditSchemaVersion {
		t.Fatalf("expected schema version %q, got %q", AuditSchemaVersion, ev.SchemaVersion)
	}
	if ev.EventID == "" {
		t.Fatal("expected event id")
	}
	if ev.Service != "identrail" || ev.Component != "api" || ev.Category != "action" {
		t.Fatalf("expected normalized service/component/category, got %q/%q/%q", ev.Service, ev.Component, ev.Category)
	}
	if ev.CorrelationID != "corr-001" {
		t.Fatalf("expected correlation_id=corr-001, got %q", ev.CorrelationID)
	}
	if ev.Actor != "user:test" {
		t.Fatalf("expected actor=user:test, got %q", ev.Actor)
	}
	if ev.Action != "tenancy.organization.upsert" {
		t.Fatalf("expected action=tenancy.organization.upsert, got %q", ev.Action)
	}
	if ev.TenantID == "tenant-1" {
		t.Fatalf("expected tenant_id to be sanitized, got %q", ev.TenantID)
	}
	if !strings.HasPrefix(ev.TenantID, "fnv64a:") {
		t.Fatalf("expected hashed tenant_id, got %q", ev.TenantID)
	}
	if ev.WorkspaceID == "workspace-1" {
		t.Fatalf("expected workspace_id to be sanitized, got %q", ev.WorkspaceID)
	}
	if !strings.HasPrefix(ev.WorkspaceID, "fnv64a:") {
		t.Fatalf("expected hashed workspace_id, got %q", ev.WorkspaceID)
	}
	if ev.Timestamp.IsZero() {
		t.Fatal("expected non-zero timestamp")
	}
}

func TestWriteActionSanitizesSubjectActorAndResourceID(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)
	ctx = WithActor(ctx, "subject:user-123")

	WriteAction(ctx, AuditEvent{
		Action:      "test.action",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ResourceID:  "workspace-a",
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Actor == "subject:user-123" {
		t.Fatalf("expected subject actor to be sanitized, got %q", ev.Actor)
	}
	if !strings.HasPrefix(ev.Actor, "subject:fnv64a:") {
		t.Fatalf("expected hashed subject actor, got %q", ev.Actor)
	}
	if ev.ResourceID == "workspace-a" {
		t.Fatalf("expected resource id to be sanitized, got %q", ev.ResourceID)
	}
	if !strings.HasPrefix(ev.ResourceID, "fnv64a:") {
		t.Fatalf("expected hashed resource id, got %q", ev.ResourceID)
	}
}

func TestWriteActionRedactsPrefixShapedIdentifiers(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)
	ctx = WithActor(ctx, "subject:hmac256:alice@example.com")

	WriteAction(ctx, AuditEvent{
		Action:     "test.action",
		ResourceID: "fnv64a:not-a-real-fingerprint",
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Actor == "subject:hmac256:alice@example.com" {
		t.Fatalf("expected prefix-shaped subject actor to be re-fingerprinted, got %q", ev.Actor)
	}
	if strings.Contains(ev.Actor, "alice@example.com") {
		t.Fatalf("expected raw subject identifier to be absent, got %q", ev.Actor)
	}
	if ev.ResourceID == "fnv64a:not-a-real-fingerprint" {
		t.Fatalf("expected prefix-shaped resource id to be re-fingerprinted, got %q", ev.ResourceID)
	}
	if strings.Contains(ev.ResourceID, "not-a-real-fingerprint") {
		t.Fatalf("expected raw resource identifier to be absent, got %q", ev.ResourceID)
	}
}

func TestWriteActionUsesConfiguredFingerprinter(t *testing.T) {
	sink := &testRecordingAuditSink{}
	fingerprinter := NewFingerprinter("audit-secret")
	ctx := WithSink(context.Background(), sink)
	ctx = WithFingerprinter(ctx, fingerprinter)
	ctx = WithActor(ctx, "subject:test-user")

	WriteAction(ctx, AuditEvent{
		Action:      "test.action",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ResourceID:  "workspace-a",
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if !strings.HasPrefix(ev.Actor, "subject:hmac256:") {
		t.Fatalf("expected hmac actor fingerprint, got %q", ev.Actor)
	}
	if !strings.HasPrefix(ev.TenantID, "hmac256:") {
		t.Fatalf("expected hmac tenant identifier, got %q", ev.TenantID)
	}
	if !strings.HasPrefix(ev.WorkspaceID, "hmac256:") {
		t.Fatalf("expected hmac workspace identifier, got %q", ev.WorkspaceID)
	}
	if !strings.HasPrefix(ev.ResourceID, "hmac256:") {
		t.Fatalf("expected hmac resource identifier, got %q", ev.ResourceID)
	}
}

func TestWriteActionResourceIDCanNotBypassWithFingerprintShape(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)
	ctx = WithActor(ctx, "subject:user-123")

	rawResourceID := "fnv64a:0123456789ab"
	WriteAction(ctx, AuditEvent{
		Action:     "test.action",
		ResourceID: rawResourceID,
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.ResourceID == rawResourceID {
		t.Fatalf("expected fingerprint-shaped resource ID to be re-hashed, got %q", ev.ResourceID)
	}
	if strings.TrimSpace(ev.ResourceID) == "" {
		t.Fatal("expected non-empty resource identifier")
	}
}

func TestWriteActionSubjectActorCanNotBypassWithFingerprintShape(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)

	rawActor := "subject:fnv64a:0123456789ab"
	WriteAction(ctx, AuditEvent{
		Action: "test.action",
		Actor:  rawActor,
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Actor == rawActor {
		t.Fatalf("expected fingerprint-shaped subject actor to be re-hashed, got %q", ev.Actor)
	}
	if strings.TrimSpace(ev.Actor) == "" {
		t.Fatal("expected non-empty actor")
	}
}

func TestWriteActionNoSinkIsNoop(t *testing.T) {
	ctx := context.Background()
	WriteAction(ctx, AuditEvent{Action: "test.action"})
}

func TestWriteActionPreservesExistingFields(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)
	ctx = WithCorrelationID(ctx, "should-not-use")
	ctx = WithActor(ctx, "should-not-use")

	WriteAction(ctx, AuditEvent{
		Action:        "test.action",
		CorrelationID: "explicit-corr",
		Actor:         "explicit-actor",
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.CorrelationID != "explicit-corr" {
		t.Fatalf("expected explicit correlation id, got %q", ev.CorrelationID)
	}
	if ev.Actor != "explicit-actor" {
		t.Fatalf("expected explicit actor, got %q", ev.Actor)
	}
}

func TestWriteActionGeneratesCorrelationIDWhenMissing(t *testing.T) {
	sink := &testRecordingAuditSink{}
	ctx := WithSink(context.Background(), sink)

	WriteAction(ctx, AuditEvent{Action: "test.action"})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.CorrelationID == "" {
		t.Fatal("expected auto-generated correlation id")
	}
}
