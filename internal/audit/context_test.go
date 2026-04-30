package audit

import (
	"context"
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
		Action:   "tenancy.organization.upsert",
		TenantID: "tenant-1",
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Kind != "action" {
		t.Fatalf("expected kind=action, got %q", ev.Kind)
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
	if ev.TenantID != "tenant-1" {
		t.Fatalf("expected tenant_id=tenant-1, got %q", ev.TenantID)
	}
	if ev.Timestamp.IsZero() {
		t.Fatal("expected non-zero timestamp")
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
