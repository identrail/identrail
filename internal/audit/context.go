package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

type sinkContextKey struct{}
type correlationContextKey struct{}
type actorContextKey struct{}

// WithSink stores an audit sink on the context. Callers should treat sink write
// errors as non-fatal to business logic.
func WithSink(ctx context.Context, sink AuditSink) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if sink == nil {
		sink = NopAuditSink{}
	}
	return context.WithValue(ctx, sinkContextKey{}, sink)
}

// SinkFromContext returns the configured sink when present.
func SinkFromContext(ctx context.Context) (AuditSink, bool) {
	if ctx == nil {
		return nil, false
	}
	value := ctx.Value(sinkContextKey{})
	sink, ok := value.(AuditSink)
	return sink, ok && sink != nil
}

// WithCorrelationID stores a correlation ID on the context.
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := strings.TrimSpace(correlationID)
	if normalized == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationContextKey{}, normalized)
}

// CorrelationIDFromContext returns a correlation ID when present.
func CorrelationIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value := ctx.Value(correlationContextKey{})
	id, ok := value.(string)
	id = strings.TrimSpace(id)
	return id, ok && id != ""
}

// EnsureCorrelationID ensures a correlation ID exists on the returned context.
func EnsureCorrelationID(ctx context.Context) (context.Context, string) {
	if id, ok := CorrelationIDFromContext(ctx); ok {
		return ctx, id
	}
	// 128-bit random ID, hex encoded.
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to time-based identifier if entropy is unavailable.
		fallback := hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
		return WithCorrelationID(ctx, fallback), fallback
	}
	id := hex.EncodeToString(buf[:])
	return WithCorrelationID(ctx, id), id
}

// WithActor stores a stable, non-secret actor identifier on the context.
func WithActor(ctx context.Context, actor string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := strings.TrimSpace(actor)
	if normalized == "" {
		return ctx
	}
	return context.WithValue(ctx, actorContextKey{}, normalized)
}

// ActorFromContext returns the actor when present.
func ActorFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value := ctx.Value(actorContextKey{})
	actor, ok := value.(string)
	actor = strings.TrimSpace(actor)
	return actor, ok && actor != ""
}

// WriteAction writes an action audit event when a sink is configured on the context.
// Sink write failures are intentionally ignored by callers.
func WriteAction(ctx context.Context, event AuditEvent) {
	sink, ok := SinkFromContext(ctx)
	if !ok {
		return
	}
	updatedCtx, correlationID := EnsureCorrelationID(ctx)
	event.Kind = "action"
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.CorrelationID == "" {
		event.CorrelationID = correlationID
	}
	if event.Actor == "" {
		if actor, ok := ActorFromContext(updatedCtx); ok {
			event.Actor = actor
		}
	}
	_ = sink.Write(updatedCtx, event)
}
