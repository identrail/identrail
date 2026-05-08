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
type fingerprinterContextKey struct{}

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

// WithFingerprinter stores an audit fingerprinter for action events.
func WithFingerprinter(ctx context.Context, fingerprinter *Fingerprinter) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, fingerprinterContextKey{}, fingerprinter)
}

// FingerprinterFromContext returns the configured fingerprinter when present.
func FingerprinterFromContext(ctx context.Context) (*Fingerprinter, bool) {
	if ctx == nil {
		return nil, false
	}
	value := ctx.Value(fingerprinterContextKey{})
	fingerprinter, ok := value.(*Fingerprinter)
	return fingerprinter, ok && fingerprinter != nil
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
	writeFingerprinter, _ := FingerprinterFromContext(updatedCtx)
	event.Actor = sanitizeActionActor(event.Actor, writeFingerprinter)
	event.TenantID = sanitizeActionScopeID(event.TenantID, writeFingerprinter)
	event.WorkspaceID = sanitizeActionScopeID(event.WorkspaceID, writeFingerprinter)
	event.ResourceID = sanitizeActionResourceID(event.ResourceID, writeFingerprinter)
	_ = sink.Write(updatedCtx, event)
}

func sanitizeActionActor(actor string, fingerprinter *Fingerprinter) string {
	normalized := strings.TrimSpace(actor)
	if normalized == "" {
		return ""
	}
	lower := strings.ToLower(normalized)
	if strings.HasPrefix(lower, "subject:") {
		subjectID := strings.TrimSpace(normalized[len("subject:"):])
		if subjectID == "" {
			return "subject:"
		}
		return "subject:" + fingerprintActionIdentifier(fingerprinter, subjectID)
	}
	return normalized
}

func sanitizeActionResourceID(resourceID string, fingerprinter *Fingerprinter) string {
	normalized := strings.TrimSpace(resourceID)
	if normalized == "" {
		return ""
	}
	return fingerprintActionIdentifier(fingerprinter, normalized)
}

func sanitizeActionScopeID(scopeID string, fingerprinter *Fingerprinter) string {
	normalized := strings.TrimSpace(scopeID)
	if normalized == "" {
		return ""
	}
	return fingerprintActionIdentifier(fingerprinter, normalized)
}

func fingerprintActionIdentifier(fingerprinter *Fingerprinter, raw string) string {
	if fingerprinter != nil {
		return fingerprinter.Identifier(raw)
	}
	return FingerprintIdentifier(raw)
}

func isFingerprintIdentifier(value string) bool {
	normalized := strings.TrimSpace(value)
	lower := strings.ToLower(normalized)
	switch {
	case strings.HasPrefix(lower, "fnv64a:"):
		return isHexFingerprint(normalized[len("fnv64a:"):], 12)
	case strings.HasPrefix(lower, "hmac256:"):
		return isHexFingerprint(normalized[len("hmac256:"):], 24)
	default:
		return false
	}
}

func isHexFingerprint(value string, expectedLength int) bool {
	normalized := strings.TrimSpace(value)
	if len(normalized) != expectedLength {
		return false
	}
	_, err := hex.DecodeString(normalized)
	return err == nil
}
