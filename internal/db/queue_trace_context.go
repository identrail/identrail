package db

import (
	"context"
	"strings"
)

type queueTraceContextKey struct{}

type queueTraceContext struct {
	traceParent string
	traceState  string
}

// WithQueueTraceContext stores queue trace propagation headers in context.
func WithQueueTraceContext(ctx context.Context, traceParent string, traceState string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, queueTraceContextKey{}, queueTraceContext{
		traceParent: strings.TrimSpace(traceParent),
		traceState:  strings.TrimSpace(traceState),
	})
}

// QueueTraceContextFromContext returns queue trace propagation headers from context.
func QueueTraceContextFromContext(ctx context.Context) (string, string) {
	if ctx == nil {
		return "", ""
	}
	raw := ctx.Value(queueTraceContextKey{})
	stored, ok := raw.(queueTraceContext)
	if !ok {
		return "", ""
	}
	return strings.TrimSpace(stored.traceParent), strings.TrimSpace(stored.traceState)
}
