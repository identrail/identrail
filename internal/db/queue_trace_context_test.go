package db

import (
	"context"
	"testing"
)

func TestQueueTraceContextFromContextMissing(t *testing.T) {
	traceParent, traceState := QueueTraceContextFromContext(context.Background())
	if traceParent != "" || traceState != "" {
		t.Fatalf("expected empty queue trace context, got traceparent=%q tracestate=%q", traceParent, traceState)
	}
}

func TestWithQueueTraceContextStoresTrimmedValues(t *testing.T) {
	ctx := WithQueueTraceContext(context.Background(), "  trace-parent  ", "  congo=t61rcWkgMzE  ")
	traceParent, traceState := QueueTraceContextFromContext(ctx)
	if traceParent != "trace-parent" {
		t.Fatalf("unexpected traceparent %q", traceParent)
	}
	if traceState != "congo=t61rcWkgMzE" {
		t.Fatalf("unexpected tracestate %q", traceState)
	}
}
