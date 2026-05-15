package workflow

import (
	"context"
	"fmt"
	"time"
)

// Destination is one downstream workflow system that can receive lifecycle events.
type Destination interface {
	Name() string
	Send(ctx context.Context, event Event) error
}

// AuditSink records every dispatch attempt for governance traceability.
type AuditSink interface {
	Record(ctx context.Context, record DispatchRecord) error
}

// DispatchRecord captures one delivery attempt by the Router.
type DispatchRecord struct {
	EventKind   EventKind `json:"event_kind"`
	FindingID   string    `json:"finding_id"`
	Destination string    `json:"destination"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	AttemptedAt time.Time `json:"attempted_at"`
}

// RoutedDestination binds a Destination to its activation policy.
type RoutedDestination struct {
	Destination Destination
	Policy      AlertPolicy
}

// Router fans events out to all destinations whose policy admits them and
// forwards a DispatchRecord for each attempt to the AuditSink.
type Router struct {
	Destinations []RoutedDestination
	Audit        AuditSink
	// Now is injectable for deterministic tests; defaults to time.Now().UTC().
	Now func() time.Time
}

// Dispatch routes one event. Returns a record per destination considered and
// the first error encountered. Errors from one destination do not stop fan-out
// to the others; every attempted delivery is still recorded.
//
// Audit failures are surfaced through the returned error so callers can fail
// closed when the governance trail cannot be persisted. Nil destinations in
// the configured slice are skipped defensively and recorded as misconfiguration
// rather than panicking on Name()/Send().
func (r Router) Dispatch(ctx context.Context, event Event) ([]DispatchRecord, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	now := r.now()
	records := make([]DispatchRecord, 0, len(r.Destinations))
	var firstErr error
	for i, routed := range r.Destinations {
		if routed.Destination == nil {
			rec := DispatchRecord{
				EventKind:   event.Kind,
				FindingID:   event.Finding.ID,
				Destination: fmt.Sprintf("invalid-route-%d", i),
				AttemptedAt: now,
				Success:     false,
				Error:       "nil destination in router configuration",
			}
			if err := r.recordAudit(ctx, rec); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("audit sink: %w", err)
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("router: %s", rec.Error)
			}
			records = append(records, rec)
			continue
		}
		if !routed.Policy.Allow(event) {
			continue
		}
		rec := DispatchRecord{
			EventKind:   event.Kind,
			FindingID:   event.Finding.ID,
			Destination: routed.Destination.Name(),
			AttemptedAt: now,
		}
		if err := routed.Destination.Send(ctx, event); err != nil {
			rec.Success = false
			rec.Error = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", routed.Destination.Name(), err)
			}
		} else {
			rec.Success = true
		}
		if err := r.recordAudit(ctx, rec); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("audit sink: %w", err)
		}
		records = append(records, rec)
	}
	return records, firstErr
}

// recordAudit forwards a record to the configured AuditSink. Returns nil when
// no sink is configured; otherwise propagates the sink's error so dispatch can
// surface it.
func (r Router) recordAudit(ctx context.Context, record DispatchRecord) error {
	if r.Audit == nil {
		return nil
	}
	return r.Audit.Record(ctx, record)
}

func (r Router) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}
