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
// the first delivery error encountered. Errors from one destination do not
// stop fan-out to the others; every attempted delivery is still recorded.
func (r Router) Dispatch(ctx context.Context, event Event) ([]DispatchRecord, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	now := r.now()
	records := make([]DispatchRecord, 0, len(r.Destinations))
	var firstErr error
	for _, routed := range r.Destinations {
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
		if r.Audit != nil {
			_ = r.Audit.Record(ctx, rec)
		}
		records = append(records, rec)
	}
	return records, firstErr
}

func (r Router) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}
