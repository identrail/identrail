// Package userpurge runs the hard-delete pass for accounts that have completed
// the soft-delete grace window. The pass is intentionally tiny — it lives in
// its own package so the worker, scheduler, and integration tests can drive it
// without pulling in unrelated API service surface.
package userpurge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
)

// Store is the subset of db.Store the purge pass needs. Narrowing the
// interface keeps tests free of unrelated method stubs.
type Store interface {
	ListUsersPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]db.User, error)
	HardDeleteUser(ctx context.Context, userID string, now time.Time) (db.User, error)
}

// Runner executes one hard-delete pass.
type Runner struct {
	Store     Store
	Now       func() time.Time
	BatchSize int
	// GracePeriod is the soft-delete-to-hard-delete window. Defaults to
	// db.UserDeletionGracePeriod when zero. Tests override it to exercise
	// boundary conditions without sleeping 30 days.
	GracePeriod time.Duration
}

// Result reports what one pass did. Returned for telemetry — the runner already
// recorded structured audit events for each hard-delete it executed.
type Result struct {
	Examined int
	Purged   int
	Errors   int
}

// RunOnce processes one batch of pending hard-deletes. It is idempotent: a row
// that has already been tombstoned is filtered out by ListUsersPendingHardDelete
// so re-running the pass on the same wall-clock time is a no-op.
func (r *Runner) RunOnce(ctx context.Context) (Result, error) {
	if r.Store == nil {
		return Result{}, errors.New("userpurge: store is required")
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	grace := r.GracePeriod
	if grace <= 0 {
		grace = db.UserDeletionGracePeriod
	}
	batchSize := r.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	cutoff := now.Add(-grace)
	pending, err := r.Store.ListUsersPendingHardDelete(ctx, cutoff, batchSize)
	if err != nil {
		return Result{}, fmt.Errorf("list pending hard deletes: %w", err)
	}
	result := Result{Examined: len(pending)}
	for _, user := range pending {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if _, hardErr := r.Store.HardDeleteUser(ctx, user.ID, now); hardErr != nil {
			// A canceled or timed-out context surfaces through HardDeleteUser
			// as an error on the dropped DB write. Propagate it so the runner
			// signals "interrupted" rather than "completed with errors": a
			// quiet "Errors++" on the last item would let a caller treat the
			// pass as having genuinely finished.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return result, ctxErr
			}
			result.Errors++
			audit.WriteAction(ctx, audit.AuditEvent{
				Action:       "auth.user.hard_delete",
				ResourceType: "user",
				ResourceID:   user.ID,
				Outcome:      "failure",
			})
			continue
		}
		result.Purged++
	}
	return result, nil
}
