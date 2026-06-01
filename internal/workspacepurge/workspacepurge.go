// Package workspacepurge runs the hard-delete pass for workspaces that have
// completed the 30-day soft-delete grace window from #1420. The package is
// deliberately small and depends only on the db.Store subset it needs — the
// worker, scheduler, and integration tests can drive it without pulling in
// unrelated API service surface, mirroring internal/userpurge's shape.
package workspacepurge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
)

// Store is the subset of db.Store the purge pass needs. Narrowing the
// interface keeps tests free of unrelated method stubs and makes the
// contract between this package and the database backend explicit.
type Store interface {
	ListWorkspacesPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]db.TenancyWorkspace, error)
	HardDeleteWorkspace(ctx context.Context, tenantID, workspaceID string, expectedDeletedAt time.Time, now time.Time) (db.TenancyWorkspace, error)
}

// Runner executes one hard-delete pass against a Store. Fields are public
// so the worker bootstrap can set them via struct literal; zero values
// fall back to safe defaults inside RunOnce so a misconfigured runner
// never sleeps 30 days or runs against an unbounded batch.
type Runner struct {
	Store     Store
	Now       func() time.Time
	BatchSize int
	// GracePeriod is the soft-delete-to-hard-delete window. Defaults to
	// db.WorkspaceDeletionGracePeriod when zero. Tests override it to
	// exercise boundary conditions without waiting 30 days of wall time.
	GracePeriod time.Duration
}

// Result reports what one pass did. Returned for telemetry — the runner
// already recorded structured audit events for each hard-delete it ran.
type Result struct {
	Examined int
	Purged   int
	Errors   int
}

// RunOnce processes one batch of workspaces past their grace deadline.
// Idempotent on the wall-clock-day boundary: a workspace whose row has
// already been purged is filtered out of ListWorkspacesPendingHardDelete
// by virtue of being gone, so re-running the pass against the same store
// state is a no-op (Examined=0, Purged=0).
func (r *Runner) RunOnce(ctx context.Context) (Result, error) {
	if r.Store == nil {
		return Result{}, errors.New("workspacepurge: store is required")
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	grace := r.GracePeriod
	if grace <= 0 {
		grace = db.WorkspaceDeletionGracePeriod
	}
	batchSize := r.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	cutoff := now.Add(-grace)
	pending, err := r.Store.ListWorkspacesPendingHardDelete(ctx, cutoff, batchSize)
	if err != nil {
		return Result{}, fmt.Errorf("list pending workspace hard deletes: %w", err)
	}
	result := Result{Examined: len(pending)}
	for _, workspace := range pending {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		// Defensive: the list query already filters by status='deleted'
		// AND deleted_at IS NOT NULL, but a future store implementation
		// that violates that contract would crash here on the nil
		// dereference. Skip the row instead and count it as an error.
		if workspace.DeletedAt == nil {
			result.Errors++
			continue
		}
		if _, hardErr := r.Store.HardDeleteWorkspace(ctx, workspace.TenantID, workspace.WorkspaceID, *workspace.DeletedAt, now); hardErr != nil {
			// A canceled / timed-out context surfaces through
			// HardDeleteWorkspace as an error on the dropped DB write.
			// Propagate it so the runner reports "interrupted" rather
			// than "completed with errors": a quiet Errors++ on the
			// last item would let a caller treat the pass as having
			// genuinely finished.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return result, ctxErr
			}
			result.Errors++
			audit.WriteAction(ctx, audit.AuditEvent{
				Action:       "tenancy.workspace.hard_delete",
				TenantID:     workspace.TenantID,
				WorkspaceID:  db.HardDeletedWorkspaceMarker(workspace.WorkspaceID),
				ResourceType: "tenancy_workspace",
				ResourceID:   db.HardDeletedWorkspaceMarker(workspace.WorkspaceID),
				Outcome:      "failure",
			})
			continue
		}
		result.Purged++
	}
	return result, nil
}
