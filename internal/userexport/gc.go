package userexport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/db"
)

// GCStore is the subset of db.Store the GC pass needs.
type GCStore interface {
	ListUserDataExportsPendingPurge(ctx context.Context, now time.Time, limit int) ([]db.UserDataExport, error)
	MarkUserDataExportPurged(ctx context.Context, jobID string, now time.Time) (db.UserDataExport, error)
}

// GCRunner deletes bundle files whose retention window has elapsed and
// stamps the matching DB row purged. Designed to be invoked from the worker.
type GCRunner struct {
	Store     GCStore
	Storage   Storage
	Now       func() time.Time
	BatchSize int
}

// GCResult reports what one pass did.
type GCResult struct {
	Examined int
	Purged   int
	Errors   int
}

// RunOnce processes one batch of pending-purge jobs.
func (g *GCRunner) RunOnce(ctx context.Context) (GCResult, error) {
	if g == nil {
		return GCResult{}, errors.New("userexport: gc runner is nil")
	}
	if g.Store == nil || g.Storage == nil {
		return GCResult{}, errors.New("userexport: gc runner is missing dependencies")
	}
	now := time.Now().UTC()
	if g.Now != nil {
		now = g.Now().UTC()
	}
	batchSize := g.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	pending, err := g.Store.ListUserDataExportsPendingPurge(ctx, now, batchSize)
	if err != nil {
		return GCResult{}, fmt.Errorf("list pending purge: %w", err)
	}
	result := GCResult{Examined: len(pending)}
	for _, job := range pending {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		// Delete the file first. If MarkUserDataExportPurged fails afterward,
		// the next pass picks the row up again and Delete is a no-op for a
		// missing file — net effect is one retried DB write, no leaked bytes.
		key := StorageKey(job)
		if delErr := g.Storage.Delete(key); delErr != nil {
			result.Errors++
			continue
		}
		if _, markErr := g.Store.MarkUserDataExportPurged(ctx, job.ID, now); markErr != nil {
			result.Errors++
			continue
		}
		result.Purged++
	}
	return result, nil
}
