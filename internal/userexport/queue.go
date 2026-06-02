package userexport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/db"
)

// QueueStore is the subset of db.Store the queue runner reads from.
type QueueStore interface {
	ClaimNextQueuedUserDataExport(ctx context.Context, now time.Time) (db.UserDataExport, error)
	FailStaleRunningUserDataExports(ctx context.Context, startedBefore time.Time, failedAt time.Time, limit int, errMsg string) ([]db.UserDataExport, error)
}

// QueueRunner drains queued export jobs. One pass claims and runs up to
// BatchSize jobs, returning how many were processed so the worker can
// report metrics. It is independent of the GC runner so the two can run on
// different cadences.
type QueueRunner struct {
	Store      QueueStore
	Runner     *Runner
	Now        func() time.Time
	BatchSize  int
	StaleAfter time.Duration
}

// QueueResult reports what one pass did. Failures are counted but do not
// abort the batch — one bad job should not block the rest of the queue.
type QueueResult struct {
	Examined    int
	Succeeded   int
	Failed      int
	StaleFailed int
}

const (
	defaultUserDataExportStaleAfter = 30 * time.Minute
	staleUserDataExportMessage      = "user data export exceeded worker timeout before reporting a terminal result"
)

// RunOnce processes up to BatchSize queued jobs.
func (q *QueueRunner) RunOnce(ctx context.Context) (QueueResult, error) {
	if q == nil {
		return QueueResult{}, errors.New("userexport: queue runner is nil")
	}
	if q.Store == nil || q.Runner == nil || q.Runner.Storage == nil {
		return QueueResult{}, errors.New("userexport: queue runner is missing dependencies")
	}
	batchSize := q.BatchSize
	if batchSize <= 0 {
		batchSize = 5
	}
	now := time.Now().UTC()
	if q.Now != nil {
		now = q.Now().UTC()
	}
	result := QueueResult{}
	staleAfter := q.StaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultUserDataExportStaleAfter
	}
	staleFailed, err := q.Store.FailStaleRunningUserDataExports(ctx, now.Add(-staleAfter), now, batchSize, staleUserDataExportMessage)
	if err != nil {
		return result, fmt.Errorf("fail stale running exports: %w", err)
	}
	result.StaleFailed = len(staleFailed)
	for _, job := range staleFailed {
		if err := q.Runner.Storage.Delete(ctx, StorageKey(job)); err != nil {
			// Best effort: mark stale jobs as failed first so the worker UI can
			// progress, even if cleanup gets delayed or a backend mount is unavailable.
			continue
		}
	}
	for i := 0; i < batchSize; i++ {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		job, err := q.Store.ClaimNextQueuedUserDataExport(ctx, now)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				return result, nil
			}
			return result, fmt.Errorf("claim queued export: %w", err)
		}
		result.Examined++
		if _, runErr := q.Runner.Run(ctx, job); runErr != nil {
			if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
				return result, runErr
			}
			result.Failed++
			continue
		}
		result.Succeeded++
	}
	return result, nil
}
