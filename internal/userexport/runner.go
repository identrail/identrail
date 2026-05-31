package userexport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/db"
)

// JobStore is the subset of db.Store the runner mutates.
type JobStore interface {
	CompleteUserDataExport(ctx context.Context, jobID string, bundlePath string, sizeBytes int64, sha256Hex string, completedAt time.Time, downloadExpiresAt time.Time, purgeAfter time.Time) (db.UserDataExport, error)
	FailUserDataExport(ctx context.Context, jobID string, errMsg string, failedAt time.Time) (db.UserDataExport, error)
}

// Runner executes one export job: builds the bundle, writes it to storage,
// and updates the DB row to ready (or failed). Invoked from the worker loop
// for queued jobs and inline from the API for fresh polls in single-process
// deployments where no worker is running.
type Runner struct {
	Source  Source
	Store   JobStore
	Storage Storage
	Now     func() time.Time
}

// Run executes a single export job end-to-end. job must already be persisted
// (status queued or running). On bundle / storage failure the job is marked
// failed and the error is returned.
func (r *Runner) Run(ctx context.Context, job db.UserDataExport) (db.UserDataExport, error) {
	if r == nil {
		return db.UserDataExport{}, errors.New("userexport: runner is nil")
	}
	if r.Source == nil || r.Store == nil || r.Storage == nil {
		return db.UserDataExport{}, errors.New("userexport: runner is missing dependencies")
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	var buf bytes.Buffer
	result, buildErr := Write(ctx, r.Source, job.UserID, now, &buf)
	if buildErr != nil {
		return r.fail(ctx, job, fmt.Errorf("build bundle: %w", buildErr), now)
	}
	key := StorageKey(job)
	path, putErr := r.Storage.Put(key, bytes.NewReader(buf.Bytes()))
	if putErr != nil {
		return r.fail(ctx, job, fmt.Errorf("write bundle: %w", putErr), now)
	}
	expiresAt := now.Add(db.UserDataExportDownloadTTL)
	purgeAfter := now.Add(db.UserDataExportRetention)
	saved, err := r.Store.CompleteUserDataExport(ctx, job.ID, path, result.SizeBytes, result.SHA256, now, expiresAt, purgeAfter)
	if err != nil {
		completeErr := fmt.Errorf("complete job: %w", err)
		deleteErr := r.Storage.Delete(key)
		if _, failErr := r.Store.FailUserDataExport(ctx, job.ID, completeErr.Error(), now); failErr != nil {
			if deleteErr != nil {
				return db.UserDataExport{}, fmt.Errorf("%w (and could not mark job failed: %v; and could not delete export bundle: %v)", completeErr, failErr, deleteErr)
			}
			return db.UserDataExport{}, fmt.Errorf("%w (and could not mark job failed: %v)", completeErr, failErr)
		}
		if deleteErr != nil {
			return db.UserDataExport{}, fmt.Errorf("%w (and could not delete export bundle: %v)", completeErr, deleteErr)
		}
		return db.UserDataExport{}, completeErr
	}
	return saved, nil
}

func (r *Runner) fail(ctx context.Context, job db.UserDataExport, runErr error, now time.Time) (db.UserDataExport, error) {
	if _, err := r.Store.FailUserDataExport(ctx, job.ID, runErr.Error(), now); err != nil {
		return db.UserDataExport{}, fmt.Errorf("%w (and could not mark job failed: %v)", runErr, err)
	}
	return db.UserDataExport{}, runErr
}

// StorageKey is the on-disk key the storage uses for a job's bundle. Exposed
// because the download handler needs to look up the file given just the job
// row.
func StorageKey(job db.UserDataExport) string {
	// Keep the on-disk layout shallow but namespaced by user so an operator
	// can `du -sh` per-user export usage without scanning every key.
	return job.UserID + "/" + job.ID + ".zip"
}
