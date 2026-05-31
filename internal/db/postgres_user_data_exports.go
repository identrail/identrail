package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const userDataExportColumns = `id::text, user_id::text, status, bundle_path, bundle_size_bytes, bundle_sha256,
		error_message, requested_at, started_at, completed_at,
		download_expires_at, purge_after, purged_at`
const userDataExportColumnsFromExports = `exports.id::text, exports.user_id::text, exports.status, exports.bundle_path, exports.bundle_size_bytes, exports.bundle_sha256,
		exports.error_message, exports.requested_at, exports.started_at, exports.completed_at,
		exports.download_expires_at, exports.purge_after, exports.purged_at`

func scanUserDataExport(row rowScanner) (UserDataExport, error) {
	var export UserDataExport
	var startedAt, completedAt, downloadExpiresAt, purgeAfter, purgedAt sql.NullTime
	if err := row.Scan(
		&export.ID,
		&export.UserID,
		&export.Status,
		&export.BundlePath,
		&export.BundleSizeBytes,
		&export.BundleSHA256,
		&export.ErrorMessage,
		&export.RequestedAt,
		&startedAt,
		&completedAt,
		&downloadExpiresAt,
		&purgeAfter,
		&purgedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserDataExport{}, ErrNotFound
		}
		return UserDataExport{}, err
	}
	if startedAt.Valid {
		t := startedAt.Time.UTC()
		export.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		export.CompletedAt = &t
	}
	if downloadExpiresAt.Valid {
		t := downloadExpiresAt.Time.UTC()
		export.DownloadExpiresAt = &t
	}
	if purgeAfter.Valid {
		t := purgeAfter.Time.UTC()
		export.PurgeAfter = &t
	}
	if purgedAt.Valid {
		t := purgedAt.Time.UTC()
		export.PurgedAt = &t
	}
	export.RequestedAt = export.RequestedAt.UTC()
	return export, nil
}

func normalizeUserDataExportLookupID(id string) (string, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return "", ErrNotFound
	}
	if _, err := uuid.Parse(trimmed); err != nil {
		return "", ErrNotFound
	}
	return trimmed, nil
}

// CreateUserDataExport inserts a queued export job for the user.
func (p *PostgresStore) CreateUserDataExport(ctx context.Context, export UserDataExport) (UserDataExport, error) {
	normalized, err := normalizeUserDataExportForCreate(export)
	if err != nil {
		return UserDataExport{}, err
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`INSERT INTO user_data_exports
		   (id, user_id, status, requested_at)
		 VALUES (NULLIF($1, '')::uuid, NULLIF($2, '')::uuid, $3, $4)
			 RETURNING `+userDataExportColumns,
		normalized.ID,
		normalized.UserID,
		normalized.Status,
		normalized.RequestedAt,
	)
	saved, err := scanUserDataExport(row)
	if err != nil {
		if isTenancyFKViolation(err) {
			return UserDataExport{}, ErrNotFound
		}
		return UserDataExport{}, err
	}
	return saved, nil
}

// GetUserDataExport returns one export, scoped to its owner.
func (p *PostgresStore) GetUserDataExport(ctx context.Context, userID string, jobID string) (UserDataExport, error) {
	normalizedJobID, err := normalizeUserDataExportLookupID(jobID)
	if err != nil {
		return UserDataExport{}, err
	}
	normalizedUserID, err := normalizeUserDataExportLookupID(userID)
	if err != nil {
		return UserDataExport{}, err
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`SELECT `+userDataExportColumns+`
		 FROM user_data_exports
		 WHERE id = NULLIF($1, '')::uuid
		   AND user_id = NULLIF($2, '')::uuid`,
		normalizedJobID,
		normalizedUserID,
	)
	return scanUserDataExport(row)
}

// GetUserDataExportByID looks up a job by id without caller scoping.
func (p *PostgresStore) GetUserDataExportByID(ctx context.Context, jobID string) (UserDataExport, error) {
	normalizedJobID, err := normalizeUserDataExportLookupID(jobID)
	if err != nil {
		return UserDataExport{}, err
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`SELECT `+userDataExportColumns+`
		 FROM user_data_exports
		 WHERE id = NULLIF($1, '')::uuid`,
		normalizedJobID,
	)
	return scanUserDataExport(row)
}

// ListUserDataExports returns the user's exports newest-first.
func (p *PostgresStore) ListUserDataExports(ctx context.Context, userID string, limit int) ([]UserDataExport, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := p.queryContextAnyScope(
		ctx,
		`SELECT `+userDataExportColumns+`
		 FROM user_data_exports
		 WHERE user_id = NULLIF($1, '')::uuid
		 ORDER BY requested_at DESC
		 LIMIT $2`,
		strings.TrimSpace(userID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UserDataExport, 0, limit)
	for rows.Next() {
		export, scanErr := scanUserDataExport(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, export)
	}
	return items, rows.Err()
}

// ClaimNextQueuedUserDataExport atomically transitions one queued job to
// running and returns it.
func (p *PostgresStore) ClaimNextQueuedUserDataExport(ctx context.Context, now time.Time) (UserDataExport, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`WITH claimed AS (
		     UPDATE user_data_exports
		     SET status = 'running', started_at = $1::timestamptz
		     WHERE id = (
		         SELECT id FROM user_data_exports
		         WHERE status = 'queued'
		         ORDER BY requested_at ASC
		         FOR UPDATE SKIP LOCKED
		         LIMIT 1
		     )
		     RETURNING `+userDataExportColumns+`
		 )
		 SELECT `+userDataExportColumns+` FROM claimed`,
		now.UTC(),
	)
	return scanUserDataExport(row)
}

// ClaimQueuedUserDataExport atomically transitions the named queued job to
// running and returns it.
func (p *PostgresStore) ClaimQueuedUserDataExport(ctx context.Context, jobID string, now time.Time) (UserDataExport, error) {
	normalizedJobID, err := normalizeUserDataExportLookupID(jobID)
	if err != nil {
		return UserDataExport{}, err
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`UPDATE user_data_exports
		 SET status = 'running', started_at = $2::timestamptz
		 WHERE id = NULLIF($1, '')::uuid
		   AND status = 'queued'
		 RETURNING `+userDataExportColumns,
		normalizedJobID,
		now.UTC(),
	)
	return scanUserDataExport(row)
}

// CompleteUserDataExport marks the job ready and records bundle metadata.
func (p *PostgresStore) CompleteUserDataExport(ctx context.Context, jobID string, bundlePath string, sizeBytes int64, sha256Hex string, completedAt time.Time, downloadExpiresAt time.Time, purgeAfter time.Time) (UserDataExport, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`UPDATE user_data_exports
		 SET status = 'ready',
		     bundle_path = $2,
		     bundle_size_bytes = $3,
		     bundle_sha256 = $4,
		     error_message = '',
		     completed_at = $5::timestamptz,
		     download_expires_at = $6::timestamptz,
		     purge_after = $7::timestamptz
		 WHERE id = NULLIF($1, '')::uuid
		   AND status IN ('queued','running')
		 RETURNING `+userDataExportColumns,
		strings.TrimSpace(jobID),
		bundlePath,
		sizeBytes,
		sha256Hex,
		completedAt.UTC(),
		downloadExpiresAt.UTC(),
		purgeAfter.UTC(),
	)
	saved, err := scanUserDataExport(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return UserDataExport{}, fmt.Errorf("user_data_export %s not in queued/running state", jobID)
		}
		return UserDataExport{}, err
	}
	return saved, nil
}

// FailUserDataExport marks a job failed.
func (p *PostgresStore) FailUserDataExport(ctx context.Context, jobID string, errMsg string, failedAt time.Time) (UserDataExport, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`UPDATE user_data_exports
		 SET status = 'failed', error_message = $2, completed_at = $3::timestamptz
		 WHERE id = NULLIF($1, '')::uuid
		   AND status IN ('queued','running')
		 RETURNING `+userDataExportColumns,
		strings.TrimSpace(jobID),
		errMsg,
		failedAt.UTC(),
	)
	saved, err := scanUserDataExport(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return UserDataExport{}, fmt.Errorf("user_data_export %s not in queued/running state", jobID)
		}
		return UserDataExport{}, err
	}
	return saved, nil
}

// FailStaleRunningUserDataExports marks interrupted running jobs failed so they
// can stop polling as running forever after worker restarts.
func (p *PostgresStore) FailStaleRunningUserDataExports(ctx context.Context, startedBefore time.Time, failedAt time.Time, limit int, errMsg string) ([]UserDataExport, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queryContextAnyScope(
		ctx,
		`WITH stale AS (
		     SELECT id
		     FROM user_data_exports
		     WHERE status = 'running'
		       AND started_at IS NOT NULL
		       AND started_at < $1::timestamptz
		     ORDER BY started_at ASC
		     FOR UPDATE SKIP LOCKED
		     LIMIT $4
		   )
		   UPDATE user_data_exports AS exports
			   SET status = 'failed',
			   error_message = $3,
			   completed_at = $2::timestamptz
			   FROM stale
			   WHERE exports.id = stale.id
			   RETURNING `+userDataExportColumnsFromExports,
		startedBefore.UTC(),
		failedAt.UTC(),
		errMsg,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UserDataExport, 0)
	for rows.Next() {
		export, scanErr := scanUserDataExport(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, export)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// ListUserDataExportsPendingPurge returns ready jobs past their retention
// window whose bundle has not yet been purged.
func (p *PostgresStore) ListUserDataExportsPendingPurge(ctx context.Context, now time.Time, limit int) ([]UserDataExport, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queryContextAnyScope(
		ctx,
		`SELECT `+userDataExportColumns+`
		 FROM user_data_exports
		 WHERE purged_at IS NULL
		   AND purge_after IS NOT NULL
		   AND purge_after <= $1::timestamptz
		 ORDER BY purge_after ASC
		 LIMIT $2`,
		now.UTC(),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UserDataExport, 0, limit)
	for rows.Next() {
		export, scanErr := scanUserDataExport(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, export)
	}
	return items, rows.Err()
}

// MarkUserDataExportPurged stamps the job as expired and clears the bundle
// pointer so a later download attempt cannot reach a deleted file.
func (p *PostgresStore) MarkUserDataExportPurged(ctx context.Context, jobID string, now time.Time) (UserDataExport, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`UPDATE user_data_exports
		 SET status = 'expired',
		     purged_at = $2::timestamptz,
		     bundle_path = ''
		 WHERE id = NULLIF($1, '')::uuid
		 RETURNING `+userDataExportColumns,
		strings.TrimSpace(jobID),
		now.UTC(),
	)
	return scanUserDataExport(row)
}
