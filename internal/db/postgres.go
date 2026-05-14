package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/db/sqlcdb"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore persists scans/findings in PostgreSQL.
type PostgresStore struct {
	db              *sql.DB
	queries         *sqlcdb.Queries
	enforceScopeRLS bool
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type storeExecutor struct {
	store *PostgresStore
}

func (e storeExecutor) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return e.store.execContext(ctx, query, args...)
}

type rowScanner interface {
	Scan(dest ...any) error
}

type rowsScanner interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

type scopedQueryRow struct {
	row *sql.Row
	tx  *sql.Tx
}

func (s *scopedQueryRow) Scan(dest ...any) error {
	err := s.row.Scan(dest...)
	if err != nil {
		_ = s.tx.Rollback()
		return err
	}
	return s.tx.Commit()
}

type errScanner struct {
	err error
}

func (e errScanner) Scan(_ ...any) error {
	return e.err
}

type scopedRows struct {
	rows    *sql.Rows
	tx      *sql.Tx
	errSeen bool
	closed  bool
}

func (s *scopedRows) Next() bool {
	return s.rows.Next()
}

func (s *scopedRows) Scan(dest ...any) error {
	err := s.rows.Scan(dest...)
	if err != nil {
		s.errSeen = true
	}
	return err
}

func (s *scopedRows) Err() error {
	err := s.rows.Err()
	if err != nil {
		s.errSeen = true
	}
	return err
}

func (s *scopedRows) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	closeErr := s.rows.Close()
	if closeErr != nil || s.errSeen {
		_ = s.tx.Rollback()
		return closeErr
	}
	if err := s.tx.Commit(); err != nil {
		return fmt.Errorf("commit scoped query: %w", err)
	}
	return nil
}

var placeholderPattern = regexp.MustCompile(`\$(\d+)`)

var errQueryArgCapacityOverflow = errors.New("query argument capacity overflow")

func checkedSliceCapacity(base int, extra int) (int, error) {
	if base < 0 || extra < 0 {
		return 0, fmt.Errorf("invalid slice capacity inputs")
	}
	maxInt := int(^uint(0) >> 1)
	if base > maxInt-extra {
		return 0, errQueryArgCapacityOverflow
	}
	return base + extra, nil
}

// NewPostgresStore opens a PostgreSQL connection and validates connectivity.
func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	// Conservative pool defaults reduce misconfiguration risk in early deployments.
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &PostgresStore{db: db, queries: sqlcdb.New(db)}, nil
}

// NewPostgresStoreWithDB builds a store around an existing sql.DB (tests).
func NewPostgresStoreWithDB(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db, queries: sqlcdb.New(db)}
}

// DB exposes the underlying sql.DB for runtime wiring (locks, health checks).
func (p *PostgresStore) DB() *sql.DB {
	if p == nil {
		return nil
	}
	return p.db
}

// SetScopeRLSEnforcement toggles statement-level RLS enforcement with scoped GUCs.
func (p *PostgresStore) SetScopeRLSEnforcement(enabled bool) {
	if p == nil {
		return
	}
	p.enforceScopeRLS = enabled
}

// ScopeRLSEnforcementEnabled returns true when scoped RLS enforcement is enabled.
func (p *PostgresStore) ScopeRLSEnforcementEnabled() bool {
	if p == nil {
		return false
	}
	return p.enforceScopeRLS
}

func (p *PostgresStore) injectScopeCTE(ctx context.Context, query string, args []any) (string, []any, error) {
	if !p.enforceScopeRLS {
		return query, args, nil
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return "", nil, err
	}

	maxPlaceholder := 0
	for _, match := range placeholderPattern.FindAllStringSubmatch(query, -1) {
		if len(match) != 2 {
			continue
		}
		value, convErr := strconv.Atoi(match[1])
		if convErr != nil {
			continue
		}
		if value > maxPlaceholder {
			maxPlaceholder = value
		}
	}

	tenantPos := maxPlaceholder + 1
	workspacePos := maxPlaceholder + 2
	enforcePos := maxPlaceholder + 3
	scopeCTE := fmt.Sprintf(
		"_identrail_scope AS (SELECT set_config('identrail.tenant_id', $%d, true), set_config('identrail.workspace_id', $%d, true), set_config('identrail.rls_enforce', $%d, true))",
		tenantPos,
		workspacePos,
		enforcePos,
	)
	trimmed := strings.TrimSpace(query)
	upper := strings.ToUpper(trimmed)
	if strings.HasPrefix(upper, "WITH RECURSIVE ") {
		trimmed = strings.TrimSpace(trimmed[len("WITH RECURSIVE "):])
		query = "WITH RECURSIVE " + scopeCTE + ", " + trimmed
	} else if strings.HasPrefix(upper, "WITH ") {
		trimmed = strings.TrimSpace(trimmed[5:])
		query = "WITH " + scopeCTE + ", " + trimmed
	} else {
		query = "WITH " + scopeCTE + " " + query
	}

	capacity, err := checkedSliceCapacity(len(args), 3)
	if err != nil {
		return "", nil, err
	}

	scopedArgs := make([]any, 0, capacity)
	scopedArgs = append(scopedArgs, args...)
	scopedArgs = append(scopedArgs, scope.TenantID, scope.WorkspaceID, "on")
	return query, scopedArgs, nil
}

func (p *PostgresStore) execContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if !p.enforceScopeRLS {
		return p.db.ExecContext(ctx, query, args...)
	}

	tx, err := p.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit scoped exec: %w", err)
	}
	return result, nil
}

func (p *PostgresStore) queryContext(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	if !p.enforceScopeRLS {
		return p.db.QueryContext(ctx, query, args...)
	}

	tx, err := p.beginTx(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return &scopedRows{rows: rows, tx: tx}, nil
}

func (p *PostgresStore) queryRowContext(ctx context.Context, query string, args ...any) rowScanner {
	if !p.enforceScopeRLS {
		return p.db.QueryRowContext(ctx, query, args...)
	}

	tx, err := p.beginTx(ctx)
	if err != nil {
		return errScanner{err: err}
	}
	return &scopedQueryRow{
		row: tx.QueryRowContext(ctx, query, args...),
		tx:  tx,
	}
}

func (p *PostgresStore) queryRowContextAnyScope(ctx context.Context, query string, args ...any) rowScanner {
	return p.db.QueryRowContext(ctx, query, args...)
}

func (p *PostgresStore) queryContextAnyScope(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	return p.db.QueryContext(ctx, query, args...)
}

func (p *PostgresStore) execContextAnyScope(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return p.db.ExecContext(ctx, query, args...)
}

func (p *PostgresStore) beginTx(ctx context.Context) (*sql.Tx, error) {
	if !p.enforceScopeRLS {
		return p.db.BeginTx(ctx, nil)
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`,
		scope.TenantID,
		scope.WorkspaceID,
		"on",
	); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set rls scope context: %w", err)
	}
	return tx, nil
}

// CreateScan inserts a new scan row.
func (p *PostgresStore) CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error) {
	return p.createScanWithStatus(ctx, provider, "running", startedAt)
}

// CreateQueuedScan inserts a queued scan request row.
func (p *PostgresStore) CreateQueuedScan(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error) {
	return p.createScanWithStatus(ctx, provider, "queued", queuedAt)
}

// CreateQueuedScanWithinLimit inserts one queued scan request only when pending capacity remains.
func (p *PostgresStore) CreateQueuedScanWithinLimit(ctx context.Context, provider string, queuedAt time.Time, maxPending int) (ScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	if maxPending <= 0 {
		maxPending = 1
	}
	tx, err := p.beginTx(ctx)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("begin queued scan transaction: %w", err)
	}
	defer tx.Rollback()

	normalizedProvider := strings.TrimSpace(provider)
	lockKey := fmt.Sprintf("scan-queue:%s:%s:%s", scope.TenantID, scope.WorkspaceID, normalizedProvider)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, lockKey); err != nil {
		return ScanRecord{}, fmt.Errorf("lock queued scan capacity: %w", err)
	}

	var queued int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		FROM scans
		WHERE tenant_id = $1
		  AND workspace_id = $2
		  AND provider = $3
		  AND status = 'queued'`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedProvider,
	).Scan(&queued); err != nil {
		return ScanRecord{}, fmt.Errorf("count queued scans: %w", err)
	}
	if queued >= maxPending {
		return ScanRecord{}, ErrQueueLimitReached
	}
	traceParent, traceState := QueueTraceContextFromContext(ctx)

	row := tx.QueryRowContext(
		ctx,
		`INSERT INTO scans (
			id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, error_message, trace_parent, trace_state
		)
		VALUES ($1, $2, $3, $4, 'queued', $5, NULL, 0, 0, NULL, NULLIF($6, ''), NULLIF($7, ''))
		RETURNING id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, ''), retry_count, max_retry_count, COALESCE(failure_category, ''), next_retry_at, dead_lettered, dead_lettered_at, COALESCE(trace_parent, ''), COALESCE(trace_state, '')`,
		uuid.NewString(),
		scope.TenantID,
		scope.WorkspaceID,
		normalizedProvider,
		queuedAt.UTC(),
		traceParent,
		traceState,
	)
	record, err := scanQueuedScanRecord(row)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("insert queued scan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ScanRecord{}, fmt.Errorf("commit queued scan transaction: %w", err)
	}
	return record, nil
}

// CreateQueuedScanIfNoPending inserts one queued scan only when no queued/running scan exists.
func (p *PostgresStore) CreateQueuedScanIfNoPending(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	tx, err := p.beginTx(ctx)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("begin queued scan transaction: %w", err)
	}
	defer tx.Rollback()

	normalizedProvider := strings.TrimSpace(provider)
	lockKey := fmt.Sprintf("scan-queue:%s:%s:%s", scope.TenantID, scope.WorkspaceID, normalizedProvider)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, lockKey); err != nil {
		return ScanRecord{}, fmt.Errorf("lock scan queue: %w", err)
	}

	var pending int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND provider = $3
		   AND status IN ('queued', 'running')`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedProvider,
	).Scan(&pending); err != nil {
		return ScanRecord{}, fmt.Errorf("count pending scans: %w", err)
	}
	if pending > 0 {
		return ScanRecord{}, ErrPendingScanExists
	}

	record := ScanRecord{
		ID:            uuid.NewString(),
		TenantID:      scope.TenantID,
		WorkspaceID:   scope.WorkspaceID,
		Provider:      normalizedProvider,
		Status:        "queued",
		StartedAt:     queuedAt.UTC(),
		MaxRetryCount: DefaultScanMaxRetryCount,
	}
	record.TraceParent, record.TraceState = QueueTraceContextFromContext(ctx)
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, error_message, trace_parent, trace_state)
		 VALUES ($1, $2, $3, $4, $5, $6, NULL, 0, 0, NULL, NULLIF($7, ''), NULLIF($8, ''))`,
		record.ID,
		record.TenantID,
		record.WorkspaceID,
		record.Provider,
		record.Status,
		record.StartedAt,
		record.TraceParent,
		record.TraceState,
	); err != nil {
		return ScanRecord{}, fmt.Errorf("insert queued scan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ScanRecord{}, fmt.Errorf("commit queued scan transaction: %w", err)
	}
	return record, nil
}

// ClaimNextQueuedScan atomically claims one queued scan for execution.
func (p *PostgresStore) ClaimNextQueuedScan(ctx context.Context, provider string) (ScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	return p.claimNextQueuedScan(ctx, provider, &scope)
}

// ClaimNextQueuedScanAnyScope atomically claims one queued scan across all scopes.
func (p *PostgresStore) ClaimNextQueuedScanAnyScope(ctx context.Context, provider string) (ScanRecord, error) {
	return p.claimNextQueuedScan(ctx, provider, nil)
}

func (p *PostgresStore) claimNextQueuedScan(ctx context.Context, provider string, scope *Scope) (ScanRecord, error) {
	query := `WITH next_scan AS (
			SELECT id
			FROM scans
			WHERE provider = $1
			  AND status = 'queued'
			  AND dead_lettered = FALSE
			  AND (next_retry_at IS NULL OR next_retry_at <= NOW())
			ORDER BY started_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE scans AS s
		SET status = 'running',
		    finished_at = NULL,
		    error_message = NULL,
		    failure_category = NULL,
		    next_retry_at = NULL
		FROM next_scan
		WHERE s.id = next_scan.id
		RETURNING s.id, s.tenant_id, s.workspace_id, s.provider, s.status, s.started_at, s.finished_at, s.asset_count, s.finding_count, COALESCE(s.error_message, ''), s.retry_count, s.max_retry_count, COALESCE(s.failure_category, ''), s.next_retry_at, s.dead_lettered, s.dead_lettered_at, COALESCE(s.trace_parent, ''), COALESCE(s.trace_state, '')`
	args := []any{strings.TrimSpace(provider)}
	if scope != nil {
		query = `WITH next_scan AS (
			SELECT id
			FROM scans
			WHERE tenant_id = $1
			  AND workspace_id = $2
			  AND provider = $3
			  AND status = 'queued'
			  AND dead_lettered = FALSE
			  AND (next_retry_at IS NULL OR next_retry_at <= NOW())
			ORDER BY started_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE scans AS s
		SET status = 'running',
		    finished_at = NULL,
		    error_message = NULL,
		    failure_category = NULL,
		    next_retry_at = NULL
		FROM next_scan
		WHERE s.id = next_scan.id
		RETURNING s.id, s.tenant_id, s.workspace_id, s.provider, s.status, s.started_at, s.finished_at, s.asset_count, s.finding_count, COALESCE(s.error_message, ''), s.retry_count, s.max_retry_count, COALESCE(s.failure_category, ''), s.next_retry_at, s.dead_lettered, s.dead_lettered_at, COALESCE(s.trace_parent, ''), COALESCE(s.trace_state, '')`
		args = []any{scope.TenantID, scope.WorkspaceID, strings.TrimSpace(provider)}
	}
	row := p.queryRowContext(ctx, query, args...)
	if scope == nil {
		row = p.queryRowContextAnyScope(ctx, query, args...)
	}
	record, err := scanQueuedScanRecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return ScanRecord{}, ErrNotFound
		}
		return ScanRecord{}, fmt.Errorf("claim queued scan: %w", err)
	}
	return record, nil
}

// CountQueuedScans returns queued scan requests count for one provider.
func (p *PostgresStore) CountQueuedScans(ctx context.Context, provider string) (int, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	if err := p.queryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND ($3 = '' OR provider = $3)
		   AND status = 'queued'
		   AND dead_lettered = FALSE`,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(provider),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued scans: %w", err)
	}
	return count, nil
}

// CountQueuedScansAnyScope returns queued scan requests count across all scopes for one provider.
func (p *PostgresStore) CountQueuedScansAnyScope(ctx context.Context, provider string) (int, error) {
	var count int
	if err := p.queryRowContextAnyScope(
		ctx,
		`SELECT COUNT(*)
		 FROM scans
		 WHERE ($1 = '' OR provider = $1)
		   AND status = 'queued'
		   AND dead_lettered = FALSE`,
		strings.TrimSpace(provider),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued scans any scope: %w", err)
	}
	return count, nil
}

// GetScan returns one scan by id.
func (p *PostgresStore) GetScan(ctx context.Context, scanID string) (ScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, ''), retry_count, max_retry_count, COALESCE(failure_category, ''), next_retry_at, dead_lettered, dead_lettered_at
		 FROM scans
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
	)
	record, err := scanScanRecord(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return ScanRecord{}, ErrNotFound
		}
		return ScanRecord{}, fmt.Errorf("query scan: %w", err)
	}
	return record, nil
}

// CompleteScan updates scan completion metadata.
func (p *PostgresStore) CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE scans
		 SET status=$2, finished_at=$3, asset_count=$4, finding_count=$5, error_message=$6, failure_category = NULL, next_retry_at = NULL, dead_lettered = FALSE, dead_lettered_at = NULL
		 WHERE id=$1
		   AND tenant_id=$7
		   AND workspace_id=$8`,
		scanID,
		status,
		finishedAt.UTC(),
		assetCount,
		findingCount,
		nullableString(errorMessage),
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("complete scan: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// ScheduleScanRetry moves a failed scan attempt back into the queue with delay metadata.
func (p *PostgresStore) ScheduleScanRetry(ctx context.Context, scanID string, queuedAt time.Time, retryCount int, maxRetryCount int, failureCategory string, errorMessage string, nextRetryAt time.Time) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE scans
		 SET status = 'queued',
		     started_at = $2,
		     finished_at = NULL,
		     error_message = $3,
		     retry_count = $4,
		     max_retry_count = $5,
		     failure_category = NULLIF($6, ''),
		     next_retry_at = $7,
		     dead_lettered = FALSE,
		     dead_lettered_at = NULL
		 WHERE id = $1
		   AND tenant_id = $8
		   AND workspace_id = $9`,
		scanID,
		queuedAt.UTC(),
		nullableString(errorMessage),
		retryCount,
		maxRetryCount,
		strings.TrimSpace(failureCategory),
		nextRetryAt.UTC(),
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("schedule scan retry: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// DeadLetterScan marks a failed queued scan as operator-replayable.
func (p *PostgresStore) DeadLetterScan(ctx context.Context, scanID string, finishedAt time.Time, retryCount int, maxRetryCount int, assetCount int, findingCount int, failureCategory string, errorMessage string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE scans
		 SET status = 'failed',
		     finished_at = $2,
		     error_message = $3,
		     retry_count = $4,
		     max_retry_count = $5,
		     asset_count = $6,
		     finding_count = $7,
		     failure_category = NULLIF($8, ''),
		     next_retry_at = NULL,
		     dead_lettered = TRUE,
		     dead_lettered_at = $2
		 WHERE id = $1
		   AND tenant_id = $9
		   AND workspace_id = $10`,
		scanID,
		finishedAt.UTC(),
		nullableString(errorMessage),
		retryCount,
		maxRetryCount,
		assetCount,
		findingCount,
		strings.TrimSpace(failureCategory),
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("dead-letter scan: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// UpsertArtifacts inserts raw and normalized artifacts idempotently for one scan.
func (p *PostgresStore) UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error {
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return err
	}
	tx, err := p.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin artifacts transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := upsertRawAssets(ctx, tx, scanID, artifacts.RawAssets); err != nil {
		return err
	}
	if err := upsertIdentities(ctx, tx, scanID, artifacts.Bundle.Identities); err != nil {
		return err
	}
	if err := upsertPolicies(ctx, tx, scanID, artifacts.Bundle.Policies); err != nil {
		return err
	}
	if err := upsertRelationships(ctx, tx, scanID, artifacts.Relationships); err != nil {
		return err
	}
	if err := upsertPermissions(ctx, tx, scanID, artifacts.Permissions); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit artifacts transaction: %w", err)
	}
	return nil
}

// UpsertFindings inserts findings idempotently for the scan.
func (p *PostgresStore) UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error {
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return err
	}
	tx, err := p.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows := make([][]any, 0, len(findings))
	seenFindings := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, dup := seenFindings[finding.ID]; dup {
			continue
		}
		seenFindings[finding.ID] = struct{}{}
		pathJSON, err := json.Marshal(finding.Path)
		if err != nil {
			return fmt.Errorf("marshal finding path: %w", err)
		}
		evidenceJSON, err := json.Marshal(finding.Evidence)
		if err != nil {
			return fmt.Errorf("marshal finding evidence: %w", err)
		}

		createdAt := finding.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		rows = append(rows, []any{
			scanID,
			finding.ID,
			string(finding.Type),
			string(finding.Severity),
			finding.Title,
			finding.HumanSummary,
			pathJSON,
			evidenceJSON,
			finding.Remediation,
			createdAt.UTC(),
		})
	}
	if err := executeBulkInsert(
		ctx,
		tx,
		`INSERT INTO findings (scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at) VALUES `,
		` ON CONFLICT (scan_id, finding_id)
		  DO UPDATE SET
		    type = EXCLUDED.type,
		    severity = EXCLUDED.severity,
		    title = EXCLUDED.title,
		    human_summary = EXCLUDED.human_summary,
		    path = EXCLUDED.path,
		    evidence = EXCLUDED.evidence,
		    remediation = EXCLUDED.remediation,
		    created_at = EXCLUDED.created_at`,
		rows,
	); err != nil {
		return fmt.Errorf("upsert findings: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit findings transaction: %w", err)
	}
	return nil
}

// GetFindingTriageState returns triage workflow state for one finding id.
func (p *PostgresStore) GetFindingTriageState(ctx context.Context, findingID string) (FindingTriageState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return FindingTriageState{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by
		 FROM finding_triage_states
		 WHERE finding_id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3`,
		strings.TrimSpace(findingID),
		scope.TenantID,
		scope.WorkspaceID,
	)
	var state FindingTriageState
	var suppressionExpiresAt sql.NullTime
	if err := row.Scan(
		&state.FindingID,
		&state.Status,
		&state.Assignee,
		&suppressionExpiresAt,
		&state.UpdatedAt,
		&state.UpdatedBy,
	); err != nil {
		if err == sql.ErrNoRows {
			return FindingTriageState{}, ErrNotFound
		}
		return FindingTriageState{}, fmt.Errorf("query finding triage state: %w", err)
	}
	if suppressionExpiresAt.Valid {
		value := suppressionExpiresAt.Time.UTC()
		state.SuppressionExpiresAt = &value
	}
	state.UpdatedAt = state.UpdatedAt.UTC()
	return state, nil
}

// ListFindingTriageStates returns triage states for provided finding ids.
func (p *PostgresStore) ListFindingTriageStates(ctx context.Context, findingIDs []string) ([]FindingTriageState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	unique := make([]string, 0, len(findingIDs))
	seen := map[string]struct{}{}
	for _, findingID := range findingIDs {
		normalized := strings.TrimSpace(findingID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) == 0 {
		return []FindingTriageState{}, nil
	}

	placeholders := make([]string, len(unique))
	args := make([]any, 0, len(unique)+2)
	args = append(args, scope.TenantID, scope.WorkspaceID)
	for i, findingID := range unique {
		placeholders[i] = fmt.Sprintf("$%d", i+3)
		args = append(args, findingID)
	}
	query := fmt.Sprintf(
		`SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by
		 FROM finding_triage_states
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND finding_id IN (%s)`,
		strings.Join(placeholders, ", "),
	)
	rows, err := p.queryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query finding triage states: %w", err)
	}
	defer rows.Close()

	result := make([]FindingTriageState, 0, len(unique))
	for rows.Next() {
		var state FindingTriageState
		var suppressionExpiresAt sql.NullTime
		if err := rows.Scan(
			&state.FindingID,
			&state.Status,
			&state.Assignee,
			&suppressionExpiresAt,
			&state.UpdatedAt,
			&state.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan finding triage state row: %w", err)
		}
		if suppressionExpiresAt.Valid {
			value := suppressionExpiresAt.Time.UTC()
			state.SuppressionExpiresAt = &value
		}
		state.UpdatedAt = state.UpdatedAt.UTC()
		result = append(result, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding triage state rows: %w", err)
	}
	return result, nil
}

// UpsertFindingTriageState creates or updates mutable triage metadata.
func (p *PostgresStore) UpsertFindingTriageState(ctx context.Context, state FindingTriageState) error {
	return p.upsertFindingTriageStateWithExecutor(ctx, storeExecutor{store: p}, state)
}

func (p *PostgresStore) upsertFindingTriageStateWithExecutor(ctx context.Context, executor sqlExecutor, state FindingTriageState) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	updatedAt := state.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	_, err = executor.ExecContext(
		ctx,
		`INSERT INTO finding_triage_states (tenant_id, workspace_id, finding_id, status, assignee, suppression_expires_at, updated_at, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, workspace_id, finding_id)
		 DO UPDATE SET
		   status = EXCLUDED.status,
		   assignee = EXCLUDED.assignee,
		   suppression_expires_at = EXCLUDED.suppression_expires_at,
		   updated_at = EXCLUDED.updated_at,
		   updated_by = EXCLUDED.updated_by`,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(state.FindingID),
		strings.TrimSpace(string(state.Status)),
		strings.TrimSpace(state.Assignee),
		state.SuppressionExpiresAt,
		updatedAt.UTC(),
		strings.TrimSpace(state.UpdatedBy),
	)
	if err != nil {
		return fmt.Errorf("upsert finding triage state: %w", err)
	}
	return nil
}

// AppendFindingTriageEvent records one immutable triage action.
func (p *PostgresStore) AppendFindingTriageEvent(ctx context.Context, event FindingTriageEvent) error {
	return p.appendFindingTriageEventWithExecutor(ctx, storeExecutor{store: p}, event)
}

func (p *PostgresStore) appendFindingTriageEventWithExecutor(ctx context.Context, executor sqlExecutor, event FindingTriageEvent) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	createdAt := event.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	eventID := strings.TrimSpace(event.ID)
	if eventID == "" {
		eventID = uuid.NewString()
	}
	_, err = executor.ExecContext(
		ctx,
		`INSERT INTO finding_triage_events (id, tenant_id, workspace_id, finding_id, action, from_status, to_status, assignee, suppression_expires_at, comment, actor, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		eventID,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(event.FindingID),
		strings.TrimSpace(event.Action),
		strings.TrimSpace(string(event.FromStatus)),
		strings.TrimSpace(string(event.ToStatus)),
		strings.TrimSpace(event.Assignee),
		event.SuppressionExpiresAt,
		strings.TrimSpace(event.Comment),
		strings.TrimSpace(event.Actor),
		createdAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert finding triage event: %w", err)
	}
	return nil
}

// ApplyFindingTriageTransition persists state and audit history atomically.
func (p *PostgresStore) ApplyFindingTriageTransition(ctx context.Context, state FindingTriageState, event FindingTriageEvent) error {
	if strings.TrimSpace(state.FindingID) == "" || strings.TrimSpace(event.FindingID) == "" {
		return fmt.Errorf("finding id is required")
	}
	if strings.TrimSpace(state.FindingID) != strings.TrimSpace(event.FindingID) {
		return fmt.Errorf("finding id mismatch between state and event")
	}

	tx, err := p.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin triage transition tx: %w", err)
	}
	if err := p.upsertFindingTriageStateWithExecutor(ctx, tx, state); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := p.appendFindingTriageEventWithExecutor(ctx, tx, event); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit triage transition tx: %w", err)
	}
	return nil
}

// ListFindingTriageEvents returns triage history newest-first for one finding id.
func (p *PostgresStore) ListFindingTriageEvents(ctx context.Context, findingID string, limit int) ([]FindingTriageEvent, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	const maxFindingTriageEventsLimit = 500
	if limit <= 0 {
		limit = 100
	} else if limit > maxFindingTriageEventsLimit {
		limit = maxFindingTriageEventsLimit
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id, finding_id, action, from_status, to_status, assignee, suppression_expires_at, comment, actor, created_at
		 FROM finding_triage_events
		 WHERE finding_id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3
		 ORDER BY created_at DESC
		 LIMIT $4`,
		strings.TrimSpace(findingID),
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query finding triage events: %w", err)
	}
	defer rows.Close()

	result := []FindingTriageEvent{}
	for rows.Next() {
		var event FindingTriageEvent
		var suppressionExpiresAt sql.NullTime
		if err := rows.Scan(
			&event.ID,
			&event.FindingID,
			&event.Action,
			&event.FromStatus,
			&event.ToStatus,
			&event.Assignee,
			&suppressionExpiresAt,
			&event.Comment,
			&event.Actor,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding triage event row: %w", err)
		}
		if suppressionExpiresAt.Valid {
			value := suppressionExpiresAt.Time.UTC()
			event.SuppressionExpiresAt = &value
		}
		event.CreatedAt = event.CreatedAt.UTC()
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding triage event rows: %w", err)
	}
	return result, nil
}

// ListScans returns latest scans first.
func (p *PostgresStore) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 , retry_count, max_retry_count, COALESCE(failure_category, ''), next_retry_at, dead_lettered, dead_lettered_at
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		 ORDER BY started_at DESC
		 LIMIT $3`,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()
	result := []ScanRecord{}
	for rows.Next() {
		record, scanErr := scanScanRecord(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan rows: %w", err)
	}
	return result, nil
}

// ListFindings returns latest findings first across scans.
func (p *PostgresStore) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		 ORDER BY f.created_at DESC
		 LIMIT $3`,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	return findingsFromSQLRows(rows)
}

// ListFindingsFiltered returns one filtered findings page with stable persistence-level ordering.
func (p *PostgresStore) ListFindingsFiltered(ctx context.Context, filter FindingListFilter) ([]domain.Finding, error) {
	normalized := NormalizeFindingListFilter(filter)
	if normalized.ScanID != "" {
		if err := p.ensureScanInScope(ctx, normalized.ScanID); err != nil {
			return nil, err
		}
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}

	args := []any{scope.TenantID, scope.WorkspaceID}
	conditions := []string{
		"s.tenant_id = $1",
		"s.workspace_id = $2",
	}
	nextArg := 3
	if normalized.ScanID != "" {
		conditions = append(conditions, fmt.Sprintf("f.scan_id = $%d", nextArg))
		args = append(args, normalized.ScanID)
		nextArg++
	}
	if normalized.FindingID != "" {
		conditions = append(conditions, fmt.Sprintf("f.finding_id = $%d", nextArg))
		args = append(args, normalized.FindingID)
		nextArg++
	}
	if normalized.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(f.severity) = $%d", nextArg))
		args = append(args, normalized.Severity)
		nextArg++
	}
	if normalized.Type != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(f.type) = $%d", nextArg))
		args = append(args, normalized.Type)
		nextArg++
	}
	evalTimePos := nextArg
	args = append(args, normalized.Now)
	nextArg++
	triageStatusExpr := fmt.Sprintf(`CASE
		WHEN ts.status = 'suppressed' AND ts.suppression_expires_at IS NOT NULL AND ts.suppression_expires_at <= $%d THEN 'open'
		ELSE COALESCE(NULLIF(ts.status, ''), 'open')
	END`, evalTimePos)
	if normalized.LifecycleStatus != "" {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", triageStatusExpr, nextArg))
		args = append(args, normalized.LifecycleStatus)
		nextArg++
	}
	if normalized.Assignee != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(COALESCE(ts.assignee, '')) = $%d", nextArg))
		args = append(args, normalized.Assignee)
		nextArg++
	}

	query := fmt.Sprintf(
		`SELECT
			f.scan_id,
			f.finding_id,
			f.type,
			f.severity,
			f.title,
			f.human_summary,
			f.path,
			f.evidence,
			COALESCE(f.remediation, ''),
			f.created_at,
			%s AS triage_status,
			COALESCE(ts.assignee, ''),
			ts.suppression_expires_at,
			ts.updated_at,
			COALESCE(ts.updated_by, '')
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		LEFT JOIN finding_triage_states ts
		  ON ts.tenant_id = s.tenant_id
		 AND ts.workspace_id = s.workspace_id
		 AND ts.finding_id = f.finding_id
		WHERE %s
		ORDER BY %s
		OFFSET $%d
		LIMIT $%d`,
		triageStatusExpr,
		strings.Join(conditions, " AND "),
		findingOrderClause(normalized.SortBy, normalized.SortDesc),
		nextArg,
		nextArg+1,
	)
	args = append(args, normalized.Offset, normalized.Limit+1)
	rows, err := p.queryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query filtered findings: %w", err)
	}
	defer rows.Close()
	return findingsWithTriageFromSQLRows(rows, normalized.Now)
}

// ListFindingsAll returns all findings for current scope ordered by recency.
func (p *PostgresStore) ListFindingsAll(ctx context.Context) ([]domain.Finding, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		 ORDER BY f.created_at DESC`,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("query all findings: %w", err)
	}
	defer rows.Close()
	return findingsFromSQLRows(rows)
}

// SummarizeFindings returns aggregate counters for current scope.
func (p *PostgresStore) SummarizeFindings(ctx context.Context) (FindingSummaryCounts, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return FindingSummaryCounts{}, err
	}
	summary := FindingSummaryCounts{
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
	}
	if err := p.queryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2`,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&summary.Total); err != nil {
		return FindingSummaryCounts{}, fmt.Errorf("count findings summary total: %w", err)
	}

	severityRows, err := p.queryContext(
		ctx,
		`SELECT f.severity, COUNT(*)
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		 GROUP BY f.severity`,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return FindingSummaryCounts{}, fmt.Errorf("query findings summary by severity: %w", err)
	}
	defer severityRows.Close()
	for severityRows.Next() {
		var severity string
		var count int
		if err := severityRows.Scan(&severity, &count); err != nil {
			return FindingSummaryCounts{}, fmt.Errorf("scan findings summary by severity: %w", err)
		}
		summary.BySeverity[severity] = count
	}
	if err := severityRows.Err(); err != nil {
		return FindingSummaryCounts{}, fmt.Errorf("iterate findings summary by severity: %w", err)
	}

	typeRows, err := p.queryContext(
		ctx,
		`SELECT f.type, COUNT(*)
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		 GROUP BY f.type`,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return FindingSummaryCounts{}, fmt.Errorf("query findings summary by type: %w", err)
	}
	defer typeRows.Close()
	for typeRows.Next() {
		var findingType string
		var count int
		if err := typeRows.Scan(&findingType, &count); err != nil {
			return FindingSummaryCounts{}, fmt.Errorf("scan findings summary by type: %w", err)
		}
		summary.ByType[findingType] = count
	}
	if err := typeRows.Err(); err != nil {
		return FindingSummaryCounts{}, fmt.Errorf("iterate findings summary by type: %w", err)
	}

	return summary, nil
}

// ListFindingsByScan returns latest findings first for one scan id.
func (p *PostgresStore) ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return nil, err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE f.scan_id = $1
		   AND s.tenant_id = $2
		   AND s.workspace_id = $3
		 ORDER BY f.created_at DESC
		 LIMIT $4`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings by scan: %w", err)
	}
	defer rows.Close()
	return findingsFromSQLRows(rows)
}

// GetFinding returns one finding by id, optionally scoped to one scan id.
func (p *PostgresStore) GetFinding(ctx context.Context, findingID string, scanID string) (domain.Finding, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return domain.Finding{}, err
	}
	id := strings.TrimSpace(findingID)
	if id == "" {
		return domain.Finding{}, ErrNotFound
	}
	query := `SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
	 FROM findings f
	 JOIN scans s ON s.id = f.scan_id
	 WHERE s.tenant_id = $1
	   AND s.workspace_id = $2
	   AND f.finding_id = $3`
	args := []any{scope.TenantID, scope.WorkspaceID, id}
	if normalizedScanID := strings.TrimSpace(scanID); normalizedScanID != "" {
		query += " AND f.scan_id = $4"
		args = append(args, normalizedScanID)
	}
	query += " ORDER BY f.created_at DESC LIMIT 1"
	rows, err := p.queryContext(ctx, query, args...)
	if err != nil {
		return domain.Finding{}, fmt.Errorf("query finding: %w", err)
	}
	defer rows.Close()
	items, err := findingsFromSQLRows(rows)
	if err != nil {
		return domain.Finding{}, err
	}
	if len(items) == 0 {
		return domain.Finding{}, ErrNotFound
	}
	return items[0], nil
}

// ListFindingMetasByScan returns lightweight finding metadata for one scan.
func (p *PostgresStore) ListFindingMetasByScan(ctx context.Context, scanID string) ([]FindingMeta, error) {
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT finding_id, scan_id, severity, type, created_at
		 FROM findings
		 WHERE scan_id = $1
		 ORDER BY created_at DESC`,
		scanID,
	)
	if err != nil {
		return nil, fmt.Errorf("query finding metas by scan: %w", err)
	}
	defer rows.Close()
	result := make([]FindingMeta, 0)
	for rows.Next() {
		var meta FindingMeta
		if err := rows.Scan(&meta.ID, &meta.ScanID, &meta.Severity, &meta.Type, &meta.CreatedAt); err != nil {
			return nil, fmt.Errorf("finding meta row: %w", err)
		}
		result = append(result, meta)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding meta rows: %w", err)
	}
	return result, nil
}

// ListFindingsByScanAndIDs returns detailed findings for one scan and ID set.
func (p *PostgresStore) ListFindingsByScanAndIDs(ctx context.Context, scanID string, findingIDs []string) ([]domain.Finding, error) {
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return nil, err
	}
	unique := make([]string, 0, len(findingIDs))
	seen := map[string]struct{}{}
	for _, findingID := range findingIDs {
		normalized := strings.TrimSpace(findingID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) == 0 {
		return []domain.Finding{}, nil
	}
	placeholders := make([]string, 0, len(unique))
	args := make([]any, 0, len(unique)+1)
	args = append(args, scanID)
	for i, findingID := range unique {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+2))
		args = append(args, findingID)
	}
	rows, err := p.queryContext(
		ctx,
		fmt.Sprintf(`SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
		 FROM findings f
		 WHERE f.scan_id = $1
		   AND f.finding_id IN (%s)`, strings.Join(placeholders, ",")),
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings by ids: %w", err)
	}
	defer rows.Close()
	return findingsFromSQLRows(rows)
}

// ListFindingTrendCounts aggregates finding totals per scan and severity.
func (p *PostgresStore) ListFindingTrendCounts(ctx context.Context, scanIDs []string, severity string, findingType string) ([]FindingTrendCount, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	unique := make([]string, 0, len(scanIDs))
	seen := map[string]struct{}{}
	for _, scanID := range scanIDs {
		normalized := strings.TrimSpace(scanID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) == 0 {
		return []FindingTrendCount{}, nil
	}
	placeholders := make([]string, 0, len(unique))
	args := make([]any, 0, len(unique)+4)
	args = append(args, scope.TenantID, scope.WorkspaceID, strings.ToLower(strings.TrimSpace(severity)), strings.ToLower(strings.TrimSpace(findingType)))
	for i, scanID := range unique {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+5))
		args = append(args, scanID)
	}
	rows, err := p.queryContext(
		ctx,
		fmt.Sprintf(`SELECT s.id, s.started_at, f.severity, COUNT(f.finding_id)
		 FROM scans s
		 LEFT JOIN findings f
		   ON f.scan_id = s.id
		  AND ($3 = '' OR LOWER(f.severity) = $3)
		  AND ($4 = '' OR LOWER(f.type) = $4)
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		   AND s.id IN (%s)
		 GROUP BY s.id, s.started_at, f.severity`, strings.Join(placeholders, ",")),
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("query finding trend counts: %w", err)
	}
	defer rows.Close()
	result := make([]FindingTrendCount, 0)
	for rows.Next() {
		var count FindingTrendCount
		var severityValue sql.NullString
		if err := rows.Scan(&count.ScanID, &count.StartedAt, &severityValue, &count.TotalCount); err != nil {
			return nil, fmt.Errorf("finding trend row: %w", err)
		}
		if severityValue.Valid {
			count.Severity = severityValue.String
		}
		result = append(result, count)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding trend rows: %w", err)
	}
	return result, nil
}

// ListRepoFindingTrendCounts aggregates repository finding totals by repo scan and severity.
func (p *PostgresStore) ListRepoFindingTrendCounts(ctx context.Context, repoScanIDs []string, severity string, findingType string) ([]FindingTrendCount, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	unique := make([]string, 0, len(repoScanIDs))
	seen := map[string]struct{}{}
	for _, repoScanID := range repoScanIDs {
		normalized := strings.TrimSpace(repoScanID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) == 0 {
		return []FindingTrendCount{}, nil
	}

	placeholders := make([]string, 0, len(unique))
	args := make([]any, 0, len(unique)+4)
	args = append(args, scope.TenantID, scope.WorkspaceID, strings.ToLower(strings.TrimSpace(severity)), strings.ToLower(strings.TrimSpace(findingType)))
	for i, repoScanID := range unique {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+5))
		args = append(args, repoScanID)
	}

	rows, err := p.queryContext(
		ctx,
		fmt.Sprintf(`SELECT rs.id, rs.started_at, rf.severity, COUNT(rf.finding_id)
		 FROM repo_scans rs
		 LEFT JOIN repo_findings rf
		   ON rf.repo_scan_id = rs.id
		  AND ($3 = '' OR LOWER(rf.severity) = $3)
		  AND ($4 = '' OR LOWER(rf.type) = $4)
		 WHERE rs.tenant_id = $1
		   AND rs.workspace_id = $2
		   AND rs.id IN (%s)
		 GROUP BY rs.id, rs.started_at, rf.severity`, strings.Join(placeholders, ",")),
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("query repo finding trend counts: %w", err)
	}
	defer rows.Close()

	result := make([]FindingTrendCount, 0)
	for rows.Next() {
		var count FindingTrendCount
		var severityValue sql.NullString
		if err := rows.Scan(&count.ScanID, &count.StartedAt, &severityValue, &count.TotalCount); err != nil {
			return nil, fmt.Errorf("repo finding trend row: %w", err)
		}
		if severityValue.Valid {
			count.Severity = severityValue.String
		}
		result = append(result, count)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo finding trend rows: %w", err)
	}
	return result, nil
}

// UpsertAuthzEntityAttributes creates or updates trusted authorization attributes.
func (p *PostgresStore) UpsertAuthzEntityAttributes(ctx context.Context, attributes AuthzEntityAttributes) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzEntityAttributesForWrite(attributes)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_entity_attributes (
			tenant_id, workspace_id, entity_kind, entity_type, entity_id, owner_team, env, risk_tier, classification, updated_at
		) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10)
		ON CONFLICT (tenant_id, workspace_id, entity_kind, entity_type, entity_id)
		DO UPDATE SET
			owner_team = EXCLUDED.owner_team,
			env = EXCLUDED.env,
			risk_tier = EXCLUDED.risk_tier,
			classification = EXCLUDED.classification,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.EntityKind,
		normalized.EntityType,
		normalized.EntityID,
		normalized.OwnerTeam,
		normalized.Environment,
		normalized.RiskTier,
		normalized.Classification,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz entity attributes: %w", err)
	}
	return nil
}

// GetAuthzEntityAttributes returns trusted authorization attributes for one entity.
func (p *PostgresStore) GetAuthzEntityAttributes(ctx context.Context, entityKind string, entityType string, entityID string) (AuthzEntityAttributes, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzEntityAttributes{}, err
	}
	normalized, err := NormalizeAuthzEntityAttributesForWrite(AuthzEntityAttributes{
		EntityKind: entityKind,
		EntityType: entityType,
		EntityID:   entityID,
	})
	if err != nil {
		return AuthzEntityAttributes{}, err
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, entity_kind, entity_type, entity_id, COALESCE(owner_team, ''), COALESCE(env, ''), COALESCE(risk_tier, ''), COALESCE(classification, ''), updated_at
		 FROM authz_entity_attributes
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND entity_kind = $3
		   AND entity_type = $4
		   AND entity_id = $5`,
		scope.TenantID,
		scope.WorkspaceID,
		normalized.EntityKind,
		normalized.EntityType,
		normalized.EntityID,
	)
	record, err := scanAuthzEntityAttributes(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzEntityAttributes{}, ErrNotFound
		}
		return AuthzEntityAttributes{}, fmt.Errorf("query authz entity attributes: %w", err)
	}
	return record, nil
}

// UpsertAuthzRelationship creates or updates one scoped ReBAC tuple.
func (p *PostgresStore) UpsertAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzRelationshipForWrite(relationship)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_relationships (
			tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id)
		DO UPDATE SET
			source = EXCLUDED.source,
			expires_at = EXCLUDED.expires_at,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.SubjectType,
		normalized.SubjectID,
		normalized.Relation,
		normalized.ObjectType,
		normalized.ObjectID,
		normalized.Source,
		normalized.ExpiresAt,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz relationship: %w", err)
	}
	return nil
}

// DeleteAuthzRelationship removes one scoped ReBAC tuple.
func (p *PostgresStore) DeleteAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzRelationshipForWrite(relationship)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`DELETE FROM authz_relationships
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND subject_type = $3
		   AND subject_id = $4
		   AND relation = $5
		   AND object_type = $6
		   AND object_id = $7`,
		scope.TenantID,
		scope.WorkspaceID,
		normalized.SubjectType,
		normalized.SubjectID,
		normalized.Relation,
		normalized.ObjectType,
		normalized.ObjectID,
	)
	if err != nil {
		return fmt.Errorf("delete authz relationship: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// ListAuthzRelationships returns scoped ReBAC tuples using optional filters.
func (p *PostgresStore) ListAuthzRelationships(ctx context.Context, filter AuthzRelationshipFilter, limit int) ([]AuthzRelationship, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	subjectType := strings.ToLower(strings.TrimSpace(filter.SubjectType))
	subjectID := strings.TrimSpace(filter.SubjectID)
	relation := strings.ToLower(strings.TrimSpace(filter.Relation))
	if relation != "" {
		if _, ok := validAuthzRelationships[relation]; !ok {
			return nil, fmt.Errorf("invalid relation value")
		}
	}
	objectType := strings.ToLower(strings.TrimSpace(filter.ObjectType))
	objectID := strings.TrimSpace(filter.ObjectID)

	args := []any{scope.TenantID, scope.WorkspaceID}
	query := strings.Builder{}
	query.WriteString(`SELECT tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at
		FROM authz_relationships
		WHERE tenant_id = $1
		  AND workspace_id = $2`)

	next := 3
	if subjectType != "" {
		query.WriteString(fmt.Sprintf(" AND subject_type = $%d", next))
		args = append(args, subjectType)
		next++
	}
	if subjectID != "" {
		query.WriteString(fmt.Sprintf(" AND subject_id = $%d", next))
		args = append(args, subjectID)
		next++
	}
	if relation != "" {
		query.WriteString(fmt.Sprintf(" AND relation = $%d", next))
		args = append(args, relation)
		next++
	}
	if objectType != "" {
		query.WriteString(fmt.Sprintf(" AND object_type = $%d", next))
		args = append(args, objectType)
		next++
	}
	if objectID != "" {
		query.WriteString(fmt.Sprintf(" AND object_id = $%d", next))
		args = append(args, objectID)
		next++
	}
	if !filter.IncludeExpired {
		query.WriteString(fmt.Sprintf(" AND (expires_at IS NULL OR expires_at > $%d)", next))
		args = append(args, time.Now().UTC())
		next++
	}
	query.WriteString(" ORDER BY subject_type ASC, subject_id ASC, relation ASC, object_type ASC, object_id ASC")
	if limit > 0 {
		query.WriteString(fmt.Sprintf(" LIMIT $%d", next))
		args = append(args, limit)
	}

	rows, err := p.queryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query authz relationships: %w", err)
	}
	defer rows.Close()

	result := []AuthzRelationship{}
	for rows.Next() {
		record, scanErr := scanAuthzRelationship(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("authz relationship row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz relationship rows: %w", err)
	}
	return result, nil
}

// UpsertAuthzPolicySet creates or updates one scoped policy set metadata record.
func (p *PostgresStore) UpsertAuthzPolicySet(ctx context.Context, policySet AuthzPolicySet) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzPolicySetForWrite(policySet)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_policy_sets (
			tenant_id, workspace_id, policy_set_id, display_name, description, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8)
		ON CONFLICT (tenant_id, workspace_id, policy_set_id)
		DO UPDATE SET
			display_name = EXCLUDED.display_name,
			description = EXCLUDED.description,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.DisplayName,
		normalized.Description,
		normalized.CreatedBy,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz policy set: %w", err)
	}
	return nil
}

// GetAuthzPolicySet returns one scoped policy set metadata record.
func (p *PostgresStore) GetAuthzPolicySet(ctx context.Context, policySetID string) (AuthzPolicySet, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicySet{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicySet{}, err
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, display_name, COALESCE(description, ''), COALESCE(created_by, ''), created_at, updated_at
		 FROM authz_policy_sets
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
	)
	record, err := scanAuthzPolicySet(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzPolicySet{}, ErrNotFound
		}
		return AuthzPolicySet{}, fmt.Errorf("query authz policy set: %w", err)
	}
	return record, nil
}

// CreateAuthzPolicyVersion persists one immutable policy bundle version.
func (p *PostgresStore) CreateAuthzPolicyVersion(ctx context.Context, version AuthzPolicyVersion) (AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(version.PolicySetID)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	if _, err := p.GetAuthzPolicySet(ctx, normalizedPolicySetID); err != nil {
		return AuthzPolicyVersion{}, err
	}
	autoIncrement := version.Version <= 0
	if autoIncrement {
		// Placeholder only for shared normalization; SQL computes final version.
		version.Version = 1
	}
	version.PolicySetID = normalizedPolicySetID

	normalized, err := NormalizeAuthzPolicyVersionForWrite(version)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	if autoIncrement {
		const maxAutoVersionInsertRetries = 5
		for attempt := 0; attempt < maxAutoVersionInsertRetries; attempt++ {
			row := p.queryRowContext(
				ctx,
				`INSERT INTO authz_policy_versions (
					tenant_id, workspace_id, policy_set_id, version, bundle, checksum, created_by, created_at
				)
				SELECT
					$1,
					$2,
					$3,
					COALESCE(MAX(version), 0) + 1,
					$4::jsonb,
					$5,
					NULLIF($6, ''),
					$7
				FROM authz_policy_versions
				WHERE tenant_id = $1
				  AND workspace_id = $2
				  AND policy_set_id = $3
				ON CONFLICT (tenant_id, workspace_id, policy_set_id, version) DO NOTHING
				RETURNING tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at`,
				normalized.TenantID,
				normalized.WorkspaceID,
				normalized.PolicySetID,
				normalized.Bundle,
				normalized.Checksum,
				normalized.CreatedBy,
				normalized.CreatedAt,
			)
			record, scanErr := scanAuthzPolicyVersion(row)
			if scanErr == nil {
				return record, nil
			}
			if errorsIsNoRows(scanErr) {
				continue
			}
			return AuthzPolicyVersion{}, fmt.Errorf("insert authz policy version: %w", scanErr)
		}
		return AuthzPolicyVersion{}, fmt.Errorf("failed to allocate authz policy version after retries")
	}

	row := p.queryRowContext(
		ctx,
		`INSERT INTO authz_policy_versions (
			tenant_id, workspace_id, policy_set_id, version, bundle, checksum, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5::jsonb, $6, NULLIF($7, ''), $8)
		RETURNING tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.Version,
		normalized.Bundle,
		normalized.Checksum,
		normalized.CreatedBy,
		normalized.CreatedAt,
	)
	record, err := scanAuthzPolicyVersion(row)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return AuthzPolicyVersion{}, fmt.Errorf("authz policy version already exists")
		}
		return AuthzPolicyVersion{}, fmt.Errorf("insert authz policy version: %w", err)
	}
	return record, nil
}

// GetAuthzPolicyVersion returns one immutable bundle version in scope.
func (p *PostgresStore) GetAuthzPolicyVersion(ctx context.Context, policySetID string, version int) (AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	if version <= 0 {
		return AuthzPolicyVersion{}, fmt.Errorf("version must be greater than zero")
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at
		 FROM authz_policy_versions
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3
		   AND version = $4`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
		version,
	)
	record, err := scanAuthzPolicyVersion(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzPolicyVersion{}, ErrNotFound
		}
		return AuthzPolicyVersion{}, fmt.Errorf("query authz policy version: %w", err)
	}
	return record, nil
}

// ListAuthzPolicyVersions returns policy versions for one policy set ordered by newest first.
func (p *PostgresStore) ListAuthzPolicyVersions(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return nil, err
	}
	const maxPolicyVersionListLimit = 500
	if limit <= 0 {
		limit = 100
	} else if limit > maxPolicyVersionListLimit {
		limit = maxPolicyVersionListLimit
	}

	rows, err := p.queryContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at
		 FROM authz_policy_versions
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3
		 ORDER BY version DESC
		 LIMIT $4`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query authz policy versions: %w", err)
	}
	defer rows.Close()

	result := []AuthzPolicyVersion{}
	for rows.Next() {
		record, scanErr := scanAuthzPolicyVersion(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("authz policy version row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz policy version rows: %w", err)
	}
	return result, nil
}

// UpsertAuthzPolicyRollout creates or updates one scoped rollout pointer row.
func (p *PostgresStore) UpsertAuthzPolicyRollout(ctx context.Context, rollout AuthzPolicyRollout) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzPolicyRolloutForWrite(rollout)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID
	tenantAllowlistPayload, err := json.Marshal(normalized.TenantAllowlist)
	if err != nil {
		return fmt.Errorf("marshal tenant allowlist: %w", err)
	}
	workspaceAllowlistPayload, err := json.Marshal(normalized.WorkspaceAllowlist)
	if err != nil {
		return fmt.Errorf("marshal workspace allowlist: %w", err)
	}
	validatedVersionsPayload, err := json.Marshal(normalized.ValidatedVersions)
	if err != nil {
		return fmt.Errorf("marshal validated versions: %w", err)
	}

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_policy_rollouts (
			tenant_id, workspace_id, policy_set_id, active_version, candidate_version, mode,
			tenant_allowlist, workspace_allowlist, canary_percentage, validated_versions, updated_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10::jsonb, NULLIF($11, ''), $12)
		ON CONFLICT (tenant_id, workspace_id, policy_set_id)
		DO UPDATE SET
			active_version = EXCLUDED.active_version,
			candidate_version = EXCLUDED.candidate_version,
			mode = EXCLUDED.mode,
			tenant_allowlist = EXCLUDED.tenant_allowlist,
			workspace_allowlist = EXCLUDED.workspace_allowlist,
			canary_percentage = EXCLUDED.canary_percentage,
			validated_versions = EXCLUDED.validated_versions,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.ActiveVersion,
		normalized.CandidateVersion,
		normalized.Mode,
		tenantAllowlistPayload,
		workspaceAllowlistPayload,
		normalized.CanaryPercentage,
		validatedVersionsPayload,
		normalized.UpdatedBy,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz policy rollout: %w", err)
	}
	return nil
}

// GetAuthzPolicyRollout returns one scoped rollout pointer row.
func (p *PostgresStore) GetAuthzPolicyRollout(ctx context.Context, policySetID string) (AuthzPolicyRollout, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, active_version, candidate_version, mode,
			COALESCE(tenant_allowlist, '[]'::jsonb)::text,
			COALESCE(workspace_allowlist, '[]'::jsonb)::text,
			canary_percentage,
			COALESCE(validated_versions, '[]'::jsonb)::text,
			COALESCE(updated_by, ''), updated_at
		 FROM authz_policy_rollouts
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
	)
	record, err := scanAuthzPolicyRollout(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzPolicyRollout{}, ErrNotFound
		}
		return AuthzPolicyRollout{}, fmt.Errorf("query authz policy rollout: %w", err)
	}
	return record, nil
}

// AppendAuthzPolicyEvent records one immutable policy lifecycle event.
func (p *PostgresStore) AppendAuthzPolicyEvent(ctx context.Context, event AuthzPolicyEvent) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzPolicyEventForWrite(event)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	}

	var metadataPayload any
	if normalized.Metadata != nil {
		payload, err := json.Marshal(normalized.Metadata)
		if err != nil {
			return fmt.Errorf("marshal authz policy event metadata: %w", err)
		}
		metadataPayload = payload
	}

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_policy_events (
			id, tenant_id, workspace_id, policy_set_id, event_type, from_version, to_version, actor, message, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10::jsonb, $11)`,
		normalized.ID,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.EventType,
		normalized.FromVersion,
		normalized.ToVersion,
		normalized.Actor,
		normalized.Message,
		metadataPayload,
		normalized.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert authz policy event: %w", err)
	}
	return nil
}

// ListAuthzPolicyEvents returns lifecycle events for one policy set (newest first).
func (p *PostgresStore) ListAuthzPolicyEvents(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyEvent, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return nil, err
	}
	const maxPolicyEventListLimit = 500
	if limit <= 0 {
		limit = 100
	} else if limit > maxPolicyEventListLimit {
		limit = maxPolicyEventListLimit
	}

	rows, err := p.queryContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, policy_set_id, event_type, from_version, to_version, COALESCE(actor, ''), COALESCE(message, ''), COALESCE(metadata, '{}'::jsonb), created_at
		 FROM authz_policy_events
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3
		 ORDER BY created_at DESC
		 LIMIT $4`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query authz policy events: %w", err)
	}
	defer rows.Close()

	result := []AuthzPolicyEvent{}
	for rows.Next() {
		record, scanErr := scanAuthzPolicyEvent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("authz policy event row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz policy event rows: %w", err)
	}
	return result, nil
}

// ListIdentities returns identities filtered by scan/provider/type/name prefix.
func (p *PostgresStore) ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error) {
	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filter.ScanID) != "" {
		if err := p.ensureScanInScope(ctx, filter.ScanID); err != nil {
			return nil, err
		}
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT i.id, i.provider, i.type, i.name, COALESCE(i.arn, ''), COALESCE(i.owner_hint, ''), i.created_at, i.last_used_at, i.tags, i.raw_ref
		 FROM identities i
		 JOIN scans s ON s.id = i.scan_id
		 WHERE ($1 = '' OR i.scan_id = $1::uuid)
		   AND ($2 = '' OR i.provider = $2)
		   AND ($3 = '' OR i.type = $3)
		   AND ($4 = '' OR LOWER(i.name) LIKE LOWER($4 || '%'))
		   AND s.tenant_id = $6
		   AND s.workspace_id = $7
		 ORDER BY i.name ASC
		 LIMIT $5`,
		filter.ScanID,
		filter.Provider,
		filter.Type,
		filter.NamePrefix,
		limit,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("query identities: %w", err)
	}
	defer rows.Close()

	result := []domain.Identity{}
	for rows.Next() {
		var identity domain.Identity
		var provider string
		var identityType string
		var arn string
		var ownerHint string
		var createdAt *time.Time
		var tagsJSON []byte
		if err := rows.Scan(&identity.ID, &provider, &identityType, &identity.Name, &arn, &ownerHint, &createdAt, &identity.LastUsedAt, &tagsJSON, &identity.RawRef); err != nil {
			return nil, fmt.Errorf("identity row: %w", err)
		}
		identity.Provider = domain.Provider(provider)
		identity.Type = domain.IdentityType(identityType)
		identity.ARN = arn
		identity.OwnerHint = ownerHint
		if createdAt != nil {
			identity.CreatedAt = createdAt.UTC()
		}
		if len(tagsJSON) > 0 {
			if err := json.Unmarshal(tagsJSON, &identity.Tags); err != nil {
				return nil, fmt.Errorf("decode identity tags: %w", err)
			}
		}
		result = append(result, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity rows: %w", err)
	}
	return result, nil
}

// ListRelationships returns relationships filtered by scan/type/from/to.
func (p *PostgresStore) ListRelationships(ctx context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error) {
	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filter.ScanID) != "" {
		if err := p.ensureScanInScope(ctx, filter.ScanID); err != nil {
			return nil, err
		}
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT r.id, r.type, r.from_node_id, r.to_node_id, COALESCE(r.evidence_ref, ''), r.discovered_at
		 FROM relationships r
		 JOIN scans s ON s.id = r.scan_id
		 WHERE ($1 = '' OR r.scan_id = $1::uuid)
		   AND ($2 = '' OR r.type = $2)
		   AND ($3 = '' OR r.from_node_id = $3)
		   AND ($4 = '' OR r.to_node_id = $4)
		   AND s.tenant_id = $6
		   AND s.workspace_id = $7
		 ORDER BY r.discovered_at DESC
		 LIMIT $5`,
		filter.ScanID,
		filter.Type,
		filter.FromNodeID,
		filter.ToNodeID,
		limit,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("query relationships: %w", err)
	}
	defer rows.Close()

	result := []domain.Relationship{}
	for rows.Next() {
		var relationship domain.Relationship
		var relationshipType string
		if err := rows.Scan(&relationship.ID, &relationshipType, &relationship.FromNodeID, &relationship.ToNodeID, &relationship.EvidenceRef, &relationship.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("relationship row: %w", err)
		}
		relationship.Type = domain.RelationshipType(relationshipType)
		result = append(result, relationship)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("relationship rows: %w", err)
	}
	return result, nil
}

// AppendScanEvent writes one scan event row.
func (p *PostgresStore) AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalizedLevel, levelErr := NormalizeScanEventLevel(strings.ToLower(strings.TrimSpace(level)))
	if levelErr != nil {
		return levelErr
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal scan event metadata: %w", err)
	}
	result, err := p.execContext(
		ctx,
		`INSERT INTO scan_events (id, scan_id, level, message, metadata, created_at)
		 SELECT $1, $2, $3, $4, $5, NOW()
		 FROM scans s
		 WHERE s.id = $2
		   AND s.tenant_id = $6
		   AND s.workspace_id = $7`,
		uuid.NewString(),
		scanID,
		normalizedLevel,
		message,
		payload,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("insert scan event: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// ListScanEvents returns latest event entries for one scan.
func (p *PostgresStore) ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return nil, err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT e.id, e.scan_id, e.level, e.message, e.metadata, e.created_at
		 FROM scan_events e
		 JOIN scans s ON s.id = e.scan_id
		 WHERE e.scan_id = $1
		   AND s.tenant_id = $2
		   AND s.workspace_id = $3
		 ORDER BY e.created_at DESC
		 LIMIT $4`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query scan events: %w", err)
	}
	defer rows.Close()
	result := []ScanEvent{}
	for rows.Next() {
		var row ScanEvent
		var metadata []byte
		if err := rows.Scan(&row.ID, &row.ScanID, &row.Level, &row.Message, &metadata, &row.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		event := ScanEvent{
			ID:        row.ID,
			ScanID:    row.ScanID,
			Level:     row.Level,
			Message:   row.Message,
			CreatedAt: row.CreatedAt,
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
				return nil, fmt.Errorf("decode scan event metadata: %w", err)
			}
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan event rows: %w", err)
	}
	return result, nil
}

// CreateRepoScan inserts a new repository exposure scan row.
func (p *PostgresStore) CreateRepoScan(ctx context.Context, repository string, startedAt time.Time) (RepoScanRecord, error) {
	return p.createRepoScanWithStatus(ctx, repository, "running", 0, 0, startedAt)
}

// CreateQueuedRepoScan inserts one queued repository scan request row.
func (p *PostgresStore) CreateQueuedRepoScan(ctx context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error) {
	return p.createRepoScanWithStatus(ctx, repository, "queued", historyLimit, maxFindings, queuedAt)
}

// CreateQueuedRepoScanWithinLimit inserts one queued repository scan only when the target is idle and queue capacity remains.
func (p *PostgresStore) CreateQueuedRepoScanWithinLimit(ctx context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time, maxPending int) (RepoScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	if maxPending <= 0 {
		maxPending = 1
	}
	tx, err := p.beginTx(ctx)
	if err != nil {
		return RepoScanRecord{}, fmt.Errorf("begin queued repo scan transaction: %w", err)
	}
	defer tx.Rollback()

	normalizedRepository := strings.TrimSpace(repository)
	queueLockKey := fmt.Sprintf("repo-queue:%s:%s", scope.TenantID, scope.WorkspaceID)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, queueLockKey); err != nil {
		return RepoScanRecord{}, fmt.Errorf("lock repo scan queue capacity: %w", err)
	}
	repositoryLockKey := fmt.Sprintf("repo-target:%s:%s:%s", scope.TenantID, scope.WorkspaceID, strings.ToLower(normalizedRepository))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, repositoryLockKey); err != nil {
		return RepoScanRecord{}, fmt.Errorf("lock repo scan target: %w", err)
	}

	var pendingForTarget int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND LOWER(repository) = LOWER($3)
		   AND status IN ('queued', 'running')`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedRepository,
	).Scan(&pendingForTarget); err != nil {
		return RepoScanRecord{}, fmt.Errorf("count pending repo scans: %w", err)
	}
	if pendingForTarget > 0 {
		return RepoScanRecord{}, ErrPendingRepoScanExists
	}

	var queued int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'queued'`,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&queued); err != nil {
		return RepoScanRecord{}, fmt.Errorf("count queued repo scans: %w", err)
	}
	if queued >= maxPending {
		return RepoScanRecord{}, ErrQueueLimitReached
	}

	record := RepoScanRecord{
		ID:           uuid.NewString(),
		TenantID:     scope.TenantID,
		WorkspaceID:  scope.WorkspaceID,
		Repository:   normalizedRepository,
		Status:       "queued",
		StartedAt:    queuedAt.UTC(),
		HistoryLimit: historyLimit,
		MaxFindings:  maxFindings,
	}
	record.TraceParent, record.TraceState = QueueTraceContextFromContext(ctx)
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit, trace_parent, trace_state)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8, NULLIF($9, ''), NULLIF($10, ''))`,
		record.ID,
		record.TenantID,
		record.WorkspaceID,
		record.Repository,
		record.Status,
		record.StartedAt,
		record.HistoryLimit,
		record.MaxFindings,
		record.TraceParent,
		record.TraceState,
	); err != nil {
		return RepoScanRecord{}, fmt.Errorf("insert queued repo scan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RepoScanRecord{}, fmt.Errorf("commit queued repo scan transaction: %w", err)
	}
	return record, nil
}

// ClaimNextQueuedRepoScan atomically claims one queued repository scan.
func (p *PostgresStore) ClaimNextQueuedRepoScan(ctx context.Context) (RepoScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	return p.claimNextQueuedRepoScan(ctx, &scope)
}

// ClaimNextQueuedRepoScanAnyScope atomically claims one queued repository scan across all scopes.
func (p *PostgresStore) ClaimNextQueuedRepoScanAnyScope(ctx context.Context) (RepoScanRecord, error) {
	return p.claimNextQueuedRepoScan(ctx, nil)
}

func (p *PostgresStore) claimNextQueuedRepoScan(ctx context.Context, scope *Scope) (RepoScanRecord, error) {
	query := `WITH next_repo_scan AS (
			SELECT id
			FROM repo_scans
			WHERE status = 'queued'
			ORDER BY started_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE repo_scans AS r
		SET status = 'running',
		    finished_at = NULL,
		    error_message = NULL
		FROM next_repo_scan
		WHERE r.id = next_repo_scan.id
		RETURNING
			r.id,
			r.tenant_id,
			r.workspace_id,
			r.repository,
			r.status,
			r.started_at,
			r.finished_at,
			r.commits_scanned,
			r.files_scanned,
			r.finding_count,
			r.truncated,
			COALESCE(r.error_message, ''),
			r.history_limit,
			r.max_findings_limit,
			COALESCE(r.trace_parent, ''),
			COALESCE(r.trace_state, '')`
	args := []any{}
	if scope != nil {
		query = `WITH next_repo_scan AS (
			SELECT id
			FROM repo_scans
			WHERE tenant_id = $1
			  AND workspace_id = $2
			  AND status = 'queued'
			ORDER BY started_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE repo_scans AS r
		SET status = 'running',
		    finished_at = NULL,
		    error_message = NULL
		FROM next_repo_scan
		WHERE r.id = next_repo_scan.id
		RETURNING
			r.id,
			r.tenant_id,
			r.workspace_id,
			r.repository,
			r.status,
			r.started_at,
			r.finished_at,
			r.commits_scanned,
			r.files_scanned,
			r.finding_count,
			r.truncated,
			COALESCE(r.error_message, ''),
			r.history_limit,
			r.max_findings_limit,
			COALESCE(r.trace_parent, ''),
			COALESCE(r.trace_state, '')`
		args = []any{scope.TenantID, scope.WorkspaceID}
	}
	row := p.queryRowContext(ctx, query, args...)
	if scope == nil {
		row = p.queryRowContextAnyScope(ctx, query, args...)
	}
	record, err := scanQueuedRepoScanRecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return RepoScanRecord{}, ErrNotFound
		}
		return RepoScanRecord{}, fmt.Errorf("claim queued repo scan: %w", err)
	}
	return record, nil
}

// CountQueuedRepoScans returns queued repository scan requests count.
func (p *PostgresStore) CountQueuedRepoScans(ctx context.Context) (int, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	if err := p.queryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'queued'`,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued repo scans: %w", err)
	}
	return count, nil
}

// CountQueuedRepoScansAnyScope returns queued repository scan requests count across all scopes.
func (p *PostgresStore) CountQueuedRepoScansAnyScope(ctx context.Context) (int, error) {
	var count int
	if err := p.queryRowContextAnyScope(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE status = 'queued'`,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued repo scans any scope: %w", err)
	}
	return count, nil
}

// CountPendingRepoScansByRepository returns queued+running scan count for one repository.
func (p *PostgresStore) CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	if err := p.queryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND LOWER(repository) = LOWER($3)
		   AND status IN ('queued', 'running')`,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(repository),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending repo scans: %w", err)
	}
	return count, nil
}

// RequeueRepoScan moves one running repository scan back to queued.
func (p *PostgresStore) RequeueRepoScan(ctx context.Context, repoScanID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE repo_scans
		 SET status = 'queued',
		     started_at = NOW(),
		     finished_at = NULL,
		     error_message = NULL
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3
		   AND status = 'running'`,
		repoScanID,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("requeue repo scan: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("requeue repo scan rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) createRepoScanWithStatus(ctx context.Context, repository string, status string, historyLimit int, maxFindings int, startedAt time.Time) (RepoScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	record := RepoScanRecord{
		ID:           uuid.NewString(),
		TenantID:     scope.TenantID,
		WorkspaceID:  scope.WorkspaceID,
		Repository:   strings.TrimSpace(repository),
		Status:       strings.TrimSpace(status),
		StartedAt:    startedAt.UTC(),
		HistoryLimit: historyLimit,
		MaxFindings:  maxFindings,
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8)`,
		record.ID,
		record.TenantID,
		record.WorkspaceID,
		record.Repository,
		record.Status,
		record.StartedAt,
		record.HistoryLimit,
		record.MaxFindings,
	)
	if err != nil {
		return RepoScanRecord{}, fmt.Errorf("insert repo scan: %w", err)
	}
	return record, nil
}

// GetRepoScan returns one repository scan by id.
func (p *PostgresStore) GetRepoScan(ctx context.Context, repoScanID string) (RepoScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, ''), history_limit, max_findings_limit
		 FROM repo_scans
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3`,
		repoScanID,
		scope.TenantID,
		scope.WorkspaceID,
	)
	record, err := scanRepoScanRecord(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return RepoScanRecord{}, ErrNotFound
		}
		return RepoScanRecord{}, fmt.Errorf("query repo scan: %w", err)
	}
	return record, nil
}

// CompleteRepoScan updates repository scan completion metadata.
func (p *PostgresStore) CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE repo_scans
		 SET status = $2,
		     finished_at = $3,
		     commits_scanned = $4,
		     files_scanned = $5,
		     finding_count = $6,
		     truncated = $7,
		     error_message = $8
		 WHERE id = $1
		   AND tenant_id = $9
		   AND workspace_id = $10`,
		repoScanID,
		strings.TrimSpace(status),
		finishedAt.UTC(),
		commitsScanned,
		filesScanned,
		findingCount,
		truncated,
		nullableString(errorMessage),
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("complete repo scan: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// UpsertRepoFindings inserts repository findings idempotently.
func (p *PostgresStore) UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error {
	if err := p.ensureRepoScanInScope(ctx, repoScanID); err != nil {
		return err
	}
	tx, err := p.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin repo findings transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows := make([][]any, 0, len(findings))
	seenRepoFindings := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, dup := seenRepoFindings[finding.ID]; dup {
			continue
		}
		seenRepoFindings[finding.ID] = struct{}{}
		domain.NormalizeRepoFindingMetadata(&finding)
		pathJSON, pathErr := json.Marshal(finding.Path)
		if pathErr != nil {
			return fmt.Errorf("marshal repo finding path: %w", pathErr)
		}
		evidenceJSON, evidenceErr := json.Marshal(finding.Evidence)
		if evidenceErr != nil {
			return fmt.Errorf("marshal repo finding evidence: %w", evidenceErr)
		}
		createdAt := finding.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		rows = append(rows, []any{
			repoScanID,
			finding.ID,
			string(finding.Type),
			string(finding.Severity),
			finding.Title,
			finding.HumanSummary,
			pathJSON,
			evidenceJSON,
			finding.Remediation,
			createdAt.UTC(),
		})
	}
	if err := executeBulkInsert(
		ctx,
		tx,
		`INSERT INTO repo_findings (repo_scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at) VALUES `,
		` ON CONFLICT (repo_scan_id, finding_id)
		  DO UPDATE SET
		    type = EXCLUDED.type,
		    severity = EXCLUDED.severity,
		    title = EXCLUDED.title,
		    human_summary = EXCLUDED.human_summary,
		    path = EXCLUDED.path,
		    evidence = EXCLUDED.evidence,
		    remediation = EXCLUDED.remediation,
		    created_at = EXCLUDED.created_at`,
		rows,
	); err != nil {
		return fmt.Errorf("upsert repo findings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit repo findings transaction: %w", err)
	}
	return nil
}

// ListRepoScans returns latest repository scans first.
func (p *PostgresStore) ListRepoScans(ctx context.Context, limit int) ([]RepoScanRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, ''), history_limit, max_findings_limit
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		 ORDER BY started_at DESC
		 LIMIT $3`,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query repo scans: %w", err)
	}
	defer rows.Close()
	result := []RepoScanRecord{}
	for rows.Next() {
		record, scanErr := scanRepoScanRecord(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("repo scan row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo scan rows: %w", err)
	}
	return result, nil
}

// ListRepoFindings returns latest repository findings first with optional filters.
func (p *PostgresStore) ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error) {
	normalized := NormalizeRepoFindingFilter(filter)
	repoScanID := normalized.RepoScanID
	if repoScanID != "" {
		if err := p.ensureRepoScanInScope(ctx, repoScanID); err != nil {
			return nil, err
		}
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	query := `SELECT rf.repo_scan_id, rf.finding_id, rf.type, rf.severity, rf.title, rf.human_summary, rf.path, rf.evidence, COALESCE(rf.remediation, ''), rf.created_at, rs.repository
		 FROM repo_findings rf
		 JOIN repo_scans rs ON rs.id = rf.repo_scan_id
		 WHERE ($1 = '' OR rf.repo_scan_id = $1::uuid)
		   AND ($2 = '' OR rf.finding_id = $2)
		   AND ($3 = '' OR rf.severity = $3)
		   AND ($4 = '' OR rf.type = $4)
		   AND rs.tenant_id = $5
		   AND rs.workspace_id = $6
		 ORDER BY ` + repoFindingOrderClause(normalized.SortBy, normalized.SortDesc)
	args := []any{
		repoScanID,
		normalized.FindingID,
		normalized.Severity,
		normalized.Type,
		scope.TenantID,
		scope.WorkspaceID,
	}
	if limit > 0 {
		query += "\n\t\t LIMIT $7"
		args = append(args, limit)
	}
	rows, err := p.queryContext(
		ctx,
		query,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("query repo findings: %w", err)
	}
	defer rows.Close()
	result := []domain.Finding{}
	for rows.Next() {
		var row struct {
			RepoScanID   string
			FindingID    string
			Type         string
			Severity     string
			Title        string
			HumanSummary string
			Path         []byte
			Evidence     []byte
			Remediation  string
			CreatedAt    time.Time
			Repository   string
		}
		if err := rows.Scan(
			&row.RepoScanID,
			&row.FindingID,
			&row.Type,
			&row.Severity,
			&row.Title,
			&row.HumanSummary,
			&row.Path,
			&row.Evidence,
			&row.Remediation,
			&row.CreatedAt,
			&row.Repository,
		); err != nil {
			return nil, fmt.Errorf("repo finding row: %w", err)
		}
		finding := domain.Finding{
			ScanID:       row.RepoScanID,
			ID:           row.FindingID,
			Type:         domain.FindingType(row.Type),
			Severity:     domain.FindingSeverity(row.Severity),
			Title:        row.Title,
			HumanSummary: row.HumanSummary,
			Remediation:  row.Remediation,
			CreatedAt:    row.CreatedAt,
		}
		if finding.Repository == "" {
			finding.Repository = strings.TrimSpace(row.Repository)
		}
		if len(row.Path) > 0 {
			if err := json.Unmarshal(row.Path, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode repo finding path: %w", err)
			}
		}
		if len(row.Evidence) > 0 {
			if err := json.Unmarshal(row.Evidence, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode repo finding evidence: %w", err)
			}
		}
		domain.NormalizeRepoFindingMetadata(&finding)
		result = append(result, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo finding rows: %w", err)
	}
	return result, nil
}

// ListRepoFindingClusters returns repository finding clusters with bounded store-side pagination.
func (p *PostgresStore) ListRepoFindingClusters(ctx context.Context, filter RepoFindingClusterListFilter) ([]domain.RepoFindingCluster, error) {
	normalized := NormalizeRepoFindingClusterListFilter(filter)
	if normalized.RepoScanID != "" {
		if err := p.ensureRepoScanInScope(ctx, normalized.RepoScanID); err != nil {
			return nil, err
		}
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}

	filteredCTE, baseArgs, nextArg := repoFindingClusterFilteredCTE(scope, normalized)
	summaryArgs := append([]any(nil), baseArgs...)
	summaryArgs = append(summaryArgs, normalized.Offset, normalized.Limit+1)
	summaryQuery := fmt.Sprintf(
		`%s,
cluster_summaries AS (
	SELECT
		cluster_key,
		MIN(repository) AS repository,
		MIN(type) AS type,
		MAX(severity_rank) AS severity_rank,
		MAX(detector) AS detector,
		COUNT(*) AS finding_count,
		MIN(created_at) AS first_seen_at,
		MAX(created_at) AS last_seen_at,
		COUNT(DISTINCT NULLIF(file_path, '')) AS path_count,
		COUNT(DISTINCT NULLIF(commit, '')) AS commit_count,
		COUNT(DISTINCT repo_scan_id) AS repo_scan_count
	FROM filtered
	GROUP BY cluster_key
),
latest_cluster_details AS (
	SELECT DISTINCT ON (cluster_key)
		cluster_key,
		title,
		human_summary,
		remediation
	FROM filtered
	ORDER BY cluster_key, created_at DESC, file_path ASC, line_number ASC, finding_id ASC
)
SELECT
	s.cluster_key,
	s.repository,
	s.type,
	CASE s.severity_rank
		WHEN 5 THEN 'critical'
		WHEN 4 THEN 'high'
		WHEN 3 THEN 'medium'
		WHEN 2 THEN 'low'
		WHEN 1 THEN 'info'
		ELSE ''
	END AS severity,
	s.detector,
	d.title,
	d.human_summary,
	d.remediation,
	s.finding_count,
	s.first_seen_at,
	s.last_seen_at,
	s.path_count,
	s.commit_count,
	s.repo_scan_count
FROM cluster_summaries s
JOIN latest_cluster_details d ON d.cluster_key = s.cluster_key
ORDER BY %s
OFFSET $%d
LIMIT $%d`,
		filteredCTE,
		repoFindingClusterOrderClause(normalized.SortBy, normalized.SortDesc),
		nextArg,
		nextArg+1,
	)
	summaryRows, err := p.queryContext(ctx, summaryQuery, summaryArgs...)
	if err != nil {
		return nil, fmt.Errorf("query repo finding cluster summaries: %w", err)
	}
	defer summaryRows.Close()

	type clusterSummaryRow struct {
		ClusterKey    string
		Repository    string
		Type          string
		Severity      string
		Detector      string
		Title         string
		HumanSummary  string
		Remediation   string
		FindingCount  int
		FirstSeenAt   time.Time
		LastSeenAt    time.Time
		PathCount     int
		CommitCount   int
		RepoScanCount int
	}

	orderedKeys := []string{}
	clustersByKey := make(map[string]*domain.RepoFindingCluster)
	for summaryRows.Next() {
		var row clusterSummaryRow
		if err := summaryRows.Scan(
			&row.ClusterKey,
			&row.Repository,
			&row.Type,
			&row.Severity,
			&row.Detector,
			&row.Title,
			&row.HumanSummary,
			&row.Remediation,
			&row.FindingCount,
			&row.FirstSeenAt,
			&row.LastSeenAt,
			&row.PathCount,
			&row.CommitCount,
			&row.RepoScanCount,
		); err != nil {
			return nil, fmt.Errorf("repo finding cluster summary row: %w", err)
		}
		cluster := domain.RepoFindingCluster{
			ID:           domain.RepoFindingClusterIDForKey(row.ClusterKey),
			Repository:   strings.TrimSpace(row.Repository),
			Type:         domain.FindingType(row.Type),
			Severity:     domain.FindingSeverity(row.Severity),
			Detector:     strings.TrimSpace(row.Detector),
			Title:        row.Title,
			HumanSummary: row.HumanSummary,
			Remediation:  row.Remediation,
			Count:        row.FindingCount,
			FirstSeenAt:  row.FirstSeenAt.UTC(),
			LastSeenAt:   row.LastSeenAt.UTC(),
			Spread: domain.RepoFindingClusterSpread{
				Paths:     row.PathCount,
				Commits:   row.CommitCount,
				RepoScans: row.RepoScanCount,
			},
		}
		orderedKeys = append(orderedKeys, row.ClusterKey)
		clustersByKey[row.ClusterKey] = &cluster
	}
	if err := summaryRows.Err(); err != nil {
		return nil, fmt.Errorf("repo finding cluster summary rows: %w", err)
	}
	if len(orderedKeys) == 0 {
		return []domain.RepoFindingCluster{}, nil
	}

	memberArgs := append([]any(nil), baseArgs...)
	memberPlaceholders := make([]string, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		memberPlaceholders = append(memberPlaceholders, fmt.Sprintf("$%d", nextArg))
		memberArgs = append(memberArgs, key)
		nextArg++
	}
	memberQuery := fmt.Sprintf(
		`%s
SELECT
	cluster_key,
	repo_scan_id,
	finding_id,
	type,
	severity,
	title,
	human_summary,
	path,
	evidence,
	remediation,
	created_at,
	repository
FROM filtered
WHERE cluster_key IN (%s)
ORDER BY cluster_key ASC, created_at DESC, file_path ASC, line_number ASC, finding_id ASC`,
		filteredCTE,
		strings.Join(memberPlaceholders, ", "),
	)
	memberRows, err := p.queryContext(ctx, memberQuery, memberArgs...)
	if err != nil {
		return nil, fmt.Errorf("query repo finding cluster members: %w", err)
	}
	defer memberRows.Close()

	for memberRows.Next() {
		var row struct {
			ClusterKey   string
			RepoScanID   string
			FindingID    string
			Type         string
			Severity     string
			Title        string
			HumanSummary string
			Path         []byte
			Evidence     []byte
			Remediation  string
			CreatedAt    time.Time
			Repository   string
		}
		if err := memberRows.Scan(
			&row.ClusterKey,
			&row.RepoScanID,
			&row.FindingID,
			&row.Type,
			&row.Severity,
			&row.Title,
			&row.HumanSummary,
			&row.Path,
			&row.Evidence,
			&row.Remediation,
			&row.CreatedAt,
			&row.Repository,
		); err != nil {
			return nil, fmt.Errorf("repo finding cluster member row: %w", err)
		}
		cluster, exists := clustersByKey[row.ClusterKey]
		if !exists {
			continue
		}
		finding := domain.Finding{
			ScanID:       row.RepoScanID,
			ID:           row.FindingID,
			Type:         domain.FindingType(row.Type),
			Severity:     domain.FindingSeverity(row.Severity),
			Title:        row.Title,
			HumanSummary: row.HumanSummary,
			Remediation:  row.Remediation,
			CreatedAt:    row.CreatedAt.UTC(),
			Repository:   strings.TrimSpace(row.Repository),
		}
		if len(row.Path) > 0 {
			if err := json.Unmarshal(row.Path, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode repo finding cluster member path: %w", err)
			}
		}
		if len(row.Evidence) > 0 {
			if err := json.Unmarshal(row.Evidence, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode repo finding cluster member evidence: %w", err)
			}
		}
		domain.NormalizeRepoFindingMetadata(&finding)
		cluster.Members = append(cluster.Members, domain.RepoFindingClusterMember{
			FindingID:           finding.ID,
			RepoScanID:          strings.TrimSpace(finding.ScanID),
			Repository:          strings.TrimSpace(finding.Repository),
			Commit:              strings.TrimSpace(finding.Commit),
			FilePath:            strings.TrimSpace(finding.FilePath),
			LineNumber:          finding.LineNumber,
			LineSnippet:         finding.LineSnippet,
			LineSnippetRedacted: finding.LineSnippetRedacted,
			CreatedAt:           finding.CreatedAt.UTC(),
		})
	}
	if err := memberRows.Err(); err != nil {
		return nil, fmt.Errorf("repo finding cluster member rows: %w", err)
	}

	result := make([]domain.RepoFindingCluster, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		cluster, exists := clustersByKey[key]
		if !exists {
			continue
		}
		result = append(result, *cluster)
	}
	return result, nil
}

func repoFindingClusterFilteredCTE(scope Scope, filter RepoFindingClusterListFilter) (string, []any, int) {
	args := []any{scope.TenantID, scope.WorkspaceID}
	conditions := []string{
		"rs.tenant_id = $1",
		"rs.workspace_id = $2",
	}
	nextArg := 3
	if filter.RepoScanID != "" {
		conditions = append(conditions, fmt.Sprintf("rf.repo_scan_id = $%d::uuid", nextArg))
		args = append(args, filter.RepoScanID)
		nextArg++
	}
	if filter.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(rf.severity) = $%d", nextArg))
		args = append(args, filter.Severity)
		nextArg++
	}
	if filter.Type != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(rf.type) = $%d", nextArg))
		args = append(args, filter.Type)
		nextArg++
	}

	repositoryExpr := "COALESCE(NULLIF(rf.evidence->>'repository', ''), rs.repository)"
	commitExpr := "COALESCE(NULLIF(rf.evidence->>'commit', ''), '')"
	filePathExpr := `COALESCE(
		NULLIF(rf.evidence->>'file_path', ''),
		CASE
			WHEN jsonb_typeof(rf.path) = 'array' AND jsonb_array_length(rf.path) > 0 THEN rf.path->>0
			ELSE ''
		END,
		''
	)`
	lineNumberExpr := `CASE
		WHEN COALESCE(rf.evidence->>'line_number', '') ~ '^[0-9]+$' THEN (rf.evidence->>'line_number')::integer
		ELSE 0
	END`
	detectorExpr := "COALESCE(NULLIF(rf.evidence->>'detector', ''), '')"
	fingerprintExpr := "NULLIF(rf.evidence->>'secret_fingerprint', '')"
	clusterKeyExpr := fmt.Sprintf(`CASE
		WHEN rf.type = 'secret_exposure' AND %s <> '' AND %s IS NOT NULL
			THEN CONCAT_WS(E'\x1f', 'secret', %s, rf.type, %s, %s)
		WHEN rf.type = 'secret_exposure'
			THEN CONCAT_WS(E'\x1f', 'finding', %s, rf.type, rf.repo_scan_id::text, rf.finding_id)
		WHEN %s <> ''
			THEN CONCAT_WS(E'\x1f', 'detector', %s, rf.type, %s)
		ELSE CONCAT_WS(E'\x1f', 'finding', %s, rf.type, rf.finding_id)
	END`,
		detectorExpr,
		fingerprintExpr,
		repositoryExpr,
		detectorExpr,
		fingerprintExpr,
		repositoryExpr,
		detectorExpr,
		repositoryExpr,
		detectorExpr,
		repositoryExpr,
	)
	severityRankExpr := `CASE LOWER(rf.severity)
		WHEN 'critical' THEN 5
		WHEN 'high' THEN 4
		WHEN 'medium' THEN 3
		WHEN 'low' THEN 2
		WHEN 'info' THEN 1
		ELSE 0
	END`

	query := fmt.Sprintf(
		`WITH filtered AS (
	SELECT
		rf.repo_scan_id,
		rf.finding_id,
		rf.type,
		rf.severity,
		rf.title,
		rf.human_summary,
		COALESCE(rf.path, '[]'::jsonb) AS path,
		COALESCE(rf.evidence, '{}'::jsonb) AS evidence,
		COALESCE(rf.remediation, '') AS remediation,
		rf.created_at,
		%s AS repository,
		%s AS commit,
		%s AS file_path,
		%s AS line_number,
		%s AS detector,
		%s AS cluster_key,
		%s AS severity_rank
	FROM repo_findings rf
	JOIN repo_scans rs ON rs.id = rf.repo_scan_id
	WHERE %s
)`,
		repositoryExpr,
		commitExpr,
		filePathExpr,
		lineNumberExpr,
		detectorExpr,
		clusterKeyExpr,
		severityRankExpr,
		strings.Join(conditions, " AND "),
	)
	return query, args, nextArg
}

func repoFindingClusterOrderClause(sortBy string, desc bool) string {
	direction := "ASC"
	if desc {
		direction = "DESC"
	}
	switch sortBy {
	case "count":
		return fmt.Sprintf("s.finding_count %s, s.cluster_key ASC", direction)
	case "severity":
		return fmt.Sprintf("s.severity_rank %s, s.finding_count %s, s.cluster_key ASC", direction, direction)
	case "repository":
		return fmt.Sprintf("s.repository %s, s.finding_count %s, s.cluster_key ASC", direction, direction)
	case "detector":
		return fmt.Sprintf("s.detector %s, s.finding_count %s, s.cluster_key ASC", direction, direction)
	case "first_seen_at":
		return fmt.Sprintf("s.first_seen_at %s, s.finding_count %s, s.cluster_key ASC", direction, direction)
	default:
		return fmt.Sprintf("s.last_seen_at %s, s.finding_count %s, s.cluster_key ASC", direction, direction)
	}
}

// Close closes database resources.
func (p *PostgresStore) Close() error {
	if p.db == nil {
		return nil
	}
	return p.db.Close()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

const bulkInsertChunkSize = 100

func executeBulkInsert(ctx context.Context, tx *sql.Tx, prefix string, suffix string, values [][]any) error {
	if len(values) == 0 {
		return nil
	}
	for start := 0; start < len(values); start += bulkInsertChunkSize {
		end := start + bulkInsertChunkSize
		if end > len(values) {
			end = len(values)
		}
		chunk := values[start:end]
		argsCap := 0
		maxInt := int(^uint(0) >> 1)
		for _, row := range chunk {
			if len(row) == 0 {
				return errors.New("bulk insert rows must contain at least one value")
			}
			if argsCap > maxInt-len(row) {
				return errors.New("bulk insert argument capacity overflow")
			}
			argsCap += len(row)
		}
		valueParts := make([]string, 0, len(chunk))
		args := make([]any, 0, argsCap)
		placeholder := 1
		for _, row := range chunk {
			rowPlaceholders := make([]string, 0, len(row))
			for _, value := range row {
				rowPlaceholders = append(rowPlaceholders, fmt.Sprintf("$%d", placeholder))
				args = append(args, value)
				placeholder++
			}
			valueParts = append(valueParts, fmt.Sprintf("(%s)", strings.Join(rowPlaceholders, ", ")))
		}
		statement := prefix + strings.Join(valueParts, ", ") + suffix
		if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	return nil
}

func upsertRawAssets(ctx context.Context, tx *sql.Tx, scanID string, assets []providers.RawAsset) error {
	rows := make([][]any, 0, len(assets))
	seenAssets := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		key := asset.SourceID + "\x00" + asset.Kind
		if _, dup := seenAssets[key]; dup {
			continue
		}
		seenAssets[key] = struct{}{}
		collectedAt, err := time.Parse(time.RFC3339Nano, asset.Collected)
		if err != nil {
			collectedAt = time.Now().UTC()
		}
		rows = append(rows, []any{scanID, asset.SourceID, asset.Kind, asset.Payload, collectedAt.UTC()})
	}
	return executeBulkInsert(
		ctx,
		tx,
		`INSERT INTO raw_assets (scan_id, source_id, kind, payload, collected_at) VALUES `,
		` ON CONFLICT (scan_id, source_id, kind)
		  DO UPDATE SET payload = EXCLUDED.payload, collected_at = EXCLUDED.collected_at`,
		rows,
	)
}

func upsertIdentities(ctx context.Context, tx *sql.Tx, scanID string, identities []domain.Identity) error {
	rows := make([][]any, 0, len(identities))
	seenIdentities := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		if _, dup := seenIdentities[identity.ID]; dup {
			continue
		}
		seenIdentities[identity.ID] = struct{}{}
		tagsJSON, err := json.Marshal(identity.Tags)
		if err != nil {
			return fmt.Errorf("marshal identity tags: %w", err)
		}
		rows = append(rows, []any{
			scanID,
			identity.ID,
			string(identity.Provider),
			string(identity.Type),
			identity.Name,
			nullableString(identity.ARN),
			nullableString(identity.OwnerHint),
			nullableTime(identity.CreatedAt),
			identity.LastUsedAt,
			tagsJSON,
			identity.RawRef,
		})
	}
	return executeBulkInsert(
		ctx,
		tx,
		`INSERT INTO identities (scan_id, id, provider, type, name, arn, owner_hint, created_at, last_used_at, tags, raw_ref) VALUES `,
		` ON CONFLICT (scan_id, id)
		  DO UPDATE SET
		    provider = EXCLUDED.provider,
		    type = EXCLUDED.type,
		    name = EXCLUDED.name,
		    arn = EXCLUDED.arn,
		    owner_hint = EXCLUDED.owner_hint,
		    created_at = EXCLUDED.created_at,
		    last_used_at = EXCLUDED.last_used_at,
		    tags = EXCLUDED.tags,
		    raw_ref = EXCLUDED.raw_ref,
		    updated_at = NOW()`,
		rows,
	)
}

func upsertPolicies(ctx context.Context, tx *sql.Tx, scanID string, policies []domain.Policy) error {
	rows := make([][]any, 0, len(policies))
	seenPolicies := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		if _, dup := seenPolicies[policy.ID]; dup {
			continue
		}
		seenPolicies[policy.ID] = struct{}{}
		normalizedJSON, err := json.Marshal(policy.Normalized)
		if err != nil {
			return fmt.Errorf("marshal policy normalized: %w", err)
		}
		rows = append(rows, []any{
			scanID,
			policy.ID,
			string(policy.Provider),
			policy.Name,
			string(policy.Document),
			normalizedJSON,
			policy.RawRef,
		})
	}
	return executeBulkInsert(
		ctx,
		tx,
		`INSERT INTO policies (scan_id, id, provider, name, document, normalized, raw_ref) VALUES `,
		` ON CONFLICT (scan_id, id)
		  DO UPDATE SET
		    provider = EXCLUDED.provider,
		    name = EXCLUDED.name,
		    document = EXCLUDED.document,
		    normalized = EXCLUDED.normalized,
		    raw_ref = EXCLUDED.raw_ref,
		    updated_at = NOW()`,
		rows,
	)
}

func upsertRelationships(ctx context.Context, tx *sql.Tx, scanID string, relationships []domain.Relationship) error {
	rows := make([][]any, 0, len(relationships))
	seenRelationships := make(map[string]struct{}, len(relationships))
	for _, relationship := range relationships {
		if _, dup := seenRelationships[relationship.ID]; dup {
			continue
		}
		seenRelationships[relationship.ID] = struct{}{}
		rows = append(rows, []any{
			scanID,
			relationship.ID,
			string(relationship.Type),
			relationship.FromNodeID,
			relationship.ToNodeID,
			nullableString(relationship.EvidenceRef),
			relationship.DiscoveredAt.UTC(),
		})
	}
	return executeBulkInsert(
		ctx,
		tx,
		`INSERT INTO relationships (scan_id, id, type, from_node_id, to_node_id, evidence_ref, discovered_at) VALUES `,
		` ON CONFLICT (scan_id, id)
		  DO UPDATE SET
		    type = EXCLUDED.type,
		    from_node_id = EXCLUDED.from_node_id,
		    to_node_id = EXCLUDED.to_node_id,
		    evidence_ref = EXCLUDED.evidence_ref,
		    discovered_at = EXCLUDED.discovered_at`,
		rows,
	)
}

func upsertPermissions(ctx context.Context, tx *sql.Tx, scanID string, permissions []providers.PermissionTuple) error {
	rows := make([][]any, 0, len(permissions))
	seenPermissions := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		key := permission.IdentityID + "\x00" + permission.Action + "\x00" + permission.Resource + "\x00" + permission.Effect
		if _, dup := seenPermissions[key]; dup {
			continue
		}
		seenPermissions[key] = struct{}{}
		rows = append(rows, []any{
			scanID,
			permission.IdentityID,
			permission.Action,
			permission.Resource,
			permission.Effect,
		})
	}
	return executeBulkInsert(
		ctx,
		tx,
		`INSERT INTO permissions (scan_id, identity_id, action, resource, effect) VALUES `,
		` ON CONFLICT (scan_id, identity_id, action, resource, effect)
		  DO NOTHING`,
		rows,
	)
}

func (p *PostgresStore) createScanWithStatus(ctx context.Context, provider string, status string, startedAt time.Time) (ScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	record := ScanRecord{
		ID:            uuid.NewString(),
		TenantID:      scope.TenantID,
		WorkspaceID:   scope.WorkspaceID,
		Provider:      strings.TrimSpace(provider),
		Status:        strings.TrimSpace(status),
		StartedAt:     startedAt.UTC(),
		MaxRetryCount: DefaultScanMaxRetryCount,
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, $5, $6, 0, 0)`,
		record.ID,
		record.TenantID,
		record.WorkspaceID,
		record.Provider,
		record.Status,
		record.StartedAt,
	)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("insert scan: %w", err)
	}
	return record, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRepoScanRecord(scanner scanner) (RepoScanRecord, error) {
	var record RepoScanRecord
	var finishedAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
		&record.Repository,
		&record.Status,
		&record.StartedAt,
		&finishedAt,
		&record.CommitsScanned,
		&record.FilesScanned,
		&record.FindingCount,
		&record.Truncated,
		&record.ErrorMessage,
		&record.HistoryLimit,
		&record.MaxFindings,
	); err != nil {
		return RepoScanRecord{}, err
	}
	record.StartedAt = record.StartedAt.UTC()
	if finishedAt.Valid {
		converted := finishedAt.Time.UTC()
		record.FinishedAt = &converted
	}
	return record, nil
}

func scanQueuedRepoScanRecord(scanner scanner) (RepoScanRecord, error) {
	var record RepoScanRecord
	var finishedAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
		&record.Repository,
		&record.Status,
		&record.StartedAt,
		&finishedAt,
		&record.CommitsScanned,
		&record.FilesScanned,
		&record.FindingCount,
		&record.Truncated,
		&record.ErrorMessage,
		&record.HistoryLimit,
		&record.MaxFindings,
		&record.TraceParent,
		&record.TraceState,
	); err != nil {
		return RepoScanRecord{}, err
	}
	record.StartedAt = record.StartedAt.UTC()
	record.TraceParent = strings.TrimSpace(record.TraceParent)
	record.TraceState = strings.TrimSpace(record.TraceState)
	if finishedAt.Valid {
		converted := finishedAt.Time.UTC()
		record.FinishedAt = &converted
	}
	return record, nil
}

func scanScanRecord(scanner scanner) (ScanRecord, error) {
	var record ScanRecord
	var finishedAt sql.NullTime
	var failureCategory sql.NullString
	var nextRetryAt sql.NullTime
	var deadLetteredAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
		&record.Provider,
		&record.Status,
		&record.StartedAt,
		&finishedAt,
		&record.AssetCount,
		&record.FindingCount,
		&record.ErrorMessage,
		&record.RetryCount,
		&record.MaxRetryCount,
		&failureCategory,
		&nextRetryAt,
		&record.DeadLettered,
		&deadLetteredAt,
	); err != nil {
		return ScanRecord{}, err
	}
	record.StartedAt = record.StartedAt.UTC()
	record.FailureCategory = strings.TrimSpace(failureCategory.String)
	if record.MaxRetryCount <= 0 {
		record.MaxRetryCount = DefaultScanMaxRetryCount
	}
	if finishedAt.Valid {
		finished := finishedAt.Time.UTC()
		record.FinishedAt = &finished
	}
	if nextRetryAt.Valid {
		retryAt := nextRetryAt.Time.UTC()
		record.NextRetryAt = &retryAt
	}
	if deadLetteredAt.Valid {
		deadLettered := deadLetteredAt.Time.UTC()
		record.DeadLetteredAt = &deadLettered
	}
	return record, nil
}

func scanQueuedScanRecord(scanner scanner) (ScanRecord, error) {
	var record ScanRecord
	var finishedAt sql.NullTime
	var failureCategory sql.NullString
	var nextRetryAt sql.NullTime
	var deadLetteredAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
		&record.Provider,
		&record.Status,
		&record.StartedAt,
		&finishedAt,
		&record.AssetCount,
		&record.FindingCount,
		&record.ErrorMessage,
		&record.RetryCount,
		&record.MaxRetryCount,
		&failureCategory,
		&nextRetryAt,
		&record.DeadLettered,
		&deadLetteredAt,
		&record.TraceParent,
		&record.TraceState,
	); err != nil {
		return ScanRecord{}, err
	}
	record.StartedAt = record.StartedAt.UTC()
	record.FailureCategory = strings.TrimSpace(failureCategory.String)
	if record.MaxRetryCount <= 0 {
		record.MaxRetryCount = DefaultScanMaxRetryCount
	}
	record.TraceParent = strings.TrimSpace(record.TraceParent)
	record.TraceState = strings.TrimSpace(record.TraceState)
	if finishedAt.Valid {
		finished := finishedAt.Time.UTC()
		record.FinishedAt = &finished
	}
	if nextRetryAt.Valid {
		retryAt := nextRetryAt.Time.UTC()
		record.NextRetryAt = &retryAt
	}
	if deadLetteredAt.Valid {
		deadLettered := deadLetteredAt.Time.UTC()
		record.DeadLetteredAt = &deadLettered
	}
	return record, nil
}

func scanAuthzEntityAttributes(scanner scanner) (AuthzEntityAttributes, error) {
	var record AuthzEntityAttributes
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.EntityKind,
		&record.EntityType,
		&record.EntityID,
		&record.OwnerTeam,
		&record.Environment,
		&record.RiskTier,
		&record.Classification,
		&record.UpdatedAt,
	); err != nil {
		return AuthzEntityAttributes{}, err
	}
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzRelationship(scanner scanner) (AuthzRelationship, error) {
	var record AuthzRelationship
	var expiresAt sql.NullTime
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.SubjectType,
		&record.SubjectID,
		&record.Relation,
		&record.ObjectType,
		&record.ObjectID,
		&record.Source,
		&expiresAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return AuthzRelationship{}, err
	}
	if expiresAt.Valid {
		converted := expiresAt.Time.UTC()
		record.ExpiresAt = &converted
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzPolicySet(scanner scanner) (AuthzPolicySet, error) {
	var record AuthzPolicySet
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&record.DisplayName,
		&record.Description,
		&record.CreatedBy,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return AuthzPolicySet{}, err
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzPolicyVersion(scanner scanner) (AuthzPolicyVersion, error) {
	var record AuthzPolicyVersion
	var bundle string
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&record.Version,
		&bundle,
		&record.Checksum,
		&record.CreatedBy,
		&record.CreatedAt,
	); err != nil {
		return AuthzPolicyVersion{}, err
	}
	record.Bundle = strings.TrimSpace(bundle)
	record.CreatedAt = record.CreatedAt.UTC()
	return record, nil
}

func scanAuthzPolicyRollout(scanner scanner) (AuthzPolicyRollout, error) {
	var record AuthzPolicyRollout
	var activeVersion sql.NullInt64
	var candidateVersion sql.NullInt64
	var tenantAllowlistJSON string
	var workspaceAllowlistJSON string
	var validatedVersionsJSON string
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&activeVersion,
		&candidateVersion,
		&record.Mode,
		&tenantAllowlistJSON,
		&workspaceAllowlistJSON,
		&record.CanaryPercentage,
		&validatedVersionsJSON,
		&record.UpdatedBy,
		&record.UpdatedAt,
	); err != nil {
		return AuthzPolicyRollout{}, err
	}
	if activeVersion.Valid {
		value := int(activeVersion.Int64)
		record.ActiveVersion = &value
	}
	if candidateVersion.Valid {
		value := int(candidateVersion.Int64)
		record.CandidateVersion = &value
	}
	if strings.TrimSpace(tenantAllowlistJSON) != "" {
		if err := json.Unmarshal([]byte(tenantAllowlistJSON), &record.TenantAllowlist); err != nil {
			return AuthzPolicyRollout{}, fmt.Errorf("decode tenant allowlist: %w", err)
		}
	}
	if strings.TrimSpace(workspaceAllowlistJSON) != "" {
		if err := json.Unmarshal([]byte(workspaceAllowlistJSON), &record.WorkspaceAllowlist); err != nil {
			return AuthzPolicyRollout{}, fmt.Errorf("decode workspace allowlist: %w", err)
		}
	}
	if strings.TrimSpace(validatedVersionsJSON) != "" {
		if err := json.Unmarshal([]byte(validatedVersionsJSON), &record.ValidatedVersions); err != nil {
			return AuthzPolicyRollout{}, fmt.Errorf("decode validated versions: %w", err)
		}
	}
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzPolicyEvent(scanner scanner) (AuthzPolicyEvent, error) {
	var record AuthzPolicyEvent
	var fromVersion sql.NullInt64
	var toVersion sql.NullInt64
	var metadata []byte
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&record.EventType,
		&fromVersion,
		&toVersion,
		&record.Actor,
		&record.Message,
		&metadata,
		&record.CreatedAt,
	); err != nil {
		return AuthzPolicyEvent{}, err
	}
	if fromVersion.Valid {
		value := int(fromVersion.Int64)
		record.FromVersion = &value
	}
	if toVersion.Valid {
		value := int(toVersion.Int64)
		record.ToVersion = &value
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &record.Metadata); err != nil {
			return AuthzPolicyEvent{}, fmt.Errorf("decode authz policy event metadata: %w", err)
		}
	}
	record.CreatedAt = record.CreatedAt.UTC()
	return record, nil
}

func findingsFromSQLRows(rows rowsScanner) ([]domain.Finding, error) {
	result := []domain.Finding{}
	for rows.Next() {
		var row struct {
			ScanID       string
			FindingID    string
			Type         string
			Severity     string
			Title        string
			HumanSummary string
			Path         []byte
			Evidence     []byte
			Remediation  string
			CreatedAt    time.Time
		}
		if err := rows.Scan(
			&row.ScanID,
			&row.FindingID,
			&row.Type,
			&row.Severity,
			&row.Title,
			&row.HumanSummary,
			&row.Path,
			&row.Evidence,
			&row.Remediation,
			&row.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("finding row: %w", err)
		}
		finding := domain.Finding{
			ScanID:       row.ScanID,
			ID:           row.FindingID,
			Type:         domain.FindingType(row.Type),
			Severity:     domain.FindingSeverity(row.Severity),
			Title:        row.Title,
			HumanSummary: row.HumanSummary,
			Remediation:  row.Remediation,
			CreatedAt:    row.CreatedAt,
		}
		if len(row.Path) > 0 {
			if err := json.Unmarshal(row.Path, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode finding path: %w", err)
			}
		}
		if len(row.Evidence) > 0 {
			if err := json.Unmarshal(row.Evidence, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode finding evidence: %w", err)
			}
		}
		result = append(result, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding rows: %w", err)
	}
	return result, nil
}

func findingsWithTriageFromSQLRows(rows rowsScanner, now time.Time) ([]domain.Finding, error) {
	result := []domain.Finding{}
	for rows.Next() {
		var row struct {
			ScanID               string
			FindingID            string
			Type                 string
			Severity             string
			Title                string
			HumanSummary         string
			Path                 []byte
			Evidence             []byte
			Remediation          string
			CreatedAt            time.Time
			TriageStatus         string
			TriageAssignee       string
			SuppressionExpiresAt sql.NullTime
			TriageUpdatedAt      sql.NullTime
			TriageUpdatedBy      string
		}
		if err := rows.Scan(
			&row.ScanID,
			&row.FindingID,
			&row.Type,
			&row.Severity,
			&row.Title,
			&row.HumanSummary,
			&row.Path,
			&row.Evidence,
			&row.Remediation,
			&row.CreatedAt,
			&row.TriageStatus,
			&row.TriageAssignee,
			&row.SuppressionExpiresAt,
			&row.TriageUpdatedAt,
			&row.TriageUpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("filtered finding row: %w", err)
		}
		finding := domain.Finding{
			ScanID:       row.ScanID,
			ID:           row.FindingID,
			Type:         domain.FindingType(row.Type),
			Severity:     domain.FindingSeverity(row.Severity),
			Title:        row.Title,
			HumanSummary: row.HumanSummary,
			Remediation:  row.Remediation,
			CreatedAt:    row.CreatedAt,
			Triage: domain.FindingTriage{
				Status:    domain.FindingLifecycleStatus(row.TriageStatus),
				Assignee:  row.TriageAssignee,
				UpdatedBy: row.TriageUpdatedBy,
			},
		}
		if row.SuppressionExpiresAt.Valid {
			value := row.SuppressionExpiresAt.Time.UTC()
			finding.Triage.SuppressionExpiresAt = &value
		}
		if row.TriageUpdatedAt.Valid {
			value := row.TriageUpdatedAt.Time.UTC()
			finding.Triage.UpdatedAt = &value
		}
		finding.Triage = NormalizeFindingTriage(finding.Triage, now)
		if len(row.Path) > 0 {
			if err := json.Unmarshal(row.Path, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode filtered finding path: %w", err)
			}
		}
		if len(row.Evidence) > 0 {
			if err := json.Unmarshal(row.Evidence, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode filtered finding evidence: %w", err)
			}
		}
		result = append(result, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("filtered finding rows: %w", err)
	}
	return result, nil
}

func findingOrderClause(sortBy string, desc bool) string {
	direction := "ASC"
	if desc {
		direction = "DESC"
	}
	switch sortBy {
	case "severity":
		return fmt.Sprintf(`CASE LOWER(f.severity)
			WHEN 'critical' THEN 5
			WHEN 'high' THEN 4
			WHEN 'medium' THEN 3
			WHEN 'low' THEN 2
			WHEN 'info' THEN 1
			ELSE 0
		END %s, f.scan_id %s, f.finding_id %s`, direction, direction, direction)
	case "type":
		return fmt.Sprintf("LOWER(f.type) %s, f.scan_id %s, f.finding_id %s", direction, direction, direction)
	case "title":
		return fmt.Sprintf("LOWER(f.title) %s, f.scan_id %s, f.finding_id %s", direction, direction, direction)
	default:
		return fmt.Sprintf("f.created_at %s, f.scan_id %s, f.finding_id %s", direction, direction, direction)
	}
}

func repoFindingOrderClause(sortBy string, desc bool) string {
	direction := "ASC"
	if desc {
		direction = "DESC"
	}
	switch sortBy {
	case "severity":
		return fmt.Sprintf(`CASE LOWER(rf.severity)
			WHEN 'critical' THEN 5
			WHEN 'high' THEN 4
			WHEN 'medium' THEN 3
			WHEN 'low' THEN 2
			WHEN 'info' THEN 1
			ELSE 0
		END %s, rf.repo_scan_id %s, rf.finding_id %s`, direction, direction, direction)
	case "type":
		return fmt.Sprintf("LOWER(rf.type) %s, rf.repo_scan_id %s, rf.finding_id %s", direction, direction, direction)
	case "title":
		return fmt.Sprintf("LOWER(rf.title) %s, rf.repo_scan_id %s, rf.finding_id %s", direction, direction, direction)
	default:
		return fmt.Sprintf("rf.created_at %s, rf.repo_scan_id %s, rf.finding_id %s", direction, direction, direction)
	}
}

func ensureRowsAffected(result sql.Result) error {
	if result == nil {
		return ErrNotFound
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) ensureScanInScope(ctx context.Context, scanID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	var exists bool
	err = p.queryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("verify scan scope: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) ensureRepoScanInScope(ctx context.Context, repoScanID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	var exists bool
	err = p.queryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM repo_scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`,
		repoScanID,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("verify repo scan scope: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func errorsIsNoRows(err error) bool {
	return err == sql.ErrNoRows
}
