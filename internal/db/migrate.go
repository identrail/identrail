package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const migrationLedgerTable = "schema_migrations"

const (
	migrationLockNamespace = 98321
	migrationLockKey       = 1
	// Legacy deployments without a migration ledger already applied pre-000015 migrations.
	// Seed those entries once so older non-idempotent migrations are not replayed.
	migrationLedgerCutoverVersion = "000015"
)

var legacyShippedCutoverMigrations = map[string]struct{}{
	"000015_db_constraints_guardrails.up.sql":               {},
	"000015_tenancy_connector_rls_scope_enforcement.up.sql": {},
	"000015_tenancy_connector_rls_scope_guardrails.up.sql":  {},
}

var grandfatheredDuplicateMigrationsBySuffix = map[string]map[string]map[string]struct{}{
	".up.sql": {
		"000015": {
			"000015_async_job_queue.up.sql":                         {},
			"000015_db_constraints_guardrails.up.sql":               {},
			"000015_tenancy_connector_rls_scope_enforcement.up.sql": {},
			"000015_tenancy_connector_rls_scope_guardrails.up.sql":  {},
		},
	},
	".down.sql": {
		"000015": {
			"000015_async_job_queue.down.sql":                         {},
			"000015_db_constraints_guardrails.down.sql":               {},
			"000015_tenancy_connector_rls_scope_enforcement.down.sql": {},
			"000015_tenancy_connector_rls_scope_guardrails.down.sql":  {},
		},
	},
}

// ApplyMigrations runs all *.up.sql files in lexical order.
func (p *PostgresStore) ApplyMigrations(ctx context.Context, dir string) error {
	if p == nil || p.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	return ApplyMigrations(ctx, p.db, dir)
}

// ApplyDownMigrations runs all *.down.sql files in reverse lexical order.
func (p *PostgresStore) ApplyDownMigrations(ctx context.Context, dir string) error {
	if p == nil || p.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	return ApplyDownMigrations(ctx, p.db, dir)
}

// ApplyMigrations applies migration scripts from directory against db.
func ApplyMigrations(ctx context.Context, db *sql.DB, dir string) error {
	if db == nil {
		return fmt.Errorf("database is not initialized")
	}
	files, err := migrationFiles(dir)
	if err != nil {
		return err
	}
	return applyMigrationFiles(ctx, db, files, true)
}

// ApplyDownMigrations applies down migration scripts in rollback order.
func ApplyDownMigrations(ctx context.Context, db *sql.DB, dir string) error {
	if db == nil {
		return fmt.Errorf("database is not initialized")
	}
	files, err := downMigrationFiles(dir)
	if err != nil {
		return err
	}
	return applyMigrationFiles(ctx, db, files, false)
}

func applyMigrationFiles(ctx context.Context, db *sql.DB, files []string, recordApplied bool) error {
	if err := acquireMigrationLock(ctx, db); err != nil {
		return err
	}
	defer releaseMigrationLock(ctx, db)
	if err := ensureMigrationLedger(ctx, db); err != nil {
		return err
	}
	if recordApplied {
		if err := seedLegacyMigrationLedger(ctx, db, files); err != nil {
			return err
		}
	}
	for _, file := range files {
		filename := filepath.Base(file)
		ledgerFilename := filename
		if !recordApplied {
			ledgerFilename = upFilenameForDown(filename)
		}
		version, err := migrationVersion(file)
		if err != nil {
			return err
		}
		query, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}
		if strings.TrimSpace(string(query)) == "" {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", filepath.Base(file), err)
		}
		if recordApplied {
			applied, appliedErr := migrationApplied(ctx, tx, filename)
			if appliedErr != nil {
				_ = tx.Rollback()
				return appliedErr
			}
			if applied {
				_ = tx.Rollback()
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, string(query)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", filepath.Base(file), err)
		}
		if recordApplied {
			if _, err := tx.ExecContext(
				ctx,
				`INSERT INTO schema_migrations (filename, version, applied_at) VALUES ($1, $2, NOW())`,
				filename,
				version,
			); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("record migration %s: %w", filename, err)
			}
		} else {
			if _, err := tx.ExecContext(ctx, `DELETE FROM schema_migrations WHERE filename = $1`, ledgerFilename); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("delete migration ledger %s: %w", ledgerFilename, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", filename, err)
		}
	}
	return nil
}

func acquireMigrationLock(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `SELECT pg_advisory_lock($1, $2)`, migrationLockNamespace, migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	return nil
}

func releaseMigrationLock(ctx context.Context, db *sql.DB) {
	if db == nil {
		return
	}
	_, _ = db.ExecContext(ctx, `SELECT pg_advisory_unlock($1, $2)`, migrationLockNamespace, migrationLockKey)
}

func migrationFiles(dir string) ([]string, error) {
	files, err := migrationFilesBySuffix(dir, ".up.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if err := validateUniqueMigrationVersions(files, ".up.sql"); err != nil {
		return nil, err
	}
	return files, nil
}

func downMigrationFiles(dir string) ([]string, error) {
	files, err := migrationFilesBySuffix(dir, ".down.sql")
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	if err := validateUniqueMigrationVersions(files, ".down.sql"); err != nil {
		return nil, err
	}
	return files, nil
}

func migrationFilesBySuffix(dir string, suffix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dir, err)
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, suffix) {
			files = append(files, filepath.Join(dir, name))
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no %s migrations found in %s", suffix, dir)
	}
	return files, nil
}

func ensureMigrationLedger(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(
		ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			version TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL
		)`,
	); err != nil {
		return fmt.Errorf("ensure migration ledger: %w", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS filename TEXT`); err != nil {
		return fmt.Errorf("ensure migration ledger filename column: %w", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS version TEXT`); err != nil {
		return fmt.Errorf("ensure migration ledger version column: %w", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE schema_migrations
		 SET filename = COALESCE(NULLIF(filename, ''), version)
		 WHERE filename IS NULL OR filename = ''`,
	); err != nil {
		return fmt.Errorf("backfill migration ledger filename: %w", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE schema_migrations
		 SET version = COALESCE(NULLIF(version, ''), split_part(filename, '_', 1))
		 WHERE version IS NULL OR version = ''`,
	); err != nil {
		return fmt.Errorf("backfill migration ledger version: %w", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`DO $$
		DECLARE
			pk_name text;
		BEGIN
			SELECT con.conname
			  INTO pk_name
			  FROM pg_constraint con
			  JOIN pg_class rel ON rel.oid = con.conrelid
			 WHERE con.contype = 'p'
			   AND rel.relname = 'schema_migrations';
			IF pk_name IS NOT NULL THEN
				EXECUTE format('ALTER TABLE schema_migrations DROP CONSTRAINT %I', pk_name);
			END IF;
		END $$;`,
	); err != nil {
		return fmt.Errorf("normalize migration ledger primary key: %w", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`ALTER TABLE schema_migrations
		 ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (filename)`,
	); err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("ensure migration ledger primary key: %w", err)
	}
	return nil
}

func migrationApplied(ctx context.Context, tx *sql.Tx, filename string) (bool, error) {
	var appliedAt string
	if err := tx.QueryRowContext(ctx, `SELECT applied_at::text FROM schema_migrations WHERE filename = $1`, filename).Scan(&appliedAt); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("lookup migration %s: %w", filename, err)
	}
	return true, nil
}

func seedLegacyMigrationLedger(ctx context.Context, db *sql.DB, files []string) error {
	needsBackfill, err := migrationLedgerNeedsBackfill(ctx, db)
	if err != nil {
		return err
	}
	if !needsBackfill {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration ledger backfill: %w", err)
	}
	for _, file := range files {
		filename := filepath.Base(file)
		version, err := migrationVersion(file)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if !shouldSeedLegacyMigration(filename, version) {
			continue
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations (filename, version, applied_at)
			 VALUES ($1, $2, NOW())
			 ON CONFLICT (filename) DO NOTHING`,
			filename,
			version,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("seed migration ledger %s: %w", filename, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration ledger backfill: %w", err)
	}
	return nil
}

func migrationLedgerNeedsBackfill(ctx context.Context, db *sql.DB) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		return false, fmt.Errorf("count migration ledger rows: %w", err)
	}
	if count > 0 {
		return false, nil
	}
	hasLegacySchema, err := relationExists(ctx, db, "scans")
	if err != nil {
		return false, err
	}
	if !hasLegacySchema {
		return false, nil
	}
	hasFullPreCutoverSchema, err := relationExists(ctx, db, "tenancy_connector_secret_envelopes")
	if err != nil {
		return false, err
	}
	return hasFullPreCutoverSchema, nil
}

func relationExists(ctx context.Context, db *sql.DB, relation string) (bool, error) {
	var relationName sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, relation).Scan(&relationName); err != nil {
		return false, fmt.Errorf("lookup relation %s: %w", relation, err)
	}
	if !relationName.Valid {
		return false, nil
	}
	return strings.TrimSpace(relationName.String) != "", nil
}

func validateUniqueMigrationVersions(files []string, suffix string) error {
	filesByVersion := make(map[string][]string, len(files))
	for _, file := range files {
		version, err := migrationVersion(file)
		if err != nil {
			return err
		}
		filesByVersion[version] = append(filesByVersion[version], filepath.Base(file))
	}

	allowedByVersion, hasSuffixAllowlist := grandfatheredDuplicateMigrationsBySuffix[suffix]
	for version, names := range filesByVersion {
		if len(names) <= 1 {
			continue
		}
		if !hasSuffixAllowlist {
			return fmt.Errorf("duplicate migration version %s in %s", version, strings.Join(names, ", "))
		}
		allowedNames, allowedVersion := allowedByVersion[version]
		if !allowedVersion {
			return fmt.Errorf("duplicate migration version %s in %s", version, strings.Join(names, ", "))
		}
		for _, name := range names {
			if _, ok := allowedNames[name]; !ok {
				return fmt.Errorf("duplicate migration version %s includes non-grandfathered migration %s", version, name)
			}
		}
	}
	return nil
}

func shouldSeedLegacyMigration(filename string, version string) bool {
	if version < migrationLedgerCutoverVersion {
		return true
	}
	if version > migrationLedgerCutoverVersion {
		return false
	}
	_, ok := legacyShippedCutoverMigrations[filename]
	return ok
}

func upFilenameForDown(downFilename string) string {
	if !strings.HasSuffix(downFilename, ".down.sql") {
		return downFilename
	}
	return strings.TrimSuffix(downFilename, ".down.sql") + ".up.sql"
}

func migrationVersion(path string) (string, error) {
	name := filepath.Base(path)
	parts := strings.SplitN(name, "_", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return "", fmt.Errorf("invalid migration filename %s", name)
	}
	for _, ch := range parts[0] {
		if ch < '0' || ch > '9' {
			return "", fmt.Errorf("invalid migration version %s", name)
		}
	}
	return parts[0], nil
}
