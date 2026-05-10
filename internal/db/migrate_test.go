package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMigrationFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "0002_add.up.sql"), []byte("SELECT 2;"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte("SELECT 1;"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "0001_init.down.sql"), []byte("DROP TABLE x;"), 0o600)

	files, err := migrationFiles(dir)
	if err != nil {
		t.Fatalf("migrationFiles failed: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if filepath.Base(files[0]) != "0001_init.up.sql" {
		t.Fatalf("expected sorted file order, got %s", files[0])
	}

	downFiles, err := downMigrationFiles(dir)
	if err != nil {
		t.Fatalf("downMigrationFiles failed: %v", err)
	}
	if len(downFiles) != 1 {
		t.Fatalf("expected 1 down file, got %d", len(downFiles))
	}
	if filepath.Base(downFiles[0]) != "0001_init.down.sql" {
		t.Fatalf("expected reverse-sorted down file order, got %s", downFiles[0])
	}
}

func TestMigrationFilesRejectDuplicateVersions(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte("SELECT 1;"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "0001_add.up.sql"), []byte("SELECT 2;"), 0o600)

	_, err := migrationFiles(dir)
	if err == nil {
		t.Fatal("expected duplicate migration version error")
	}
}

func TestMigrationFilesAllowGrandfatheredDuplicateVersion(t *testing.T) {
	dir := t.TempDir()
	for _, filename := range []string{
		"000015_async_job_queue.up.sql",
		"000015_db_constraints_guardrails.up.sql",
		"000015_tenancy_connector_rls_scope_enforcement.up.sql",
		"000015_tenancy_connector_rls_scope_guardrails.up.sql",
	} {
		if err := os.WriteFile(filepath.Join(dir, filename), []byte("SELECT 1;"), 0o600); err != nil {
			t.Fatalf("write migration: %v", err)
		}
	}

	files, err := migrationFiles(dir)
	if err != nil {
		t.Fatalf("expected grandfathered duplicate version to be allowed: %v", err)
	}
	if len(files) != 4 {
		t.Fatalf("expected 4 files, got %d", len(files))
	}
}

func TestUpFilenameForDown(t *testing.T) {
	if got := upFilenameForDown("0001_init.down.sql"); got != "0001_init.up.sql" {
		t.Fatalf("expected up filename mapping, got %s", got)
	}
	if got := upFilenameForDown("unexpected.sql"); got != "unexpected.sql" {
		t.Fatalf("expected passthrough for non-down migration filenames, got %s", got)
	}
}

func TestShouldSeedLegacyMigration(t *testing.T) {
	if !shouldSeedLegacyMigration("000014_connector_secret_envelopes.up.sql", "000014") {
		t.Fatal("expected pre-cutover migrations to be seeded")
	}
	if !shouldSeedLegacyMigration("000015_db_constraints_guardrails.up.sql", "000015") {
		t.Fatal("expected released cutover migration to be seeded")
	}
	if shouldSeedLegacyMigration("000015_async_job_queue.up.sql", "000015") {
		t.Fatal("expected async job migration to remain pending")
	}
	if shouldSeedLegacyMigration("000016_future_migration.up.sql", "000016") {
		t.Fatal("expected post-cutover migration to remain pending")
	}
}

func TestMigrationLedgerNeedsBackfill(t *testing.T) {
	t.Run("ledger already populated", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM schema_migrations`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

		needsBackfill, err := migrationLedgerNeedsBackfill(context.Background(), db)
		if err != nil {
			t.Fatalf("migrationLedgerNeedsBackfill failed: %v", err)
		}
		if needsBackfill {
			t.Fatal("expected no backfill when ledger already contains rows")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("no legacy schema", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM schema_migrations`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT to_regclass($1)::text`)).
			WithArgs("scans").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))

		needsBackfill, err := migrationLedgerNeedsBackfill(context.Background(), db)
		if err != nil {
			t.Fatalf("migrationLedgerNeedsBackfill failed: %v", err)
		}
		if needsBackfill {
			t.Fatal("expected no backfill when legacy schema is absent")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("legacy schema without full pre-cutover marker", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM schema_migrations`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT to_regclass($1)::text`)).
			WithArgs("scans").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("scans"))
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT to_regclass($1)::text`)).
			WithArgs("tenancy_connector_secret_envelopes").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))

		needsBackfill, err := migrationLedgerNeedsBackfill(context.Background(), db)
		if err != nil {
			t.Fatalf("migrationLedgerNeedsBackfill failed: %v", err)
		}
		if needsBackfill {
			t.Fatal("expected no backfill when pre-cutover marker is missing")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("full pre-cutover schema present", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM schema_migrations`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT to_regclass($1)::text`)).
			WithArgs("scans").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("scans"))
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT to_regclass($1)::text`)).
			WithArgs("tenancy_connector_secret_envelopes").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("tenancy_connector_secret_envelopes"))

		needsBackfill, err := migrationLedgerNeedsBackfill(context.Background(), db)
		if err != nil {
			t.Fatalf("migrationLedgerNeedsBackfill failed: %v", err)
		}
		if !needsBackfill {
			t.Fatal("expected backfill when full pre-cutover schema marker is present")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})
}

func expectEnsureMigrationLedger(mock sqlmock.Sqlmock) {
	mock.ExpectExec(regexp.QuoteMeta(`CREATE TABLE IF NOT EXISTS schema_migrations`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS filename TEXT`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS version TEXT`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE schema_migrations`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE schema_migrations`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DO $$`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`ALTER TABLE schema_migrations`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func expectSkipLegacyLedgerBackfill(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM schema_migrations`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT to_regclass($1)::text`)).
		WithArgs("scans").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))
}

func TestApplyMigrations(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_lock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEnsureMigrationLedger(mock)
	expectSkipLegacyLedgerBackfill(mock)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT applied_at::text FROM schema_migrations WHERE filename = $1`)).
		WithArgs("0001_init.up.sql").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO schema_migrations (filename, version, applied_at) VALUES ($1, $2, NOW())`)).
		WithArgs("0001_init.up.sql", "0001").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_unlock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := ApplyMigrations(context.Background(), db, dir); err != nil {
		t.Fatalf("apply migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyMigrationsSkipsRecordedVersion(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_lock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEnsureMigrationLedger(mock)
	expectSkipLegacyLedgerBackfill(mock)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT applied_at::text FROM schema_migrations WHERE filename = $1`)).
		WithArgs("0001_init.up.sql").
		WillReturnRows(sqlmock.NewRows([]string{"applied_at"}).AddRow("2026-05-05T00:00:00Z"))
	mock.ExpectRollback()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_unlock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := ApplyMigrations(context.Background(), db, dir); err != nil {
		t.Fatalf("apply migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyMigrationsRollsBackFailedMigration(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1; SELECT 2;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_lock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEnsureMigrationLedger(mock)
	expectSkipLegacyLedgerBackfill(mock)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT applied_at::text FROM schema_migrations WHERE filename = $1`)).
		WithArgs("0001_init.up.sql").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnError(sql.ErrTxDone)
	mock.ExpectRollback()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_unlock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = ApplyMigrations(context.Background(), db, dir)
	if err == nil {
		t.Fatal("expected migration failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyDownMigrations(t *testing.T) {
	dir := t.TempDir()
	queryOne := "SELECT 1;"
	queryTwo := "SELECT 2;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.down.sql"), []byte(queryOne), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0002_add.down.sql"), []byte(queryTwo), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_lock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEnsureMigrationLedger(mock)
	// Down migrations are applied in reverse lexical order.
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(queryTwo)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM schema_migrations WHERE filename = $1`)).
		WithArgs("0002_add.up.sql").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(queryOne)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM schema_migrations WHERE filename = $1`)).
		WithArgs("0001_init.up.sql").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_unlock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := ApplyDownMigrations(context.Background(), db, dir); err != nil {
		t.Fatalf("apply down migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyMigrationsNoFiles(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	err = ApplyMigrations(context.Background(), db, t.TempDir())
	if err == nil {
		t.Fatal("expected error when no migration files")
	}
}

func TestPostgresStoreApplyMigrationsNilStore(t *testing.T) {
	store := &PostgresStore{}
	err := store.ApplyMigrations(context.Background(), "migrations")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewPostgresStoreWithDBApplyMigrations(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_lock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEnsureMigrationLedger(mock)
	expectSkipLegacyLedgerBackfill(mock)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT applied_at::text FROM schema_migrations WHERE filename = $1`)).
		WithArgs("0001_init.up.sql").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO schema_migrations (filename, version, applied_at) VALUES ($1, $2, NOW())`)).
		WithArgs("0001_init.up.sql", "0001").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_unlock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.ApplyMigrations(context.Background(), dir); err != nil {
		t.Fatalf("apply migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNewPostgresStoreWithDBApplyDownMigrations(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.down.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_lock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEnsureMigrationLedger(mock)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM schema_migrations WHERE filename = $1`)).
		WithArgs("0001_init.up.sql").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_unlock($1, $2)`)).
		WithArgs(migrationLockNamespace, migrationLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.ApplyDownMigrations(context.Background(), dir); err != nil {
		t.Fatalf("apply down migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyMigrationsWithNilDB(t *testing.T) {
	err := ApplyMigrations(context.Background(), (*sql.DB)(nil), t.TempDir())
	if err == nil {
		t.Fatal("expected error for nil db")
	}
}

func TestApplyDownMigrationsWithNilDB(t *testing.T) {
	err := ApplyDownMigrations(context.Background(), (*sql.DB)(nil), t.TempDir())
	if err == nil {
		t.Fatal("expected error for nil db")
	}
}
