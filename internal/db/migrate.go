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
	if err := ensureMigrationLedger(ctx, db); err != nil {
		return err
	}
	for _, file := range files {
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
			applied, appliedErr := migrationApplied(ctx, tx, version)
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
				`INSERT INTO schema_migrations (version, filename, applied_at) VALUES ($1, $2, NOW())`,
				version,
				filepath.Base(file),
			); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("record migration %s: %w", filepath.Base(file), err)
			}
		} else {
			if _, err := tx.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = $1`, version); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("delete migration ledger %s: %w", filepath.Base(file), err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", filepath.Base(file), err)
		}
	}
	return nil
}

func migrationFiles(dir string) ([]string, error) {
	files, err := migrationFilesBySuffix(dir, ".up.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if err := validateUniqueMigrationVersions(files); err != nil {
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
	if err := validateUniqueMigrationVersions(files); err != nil {
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
			version TEXT PRIMARY KEY,
			filename TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL
		)`,
	); err != nil {
		return fmt.Errorf("ensure migration ledger: %w", err)
	}
	return nil
}

func migrationApplied(ctx context.Context, tx *sql.Tx, version string) (bool, error) {
	var appliedAt string
	if err := tx.QueryRowContext(ctx, `SELECT applied_at::text FROM schema_migrations WHERE version = $1`, version).Scan(&appliedAt); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("lookup migration %s: %w", version, err)
	}
	return true, nil
}

func validateUniqueMigrationVersions(files []string) error {
	seen := make(map[string]string, len(files))
	for _, file := range files {
		version, err := migrationVersion(file)
		if err != nil {
			return err
		}
		if existing, exists := seen[version]; exists {
			return fmt.Errorf("duplicate migration version %s in %s and %s", version, filepath.Base(existing), filepath.Base(file))
		}
		seen[version] = file
	}
	return nil
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
