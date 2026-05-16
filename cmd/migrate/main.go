package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	defaultMigrationsDir = "migrations"
	defaultTimeout       = 5 * time.Minute
)

type migrationStore interface {
	ApplyMigrations(context.Context, string) error
	Close() error
}

type storeOpener func(string) (migrationStore, error)

func main() {
	os.Exit(run(context.Background(), os.Getenv, openPostgresStore, os.Stdout, os.Stderr))
}

func openPostgresStore(databaseURL string) (migrationStore, error) {
	return db.NewPostgresStore(databaseURL)
}

func run(
	ctx context.Context,
	getenv func(string) string,
	openStore storeOpener,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	databaseURL := strings.TrimSpace(getenv("IDENTRAIL_DATABASE_URL"))
	if databaseURL == "" {
		fmt.Fprintln(stderr, "IDENTRAIL_DATABASE_URL is required")
		return 1
	}

	migrationsDir := strings.TrimSpace(getenv("IDENTRAIL_MIGRATIONS_DIR"))
	if migrationsDir == "" {
		migrationsDir = defaultMigrationsDir
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	store, err := openStore(databaseURL)
	if err != nil {
		fmt.Fprintf(stderr, "open postgres store: %v\n", err)
		return 1
	}
	defer func() {
		if err := store.Close(); err != nil {
			fmt.Fprintf(stderr, "close postgres store: %v\n", err)
		}
	}()

	if err := store.ApplyMigrations(ctx, migrationsDir); err != nil {
		fmt.Fprintf(stderr, "apply migrations from %s: %v\n", migrationsDir, err)
		return 1
	}

	fmt.Fprintf(stdout, "Applied migrations from %s\n", migrationsDir)
	return 0
}
