package scheduler

import (
	"context"
	"database/sql"
	"hash/fnv"
	"strings"
	"sync"
	"time"
)

// PostgresAdvisoryLocker implements Locker using PostgreSQL advisory locks.
// A dedicated connection is held until release to keep lock ownership session-bound.
type PostgresAdvisoryLocker struct {
	db *sql.DB
}

// NewPostgresAdvisoryLocker builds a PostgreSQL-backed locker.
func NewPostgresAdvisoryLocker(db *sql.DB) *PostgresAdvisoryLocker {
	return &PostgresAdvisoryLocker{db: db}
}

// TryAcquire attempts to take a non-blocking advisory lock for key.
func (l *PostgresAdvisoryLocker) TryAcquire(ctx context.Context, key string) (ReleaseFn, bool) {
	if l == nil || l.db == nil {
		return nil, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lockKey := advisoryLockID(key)
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, false
	}

	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&acquired); err != nil {
		_ = conn.Close()
		return nil, false
	}
	if !acquired {
		_ = conn.Close()
		return nil, false
	}

	var once sync.Once
	return func(releaseCtx context.Context) {
		once.Do(func() {
			if releaseCtx == nil || releaseCtx.Err() != nil {
				releaseCtx = context.Background()
			}
			unlockCtx, cancel := context.WithTimeout(releaseCtx, 5*time.Second)
			defer cancel()
			_, _ = conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock($1)", lockKey)
			_ = conn.Close()
		})
	}, true
}

func advisoryLockID(key string) int64 {
	normalized := strings.TrimSpace(key)
	if normalized == "" {
		normalized = "default"
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(normalized))
	return int64(hasher.Sum64())
}
