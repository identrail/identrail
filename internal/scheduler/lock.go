package scheduler

import (
	"context"
	"sync"
)

// ReleaseFn releases an acquired lock.
type ReleaseFn func(context.Context)

// Locker coordinates idempotent, non-overlapping scan execution.
type Locker interface {
	TryAcquire(ctx context.Context, key string) (ReleaseFn, bool)
}

// InMemoryLocker is a keyed in-memory lock implementation.
type InMemoryLocker struct {
	mu    sync.Mutex
	locks map[string]bool
}

// NewInMemoryLocker creates an empty in-memory locker.
func NewInMemoryLocker() *InMemoryLocker {
	return &InMemoryLocker{locks: map[string]bool{}}
}

// TryAcquire acquires a key lock if available.
func (l *InMemoryLocker) TryAcquire(_ context.Context, key string) (ReleaseFn, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if key == "" {
		key = "default"
	}
	if l.locks[key] {
		return nil, false
	}
	l.locks[key] = true

	released := false
	return func(_ context.Context) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		delete(l.locks, key)
		released = true
	}, true
}
