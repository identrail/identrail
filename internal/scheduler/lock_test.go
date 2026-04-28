package scheduler

import (
	"context"
	"testing"
)

func TestInMemoryLockerTryAcquire(t *testing.T) {
	locker := NewInMemoryLocker()

	release, ok := locker.TryAcquire(context.Background(), "scan:aws")
	if !ok || release == nil {
		t.Fatal("expected first acquire success")
	}

	if _, ok := locker.TryAcquire(context.Background(), "scan:aws"); ok {
		t.Fatal("expected lock contention")
	}

	release(context.Background())
	if _, ok := locker.TryAcquire(context.Background(), "scan:aws"); !ok {
		t.Fatal("expected acquire after release")
	}
}

func TestInMemoryLockerReleaseIdempotent(t *testing.T) {
	locker := NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "scan:aws")
	if !ok {
		t.Fatal("expected acquire success")
	}
	release(context.Background())
	release(context.Background())

	if _, ok := locker.TryAcquire(context.Background(), "scan:aws"); !ok {
		t.Fatal("expected acquire after double release")
	}
}
