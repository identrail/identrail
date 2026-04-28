package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunnerRunOnce(t *testing.T) {
	var calls int32
	runner := Runner{
		Locker: NewInMemoryLocker(),
		Key:    "scan:aws",
		Trigger: func(context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRunnerRunOnceAlreadyRunning(t *testing.T) {
	locker := NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release(context.Background())

	runner := Runner{
		Locker:  locker,
		Key:     "scan:aws",
		Trigger: func(context.Context) error { return nil },
	}

	err := runner.RunOnce(context.Background())
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("expected ErrAlreadyRunning, got %v", err)
	}
}

func TestRunnerStartAndStop(t *testing.T) {
	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := Runner{
		Interval: 5 * time.Millisecond,
		Locker:   NewInMemoryLocker(),
		Key:      "scan:aws",
		Trigger: func(context.Context) error {
			if atomic.AddInt32(&calls, 1) >= 2 {
				cancel()
			}
			return nil
		},
	}

	err := runner.Start(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 calls, got %d", calls)
	}
}

func TestRunnerValidation(t *testing.T) {
	err := Runner{Trigger: nil, Interval: time.Second}.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected trigger validation error")
	}

	err = Runner{Trigger: func(context.Context) error { return nil }}.Start(context.Background())
	if err == nil {
		t.Fatal("expected interval validation error")
	}
}

func TestRunnerRunOnceRetriesThenSucceeds(t *testing.T) {
	var calls int32
	runner := Runner{
		MaxAttempts:  3,
		RetryBackoff: 1 * time.Millisecond,
		Trigger: func(context.Context) error {
			if atomic.AddInt32(&calls, 1) < 3 {
				return errors.New("transient failure")
			}
			return nil
		},
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRunnerRunOnceDeadLetterOnFailure(t *testing.T) {
	var deadLetterCalls int32
	runner := Runner{
		MaxAttempts:  2,
		RetryBackoff: 1 * time.Millisecond,
		Trigger: func(context.Context) error {
			return errors.New("persistent failure")
		},
		OnDeadLetter: func(context.Context, error) {
			atomic.AddInt32(&deadLetterCalls, 1)
		},
	}

	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected persistent failure")
	}
	if deadLetterCalls != 1 {
		t.Fatalf("expected one dead-letter callback, got %d", deadLetterCalls)
	}
}
