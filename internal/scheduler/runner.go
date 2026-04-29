package scheduler

import (
	"context"
	"errors"
	"time"
)

// ErrAlreadyRunning indicates a scheduled scan trigger was skipped due to an in-flight run.
var ErrAlreadyRunning = errors.New("scan already running")

// TriggerFunc runs one scheduled scan iteration.
type TriggerFunc func(context.Context) error

// DeadLetterFunc is called when retries are exhausted and trigger still fails.
type DeadLetterFunc func(context.Context, error)

// ErrorFunc is called when scheduled RunOnce returns a non-cancellation error.
type ErrorFunc func(context.Context, error)

// Runner periodically executes a trigger while enforcing single-flight per key.
type Runner struct {
	Interval     time.Duration
	Key          string
	Locker       Locker
	Trigger      TriggerFunc
	MaxAttempts  int
	RetryBackoff time.Duration
	OnDeadLetter DeadLetterFunc
	OnError      ErrorFunc
}

// RunOnce triggers a scan exactly once.
func (r Runner) RunOnce(ctx context.Context) error {
	if r.Trigger == nil {
		return errors.New("runner trigger is required")
	}

	if r.Locker != nil {
		release, ok := r.Locker.TryAcquire(ctx, r.key())
		if !ok {
			return ErrAlreadyRunning
		}
		defer release(context.Background())
	}

	attempts := r.MaxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	backoff := r.RetryBackoff
	if backoff <= 0 {
		backoff = 1 * time.Second
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		lastErr = r.Trigger(ctx)
		if lastErr == nil {
			return nil
		}
		if attempt == attempts {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		next := backoff * 2
		if next > 30*time.Second {
			next = 30 * time.Second
		}
		backoff = next
	}
	if r.OnDeadLetter != nil {
		r.OnDeadLetter(ctx, lastErr)
	}
	return lastErr
}

// Start runs the scheduler loop until context cancellation.
func (r Runner) Start(ctx context.Context) error {
	if r.Interval <= 0 {
		return errors.New("runner interval must be greater than zero")
	}
	if r.Trigger == nil {
		return errors.New("runner trigger is required")
	}

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			err := r.RunOnce(ctx)
			if err == nil || errors.Is(err, ErrAlreadyRunning) {
				continue
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if r.OnError != nil {
				r.OnError(ctx, err)
				continue
			}
			return err
		}
	}
}

func (r Runner) key() string {
	if r.Key == "" {
		return "scan"
	}
	return r.Key
}
