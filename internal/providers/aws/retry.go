package aws

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

func retryAWSPage[T any](ctx context.Context, policy RetryPolicy, jitter float64, randFn func() float64, sleep Sleeper, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	var lastErr error
	for attempt := 0; attempt <= policy.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		result, err := fn(ctx)
		if err == nil {
			return result, nil
		}
		if !isRetryable(err) || attempt == policy.MaxRetries {
			lastErr = err
			break
		}
		delay := awsRetryBackoff(policy, jitter, randFn, attempt)
		if sleepErr := sleep(ctx, delay); sleepErr != nil {
			return zero, sleepErr
		}
		lastErr = err
	}
	return zero, fmt.Errorf("retries exhausted: %w", lastErr)
}

func awsRetryBackoff(policy RetryPolicy, jitter float64, randFn func() float64, attempt int) time.Duration {
	delay := policy.BaseDelay << attempt
	if delay > policy.MaxDelay {
		delay = policy.MaxDelay
	}
	if jitter <= 0 {
		return delay
	}
	if randFn == nil {
		randFn = rand.Float64
	}
	jitterRange := float64(delay) * jitter
	jitterOffset := (randFn()*2 - 1) * jitterRange
	jittered := time.Duration(float64(delay) + jitterOffset)
	if jittered < 0 {
		return 0
	}
	if jittered > policy.MaxDelay {
		return policy.MaxDelay
	}
	return jittered
}
