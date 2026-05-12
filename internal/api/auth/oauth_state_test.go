package auth

import (
	"errors"
	"testing"
	"time"
)

func TestOAuthStateManagerConsumeRejectsReplayAndTampering(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	manager := NewOAuthStateManager("state-secret", func() time.Time { return now })

	raw, err := manager.Issue("login", "/app")
	if err != nil {
		t.Fatalf("issue state: %v", err)
	}
	state, err := manager.Consume(raw)
	if err != nil {
		t.Fatalf("consume state: %v", err)
	}
	if state.Intent != "login" || state.ReturnTo != "/app" {
		t.Fatalf("unexpected state: %+v", state)
	}
	if _, err := manager.Consume(raw); !errors.Is(err, ErrOAuthStateReused) {
		t.Fatalf("expected replay to be rejected, got %v", err)
	}
	if _, err := manager.Consume(raw + "x"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected tampered state to be rejected, got %v", err)
	}
}

func TestOAuthStateManagerRejectsExpiredState(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	manager := NewOAuthStateManager("state-secret", func() time.Time { return now })
	raw, err := manager.Issue("signup", "/onboarding/org")
	if err != nil {
		t.Fatalf("issue state: %v", err)
	}
	now = now.Add(defaultOAuthStateTTL + time.Second)
	if _, err := manager.Consume(raw); !errors.Is(err, ErrOAuthStateExpired) {
		t.Fatalf("expected expired state to be rejected, got %v", err)
	}
}
