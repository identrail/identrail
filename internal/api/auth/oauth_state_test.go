package auth

import (
	"errors"
	"strings"
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

func TestOAuthStateManagerPreviousKeyRotation(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	oldKey, newKey := "old-state-secret", "new-state-secret"

	oldManager := NewOAuthStateManager(oldKey, clock)
	raw, err := oldManager.Issue("login", "/app")
	if err != nil {
		t.Fatalf("issue with old key: %v", err)
	}

	// Active key only: state signed with the retired key is rejected.
	active := NewOAuthStateManager(newKey, clock)
	if _, err := active.Decode(raw); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("expected old-key state rejected without previous key, got %v", err)
	}

	// Rotation window: previous key accepted for verification.
	rotating := NewOAuthStateManager(newKey, clock).WithPreviousSecret(oldKey)
	state, err := rotating.Decode(raw)
	if err != nil || state.Intent != "login" || state.ReturnTo != "/app" {
		t.Fatalf("expected previous-key state accepted, got state=%+v err=%v", state, err)
	}
	if _, err := rotating.Consume(raw); err != nil {
		t.Fatalf("expected previous-key Consume to succeed, got %v", err)
	}

	// New state is always signed with the active key: an old-key-only
	// manager must reject it.
	fresh, err := rotating.Issue("signup", "/onboarding/org")
	if err != nil {
		t.Fatalf("issue with active key: %v", err)
	}
	if _, err := NewOAuthStateManager(oldKey, clock).Decode(fresh); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("active-key state must not verify under the old key, got %v", err)
	}
	if state, err := rotating.Decode(fresh); err != nil || state.Intent != "signup" {
		t.Fatalf("active-key state must verify under the active key, got %+v err=%v", state, err)
	}

	// A wrong previous key does not widen acceptance.
	if _, err := NewOAuthStateManager(newKey, clock).WithPreviousSecret("unrelated").Decode(raw); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("unrelated previous key must not accept old-key state, got %v", err)
	}
	// An empty previous key clears it, reverting to active-only.
	if _, err := rotating.WithPreviousSecret("").Decode(raw); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("cleared previous key must reject old-key state, got %v", err)
	}
	// The previous key is stored verbatim (matching how the active key is
	// stored): a key with surrounding whitespace still verifies tokens that
	// were signed with those exact bytes, so a rotation grace window is not
	// broken by trimming.
	wsKey := "  ws-old-key  "
	wsRaw, err := NewOAuthStateManager(wsKey, clock).Issue("login", "/app")
	if err != nil {
		t.Fatalf("issue with whitespace key: %v", err)
	}
	if _, err := NewOAuthStateManager(newKey, clock).WithPreviousSecret(wsKey).Decode(wsRaw); err != nil {
		t.Fatalf("verbatim previous key must verify whitespace-key state, got %v", err)
	}
	if _, err := NewOAuthStateManager(newKey, clock).WithPreviousSecret(strings.TrimSpace(wsKey)).Decode(wsRaw); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("trimmed previous key must NOT verify whitespace-key state, got %v", err)
	}

	// A whitespace-only previous key is treated as unset (matching config
	// semantics), so it never becomes an accidental low-entropy verification
	// key: state forged under that whitespace value must be rejected.
	for _, blank := range []string{"   ", "\n", "\t "} {
		mgr := NewOAuthStateManager(newKey, clock).WithPreviousSecret(blank)
		forged, ferr := NewOAuthStateManager(blank, clock).Issue("login", "/app")
		if ferr != nil {
			t.Fatalf("issue under blank key %q: %v", blank, ferr)
		}
		if _, err := mgr.Decode(forged); !errors.Is(err, ErrOAuthStateInvalid) {
			t.Fatalf("whitespace-only previous key %q must be unset, forged state accepted: %v", blank, err)
		}
		if _, err := mgr.Decode(raw); !errors.Is(err, ErrOAuthStateInvalid) {
			t.Fatalf("whitespace-only previous key %q must not verify old-key state: %v", blank, err)
		}
	}
}
