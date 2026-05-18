package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMFAPendingStateManagerSealsEncryptedState(t *testing.T) {
	now := time.Date(2026, 5, 16, 18, 45, 0, 0, time.UTC)
	manager := NewMFAPendingStateManager(strings.Repeat("a", 64), func() time.Time { return now })
	raw, err := manager.Seal(WorkOSMFAPendingState{
		Mode:                       WorkOSMFAModeEnrollment,
		PendingAuthenticationToken: "pending-token",
		User:                       WorkOSProfile{ID: "user_123", Email: "user@example.com"},
		ReturnTo:                   "https://app.identrail.test/app",
	})
	if err != nil {
		t.Fatalf("seal pending mfa state: %v", err)
	}
	if strings.Contains(raw, "pending-token") || strings.Contains(raw, "user@example.com") {
		t.Fatalf("sealed state must not expose sensitive values: %q", raw)
	}
	opened, err := manager.Open(raw)
	if err != nil {
		t.Fatalf("open pending mfa state: %v", err)
	}
	if opened.PendingAuthenticationToken != "pending-token" || opened.User.Email != "user@example.com" || opened.Mode != WorkOSMFAModeEnrollment {
		t.Fatalf("unexpected pending mfa state: %+v", opened)
	}
}

func TestMFAPendingStateManagerRejectsExpiredState(t *testing.T) {
	now := time.Date(2026, 5, 16, 18, 45, 0, 0, time.UTC)
	managerNow := now
	manager := NewMFAPendingStateManager(strings.Repeat("a", 64), func() time.Time { return managerNow })
	raw, err := manager.Seal(WorkOSMFAPendingState{
		Mode:                       WorkOSMFAModeChallenge,
		PendingAuthenticationToken: "pending-token",
		User:                       WorkOSProfile{ID: "user_123", Email: "user@example.com"},
	})
	if err != nil {
		t.Fatalf("seal pending mfa state: %v", err)
	}
	managerNow = now.Add(DefaultMFAPendingTTL + time.Second)
	if _, err := manager.Open(raw); !errors.Is(err, ErrMFAPendingStateExpired) {
		t.Fatalf("expected expired pending mfa state, got %v", err)
	}
}

func TestMFAPendingStateManagerRejectsInvalidState(t *testing.T) {
	if _, err := (*MFAPendingStateManager)(nil).Seal(WorkOSMFAPendingState{}); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("expected nil manager seal to fail, got %v", err)
	}
	manager := NewMFAPendingStateManager(strings.Repeat("a", 64), nil)
	raw, err := manager.Seal(WorkOSMFAPendingState{
		Mode:                       WorkOSMFAModeChallenge,
		PendingAuthenticationToken: "pending-token",
		User:                       WorkOSProfile{ID: "user_123", Email: "user@example.com"},
	})
	if err != nil {
		t.Fatalf("seal pending mfa state: %v", err)
	}
	if _, err := manager.Open(raw + "tampered"); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("expected tampered state to fail, got %v", err)
	}
	if _, err := manager.Open("bad"); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("expected malformed state to fail, got %v", err)
	}
	badNonce := strings.Join([]string{
		mfaPendingStateVersion,
		base64.RawURLEncoding.EncodeToString([]byte("short")),
		base64.RawURLEncoding.EncodeToString([]byte("ciphertext")),
	}, ".")
	if _, err := manager.Open(badNonce); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("expected short nonce state to fail, got %v", err)
	}
}

func TestMFAPendingStateManagerPreviousKeyRotation(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	oldKey, newKey := strings.Repeat("o", 64), strings.Repeat("n", 64)
	pending := WorkOSMFAPendingState{
		Mode:                       WorkOSMFAModeChallenge,
		PendingAuthenticationToken: "pending-token",
		User:                       WorkOSProfile{ID: "user_123", Email: "user@example.com"},
	}

	sealed, err := NewMFAPendingStateManager(oldKey, clock).Seal(pending)
	if err != nil {
		t.Fatalf("seal with old key: %v", err)
	}

	// Active key only: state sealed with the retired key cannot be opened.
	if _, err := NewMFAPendingStateManager(newKey, clock).Open(sealed); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("expected old-key state rejected without previous key, got %v", err)
	}

	// Rotation window: previous key accepted for decryption.
	rotating := NewMFAPendingStateManager(newKey, clock).WithPreviousSecret(oldKey)
	opened, err := rotating.Open(sealed)
	if err != nil || opened.PendingAuthenticationToken != "pending-token" {
		t.Fatalf("expected previous-key Open to succeed, got %+v err=%v", opened, err)
	}

	// New state is always sealed with the active key.
	fresh, err := rotating.Seal(pending)
	if err != nil {
		t.Fatalf("seal with active key: %v", err)
	}
	if _, err := NewMFAPendingStateManager(oldKey, clock).Open(fresh); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("active-key state must not open under the old key, got %v", err)
	}
	if _, err := rotating.Open(fresh); err != nil {
		t.Fatalf("active-key state must open under the active key, got %v", err)
	}

	// A wrong previous key does not widen acceptance, and clearing it reverts.
	if _, err := NewMFAPendingStateManager(newKey, clock).WithPreviousSecret(strings.Repeat("x", 64)).Open(sealed); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("unrelated previous key must not open old-key state, got %v", err)
	}
	if _, err := rotating.WithPreviousSecret("").Open(sealed); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("cleared previous key must reject old-key state, got %v", err)
	}
}
