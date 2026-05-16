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
