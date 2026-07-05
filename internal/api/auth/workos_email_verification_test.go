package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/workos/workos-go/v6/pkg/workos_errors"
)

func TestEmailVerificationPendingStateManagerSealsEncryptedState(t *testing.T) {
	now := time.Date(2026, 7, 4, 18, 45, 0, 0, time.UTC)
	manager := NewEmailVerificationPendingStateManager(strings.Repeat("a", 64), func() time.Time { return now })
	raw, err := manager.Seal(WorkOSEmailVerificationPendingState{
		Email:                      "user@example.com",
		PendingAuthenticationToken: "pending-token",
		EmailVerificationID:        "email_verification_1",
		ReturnTo:                   "https://app.identrail.test/app",
	})
	if err != nil {
		t.Fatalf("seal pending email verification state: %v", err)
	}
	if strings.Contains(raw, "pending-token") || strings.Contains(raw, "user@example.com") {
		t.Fatalf("sealed state must not expose sensitive values: %q", raw)
	}
	opened, err := manager.Open(raw)
	if err != nil {
		t.Fatalf("open pending email verification state: %v", err)
	}
	if opened.PendingAuthenticationToken != "pending-token" || opened.Email != "user@example.com" || opened.EmailVerificationID != "email_verification_1" {
		t.Fatalf("unexpected pending email verification state: %+v", opened)
	}
}

func TestEmailVerificationPendingStateManagerRejectsExpiredAndInvalidState(t *testing.T) {
	now := time.Date(2026, 7, 4, 18, 45, 0, 0, time.UTC)
	managerNow := now
	manager := NewEmailVerificationPendingStateManager(strings.Repeat("a", 64), func() time.Time { return managerNow })
	raw, err := manager.Seal(WorkOSEmailVerificationPendingState{
		PendingAuthenticationToken: "pending-token",
	})
	if err != nil {
		t.Fatalf("seal pending email verification state: %v", err)
	}
	managerNow = now.Add(DefaultEmailVerificationPendingTTL + time.Second)
	if _, err := manager.Open(raw); !errors.Is(err, ErrEmailVerificationPendingStateExpired) {
		t.Fatalf("expected expired pending state, got %v", err)
	}
	managerNow = now
	if _, err := manager.Open(raw + "tampered"); !errors.Is(err, ErrEmailVerificationPendingStateInvalid) {
		t.Fatalf("expected tampered state to fail, got %v", err)
	}
	if _, err := (*EmailVerificationPendingStateManager)(nil).Seal(WorkOSEmailVerificationPendingState{}); !errors.Is(err, ErrEmailVerificationPendingStateInvalid) {
		t.Fatalf("expected nil manager seal to fail, got %v", err)
	}
}

func TestEmailVerificationPendingStateManagerAADSeparationFromMFA(t *testing.T) {
	// An MFA pending blob must never open as email-verification state (and
	// vice versa) even under the same session key: the two flows carry
	// different privileges and use distinct AADs to prevent cross-replay.
	key := strings.Repeat("a", 64)
	mfaSealed, err := NewMFAPendingStateManager(key, nil).Seal(WorkOSMFAPendingState{
		Mode:                       WorkOSMFAModeChallenge,
		PendingAuthenticationToken: "pending-token",
	})
	if err != nil {
		t.Fatalf("seal mfa state: %v", err)
	}
	if _, err := NewEmailVerificationPendingStateManager(key, nil).Open(mfaSealed); !errors.Is(err, ErrEmailVerificationPendingStateInvalid) {
		t.Fatalf("mfa pending blob must not open as email verification state, got %v", err)
	}
	emailSealed, err := NewEmailVerificationPendingStateManager(key, nil).Seal(WorkOSEmailVerificationPendingState{
		PendingAuthenticationToken: "pending-token",
	})
	if err != nil {
		t.Fatalf("seal email verification state: %v", err)
	}
	if _, err := NewMFAPendingStateManager(key, nil).Open(emailSealed); !errors.Is(err, ErrMFAPendingStateInvalid) {
		t.Fatalf("email verification blob must not open as mfa state, got %v", err)
	}
}

func TestEmailVerificationPendingStateManagerPreviousKeyRotation(t *testing.T) {
	oldKey, newKey := strings.Repeat("o", 64), strings.Repeat("n", 64)
	pending := WorkOSEmailVerificationPendingState{PendingAuthenticationToken: "pending-token"}

	sealed, err := NewEmailVerificationPendingStateManager(oldKey, nil).Seal(pending)
	if err != nil {
		t.Fatalf("seal with old key: %v", err)
	}
	if _, err := NewEmailVerificationPendingStateManager(newKey, nil).Open(sealed); !errors.Is(err, ErrEmailVerificationPendingStateInvalid) {
		t.Fatalf("expected old-key state rejected without previous key, got %v", err)
	}
	rotating := NewEmailVerificationPendingStateManager(newKey, nil).WithPreviousSecret(oldKey)
	opened, err := rotating.Open(sealed)
	if err != nil || opened.PendingAuthenticationToken != "pending-token" {
		t.Fatalf("expected previous-key Open to succeed, got %+v err=%v", opened, err)
	}
}

func TestAsWorkOSEmailVerificationRequired(t *testing.T) {
	if _, ok := AsWorkOSEmailVerificationRequired(nil); ok {
		t.Fatal("nil error must not report email verification required")
	}
	if _, ok := AsWorkOSEmailVerificationRequired(errors.New("boom")); ok {
		t.Fatal("unrelated error must not report email verification required")
	}
	direct := &WorkOSEmailVerificationRequired{PendingAuthenticationToken: "token"}
	if required, ok := AsWorkOSEmailVerificationRequired(direct); !ok || required.PendingAuthenticationToken != "token" {
		t.Fatalf("expected direct error to round-trip, got %+v ok=%v", required, ok)
	}
	typed := &workos_errors.EmailVerificationRequiredError{
		Email:                      "user@example.com",
		EmailVerificationID:        "email_verification_1",
		PendingAuthenticationToken: "token",
	}
	required, ok := AsWorkOSEmailVerificationRequired(typed)
	if !ok || required.Email != "user@example.com" || required.PendingAuthenticationToken != "token" || required.EmailVerificationID != "email_verification_1" {
		t.Fatalf("expected typed sdk error to convert, got %+v ok=%v", required, ok)
	}
	httpErr := workos_errors.HTTPError{
		ErrorCode:                  workos_errors.EmailVerificationRequiredCode,
		PendingAuthenticationToken: "token",
		EmailVerificationID:        "email_verification_1",
	}
	required, ok = AsWorkOSEmailVerificationRequired(httpErr)
	if !ok || required.PendingAuthenticationToken != "token" || required.EmailVerificationID != "email_verification_1" {
		t.Fatalf("expected http error code to convert, got %+v ok=%v", required, ok)
	}
}
