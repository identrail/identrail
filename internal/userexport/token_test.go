package userexport_test

import (
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/userexport"
)

func TestSignedDownloadURLRoundTrip(t *testing.T) {
	secret := []byte("test-secret-please-rotate")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)

	token, err := userexport.SignedDownloadURL(secret, "job-1", exp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.HasPrefix(token, "job-1.") {
		t.Fatalf("unexpected token shape: %s", token)
	}
	jobID, err := userexport.VerifySignedDownloadURL(secret, token, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if jobID != "job-1" {
		t.Fatalf("job id mismatch: %s", jobID)
	}
}

func TestSignedDownloadURLRejectsExpired(t *testing.T) {
	secret := []byte("test-secret")
	exp := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	token, err := userexport.SignedDownloadURL(secret, "job-1", exp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := userexport.VerifySignedDownloadURL(secret, token, exp.Add(time.Second)); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestSignedDownloadURLRejectsTamperedJobID(t *testing.T) {
	secret := []byte("test-secret")
	exp := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Add(time.Hour)
	token, err := userexport.SignedDownloadURL(secret, "job-1", exp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.SplitN(token, ".", 2)
	tampered := "job-2." + parts[1]
	if _, err := userexport.VerifySignedDownloadURL(secret, tampered, exp.Add(-time.Minute)); err == nil {
		t.Fatal("expected signature mismatch")
	}
}

func TestSignedDownloadURLRejectsWrongSecret(t *testing.T) {
	exp := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Add(time.Hour)
	token, err := userexport.SignedDownloadURL([]byte("first-secret"), "job-1", exp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := userexport.VerifySignedDownloadURL([]byte("second-secret"), token, exp.Add(-time.Minute)); err == nil {
		t.Fatal("expected signature mismatch under different secret")
	}
}

func TestSignedDownloadURLRejectsInvalidInputs(t *testing.T) {
	exp := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Add(time.Hour)
	if _, err := userexport.SignedDownloadURL(nil, "job-1", exp); err == nil {
		t.Fatal("expected empty signing secret error")
	}
	if _, err := userexport.SignedDownloadURL([]byte("secret"), "  ", exp); err == nil {
		t.Fatal("expected blank job id error")
	}
	if _, err := userexport.VerifySignedDownloadURL(nil, "token", exp); err == nil {
		t.Fatal("expected empty verify secret error")
	}
	for _, raw := range []string{"", "one.two", "one.two.three.four", ".123.sig", "job..sig", "job.123."} {
		if _, err := userexport.VerifySignedDownloadURL([]byte("secret"), raw, exp); err == nil {
			t.Fatalf("expected malformed token error for %q", raw)
		}
	}
	badExpiry := "job.not-a-unix." + strings.Repeat("a", 43)
	if _, err := userexport.VerifySignedDownloadURL([]byte("secret"), badExpiry, exp); err == nil {
		t.Fatal("expected invalid expiry or signature error")
	}
}
