package userexport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignedDownloadURL builds a "<jobID>.<expUnix>.<sig>" token bound to jobID
// and the absolute expiry, signed with secret. The token is stateless —
// verification only needs the same secret, so the worker can hand off to the
// API without persisting any per-job credential.
//
// The token format is opaque to the user; callers should attach it as the
// `token` query parameter on the download URL.
func SignedDownloadURL(secret []byte, jobID string, expiresAt time.Time) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("userexport: signing secret is empty")
	}
	if strings.TrimSpace(jobID) == "" {
		return "", errors.New("userexport: job id is empty")
	}
	exp := strconv.FormatInt(expiresAt.UTC().Unix(), 10)
	sig := computeSig(secret, jobID, exp)
	return fmt.Sprintf("%s.%s.%s", jobID, exp, sig), nil
}

// VerifySignedDownloadURL parses and validates a token. On success returns the
// embedded job id. Verification is constant-time on the signature comparison
// so timing cannot leak whether the secret is close to a guess.
func VerifySignedDownloadURL(secret []byte, raw string, now time.Time) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("userexport: signing secret is empty")
	}
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return "", errors.New("userexport: malformed token")
	}
	jobID, expStr, sig := parts[0], parts[1], parts[2]
	if jobID == "" || expStr == "" || sig == "" {
		return "", errors.New("userexport: malformed token")
	}
	expectedSig := computeSig(secret, jobID, expStr)
	if !hmac.Equal([]byte(expectedSig), []byte(sig)) {
		return "", errors.New("userexport: signature mismatch")
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("userexport: invalid expiry: %w", err)
	}
	if time.Unix(expUnix, 0).UTC().Before(now.UTC()) {
		return "", errors.New("userexport: token expired")
	}
	return jobID, nil
}

func computeSig(secret []byte, jobID string, exp string) string {
	mac := hmac.New(sha256.New, secret)
	// Domain-separate so the same key cannot mint tokens accepted by
	// unrelated future verifiers reading the same canonical input.
	mac.Write([]byte("identrail.user_export.v1\n"))
	mac.Write([]byte(jobID))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(exp))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
