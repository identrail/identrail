package auth

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/workos/workos-go/v6/pkg/workos_errors"
)

const (
	PendingEmailVerificationCookieName = "identrail_email_verification_pending"
	DefaultEmailVerificationPendingTTL = 10 * time.Minute

	emailVerificationPendingStateVersion = "v1"
	emailVerificationPendingStateAAD     = "identrail.workos.email.verification.pending.v1"
)

var (
	ErrEmailVerificationPendingStateInvalid = errors.New("email verification pending state invalid")
	ErrEmailVerificationPendingStateExpired = errors.New("email verification pending state expired")
)

// WorkOSEmailVerificationRequired is returned when WorkOS refuses a code
// exchange because the user's email address has not been verified. WorkOS
// has already emailed the user a one-time code; the pending token and
// verification id let the app finish the handshake once the user enters it.
type WorkOSEmailVerificationRequired struct {
	Email                      string
	PendingAuthenticationToken string
	EmailVerificationID        string
}

func (e *WorkOSEmailVerificationRequired) Error() string {
	return "workos email verification required"
}

func AsWorkOSEmailVerificationRequired(err error) (*WorkOSEmailVerificationRequired, bool) {
	if err == nil {
		return nil, false
	}
	var required *WorkOSEmailVerificationRequired
	if errors.As(err, &required) && required != nil {
		return required, true
	}
	var verificationErr *workos_errors.EmailVerificationRequiredError
	if errors.As(err, &verificationErr) && verificationErr != nil {
		return &WorkOSEmailVerificationRequired{
			Email:                      verificationErr.Email,
			PendingAuthenticationToken: verificationErr.PendingAuthenticationToken,
			EmailVerificationID:        verificationErr.EmailVerificationID,
		}, true
	}
	var httpErr workos_errors.HTTPError
	if errors.As(err, &httpErr) && httpErr.ErrorCode == workos_errors.EmailVerificationRequiredCode {
		return &WorkOSEmailVerificationRequired{
			PendingAuthenticationToken: httpErr.PendingAuthenticationToken,
			EmailVerificationID:        httpErr.EmailVerificationID,
		}, true
	}
	return nil, false
}

type WorkOSEmailVerificationPendingState struct {
	Intent                     string `json:"intent,omitempty"`
	ReturnTo                   string `json:"return_to,omitempty"`
	Email                      string `json:"email,omitempty"`
	PendingAuthenticationToken string `json:"pending_authentication_token"`
	EmailVerificationID        string `json:"email_verification_id,omitempty"`
	ExpiresAt                  int64  `json:"expires_at"`
}

type WorkOSEmailVerificationVerifyRequest struct {
	PendingAuthenticationToken string
	Code                       string
	IPAddress                  string
	UserAgent                  string
}

type EmailVerificationPendingStateManager struct {
	secret   []byte
	previous []byte
	ttl      time.Duration
	now      func() time.Time
}

func NewEmailVerificationPendingStateManager(secret string, now func() time.Time) *EmailVerificationPendingStateManager {
	if now == nil {
		now = time.Now
	}
	return &EmailVerificationPendingStateManager{
		secret: []byte(strings.TrimSpace(secret)),
		ttl:    DefaultEmailVerificationPendingTTL,
		now:    now,
	}
}

// WithPreviousSecret registers a previous sealing key accepted for opening
// (decryption) only during a key-rotation window. State is always sealed
// with the active secret; the previous secret is never used to seal. An
// empty previous secret clears any prior value. Returns the manager so it
// can be chained off the constructor.
func (m *EmailVerificationPendingStateManager) WithPreviousSecret(previous string) *EmailVerificationPendingStateManager {
	if m == nil {
		return m
	}
	if trimmed := strings.TrimSpace(previous); trimmed != "" {
		m.previous = []byte(trimmed)
	} else {
		m.previous = nil
	}
	return m
}

func (m *EmailVerificationPendingStateManager) TTL() time.Duration {
	if m == nil || m.ttl <= 0 {
		return DefaultEmailVerificationPendingTTL
	}
	return m.ttl
}

func (m *EmailVerificationPendingStateManager) Seal(state WorkOSEmailVerificationPendingState) (string, error) {
	if m == nil || len(m.secret) == 0 {
		return "", ErrEmailVerificationPendingStateInvalid
	}
	now := m.now().UTC()
	if state.ExpiresAt <= 0 {
		state.ExpiresAt = now.Add(m.TTL()).Unix()
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sealed, err := sealPendingPayload(m.secret, emailVerificationPendingStateVersion, emailVerificationPendingStateAAD, payload)
	if err != nil {
		return "", ErrEmailVerificationPendingStateInvalid
	}
	return sealed, nil
}

func (m *EmailVerificationPendingStateManager) Open(raw string) (WorkOSEmailVerificationPendingState, error) {
	if m == nil || len(m.secret) == 0 {
		return WorkOSEmailVerificationPendingState{}, ErrEmailVerificationPendingStateInvalid
	}
	payload, err := openPendingPayload(m.secret, m.previous, emailVerificationPendingStateVersion, emailVerificationPendingStateAAD, raw)
	if err != nil {
		return WorkOSEmailVerificationPendingState{}, ErrEmailVerificationPendingStateInvalid
	}
	var state WorkOSEmailVerificationPendingState
	if err := json.Unmarshal(payload, &state); err != nil {
		return WorkOSEmailVerificationPendingState{}, ErrEmailVerificationPendingStateInvalid
	}
	if state.ExpiresAt <= 0 || !time.Unix(state.ExpiresAt, 0).After(m.now().UTC()) {
		return WorkOSEmailVerificationPendingState{}, ErrEmailVerificationPendingStateExpired
	}
	return state, nil
}
