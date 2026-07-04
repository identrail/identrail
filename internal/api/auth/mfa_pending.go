package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	PendingMFACookieName = "identrail_mfa_pending"
	DefaultMFAPendingTTL = 10 * time.Minute

	mfaPendingStateVersion = "v1"
	mfaPendingStateAAD     = "identrail.workos.mfa.pending.v1"
)

var (
	ErrMFAPendingStateInvalid = errors.New("mfa pending state invalid")
	ErrMFAPendingStateExpired = errors.New("mfa pending state expired")
)

type WorkOSMFAPendingState struct {
	Mode                       string             `json:"mode"`
	Intent                     string             `json:"intent,omitempty"`
	ReturnTo                   string             `json:"return_to,omitempty"`
	PendingAuthenticationToken string             `json:"pending_authentication_token"`
	User                       WorkOSProfile      `json:"user"`
	AuthenticationFactors      []WorkOSMFAFactor  `json:"authentication_factors,omitempty"`
	ChallengeID                string             `json:"challenge_id,omitempty"`
	ChallengeExpiresAt         string             `json:"challenge_expires_at,omitempty"`
	TOTP                       *WorkOSPendingTOTP `json:"totp,omitempty"`
	ExpiresAt                  int64              `json:"expires_at"`
}

type WorkOSPendingTOTP struct {
	FactorID string `json:"factor_id"`
	QRCode   string `json:"qr_code"`
	Secret   string `json:"secret"`
	URI      string `json:"uri"`
}

type MFAPendingStateManager struct {
	secret   []byte
	previous []byte
	ttl      time.Duration
	now      func() time.Time
}

func NewMFAPendingStateManager(secret string, now func() time.Time) *MFAPendingStateManager {
	if now == nil {
		now = time.Now
	}
	return &MFAPendingStateManager{
		secret: []byte(strings.TrimSpace(secret)),
		ttl:    DefaultMFAPendingTTL,
		now:    now,
	}
}

// WithPreviousSecret registers a previous sealing key accepted for opening
// (decryption) only during a key-rotation window. State is always sealed
// with the active secret; the previous secret is never used to seal. An
// empty previous secret clears any prior value. Returns the manager so it
// can be chained off the constructor.
func (m *MFAPendingStateManager) WithPreviousSecret(previous string) *MFAPendingStateManager {
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

func (m *MFAPendingStateManager) TTL() time.Duration {
	if m == nil || m.ttl <= 0 {
		return DefaultMFAPendingTTL
	}
	return m.ttl
}

func (m *MFAPendingStateManager) Seal(state WorkOSMFAPendingState) (string, error) {
	if m == nil || len(m.secret) == 0 {
		return "", ErrMFAPendingStateInvalid
	}
	now := m.now().UTC()
	if state.ExpiresAt <= 0 {
		state.ExpiresAt = now.Add(m.TTL()).Unix()
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sealed, err := sealPendingPayload(m.secret, mfaPendingStateVersion, mfaPendingStateAAD, payload)
	if err != nil {
		return "", ErrMFAPendingStateInvalid
	}
	return sealed, nil
}

func (m *MFAPendingStateManager) Open(raw string) (WorkOSMFAPendingState, error) {
	if m == nil || len(m.secret) == 0 {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	payload, err := openPendingPayload(m.secret, m.previous, mfaPendingStateVersion, mfaPendingStateAAD, raw)
	if err != nil {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	var state WorkOSMFAPendingState
	if err := json.Unmarshal(payload, &state); err != nil {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	if state.ExpiresAt <= 0 || !time.Unix(state.ExpiresAt, 0).After(m.now().UTC()) {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateExpired
	}
	return state, nil
}

var errPendingPayloadInvalid = errors.New("pending payload invalid")

func sealPendingPayload(secret []byte, version, aad string, payload []byte) (string, error) {
	gcm, err := cipherFor(secret)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, payload, []byte(aad))
	return strings.Join([]string{
		version,
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(ciphertext),
	}, "."), nil
}

// openPendingPayload opens the sealed payload with the active key, falling
// back to the previous key when one is configured (key-rotation window).
// Payloads are only ever sealed with the active key, so the previous key is
// open-only.
func openPendingPayload(secret, previous []byte, version, aad, raw string) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 || parts[0] != version {
		return nil, errPendingPayloadInvalid
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errPendingPayloadInvalid
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errPendingPayloadInvalid
	}
	secrets := [][]byte{secret}
	if len(previous) > 0 {
		secrets = append(secrets, previous)
	}
	for _, candidate := range secrets {
		gcm, err := cipherFor(candidate)
		if err != nil {
			return nil, err
		}
		if len(nonce) != gcm.NonceSize() {
			return nil, errPendingPayloadInvalid
		}
		if payload, err := gcm.Open(nil, nonce, ciphertext, []byte(aad)); err == nil {
			return payload, nil
		}
	}
	return nil, errPendingPayloadInvalid
}

func cipherFor(secret []byte) (cipher.AEAD, error) {
	key := sha256.Sum256(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
