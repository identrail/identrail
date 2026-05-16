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
	secret []byte
	ttl    time.Duration
	now    func() time.Time
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
	gcm, err := m.cipher()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, payload, []byte(mfaPendingStateAAD))
	return strings.Join([]string{
		mfaPendingStateVersion,
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(ciphertext),
	}, "."), nil
}

func (m *MFAPendingStateManager) Open(raw string) (WorkOSMFAPendingState, error) {
	if m == nil || len(m.secret) == 0 {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 || parts[0] != mfaPendingStateVersion {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	gcm, err := m.cipher()
	if err != nil {
		return WorkOSMFAPendingState{}, err
	}
	if len(nonce) != gcm.NonceSize() {
		return WorkOSMFAPendingState{}, ErrMFAPendingStateInvalid
	}
	payload, err := gcm.Open(nil, nonce, ciphertext, []byte(mfaPendingStateAAD))
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

func (m *MFAPendingStateManager) cipher() (cipher.AEAD, error) {
	key := sha256.Sum256(m.secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
