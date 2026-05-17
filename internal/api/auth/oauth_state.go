package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const defaultOAuthStateTTL = 10 * time.Minute

var (
	ErrOAuthStateInvalid = errors.New("oauth state invalid")
	ErrOAuthStateExpired = errors.New("oauth state expired")
	ErrOAuthStateReused  = errors.New("oauth state reused")
)

// OAuthState captures the small amount of callback context we need to restore
// after WorkOS redirects back to Identrail. When the same state token carries
// a SAML SP-initiated request, ConnectionID and SAMLRequestID are populated so
// the ACS handler can scope the response to the originating connection and
// match the InResponseTo replay-protection field.
type OAuthState struct {
	Nonce         string `json:"nonce"`
	Intent        string `json:"intent"`
	ReturnTo      string `json:"return_to,omitempty"`
	ExpiresAt     int64  `json:"expires_at"`
	ConnectionID  string `json:"connection_id,omitempty"`
	SAMLRequestID string `json:"saml_request_id,omitempty"`
}

type OAuthStateManager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time

	mu   sync.Mutex
	used map[string]time.Time
}

func NewOAuthStateManager(secret string, now func() time.Time) *OAuthStateManager {
	if now == nil {
		now = time.Now
	}
	return &OAuthStateManager{
		secret: []byte(secret),
		ttl:    defaultOAuthStateTTL,
		now:    now,
		used:   map[string]time.Time{},
	}
}

func (m *OAuthStateManager) Issue(intent string, returnTo string) (string, error) {
	return m.IssueWithSAML(intent, returnTo, "", "")
}

// IssueWithSAML mints a state token carrying SAML SP-initiated context. The
// connection id and AuthnRequest id propagate through the IdP as RelayState
// and come back to the ACS handler so it can verify InResponseTo and route to
// the right connection.
func (m *OAuthStateManager) IssueWithSAML(intent, returnTo, connectionID, samlRequestID string) (string, error) {
	if m == nil || len(m.secret) == 0 {
		return "", ErrOAuthStateInvalid
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	state := OAuthState{
		Nonce:         base64.RawURLEncoding.EncodeToString(nonceBytes),
		Intent:        strings.TrimSpace(intent),
		ReturnTo:      strings.TrimSpace(returnTo),
		ExpiresAt:     m.now().Add(m.ttl).Unix(),
		ConnectionID:  strings.TrimSpace(connectionID),
		SAMLRequestID: strings.TrimSpace(samlRequestID),
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	signature := signOAuthState(m.secret, payloadPart)
	return payloadPart + "." + signature, nil
}

func (m *OAuthStateManager) Consume(raw string) (OAuthState, error) {
	if m == nil || len(m.secret) == 0 {
		return OAuthState{}, ErrOAuthStateInvalid
	}
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return OAuthState{}, ErrOAuthStateInvalid
	}
	expected := signOAuthState(m.secret, parts[0])
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return OAuthState{}, ErrOAuthStateInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return OAuthState{}, ErrOAuthStateInvalid
	}
	var state OAuthState
	if err := json.Unmarshal(payload, &state); err != nil {
		return OAuthState{}, ErrOAuthStateInvalid
	}
	now := m.now()
	if state.Nonce == "" || state.ExpiresAt <= 0 {
		return OAuthState{}, ErrOAuthStateInvalid
	}
	if !time.Unix(state.ExpiresAt, 0).After(now) {
		return OAuthState{}, ErrOAuthStateExpired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	if _, exists := m.used[state.Nonce]; exists {
		return OAuthState{}, ErrOAuthStateReused
	}
	m.used[state.Nonce] = time.Unix(state.ExpiresAt, 0)
	return state, nil
}

func (m *OAuthStateManager) pruneLocked(now time.Time) {
	for nonce, expiresAt := range m.used {
		if !expiresAt.After(now) {
			delete(m.used, nonce)
		}
	}
}

func signOAuthState(secret []byte, payloadPart string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payloadPart))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
