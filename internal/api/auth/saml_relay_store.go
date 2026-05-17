package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	// defaultSAMLRelayTTL bounds how long a SAML SP-initiated login may
	// remain in-flight between the AuthnRequest and the matching ACS POST.
	defaultSAMLRelayTTL = 10 * time.Minute
	// SAMLRelayHandleByteLength chooses 16 random bytes → 22 base64url
	// characters, well under the 80-byte RelayState limit imposed by the
	// SAML 2.0 HTTP-Redirect binding for any IdP that enforces it.
	SAMLRelayHandleByteLength = 16
)

// ErrSAMLRelayHandleInvalid is returned when an opaque relay handle is
// missing, expired, malformed, or has already been consumed.
var ErrSAMLRelayHandleInvalid = errors.New("saml relay handle invalid")

// SAMLRelayEntry is the server-side state associated with one opaque relay
// handle. The HMAC-signed cookie pattern used by OAuthStateManager would
// produce a token too large for the SAML 2.0 RelayState 80-byte cap, so SAML
// SP-initiated flows store the full state server-side and put only a short
// opaque handle on the wire.
type SAMLRelayEntry struct {
	ConnectionID  string
	SAMLRequestID string
	ReturnTo      string
	Intent        string
	ExpiresAt     time.Time
}

// SAMLRelayStore mints opaque handles and one-shot-consumes them on the ACS
// callback. In-memory backing is sufficient for v1 (single-process API);
// multi-process deployments should swap in a DB-backed implementation in a
// follow-up.
type SAMLRelayStore struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]SAMLRelayEntry
}

// NewSAMLRelayStore returns an in-memory store using defaultSAMLRelayTTL and
// time.Now. The now function is injectable so tests can advance the clock.
func NewSAMLRelayStore(now func() time.Time) *SAMLRelayStore {
	if now == nil {
		now = time.Now
	}
	return &SAMLRelayStore{
		ttl:     defaultSAMLRelayTTL,
		now:     now,
		entries: map[string]SAMLRelayEntry{},
	}
}

// Issue generates an opaque handle and persists the entry. The handle is
// short enough to fit inside any IdP's RelayState limit and contains no
// sensitive information.
func (s *SAMLRelayStore) Issue(entry SAMLRelayEntry) (string, error) {
	handle, err := newSAMLRelayHandle()
	if err != nil {
		return "", err
	}
	if entry.ExpiresAt.IsZero() {
		entry.ExpiresAt = s.now().Add(s.ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	s.entries[handle] = entry
	return handle, nil
}

// Consume returns the entry for handle and atomically deletes it. A
// subsequent call with the same handle returns ErrSAMLRelayHandleInvalid,
// preventing replay of the same RelayState value.
func (s *SAMLRelayStore) Consume(handle string) (SAMLRelayEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	entry, ok := s.entries[handle]
	if !ok {
		return SAMLRelayEntry{}, ErrSAMLRelayHandleInvalid
	}
	delete(s.entries, handle)
	if entry.ExpiresAt.Before(now) || entry.ExpiresAt.Equal(now) {
		return SAMLRelayEntry{}, ErrSAMLRelayHandleInvalid
	}
	return entry, nil
}

func (s *SAMLRelayStore) pruneLocked(now time.Time) {
	for handle, entry := range s.entries {
		if entry.ExpiresAt.Before(now) || entry.ExpiresAt.Equal(now) {
			delete(s.entries, handle)
		}
	}
}

func newSAMLRelayHandle() (string, error) {
	buf := make([]byte, SAMLRelayHandleByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
