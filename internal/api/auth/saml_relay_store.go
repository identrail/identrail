package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/identrail/identrail/internal/db"
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

// SAMLRelayEntry is the SP-side state associated with one opaque relay
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
// callback. State is persisted through db.Store so callbacks routed to a
// different API instance than the one that issued the AuthnRequest still
// find their relay row.
type SAMLRelayStore struct {
	store db.Store
	ttl   time.Duration
	now   func() time.Time
}

// NewSAMLRelayStore returns a store backed by the supplied db.Store. The
// now function is injectable so tests can advance the clock; pass nil for
// time.Now.
func NewSAMLRelayStore(store db.Store, now func() time.Time) *SAMLRelayStore {
	if now == nil {
		now = time.Now
	}
	return &SAMLRelayStore{
		store: store,
		ttl:   defaultSAMLRelayTTL,
		now:   now,
	}
}

// Issue generates an opaque handle, persists the entry through db.Store, and
// returns the handle. The handle is short enough to fit inside any IdP's
// RelayState limit and contains no sensitive information.
func (s *SAMLRelayStore) Issue(ctx context.Context, entry SAMLRelayEntry) (string, error) {
	if s == nil || s.store == nil {
		return "", ErrSAMLRelayHandleInvalid
	}
	handle, err := newSAMLRelayHandle()
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	expiresAt := entry.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(s.ttl)
	}
	if _, err := s.store.CreateSAMLRelayState(ctx, db.SAMLRelayState{
		Handle:        handle,
		ConnectionID:  entry.ConnectionID,
		SAMLRequestID: entry.SAMLRequestID,
		ReturnTo:      entry.ReturnTo,
		Intent:        entry.Intent,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
	}); err != nil {
		return "", err
	}
	return handle, nil
}

// Consume returns the entry for handle and atomically marks it consumed. A
// subsequent call with the same handle returns ErrSAMLRelayHandleInvalid,
// preventing replay of the same RelayState value.
func (s *SAMLRelayStore) Consume(ctx context.Context, handle string) (SAMLRelayEntry, error) {
	if s == nil || s.store == nil {
		return SAMLRelayEntry{}, ErrSAMLRelayHandleInvalid
	}
	state, err := s.store.ConsumeSAMLRelayState(ctx, handle, s.now().UTC())
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return SAMLRelayEntry{}, ErrSAMLRelayHandleInvalid
		}
		return SAMLRelayEntry{}, err
	}
	return SAMLRelayEntry{
		ConnectionID:  state.ConnectionID,
		SAMLRequestID: state.SAMLRequestID,
		ReturnTo:      state.ReturnTo,
		Intent:        state.Intent,
		ExpiresAt:     state.ExpiresAt,
	}, nil
}

func newSAMLRelayHandle() (string, error) {
	buf := make([]byte, SAMLRelayHandleByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
