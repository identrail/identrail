package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	// defaultOAuthTransactionTTL bounds how long a WorkOS OAuth login may
	// remain in-flight between the /auth/login (or /auth/signup) redirect and
	// the matching /auth/callback. It matches the signed-state TTL and the
	// 10-minute window documented in docs/auth/threat-model.md.
	defaultOAuthTransactionTTL = defaultOAuthStateTTL
	// oauthCookieTokenByteLength is the entropy of the browser-bound cookie
	// token. 32 random bytes (256 bits) is well beyond brute-force reach
	// within the short transaction TTL.
	oauthCookieTokenByteLength = 32
	// OAuthTransactionCookiePrefix prefixes the short-lived, HttpOnly,
	// Secure, SameSite=Lax cookie that binds an in-flight OAuth login to the
	// browser that started it. The cookie name is scoped per state nonce so
	// concurrent in-flight logins (double-click, two tabs, switching
	// provider) each keep their own browser-bound token instead of one
	// overwriting another.
	OAuthTransactionCookiePrefix = "idr_oauth_txn"
)

// OAuthTransactionCookieName returns the per-nonce transaction cookie name.
// The nonce is base64url (RFC 4648 raw) so its characters are all valid
// cookie-name token characters; any unexpected character is mapped to '_'
// defensively so a malformed nonce can never produce an invalid Set-Cookie.
func OAuthTransactionCookieName(nonce string) string {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return OAuthTransactionCookiePrefix
	}
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, nonce)
	return OAuthTransactionCookiePrefix + "_" + sanitized
}

// ErrOAuthTransactionInvalid is returned when the store-backed OAuth
// transaction is missing, expired, already consumed, or its browser-bound
// cookie token does not match the row issued when the redirect was minted.
var ErrOAuthTransactionInvalid = errors.New("oauth transaction invalid")

// OAuthTransactionEntry is the SP-side context bound to one in-flight WorkOS
// OAuth login. Nonce comes from the signed state token; CookieToken is the
// opaque value placed in the browser-bound transaction cookie.
type OAuthTransactionEntry struct {
	Nonce             string
	Intent            string
	ReturnTo          string
	ExpectedUserID    string
	ExpectedSessionID string
	ExpiresAt         time.Time
}

// OAuthTransactionStore mints the browser-bound cookie token, persists the
// transaction through db.Store, and one-shot-consumes it on the callback.
// Persisting through db.Store means a callback routed to a different API
// instance than the one that issued the redirect still finds the row, so a
// captured signed state cannot be replayed anywhere in the fleet.
type OAuthTransactionStore struct {
	store db.Store
	ttl   time.Duration
	now   func() time.Time
}

// NewOAuthTransactionStore returns a store backed by the supplied db.Store.
// The now function is injectable so tests can advance the clock; pass nil
// for time.Now.
func NewOAuthTransactionStore(store db.Store, now func() time.Time) *OAuthTransactionStore {
	if now == nil {
		now = time.Now
	}
	return &OAuthTransactionStore{
		store: store,
		ttl:   defaultOAuthTransactionTTL,
		now:   now,
	}
}

// TTL is the lifetime of an in-flight OAuth transaction. The browser-bound
// cookie is set to expire on the same window so a stale cookie cannot
// outlive its store row.
func (s *OAuthTransactionStore) TTL() time.Duration {
	if s == nil || s.ttl <= 0 {
		return defaultOAuthTransactionTTL
	}
	return s.ttl
}

// Issue generates the opaque cookie token, persists the transaction keyed by
// the signed-state nonce, and returns the cookie token. The caller sets the
// returned value in a short-lived HttpOnly, Secure, SameSite=Lax cookie.
func (s *OAuthTransactionStore) Issue(ctx context.Context, entry OAuthTransactionEntry) (string, error) {
	if s == nil || s.store == nil {
		return "", ErrOAuthTransactionInvalid
	}
	nonce := strings.TrimSpace(entry.Nonce)
	if nonce == "" {
		return "", ErrOAuthTransactionInvalid
	}
	cookieToken, err := newOAuthCookieToken()
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	expiresAt := entry.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(s.ttl)
	}
	if _, err := s.store.CreateOAuthTransaction(ctx, db.OAuthTransaction{
		Nonce:             nonce,
		CookieToken:       cookieToken,
		Intent:            entry.Intent,
		ReturnTo:          entry.ReturnTo,
		ExpectedUserID:    entry.ExpectedUserID,
		ExpectedSessionID: entry.ExpectedSessionID,
		ExpiresAt:         expiresAt,
		CreatedAt:         now,
	}); err != nil {
		return "", err
	}
	return cookieToken, nil
}

// Consume returns the entry for the (nonce, cookieToken) pair and atomically
// marks the row consumed. A missing, expired, reused, or cookie-mismatched
// transaction returns ErrOAuthTransactionInvalid, so the OAuth state cannot
// be replayed even against another API instance sharing the database.
func (s *OAuthTransactionStore) Consume(ctx context.Context, nonce string, cookieToken string) (OAuthTransactionEntry, error) {
	if s == nil || s.store == nil {
		return OAuthTransactionEntry{}, ErrOAuthTransactionInvalid
	}
	txn, err := s.store.ConsumeOAuthTransaction(ctx, nonce, cookieToken, s.now().UTC())
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return OAuthTransactionEntry{}, ErrOAuthTransactionInvalid
		}
		return OAuthTransactionEntry{}, err
	}
	return OAuthTransactionEntry{
		Nonce:             txn.Nonce,
		Intent:            txn.Intent,
		ReturnTo:          txn.ReturnTo,
		ExpectedUserID:    txn.ExpectedUserID,
		ExpectedSessionID: txn.ExpectedSessionID,
		ExpiresAt:         txn.ExpiresAt,
	}, nil
}

func newOAuthCookieToken() (string, error) {
	buf := make([]byte, oauthCookieTokenByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
