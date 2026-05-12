package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/db"
)

const (
	CookieName              = "identrail_session"
	IdleTimeout             = 15 * time.Minute
	AbsoluteTimeout         = 14 * 24 * time.Hour
	DefaultSessionListLimit = 100
)

var ErrInvalidSessionID = errors.New("invalid session id")

// CurrentSession is the authenticated browser session attached to a request.
type CurrentSession struct {
	Session db.Session
	IDHash  []byte
}

// Manager owns session cookie encoding and lookup.
type Manager struct {
	Store         db.Store
	PublicBaseURL string
	Now           func() time.Time
}

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// NewSessionID creates the plaintext cookie value and its database lookup hash.
func NewSessionID() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	hash := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(raw), hash[:], nil
}

// HashCookieValue decodes a cookie value and returns its SHA-256 lookup key.
func HashCookieValue(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != 32 {
		return nil, ErrInvalidSessionID
	}
	hash := sha256.Sum256(raw)
	return hash[:], nil
}

// EncodePublicSessionID returns the non-secret id used by session-management endpoints.
func EncodePublicSessionID(hash []byte) string {
	return base64.RawURLEncoding.EncodeToString(hash)
}

// DecodePublicSessionID decodes a session-management id back to the stored hash.
func DecodePublicSessionID(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != sha256.Size {
		return nil, ErrInvalidSessionID
	}
	return raw, nil
}

// CreateSession creates a persisted session and returns the cookie value.
func (m Manager) CreateSession(ctx context.Context, session db.Session) (string, db.Session, error) {
	cookieValue, hash, err := NewSessionID()
	if err != nil {
		return "", db.Session{}, err
	}
	now := m.now()
	session.ID = hash
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	if session.LastSeenAt.IsZero() {
		session.LastSeenAt = now
	}
	if session.IdleExpiresAt.IsZero() {
		session.IdleExpiresAt = now.Add(IdleTimeout)
	}
	if session.AbsoluteExpiresAt.IsZero() {
		session.AbsoluteExpiresAt = now.Add(AbsoluteTimeout)
	}
	saved, err := m.Store.CreateSession(ctx, session)
	if err != nil {
		return "", db.Session{}, err
	}
	return cookieValue, saved, nil
}

// LookupRequest resolves the request cookie into a current session.
func (m Manager) LookupRequest(r *http.Request) (CurrentSession, error) {
	if m.Store == nil || r == nil {
		return CurrentSession{}, db.ErrNotFound
	}
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return CurrentSession{}, err
	}
	hash, err := HashCookieValue(cookie.Value)
	if err != nil {
		return CurrentSession{}, err
	}
	session, err := m.Store.TouchSession(r.Context(), hash, m.now())
	if err != nil {
		return CurrentSession{}, err
	}
	return CurrentSession{Session: session, IDHash: hash}, nil
}

// Cookie returns the Set-Cookie value for a live session.
func (m Manager) Cookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(AbsoluteTimeout.Seconds()),
		HttpOnly: true,
		Secure:   cookieSecure(m.PublicBaseURL),
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie returns the Set-Cookie value that removes a session.
func (m Manager) ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cookieSecure(m.PublicBaseURL),
		SameSite: http.SameSiteLaxMode,
	}
}

func cookieSecure(publicBaseURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(publicBaseURL))
	if err != nil {
		return true
	}
	return !strings.EqualFold(parsed.Scheme, "http")
}

// Middleware attaches a current session when a browser cookie is present.
func (m Manager) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		current, err := m.LookupRequest(c.Request)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("auth.session", current)
		c.Set("auth.subject", current.Session.UserID)
		c.Set("auth.user_id", current.Session.UserID)
		roles := []string{"authenticated"}
		if current.Session.CurrentOrgID != "" {
			c.Set("auth.tenant_id", current.Session.CurrentOrgID)
		}
		if current.Session.CurrentWorkspaceID != "" {
			c.Set("auth.workspace_id", current.Session.CurrentWorkspaceID)
		}
		if m.Store != nil && current.Session.CurrentOrgID != "" && current.Session.CurrentWorkspaceID != "" {
			scopedCtx := db.WithScope(c.Request.Context(), db.Scope{
				TenantID:    current.Session.CurrentOrgID,
				WorkspaceID: current.Session.CurrentWorkspaceID,
			})
			if member, err := m.Store.GetWorkspaceMemberByUserUUID(scopedCtx, current.Session.CurrentWorkspaceID, current.Session.UserID); err == nil {
				if member.Status == "active" && member.Role != "" {
					roles = append(roles, member.Role)
				}
			}
		}
		c.Set("auth.roles", roles)
		c.Set("auth.session_id_hash", current.IDHash)
		c.Next()
	}
}

// CurrentFromGin returns the current browser session from middleware state.
func CurrentFromGin(c *gin.Context) (CurrentSession, bool) {
	if c == nil {
		return CurrentSession{}, false
	}
	value, exists := c.Get("auth.session")
	if !exists {
		return CurrentSession{}, false
	}
	current, ok := value.(CurrentSession)
	return current, ok
}
