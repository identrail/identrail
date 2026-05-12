package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/db"
)

func TestSessionIDEncodingAndCookieHashing(t *testing.T) {
	cookieValue, hash, err := NewSessionID()
	if err != nil {
		t.Fatalf("new session id: %v", err)
	}
	if len(hash) != 32 {
		t.Fatalf("expected 32-byte session hash, got %d", len(hash))
	}
	decodedHash, err := HashCookieValue(cookieValue)
	if err != nil {
		t.Fatalf("hash cookie value: %v", err)
	}
	if !bytes.Equal(decodedHash, hash) {
		t.Fatalf("cookie hash mismatch")
	}

	publicID := EncodePublicSessionID(hash)
	decodedPublicID, err := DecodePublicSessionID(publicID)
	if err != nil {
		t.Fatalf("decode public session id: %v", err)
	}
	if !bytes.Equal(decodedPublicID, hash) {
		t.Fatalf("public id mismatch")
	}
	if _, err := HashCookieValue("not-valid"); !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected invalid cookie value error, got %v", err)
	}
	if _, err := DecodePublicSessionID("short"); !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected invalid public id error, got %v", err)
	}
}

func TestManagerCreateLookupAndCookieAttributes(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 11, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(context.Background(), db.User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "alice@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	manager := Manager{
		Store:         store,
		PublicBaseURL: "https://app.identrail.com",
		Now:           func() time.Time { return now },
	}

	cookieValue, saved, err := manager.CreateSession(context.Background(), db.Session{
		UserID:     user.ID,
		AuthMethod: "manual",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if saved.CreatedAt != now || saved.LastSeenAt != now {
		t.Fatalf("session timestamps were not defaulted from manager clock: %+v", saved)
	}
	if !saved.IdleExpiresAt.Equal(now.Add(IdleTimeout)) {
		t.Fatalf("unexpected idle expiry: %v", saved.IdleExpiresAt)
	}
	if !saved.AbsoluteExpiresAt.Equal(now.Add(AbsoluteTimeout)) {
		t.Fatalf("unexpected absolute expiry: %v", saved.AbsoluteExpiresAt)
	}

	cookie := manager.Cookie(cookieValue)
	if cookie.Name != CookieName || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("unexpected live cookie attributes: %+v", cookie)
	}
	clearCookie := manager.ClearCookie()
	if clearCookie.Name != CookieName || clearCookie.MaxAge != -1 || clearCookie.Domain != "" {
		t.Fatalf("unexpected clear cookie attributes: %+v", clearCookie)
	}
	localCookie := (Manager{PublicBaseURL: "http://localhost:8080"}).Cookie("value")
	if localCookie.Domain != "" || localCookie.Secure {
		t.Fatalf("expected localhost cookie to be host-only and non-secure, got %+v", localCookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.AddCookie(cookie)
	current, err := manager.LookupRequest(req)
	if err != nil {
		t.Fatalf("lookup request: %v", err)
	}
	if current.Session.User == nil || current.Session.User.ID != user.ID {
		t.Fatalf("expected joined user on current session: %+v", current)
	}
	if !bytes.Equal(current.IDHash, saved.ID) {
		t.Fatalf("expected current hash to match saved session")
	}
}

func TestMiddlewareSessionStates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(context.Background(), db.User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "alice@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	manager := Manager{
		Store: store,
		Now:   func() time.Time { return now },
	}
	cookieValue, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:     user.ID,
		AuthMethod: "manual",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	router := gin.New()
	router.Use(manager.Middleware())
	router.GET("/", func(c *gin.Context) {
		current, ok := CurrentFromGin(c)
		if !ok {
			c.String(http.StatusOK, "guest")
			return
		}
		roles, _ := c.Get("auth.roles")
		subject, _ := c.Get("auth.subject")
		c.JSON(http.StatusOK, gin.H{
			"user_id": current.Session.UserID,
			"subject": subject,
			"roles":   roles,
		})
	})

	noCookie := httptest.NewRecorder()
	router.ServeHTTP(noCookie, httptest.NewRequest(http.MethodGet, "/", nil))
	if noCookie.Code != http.StatusOK || noCookie.Body.String() != "guest" {
		t.Fatalf("expected request without cookie to pass through, got code=%d body=%q", noCookie.Code, noCookie.Body.String())
	}

	badCookieReq := httptest.NewRequest(http.MethodGet, "/", nil)
	badCookieReq.AddCookie(&http.Cookie{Name: CookieName, Value: "bad"})
	badCookie := httptest.NewRecorder()
	router.ServeHTTP(badCookie, badCookieReq)
	if badCookie.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid cookie to be rejected, got %d", badCookie.Code)
	}

	validReq := httptest.NewRequest(http.MethodGet, "/", nil)
	validReq.AddCookie(manager.Cookie(cookieValue))
	valid := httptest.NewRecorder()
	router.ServeHTTP(valid, validReq)
	if valid.Code != http.StatusOK {
		t.Fatalf("expected valid session, got %d body=%s", valid.Code, valid.Body.String())
	}
	if !bytes.Contains(valid.Body.Bytes(), []byte(`"subject":"11111111-1111-1111-1111-111111111111"`)) {
		t.Fatalf("expected session subject in response, got %s", valid.Body.String())
	}
	if !bytes.Contains(valid.Body.Bytes(), []byte(`authenticated`)) {
		t.Fatalf("expected authenticated role in response, got %s", valid.Body.String())
	}

	if _, ok := CurrentFromGin(nil); ok {
		t.Fatal("expected nil gin context to have no current session")
	}
}

func TestMiddlewareOnlyAddsActiveWorkspaceMemberRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 16, 0, 0, 0, time.UTC)
	scope := db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	scopedCtx := db.WithScope(context.Background(), scope)
	user, err := store.UpsertUser(context.Background(), db.User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "alice@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "legacy-user-a",
		UserUUID:    user.ID,
		Email:       user.PrimaryEmail,
		Role:        "admin",
		Status:      "suspended",
	}); err != nil {
		t.Fatalf("upsert member: %v", err)
	}

	manager := Manager{Store: store, Now: func() time.Time { return now }}
	cookieValue, _, err := manager.CreateSession(context.Background(), db.Session{
		UserID:             user.ID,
		CurrentOrgID:       "tenant-a",
		CurrentWorkspaceID: "workspace-a",
		AuthMethod:         "manual",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	router := gin.New()
	router.Use(manager.Middleware())
	router.GET("/", func(c *gin.Context) {
		roles, _ := c.Get("auth.roles")
		c.JSON(http.StatusOK, gin.H{"roles": roles})
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(manager.Cookie(cookieValue))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("admin")) {
		t.Fatalf("expected suspended member role to be omitted, got %s", w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("authenticated")) {
		t.Fatalf("expected authenticated role to remain, got %s", w.Body.String())
	}
}
