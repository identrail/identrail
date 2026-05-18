package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
)

const (
	csrfPublicBaseURL = "https://app.identrail.test"
	csrfWebOrigin     = "https://web.identrail.test"
)

// newCSRFTestEngine builds a minimal gin engine that mounts the browser-write
// CSRF guard exactly as the router does: after a stand-in session middleware
// that marks the request as browser session-authenticated when
// authenticated is true.
func newCSRFTestEngine(authenticated bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	e := gin.New()
	e.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("auth.session", sessionauth.CurrentSession{})
		}
		c.Next()
	})
	e.Use(browserWriteCSRFMiddleware(csrfPublicBaseURL, []string{csrfWebOrigin, "*"}))
	handler := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		e.Handle(m, "/v1/thing", handler)
	}
	return e
}

func csrfDo(e *gin.Engine, method, contentType string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/v1/thing", strings.NewReader(`{}`))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w
}

func TestBrowserWriteCSRFAcceptsFirstPartyRequests(t *testing.T) {
	e := newCSRFTestEngine(true)

	for name, headers := range map[string]map[string]string{
		"public base origin":    {"Origin": csrfPublicBaseURL},
		"configured web origin": {"Origin": csrfWebOrigin, "Sec-Fetch-Site": "same-site"},
		"same-origin sec-fetch": {"Origin": csrfPublicBaseURL, "Sec-Fetch-Site": "same-origin"},
		"sec-fetch none":        {"Origin": csrfPublicBaseURL, "Sec-Fetch-Site": "none"},
		"referer fallback":      {"Referer": csrfPublicBaseURL + "/app/settings"},
	} {
		w := csrfDo(e, http.MethodPost, "application/json", headers)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d body=%s", name, w.Code, w.Body.String())
		}
	}
}

func TestBrowserWriteCSRFRejectsCrossOrigin(t *testing.T) {
	e := newCSRFTestEngine(true)

	cases := map[string]map[string]string{
		"cross-origin origin":    {"Origin": "https://evil.example"},
		"bad sec-fetch-site":     {"Origin": csrfPublicBaseURL, "Sec-Fetch-Site": "cross-site"},
		"untrusted referer":      {"Referer": "https://evil.example/app"},
		"missing origin+referer": {},
	}
	for name, headers := range cases {
		w := csrfDo(e, http.MethodPost, "application/json", headers)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: expected 403, got %d body=%s", name, w.Code, w.Body.String())
		}
	}
}

func TestBrowserWriteCSRFContentTypeEnforcement(t *testing.T) {
	e := newCSRFTestEngine(true)
	first := map[string]string{"Origin": csrfPublicBaseURL}

	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"} {
		if w := csrfDo(e, http.MethodPost, ct, first); w.Code != http.StatusForbidden {
			t.Fatalf("content type %q: expected 403, got %d", ct, w.Code)
		}
	}
	if w := csrfDo(e, http.MethodPost, "application/json; charset=utf-8", first); w.Code != http.StatusOK {
		t.Fatalf("application/json should pass, got %d body=%s", w.Code, w.Body.String())
	}
	// Bodiless write (no content type) is allowed once the origin is trusted.
	req := httptest.NewRequest(http.MethodPost, "/v1/thing", nil)
	req.Header.Set("Origin", csrfPublicBaseURL)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bodiless write should pass, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestBrowserWriteCSRFExemptions(t *testing.T) {
	// Safe methods are never guarded, even cross-origin.
	authed := newCSRFTestEngine(true)
	if w := csrfDo(authed, http.MethodGet, "", map[string]string{"Origin": "https://evil.example"}); w.Code != http.StatusOK {
		t.Fatalf("GET must bypass the guard, got %d", w.Code)
	}

	// Non-browser auth (API key / bearer / agent token) has no resolved
	// browser session, so a cross-origin write is not guarded here — those
	// mechanisms are validated elsewhere and are not cookie-CSRF-able.
	unauthed := newCSRFTestEngine(false)
	if w := csrfDo(unauthed, http.MethodPost, "application/json", map[string]string{"Origin": "https://evil.example"}); w.Code != http.StatusOK {
		t.Fatalf("non-browser-session write must bypass the guard, got %d body=%s", w.Code, w.Body.String())
	}
}
