package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
)

// browserWriteCSRFMiddleware is the request-side CSRF/origin guard for
// unsafe, browser session-authenticated /v1 writes.
//
// CORS controls which cross-origin scripts may *read* a response; it is not a
// CSRF defense, because the browser still *sends* the cookie and performs the
// write before the response is filtered. Identrail uses cookie-based browser
// sessions, so unsafe session-authenticated API writes need an explicit
// request-side check. SameSite=Lax helps but does not cover same-site
// sibling-origin requests or a future cookie/origin misconfiguration.
//
// The guard only acts when the request is authenticated by a resolved
// browser session (sessionauth populated "auth.session"). API-key, OIDC
// bearer, SCIM bearer-token, connector-agent token, OAuth/SAML callback, and
// webhook routes do not carry the browser session cookie, so they pass
// through untouched and keep relying on their own auth mechanisms — this is
// exactly the exemption set the threat model calls out.
func browserWriteCSRFMiddleware(publicBaseURL string, corsAllowedOrigins []string) gin.HandlerFunc {
	trusted := map[string]struct{}{}
	for _, origin := range authReturnToOrigins(publicBaseURL, corsAllowedOrigins) {
		trusted[strings.ToLower(strings.TrimSpace(origin))] = struct{}{}
	}

	return func(c *gin.Context) {
		if !isUnsafeBrowserWriteMethod(c.Request.Method) {
			c.Next()
			return
		}
		if _, ok := sessionauth.CurrentFromGin(c); !ok {
			// Not a browser session (API key / bearer / agent token / no
			// auth). Those mechanisms are not CSRF-able with a cookie and
			// are validated elsewhere.
			c.Next()
			return
		}

		// Sec-Fetch-Site is set by the browser and cannot be forged by page
		// JavaScript. For browser-session writes, we allow cross-site when the
		// request later passes trusted-origin checks (for deployments that split
		// web and API registrable domains).
		if site := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Site"))); site != "" {
			switch site {
			case "same-origin", "same-site", "cross-site", "none":
			default:
				rejectBrowserWriteCSRF(c)
				return
			}
		}

		// Every /v1 write endpoint consumes JSON. A cross-site HTML form can
		// only submit text/plain, application/x-www-form-urlencoded, or
		// multipart/form-data without tripping a CORS preflight, so when a
		// body content type is present it must be application/json. An empty
		// content type (bodiless POST/DELETE such as revoke-others) is left
		// to the Origin check below — an HTML form auto-post always carries
		// one of the simple content types, so absence is not form-forgeable.
		if !browserWriteContentTypeAllowed(c.GetHeader("Content-Type")) {
			rejectBrowserWriteCSRF(c)
			return
		}

		// Origin is the authoritative, browser-set value. When present it
		// must be a configured first-party web/API origin. When absent (a
		// few browsers omit it on same-origin requests) fall back to the
		// Referer origin. A cookie-authenticated write with neither is not a
		// legitimate first-party fetch from the Identrail SPA.
		if origin := strings.TrimSpace(c.GetHeader("Origin")); origin != "" {
			if !originIsTrusted(origin, trusted) {
				rejectBrowserWriteCSRF(c)
				return
			}
			c.Next()
			return
		}
		if referer := strings.TrimSpace(c.GetHeader("Referer")); referer != "" {
			if !originIsTrusted(referer, trusted) {
				rejectBrowserWriteCSRF(c)
				return
			}
			c.Next()
			return
		}
		rejectBrowserWriteCSRF(c)
	}
}

func isUnsafeBrowserWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// browserWriteContentTypeAllowed permits an empty Content-Type (bodiless
// write) and otherwise requires application/json. The media type is compared
// case-insensitively and ignores parameters such as "; charset=utf-8".
func browserWriteContentTypeAllowed(contentType string) bool {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return true
	}
	mediaType := contentType
	if idx := strings.IndexByte(mediaType, ';'); idx >= 0 {
		mediaType = mediaType[:idx]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/json")
}

func originIsTrusted(raw string, trusted map[string]struct{}) bool {
	origin, ok := authReturnToOrigin(raw)
	if !ok {
		return false
	}
	_, allowed := trusted[strings.ToLower(origin)]
	return allowed
}

func rejectBrowserWriteCSRF(c *gin.Context) {
	auditAuthAction(c.Request.Context(), "auth.request.denied", "", "denied")
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-origin request blocked"})
}
