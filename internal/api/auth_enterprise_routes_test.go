package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestEnterpriseAuthPrepRoutesReturnNotImplemented(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		APIKeyScopes: map[string][]string{
			"writer-key": {scopeWrite},
			"reader-key": {scopeRead},
		},
	})

	cases := []struct {
		method string
		path   string
		key    string
	}{
		{method: http.MethodPost, path: "/v1/invitations", key: "writer-key"},
		{method: http.MethodGet, path: "/v1/me/invitations", key: "reader-key"},
		{method: http.MethodPost, path: "/v1/orgs/tenant-a/domains", key: "writer-key"},
		{method: http.MethodPost, path: "/v1/orgs/tenant-a/domains/11111111-1111-1111-1111-111111111111/verify", key: "writer-key"},
		{method: http.MethodGet, path: "/v1/orgs/tenant-a/sso", key: "reader-key"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("X-API-Key", tc.key)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s: expected 501, got %d body=%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}
