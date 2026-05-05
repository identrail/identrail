package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestRouterScopedAuthorizationNormalizesScopeValues(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeyScopes: map[string][]string{
			"reader-key": {" READ "},
			"writer-key": {" write "},
		},
	})

	readerReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	readerReq.Header.Set("X-API-Key", "reader-key")
	readerResp := httptest.NewRecorder()
	r.ServeHTTP(readerResp, readerReq)
	if readerResp.Code != http.StatusOK {
		t.Fatalf("expected reader GET 200, got %d", readerResp.Code)
	}

	readerWriteReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	readerWriteReq.Header.Set("X-API-Key", "reader-key")
	readerWriteResp := httptest.NewRecorder()
	r.ServeHTTP(readerWriteResp, readerWriteReq)
	if readerWriteResp.Code != http.StatusForbidden {
		t.Fatalf("expected reader POST 403, got %d", readerWriteResp.Code)
	}

	writerWriteReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writerWriteReq.Header.Set("X-API-Key", "writer-key")
	writerWriteResp := httptest.NewRecorder()
	r.ServeHTTP(writerWriteResp, writerWriteReq)
	if writerWriteResp.Code != http.StatusAccepted {
		t.Fatalf("expected writer POST 202, got %d", writerWriteResp.Code)
	}
}
