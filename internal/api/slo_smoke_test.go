package api

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

const findingsListP95SLOThreshold = 300 * time.Millisecond

func TestFindingsListLatencySLOSmoke(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	router := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	seedReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	seedW := httptest.NewRecorder()
	router.ServeHTTP(seedW, seedReq)
	if seedW.Code != http.StatusAccepted {
		t.Fatalf("seed scan failed: %d", seedW.Code)
	}

	const sampleSize = 200
	durations := make([]time.Duration, 0, sampleSize)
	success := 0
	for i := 0; i < sampleSize; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/findings?limit=10", nil)
		w := httptest.NewRecorder()
		started := time.Now()
		router.ServeHTTP(w, req)
		durations = append(durations, time.Since(started))
		if w.Code == http.StatusOK {
			success++
		}
	}

	if success != sampleSize {
		t.Fatalf("expected 100%% success, got %d/%d", success, sampleSize)
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(sampleSize*95/100)-1]
	if p95 > findingsListP95SLOThreshold {
		t.Fatalf("p95 findings list latency exceeded SLO threshold (%v): %v", findingsListP95SLOThreshold, p95)
	}
}
