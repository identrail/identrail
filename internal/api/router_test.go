package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/repoexposure"
	"github.com/identrail/identrail/internal/scheduler"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type routerScanner struct{}

func (routerScanner) Run(_ context.Context) (app.ScanResult, error) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	return app.ScanResult{
		Assets: 1,
		Findings: []domain.Finding{{
			ID:           "f1",
			Type:         domain.FindingRiskyTrustPolicy,
			Severity:     domain.SeverityHigh,
			Title:        "Risky trust",
			HumanSummary: "summary",
			CreatedAt:    now,
		}},
		Completed: now,
	}, nil
}

type recordingAuditSink struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

type fakeTokenVerifier struct {
	tokens map[string]VerifiedToken
	errs   map[string]error
}

func (v fakeTokenVerifier) VerifyToken(_ context.Context, rawToken string) (VerifiedToken, error) {
	if err, ok := v.errs[rawToken]; ok {
		return VerifiedToken{}, err
	}
	token, ok := v.tokens[rawToken]
	if !ok {
		return VerifiedToken{}, errors.New("invalid token")
	}
	return token, nil
}

func (s *recordingAuditSink) Write(_ context.Context, event audit.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (*recordingAuditSink) Close() error { return nil }

func countAuditEventsByKind(events []audit.AuditEvent, kind string) int {
	count := 0
	for _, event := range events {
		if event.Kind == kind {
			count++
		}
	}
	return count
}

func TestRouterHealthz(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{RateLimitRPM: 1000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("unexpected status body: %+v", body)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected security header nosniff, got %q", got)
	}
}

func TestRouterReadyzWithoutService(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{RateLimitRPM: 1000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}
	assertServiceStatusBody(t, w.Body.Bytes(), "not_ready")
}

func TestRouterReadyzWithService(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	svc := NewService(db.NewMemoryStore(), routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	assertServiceStatusBody(t, w.Body.Bytes(), "ready")
}

func TestRouterReadyzWithDependencyFailure(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	svc := NewService(db.NewMemoryStore(), routerScanner{}, "aws")
	svc.ReadinessCheck = func(context.Context) error {
		return errors.New("dependency unavailable")
	}
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}
	assertServiceStatusBody(t, w.Body.Bytes(), "not_ready")
}

func TestRouterMetricsRequiresAuthentication(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys: []string{"metrics-key"},
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected metrics endpoint to require auth, got %d", w.Code)
	}
}

func TestRouterMetricsRateLimitAppliesBeforeAuth(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys:        []string{"metrics-key"},
		RateLimitRPM:   1,
		RateLimitBurst: 1,
	})

	first := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	first.RemoteAddr = "127.0.0.1:30001"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected first unauthorized metrics request to return 401, got %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	second.RemoteAddr = "127.0.0.1:30001"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second unauthorized metrics request to return 429, got %d", w2.Code)
	}
}

func TestRouterMetricsRequiresWriteOrAdminScope(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeyScopes: map[string][]string{
			"reader-key": {scopeRead},
			"writer-key": {scopeWrite},
		},
	})

	readReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	readReq.Header.Set("X-API-Key", "reader-key")
	readW := httptest.NewRecorder()
	r.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusForbidden {
		t.Fatalf("expected read-only scoped key denied on metrics endpoint, got %d", readW.Code)
	}

	writeReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	writeReq.Header.Set("X-API-Key", "writer-key")
	writeW := httptest.NewRecorder()
	r.ServeHTTP(writeW, writeReq)
	if writeW.Code != http.StatusOK {
		t.Fatalf("expected write scoped key allowed on metrics endpoint, got %d", writeW.Code)
	}
	if strings.TrimSpace(writeW.Body.String()) == "" {
		t.Fatal("expected metrics response body")
	}
}

func TestRouterCORSDisabledByDefault(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{RateLimitRPM: 1000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://app.identrail.io")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no cors allow origin header, got %q", got)
	}
}

func assertServiceStatusBody(t *testing.T, payload []byte, wantStatus string) {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != wantStatus {
		t.Fatalf("expected status %q, got %+v", wantStatus, body)
	}
	if body["service"] != "identrail" {
		t.Fatalf("expected service identrail, got %+v", body)
	}
}

func TestRouterCORSAllowsConfiguredOrigin(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		CORSAllowedOrigins: []string{"https://app.identrail.io"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://app.identrail.io")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.identrail.io" {
		t.Fatalf("expected cors allow origin header, got %q", got)
	}
	if !varyHeaderContains(w.Header().Get("Vary"), "Origin") {
		t.Fatalf("expected Vary header to include Origin, got %q", w.Header().Get("Vary"))
	}
}

func TestRouterCORSPreflightBypassesAuth(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys:            []string{"reader-key"},
		WriteAPIKeys:       []string{"reader-key"},
		CORSAllowedOrigins: []string{"https://app.identrail.io"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/v1/findings", nil)
	req.Header.Set("Origin", "https://app.identrail.io")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	req.Header.Set("Access-Control-Request-Headers", "Authorization,X-API-Key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.identrail.io" {
		t.Fatalf("expected cors allow origin header, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodGet) {
		t.Fatalf("expected allow methods header to include GET, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodPatch) {
		t.Fatalf("expected allow methods header to include PATCH, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "x-api-key") {
		t.Fatalf("expected allow headers to include x-api-key, got %q", got)
	}
}

func TestRouterCORSSkipsUnlistedOrigin(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		CORSAllowedOrigins: []string{"https://app.identrail.io"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no cors allow origin for unlisted origin, got %q", got)
	}
}

func TestRouterIgnoresForwardedIPWhenNoTrustedProxies(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink:      sink,
		RateLimitRPM:   10000,
		RateLimitBurst: 1000,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	req.RemoteAddr = "10.1.1.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	last := sink.events[len(sink.events)-1]
	if last.ClientIP != "10.1.1.1" {
		t.Fatalf("expected remote ip to be used, got %q", last.ClientIP)
	}
}

func TestRouterUsesForwardedIPWhenTrustedProxyConfigured(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink:      sink,
		RateLimitRPM:   10000,
		RateLimitBurst: 1000,
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	req.RemoteAddr = "10.1.1.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	last := sink.events[len(sink.events)-1]
	if last.ClientIP != "203.0.113.10" {
		t.Fatalf("expected forwarded ip to be used, got %q", last.ClientIP)
	}
}

func TestRouterRunsScanAndListsData(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: historyLimit,
				FilesScanned:   2,
				Findings: []domain.Finding{
					{ID: "repo-f1", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh},
				},
			},
		}
	}
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	postReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	postW := httptest.NewRecorder()
	r.ServeHTTP(postW, postReq)
	if postW.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", postW.Code)
	}
	var postBody struct {
		Scan db.ScanRecord `json:"scan"`
	}
	if err := json.Unmarshal(postW.Body.Bytes(), &postBody); err != nil {
		t.Fatalf("decode post body: %v", err)
	}
	if postBody.Scan.ID == "" {
		t.Fatal("expected scan id in post response")
	}
	firstScanID := postBody.Scan.ID

	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process first queued scan: %v", err)
	}
	if !processed {
		t.Fatal("expected first queued scan to be processed")
	}

	postReq2 := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	postW2 := httptest.NewRecorder()
	r.ServeHTTP(postW2, postReq2)
	if postW2.Code != http.StatusAccepted {
		t.Fatalf("expected second scan status 202, got %d", postW2.Code)
	}
	var postBody2 struct {
		Scan db.ScanRecord `json:"scan"`
	}
	if err := json.Unmarshal(postW2.Body.Bytes(), &postBody2); err != nil {
		t.Fatalf("decode second post body: %v", err)
	}
	if postBody2.Scan.ID == "" {
		t.Fatal("expected second scan id in post response")
	}

	processed, err = svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process second queued scan: %v", err)
	}
	if !processed {
		t.Fatal("expected second queued scan to be processed")
	}

	findingsReq := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	findingsW := httptest.NewRecorder()
	r.ServeHTTP(findingsW, findingsReq)
	if findingsW.Code != http.StatusOK {
		t.Fatalf("expected findings 200, got %d", findingsW.Code)
	}
	if !json.Valid(findingsW.Body.Bytes()) {
		t.Fatalf("expected valid json findings body: %s", findingsW.Body.String())
	}

	filteredFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/findings?severity=high&type=risky_trust_policy", nil)
	filteredFindingsW := httptest.NewRecorder()
	r.ServeHTTP(filteredFindingsW, filteredFindingsReq)
	if filteredFindingsW.Code != http.StatusOK {
		t.Fatalf("expected filtered findings 200, got %d", filteredFindingsW.Code)
	}

	findingReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1", nil)
	findingW := httptest.NewRecorder()
	r.ServeHTTP(findingW, findingReq)
	if findingW.Code != http.StatusOK {
		t.Fatalf("expected finding by id 200, got %d", findingW.Code)
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1/exports", nil)
	exportW := httptest.NewRecorder()
	r.ServeHTTP(exportW, exportReq)
	if exportW.Code != http.StatusOK {
		t.Fatalf("expected finding exports 200, got %d", exportW.Code)
	}
	var exportBody struct {
		OCSF map[string]any `json:"ocsf"`
		ASFF map[string]any `json:"asff"`
	}
	if err := json.Unmarshal(exportW.Body.Bytes(), &exportBody); err != nil {
		t.Fatalf("decode export body: %v", err)
	}
	findingInfo, ok := exportBody.OCSF["finding_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected finding_info object in OCSF payload, got %+v", exportBody.OCSF)
	}
	if findingInfo["uid"] != "f1" {
		t.Fatalf("expected ocsf payload, got %+v", exportBody.OCSF)
	}
	if exportBody.ASFF["SchemaVersion"] != "2018-10-08" {
		t.Fatalf("expected ASFF schema version, got %+v", exportBody.ASFF)
	}

	scansReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	scansW := httptest.NewRecorder()
	r.ServeHTTP(scansW, scansReq)
	if scansW.Code != http.StatusOK {
		t.Fatalf("expected scans 200, got %d", scansW.Code)
	}

	summaryReq := httptest.NewRequest(http.MethodGet, "/v1/findings/summary", nil)
	summaryW := httptest.NewRecorder()
	r.ServeHTTP(summaryW, summaryReq)
	if summaryW.Code != http.StatusOK {
		t.Fatalf("expected summary 200, got %d", summaryW.Code)
	}

	trendsReq := httptest.NewRequest(http.MethodGet, "/v1/findings/trends", nil)
	trendsW := httptest.NewRecorder()
	r.ServeHTTP(trendsW, trendsReq)
	if trendsW.Code != http.StatusOK {
		t.Fatalf("expected trends 200, got %d", trendsW.Code)
	}

	trendsFilteredReq := httptest.NewRequest(http.MethodGet, "/v1/findings/trends?severity=high&type=risky_trust_policy", nil)
	trendsFilteredW := httptest.NewRecorder()
	r.ServeHTTP(trendsFilteredW, trendsFilteredReq)
	if trendsFilteredW.Code != http.StatusOK {
		t.Fatalf("expected filtered trends 200, got %d", trendsFilteredW.Code)
	}

	identitiesReq := httptest.NewRequest(http.MethodGet, "/v1/identities", nil)
	identitiesW := httptest.NewRecorder()
	r.ServeHTTP(identitiesW, identitiesReq)
	if identitiesW.Code != http.StatusOK {
		t.Fatalf("expected identities 200, got %d", identitiesW.Code)
	}

	relationshipsReq := httptest.NewRequest(http.MethodGet, "/v1/relationships", nil)
	relationshipsW := httptest.NewRecorder()
	r.ServeHTTP(relationshipsW, relationshipsReq)
	if relationshipsW.Code != http.StatusOK {
		t.Fatalf("expected relationships 200, got %d", relationshipsW.Code)
	}

	ownershipReq := httptest.NewRequest(http.MethodGet, "/v1/ownership/signals", nil)
	ownershipW := httptest.NewRecorder()
	r.ServeHTTP(ownershipW, ownershipReq)
	if ownershipW.Code != http.StatusOK {
		t.Fatalf("expected ownership signals 200, got %d", ownershipW.Code)
	}

	diffReq := httptest.NewRequest(
		http.MethodGet,
		"/v1/scans/"+postBody2.Scan.ID+"/diff?previous_scan_id="+firstScanID,
		nil,
	)
	diffW := httptest.NewRecorder()
	r.ServeHTTP(diffW, diffReq)
	if diffW.Code != http.StatusOK {
		t.Fatalf("expected diff 200, got %d", diffW.Code)
	}

	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/scans/"+postBody.Scan.ID+"/events", nil)
	eventsW := httptest.NewRecorder()
	r.ServeHTTP(eventsW, eventsReq)
	if eventsW.Code != http.StatusOK {
		t.Fatalf("expected events 200, got %d", eventsW.Code)
	}

	eventsFilteredReq := httptest.NewRequest(http.MethodGet, "/v1/scans/"+postBody.Scan.ID+"/events?level=info", nil)
	eventsFilteredW := httptest.NewRecorder()
	r.ServeHTTP(eventsFilteredW, eventsFilteredReq)
	if eventsFilteredW.Code != http.StatusOK {
		t.Fatalf("expected filtered events 200, got %d", eventsFilteredW.Code)
	}

	repoBody := bytes.NewBufferString(`{"repository":"owner/repo","history_limit":50,"max_findings":20}`)
	repoReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", repoBody)
	repoReq.Header.Set("Content-Type", "application/json")
	repoW := httptest.NewRecorder()
	r.ServeHTTP(repoW, repoReq)
	if repoW.Code != http.StatusAccepted {
		t.Fatalf("expected repo scan 202, got %d", repoW.Code)
	}
	processedRepo, processRepoErr := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if processRepoErr != nil {
		t.Fatalf("process queued repo scan: %v", processRepoErr)
	}
	if !processedRepo {
		t.Fatal("expected queued repo scan to be processed")
	}

	repoScansReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans", nil)
	repoScansW := httptest.NewRecorder()
	r.ServeHTTP(repoScansW, repoScansReq)
	if repoScansW.Code != http.StatusOK {
		t.Fatalf("expected repo scans 200, got %d", repoScansW.Code)
	}
	var repoScansBody struct {
		Items []db.RepoScanRecord `json:"items"`
	}
	if err := json.Unmarshal(repoScansW.Body.Bytes(), &repoScansBody); err != nil {
		t.Fatalf("decode repo scans body: %v", err)
	}
	if len(repoScansBody.Items) == 0 {
		t.Fatal("expected repo scan items")
	}

	repoScanID := repoScansBody.Items[0].ID
	repoScanReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans/"+repoScanID, nil)
	repoScanW := httptest.NewRecorder()
	r.ServeHTTP(repoScanW, repoScanReq)
	if repoScanW.Code != http.StatusOK {
		t.Fatalf("expected repo scan detail 200, got %d", repoScanW.Code)
	}

	repoFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/repo-findings?repo_scan_id="+repoScanID, nil)
	repoFindingsW := httptest.NewRecorder()
	r.ServeHTTP(repoFindingsW, repoFindingsReq)
	if repoFindingsW.Code != http.StatusOK {
		t.Fatalf("expected repo findings 200, got %d", repoFindingsW.Code)
	}

	scansPageOneReq := httptest.NewRequest(http.MethodGet, "/v1/scans?limit=1", nil)
	scansPageOneW := httptest.NewRecorder()
	r.ServeHTTP(scansPageOneW, scansPageOneReq)
	if scansPageOneW.Code != http.StatusOK {
		t.Fatalf("expected scans page one 200, got %d", scansPageOneW.Code)
	}
	var scansPageOne struct {
		Items      []db.ScanRecord `json:"items"`
		NextCursor string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(scansPageOneW.Body.Bytes(), &scansPageOne); err != nil {
		t.Fatalf("decode scans page one: %v", err)
	}
	if len(scansPageOne.Items) != 1 || scansPageOne.NextCursor == "" {
		t.Fatalf("expected one scan and next cursor, got %+v", scansPageOne)
	}

	scansPageTwoReq := httptest.NewRequest(http.MethodGet, "/v1/scans?limit=1&cursor="+scansPageOne.NextCursor, nil)
	scansPageTwoW := httptest.NewRecorder()
	r.ServeHTTP(scansPageTwoW, scansPageTwoReq)
	if scansPageTwoW.Code != http.StatusOK {
		t.Fatalf("expected scans page two 200, got %d", scansPageTwoW.Code)
	}
	var scansPageTwo struct {
		Items []db.ScanRecord `json:"items"`
	}
	if err := json.Unmarshal(scansPageTwoW.Body.Bytes(), &scansPageTwo); err != nil {
		t.Fatalf("decode scans page two: %v", err)
	}
	if len(scansPageTwo.Items) != 1 {
		t.Fatalf("expected one scan on page two, got %+v", scansPageTwo)
	}
	if scansPageOne.Items[0].ID == scansPageTwo.Items[0].ID {
		t.Fatalf("expected different scan records across pages, got %q", scansPageTwo.Items[0].ID)
	}
}

func TestRouterUnavailableWhenServiceMissing(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{})

	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}

	summaryReq := httptest.NewRequest(http.MethodGet, "/v1/findings/summary", nil)
	summaryW := httptest.NewRecorder()
	r.ServeHTTP(summaryW, summaryReq)
	if summaryW.Code != http.StatusOK {
		t.Fatalf("expected summary 200 without service, got %d", summaryW.Code)
	}

	findingReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1", nil)
	findingW := httptest.NewRecorder()
	r.ServeHTTP(findingW, findingReq)
	if findingW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected finding-by-id 503 without service, got %d", findingW.Code)
	}

	exportsReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1/exports", nil)
	exportsW := httptest.NewRecorder()
	r.ServeHTTP(exportsW, exportsReq)
	if exportsW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected finding exports 503 without service, got %d", exportsW.Code)
	}

	identityReq := httptest.NewRequest(http.MethodGet, "/v1/identities", nil)
	identityW := httptest.NewRecorder()
	r.ServeHTTP(identityW, identityReq)
	if identityW.Code != http.StatusOK {
		t.Fatalf("expected identities 200 without service, got %d", identityW.Code)
	}

	ownershipReq := httptest.NewRequest(http.MethodGet, "/v1/ownership/signals", nil)
	ownershipW := httptest.NewRecorder()
	r.ServeHTTP(ownershipW, ownershipReq)
	if ownershipW.Code != http.StatusOK {
		t.Fatalf("expected ownership signals 200 without service, got %d", ownershipW.Code)
	}

	repoReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	repoReq.Header.Set("Content-Type", "application/json")
	repoW := httptest.NewRecorder()
	r.ServeHTTP(repoW, repoReq)
	if repoW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected repo scan 503 without service, got %d", repoW.Code)
	}

	repoScansReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans", nil)
	repoScansW := httptest.NewRecorder()
	r.ServeHTTP(repoScansW, repoScansReq)
	if repoScansW.Code != http.StatusOK {
		t.Fatalf("expected repo scans 200 without service, got %d", repoScansW.Code)
	}

	repoFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/repo-findings", nil)
	repoFindingsW := httptest.NewRecorder()
	r.ServeHTTP(repoFindingsW, repoFindingsReq)
	if repoFindingsW.Code != http.StatusOK {
		t.Fatalf("expected repo findings 200 without service, got %d", repoFindingsW.Code)
	}
}

func TestRouterScanEnqueueSucceedsWhenExecutionLockIsHeld(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")

	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "identrail:scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release(context.Background())
	svc.Locker = locker

	r := NewRouter(logger, metrics, svc, RouterOptions{})
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", w.Code)
	}
}

func TestRouterRepoScanEnqueueSucceedsWhenExecutionLockIsHeld(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "identrail:repo-scan:owner/repo")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release(context.Background())
	svc.Locker = locker

	r := NewRouter(logger, metrics, svc, RouterOptions{})
	req := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", w.Code)
	}
}

func TestRouterScanDuplicateGuard(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.ScanQueueMaxPending = 1
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	firstW := httptest.NewRecorder()
	r.ServeHTTP(firstW, firstReq)
	if firstW.Code != http.StatusAccepted {
		t.Fatalf("expected first enqueue 202, got %d", firstW.Code)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	secondW := httptest.NewRecorder()
	r.ServeHTTP(secondW, secondReq)
	if secondW.Code != http.StatusConflict {
		t.Fatalf("expected duplicate guard 409, got %d", secondW.Code)
	}
}

func TestRouterRepoScanQueueBackpressureAndDuplicateGuard(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 1
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	firstReq.Header.Set("Content-Type", "application/json")
	firstW := httptest.NewRecorder()
	r.ServeHTTP(firstW, firstReq)
	if firstW.Code != http.StatusAccepted {
		t.Fatalf("expected first repo enqueue 202, got %d", firstW.Code)
	}

	dupReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	dupReq.Header.Set("Content-Type", "application/json")
	dupW := httptest.NewRecorder()
	r.ServeHTTP(dupW, dupReq)
	if dupW.Code != http.StatusConflict {
		t.Fatalf("expected duplicate target conflict 409, got %d", dupW.Code)
	}

	otherReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/another"}`))
	otherReq.Header.Set("Content-Type", "application/json")
	otherW := httptest.NewRecorder()
	r.ServeHTTP(otherW, otherReq)
	if otherW.Code != http.StatusTooManyRequests {
		t.Fatalf("expected repo queue backpressure 429, got %d", otherW.Code)
	}
}

func TestRouterSupportsFindingsSortParameters(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)

	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f-critical", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, Title: "critical", CreatedAt: now},
		{ID: "f-info", Severity: domain.SeverityInfo, Type: domain.FindingOwnerless, Title: "info", CreatedAt: now},
		{ID: "f-high", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "high", CreatedAt: now},
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/v1/findings?scan_id="+scan.ID+"&sort_by=severity&sort_order=asc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body struct {
		Items []domain.Finding `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Items) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(body.Items))
	}
	if body.Items[0].ID != "f-info" || body.Items[2].ID != "f-critical" {
		t.Fatalf("unexpected sort order by severity asc: %+v", body.Items)
	}
}

func TestRouterFindingsPaginationFilterDeterminism(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 30, 0, 0, time.UTC)

	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f-a", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "a", CreatedAt: now},
		{ID: "f-b", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "b", CreatedAt: now},
		{ID: "f-c", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "c", CreatedAt: now},
	}); err != nil {
		t.Fatalf("seed findings for scan A: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scanB.ID, []domain.Finding{
		{ID: "f-other-scan", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "other", CreatedAt: now},
	}); err != nil {
		t.Fatalf("seed findings for scan B: %v", err)
	}

	for findingID, assignee := range map[string]string{
		"f-a": "platform",
		"f-b": "platform",
		"f-c": "security",
	} {
		if err := store.UpsertFindingTriageState(defaultScopeContext(), db.FindingTriageState{
			FindingID: findingID,
			Status:    domain.FindingLifecycleAck,
			Assignee:  assignee,
			UpdatedAt: now,
			UpdatedBy: "subject:test",
		}); err != nil {
			t.Fatalf("upsert triage state for %s: %v", findingID, err)
		}
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	baseQuery := "/v1/findings?scan_id=" + scanA.ID +
		"&severity=high&type=risky_trust_policy&lifecycle_status=ack&assignee=platform" +
		"&sort_by=severity&sort_order=asc&limit=1"
	pageOneReq := httptest.NewRequest(http.MethodGet, baseQuery, nil)
	pageOneW := httptest.NewRecorder()
	r.ServeHTTP(pageOneW, pageOneReq)
	if pageOneW.Code != http.StatusOK {
		t.Fatalf("expected findings page one 200, got %d body=%s", pageOneW.Code, pageOneW.Body.String())
	}
	var pageOneBody struct {
		Items      []domain.Finding `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(pageOneW.Body.Bytes(), &pageOneBody); err != nil {
		t.Fatalf("decode findings page one: %v", err)
	}
	if len(pageOneBody.Items) != 1 || pageOneBody.Items[0].ID != "f-a" {
		t.Fatalf("unexpected findings page one items: %+v", pageOneBody.Items)
	}
	if pageOneBody.NextCursor == "" {
		t.Fatal("expected findings page one next_cursor")
	}

	pageTwoReq := httptest.NewRequest(http.MethodGet, baseQuery+"&cursor="+pageOneBody.NextCursor, nil)
	pageTwoW := httptest.NewRecorder()
	r.ServeHTTP(pageTwoW, pageTwoReq)
	if pageTwoW.Code != http.StatusOK {
		t.Fatalf("expected findings page two 200, got %d body=%s", pageTwoW.Code, pageTwoW.Body.String())
	}
	var pageTwoBody struct {
		Items      []domain.Finding `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(pageTwoW.Body.Bytes(), &pageTwoBody); err != nil {
		t.Fatalf("decode findings page two: %v", err)
	}
	if len(pageTwoBody.Items) != 1 || pageTwoBody.Items[0].ID != "f-b" {
		t.Fatalf("unexpected findings page two items: %+v", pageTwoBody.Items)
	}
	if pageTwoBody.NextCursor != "" {
		t.Fatalf("expected no further cursor after last filtered result, got %q", pageTwoBody.NextCursor)
	}
	if pageOneBody.Items[0].ID == pageTwoBody.Items[0].ID {
		t.Fatalf("expected no duplicate findings across pages, got %q", pageOneBody.Items[0].ID)
	}
	for _, item := range append(pageOneBody.Items, pageTwoBody.Items...) {
		if item.ScanID != scanA.ID {
			t.Fatalf("expected scan_id filter to persist across pages, got finding %+v", item)
		}
		if item.Severity != domain.SeverityHigh || item.Type != domain.FindingRiskyTrustPolicy {
			t.Fatalf("expected severity/type filters to persist across pages, got finding %+v", item)
		}
		if item.Triage.Status != domain.FindingLifecycleAck || item.Triage.Assignee != "platform" {
			t.Fatalf("expected lifecycle_status/assignee filters to persist across pages, got finding %+v", item)
		}
	}
}

func TestRouterSupportsScansSortParameters(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.CompleteScan(defaultScopeContext(), scanA.ID, "completed", now.Add(2*time.Minute), 2, 7, ""); err != nil {
		t.Fatalf("complete scan A: %v", err)
	}
	if err := store.CompleteScan(defaultScopeContext(), scanB.ID, "completed", now.Add(3*time.Minute), 2, 1, ""); err != nil {
		t.Fatalf("complete scan B: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans?sort_by=finding_count&sort_order=asc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body struct {
		Items []db.ScanRecord `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(body.Items))
	}
	if body.Items[0].FindingCount != 1 || body.Items[1].FindingCount != 7 {
		t.Fatalf("unexpected scan sort order: %+v", body.Items)
	}
}

func TestRouterSortsScansBeyondInitialPageFetchWindow(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)

	scanOldest, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create oldest scan: %v", err)
	}
	scanMiddle, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create middle scan: %v", err)
	}
	scanNewest, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create newest scan: %v", err)
	}
	if err := store.CompleteScan(defaultScopeContext(), scanOldest.ID, "completed", now.Add(3*time.Minute), 2, 99, ""); err != nil {
		t.Fatalf("complete oldest scan: %v", err)
	}
	if err := store.CompleteScan(defaultScopeContext(), scanMiddle.ID, "completed", now.Add(4*time.Minute), 2, 1, ""); err != nil {
		t.Fatalf("complete middle scan: %v", err)
	}
	if err := store.CompleteScan(defaultScopeContext(), scanNewest.ID, "completed", now.Add(5*time.Minute), 2, 2, ""); err != nil {
		t.Fatalf("complete newest scan: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans?limit=1&sort_by=finding_count&sort_order=desc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body struct {
		Items []db.ScanRecord `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("expected one scan on page, got %d", len(body.Items))
	}
	if body.Items[0].ID != scanOldest.ID || body.Items[0].FindingCount != 99 {
		t.Fatalf("expected oldest high-finding scan first, got %+v", body.Items[0])
	}
}

func TestSortHelpersFallbackAndLevels(t *testing.T) {
	sortBy, desc := parseSortParams(" ", "invalid", "created_at")
	if sortBy != "created_at" || !desc {
		t.Fatalf("expected fallback sort defaults, got sort_by=%q desc=%t", sortBy, desc)
	}

	if got := scanEventLevelRank("warn"); got <= scanEventLevelRank("info") {
		t.Fatalf("expected warn rank greater than info, got warn=%d info=%d", got, scanEventLevelRank("info"))
	}
}

func TestSortHelpersCoverageForAllCollections(t *testing.T) {
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	findings := []domain.Finding{
		{ID: "f1", Severity: domain.SeverityLow, Type: domain.FindingOwnerless, Title: "b", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "f2", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, Title: "a", CreatedAt: now.Add(-1 * time.Minute)},
	}
	sortFindings(findings, "title", false)
	if findings[0].Title != "a" {
		t.Fatalf("expected title asc sort, got %+v", findings)
	}
	sortFindings(findings, "severity", true)
	if findings[0].Severity != domain.SeverityCritical {
		t.Fatalf("expected severity desc sort, got %+v", findings)
	}

	scans := []db.ScanRecord{
		{ID: "s1", Status: "completed", AssetCount: 2, FindingCount: 8, StartedAt: now.Add(-2 * time.Minute)},
		{ID: "s2", Status: "running", AssetCount: 5, FindingCount: 1, StartedAt: now.Add(-1 * time.Minute)},
	}
	sortScans(scans, "finding_count", false)
	if scans[0].ID != "s2" {
		t.Fatalf("expected finding_count asc sort, got %+v", scans)
	}
	sortScans(scans, "asset_count", true)
	if scans[0].ID != "s2" {
		t.Fatalf("expected asset_count desc sort, got %+v", scans)
	}
	sortScans(scans, "status", false)
	if scans[0].Status != "completed" {
		t.Fatalf("expected status asc sort, got %+v", scans)
	}

	events := []db.ScanEvent{
		{ID: "e1", Level: db.ScanEventLevelInfo, Message: "z", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "e2", Level: db.ScanEventLevelError, Message: "a", CreatedAt: now.Add(-1 * time.Minute)},
	}
	sortScanEvents(events, "level", true)
	if events[0].Level != db.ScanEventLevelError {
		t.Fatalf("expected level desc sort, got %+v", events)
	}
	sortScanEvents(events, "message", false)
	if events[0].Message != "a" {
		t.Fatalf("expected message asc sort, got %+v", events)
	}

	repoScans := []db.RepoScanRecord{
		{ID: "r1", Repository: "z/repo", Status: "completed", CommitsScanned: 10, FindingCount: 4, StartedAt: now.Add(-2 * time.Minute)},
		{ID: "r2", Repository: "a/repo", Status: "running", CommitsScanned: 3, FindingCount: 1, StartedAt: now.Add(-1 * time.Minute)},
	}
	sortRepoScans(repoScans, "repository", false)
	if repoScans[0].Repository != "a/repo" {
		t.Fatalf("expected repository asc sort, got %+v", repoScans)
	}
	sortRepoScans(repoScans, "commits_scanned", false)
	if repoScans[0].CommitsScanned != 3 {
		t.Fatalf("expected commits_scanned asc sort, got %+v", repoScans)
	}

	identities := []domain.Identity{
		{ID: "i1", Provider: domain.ProviderKubernetes, Type: domain.IdentityTypeServiceAccount, Name: "zeta", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "i2", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "alpha", CreatedAt: now.Add(-1 * time.Minute)},
	}
	sortIdentities(identities, "provider", false)
	if identities[0].Provider != domain.ProviderAWS {
		t.Fatalf("expected provider asc sort, got %+v", identities)
	}
	sortIdentities(identities, "type", false)
	if identities[0].Type != domain.IdentityTypeRole {
		t.Fatalf("expected type asc sort, got %+v", identities)
	}
	sortIdentities(identities, "created_at", true)
	if !identities[0].CreatedAt.After(identities[1].CreatedAt) {
		t.Fatalf("expected created_at desc sort, got %+v", identities)
	}

	relationships := []domain.Relationship{
		{ID: "x2", Type: domain.RelationshipCanAccess, FromNodeID: "z", ToNodeID: "a", DiscoveredAt: now.Add(-2 * time.Minute)},
		{ID: "x1", Type: domain.RelationshipCanAssume, FromNodeID: "a", ToNodeID: "z", DiscoveredAt: now.Add(-1 * time.Minute)},
	}
	sortRelationships(relationships, "type", false)
	if relationships[0].Type != domain.RelationshipCanAccess {
		t.Fatalf("expected type asc sort, got %+v", relationships)
	}
	sortRelationships(relationships, "from_node_id", false)
	if relationships[0].FromNodeID != "a" {
		t.Fatalf("expected from_node_id asc sort, got %+v", relationships)
	}
	sortRelationships(relationships, "to_node_id", false)
	if relationships[0].ToNodeID != "a" {
		t.Fatalf("expected to_node_id asc sort, got %+v", relationships)
	}

	ownership := []domain.OwnershipSignal{
		{ID: "o1", Team: "zeta", Source: "tags", Confidence: 0.5},
		{ID: "o2", Team: "alpha", Source: "owner_hint", Confidence: 0.9},
	}
	sortOwnershipSignals(ownership, "team", false)
	if ownership[0].Team != "alpha" {
		t.Fatalf("expected team asc sort, got %+v", ownership)
	}
	sortOwnershipSignals(ownership, "source", false)
	if ownership[0].Source != "owner_hint" {
		t.Fatalf("expected source asc sort, got %+v", ownership)
	}
	sortOwnershipSignals(ownership, "confidence", true)
	if ownership[0].Confidence < ownership[1].Confidence {
		t.Fatalf("expected confidence desc sort, got %+v", ownership)
	}

	if compareFloat(1.2, 1.2) != 0 {
		t.Fatal("expected compareFloat equality branch")
	}
}

func TestSecureKeyHelpers(t *testing.T) {
	if !secureKeyEquals("reader-secret", "reader-secret") {
		t.Fatal("expected equal keys to match")
	}
	if secureKeyEquals("reader-secret", "reader-secret-2") {
		t.Fatal("expected different keys to not match")
	}
	if keyInList([]string{"reader", "writer"}, "admin") {
		t.Fatal("expected missing key to not be found")
	}
	if !keyInList([]string{"reader", "writer"}, "writer") {
		t.Fatal("expected exact key to be found")
	}
	scoped := map[string]scopedAPIKeyAuthConfig{
		"reader": {Scopes: newScopeSet([]string{"read"})},
		"writer": {Scopes: newScopeSet([]string{"read", "write"})},
	}
	if _, ok := scopedKeyLookup(scoped, "missing"); ok {
		t.Fatal("expected missing scoped key to not resolve")
	}
	if config, ok := scopedKeyLookup(scoped, "writer"); !ok || !config.Scopes.has("write") {
		t.Fatalf("expected writer scopes to resolve, got ok=%t config=%+v", ok, config)
	}
}

func varyHeaderContains(varyHeader string, value string) bool {
	for _, token := range strings.Split(varyHeader, ",") {
		if strings.EqualFold(strings.TrimSpace(token), strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

func TestRouterRequiresAPIKeyForV1(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{APIKeys: []string{"secret-key"}})

	unauthReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	unauthW := httptest.NewRecorder()
	r.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthW.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	authReq.Header.Set("X-API-Key", "secret-key")
	authW := httptest.NewRecorder()
	r.ServeHTTP(authW, authReq)
	if authW.Code != http.StatusOK {
		t.Fatalf("expected 200 with api key, got %d", authW.Code)
	}
}

func TestRouterWriteAuthorization(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"read-key", "write-key"},
		WriteAPIKeys: []string{"write-key"},
	})

	readReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	readReq.Header.Set("X-API-Key", "read-key")
	readW := httptest.NewRecorder()
	r.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("expected read with read-key to pass, got %d", readW.Code)
	}

	writeDeniedReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeDeniedReq.Header.Set("X-API-Key", "read-key")
	writeDeniedW := httptest.NewRecorder()
	r.ServeHTTP(writeDeniedW, writeDeniedReq)
	if writeDeniedW.Code != http.StatusForbidden {
		t.Fatalf("expected write with read-key to be forbidden, got %d", writeDeniedW.Code)
	}

	writeAllowedReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeAllowedReq.Header.Set("X-API-Key", "write-key")
	writeAllowedW := httptest.NewRecorder()
	r.ServeHTTP(writeAllowedW, writeAllowedReq)
	if writeAllowedW.Code != http.StatusAccepted {
		t.Fatalf("expected write with write-key to pass, got %d", writeAllowedW.Code)
	}
}

func TestRouterFindingTriageWorkflowEndpoints(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"read-key", "write-key"},
		WriteAPIKeys: []string{"write-key"},
	})

	triggerReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	triggerReq.Header.Set("X-API-Key", "write-key")
	triggerW := httptest.NewRecorder()
	r.ServeHTTP(triggerW, triggerReq)
	if triggerW.Code != http.StatusAccepted {
		t.Fatalf("expected scan trigger 202, got %d", triggerW.Code)
	}
	var triggerBody struct {
		Scan db.ScanRecord `json:"scan"`
	}
	if err := json.Unmarshal(triggerW.Body.Bytes(), &triggerBody); err != nil {
		t.Fatalf("decode scan trigger body: %v", err)
	}
	if triggerBody.Scan.ID == "" {
		t.Fatal("expected scan id in trigger response")
	}
	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan: %v", err)
	}
	if !processed {
		t.Fatal("expected one queued scan to be processed")
	}

	triagePayload := bytes.NewBufferString(`{"status":"ack","assignee":"platform","comment":"acknowledged for follow-up"}`)
	triageDeniedReq := httptest.NewRequest(http.MethodPatch, "/v1/findings/f1/triage?scan_id="+triggerBody.Scan.ID, bytes.NewBuffer(triagePayload.Bytes()))
	triageDeniedReq.Header.Set("Content-Type", "application/json")
	triageDeniedReq.Header.Set("X-API-Key", "read-key")
	triageDeniedW := httptest.NewRecorder()
	r.ServeHTTP(triageDeniedW, triageDeniedReq)
	if triageDeniedW.Code != http.StatusForbidden {
		t.Fatalf("expected read-key triage to be forbidden, got %d", triageDeniedW.Code)
	}

	triageReq := httptest.NewRequest(http.MethodPatch, "/v1/findings/f1/triage?scan_id="+triggerBody.Scan.ID, bytes.NewBuffer(triagePayload.Bytes()))
	triageReq.Header.Set("Content-Type", "application/json")
	triageReq.Header.Set("X-API-Key", "write-key")
	triageW := httptest.NewRecorder()
	r.ServeHTTP(triageW, triageReq)
	if triageW.Code != http.StatusOK {
		t.Fatalf("expected write-key triage to pass, got %d", triageW.Code)
	}

	var triageBody struct {
		Finding domain.Finding `json:"finding"`
	}
	if err := json.Unmarshal(triageW.Body.Bytes(), &triageBody); err != nil {
		t.Fatalf("decode triage body: %v", err)
	}
	if triageBody.Finding.Triage.Status != domain.FindingLifecycleAck {
		t.Fatalf("expected ack triage status, got %q", triageBody.Finding.Triage.Status)
	}
	if triageBody.Finding.Triage.Assignee != "platform" {
		t.Fatalf("expected platform assignee, got %q", triageBody.Finding.Triage.Assignee)
	}

	filteredReq := httptest.NewRequest(http.MethodGet, "/v1/findings?lifecycle_status=ack&assignee=platform", nil)
	filteredReq.Header.Set("X-API-Key", "read-key")
	filteredW := httptest.NewRecorder()
	r.ServeHTTP(filteredW, filteredReq)
	if filteredW.Code != http.StatusOK {
		t.Fatalf("expected filtered findings 200, got %d", filteredW.Code)
	}
	var filteredBody struct {
		Items []domain.Finding `json:"items"`
	}
	if err := json.Unmarshal(filteredW.Body.Bytes(), &filteredBody); err != nil {
		t.Fatalf("decode filtered findings body: %v", err)
	}
	if len(filteredBody.Items) != 1 || filteredBody.Items[0].ID != "f1" {
		t.Fatalf("unexpected filtered findings: %+v", filteredBody.Items)
	}

	historyReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1/history?scan_id="+triggerBody.Scan.ID, nil)
	historyReq.Header.Set("X-API-Key", "read-key")
	historyW := httptest.NewRecorder()
	r.ServeHTTP(historyW, historyReq)
	if historyW.Code != http.StatusOK {
		t.Fatalf("expected triage history 200, got %d", historyW.Code)
	}
	var historyBody struct {
		Items []db.FindingTriageEvent `json:"items"`
	}
	if err := json.Unmarshal(historyW.Body.Bytes(), &historyBody); err != nil {
		t.Fatalf("decode history body: %v", err)
	}
	if len(historyBody.Items) != 1 {
		t.Fatalf("expected one history event, got %d", len(historyBody.Items))
	}
	if historyBody.Items[0].Action != db.FindingTriageActionAcknowledged {
		t.Fatalf("expected acknowledged action, got %q", historyBody.Items[0].Action)
	}
	if historyBody.Items[0].Actor == "" {
		t.Fatalf("expected actor on history event, got %+v", historyBody.Items[0])
	}
}

func TestRouterWriteAuthorizationRequiresConfiguredWriteKeys(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys: []string{"read-key"},
	})

	writeReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeReq.Header.Set("X-API-Key", "read-key")
	writeW := httptest.NewRecorder()
	r.ServeHTTP(writeW, writeReq)
	if writeW.Code != http.StatusForbidden {
		t.Fatalf("expected write to be forbidden when no write keys are configured, got %d", writeW.Code)
	}
}

func TestRouterScopedAuthorizationPrefersScopeMap(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"legacy-key"},
		WriteAPIKeys: []string{"legacy-key"},
		APIKeyScopes: map[string][]string{
			"reader-key": {"read"},
			"writer-key": {scopeWrite},
			"bad-key":    {"invalid"},
		},
	})

	legacyReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	legacyReq.Header.Set("X-API-Key", "legacy-key")
	legacyW := httptest.NewRecorder()
	r.ServeHTTP(legacyW, legacyReq)
	if legacyW.Code != http.StatusUnauthorized {
		t.Fatalf("expected legacy key rejected when scoped keys set, got %d", legacyW.Code)
	}

	readReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	readReq.Header.Set("X-API-Key", "reader-key")
	readW := httptest.NewRecorder()
	r.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("expected read with reader-key to pass, got %d", readW.Code)
	}

	readWriteDeniedReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	readWriteDeniedReq.Header.Set("X-API-Key", "reader-key")
	readWriteDeniedW := httptest.NewRecorder()
	r.ServeHTTP(readWriteDeniedW, readWriteDeniedReq)
	if readWriteDeniedW.Code != http.StatusForbidden {
		t.Fatalf("expected writer action to fail with reader-key, got %d", readWriteDeniedW.Code)
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeReq.Header.Set("X-API-Key", "writer-key")
	writeW := httptest.NewRecorder()
	r.ServeHTTP(writeW, writeReq)
	if writeW.Code != http.StatusAccepted {
		t.Fatalf("expected write with writer-key to pass, got %d", writeW.Code)
	}

	bearerFallbackReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	bearerFallbackReq.Header.Set("Authorization", "Bearer writer-key")
	bearerFallbackW := httptest.NewRecorder()
	r.ServeHTTP(bearerFallbackW, bearerFallbackReq)
	if bearerFallbackW.Code != http.StatusUnauthorized {
		t.Fatalf("expected bearer api-key fallback to be rejected, got %d", bearerFallbackW.Code)
	}

	badScopeReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	badScopeReq.Header.Set("X-API-Key", "bad-key")
	badScopeW := httptest.NewRecorder()
	r.ServeHTTP(badScopeW, badScopeReq)
	if badScopeW.Code != http.StatusForbidden {
		t.Fatalf("expected bad-key read to be forbidden, got %d", badScopeW.Code)
	}
}

func TestRouterScopedAuthorizationRejectsUnboundScopedKey(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeyScopes: map[string][]string{
			"reader-key": {"read"},
		},
		APIKeyScopeBindings: map[string]db.Scope{
			"other-key": {TenantID: "tenant-a", WorkspaceID: "workspace-a"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	req.Header.Set("X-API-Key", "reader-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unbound scoped key to be rejected, got %d", w.Code)
	}
}

func TestAPIKeyAuthMiddlewareEnforcesScopeBindings(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(apiKeyAuthMiddleware(
		[]string{"reader-key"},
		map[string][]string{"reader-key": {"read"}},
		map[string]db.Scope{"reader-key": {TenantID: "tenant-a", WorkspaceID: "workspace-a"}},
		nil,
		nil,
		nil,
		nil,
		nil,
	))
	r.Use(requestScopeMiddleware("default-tenant", "default-workspace"))
	r.GET("/scope", func(c *gin.Context) {
		scope := db.ScopeFromContext(c.Request.Context())
		c.JSON(http.StatusOK, map[string]string{
			"tenant_id":    scope.TenantID,
			"workspace_id": scope.WorkspaceID,
		})
	})

	noHeaderReq := httptest.NewRequest(http.MethodGet, "/scope", nil)
	noHeaderReq.Header.Set("X-API-Key", "reader-key")
	noHeaderW := httptest.NewRecorder()
	r.ServeHTTP(noHeaderW, noHeaderReq)
	if noHeaderW.Code != http.StatusOK {
		t.Fatalf("expected bound key to work without explicit headers, got %d", noHeaderW.Code)
	}
	var noHeaderBody map[string]string
	if err := json.Unmarshal(noHeaderW.Body.Bytes(), &noHeaderBody); err != nil {
		t.Fatalf("decode no-header scope response: %v", err)
	}
	if noHeaderBody["tenant_id"] != "tenant-a" || noHeaderBody["workspace_id"] != "workspace-a" {
		t.Fatalf("expected bound scope tenant-a/workspace-a, got %+v", noHeaderBody)
	}

	matchReq := httptest.NewRequest(http.MethodGet, "/scope", nil)
	matchReq.Header.Set("X-API-Key", "reader-key")
	matchReq.Header.Set(scopeHeaderTenantID, "tenant-a")
	matchReq.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	matchW := httptest.NewRecorder()
	r.ServeHTTP(matchW, matchReq)
	if matchW.Code != http.StatusOK {
		t.Fatalf("expected matching scoped headers to pass, got %d", matchW.Code)
	}

	mismatchReq := httptest.NewRequest(http.MethodGet, "/scope", nil)
	mismatchReq.Header.Set("X-API-Key", "reader-key")
	mismatchReq.Header.Set(scopeHeaderTenantID, "tenant-b")
	mismatchReq.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	mismatchW := httptest.NewRecorder()
	r.ServeHTTP(mismatchW, mismatchReq)
	if mismatchW.Code != http.StatusUnauthorized {
		t.Fatalf("expected mismatched scoped headers to be rejected, got %d", mismatchW.Code)
	}
}

func TestRouterOIDCOnlyAuthentication(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"good-token": {
					Subject:     "user-1",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"read"},
				},
				"no-scope-token": {
					Subject:     "user-2",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      nil,
				},
			},
			errs: map[string]error{
				"expired-token": errors.New("oidc: token is expired"),
			},
		},
	})

	unauthReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	unauthW := httptest.NewRecorder()
	r.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", unauthW.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	authReq.Header.Set("Authorization", "Bearer good-token")
	authW := httptest.NewRecorder()
	r.ServeHTTP(authW, authReq)
	if authW.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid oidc token, got %d", authW.Code)
	}

	noScopeReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	noScopeReq.Header.Set("Authorization", "Bearer no-scope-token")
	noScopeW := httptest.NewRecorder()
	r.ServeHTTP(noScopeW, noScopeReq)
	if noScopeW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for oidc token without read scope, got %d", noScopeW.Code)
	}

	expiredReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	expiredReq.Header.Set("Authorization", "Bearer expired-token")
	expiredW := httptest.NewRecorder()
	r.ServeHTTP(expiredW, expiredReq)
	if expiredW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired oidc token, got %d", expiredW.Code)
	}
}

func TestRouterOIDCWriteScopeAuthorization(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"reader-token": {
					Subject:     "user-read",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"identrail.read"},
				},
				"writer-token": {
					Subject:     "user-write",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"identrail.write"},
				},
			},
		},
		OIDCWriteScopes: []string{"identrail.write"},
	})

	readerWriteReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	readerWriteReq.Header.Set("Authorization", "Bearer reader-token")
	readerWriteW := httptest.NewRecorder()
	r.ServeHTTP(readerWriteW, readerWriteReq)
	if readerWriteW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only token on write path, got %d", readerWriteW.Code)
	}

	writerReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writerReq.Header.Set("Authorization", "Bearer writer-token")
	writerW := httptest.NewRecorder()
	r.ServeHTTP(writerW, writerReq)
	if writerW.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for writer token, got %d", writerW.Code)
	}
}

func TestRouterHybridOIDCAndLegacyAPIKeyReadCompatibility(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys: []string{"legacy-key"},
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"reader-token": {
					Subject:     "user-read",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"identrail.read"},
				},
			},
		},
	})

	readReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	readReq.Header.Set("X-API-Key", "legacy-key")
	readW := httptest.NewRecorder()
	r.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("expected legacy api key read to pass in hybrid mode, got %d", readW.Code)
	}
}

func TestRequestScopeMiddlewarePrefersOIDCTenantWorkspaceClaims(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth.tenant_id", "tenant-from-token")
		c.Set("auth.workspace_id", "workspace-from-token")
		c.Next()
	})
	r.Use(requestScopeMiddleware("default-tenant", "default-workspace", false))
	r.GET("/scope", func(c *gin.Context) {
		scope := db.ScopeFromContext(c.Request.Context())
		c.JSON(http.StatusOK, map[string]string{
			"tenant_id":    scope.TenantID,
			"workspace_id": scope.WorkspaceID,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/scope", nil)
	req.Header.Set("X-Identrail-Tenant-ID", "header-tenant")
	req.Header.Set("X-Identrail-Workspace-ID", "header-workspace")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["tenant_id"] != "tenant-from-token" {
		t.Fatalf("expected tenant from oidc claim, got %q", body["tenant_id"])
	}
	if body["workspace_id"] != "workspace-from-token" {
		t.Fatalf("expected workspace from oidc claim, got %q", body["workspace_id"])
	}
}

func TestRequestScopeMiddlewareRequiresExplicitScope(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(requestScopeMiddleware("default-tenant", "default-workspace", true))
	r.GET("/scope", func(c *gin.Context) {
		scope := db.ScopeFromContext(c.Request.Context())
		c.JSON(http.StatusOK, map[string]string{
			"tenant_id":    scope.TenantID,
			"workspace_id": scope.WorkspaceID,
		})
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/scope", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected missing explicit scope to return 400, got %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/scope", nil)
	req.Header.Set("X-Identrail-Tenant-ID", "tenant-a")
	req.Header.Set("X-Identrail-Workspace-ID", "workspace-a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected explicit headers to pass, got %d", w.Code)
	}
}
func TestRequestScopeMiddlewareIgnoresScopeHeadersForAPIKeyAuth(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth.api_key", "reader-key")
		c.Next()
	})
	r.Use(requestScopeMiddleware("default-tenant", "default-workspace"))
	r.GET("/scope", func(c *gin.Context) {
		scope := db.ScopeFromContext(c.Request.Context())
		c.JSON(http.StatusOK, map[string]string{
			"tenant_id":    scope.TenantID,
			"workspace_id": scope.WorkspaceID,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/scope", nil)
	req.Header.Set("X-Identrail-Tenant-ID", "header-tenant")
	req.Header.Set("X-Identrail-Workspace-ID", "header-workspace")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["tenant_id"] != "default-tenant" {
		t.Fatalf("expected default tenant for api key auth, got %q", body["tenant_id"])
	}
	if body["workspace_id"] != "default-workspace" {
		t.Fatalf("expected default workspace for api key auth, got %q", body["workspace_id"])
	}
}

func TestRequestScopeMiddlewareUsesAPIKeyScopeBindings(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth.api_key", "reader-key")
		c.Set(authAPIKeyTenantID, "tenant-a")
		c.Set(authAPIKeyWorkspaceID, "workspace-a")
		c.Next()
	})
	r.Use(requestScopeMiddleware("default-tenant", "default-workspace"))
	r.GET("/scope", func(c *gin.Context) {
		scope := db.ScopeFromContext(c.Request.Context())
		c.JSON(http.StatusOK, map[string]string{
			"tenant_id":    scope.TenantID,
			"workspace_id": scope.WorkspaceID,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/scope", nil)
	req.Header.Set(scopeHeaderTenantID, "tenant-a")
	req.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected bound api key scope to pass, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["tenant_id"] != "tenant-a" || body["workspace_id"] != "workspace-a" {
		t.Fatalf("expected bound scope values, got %+v", body)
	}
}

func TestRequestScopeMiddlewareRejectsAPIKeyHeaderScopeMismatch(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth.api_key", "reader-key")
		c.Set(authAPIKeyTenantID, "tenant-a")
		c.Set(authAPIKeyWorkspaceID, "workspace-a")
		c.Next()
	})
	r.Use(requestScopeMiddleware("default-tenant", "default-workspace"))
	r.GET("/scope", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/scope", nil)
	req.Header.Set(scopeHeaderTenantID, "tenant-b")
	req.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected mismatched api key scope override rejected with 403, got %d", w.Code)
	}
}

func TestRouterRateLimitExceeded(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{RateLimitRPM: 1, RateLimitBurst: 1})

	first := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	first.RemoteAddr = "127.0.0.1:12345"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	second.RemoteAddr = "127.0.0.1:12345"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", w2.Code)
	}
}

func TestRouterRejectsOversizedJSONRequestBody(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"writer-key"},
		WriteAPIKeys: []string{"writer-key"},
	})

	payload := bytes.Repeat([]byte("a"), int(defaultJSONBodyLimit)+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "writer-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized request to return 413, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRouterRejectsOversizedJSONRequestBodyWithoutContentType(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"writer-key"},
		WriteAPIKeys: []string{"writer-key"},
	})

	payload := bytes.Repeat([]byte("a"), int(defaultJSONBodyLimit)+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewReader(payload))
	req.Header.Set("X-API-Key", "writer-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized request without content type to return 413, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRouterRejectsOversizedChunkedJSONRequestBody(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"writer-key"},
		WriteAPIKeys: []string{"writer-key"},
	})

	payload := bytes.Repeat([]byte("a"), int(defaultJSONBodyLimit)+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "writer-key")
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized chunked request to return 413, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRouterRateLimitAppliesToUnauthorizedRequests(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys:        []string{"secret-key"},
		RateLimitRPM:   1,
		RateLimitBurst: 1,
	})

	first := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	first.RemoteAddr = "127.0.0.1:23456"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected first unauthorized request 401, got %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	second.RemoteAddr = "127.0.0.1:23456"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second unauthorized request 429, got %d", w2.Code)
	}
}

func TestRouterRateLimitDoesNotTrustPresentedBearerTokenValue(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"good-token": {
					Subject:     "user-1",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"read"},
				},
			},
		},
		RateLimitRPM:   1,
		RateLimitBurst: 1,
	})

	invalid := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	invalid.RemoteAddr = "127.0.0.1:27501"
	invalid.Header.Set("Authorization", "Bearer invalid-token")
	invalidW := httptest.NewRecorder()
	r.ServeHTTP(invalidW, invalid)
	if invalidW.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid bearer request to be unauthorized, got %d", invalidW.Code)
	}

	validFirst := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	validFirst.RemoteAddr = "127.0.0.1:27501"
	validFirst.Header.Set("Authorization", "Bearer good-token")
	validFirstW := httptest.NewRecorder()
	r.ServeHTTP(validFirstW, validFirst)
	if validFirstW.Code != http.StatusTooManyRequests {
		t.Fatalf("expected valid bearer request to share anonymous bearer bucket after invalid token, got %d", validFirstW.Code)
	}

	validSecond := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	validSecond.RemoteAddr = "127.0.0.1:27501"
	validSecond.Header.Set("Authorization", "Bearer good-token")
	validSecondW := httptest.NewRecorder()
	r.ServeHTTP(validSecondW, validSecond)
	if validSecondW.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request on exhausted bearer bucket to hit 429, got %d", validSecondW.Code)
	}
}
func TestRouterRateLimitExceededIsAudited(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink:      sink,
		RateLimitRPM:   1,
		RateLimitBurst: 1,
	})

	first := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	first.RemoteAddr = "127.0.0.1:34567"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	second.RemoteAddr = "127.0.0.1:34567"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", w2.Code)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) < 2 {
		t.Fatalf("expected both requests to be audited, got %d events", len(sink.events))
	}
	last := sink.events[len(sink.events)-1]
	if last.Path != "/v1/scans" || last.Status != http.StatusTooManyRequests {
		t.Fatalf("expected throttled request audit event, got %+v", last)
	}
}

func TestRouterRateLimitAppliesBeforeUnauthorizedAuthChecks(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys:        []string{"expected-key"},
		RateLimitRPM:   1,
		RateLimitBurst: 1,
	})

	first := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	first.RemoteAddr = "127.0.0.1:23456"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected first unauthorized request to return 401, got %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	second.RemoteAddr = "127.0.0.1:23456"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second unauthorized request to return 429, got %d", w2.Code)
	}

	authorized := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	authorized.RemoteAddr = "127.0.0.1:23456"
	authorized.Header.Set("X-API-Key", "expected-key")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, authorized)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected authorized request to use a separate rate limit bucket, got %d", w3.Code)
	}
}

func TestRouterRateLimitDoesNotTrustPresentedCredentialValue(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys:        []string{"expected-key"},
		RateLimitRPM:   1,
		RateLimitBurst: 1,
	})

	first := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	first.RemoteAddr = "127.0.0.1:34567"
	first.Header.Set("X-API-Key", "bogus-one")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected first invalid API key request to return 401, got %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	second.RemoteAddr = "127.0.0.1:34567"
	second.Header.Set("X-API-Key", "bogus-two")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second invalid API key request to return 429 despite a rotated key, got %d", w2.Code)
	}
}

func TestIPRateLimiterEvictsExpiredEntries(t *testing.T) {
	now := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	limiter := newIPRateLimiterWithClock(
		60,
		1,
		func() time.Time { return now },
		1*time.Second,
		2,
		1,
	)

	if !limiter.allow("10.0.0.1") {
		t.Fatal("expected first request to pass")
	}
	if len(limiter.limiters) != 1 {
		t.Fatalf("expected one tracked ip, got %d", len(limiter.limiters))
	}

	now = now.Add(2 * time.Second)
	if !limiter.allow("10.0.0.2") {
		t.Fatal("expected new request to pass")
	}
	if len(limiter.limiters) != 1 {
		t.Fatalf("expected stale entry eviction to keep one tracked ip, got %d", len(limiter.limiters))
	}
	if _, exists := limiter.limiters["10.0.0.1"]; exists {
		t.Fatal("expected expired ip entry to be evicted")
	}
}

func TestIPRateLimiterEvictsOldestEntryWhenCapacityReached(t *testing.T) {
	now := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	limiter := newIPRateLimiterWithClock(
		60,
		1,
		func() time.Time { return now },
		1*time.Hour,
		2,
		1,
	)

	if !limiter.allow("10.0.0.1") {
		t.Fatal("expected first request to pass")
	}
	now = now.Add(100 * time.Millisecond)
	if !limiter.allow("10.0.0.2") {
		t.Fatal("expected second request to pass")
	}
	now = now.Add(100 * time.Millisecond)
	if !limiter.allow("10.0.0.3") {
		t.Fatal("expected third request to pass")
	}
	if len(limiter.limiters) != 2 {
		t.Fatalf("expected limiter size to stay bounded at 2, got %d", len(limiter.limiters))
	}
	if _, exists := limiter.limiters["10.0.0.1"]; exists {
		t.Fatal("expected oldest entry to be evicted when capacity is reached")
	}
	if _, exists := limiter.limiters["10.0.0.2"]; !exists {
		t.Fatal("expected newer entry to remain in limiter cache")
	}
	if _, exists := limiter.limiters["10.0.0.3"]; !exists {
		t.Fatal("expected most recent entry to remain in limiter cache")
	}
}

func TestParseLimit(t *testing.T) {
	if got := parseLimit("", 10, 500); got != 10 {
		t.Fatalf("expected fallback 10, got %d", got)
	}
	if got := parseLimit("invalid", 10, 500); got != 10 {
		t.Fatalf("expected fallback 10, got %d", got)
	}
	if got := parseLimit("1000", 10, 500); got != 500 {
		t.Fatalf("expected clamp 500, got %d", got)
	}
	if got := parseLimit("25", 10, 500); got != 25 {
		t.Fatalf("expected 25, got %d", got)
	}
}

func TestRouterEmitsAuditLog(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	entries := observed.FilterMessage("api request").All()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit log entry")
	}
	last := entries[len(entries)-1]
	if got := last.ContextMap()["path"]; got != "/v1/scans" {
		t.Fatalf("expected path /v1/scans, got %v", got)
	}
	if got := last.ContextMap()["method"]; got != "GET" {
		t.Fatalf("expected method GET, got %v", got)
	}
	if got := last.ContextMap()["component"]; got != "api" {
		t.Fatalf("expected component api, got %v", got)
	}
	if got := last.ContextMap()["operation"]; got != "api_request" {
		t.Fatalf("expected operation api_request, got %v", got)
	}
	gotRequestID, ok := last.ContextMap()["request_id"]
	if !ok {
		t.Fatal("expected request_id in audit log entry")
	}
	if gotRequestID == nil {
		t.Fatal("expected request_id in audit log entry")
	}
	if got, ok := gotRequestID.(string); !ok || got == "" {
		t.Fatal("expected request_id in audit log entry")
	}
}

func TestRouterWritesAuditSink(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink:    sink,
		APIKeyScopes: map[string][]string{"reader-key": {"read", "tenant:tenant-a", "workspace:workspace-a"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans/scan-1/events", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	req.Header.Set("User-Agent", "router-test")
	req.Header.Set("X-API-Key", "reader-key")
	req.Header.Set(scopeHeaderTenantID, "tenant-a")
	req.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected sink to capture at least one event")
	}
	event := sink.events[len(sink.events)-1]
	if event.Path != "/v1/scans/scan-1/events" || event.Method != http.MethodGet {
		t.Fatalf("unexpected sink event: %+v", event)
	}
	if event.UserAgent != "router-test" {
		t.Fatalf("unexpected user agent in event: %q", event.UserAgent)
	}
	if event.APIKeyID == "" {
		t.Fatal("expected api key fingerprint in audit event")
	}
	if event.APIKeyID == "reader-key" {
		t.Fatal("expected fingerprint instead of raw api key")
	}
	if event.Authz == nil {
		t.Fatal("expected authz decision in audit event")
	}
	if !event.Authz.Allowed {
		t.Fatalf("expected allowed authz decision, got %+v", event.Authz)
	}
	if event.Authz.Input.SubjectIDHash == "reader-key" {
		t.Fatal("expected subject_id_hash instead of raw principal identifier")
	}
	if event.Authz.Input.ResourceIDHash == "" {
		t.Fatal("expected resource_id_hash in authz input summary")
	}
	if event.Authz.Input.ResourceIDHash == "scan-1" {
		t.Fatal("expected sanitized resource_id_hash instead of raw resource id")
	}
	if event.Authz.PolicySetID != defaultCentralPolicySetID {
		t.Fatalf("expected policy set %q, got %q", defaultCentralPolicySetID, event.Authz.PolicySetID)
	}
}

func TestRouterWritesAuditSinkForDeniedAuthzDecision(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink: sink,
		APIKeyScopes: map[string][]string{
			"read-key": {scopeRead, "tenant:tenant-a", "workspace:workspace-a"},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	req.Header.Set("User-Agent", "router-test-deny")
	req.Header.Set("X-API-Key", "read-key")
	req.Header.Set(scopeHeaderTenantID, "tenant-a")
	req.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected denied request status 403, got %d body=%s", w.Code, w.Body.String())
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected sink to capture denied event")
	}
	event := sink.events[len(sink.events)-1]
	if event.Authz == nil {
		t.Fatal("expected authz decision in denied audit event")
	}
	if event.Authz.Allowed {
		t.Fatalf("expected denied authz decision, got %+v", event.Authz)
	}
	if event.Authz.Input.SubjectIDHash == "read-key" {
		t.Fatal("expected subject_id_hash instead of raw principal identifier")
	}
	if event.Authz.Input.Action != policyActionScansRun {
		t.Fatalf("expected action %q, got %q", policyActionScansRun, event.Authz.Input.Action)
	}
}

func TestRouterWritesAuditSinkForScopedAPIKeyBindingAuthenticationFailure(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink: sink,
		APIKeyScopes: map[string][]string{
			"reader-key":  {scopeRead},
			"unbound-key": {scopeRead},
		},
		APIKeyScopeBindings: map[string]db.Scope{
			"reader-key": {TenantID: "tenant-a", WorkspaceID: "workspace-a"},
		},
	})

	mismatchReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	mismatchReq.Header.Set("X-API-Key", "reader-key")
	mismatchReq.Header.Set(scopeHeaderTenantID, "tenant-b")
	mismatchReq.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	mismatchW := httptest.NewRecorder()
	r.ServeHTTP(mismatchW, mismatchReq)
	if mismatchW.Code != http.StatusUnauthorized {
		t.Fatalf("expected scoped mismatch request to be unauthorized, got %d", mismatchW.Code)
	}

	unboundReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	unboundReq.Header.Set("X-API-Key", "unbound-key")
	unboundW := httptest.NewRecorder()
	r.ServeHTTP(unboundW, unboundReq)
	if unboundW.Code != http.StatusUnauthorized {
		t.Fatalf("expected unbound scoped key request to be unauthorized, got %d", unboundW.Code)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	authFailureCount := countAuditEventsByKind(sink.events, "api_auth_failure")
	if authFailureCount < 2 {
		t.Fatalf("expected at least two auth failure audit events for scoped key failures, got %d events: %+v", authFailureCount, sink.events)
	}

}

func TestRouterScanDiffAndEventsNotFound(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{})
	missingScanID := "11111111-1111-1111-1111-111111111111"

	diffReq := httptest.NewRequest(http.MethodGet, "/v1/scans/"+missingScanID+"/diff", nil)
	diffW := httptest.NewRecorder()
	r.ServeHTTP(diffW, diffReq)
	if diffW.Code != http.StatusNotFound {
		t.Fatalf("expected diff 404 for missing scan, got %d", diffW.Code)
	}

	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/scans/"+missingScanID+"/events", nil)
	eventsW := httptest.NewRecorder()
	r.ServeHTTP(eventsW, eventsReq)
	if eventsW.Code != http.StatusNotFound {
		t.Fatalf("expected events 404 for missing scan, got %d", eventsW.Code)
	}

	identitiesReq := httptest.NewRequest(http.MethodGet, "/v1/identities?scan_id="+missingScanID, nil)
	identitiesW := httptest.NewRecorder()
	r.ServeHTTP(identitiesW, identitiesReq)
	if identitiesW.Code != http.StatusNotFound {
		t.Fatalf("expected identities 404 for missing scan, got %d", identitiesW.Code)
	}

	relationshipsReq := httptest.NewRequest(http.MethodGet, "/v1/relationships?scan_id="+missingScanID, nil)
	relationshipsW := httptest.NewRecorder()
	r.ServeHTTP(relationshipsW, relationshipsReq)
	if relationshipsW.Code != http.StatusNotFound {
		t.Fatalf("expected relationships 404 for missing scan, got %d", relationshipsW.Code)
	}

	findingsReq := httptest.NewRequest(http.MethodGet, "/v1/findings?scan_id="+missingScanID, nil)
	findingsW := httptest.NewRecorder()
	r.ServeHTTP(findingsW, findingsReq)
	if findingsW.Code != http.StatusNotFound {
		t.Fatalf("expected findings 404 for missing scan, got %d", findingsW.Code)
	}

	findingReq := httptest.NewRequest(http.MethodGet, "/v1/findings/missing", nil)
	findingW := httptest.NewRecorder()
	r.ServeHTTP(findingW, findingReq)
	if findingW.Code != http.StatusNotFound {
		t.Fatalf("expected finding-by-id 404 for missing finding, got %d", findingW.Code)
	}

	scan, err := store.CreateScan(defaultScopeContext(), "aws", time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	invalidBaselineReq := httptest.NewRequest(
		http.MethodGet,
		"/v1/scans/"+scan.ID+"/diff?previous_scan_id="+scan.ID,
		nil,
	)
	invalidBaselineW := httptest.NewRecorder()
	r.ServeHTTP(invalidBaselineW, invalidBaselineReq)
	if invalidBaselineW.Code != http.StatusBadRequest {
		t.Fatalf("expected diff 400 for invalid baseline scan, got %d", invalidBaselineW.Code)
	}
}

func TestRouterRejectsInvalidScanUUIDInputs(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	cases := []string{
		"/v1/scans/not-a-uuid/diff",
		"/v1/scans/not-a-uuid/events",
		"/v1/findings?scan_id=not-a-uuid",
		"/v1/findings/f1?scan_id=not-a-uuid",
		"/v1/findings/f1/history?scan_id=not-a-uuid",
		"/v1/findings/f1/exports?scan_id=not-a-uuid",
		"/v1/identities?scan_id=not-a-uuid",
		"/v1/relationships?scan_id=not-a-uuid",
		"/v1/ownership/signals?scan_id=not-a-uuid",
	}
	for _, path := range cases {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid scan_id on %s, got %d", path, w.Code)
		}
	}

	triageReq := httptest.NewRequest(http.MethodPatch, "/v1/findings/f1/triage?scan_id=not-a-uuid", bytes.NewBufferString(`{"status":"ack"}`))
	triageW := httptest.NewRecorder()
	r.ServeHTTP(triageW, triageReq)
	if triageW.Code != http.StatusBadRequest {
		t.Fatalf("expected triage 400 for invalid scan_id, got %d", triageW.Code)
	}
}

func TestRouterRejectsInvalidRepoScanUUIDInputs(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	repoScanReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans/not-a-uuid", nil)
	repoScanW := httptest.NewRecorder()
	r.ServeHTTP(repoScanW, repoScanReq)
	if repoScanW.Code != http.StatusBadRequest {
		t.Fatalf("expected repo scan detail 400 for invalid repo_scan_id, got %d", repoScanW.Code)
	}

	repoFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/repo-findings?repo_scan_id=not-a-uuid", nil)
	repoFindingsW := httptest.NewRecorder()
	r.ServeHTTP(repoFindingsW, repoFindingsReq)
	if repoFindingsW.Code != http.StatusBadRequest {
		t.Fatalf("expected repo findings 400 for invalid repo_scan_id filter, got %d", repoFindingsW.Code)
	}
}

func TestRouterErrorEnvelopeForCommonStatuses(t *testing.T) {
	assertErrorEnvelope := func(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int) {
		t.Helper()
		if w.Code != expectedStatus {
			t.Fatalf("expected status %d, got %d body=%s", expectedStatus, w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode error envelope: %v body=%s", err, w.Body.String())
		}
		raw, ok := body["error"]
		if !ok {
			t.Fatalf("expected error field in envelope, got %+v", body)
		}
		message, ok := raw.(string)
		if !ok || strings.TrimSpace(message) == "" {
			t.Fatalf("expected non-empty error string, got %+v", body)
		}
	}

	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()

	noServiceRouter := NewRouter(logger, metrics, nil, RouterOptions{})
	noServiceReq := httptest.NewRequest(http.MethodGet, "/v1/workspaces", nil)
	noServiceW := httptest.NewRecorder()
	noServiceRouter.ServeHTTP(noServiceW, noServiceReq)
	assertErrorEnvelope(t, noServiceW, http.StatusServiceUnavailable)

	authSvc := NewService(db.NewMemoryStore(), routerScanner{}, "aws")
	authRouter := NewRouter(logger, metrics, authSvc, RouterOptions{
		APIKeys:            []string{"read-key"},
		WriteAPIKeys:       []string{"write-key"},
		APIKeyScopes:       map[string][]string{"read-key": {scopeRead}, "write-key": {scopeRead, scopeWrite}},
		RateLimitRPM:       10000,
		RateLimitBurst:     1000,
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})
	unauthorizedReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	unauthorizedW := httptest.NewRecorder()
	authRouter.ServeHTTP(unauthorizedW, unauthorizedReq)
	assertErrorEnvelope(t, unauthorizedW, http.StatusUnauthorized)

	forbiddenReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	forbiddenReq.Header.Set("X-API-Key", "read-key")
	forbiddenW := httptest.NewRecorder()
	authRouter.ServeHTTP(forbiddenW, forbiddenReq)
	assertErrorEnvelope(t, forbiddenW, http.StatusForbidden)

	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.ScanQueueMaxPending = 1
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	securedRouter := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"write-key"},
		WriteAPIKeys: []string{"write-key"},
		APIKeyScopes: map[string][]string{"write-key": {scopeRead, scopeWrite}},
	})

	notFoundReq := httptest.NewRequest(http.MethodGet, "/v1/findings?scan_id=00000000-0000-0000-0000-000000000000", nil)
	notFoundReq.Header.Set("X-API-Key", "write-key")
	notFoundW := httptest.NewRecorder()
	securedRouter.ServeHTTP(notFoundW, notFoundReq)
	assertErrorEnvelope(t, notFoundW, http.StatusNotFound)

	badRequestReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans/not-a-uuid", nil)
	badRequestReq.Header.Set("X-API-Key", "write-key")
	badRequestW := httptest.NewRecorder()
	securedRouter.ServeHTTP(badRequestW, badRequestReq)
	assertErrorEnvelope(t, badRequestW, http.StatusBadRequest)

	firstRepoReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	firstRepoReq.Header.Set("X-API-Key", "write-key")
	firstRepoReq.Header.Set("Content-Type", "application/json")
	firstRepoW := httptest.NewRecorder()
	securedRouter.ServeHTTP(firstRepoW, firstRepoReq)
	if firstRepoW.Code != http.StatusAccepted {
		t.Fatalf("expected first repo scan enqueue 202, got %d body=%s", firstRepoW.Code, firstRepoW.Body.String())
	}

	conflictReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	conflictReq.Header.Set("X-API-Key", "write-key")
	conflictReq.Header.Set("Content-Type", "application/json")
	conflictW := httptest.NewRecorder()
	securedRouter.ServeHTTP(conflictW, conflictReq)
	assertErrorEnvelope(t, conflictW, http.StatusConflict)

	firstScanReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	firstScanReq.Header.Set("X-API-Key", "write-key")
	firstScanW := httptest.NewRecorder()
	securedRouter.ServeHTTP(firstScanW, firstScanReq)
	if firstScanW.Code != http.StatusAccepted {
		t.Fatalf("expected first scan enqueue 202, got %d body=%s", firstScanW.Code, firstScanW.Body.String())
	}

	queueFullReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	queueFullReq.Header.Set("X-API-Key", "write-key")
	queueFullW := httptest.NewRecorder()
	securedRouter.ServeHTTP(queueFullW, queueFullReq)
	assertErrorEnvelope(t, queueFullW, http.StatusConflict)
}

func TestRouterPaginationHelpers(t *testing.T) {
	if got := parseCursor(""); got != 0 {
		t.Fatalf("expected empty cursor to parse as 0, got %d", got)
	}
	if got := parseCursor("bad"); got != 0 {
		t.Fatalf("expected invalid cursor to parse as 0, got %d", got)
	}
	if got := parseCursor("12"); got != 12 {
		t.Fatalf("expected cursor 12, got %d", got)
	}
	items := []int{1, 2, 3}
	page, next := pageWithCursor(items, 0, 2)
	if len(page) != 2 || next != "2" {
		t.Fatalf("unexpected page result page=%+v next=%q", page, next)
	}
	page, next = pageWithCursor(items, 2, 2)
	if len(page) != 1 || next != "" {
		t.Fatalf("unexpected final page result page=%+v next=%q", page, next)
	}
}

func TestRouterTenancyRoutesUnavailableWithoutService(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{RateLimitRPM: 1000, RateLimitBurst: 1000})

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/whoami"},
		{http.MethodGet, "/v1/organizations/current"},
		{http.MethodPut, "/v1/organizations/current"},
		{http.MethodGet, "/v1/workspaces"},
		{http.MethodPost, "/v1/workspaces"},
		{http.MethodPost, "/v1/workspaces/active"},
		{http.MethodGet, "/v1/workspaces/ws-1"},
		{http.MethodDelete, "/v1/workspaces/ws-1"},
		{http.MethodGet, "/v1/workspaces/ws-1/members"},
		{http.MethodPost, "/v1/workspaces/ws-1/members"},
		{http.MethodGet, "/v1/workspaces/ws-1/members/m-1"},
		{http.MethodDelete, "/v1/workspaces/ws-1/members/m-1"},
		{http.MethodGet, "/v1/workspaces/ws-1/projects"},
		{http.MethodPost, "/v1/workspaces/ws-1/projects"},
		{http.MethodGet, "/v1/workspaces/ws-1/projects/p-1"},
		{http.MethodDelete, "/v1/workspaces/ws-1/projects/p-1"},
		{http.MethodPost, "/v1/workspaces/ws-1/projects/p-1/aws/connection"},
		{http.MethodGet, "/v1/workspaces/ws-1/projects/p-1/aws/connection"},
		{http.MethodPost, "/v1/workspaces/ws-1/projects/p-1/github/connect/start"},
		{http.MethodPost, "/v1/workspaces/ws-1/projects/p-1/github/connect/complete"},
		{http.MethodGet, "/v1/workspaces/ws-1/projects/p-1/github/connection"},
		{http.MethodPut, "/v1/workspaces/ws-1/projects/p-1/github/repositories"},
		{http.MethodPost, "/v1/workspaces/ws-1/projects/p-1/github/secret/rotate"},
	}

	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: expected 503 without service, got %d", rt.method, rt.path, w.Code)
		}
	}
}

func TestRouterTenancyEndpointsCRUDFlow(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doRequest := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	orgResp := doRequest(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	if orgResp.Code != http.StatusOK {
		t.Fatalf("expected organization upsert 200, got %d body=%s", orgResp.Code, orgResp.Body.String())
	}

	workspaceResp := doRequest(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	if workspaceResp.Code != http.StatusOK {
		t.Fatalf("expected workspace upsert 200, got %d body=%s", workspaceResp.Code, workspaceResp.Body.String())
	}

	memberResp := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/members", `{"member_id":"member-1","user_id":"user-1","email":"user1@example.com","role":"admin","status":"active"}`)
	if memberResp.Code != http.StatusOK {
		t.Fatalf("expected member upsert 200, got %d body=%s", memberResp.Code, memberResp.Body.String())
	}

	listMembersResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/members?role=admin&status=active", "")
	if listMembersResp.Code != http.StatusOK {
		t.Fatalf("expected member list 200, got %d body=%s", listMembersResp.Code, listMembersResp.Body.String())
	}
	var membersBody struct {
		Items []db.TenancyWorkspaceMember `json:"items"`
	}
	if err := json.Unmarshal(listMembersResp.Body.Bytes(), &membersBody); err != nil {
		t.Fatalf("decode members response: %v", err)
	}
	if len(membersBody.Items) != 1 || membersBody.Items[0].MemberID != "member-1" {
		t.Fatalf("unexpected members payload: %+v", membersBody.Items)
	}

	projectResp := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1","description":"First project"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("expected project upsert 200, got %d body=%s", projectResp.Code, projectResp.Body.String())
	}

	projectDetailResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1", "")
	if projectDetailResp.Code != http.StatusOK {
		t.Fatalf("expected project get 200, got %d body=%s", projectDetailResp.Code, projectDetailResp.Body.String())
	}

	listProjectsResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/projects?include_archived=true", "")
	if listProjectsResp.Code != http.StatusOK {
		t.Fatalf("expected project list 200, got %d body=%s", listProjectsResp.Code, listProjectsResp.Body.String())
	}
	var projectsBody struct {
		Items []db.TenancyProject `json:"items"`
	}
	if err := json.Unmarshal(listProjectsResp.Body.Bytes(), &projectsBody); err != nil {
		t.Fatalf("decode projects response: %v", err)
	}
	if len(projectsBody.Items) != 1 || projectsBody.Items[0].ProjectID != "project-1" {
		t.Fatalf("unexpected projects payload: %+v", projectsBody.Items)
	}

	orgGetResp := doRequest(http.MethodGet, "/v1/organizations/current", "")
	if orgGetResp.Code != http.StatusOK {
		t.Fatalf("expected organization get 200, got %d body=%s", orgGetResp.Code, orgGetResp.Body.String())
	}

	workspaceGetResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a", "")
	if workspaceGetResp.Code != http.StatusOK {
		t.Fatalf("expected workspace get 200, got %d body=%s", workspaceGetResp.Code, workspaceGetResp.Body.String())
	}

	listWorkspacesResp := doRequest(http.MethodGet, "/v1/workspaces?sort_by=display_name&sort_order=desc", "")
	if listWorkspacesResp.Code != http.StatusOK {
		t.Fatalf("expected workspace list 200, got %d body=%s", listWorkspacesResp.Code, listWorkspacesResp.Body.String())
	}

	memberGetResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/members/member-1", "")
	if memberGetResp.Code != http.StatusOK {
		t.Fatalf("expected member get 200, got %d body=%s", memberGetResp.Code, memberGetResp.Body.String())
	}

	deleteProjectResp := doRequest(http.MethodDelete, "/v1/workspaces/workspace-a/projects/project-1", "")
	if deleteProjectResp.Code != http.StatusNoContent {
		t.Fatalf("expected project delete 204, got %d body=%s", deleteProjectResp.Code, deleteProjectResp.Body.String())
	}

	deleteMemberResp := doRequest(http.MethodDelete, "/v1/workspaces/workspace-a/members/member-1", "")
	if deleteMemberResp.Code != http.StatusNoContent {
		t.Fatalf("expected member delete 204, got %d body=%s", deleteMemberResp.Code, deleteMemberResp.Body.String())
	}

	deleteWorkspaceResp := doRequest(http.MethodDelete, "/v1/workspaces/workspace-a", "")
	if deleteWorkspaceResp.Code != http.StatusNoContent {
		t.Fatalf("expected workspace delete 204, got %d body=%s", deleteWorkspaceResp.Code, deleteWorkspaceResp.Body.String())
	}

	notFoundResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a", "")
	if notFoundResp.Code != http.StatusNotFound {
		t.Fatalf("expected workspace get 404 after delete, got %d", notFoundResp.Code)
	}
}

func TestRouterGitHubConnectionAndWebhookFlow(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doAPI := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if resp := doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`); resp.Code != http.StatusOK {
		t.Fatalf("seed organization failed %d body=%s", resp.Code, resp.Body.String())
	}
	if resp := doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`); resp.Code != http.StatusOK {
		t.Fatalf("seed workspace failed %d body=%s", resp.Code, resp.Body.String())
	}
	if resp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`); resp.Code != http.StatusOK {
		t.Fatalf("seed project failed %d body=%s", resp.Code, resp.Body.String())
	}

	startResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/start", `{}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("start github connection expected 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody struct {
		Connection GitHubConnectionStartResponse `json:"connection"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if strings.TrimSpace(startBody.Connection.State) == "" || !strings.Contains(startBody.Connection.ConnectURL, "github.com/apps/") {
		t.Fatalf("unexpected start response: %+v", startBody.Connection)
	}

	completePayload := struct {
		State                  string   `json:"state"`
		InstallationID         int64    `json:"installation_id"`
		AccountLogin           string   `json:"account_login"`
		TokenReference         string   `json:"token_reference"`
		WebhookSecret          string   `json:"webhook_secret"`
		WebhookSecretReference string   `json:"webhook_secret_reference"`
		SelectedRepositories   []string `json:"selected_repositories"`
	}{
		State:                  startBody.Connection.State,
		InstallationID:         123456,
		AccountLogin:           "identrail",
		TokenReference:         "vault://github/token/project-1",
		WebhookSecret:          "super-secret-webhook-key",
		WebhookSecretReference: "vault://github/webhook/project-1",
		SelectedRepositories:   []string{"owner/repo"},
	}
	completeJSON, _ := json.Marshal(completePayload)
	completeResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete", string(completeJSON))
	if completeResp.Code != http.StatusOK {
		t.Fatalf("complete github connection expected 200, got %d body=%s", completeResp.Code, completeResp.Body.String())
	}

	reposResp := doAPI(http.MethodPut, "/v1/workspaces/workspace-a/projects/project-1/github/repositories", `{"repositories":["owner/repo","owner/repo-two"]}`)
	if reposResp.Code != http.StatusOK {
		t.Fatalf("update github repositories expected 200, got %d body=%s", reposResp.Code, reposResp.Body.String())
	}

	statusResp := doAPI(http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/github/connection", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("get github connection expected 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Connection GitHubConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !statusBody.Connection.Connected || len(statusBody.Connection.SelectedRepositories) != 2 {
		t.Fatalf("unexpected github connection status: %+v", statusBody.Connection)
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":123456}}`)
	webhookReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(webhookPayload))
	webhookReq.Header.Set("X-GitHub-Event", "push")
	webhookReq.Header.Set("X-GitHub-Delivery", "delivery-1")
	webhookReq.Header.Set("X-Hub-Signature-256", githubWebhookSignature("super-secret-webhook-key", webhookPayload))
	webhookResp := httptest.NewRecorder()
	r.ServeHTTP(webhookResp, webhookReq)
	if webhookResp.Code != http.StatusAccepted {
		t.Fatalf("github webhook expected 202, got %d body=%s", webhookResp.Code, webhookResp.Body.String())
	}
	var webhookBody struct {
		Webhook GitHubWebhookResult `json:"webhook"`
	}
	if err := json.Unmarshal(webhookResp.Body.Bytes(), &webhookBody); err != nil {
		t.Fatalf("decode webhook response: %v", err)
	}
	if webhookBody.Webhook.MatchedProjects != 1 || webhookBody.Webhook.QueuedScans != 1 {
		t.Fatalf("unexpected webhook result: %+v", webhookBody.Webhook)
	}

	repoScansResp := doAPI(http.MethodGet, "/v1/repo-scans", "")
	if repoScansResp.Code != http.StatusOK {
		t.Fatalf("list repo scans expected 200, got %d body=%s", repoScansResp.Code, repoScansResp.Body.String())
	}
	var scansBody struct {
		Items []db.RepoScanRecord `json:"items"`
	}
	if err := json.Unmarshal(repoScansResp.Body.Bytes(), &scansBody); err != nil {
		t.Fatalf("decode repo scans response: %v", err)
	}
	if len(scansBody.Items) == 0 || scansBody.Items[0].Repository != "owner/repo" {
		t.Fatalf("expected queued repo scan for owner/repo, got %+v", scansBody.Items)
	}
}

func TestRouterGitHubWebhookRejectsInvalidSignature(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	doAPI := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "writer-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	_ = doAPI(http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	_ = doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	startResp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/start", `{}`)
	var startBody struct {
		Connection GitHubConnectionStartResponse `json:"connection"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	completeJSON := `{"state":"` + startBody.Connection.State + `","installation_id":42,"account_login":"identrail","token_reference":"vault://token","webhook_secret":"right-secret","webhook_secret_reference":"vault://secret","selected_repositories":["owner/repo"]}`
	if resp := doAPI(http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/github/connect/complete", completeJSON); resp.Code != http.StatusOK {
		t.Fatalf("complete connection expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	webhookPayload := []byte(`{"repository":{"full_name":"owner/repo"},"installation":{"id":42}}`)
	webhookReq := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(webhookPayload))
	webhookReq.Header.Set("X-GitHub-Event", "push")
	webhookReq.Header.Set("X-Hub-Signature-256", githubWebhookSignature("wrong-secret", webhookPayload))
	webhookResp := httptest.NewRecorder()
	r.ServeHTTP(webhookResp, webhookReq)
	if webhookResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected webhook 401 for invalid signature, got %d body=%s", webhookResp.Code, webhookResp.Body.String())
	}
}

func TestRouterWhoAmIAndActiveWorkspaceContext(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.UpsertOrganization(scopeCtx, db.TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopeCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("seed workspace-a: %v", err)
	}
	workspaceBCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-b"})
	if err := store.UpsertWorkspace(workspaceBCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-b",
		DisplayName: "Workspace B",
		Slug:        "workspace-b",
	}); err != nil {
		t.Fatalf("seed workspace-b: %v", err)
	}

	workspaceACtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertWorkspaceMember(workspaceACtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "user-1",
		Email:       "user1@example.com",
		Role:        "admin",
		Status:      "active",
	}); err != nil {
		t.Fatalf("seed workspace-a member: %v", err)
	}
	if err := store.UpsertWorkspaceMember(workspaceBCtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-b",
		MemberID:    "member-b",
		UserID:      "user-1",
		Email:       "user1@example.com",
		Role:        "viewer",
		Status:      "active",
	}); err != nil {
		t.Fatalf("seed workspace-b member: %v", err)
	}
	if err := store.UpsertWorkspaceMember(workspaceACtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		MemberID:    "member-outsider",
		UserID:      "user-2",
		Email:       "user2@example.com",
		Role:        "viewer",
		Status:      "removed",
	}); err != nil {
		t.Fatalf("seed outsider member: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"user-1-token": {
					Subject:     "user-1",
					TenantID:    "tenant-a",
					WorkspaceID: "workspace-a",
					Roles:       []string{"analyst"},
					Scopes:      []string{"identrail.read"},
				},
				"user-2-token": {
					Subject:     "user-2",
					TenantID:    "tenant-a",
					WorkspaceID: "workspace-a",
					Roles:       []string{"viewer"},
					Scopes:      []string{"identrail.read"},
				},
			},
		},
	})

	whoamiReq := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	whoamiReq.Header.Set("Authorization", "Bearer user-1-token")
	whoamiResp := httptest.NewRecorder()
	r.ServeHTTP(whoamiResp, whoamiReq)
	if whoamiResp.Code != http.StatusOK {
		t.Fatalf("expected whoami 200, got %d body=%s", whoamiResp.Code, whoamiResp.Body.String())
	}
	var whoamiBody struct {
		Principal struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"principal"`
		Roles  []string `json:"roles"`
		Scopes []string `json:"scopes"`
		Scope  struct {
			TenantID    string `json:"tenant_id"`
			WorkspaceID string `json:"workspace_id"`
		} `json:"scope"`
		ActiveWorkspace *WorkspaceContext  `json:"active_workspace"`
		Workspaces      []WorkspaceContext `json:"workspaces"`
	}
	if err := json.Unmarshal(whoamiResp.Body.Bytes(), &whoamiBody); err != nil {
		t.Fatalf("decode whoami response: %v", err)
	}
	if whoamiBody.Principal.Type != "subject" || whoamiBody.Principal.ID != "user-1" {
		t.Fatalf("unexpected principal payload: %+v", whoamiBody.Principal)
	}
	if len(whoamiBody.Roles) != 1 || whoamiBody.Roles[0] != "analyst" {
		t.Fatalf("unexpected roles payload: %+v", whoamiBody.Roles)
	}
	if len(whoamiBody.Scopes) != 1 || whoamiBody.Scopes[0] != "read" {
		t.Fatalf("unexpected scopes payload: %+v", whoamiBody.Scopes)
	}
	if whoamiBody.Scope.TenantID != "tenant-a" || whoamiBody.Scope.WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected scope payload: %+v", whoamiBody.Scope)
	}
	if whoamiBody.ActiveWorkspace == nil || whoamiBody.ActiveWorkspace.Workspace.WorkspaceID != "workspace-a" {
		t.Fatalf("expected active workspace-a, got %+v", whoamiBody.ActiveWorkspace)
	}
	if whoamiBody.ActiveWorkspace.Member == nil || whoamiBody.ActiveWorkspace.Member.Role != "admin" {
		t.Fatalf("expected active workspace member role admin, got %+v", whoamiBody.ActiveWorkspace.Member)
	}
	if len(whoamiBody.Workspaces) != 2 {
		t.Fatalf("expected two workspace contexts, got %d", len(whoamiBody.Workspaces))
	}

	switchReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces/active", bytes.NewBufferString(`{"workspace_id":"workspace-b"}`))
	switchReq.Header.Set("Authorization", "Bearer user-1-token")
	switchReq.Header.Set("Content-Type", "application/json")
	switchResp := httptest.NewRecorder()
	r.ServeHTTP(switchResp, switchReq)
	if switchResp.Code != http.StatusOK {
		t.Fatalf("expected active switch 200, got %d body=%s", switchResp.Code, switchResp.Body.String())
	}
	var switchBody struct {
		ActiveWorkspace WorkspaceContext `json:"active_workspace"`
		Scope           struct {
			TenantID    string `json:"tenant_id"`
			WorkspaceID string `json:"workspace_id"`
		} `json:"scope"`
		ScopeHeaders map[string]string `json:"scope_headers"`
	}
	if err := json.Unmarshal(switchResp.Body.Bytes(), &switchBody); err != nil {
		t.Fatalf("decode switch response: %v", err)
	}
	if switchBody.ActiveWorkspace.Workspace.WorkspaceID != "workspace-b" {
		t.Fatalf("expected switched workspace-b, got %+v", switchBody.ActiveWorkspace.Workspace)
	}
	if switchBody.ActiveWorkspace.Member == nil || switchBody.ActiveWorkspace.Member.Role != "viewer" {
		t.Fatalf("expected switched role viewer, got %+v", switchBody.ActiveWorkspace.Member)
	}
	if switchBody.Scope.WorkspaceID != "workspace-b" {
		t.Fatalf("expected switched scope workspace-b, got %+v", switchBody.Scope)
	}
	if switchBody.ScopeHeaders[scopeHeaderWorkspaceID] != "workspace-b" {
		t.Fatalf("expected workspace scope header workspace-b, got %+v", switchBody.ScopeHeaders)
	}

	switchBadBodyReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces/active", bytes.NewBufferString(`{"workspace_id":""}`))
	switchBadBodyReq.Header.Set("Authorization", "Bearer user-1-token")
	switchBadBodyReq.Header.Set("Content-Type", "application/json")
	switchBadBodyResp := httptest.NewRecorder()
	r.ServeHTTP(switchBadBodyResp, switchBadBodyReq)
	if switchBadBodyResp.Code != http.StatusBadRequest {
		t.Fatalf("expected active switch bad request 400, got %d body=%s", switchBadBodyResp.Code, switchBadBodyResp.Body.String())
	}

	switchMissingReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces/active", bytes.NewBufferString(`{"workspace_id":"workspace-missing"}`))
	switchMissingReq.Header.Set("Authorization", "Bearer user-1-token")
	switchMissingReq.Header.Set("Content-Type", "application/json")
	switchMissingResp := httptest.NewRecorder()
	r.ServeHTTP(switchMissingResp, switchMissingReq)
	if switchMissingResp.Code != http.StatusNotFound {
		t.Fatalf("expected active switch missing workspace 404, got %d body=%s", switchMissingResp.Code, switchMissingResp.Body.String())
	}

	switchDeniedReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces/active", bytes.NewBufferString(`{"workspace_id":"workspace-b"}`))
	switchDeniedReq.Header.Set("Authorization", "Bearer user-2-token")
	switchDeniedReq.Header.Set("Content-Type", "application/json")
	switchDeniedResp := httptest.NewRecorder()
	r.ServeHTTP(switchDeniedResp, switchDeniedReq)
	if switchDeniedResp.Code != http.StatusForbidden {
		t.Fatalf("expected active switch forbidden 403, got %d body=%s", switchDeniedResp.Code, switchDeniedResp.Body.String())
	}
}

func TestSortWorkspaces(t *testing.T) {
	now := time.Now()
	items := []db.TenancyWorkspace{
		{WorkspaceID: "ws-b", DisplayName: "Beta", Slug: "beta", CreatedAt: now},
		{WorkspaceID: "ws-a", DisplayName: "Alpha", Slug: "alpha", CreatedAt: now.Add(-time.Hour)},
		{WorkspaceID: "ws-c", DisplayName: "Charlie", Slug: "charlie", CreatedAt: now.Add(time.Hour)},
	}

	sortWorkspaces(items, "slug", false)
	if items[0].Slug != "alpha" || items[1].Slug != "beta" || items[2].Slug != "charlie" {
		t.Fatalf("expected ascending slug sort, got %v %v %v", items[0].Slug, items[1].Slug, items[2].Slug)
	}

	sortWorkspaces(items, "display_name", true)
	if items[0].DisplayName != "Charlie" || items[2].DisplayName != "Alpha" {
		t.Fatalf("expected descending display_name sort, got %v %v %v", items[0].DisplayName, items[1].DisplayName, items[2].DisplayName)
	}

	sortWorkspaces(items, "workspace_id", false)
	if items[0].WorkspaceID != "ws-a" || items[2].WorkspaceID != "ws-c" {
		t.Fatalf("expected ascending workspace_id sort, got %v %v %v", items[0].WorkspaceID, items[1].WorkspaceID, items[2].WorkspaceID)
	}

	sortWorkspaces(items, "created_at", false)
	if !items[0].CreatedAt.Before(items[1].CreatedAt) {
		t.Fatalf("expected ascending created_at sort")
	}
}

func TestSortProjects(t *testing.T) {
	now := time.Now()
	items := []db.TenancyProject{
		{ProjectID: "p-b", Name: "Bravo", Slug: "bravo", CreatedAt: now, UpdatedAt: now},
		{ProjectID: "p-a", Name: "Alpha", Slug: "alpha", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(time.Hour)},
		{ProjectID: "p-c", Name: "Charlie", Slug: "charlie", CreatedAt: now.Add(time.Hour), UpdatedAt: now.Add(-time.Hour)},
	}

	sortProjects(items, "name", false)
	if items[0].Name != "Alpha" || items[1].Name != "Bravo" || items[2].Name != "Charlie" {
		t.Fatalf("expected ascending name sort, got %v %v %v", items[0].Name, items[1].Name, items[2].Name)
	}

	sortProjects(items, "name", true)
	if items[0].Name != "Charlie" || items[2].Name != "Alpha" {
		t.Fatalf("expected descending name sort, got %v %v %v", items[0].Name, items[1].Name, items[2].Name)
	}

	sortProjects(items, "slug", false)
	if items[0].Slug != "alpha" || items[2].Slug != "charlie" {
		t.Fatalf("expected ascending slug sort, got %v %v %v", items[0].Slug, items[1].Slug, items[2].Slug)
	}

	sortProjects(items, "project_id", false)
	if items[0].ProjectID != "p-a" || items[2].ProjectID != "p-c" {
		t.Fatalf("expected ascending project_id sort, got %v %v %v", items[0].ProjectID, items[1].ProjectID, items[2].ProjectID)
	}

	sortProjects(items, "updated_at", false)
	if !items[0].UpdatedAt.Before(items[1].UpdatedAt) {
		t.Fatalf("expected ascending updated_at sort")
	}

	sortProjects(items, "created_at", false)
	if !items[0].CreatedAt.Before(items[1].CreatedAt) {
		t.Fatalf("expected ascending created_at sort (default)")
	}
}

func TestSortWorkspaceMembers(t *testing.T) {
	now := time.Now()
	items := []db.TenancyWorkspaceMember{
		{MemberID: "m-c", JoinedAt: now.Add(time.Hour)},
		{MemberID: "m-a", JoinedAt: now.Add(-time.Hour)},
		{MemberID: "m-b", JoinedAt: now},
	}

	sortWorkspaceMembers(items)
	if items[0].MemberID != "m-a" || items[1].MemberID != "m-b" || items[2].MemberID != "m-c" {
		t.Fatalf("expected members sorted by joined_at asc, got %v %v %v", items[0].MemberID, items[1].MemberID, items[2].MemberID)
	}
}

func TestRouterTenancyInvalidRoleStatus(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"key"},
		WriteAPIKeys:       []string{"key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/ws/members?role=invalid_role", nil)
	req.Header.Set("X-API-Key", "key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid role, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/workspaces/ws/members?status=bogus", nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid status, got %d", w.Code)
	}
}

func TestRouterTenancyErrorPaths(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"key"},
		WriteAPIKeys:       []string{"key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
		RateLimitRPM:       10000,
		RateLimitBurst:     10000,
	})

	doRequest := func(method string, path string, body string) *httptest.ResponseRecorder {
		var requestBody *bytes.Buffer
		if body == "" {
			requestBody = bytes.NewBuffer(nil)
		} else {
			requestBody = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, requestBody)
		req.Header.Set("X-API-Key", "key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	orgBadBody := doRequest(http.MethodPut, "/v1/organizations/current", `{invalid json`)
	if orgBadBody.Code != http.StatusBadRequest {
		t.Fatalf("expected org bad body 400, got %d", orgBadBody.Code)
	}

	wsBadBody := doRequest(http.MethodPost, "/v1/workspaces", `{invalid`)
	if wsBadBody.Code != http.StatusBadRequest {
		t.Fatalf("expected workspace bad body 400, got %d", wsBadBody.Code)
	}

	memberBadBody := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/members", `{invalid`)
	if memberBadBody.Code != http.StatusBadRequest {
		t.Fatalf("expected member bad body 400, got %d", memberBadBody.Code)
	}

	projectBadBody := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{invalid`)
	if projectBadBody.Code != http.StatusBadRequest {
		t.Fatalf("expected project bad body 400, got %d", projectBadBody.Code)
	}

	orgNotFound := doRequest(http.MethodGet, "/v1/organizations/current", "")
	if orgNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected org not found 404, got %d", orgNotFound.Code)
	}

	wsNotFound := doRequest(http.MethodGet, "/v1/workspaces/nonexistent", "")
	if wsNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected workspace not found 404, got %d", wsNotFound.Code)
	}

	wsDeleteNotFound := doRequest(http.MethodDelete, "/v1/workspaces/nonexistent", "")
	if wsDeleteNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected workspace delete not found 404, got %d", wsDeleteNotFound.Code)
	}

	memberNotFound := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/members/nonexistent", "")
	if memberNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected member not found 404, got %d", memberNotFound.Code)
	}

	memberDeleteNotFound := doRequest(http.MethodDelete, "/v1/workspaces/workspace-a/members/nonexistent", "")
	if memberDeleteNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected member delete not found 404, got %d", memberDeleteNotFound.Code)
	}

	projectNotFound := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/projects/nonexistent", "")
	if projectNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected project not found 404, got %d", projectNotFound.Code)
	}

	projectDeleteNotFound := doRequest(http.MethodDelete, "/v1/workspaces/workspace-a/projects/nonexistent", "")
	if projectDeleteNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected project delete not found 404, got %d", projectDeleteNotFound.Code)
	}

	listWorkspacesResp := doRequest(http.MethodGet, "/v1/workspaces", "")
	if listWorkspacesResp.Code != http.StatusOK {
		t.Fatalf("expected workspace list 200, got %d", listWorkspacesResp.Code)
	}

	listMembersResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/members", "")
	if listMembersResp.Code != http.StatusOK {
		t.Fatalf("expected members list 200, got %d", listMembersResp.Code)
	}

	listProjectsResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/projects", "")
	if listProjectsResp.Code != http.StatusOK {
		t.Fatalf("expected projects list 200, got %d", listProjectsResp.Code)
	}

	badArchivedResp := doRequest(http.MethodGet, "/v1/workspaces/workspace-a/projects?include_archived=notbool", "")
	if badArchivedResp.Code != http.StatusBadRequest {
		t.Fatalf("expected bad include_archived 400, got %d", badArchivedResp.Code)
	}

	orgInvalidSlug := doRequest(http.MethodPut, "/v1/organizations/current", `{"display_name":"","slug":""}`)
	if orgInvalidSlug.Code != http.StatusBadRequest {
		t.Fatalf("expected org invalid data 400, got %d body=%s", orgInvalidSlug.Code, orgInvalidSlug.Body.String())
	}

	doRequest(http.MethodPut, "/v1/organizations/current", `{"display_name":"Org","slug":"org"}`)

	wsInvalidSlug := doRequest(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"","slug":""}`)
	if wsInvalidSlug.Code != http.StatusBadRequest {
		t.Fatalf("expected workspace invalid data 400, got %d body=%s", wsInvalidSlug.Code, wsInvalidSlug.Body.String())
	}

	doRequest(http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"WS","slug":"ws-a"}`)

	memberInvalid := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/members", `{"member_id":"","user_id":"","email":"","role":"","status":""}`)
	if memberInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected member invalid data 400, got %d body=%s", memberInvalid.Code, memberInvalid.Body.String())
	}

	projectInvalid := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"","name":"","slug":""}`)
	if projectInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected project invalid data 400, got %d body=%s", projectInvalid.Code, projectInvalid.Body.String())
	}

	wsMismatch := doRequest(http.MethodPost, "/v1/workspaces", `{"workspace_id":"other-ws","display_name":"Other","slug":"other"}`)
	if wsMismatch.Code != http.StatusNotFound {
		t.Fatalf("expected workspace scope mismatch 404, got %d body=%s", wsMismatch.Code, wsMismatch.Body.String())
	}

	memberWsMismatch := doRequest(http.MethodPost, "/v1/workspaces/other-ws/members", `{"member_id":"m-1","user_id":"u-1","email":"a@b.com","role":"admin","status":"active"}`)
	if memberWsMismatch.Code != http.StatusNotFound {
		t.Fatalf("expected member workspace mismatch 404, got %d body=%s", memberWsMismatch.Code, memberWsMismatch.Body.String())
	}

	projectWsMismatch := doRequest(http.MethodPost, "/v1/workspaces/other-ws/projects", `{"project_id":"p-1","name":"P","slug":"p"}`)
	if projectWsMismatch.Code != http.StatusNotFound {
		t.Fatalf("expected project workspace mismatch 404, got %d body=%s", projectWsMismatch.Code, projectWsMismatch.Body.String())
	}

	projectWithArchived := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"p-arch","name":"Archived","slug":"arch","archived_at":"2025-01-01T00:00:00Z"}`)
	if projectWithArchived.Code != http.StatusOK {
		t.Fatalf("expected project with archived_at 200, got %d body=%s", projectWithArchived.Code, projectWithArchived.Body.String())
	}

	projectBadArchived := doRequest(http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"p-bad","name":"Bad","slug":"bad","archived_at":"not-a-date"}`)
	if projectBadArchived.Code != http.StatusBadRequest {
		t.Fatalf("expected project with bad archived_at 400, got %d body=%s", projectBadArchived.Code, projectBadArchived.Body.String())
	}
}

func githubWebhookSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestRouterDoesNotWriteAuditSinkForAuthenticationFailure(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink: sink,
		APIKeys:   []string{"good-key"},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	req.Header.Set("User-Agent", "router-test-auth-failure")
	req.Header.Set("X-API-Key", "bad-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status 401, got %d", w.Code)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	authFailureCount := countAuditEventsByKind(sink.events, "api_auth_failure")
	if authFailureCount == 0 {
		t.Fatalf("expected auth failure audit event, got %d events: %+v", len(sink.events), sink.events)
	}
	for _, event := range sink.events {
		if event.Kind != "api_auth_failure" {
			continue
		}
		if event.APIKeyID == "bad-key" {
			t.Fatalf("expected hashed api_key_id in auth failure event, got %+v", event)
		}
	}
}

func TestRouterWritesAuditSinkWithSanitizedOIDCSubjectActor(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink: sink,
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"subject-token": {
					Subject:     "user-raw-subject",
					TenantID:    "tenant-a",
					WorkspaceID: "workspace-a",
					Scopes:      []string{scopeRead},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	req.Header.Set("Authorization", "Bearer subject-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected sink to capture event")
	}
	event := sink.events[len(sink.events)-1]
	if event.Actor == "subject:user-raw-subject" {
		t.Fatalf("expected sanitized subject actor, got %+v", event)
	}
	if !strings.HasPrefix(event.Actor, "subject:fnv64a:") {
		t.Fatalf("expected hashed subject actor format, got %+v", event)
	}
}

func TestSetAuditActorOnRequestContextPreservesOIDCActorCorrelationForActionEvents(t *testing.T) {
	fingerprinter := audit.NewFingerprinter("audit-secret")
	sink := &recordingAuditSink{}

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces", nil)
	ctx := audit.WithSink(req.Context(), sink)
	ctx = audit.WithFingerprinter(ctx, fingerprinter)
	c.Request = req.WithContext(ctx)
	c.Set("auth.subject", "oidc-actor-123")

	requestActor := triageActorFromContext(c, fingerprinter)
	setAuditActorOnRequestContext(c, fingerprinter)
	audit.WriteAction(c.Request.Context(), audit.AuditEvent{
		Action:     "workspace.create",
		ResourceID: "workspace-a",
	})

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 action event, got %d", len(sink.events))
	}
	event := sink.events[0]
	if event.Actor != requestActor {
		t.Fatalf("expected action actor %q to match request actor %q", event.Actor, requestActor)
	}
	if strings.Contains(event.Actor, "oidc-actor-123") {
		t.Fatalf("expected redacted action actor, got %+v", event)
	}
}

func TestSetAuditActorOnRequestContextKeepsAPIKeyActorsRedactedForActionEvents(t *testing.T) {
	fingerprinter := audit.NewFingerprinter("audit-secret")
	sink := &recordingAuditSink{}

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces", nil)
	ctx := audit.WithSink(req.Context(), sink)
	ctx = audit.WithFingerprinter(ctx, fingerprinter)
	c.Request = req.WithContext(ctx)
	c.Set("auth.api_key", "fixture-credential-123")

	requestActor := triageActorFromContext(c, fingerprinter)
	setAuditActorOnRequestContext(c, fingerprinter)
	audit.WriteAction(c.Request.Context(), audit.AuditEvent{
		Action:     "workspace.create",
		ResourceID: "workspace-a",
	})

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 action event, got %d", len(sink.events))
	}
	event := sink.events[0]
	if event.Actor != requestActor {
		t.Fatalf("expected action actor %q to match request actor %q", event.Actor, requestActor)
	}
	if strings.Contains(event.Actor, "fixture-credential-123") {
		t.Fatalf("expected redacted api key actor, got %+v", event)
	}
}
