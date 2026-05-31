package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/scheduler"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/identrail/identrail/internal/userexport"
	"go.uber.org/zap"
)

func setupExportHarness(t *testing.T) (*ginlessSessionHarness, string, string) {
	t.Helper()
	harness, cookie, _ := setupSessionRouter(t)
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	harness.svc.UserExportStorage = storage
	harness.svc.UserExportTokenSecret = []byte("test-export-secret")
	harness.router = NewRouter(zap.NewNop(), telemetry.NewMetrics(), harness.svc, RouterOptions{
		FeatureNewAuth: true,
		PublicBaseURL:  "http://localhost:8080",
		RateLimitRPM:   1000,
		RateLimitBurst: 1000,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookie})
	rec := httptest.NewRecorder()
	harness.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed /v1/me: %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Me struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"me"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /v1/me: %v", err)
	}
	return harness, cookie, payload.Me.User.ID
}

func TestMeExportEnqueueAndPollLifecycle(t *testing.T) {
	harness, cookie, _ := setupExportHarness(t)

	postReq := httptest.NewRequest(http.MethodPost, "/v1/me/export", nil)
	postReq.Header.Set("Origin", "http://localhost:8080")
	postReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookie})
	postRec := httptest.NewRecorder()
	harness.router.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/me/export: %d %s", postRec.Code, postRec.Body.String())
	}
	var enqueued meExportResponse
	if err := json.Unmarshal(postRec.Body.Bytes(), &enqueued); err != nil {
		t.Fatalf("decode enqueue response: %v", err)
	}
	if enqueued.ID == "" || enqueued.Status != db.UserDataExportStatusQueued {
		t.Fatalf("unexpected enqueue: %+v", enqueued)
	}

	queue := &userexport.QueueRunner{
		Store: harness.svc.Store,
		Runner: &userexport.Runner{
			Source:  harness.svc.Store,
			Store:   harness.svc.Store,
			Storage: harness.svc.UserExportStorage,
			Now:     harness.svc.Now,
		},
	}
	if _, err := queue.RunOnce(context.Background()); err != nil {
		t.Fatalf("run queue: %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/v1/me/export/"+enqueued.ID, nil)
	getReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookie})
	getRec := httptest.NewRecorder()
	harness.router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/me/export: %d %s", getRec.Code, getRec.Body.String())
	}
	var ready meExportResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &ready); err != nil {
		t.Fatalf("decode ready response: %v", err)
	}
	if ready.Status != db.UserDataExportStatusReady {
		t.Fatalf("expected ready, got %s", ready.Status)
	}
	if ready.DownloadURL == "" {
		t.Fatalf("expected download_url, got %+v", ready)
	}

	dlReq := httptest.NewRequest(http.MethodGet, ready.DownloadURL, nil)
	dlRec := httptest.NewRecorder()
	harness.router.ServeHTTP(dlRec, dlReq)
	if dlRec.Code != http.StatusOK {
		t.Fatalf("download: %d %s", dlRec.Code, dlRec.Body.String())
	}
	if ct := dlRec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("unexpected content type: %s", ct)
	}
	if dlRec.Body.Len() == 0 {
		t.Fatal("expected non-empty bundle")
	}
}

func TestMeExportScopingHidesOtherUsersJobs(t *testing.T) {
	harness, cookie, ownerID := setupExportHarness(t)
	other, err := harness.svc.Store.UpsertUser(context.Background(), db.User{PrimaryEmail: "other@example.com"})
	if err != nil {
		t.Fatalf("seed other: %v", err)
	}
	if other.ID == ownerID {
		t.Fatal("expected distinct user ids")
	}
	job, err := harness.svc.Store.CreateUserDataExport(context.Background(), db.UserDataExport{
		UserID:      other.ID,
		RequestedAt: time.Now().UTC(),
		Status:      db.UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create other job: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/me/export/"+job.ID, nil)
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookie})
	rec := httptest.NewRecorder()
	harness.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-user lookup, got %d", rec.Code)
	}
}

func TestMeExportDownloadRequiresMatchingToken(t *testing.T) {
	harness, _, _ := setupExportHarness(t)
	exp := time.Now().Add(time.Hour)
	bad, err := userexport.SignedDownloadURL([]byte("wrong-secret"), "some-job", exp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/me/export/some-job/download?token="+bad, nil)
	rec := httptest.NewRecorder()
	harness.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for bad token, got %d", rec.Code)
	}
}

func TestMeExportRateLimited(t *testing.T) {
	harness, cookie, ownerID := setupExportHarness(t)
	now := time.Now().UTC()
	for i := 0; i < userExportRateLimit; i++ {
		if _, err := harness.svc.Store.CreateUserDataExport(context.Background(), db.UserDataExport{
			UserID:      ownerID,
			RequestedAt: now.Add(-time.Duration(i) * time.Minute),
			Status:      db.UserDataExportStatusReady,
		}); err != nil {
			t.Fatalf("seed job %d: %v", i, err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/me/export", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	req.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookie})
	rec := httptest.NewRecorder()
	harness.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d %s", rec.Code, rec.Body.String())
	}
}

type singleAcquireFailureLocker struct {
	acquired uint32
}

func (s *singleAcquireFailureLocker) TryAcquire(context.Context, string) (scheduler.ReleaseFn, bool) {
	if !atomic.CompareAndSwapUint32(&s.acquired, 0, 1) {
		return nil, false
	}
	return func(context.Context) {}, true
}

func TestMeExportRateLimitUsesUserLock(t *testing.T) {
	harness, cookie, ownerID := setupExportHarness(t)
	harness.svc.Locker = &singleAcquireFailureLocker{}
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/me/export", nil)
	firstReq.Header.Set("Origin", "http://localhost:8080")
	firstReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookie})
	firstRec := httptest.NewRecorder()
	harness.router.ServeHTTP(firstRec, firstReq)
	if firstRec.Code != http.StatusAccepted {
		t.Fatalf("first request expected 202, got %d %s", firstRec.Code, firstRec.Body.String())
	}
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/me/export", nil)
	secondReq.Header.Set("Origin", "http://localhost:8080")
	secondReq.AddCookie(&http.Cookie{Name: sessionauth.CookieName, Value: cookie})
	secondRec := httptest.NewRecorder()
	harness.router.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for locked request, got %d %s", secondRec.Code, secondRec.Body.String())
	}
	items, err := harness.svc.Store.ListUserDataExports(context.Background(), ownerID, 10)
	if err != nil {
		t.Fatalf("list exports: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one job when lock blocks concurrent enqueue, got %d", len(items))
	}
}

func TestToMeExportResponseOmitsExpiredDownloadURL(t *testing.T) {
	harness, _, _ := setupExportHarness(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	harness.svc.Now = func() time.Time { return now }
	resp := toMeExportResponse(harness.svc, nil, db.UserDataExport{
		ID:                "11111111-1111-1111-1111-111111111111",
		Status:            db.UserDataExportStatusReady,
		RequestedAt:       now.Add(-time.Minute),
		DownloadExpiresAt: &now,
	})
	if resp.DownloadURL != "" {
		t.Fatalf("expected expired job to have no download url, got %q", resp.DownloadURL)
	}

	active := now.Add(time.Hour)
	resp = toMeExportResponse(harness.svc, nil, db.UserDataExport{
		ID:                "22222222-2222-2222-2222-222222222222",
		Status:            db.UserDataExportStatusReady,
		RequestedAt:       now,
		DownloadExpiresAt: &active,
	})
	downloadURL, err := url.Parse(resp.DownloadURL)
	if err != nil {
		t.Fatalf("expected valid download url for active export, got %v", err)
	}
	if downloadURL.Path != "/v1/me/export/22222222-2222-2222-2222-222222222222/download" {
		t.Fatalf("unexpected download path: %s", downloadURL.Path)
	}
}
