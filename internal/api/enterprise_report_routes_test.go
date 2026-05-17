package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/enterprise"
)

func execReportScope(org string) db.Scope {
	return db.Scope{TenantID: org, WorkspaceID: org}
}

func seedExecReportScan(t *testing.T, store db.Store, scope db.Scope, startedAt time.Time) string {
	t.Helper()
	scan, err := store.CreateScan(db.WithScope(context.Background(), scope), "aws", startedAt)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	return scan.ID
}

func seedExecReportFinding(t *testing.T, store db.Store, scope db.Scope, scanID, id string, sev domain.FindingSeverity, typ domain.FindingType, createdAt time.Time, resolvedAt *time.Time) {
	t.Helper()
	ctx := db.WithScope(context.Background(), scope)
	if err := store.UpsertFindings(ctx, scanID, []domain.Finding{
		{ID: id, ScanID: scanID, Type: typ, Severity: sev, Title: id, CreatedAt: createdAt},
	}); err != nil {
		t.Fatalf("seed finding %s: %v", id, err)
	}
	if resolvedAt != nil {
		if err := store.UpsertFindingTriageState(ctx, db.FindingTriageState{
			FindingID:  id,
			Status:     domain.FindingLifecycleResolved,
			ResolvedAt: resolvedAt,
			UpdatedAt:  *resolvedAt,
			UpdatedBy:  "subject:tester",
		}); err != nil {
			t.Fatalf("seed triage %s: %v", id, err)
		}
	}
}

// execReportRig builds a router whose injected middleware mirrors the
// production session + scope wiring for a given organization.
func execReportRig(t *testing.T, org string, clock *time.Time) (*Service, *gin.Engine, db.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	if clock != nil {
		svc.Now = func() time.Time { return *clock }
	}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		ctx := db.WithScope(c.Request.Context(), execReportScope(org))
		c.Request = c.Request.WithContext(ctx)
		c.Set("auth.session", sessionauth.CurrentSession{
			Session: db.Session{
				UserID:             "11111111-1111-1111-1111-111111111111",
				CurrentOrgID:       org,
				CurrentWorkspaceID: org,
			},
		})
	})
	v1 := r.Group("/v1")
	registerExecutiveReportRoutes(v1, nil, svc)
	return svc, r, store
}

func TestExecutiveReport_RequiresSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := gin.New()
	v1 := r.Group("/v1")
	registerExecutiveReportRoutes(v1, nil, svc)

	w := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing session must be rejected; got %d", w.Code)
	}
}

func TestExecutiveReport_RequiresOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth.session", sessionauth.CurrentSession{
			Session: db.Session{UserID: "11111111-1111-1111-1111-111111111111"},
		})
	})
	v1 := r.Group("/v1")
	registerExecutiveReportRoutes(v1, nil, svc)

	w := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("empty org context must be rejected; got %d", w.Code)
	}
}

func TestExecutiveReport_ReturnsReportWithMTTRFromResolvedAt(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := now
	svc, r, store := execReportRig(t, "org-a", &clock)

	scope := execReportScope("org-a")
	scanID := seedExecReportScan(t, store, scope, now.Add(-31*24*time.Hour))
	seedExecReportFinding(t, store, scope, scanID, "f1", domain.SeverityHigh, domain.FindingOverPrivileged, now.Add(-3*24*time.Hour), nil)
	seedExecReportFinding(t, store, scope, scanID, "f2", domain.SeverityCritical, domain.FindingEscalationPath, now.Add(-2*24*time.Hour), nil)
	resolvedAt := now.Add(-1 * 24 * time.Hour)
	seedExecReportFinding(t, store, scope, scanID, "f3", domain.SeverityMedium, domain.FindingStaleIdentity, now.Add(-3*24*time.Hour), &resolvedAt)

	_ = svc
	w := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var report enterprise.ExecutiveReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.OrganizationID != "org-a" {
		t.Errorf("organization_id: want org-a, got %q", report.OrganizationID)
	}
	if report.TotalOpenFindings != 2 {
		t.Errorf("total open: want 2, got %d", report.TotalOpenFindings)
	}
	if report.MeanTimeToResolve == nil {
		t.Fatal("expected MTTR from ResolvedAt data")
	}
	if report.MeanTimeToResolve.ResolvedCount != 1 {
		t.Errorf("MTTR sample count: want 1, got %d", report.MeanTimeToResolve.ResolvedCount)
	}
	if want := (2 * 24 * time.Hour).Seconds(); report.MeanTimeToResolve.Seconds != want {
		t.Errorf("MTTR seconds: want %v, got %v", want, report.MeanTimeToResolve.Seconds)
	}
}

func TestExecutiveReport_CachesPerOrganizationWithinTTL(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := now
	_, r, store := execReportRig(t, "org-a", &clock)

	scope := execReportScope("org-a")
	scanID := seedExecReportScan(t, store, scope, now.Add(-2*24*time.Hour))
	seedExecReportFinding(t, store, scope, scanID, "f1", domain.SeverityHigh, domain.FindingOverPrivileged, now.Add(-1*24*time.Hour), nil)

	first := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first call: got %d", first.Code)
	}

	// Mutate the store, then call again within the 60s window: the response
	// must still be the cached one, proving the cache is consulted.
	seedExecReportFinding(t, store, scope, scanID, "f2", domain.SeverityCritical, domain.FindingEscalationPath, now.Add(-12*time.Hour), nil)
	clock = now.Add(30 * time.Second)
	cached := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var cachedReport enterprise.ExecutiveReport
	if err := json.Unmarshal(cached.Body.Bytes(), &cachedReport); err != nil {
		t.Fatalf("decode cached: %v", err)
	}
	if cachedReport.TotalOpenFindings != 1 {
		t.Errorf("within TTL the cached report must be returned; want 1 open, got %d", cachedReport.TotalOpenFindings)
	}

	// Past the TTL the report is rebuilt and reflects the mutation.
	clock = now.Add(61 * time.Second)
	fresh := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var freshReport enterprise.ExecutiveReport
	if err := json.Unmarshal(fresh.Body.Bytes(), &freshReport); err != nil {
		t.Fatalf("decode fresh: %v", err)
	}
	if freshReport.TotalOpenFindings != 2 {
		t.Errorf("after TTL the report must rebuild; want 2 open, got %d", freshReport.TotalOpenFindings)
	}
}

func TestExecutiveReport_IsolatesOrganizations(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := now

	// org-a has findings; org-b shares the same store but a different scope.
	_, rA, store := execReportRig(t, "org-a", &clock)
	scopeA := execReportScope("org-a")
	scanID := seedExecReportScan(t, store, scopeA, now.Add(-2*24*time.Hour))
	seedExecReportFinding(t, store, scopeA, scanID, "f1", domain.SeverityHigh, domain.FindingOverPrivileged, now.Add(-1*24*time.Hour), nil)

	wA := doJSON(t, rA, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var repA enterprise.ExecutiveReport
	if err := json.Unmarshal(wA.Body.Bytes(), &repA); err != nil {
		t.Fatalf("decode org-a: %v", err)
	}
	if repA.TotalOpenFindings != 1 {
		t.Errorf("org-a should see its own finding; got %d", repA.TotalOpenFindings)
	}

	rB := gin.New()
	rB.Use(func(c *gin.Context) {
		ctx := db.WithScope(c.Request.Context(), execReportScope("org-b"))
		c.Request = c.Request.WithContext(ctx)
		c.Set("auth.session", sessionauth.CurrentSession{
			Session: db.Session{UserID: "22222222-2222-2222-2222-222222222222", CurrentOrgID: "org-b", CurrentWorkspaceID: "org-b"},
		})
	})
	svcB := NewService(store, routerScanner{}, "aws")
	svcB.Now = func() time.Time { return clock }
	v1B := rB.Group("/v1")
	registerExecutiveReportRoutes(v1B, nil, svcB)

	wB := doJSON(t, rB, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var repB enterprise.ExecutiveReport
	if err := json.Unmarshal(wB.Body.Bytes(), &repB); err != nil {
		t.Fatalf("decode org-b: %v", err)
	}
	if repB.OrganizationID != "org-b" {
		t.Errorf("org-b report mislabeled: %q", repB.OrganizationID)
	}
	if repB.TotalOpenFindings != 0 {
		t.Errorf("org-b must not see org-a findings; got %d", repB.TotalOpenFindings)
	}
}

func TestExecutiveReportCache_EvictsExpiredEntries(t *testing.T) {
	ttl := 60 * time.Second
	cache := newExecutiveReportCache(ttl)
	t0 := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	cache.set("tenant-a\x00ws-a", enterprise.ExecutiveReport{OrganizationID: "a"}, t0)

	// A stale entry must not be served, and the lookup itself evicts it.
	if _, ok := cache.get("tenant-a\x00ws-a", t0.Add(ttl+time.Second)); ok {
		t.Fatal("expired entry must not be served")
	}
	cache.mu.Lock()
	if _, present := cache.entries["tenant-a\x00ws-a"]; present {
		cache.mu.Unlock()
		t.Fatal("expired entry must be evicted on stale get")
	}
	cache.mu.Unlock()

	// A later write for a different scope sweeps any other expired entries so
	// the map cannot grow without bound.
	cache.set("tenant-a\x00ws-a", enterprise.ExecutiveReport{OrganizationID: "a"}, t0)
	cache.set("tenant-b\x00ws-b", enterprise.ExecutiveReport{OrganizationID: "b"}, t0.Add(ttl+time.Second))
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if _, present := cache.entries["tenant-a\x00ws-a"]; present {
		t.Fatal("expired entry must be swept on the next set")
	}
	if len(cache.entries) != 1 {
		t.Fatalf("cache must not retain expired entries; size=%d", len(cache.entries))
	}
}

func TestExecutiveReport_IsolatesWorkspacesWithinSameOrg(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := now
	store := db.NewMemoryStore()

	wsScope := func(ws string) db.Scope { return db.Scope{TenantID: "org-shared", WorkspaceID: ws} }
	rig := func(ws string) *gin.Engine {
		svc := NewService(store, routerScanner{}, "aws")
		svc.Now = func() time.Time { return clock }
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), wsScope(ws)))
			c.Set("auth.session", sessionauth.CurrentSession{
				Session: db.Session{UserID: "11111111-1111-1111-1111-111111111111", CurrentOrgID: "org-shared", CurrentWorkspaceID: ws},
			})
		})
		v1 := r.Group("/v1")
		registerExecutiveReportRoutes(v1, nil, svc)
		return r
	}

	scanID := seedExecReportScan(t, store, wsScope("ws-1"), now.Add(-2*24*time.Hour))
	seedExecReportFinding(t, store, wsScope("ws-1"), scanID, "f1", domain.SeverityHigh, domain.FindingOverPrivileged, now.Add(-1*24*time.Hour), nil)

	// ws-1 sees its finding; ws-2 in the same org must not get ws-1's report.
	w1 := doJSON(t, rig("ws-1"), http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var rep1 enterprise.ExecutiveReport
	if err := json.Unmarshal(w1.Body.Bytes(), &rep1); err != nil {
		t.Fatalf("decode ws-1: %v", err)
	}
	if rep1.TotalOpenFindings != 1 {
		t.Fatalf("ws-1 should see its finding; got %d", rep1.TotalOpenFindings)
	}

	w2 := doJSON(t, rig("ws-2"), http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var rep2 enterprise.ExecutiveReport
	if err := json.Unmarshal(w2.Body.Bytes(), &rep2); err != nil {
		t.Fatalf("decode ws-2: %v", err)
	}
	if rep2.TotalOpenFindings != 0 {
		t.Fatalf("ws-2 must not receive ws-1's cached report within the same org; got %d", rep2.TotalOpenFindings)
	}
}
