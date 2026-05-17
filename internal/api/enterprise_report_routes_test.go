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

const execReportTestUser = "11111111-1111-1111-1111-111111111111"

func seedExecReportWorkspace(t *testing.T, store db.Store, tenant, ws string) {
	t.Helper()
	tenantCtx := db.WithScope(context.Background(), db.Scope{TenantID: tenant, WorkspaceID: ws})
	if err := store.UpsertOrganization(tenantCtx, db.TenancyOrganization{DisplayName: tenant, Slug: tenant}); err != nil {
		t.Fatalf("seed org %s: %v", tenant, err)
	}
	if err := store.UpsertWorkspace(tenantCtx, db.TenancyWorkspace{WorkspaceID: ws, DisplayName: ws, Slug: ws}); err != nil {
		t.Fatalf("seed workspace %s/%s: %v", tenant, ws, err)
	}
}

// seedExecReportMembership grants the test user an active membership in one
// workspace so the org report is authorized to aggregate it.
func seedExecReportMembership(t *testing.T, store db.Store, tenant, ws string) {
	t.Helper()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: tenant, WorkspaceID: ws})
	if err := store.UpsertWorkspaceMember(ctx, db.TenancyWorkspaceMember{
		WorkspaceID: ws,
		MemberID:    "member-" + ws,
		UserID:      execReportTestUser,
		UserUUID:    execReportTestUser,
		Role:        "viewer",
		Status:      "active",
	}); err != nil {
		t.Fatalf("seed membership %s/%s: %v", tenant, ws, err)
	}
}

func TestExecutiveReport_AggregatesAcrossOrgWorkspaces(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	clock := now
	store := db.NewMemoryStore()

	const org = "org-shared"
	seedExecReportWorkspace(t, store, org, "ws-1")
	seedExecReportWorkspace(t, store, org, "ws-2")
	seedExecReportWorkspace(t, store, org, "ws-3")
	// The caller is a member of ws-1 and ws-2 only.
	seedExecReportMembership(t, store, org, "ws-1")
	seedExecReportMembership(t, store, org, "ws-2")

	ws1Scope := db.Scope{TenantID: org, WorkspaceID: "ws-1"}
	ws2Scope := db.Scope{TenantID: org, WorkspaceID: "ws-2"}
	ws3Scope := db.Scope{TenantID: org, WorkspaceID: "ws-3"}
	scan1 := seedExecReportScan(t, store, ws1Scope, now.Add(-2*24*time.Hour))
	seedExecReportFinding(t, store, ws1Scope, scan1, "f1", domain.SeverityHigh, domain.FindingOverPrivileged, now.Add(-1*24*time.Hour), nil)
	scan2 := seedExecReportScan(t, store, ws2Scope, now.Add(-2*24*time.Hour))
	seedExecReportFinding(t, store, ws2Scope, scan2, "f2", domain.SeverityCritical, domain.FindingEscalationPath, now.Add(-1*24*time.Hour), nil)
	// ws-3 has a finding but the caller is NOT a member — it must be excluded.
	scan3 := seedExecReportScan(t, store, ws3Scope, now.Add(-2*24*time.Hour))
	seedExecReportFinding(t, store, ws3Scope, scan3, "f-secret", domain.SeverityCritical, domain.FindingStaleIdentity, now.Add(-1*24*time.Hour), nil)

	// One shared Service (one cache). The caller's active workspace is ws-1,
	// but the report must cover every workspace the caller belongs to.
	svc := NewService(store, routerScanner{}, "aws")
	svc.Now = func() time.Time { return clock }
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), ws1Scope))
		c.Set("auth.session", sessionauth.CurrentSession{
			Session: db.Session{UserID: "11111111-1111-1111-1111-111111111111", CurrentOrgID: org, CurrentWorkspaceID: "ws-1"},
		})
	})
	v1 := r.Group("/v1")
	registerExecutiveReportRoutes(v1, nil, svc)

	first := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var rep enterprise.ExecutiveReport
	if err := json.Unmarshal(first.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.TotalOpenFindings != 2 {
		t.Fatalf("report must aggregate the caller's member workspaces (ws-1,ws-2) and exclude the non-member ws-3; want 2, got %d", rep.TotalOpenFindings)
	}

	// Add a finding in ws-2 and call again within the TTL: the org-wide cache
	// (one entry keyed by tenant) must return the prior snapshot.
	seedExecReportFinding(t, store, ws2Scope, scan2, "f3", domain.SeverityMedium, domain.FindingStaleIdentity, now.Add(-12*time.Hour), nil)
	clock = now.Add(30 * time.Second)
	cached := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var cachedRep enterprise.ExecutiveReport
	if err := json.Unmarshal(cached.Body.Bytes(), &cachedRep); err != nil {
		t.Fatalf("decode cached: %v", err)
	}
	if cachedRep.TotalOpenFindings != 2 {
		t.Fatalf("within TTL the shared org cache must be served; want 2, got %d", cachedRep.TotalOpenFindings)
	}

	// Past the TTL the org-wide report rebuilds and reflects every workspace.
	clock = now.Add(61 * time.Second)
	fresh := doJSON(t, r, http.MethodGet, "/v1/enterprise/reports/executive", nil)
	var freshRep enterprise.ExecutiveReport
	if err := json.Unmarshal(fresh.Body.Bytes(), &freshRep); err != nil {
		t.Fatalf("decode fresh: %v", err)
	}
	if freshRep.TotalOpenFindings != 3 {
		t.Fatalf("after TTL the org-wide report must rebuild; want 3, got %d", freshRep.TotalOpenFindings)
	}
}
