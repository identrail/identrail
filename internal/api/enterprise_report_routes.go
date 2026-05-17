package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/enterprise"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

// executiveReportCacheTTL bounds how long a built executive report is reused
// for one organization. Leadership dashboards refresh frequently; a short
// window keeps the response fresh without re-scanning every finding per click.
const executiveReportCacheTTL = 60 * time.Second

type cachedExecutiveReport struct {
	report    enterprise.ExecutiveReport
	expiresAt time.Time
}

// executiveReportCache memoizes the per-organization executive report for a
// short TTL. Entries are keyed strictly by organization id and are never
// shared across organizations, so the cache cannot leak one tenant's posture
// into another's response.
type executiveReportCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]cachedExecutiveReport
}

func newExecutiveReportCache(ttl time.Duration) *executiveReportCache {
	return &executiveReportCache{ttl: ttl, entries: map[string]cachedExecutiveReport{}}
}

func (c *executiveReportCache) get(key string, now time.Time) (enterprise.ExecutiveReport, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return enterprise.ExecutiveReport{}, false
	}
	if !now.Before(entry.expiresAt) {
		// Evict the stale entry we just touched rather than leaving it.
		delete(c.entries, key)
		return enterprise.ExecutiveReport{}, false
	}
	return entry.report, true
}

func (c *executiveReportCache) set(key string, report enterprise.ExecutiveReport, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Sweep expired entries so the per-scope map cannot grow without bound as
	// organizations/workspaces come and go. Writes are infrequent (at most one
	// per scope per TTL), so the linear sweep is cheap.
	for k, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = cachedExecutiveReport{report: report, expiresAt: now.Add(c.ttl)}
}

// maxOrgReportWorkspaces bounds how many workspaces the executive report will
// aggregate. It is far above any realistic per-organization workspace count;
// it exists only so a pathological tenant cannot make one request unbounded.
const maxOrgReportWorkspaces = 1000

// organizationWorkspaceIDs returns every workspace in the caller's tenant so
// the report covers the whole organization. The caller's active workspace is
// always included so deployments that never registered tenancy workspace rows
// (e.g. single-workspace/default mode) still produce a non-empty report.
func organizationWorkspaceIDs(ctx context.Context, svc *Service, scope db.Scope) ([]string, error) {
	workspaces, err := svc.Store.ListWorkspaces(ctx, maxOrgReportWorkspaces)
	if err != nil {
		return nil, err
	}
	ordered := make([]string, 0, len(workspaces)+1)
	seen := map[string]struct{}{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		ordered = append(ordered, id)
	}
	for _, ws := range workspaces {
		add(ws.WorkspaceID)
	}
	add(scope.WorkspaceID)
	return ordered, nil
}

func registerExecutiveReportRoutes(v1 *gin.RouterGroup, logger *zap.Logger, svc *Service) {
	if svc == nil {
		return
	}
	cache := newExecutiveReportCache(executiveReportCacheTTL)
	v1.GET("/enterprise/reports/executive", executiveReportHandler(logger, svc, cache))
}

func executiveReportHandler(logger *zap.Logger, svc *Service, cache *executiveReportCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := requireEnterpriseSession(c)
		if !ok {
			return
		}
		orgID := strings.TrimSpace(current.Session.CurrentOrgID)
		if orgID == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "org context required"})
			return
		}

		clock := svc.Now
		if clock == nil {
			clock = time.Now
		}
		now := clock()

		// The report is organization-wide. The request scope's tenant id is the
		// organization (session sets tenant_id from CurrentOrgID), so the cache
		// is keyed by tenant: every workspace in the org shares one org-wide
		// snapshot and cannot see a partial, workspace-scoped one.
		reqCtx := c.Request.Context()
		scope := db.ScopeFromContext(reqCtx)
		cacheKey := scope.TenantID

		if report, ok := cache.get(cacheKey, now); ok {
			c.JSON(http.StatusOK, report)
			return
		}

		// An executive report covers the whole organization, but findings are
		// stored per workspace. Enumerate every workspace in the tenant and
		// aggregate, rather than reporting only the caller's active workspace.
		workspaceIDs, err := organizationWorkspaceIDs(reqCtx, svc, scope)
		if err != nil {
			if logger != nil {
				logger.Error("list workspaces for executive report", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
			return
		}

		var findings []domain.Finding
		for _, wsID := range workspaceIDs {
			wsCtx := db.WithScope(reqCtx, db.Scope{TenantID: scope.TenantID, WorkspaceID: wsID})
			// ListFindingsAll is uncapped; triage (including the trustworthy
			// ResolvedAt that MTTR depends on) is hydrated separately since the
			// raw finding rows do not carry it.
			wsFindings, err := svc.Store.ListFindingsAll(wsCtx)
			if err != nil {
				if logger != nil {
					logger.Error("list findings for executive report", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
				return
			}
			wsFindings, err = svc.applyFindingTriageStates(wsCtx, wsFindings)
			if err != nil {
				if logger != nil {
					logger.Error("hydrate triage for executive report", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
				return
			}
			findings = append(findings, wsFindings...)
		}

		report := enterprise.BuildExecutiveReport(findings, enterprise.ReportOptions{
			OrganizationID: orgID,
			Now:            clock,
		})
		cache.set(cacheKey, report, now)
		c.JSON(http.StatusOK, report)
	}
}
