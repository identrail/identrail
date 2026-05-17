package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identrail/identrail/internal/db"
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

		// Cache by the exact data scope, not just the org. The request-scope
		// middleware narrows findings to tenant+workspace, so keying only by
		// org id would let one workspace serve another workspace's cached
		// report within the same organization for up to the TTL.
		reqCtx := c.Request.Context()
		scope := db.ScopeFromContext(reqCtx)
		cacheKey := scope.TenantID + "\x00" + scope.WorkspaceID

		if report, ok := cache.get(cacheKey, now); ok {
			c.JSON(http.StatusOK, report)
			return
		}

		// Findings are scope-filtered by the request-scope middleware, so the
		// store only returns the caller's tenant+workspace findings.
		// ListFindingsAll is uncapped; triage (including the trustworthy
		// ResolvedAt that MTTR depends on) is hydrated separately since the raw
		// finding rows do not carry it.
		findings, err := svc.Store.ListFindingsAll(reqCtx)
		if err != nil {
			if logger != nil {
				logger.Error("list findings for executive report", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
			return
		}
		findings, err = svc.applyFindingTriageStates(reqCtx, findings)
		if err != nil {
			if logger != nil {
				logger.Error("hydrate triage for executive report", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
			return
		}

		report := enterprise.BuildExecutiveReport(findings, enterprise.ReportOptions{
			OrganizationID: orgID,
			Now:            clock,
		})
		cache.set(cacheKey, report, now)
		c.JSON(http.StatusOK, report)
	}
}
