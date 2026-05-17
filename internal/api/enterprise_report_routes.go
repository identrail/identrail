package api

import (
	"context"
	"net/http"
	"sort"
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

// authorizedReportWorkspaceIDs returns the workspaces whose findings the caller
// may aggregate into the organization report: exactly the workspaces in the
// organization (tenant) where the user holds an active membership. This is the
// authorization boundary — a workspace-scoped member must never pull findings
// from workspaces they do not belong to, even though the central route check
// only authorizes enterprise.read for their active workspace.
//
// The caller's active workspace is always included: the route check already
// authorized it, and deployments that never wrote tenancy membership rows
// (single-workspace/default mode) must still produce a non-empty report.
func authorizedReportWorkspaceIDs(ctx context.Context, svc *Service, userUUID string, scope db.Scope) ([]string, error) {
	memberships, err := svc.Store.ListWorkspaceMembershipsByUserUUIDAndTenantID(ctx, userUUID, scope.TenantID)
	if err != nil {
		return nil, err
	}
	ordered := make([]string, 0, len(memberships)+1)
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
	for _, m := range memberships {
		add(m.WorkspaceID)
	}
	add(scope.WorkspaceID)
	return ordered, nil
}

// executiveReportCacheKey derives a cache key from the tenant and the exact
// set of workspaces the report was built from. Sorting makes the key stable
// regardless of resolution order, and including the set guarantees a caller
// can only read a cached report built from the same authorized scope.
func executiveReportCacheKey(tenantID string, workspaceIDs []string) string {
	sorted := append([]string(nil), workspaceIDs...)
	sort.Strings(sorted)
	return tenantID + "\x00" + strings.Join(sorted, "\x1f")
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

		reqCtx := c.Request.Context()
		scope := db.ScopeFromContext(reqCtx)

		// An executive report covers the organization, but findings are stored
		// per workspace. Aggregate across the workspaces the caller is actually
		// a member of — never every workspace in the tenant — so the report
		// cannot expose findings from workspaces the user is not authorized for.
		// This is resolved before the cache lookup because the report content
		// depends on the authorized set, so it must be part of the cache key.
		workspaceIDs, err := authorizedReportWorkspaceIDs(reqCtx, svc, strings.TrimSpace(current.Session.UserID), scope)
		if err != nil {
			if logger != nil {
				logger.Error("resolve authorized workspaces for executive report", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
			return
		}

		// Key the cache by tenant + the exact authorized workspace set. Two
		// callers with the same membership set legitimately share one report;
		// a narrower-access caller can never receive a broader caller's cached
		// data, because their key differs.
		cacheKey := executiveReportCacheKey(scope.TenantID, workspaceIDs)

		if report, ok := cache.get(cacheKey, now); ok {
			c.JSON(http.StatusOK, report)
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

			repoFindings, err := svc.Store.ListRepoFindings(wsCtx, db.RepoFindingFilter{}, 0)
			if err != nil {
				if logger != nil {
					logger.Error("list repo findings for executive report", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
				return
			}
			repoFindings = enrichFindingsWithRepoContext(repoFindings)
			repoFindings, err = svc.applyFindingTriageStates(wsCtx, repoFindings)
			if err != nil {
				if logger != nil {
					logger.Error("hydrate repo finding triage for executive report", telemetry.ZapError(err))
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
				return
			}
			findings = append(findings, repoFindings...)
		}

		report := enterprise.BuildExecutiveReport(findings, enterprise.ReportOptions{
			OrganizationID: orgID,
			Now:            clock,
		})
		cache.set(cacheKey, report, now)
		c.JSON(http.StatusOK, report)
	}
}
