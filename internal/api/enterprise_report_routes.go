package api

import (
	"context"
	"errors"
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

// executiveReportCacheKey derives a cache key from the tenant, the exact set
// of workspaces the report was built from, and the active domain filter.
// Sorting makes the key stable regardless of resolution order, and including
// the set guarantees a caller can only read a cached report built from the
// same authorized scope. The domain segment isolates per-domain reports so an
// "All" caller cannot receive an AWS-only cached entry, or vice versa.
func executiveReportCacheKey(tenantID string, workspaceIDs []string, domain string) string {
	sorted := append([]string(nil), workspaceIDs...)
	sort.Strings(sorted)
	return tenantID + "\x00" + strings.Join(sorted, "\x1f") + "\x00" + domain
}

// executiveReportDomain represents the optional ?domain= filter on the
// executive report endpoint. The empty value means "all domains".
type executiveReportDomain string

const (
	executiveReportDomainAll        executiveReportDomain = ""
	executiveReportDomainAWS        executiveReportDomain = "aws"
	executiveReportDomainGitHub     executiveReportDomain = "github"
	executiveReportDomainKubernetes executiveReportDomain = "kubernetes"
)

// parseExecutiveReportDomain validates the ?domain= query value. Unknown
// values are rejected so a typo can never silently widen to "all".
func parseExecutiveReportDomain(raw string) (executiveReportDomain, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return executiveReportDomainAll, nil
	case "aws":
		return executiveReportDomainAWS, nil
	case "github":
		return executiveReportDomainGitHub, nil
	case "kubernetes":
		return executiveReportDomainKubernetes, nil
	default:
		return executiveReportDomainAll, errInvalidExecutiveReportDomain
	}
}

var errInvalidExecutiveReportDomain = errors.New("invalid domain")

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

		reportDomain, err := parseExecutiveReportDomain(c.Query("domain"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain", "allowed": []string{"aws", "github", "kubernetes"}})
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
		cacheKey := executiveReportCacheKey(scope.TenantID, workspaceIDs, string(reportDomain))

		if report, ok := cache.get(cacheKey, now); ok {
			c.JSON(http.StatusOK, report)
			return
		}

		// Graph findings (AWS + Kubernetes) come from ListFindingsAll; repo
		// findings (GitHub) come from ListRepoFindings. The domain filter
		// determines which sources contribute and, for graph findings, which
		// scan provider is kept.
		includeGraph := reportDomain == executiveReportDomainAll || reportDomain == executiveReportDomainAWS || reportDomain == executiveReportDomainKubernetes
		includeRepo := reportDomain == executiveReportDomainAll || reportDomain == executiveReportDomainGitHub

		var findings []domain.Finding
		for _, wsID := range workspaceIDs {
			wsCtx := db.WithScope(reqCtx, db.Scope{TenantID: scope.TenantID, WorkspaceID: wsID})

			if includeGraph {
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
				if reportDomain == executiveReportDomainAWS || reportDomain == executiveReportDomainKubernetes {
					provider := string(domain.ProviderAWS)
					if reportDomain == executiveReportDomainKubernetes {
						provider = string(domain.ProviderKubernetes)
					}
					wsFindings, err = filterFindingsByScanProvider(wsCtx, svc, wsFindings, provider)
					if err != nil {
						if logger != nil {
							logger.Error("filter findings by scan provider", telemetry.ZapError(err))
						}
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
						return
					}
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

			if includeRepo {
				repoFindings, err := svc.Store.ListRepoFindings(wsCtx, db.RepoFindingFilter{}, 0)
				if err != nil {
					if logger != nil {
						logger.Error("list repo findings for executive report", telemetry.ZapError(err))
					}
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
					return
				}
				repoFindings = enrichFindingsWithRepoContext(repoFindings)
				repoFindings, err = svc.applyRepoFindingTriageStates(wsCtx, repoFindings)
				if err != nil {
					if logger != nil {
						logger.Error("hydrate repo finding triage for executive report", telemetry.ZapError(err))
					}
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build executive report"})
					return
				}
				findings = append(findings, repoFindings...)
			}
		}

		report := enterprise.BuildExecutiveReport(findings, enterprise.ReportOptions{
			OrganizationID: orgID,
			Now:            clock,
		})
		cache.set(cacheKey, report, now)
		c.JSON(http.StatusOK, report)
	}
}

// filterFindingsByScanProvider keeps only findings whose owning scan was run
// by the requested provider (aws or kubernetes). Findings without a known
// scan, or whose scan was run by a different provider, are dropped. Used to
// split the graph finding stream into AWS- vs Kubernetes-only views for the
// per-domain executive report.
//
// The lookup resolves scans by ID rather than calling ListScans, because
// ListScans coerces a non-positive limit to 100 in both store backends. A
// workspace with more than 100 scans would silently drop findings whose
// owning scan is older than that, so the AWS/Kubernetes report would undercount
// while the All report still included them. Looking up only the scan IDs the
// findings actually reference avoids the cap and keeps the work proportional
// to the finding set, not to scan history.
func filterFindingsByScanProvider(ctx context.Context, svc *Service, findings []domain.Finding, provider string) ([]domain.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}

	// Deduplicate scan IDs so we issue at most one GetScan per distinct scan.
	scanIDs := make(map[string]struct{})
	for _, finding := range findings {
		if id := strings.TrimSpace(finding.ScanID); id != "" {
			scanIDs[id] = struct{}{}
		}
	}

	wantProvider := strings.TrimSpace(provider)
	keep := make(map[string]struct{}, len(scanIDs))
	for id := range scanIDs {
		scan, err := svc.Store.GetScan(ctx, id)
		if err != nil {
			// A finding's scan can legitimately be missing (e.g. retention/
			// purge has dropped the scan row while findings persist). Drop the
			// finding from the per-domain report rather than failing the whole
			// request, matching the spirit of "filter by provider, exclude
			// what we cannot classify".
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if strings.EqualFold(strings.TrimSpace(scan.Provider), wantProvider) {
			keep[id] = struct{}{}
		}
	}

	filtered := findings[:0:0]
	for _, finding := range findings {
		if _, ok := keep[finding.ScanID]; ok {
			filtered = append(filtered, finding)
		}
	}
	return filtered, nil
}
