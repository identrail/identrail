package awscontract

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CoveragePlannerVersion is the stable contract version operators and downstream
// fan-out workers cite when persisting or reconciling a coverage plan.
const CoveragePlannerVersion = "aws-account-region-coverage-planner-v1"

// CoverageState is the explicit lifecycle state of one account/region/service
// scan target. Unknown, denied, unsupported, and partially failed states are
// first-class so operators never read a partial or blocked target as a success.
type CoverageState string

const (
	// CoverageStateDisabled marks a target whose account, region, or service is
	// explicitly disabled in the connector coverage configuration.
	CoverageStateDisabled CoverageState = "disabled"
	// CoverageStateBlocked marks an enabled target whose prerequisites are not
	// yet satisfied (for example a member account that has not been onboarded or
	// an opt-in region that is not enabled on the account).
	CoverageStateBlocked CoverageState = "blocked"
	// CoverageStatePlanned marks an enabled, unblocked target that has not been
	// attempted yet.
	CoverageStatePlanned CoverageState = "planned"
	// CoverageStatePending marks a target queued for execution.
	CoverageStatePending CoverageState = "pending"
	// CoverageStateInProgress marks a target whose scan is running and may carry a
	// resumable cursor.
	CoverageStateInProgress CoverageState = "in_progress"
	// CoverageStateCovered marks a target whose scan completed successfully.
	CoverageStateCovered CoverageState = "covered"
	// CoverageStatePartial marks a target that completed with a partial failure
	// and must be reconciled or rerun.
	CoverageStatePartial CoverageState = "partial"
	// CoverageStateFailed marks a target whose scan failed and is retryable.
	CoverageStateFailed CoverageState = "failed"
	// CoverageStatePermissionDenied marks a target the connector role cannot scan
	// because AWS denied a required read-only action.
	CoverageStatePermissionDenied CoverageState = "permission_denied"
	// CoverageStateUnsupported marks a target whose region or service is not
	// available (for example a service that is not offered in a region).
	CoverageStateUnsupported CoverageState = "unsupported"
)

// CoveragePriority orders how urgently a target should be scanned. The most
// urgent priority among a target's account, region, and service wins.
type CoveragePriority string

const (
	CoveragePriorityCritical CoveragePriority = "critical"
	CoveragePriorityHigh     CoveragePriority = "high"
	CoveragePriorityNormal   CoveragePriority = "normal"
	CoveragePriorityLow      CoveragePriority = "low"
)

// defaultGlobalServiceHomeRegion is where global-scope services (for example
// IAM) are planned once per account rather than fanned out per region.
const defaultGlobalServiceHomeRegion = "us-east-1"

// CoverageAccount is one AWS account in the connector's coverage configuration.
type CoverageAccount struct {
	AccountID     string           `json:"account_id"`
	Name          string           `json:"name,omitempty"`
	Enabled       bool             `json:"enabled"`
	Priority      CoveragePriority `json:"priority,omitempty"`
	Reason        string           `json:"reason,omitempty"`
	Prerequisites []string         `json:"prerequisites,omitempty"`
	// Management marks the organization management/payer account.
	Management bool `json:"management,omitempty"`
}

// CoverageRegion is one AWS region in the connector's coverage configuration.
type CoverageRegion struct {
	Region        string           `json:"region"`
	Name          string           `json:"name,omitempty"`
	Enabled       bool             `json:"enabled"`
	Priority      CoveragePriority `json:"priority,omitempty"`
	Reason        string           `json:"reason,omitempty"`
	Prerequisites []string         `json:"prerequisites,omitempty"`
	// OptIn marks a region that AWS disables by default and that must be opted
	// into on each account before it can be scanned.
	OptIn bool `json:"opt_in,omitempty"`
}

// CoverageService is one AWS service partition in the coverage configuration.
type CoverageService struct {
	Service       string           `json:"service"`
	Name          string           `json:"name,omitempty"`
	Enabled       bool             `json:"enabled"`
	Priority      CoveragePriority `json:"priority,omitempty"`
	Reason        string           `json:"reason,omitempty"`
	Prerequisites []string         `json:"prerequisites,omitempty"`
	// Global marks a service whose inventory is account-global (for example IAM).
	// Global services are planned once per account in HomeRegion instead of being
	// fanned out across every region, which keeps the plan honest about where the
	// scan actually runs.
	Global bool `json:"global,omitempty"`
	// HomeRegion overrides where a global service is planned. Defaults to
	// us-east-1 when empty.
	HomeRegion string `json:"home_region,omitempty"`
}

// CoverageCheckpoint is the persisted prior state of one target, used to make
// the plan resumable. The fan-out worker writes checkpoints as targets advance;
// the planner replays them so a rerun continues from the last cursor instead of
// rescanning covered targets.
type CoverageCheckpoint struct {
	AccountID     string        `json:"account_id"`
	Region        string        `json:"region"`
	Service       string        `json:"service"`
	State         CoverageState `json:"state"`
	Cursor        string        `json:"cursor,omitempty"`
	FailureReason string        `json:"failure_reason,omitempty"`
	Attempts      int           `json:"attempts,omitempty"`
	ObservedAt    time.Time     `json:"observed_at,omitempty"`
}

// CoveragePlanConfig is the connector's expanded account/region/service scan
// configuration plus any prior checkpoints to resume from.
type CoveragePlanConfig struct {
	ConnectorID string               `json:"connector_id,omitempty"`
	Accounts    []CoverageAccount    `json:"accounts"`
	Regions     []CoverageRegion     `json:"regions"`
	Services    []CoverageService    `json:"services"`
	Checkpoints []CoverageCheckpoint `json:"checkpoints,omitempty"`
}

// CoverageTarget is one planned account/region/service scan unit with its
// expectation (reason, priority, prerequisites) and current coverage state.
type CoverageTarget struct {
	Key           string           `json:"key"`
	AccountID     string           `json:"account_id"`
	AccountName   string           `json:"account_name,omitempty"`
	Region        string           `json:"region"`
	RegionName    string           `json:"region_name,omitempty"`
	Service       string           `json:"service"`
	ServiceName   string           `json:"service_name,omitempty"`
	Global        bool             `json:"global,omitempty"`
	Enabled       bool             `json:"enabled"`
	Priority      CoveragePriority `json:"priority"`
	PriorityRank  int              `json:"priority_rank"`
	Reason        string           `json:"reason,omitempty"`
	Prerequisites []string         `json:"prerequisites,omitempty"`
	State         CoverageState    `json:"state"`
	Cursor        string           `json:"cursor,omitempty"`
	FailureReason string           `json:"failure_reason,omitempty"`
	Attempts      int              `json:"attempts,omitempty"`
	Resumable     bool             `json:"resumable"`
	EvidenceRef   string           `json:"evidence_ref"`
	ObservedAt    time.Time        `json:"observed_at,omitempty"`
}

// CoveragePlanSummary aggregates a plan for dashboards, recovery, and reruns.
type CoveragePlanSummary struct {
	TotalTargets       int                      `json:"total_targets"`
	EnabledTargets     int                      `json:"enabled_targets"`
	DisabledTargets    int                      `json:"disabled_targets"`
	AccountCount       int                      `json:"account_count"`
	RegionCount        int                      `json:"region_count"`
	ServiceCount       int                      `json:"service_count"`
	OutstandingTargets int                      `json:"outstanding_targets"`
	CoveredTargets     int                      `json:"covered_targets"`
	BlockedTargets     int                      `json:"blocked_targets"`
	FailedTargets      int                      `json:"failed_targets"`
	PermissionDenied   int                      `json:"permission_denied_targets"`
	ResumableTargets   int                      `json:"resumable_targets"`
	CoveragePercent    float64                  `json:"coverage_percent"`
	StateCounts        map[CoverageState]int    `json:"state_counts"`
	PriorityCounts     map[CoveragePriority]int `json:"priority_counts"`
	Prerequisites      []string                 `json:"prerequisites"`
}

// CoveragePlan is the deterministic output of the planner.
type CoveragePlan struct {
	ConnectorID string              `json:"connector_id,omitempty"`
	Version     string              `json:"version"`
	Targets     []CoverageTarget    `json:"targets"`
	Summary     CoveragePlanSummary `json:"summary"`
	GeneratedAt time.Time           `json:"generated_at"`
}

// PlanCoverage expands a connector coverage configuration into a deterministic,
// resumable set of account/region/service scan targets. It is a pure function:
// the same configuration and checkpoints always produce the same ordered plan,
// so persistence, dashboards, and fan-out reruns stay reconcilable. It performs
// no AWS calls and reads no customer payloads.
//
// A target is enabled only when its account, region, and service are all
// enabled. Global-scope services are planned once per account in their home
// region instead of being fanned out across every region. Prior checkpoints are
// replayed so a covered target stays covered and an interrupted target keeps its
// cursor. The most urgent priority among a target's account, region, and service
// wins, and targets are ordered by priority, then account, region, and service.
func PlanCoverage(config CoveragePlanConfig, generatedAt time.Time) (CoveragePlan, error) {
	accounts, err := normalizeCoverageAccounts(config.Accounts)
	if err != nil {
		return CoveragePlan{}, err
	}
	regions, err := normalizeCoverageRegions(config.Regions)
	if err != nil {
		return CoveragePlan{}, err
	}
	services, err := normalizeCoverageServices(config.Services)
	if err != nil {
		return CoveragePlan{}, err
	}
	checkpoints, err := indexCoverageCheckpoints(config.Checkpoints)
	if err != nil {
		return CoveragePlan{}, err
	}

	targets := []CoverageTarget{}
	seen := map[string]struct{}{}
	for _, account := range accounts {
		for _, service := range services {
			if service.Global {
				target := buildCoverageTarget(config.ConnectorID, account, globalCoverageRegion(service), service, checkpoints)
				appendCoverageTarget(&targets, seen, target)
				continue
			}
			for _, region := range regions {
				target := buildCoverageTarget(config.ConnectorID, account, region, service, checkpoints)
				appendCoverageTarget(&targets, seen, target)
			}
		}
	}

	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].PriorityRank != targets[j].PriorityRank {
			return targets[i].PriorityRank < targets[j].PriorityRank
		}
		return targets[i].Key < targets[j].Key
	})

	return CoveragePlan{
		ConnectorID: strings.TrimSpace(config.ConnectorID),
		Version:     CoveragePlannerVersion,
		Targets:     targets,
		Summary:     summarizeCoveragePlan(targets, len(accounts), len(regions), len(services)),
		GeneratedAt: generatedAt.UTC(),
	}, nil
}

// globalCoverageRegion synthesizes the home-region pseudo-region a global
// service is planned in. It is always enabled so a global service is never
// suppressed by a disabled member region; its prerequisites still apply.
func globalCoverageRegion(service CoverageService) CoverageRegion {
	home := strings.TrimSpace(service.HomeRegion)
	if home == "" {
		home = defaultGlobalServiceHomeRegion
	}
	return CoverageRegion{
		Region:  home,
		Name:    "global (" + home + ")",
		Enabled: true,
	}
}

func buildCoverageTarget(connectorID string, account CoverageAccount, region CoverageRegion, service CoverageService, checkpoints map[string]CoverageCheckpoint) CoverageTarget {
	enabled := account.Enabled && region.Enabled && service.Enabled
	priority, rank := mostUrgentCoveragePriority(account.Priority, region.Priority, service.Priority)
	prerequisites := mergeCoveragePrerequisites(account, region, service)

	target := CoverageTarget{
		Key:           coverageTargetKey(account.AccountID, region.Region, service.Service),
		AccountID:     account.AccountID,
		AccountName:   strings.TrimSpace(account.Name),
		Region:        region.Region,
		RegionName:    strings.TrimSpace(region.Name),
		Service:       service.Service,
		ServiceName:   strings.TrimSpace(service.Name),
		Global:        service.Global,
		Enabled:       enabled,
		Priority:      priority,
		PriorityRank:  rank,
		Reason:        composeCoverageReason(account, region, service),
		Prerequisites: prerequisites,
		EvidenceRef:   coverageEvidenceRef(connectorID, account.AccountID, region.Region, service.Service),
	}

	switch {
	case !enabled:
		target.State = CoverageStateDisabled
	case len(prerequisites) > 0:
		// Prerequisites that are not yet provably satisfied keep the target out of
		// the ready queue. A checkpoint can later promote it to a live state.
		target.State = CoverageStateBlocked
	default:
		target.State = CoverageStatePlanned
	}

	if checkpoint, ok := checkpoints[target.Key]; ok {
		applyCoverageCheckpoint(&target, checkpoint)
	}
	target.Resumable = coverageTargetResumable(target)
	return target
}

// applyCoverageCheckpoint replays a persisted target state. A disabled target
// stays disabled regardless of checkpoint so configuration always wins over a
// stale prior run.
func applyCoverageCheckpoint(target *CoverageTarget, checkpoint CoverageCheckpoint) {
	if !target.Enabled {
		return
	}
	if checkpoint.State == CoverageStateDisabled {
		return
	}
	if checkpoint.State != "" {
		target.State = checkpoint.State
	}
	target.Cursor = strings.TrimSpace(checkpoint.Cursor)
	target.FailureReason = strings.TrimSpace(checkpoint.FailureReason)
	if checkpoint.Attempts > 0 {
		target.Attempts = checkpoint.Attempts
	}
	if !checkpoint.ObservedAt.IsZero() {
		target.ObservedAt = checkpoint.ObservedAt.UTC()
	}
}

func coverageTargetResumable(target CoverageTarget) bool {
	switch target.State {
	case CoverageStateInProgress, CoverageStatePending, CoverageStateFailed, CoverageStatePartial:
		return true
	default:
		return false
	}
}

func appendCoverageTarget(targets *[]CoverageTarget, seen map[string]struct{}, target CoverageTarget) {
	if _, exists := seen[target.Key]; exists {
		return
	}
	seen[target.Key] = struct{}{}
	*targets = append(*targets, target)
}

func summarizeCoveragePlan(targets []CoverageTarget, accountCount, regionCount, serviceCount int) CoveragePlanSummary {
	summary := CoveragePlanSummary{
		TotalTargets:   len(targets),
		AccountCount:   accountCount,
		RegionCount:    regionCount,
		ServiceCount:   serviceCount,
		StateCounts:    map[CoverageState]int{},
		PriorityCounts: map[CoveragePriority]int{},
	}
	prerequisites := []string{}
	for _, target := range targets {
		summary.StateCounts[target.State]++
		summary.PriorityCounts[target.Priority]++
		if target.Enabled {
			summary.EnabledTargets++
		} else {
			summary.DisabledTargets++
		}
		if target.Resumable {
			summary.ResumableTargets++
		}
		switch target.State {
		case CoverageStateCovered:
			summary.CoveredTargets++
		case CoverageStateBlocked:
			summary.BlockedTargets++
		case CoverageStateFailed:
			summary.FailedTargets++
		case CoverageStatePermissionDenied:
			summary.PermissionDenied++
		}
		if target.Enabled && target.State != CoverageStateCovered {
			summary.OutstandingTargets++
		}
		prerequisites = append(prerequisites, target.Prerequisites...)
	}
	summary.Prerequisites = dedupeSortedCoverageStrings(prerequisites)
	if summary.EnabledTargets > 0 {
		summary.CoveragePercent = roundCoveragePercent(float64(summary.CoveredTargets) / float64(summary.EnabledTargets) * 100)
	}
	return summary
}

func normalizeCoverageAccounts(input []CoverageAccount) ([]CoverageAccount, error) {
	out := make([]CoverageAccount, 0, len(input))
	seen := map[string]struct{}{}
	for _, account := range input {
		accountID := strings.TrimSpace(account.AccountID)
		if !isTwelveDigitAWSAccountID(accountID) {
			return nil, fmt.Errorf("coverage account id %q must be 12 digits", account.AccountID)
		}
		if _, ok := seen[accountID]; ok {
			continue
		}
		seen[accountID] = struct{}{}
		account.AccountID = accountID
		account.Priority = NormalizeCoveragePriority(account.Priority)
		account.Prerequisites = dedupeSortedCoverageStrings(account.Prerequisites)
		out = append(out, account)
	}
	return out, nil
}

func normalizeCoverageRegions(input []CoverageRegion) ([]CoverageRegion, error) {
	out := make([]CoverageRegion, 0, len(input))
	seen := map[string]struct{}{}
	for _, region := range input {
		code := strings.ToLower(strings.TrimSpace(region.Region))
		if code == "" {
			return nil, fmt.Errorf("coverage region code is required")
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		region.Region = code
		region.Priority = NormalizeCoveragePriority(region.Priority)
		region.Prerequisites = dedupeSortedCoverageStrings(region.Prerequisites)
		out = append(out, region)
	}
	return out, nil
}

func normalizeCoverageServices(input []CoverageService) ([]CoverageService, error) {
	out := make([]CoverageService, 0, len(input))
	seen := map[string]struct{}{}
	for _, service := range input {
		name := strings.ToLower(strings.TrimSpace(service.Service))
		if name == "" {
			return nil, fmt.Errorf("coverage service name is required")
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		service.Service = name
		service.HomeRegion = strings.ToLower(strings.TrimSpace(service.HomeRegion))
		service.Priority = NormalizeCoveragePriority(service.Priority)
		service.Prerequisites = dedupeSortedCoverageStrings(service.Prerequisites)
		out = append(out, service)
	}
	return out, nil
}

func indexCoverageCheckpoints(input []CoverageCheckpoint) (map[string]CoverageCheckpoint, error) {
	index := make(map[string]CoverageCheckpoint, len(input))
	for _, checkpoint := range input {
		accountID := strings.TrimSpace(checkpoint.AccountID)
		region := strings.ToLower(strings.TrimSpace(checkpoint.Region))
		service := strings.ToLower(strings.TrimSpace(checkpoint.Service))
		if accountID == "" || region == "" || service == "" {
			return nil, fmt.Errorf("coverage checkpoint requires account, region, and service")
		}
		if checkpoint.State != "" && !validCoverageState(checkpoint.State) {
			return nil, fmt.Errorf("coverage checkpoint has invalid state %q", checkpoint.State)
		}
		key := coverageTargetKey(accountID, region, service)
		// Last checkpoint for a key wins; callers pass at most one per target.
		index[key] = checkpoint
	}
	return index, nil
}

// NormalizeCoveragePriority maps a raw priority onto the supported set,
// defaulting to normal.
func NormalizeCoveragePriority(priority CoveragePriority) CoveragePriority {
	switch CoveragePriority(strings.ToLower(strings.TrimSpace(string(priority)))) {
	case CoveragePriorityCritical:
		return CoveragePriorityCritical
	case CoveragePriorityHigh:
		return CoveragePriorityHigh
	case CoveragePriorityLow:
		return CoveragePriorityLow
	default:
		return CoveragePriorityNormal
	}
}

func coveragePriorityRank(priority CoveragePriority) int {
	switch NormalizeCoveragePriority(priority) {
	case CoveragePriorityCritical:
		return 0
	case CoveragePriorityHigh:
		return 1
	case CoveragePriorityLow:
		return 3
	default:
		return 2
	}
}

// mostUrgentCoveragePriority returns the most urgent (lowest rank) priority
// among the dimensions so a critical account or service is never buried behind a
// normal one.
func mostUrgentCoveragePriority(priorities ...CoveragePriority) (CoveragePriority, int) {
	best := CoveragePriorityLow
	bestRank := coveragePriorityRank(best)
	for _, priority := range priorities {
		if rank := coveragePriorityRank(priority); rank < bestRank {
			best = NormalizeCoveragePriority(priority)
			bestRank = rank
		}
	}
	return best, bestRank
}

func composeCoverageReason(account CoverageAccount, region CoverageRegion, service CoverageService) string {
	parts := []string{}
	if reason := strings.TrimSpace(account.Reason); reason != "" {
		parts = append(parts, "account: "+reason)
	}
	if reason := strings.TrimSpace(region.Reason); reason != "" {
		parts = append(parts, "region: "+reason)
	}
	if reason := strings.TrimSpace(service.Reason); reason != "" {
		parts = append(parts, "service: "+reason)
	}
	return strings.Join(parts, "; ")
}

// mergeCoveragePrerequisites unions the dimension prerequisites with derived
// prerequisites (opt-in region enablement, management-account scoping) so an
// operator sees exactly what must be true before the target can be scanned.
func mergeCoveragePrerequisites(account CoverageAccount, region CoverageRegion, service CoverageService) []string {
	prerequisites := []string{}
	prerequisites = append(prerequisites, account.Prerequisites...)
	prerequisites = append(prerequisites, region.Prerequisites...)
	prerequisites = append(prerequisites, service.Prerequisites...)
	if region.OptIn {
		prerequisites = append(prerequisites, fmt.Sprintf("opt-in region %s must be enabled on account %s", region.Region, account.AccountID))
	}
	if account.Management {
		prerequisites = append(prerequisites, fmt.Sprintf("management account %s requires organization read access", account.AccountID))
	}
	return dedupeSortedCoverageStrings(prerequisites)
}

func coverageTargetKey(accountID, region, service string) string {
	return strings.Join([]string{
		strings.TrimSpace(accountID),
		strings.ToLower(strings.TrimSpace(region)),
		strings.ToLower(strings.TrimSpace(service)),
	}, "|")
}

func coverageEvidenceRef(connectorID, accountID, region, service string) string {
	connector := strings.TrimSpace(connectorID)
	if connector == "" {
		connector = "connector"
	}
	return "aws:coverage:" + strings.Join([]string{
		connector,
		strings.TrimSpace(accountID),
		strings.ToLower(strings.TrimSpace(region)),
		strings.ToLower(strings.TrimSpace(service)),
	}, ":")
}

func validCoverageState(state CoverageState) bool {
	switch state {
	case CoverageStateDisabled, CoverageStateBlocked, CoverageStatePlanned, CoverageStatePending,
		CoverageStateInProgress, CoverageStateCovered, CoverageStatePartial, CoverageStateFailed,
		CoverageStatePermissionDenied, CoverageStateUnsupported:
		return true
	default:
		return false
	}
}

func dedupeSortedCoverageStrings(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func roundCoveragePercent(value float64) float64 {
	return float64(int64(value*100+0.5)) / 100
}

// DefaultCoverageServices returns the baseline AWS service partitions the
// machine-identity scanner plans for, with IAM marked global so it is planned
// once per account instead of per region. Callers may extend or override the
// catalog; it exists so operators and tests share one deterministic default.
func DefaultCoverageServices() []CoverageService {
	return []CoverageService{
		{Service: "iam", Name: "IAM roles and policies", Enabled: true, Priority: CoveragePriorityCritical, Global: true, HomeRegion: defaultGlobalServiceHomeRegion, Reason: "account-global machine identity inventory"},
		{Service: "ec2", Name: "EC2 instance profiles", Enabled: true, Priority: CoveragePriorityHigh, Reason: "compute workload identities"},
		{Service: "ecs", Name: "ECS task and execution roles", Enabled: true, Priority: CoveragePriorityHigh, Reason: "container workload identities"},
		{Service: "lambda", Name: "Lambda execution roles", Enabled: true, Priority: CoveragePriorityHigh, Reason: "serverless workload identities"},
		{Service: "eks", Name: "EKS workload identities", Enabled: true, Priority: CoveragePriorityNormal, Reason: "Kubernetes workload identities"},
		{Service: "secretsmanager", Name: "Secrets Manager references", Enabled: true, Priority: CoveragePriorityNormal, Reason: "credential reference mapping"},
	}
}
