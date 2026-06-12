package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const awsCoveragePlannerCurrentIssue = 1501
const awsCoveragePlannerGlobalServiceHomeRegion = "us-east-1"
const awsCoverageScanCursorTTL = 24 * time.Hour
const awsCoveragePlannerAccountRegionPageSize = 250

// AWSCoveragePlanRequest filters and pins the account/region coverage plan.
type AWSCoveragePlanRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	// Account filters targets to one 12-digit AWS account id.
	Account string `json:"account,omitempty"`
	// Region filters targets to one AWS region code.
	Region string `json:"region,omitempty"`
	// Service filters targets to one AWS service partition (for example iam, lambda).
	Service string `json:"service,omitempty"`
	// State filters targets to one coverage lifecycle state.
	State string `json:"state,omitempty"`
}

// AWSCoveragePlanTarget is one operator-visible account/region/service scan unit.
type AWSCoveragePlanTarget struct {
	Key           string    `json:"key"`
	AccountID     string    `json:"account_id"`
	AccountName   string    `json:"account_name,omitempty"`
	Region        string    `json:"region"`
	RegionName    string    `json:"region_name,omitempty"`
	Service       string    `json:"service"`
	ServiceName   string    `json:"service_name,omitempty"`
	Collector     string    `json:"collector,omitempty"`
	Global        bool      `json:"global"`
	Enabled       bool      `json:"enabled"`
	Priority      string    `json:"priority"`
	PriorityRank  int       `json:"priority_rank"`
	Reason        string    `json:"reason,omitempty"`
	Prerequisites []string  `json:"prerequisites"`
	State         string    `json:"state"`
	Cursor        string    `json:"cursor,omitempty"`
	FailureReason string    `json:"failure_reason,omitempty"`
	Attempts      int       `json:"attempts,omitempty"`
	Resumable     bool      `json:"resumable"`
	NextAction    string    `json:"next_action"`
	EvidenceRef   string    `json:"evidence_ref"`
	ObservedAt    time.Time `json:"observed_at,omitempty"`
}

// AWSCoveragePlanSummary mirrors the planner summary for dashboards.
type AWSCoveragePlanSummary struct {
	TotalTargets       int            `json:"total_targets"`
	EnabledTargets     int            `json:"enabled_targets"`
	DisabledTargets    int            `json:"disabled_targets"`
	AccountCount       int            `json:"account_count"`
	RegionCount        int            `json:"region_count"`
	ServiceCount       int            `json:"service_count"`
	OutstandingTargets int            `json:"outstanding_targets"`
	CoveredTargets     int            `json:"covered_targets"`
	BlockedTargets     int            `json:"blocked_targets"`
	FailedTargets      int            `json:"failed_targets"`
	PermissionDenied   int            `json:"permission_denied_targets"`
	ResumableTargets   int            `json:"resumable_targets"`
	CoveragePercent    float64        `json:"coverage_percent"`
	StateCounts        map[string]int `json:"state_counts"`
	PriorityCounts     map[string]int `json:"priority_counts"`
	Prerequisites      []string       `json:"prerequisites"`
}

// AWSCoveragePlanDiagnostic carries a deterministic planning/execution failure.
type AWSCoveragePlanDiagnostic struct {
	Source      string `json:"source"`
	Scope       string `json:"scope,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSCoveragePlanCoverageGap names an explicit limit of the planner.
type AWSCoveragePlanCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSCoveragePlanResult is the full account/region coverage planning response.
type AWSCoveragePlanResult struct {
	TenantID           string                       `json:"tenant_id"`
	WorkspaceID        string                       `json:"workspace_id"`
	ProjectID          string                       `json:"project_id"`
	ConnectorID        string                       `json:"connector_id,omitempty"`
	AccountID          string                       `json:"account_id,omitempty"`
	Region             string                       `json:"region,omitempty"`
	ParentIssueNumber  int                          `json:"parent_issue_number"`
	ParentIssueRef     string                       `json:"parent_issue_ref"`
	CurrentIssueNumber int                          `json:"current_issue_number"`
	CurrentIssueRef    string                       `json:"current_issue_ref"`
	Version            string                       `json:"version"`
	Status             string                       `json:"status"`
	FixtureState       string                       `json:"fixture_state,omitempty"`
	Confidence         float64                      `json:"confidence"`
	FilteredTargets    int                          `json:"filtered_targets"`
	Summary            AWSCoveragePlanSummary       `json:"summary"`
	Targets            []AWSCoveragePlanTarget      `json:"targets"`
	FailureReasons     []string                     `json:"failure_reasons"`
	RemediationHints   []string                     `json:"remediation_hints"`
	EvidenceLinks      []string                     `json:"evidence_links"`
	CoverageGaps       []AWSCoveragePlanCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSCoveragePlanDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
}

// GetAWSCoveragePlan returns the deterministic account/region/service coverage
// plan for a project's AWS connector. It is read-only and metadata-only: it
// reads no customer payloads and mutates no AWS state.
func (s *Service) GetAWSCoveragePlan(ctx context.Context, workspaceID string, projectID string, request AWSCoveragePlanRequest) (AWSCoveragePlanResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSCoveragePlanResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSCoveragePlanResult{}, err
	}
	coverageRows := []db.AWSAccountRegionCoverage{}
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection {
		coverageRows, err = awsCoverageListRows(ctx, s.Store, db.AWSAccountRegionCoverageFilter{
			WorkspaceID: project.WorkspaceID,
			ProjectID:   project.ProjectID,
			ConnectorID: strings.TrimSpace(connection.ConnectorID),
			Limit:       awsCoveragePlannerAccountRegionPageSize,
		})
		if err != nil {
			return AWSCoveragePlanResult{}, err
		}
	}
	return buildAWSCoveragePlan(scope, project, connection, hasConnection, request, coverageRows, s.Now().UTC())
}

func buildAWSCoveragePlan(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSCoveragePlanRequest, coverageRows []db.AWSAccountRegionCoverage, checkedAt time.Time) (AWSCoveragePlanResult, error) {
	fixtureState := normalizeAWSCoveragePlanFixtureState(request.FixtureState, connection, hasConnection)
	if strings.TrimSpace(request.FixtureState) != "" && fixtureState == "" {
		return AWSCoveragePlanResult{}, ErrInvalidAWSConnectionRequest
	}
	if !validAWSCoveragePlanStateFilter(request.State) {
		return AWSCoveragePlanResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(strings.TrimSpace(connection.AccountID), "111111111111")
	region := firstNonEmptyAWSValue(strings.TrimSpace(connection.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(strings.TrimSpace(connection.ConnectorID), strings.TrimSpace(request.ConnectorID), "aws-fixture")

	var config awscontract.CoveragePlanConfig
	var diagnostics []AWSCoveragePlanDiagnostic
	var gaps []AWSCoveragePlanCoverageGap
	if fixtureState != "" {
		config, diagnostics, gaps = awsCoveragePlanFixtureConfig(connectorID, accountID, region, fixtureState)
	} else {
		config, diagnostics, gaps = awsCoveragePlanLiveConfig(connectorID, accountID, region, hasConnection, connection.Connected, coverageRows, checkedAt)
	}
	plan, err := awscontract.PlanCoverage(config, checkedAt)
	if err != nil {
		return AWSCoveragePlanResult{}, err
	}
	summary := mapAWSCoveragePlanSummary(plan.Summary)
	targets := mapAWSCoveragePlanTargets(plan.Targets)
	filtered := filterAWSCoveragePlanTargets(targets, request)
	status, confidence, failures, remediations := summarizeAWSCoveragePlan(fixtureState, diagnostics, plan)

	return AWSCoveragePlanResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsCoveragePlannerCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsCoveragePlannerCurrentIssue),
		Version:            plan.Version,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		FilteredTargets:    len(filtered),
		Summary:            summary,
		Targets:            filtered,
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsCoveragePlannerCurrentIssue),
			"/docs/aws-account-region-coverage-planner",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: gaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}, nil
}

func normalizeAWSCoveragePlanFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		return ""
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsCoveragePlanLiveConfig(connectorID, connectionAccountID, connectionRegion string, hasConnection bool, connected bool, rows []db.AWSAccountRegionCoverage, checkedAt time.Time) (awscontract.CoveragePlanConfig, []AWSCoveragePlanDiagnostic, []AWSCoveragePlanCoverageGap) {
	gaps := []AWSCoveragePlanCoverageGap{
		{
			Capability:  "secret_value_inspection",
			Status:      "unsupported",
			Reason:      "Coverage planning reads no customer payloads, secret values, or object contents; it only plans where read-only collectors will run.",
			Remediation: "Inspect values through the owning service outside Identrail.",
		},
	}
	diagnostics := []AWSCoveragePlanDiagnostic{}
	if hasConnection && !connected {
		diagnostics = append(diagnostics, AWSCoveragePlanDiagnostic{
			Source:      "coverage_planner",
			Scope:       connectorID,
			Code:        "permission_denied",
			Message:     "AWS connector is not currently healthy enough to plan live scan cursors.",
			Remediation: "Repair the AWS connector role or health checks, then rerun the coverage plan.",
			Retryable:   false,
		})
	}
	if len(rows) == 0 {
		return awscontract.CoveragePlanConfig{ConnectorID: connectorID}, diagnostics, gaps
	}

	accountsByID := map[string]awscontract.CoverageAccount{}
	regionsByID := map[string]awscontract.CoverageRegion{}
	serviceNames := map[string]struct{}{}
	checkpoints := []awscontract.CoverageCheckpoint{}
	regionAvailability := []awscontract.CoverageAccountRegionAvailability{}
	persistedAccountRegions := map[string]struct{}{}

	for _, row := range rows {
		accountID := strings.TrimSpace(row.AccountID)
		region := strings.ToLower(strings.TrimSpace(row.Region))
		if accountID == "" || region == "" {
			continue
		}
		persistedAccountRegions[awsCoverageAccountRegionKey(accountID, region)] = struct{}{}
		account := accountsByID[accountID]
		account.AccountID = accountID
		account.Enabled = true
		account.Name = firstNonEmptyAWSValue(strings.TrimSpace(row.AccountAlias), account.Name)
		account.Priority = awsCoverageAccountPriority(accountID, connectionAccountID)
		account.Reason = firstNonEmptyAWSValue(account.Reason, "persisted account/region coverage")
		account.Management = accountID == strings.TrimSpace(connectionAccountID)
		accountsByID[accountID] = account

		coverageRegion := regionsByID[region]
		coverageRegion.Region = region
		coverageRegion.Enabled = true
		coverageRegion.Priority = awsCoverageRegionPriority(region, connectionRegion)
		coverageRegion.Reason = firstNonEmptyAWSValue(coverageRegion.Reason, "persisted account/region coverage")
		regionsByID[region] = coverageRegion

		if availability := awsCoverageAvailabilityFromRow(row, checkedAt); availability.State != "" {
			regionAvailability = append(regionAvailability, availability)
		}
		rowCheckpoints, rowDiagnostics, rowServices := awsCoverageCheckpointsFromScanCursor(row, checkedAt)
		checkpoints = append(checkpoints, rowCheckpoints...)
		diagnostics = append(diagnostics, rowDiagnostics...)
		for _, service := range rowServices {
			serviceNames[service] = struct{}{}
		}
	}

	accounts := make([]awscontract.CoverageAccount, 0, len(accountsByID))
	for _, account := range accountsByID {
		accounts = append(accounts, account)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].AccountID < accounts[j].AccountID })

	regions := make([]awscontract.CoverageRegion, 0, len(regionsByID))
	for _, region := range regionsByID {
		regions = append(regions, region)
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].Region < regions[j].Region })

	services := awsCoverageServicesWithDiscovered(serviceNames)
	serviceAvailability := awsCoverageMissingAccountRegionServiceAvailability(accounts, regions, services, persistedAccountRegions, checkedAt)
	return awscontract.CoveragePlanConfig{
		ConnectorID:         connectorID,
		Accounts:            accounts,
		Regions:             regions,
		RegionAvailability:  regionAvailability,
		ServiceAvailability: serviceAvailability,
		Services:            services,
		Checkpoints:         checkpoints,
	}, diagnostics, gaps
}

func validAWSCoveragePlanStateFilter(state string) bool {
	switch awscontract.CoverageState(strings.ToLower(strings.TrimSpace(state))) {
	case "",
		awscontract.CoverageStateDisabled, awscontract.CoverageStateBlocked, awscontract.CoverageStatePlanned,
		awscontract.CoverageStatePending, awscontract.CoverageStateInProgress, awscontract.CoverageStateCovered,
		awscontract.CoverageStatePartial, awscontract.CoverageStateFailed, awscontract.CoverageStatePermissionDenied,
		awscontract.CoverageStateUnsupported:
		return true
	default:
		return false
	}
}

func awsCoverageAccountPriority(accountID, connectionAccountID string) awscontract.CoveragePriority {
	if strings.TrimSpace(accountID) == strings.TrimSpace(connectionAccountID) {
		return awscontract.CoveragePriorityCritical
	}
	return awscontract.CoveragePriorityHigh
}

func awsCoverageRegionPriority(region, connectionRegion string) awscontract.CoveragePriority {
	if strings.EqualFold(strings.TrimSpace(region), strings.TrimSpace(connectionRegion)) {
		return awscontract.CoveragePriorityHigh
	}
	return awscontract.CoveragePriorityNormal
}

func awsCoverageMissingAccountRegionServiceAvailability(accounts []awscontract.CoverageAccount, regions []awscontract.CoverageRegion, services []awscontract.CoverageService, persisted map[string]struct{}, checkedAt time.Time) []awscontract.CoverageAccountServiceAvailability {
	availability := []awscontract.CoverageAccountServiceAvailability{}
	for _, account := range accounts {
		accountID := strings.TrimSpace(account.AccountID)
		if accountID == "" {
			continue
		}
		for _, region := range regions {
			regionName := strings.ToLower(strings.TrimSpace(region.Region))
			if regionName == "" {
				continue
			}
			if _, ok := persisted[awsCoverageAccountRegionKey(accountID, regionName)]; ok {
				continue
			}
			for _, service := range services {
				if service.Global {
					continue
				}
				serviceName := strings.ToLower(strings.TrimSpace(service.Service))
				if serviceName == "" {
					continue
				}
				availability = append(availability, awscontract.CoverageAccountServiceAvailability{
					AccountID:   accountID,
					Region:      regionName,
					Service:     serviceName,
					State:       awscontract.CoverageStateBlocked,
					Reason:      "no persisted account/region coverage row for this pair",
					EvidenceRef: "aws:coverage:" + strings.Join([]string{accountID, regionName, serviceName}, ":"),
					ObservedAt:  checkedAt,
				})
			}
		}
	}
	return availability
}

func awsCoverageAccountRegionKey(accountID string, region string) string {
	return strings.TrimSpace(accountID) + "|" + strings.ToLower(strings.TrimSpace(region))
}

func awsCoverageAvailabilityFromRow(row db.AWSAccountRegionCoverage, checkedAt time.Time) awscontract.CoverageAccountRegionAvailability {
	status := strings.ToLower(strings.TrimSpace(row.CoverageStatus))
	reason := ""
	state := awscontract.CoverageState("")
	switch {
	case row.Disabled || status == db.AWSAccountRegionCoverageDisabled:
		state = awscontract.CoverageStateDisabled
		reason = "account/region scanning disabled in connector coverage"
	case row.Suspended || status == db.AWSAccountRegionCoverageSuspended:
		state = awscontract.CoverageStateBlocked
		reason = "aws account is suspended"
	case row.Unreachable || status == db.AWSAccountRegionCoverageUnreachable:
		state = awscontract.CoverageStateBlocked
		reason = "account/region is unreachable from the connector role"
	case status == db.AWSAccountRegionCoverageGap:
		state = awscontract.CoverageStateBlocked
		reason = "coverage gap recorded for this account/region"
	case status == db.AWSAccountRegionCoverageError && awsCoverageErrorLooksDenied(row):
		state = awscontract.CoverageStatePermissionDenied
		reason = "aws denied read-only account/region coverage"
	case status == db.AWSAccountRegionCoverageError:
		state = awscontract.CoverageStateBlocked
		reason = "account/region coverage has an unresolved collection error"
	}
	if state == "" {
		return awscontract.CoverageAccountRegionAvailability{}
	}
	failure := strings.TrimSpace(row.LastObservedErrorMessage)
	if failure == "" {
		failure = strings.TrimSpace(row.LastObservedErrorCode)
	}
	observedAt := row.UpdatedAt
	if observedAt.IsZero() {
		observedAt = checkedAt
	}
	return awscontract.CoverageAccountRegionAvailability{
		AccountID:     row.AccountID,
		Region:        row.Region,
		State:         state,
		Reason:        reason,
		FailureReason: failure,
		EvidenceRef:   awsCoverageRowEvidenceRef(row),
		ObservedAt:    observedAt.UTC(),
	}
}

func awsCoverageErrorLooksDenied(row db.AWSAccountRegionCoverage) bool {
	combined := strings.ToLower(strings.TrimSpace(row.LastObservedErrorCode + " " + row.LastObservedErrorMessage))
	return strings.Contains(combined, "accessdenied") ||
		strings.Contains(combined, "access denied") ||
		strings.Contains(combined, "unauthorized") ||
		strings.Contains(combined, "permission")
}

func awsCoverageCheckpointsFromScanCursor(row db.AWSAccountRegionCoverage, checkedAt time.Time) ([]awscontract.CoverageCheckpoint, []AWSCoveragePlanDiagnostic, []string) {
	entries := awsCoverageCursorEntries(row.ScanCursor)
	checkpoints := []awscontract.CoverageCheckpoint{}
	diagnostics := []AWSCoveragePlanDiagnostic{}
	services := []string{}
	for _, entry := range entries {
		service := strings.ToLower(strings.TrimSpace(entry.service))
		if service == "" {
			continue
		}
		state, ok := awsCoverageCursorState(entry.fields)
		if !ok {
			diagnostics = append(diagnostics, awsCoverageCursorDiagnostic(row, service, "malformed_cursor", "Scan cursor entry does not contain a supported coverage state.", false))
			continue
		}
		observedFallback := row.UpdatedAt
		if observedFallback.IsZero() {
			observedFallback = checkedAt
		}
		observedAt := awsCoverageCursorTime(entry.fields, observedFallback)
		if awsCoverageCursorExpired(state, observedAt, checkedAt) {
			diagnostics = append(diagnostics, awsCoverageCursorDiagnostic(row, service, "stale_cursor_expired", "Stored scan cursor is stale and will not be reused for continuation.", true))
			services = append(services, service)
			continue
		}
		checkpoints = append(checkpoints, awscontract.CoverageCheckpoint{
			AccountID:     row.AccountID,
			Region:        awsCoverageCheckpointRegion(service, row.Region),
			Service:       service,
			Collector:     firstNonEmptyAWSValue(awsCoverageCursorString(entry.fields, "collector"), entry.collector),
			State:         state,
			Cursor:        awsCoverageCursorString(entry.fields, "cursor"),
			FailureReason: firstNonEmptyAWSValue(awsCoverageCursorString(entry.fields, "failure_reason"), awsCoverageCursorString(entry.fields, "error"), awsCoverageCursorString(entry.fields, "message")),
			Attempts:      awsCoverageCursorInt(entry.fields, "attempts"),
			ObservedAt:    observedAt,
		})
		services = append(services, service)
	}
	return checkpoints, diagnostics, dedupeStrings(services)
}

func awsCoverageCheckpointRegion(service string, rowRegion string) string {
	service = strings.ToLower(strings.TrimSpace(service))
	for _, defaultService := range awscontract.DefaultCoverageServices() {
		if strings.ToLower(strings.TrimSpace(defaultService.Service)) != service || !defaultService.Global {
			continue
		}
		return firstNonEmptyAWSValue(strings.ToLower(strings.TrimSpace(defaultService.HomeRegion)), awsCoveragePlannerGlobalServiceHomeRegion)
	}
	return strings.ToLower(strings.TrimSpace(rowRegion))
}

func awsCoverageListRows(ctx context.Context, store db.Store, filter db.AWSAccountRegionCoverageFilter) ([]db.AWSAccountRegionCoverage, error) {
	if filter.Limit <= 0 {
		filter.Limit = awsCoveragePlannerAccountRegionPageSize
	}
	allRows := []db.AWSAccountRegionCoverage{}
	for offset := 0; ; offset += filter.Limit {
		filter.Offset = offset
		batch, err := store.ListAWSAccountRegionCoverages(ctx, filter)
		if err != nil {
			return nil, err
		}
		allRows = append(allRows, batch...)
		if len(batch) < filter.Limit {
			break
		}
	}
	return allRows, nil
}

type awsCoverageCursorEntry struct {
	service   string
	collector string
	fields    map[string]any
}

func awsCoverageCursorEntries(cursor map[string]any) []awsCoverageCursorEntry {
	if len(cursor) == 0 {
		return nil
	}
	entries := []awsCoverageCursorEntry{}
	for _, key := range []string{"services", "service_cursors", "checkpoints", "cursors"} {
		if nested, ok := cursor[key].(map[string]any); ok {
			entries = append(entries, awsCoverageCursorEntriesFromMap(nested)...)
		}
	}
	entries = append(entries, awsCoverageCursorEntriesFromMap(cursor)...)
	return entries
}

func awsCoverageCursorEntriesFromMap(input map[string]any) []awsCoverageCursorEntry {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []awsCoverageCursorEntry{}
	for _, key := range keys {
		if awsCoverageCursorMetaKey(key) {
			continue
		}
		fields, ok := input[key].(map[string]any)
		if !ok {
			continue
		}
		service, collector := awsCoverageSplitCursorKey(key)
		out = append(out, awsCoverageCursorEntry{service: service, collector: collector, fields: fields})
	}
	return out
}

func awsCoverageCursorMetaKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "", "cursor", "next_token", "token", "state", "status", "attempts", "observed_at", "updated_at", "collector", "failure_reason", "error", "message",
		"services", "service_cursors", "checkpoints", "cursors":
		return true
	default:
		return false
	}
}

func awsCoverageSplitCursorKey(key string) (string, string) {
	parts := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(key)), func(r rune) bool {
		return r == ':' || r == '/' || r == '|'
	})
	if len(parts) == 0 {
		return "", ""
	}
	service := strings.TrimSpace(parts[0])
	collector := ""
	if len(parts) > 1 {
		collector = strings.Join(parts[1:], ":")
	}
	return service, collector
}

func awsCoverageCursorState(fields map[string]any) (awscontract.CoverageState, bool) {
	raw := strings.ToLower(firstNonEmptyAWSValue(awsCoverageCursorString(fields, "state"), awsCoverageCursorString(fields, "status")))
	switch raw {
	case "planned":
		return awscontract.CoverageStatePlanned, true
	case "pending", "queued":
		return awscontract.CoverageStatePending, true
	case "in_progress", "running", "started":
		return awscontract.CoverageStateInProgress, true
	case "covered", "complete", "completed", "success", "succeeded":
		return awscontract.CoverageStateCovered, true
	case "partial", "partial_failure":
		return awscontract.CoverageStatePartial, true
	case "failed", "failure", "error", "throttled":
		return awscontract.CoverageStateFailed, true
	case "permission_denied", "access_denied", "denied":
		return awscontract.CoverageStatePermissionDenied, true
	case "unsupported":
		return awscontract.CoverageStateUnsupported, true
	case "blocked":
		return awscontract.CoverageStateBlocked, true
	case "disabled":
		return awscontract.CoverageStateDisabled, true
	default:
		return "", false
	}
}

func awsCoverageCursorExpired(state awscontract.CoverageState, observedAt time.Time, checkedAt time.Time) bool {
	switch state {
	case awscontract.CoverageStatePending, awscontract.CoverageStateInProgress, awscontract.CoverageStatePartial, awscontract.CoverageStateFailed:
	default:
		return false
	}
	if observedAt.IsZero() {
		return false
	}
	return !observedAt.Add(awsCoverageScanCursorTTL).After(checkedAt)
}

func awsCoverageCursorString(fields map[string]any, key string) string {
	raw, ok := fields[key]
	if !ok || raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	case []byte:
		return strings.TrimSpace(string(value))
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func awsCoverageCursorInt(fields map[string]any, key string) int {
	raw, ok := fields[key]
	if !ok || raw == nil {
		return 0
	}
	switch value := raw.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		parsed, _ := strconv.Atoi(value.String())
		return parsed
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(value))
		return parsed
	default:
		return 0
	}
}

func awsCoverageCursorTime(fields map[string]any, fallback time.Time) time.Time {
	for _, key := range []string{"observed_at", "updated_at", "checked_at"} {
		raw := awsCoverageCursorString(fields, key)
		if raw == "" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return parsed.UTC()
		}
	}
	return fallback.UTC()
}

func awsCoverageCursorDiagnostic(row db.AWSAccountRegionCoverage, service string, code string, message string, retryable bool) AWSCoveragePlanDiagnostic {
	return AWSCoveragePlanDiagnostic{
		Source:      "scan_cursor",
		Scope:       strings.Join([]string{row.AccountID, strings.ToLower(strings.TrimSpace(row.Region)), strings.ToLower(strings.TrimSpace(service))}, "/"),
		Code:        code,
		Message:     message,
		Remediation: "Refresh this account/region/service scan so Identrail can write a current checkpoint.",
		Retryable:   retryable,
	}
}

func awsCoverageServicesWithDiscovered(discovered map[string]struct{}) []awscontract.CoverageService {
	services := awscontract.DefaultCoverageServices()
	seen := map[string]struct{}{}
	for _, service := range services {
		seen[strings.ToLower(strings.TrimSpace(service.Service))] = struct{}{}
	}
	names := make([]string, 0, len(discovered))
	for service := range discovered {
		service = strings.ToLower(strings.TrimSpace(service))
		if service == "" {
			continue
		}
		if _, ok := seen[service]; ok {
			continue
		}
		names = append(names, service)
	}
	sort.Strings(names)
	for _, service := range names {
		services = append(services, awscontract.CoverageService{
			Service: service,
			Name:    service,
			Enabled: true,
			Reason:  "persisted scan cursor service",
		})
	}
	return services
}

func awsCoverageRowEvidenceRef(row db.AWSAccountRegionCoverage) string {
	return "aws:coverage:" + strings.Join([]string{
		strings.TrimSpace(row.ConnectorID),
		strings.TrimSpace(row.AccountID),
		strings.ToLower(strings.TrimSpace(row.Region)),
	}, ":")
}

// awsCoveragePlanFixtureConfig returns the deterministic connector coverage
// configuration, prior checkpoints, diagnostics, and gaps for a fixture state.
// The configuration is fed to the real planner so the API exercises the same
// code path operators will run against live connectors.
func awsCoveragePlanFixtureConfig(connectorID, accountID, region, fixtureState string) (awscontract.CoveragePlanConfig, []AWSCoveragePlanDiagnostic, []AWSCoveragePlanCoverageGap) {
	gaps := []AWSCoveragePlanCoverageGap{
		{
			Capability:  "live_account_discovery",
			Status:      "out_of_scope",
			Reason:      "The planner accepts per-account region and service availability overrides for this issue, while organization-driven account discovery remains an upstream dependency.",
			Remediation: "Populate accounts and regions from connector configuration or organization discovery before planning.",
		},
		{
			Capability:  "secret_value_inspection",
			Status:      "unsupported",
			Reason:      "Coverage planning reads no customer payloads, secret values, or object contents; it only plans where read-only collectors will run.",
			Remediation: "Inspect values through the owning service outside Identrail.",
		},
	}

	if fixtureState == "empty" {
		return awscontract.CoveragePlanConfig{ConnectorID: connectorID}, nil, gaps
	}

	secondaryAccount := awsCoveragePlanSiblingAccount(accountID)
	config := awscontract.CoveragePlanConfig{
		ConnectorID: connectorID,
		Accounts: []awscontract.CoverageAccount{
			{AccountID: accountID, Name: "production", Enabled: true, Priority: awscontract.CoveragePriorityCritical, Management: true, Reason: "primary production estate"},
			{AccountID: secondaryAccount, Name: "data", Enabled: true, Priority: awscontract.CoveragePriorityHigh, Reason: "regulated data workloads"},
			{AccountID: "999999999999", Name: "retired-sandbox", Enabled: false, Reason: "account decommissioned"},
		},
		Regions: []awscontract.CoverageRegion{
			{Region: region, Enabled: true, Priority: awscontract.CoveragePriorityHigh, Reason: "connector home region"},
			{Region: awsCoveragePlanSecondaryRegion(region), Enabled: true, Reason: "secondary workload region"},
			{Region: "ap-east-1", Enabled: false, OptIn: true, Reason: "opt-in region not enabled"},
		},
		Services: awscontract.DefaultCoverageServices(),
	}

	diagnostics := []AWSCoveragePlanDiagnostic{}
	// Capability examples: explicit account-region and account-region-service availability
	// signals are surfaced here so the UI can show opt-in blocked, unsupported,
	// and permission-denied behavior before live discovery is implemented.
	if fixtureState == "degraded" || fixtureState == "partial_failure" || fixtureState == "permission_denied" {
		config.RegionAvailability = []awscontract.CoverageAccountRegionAvailability{{
			AccountID:   accountID,
			Region:      awsCoveragePlanSecondaryRegion(region),
			State:       awscontract.CoverageStateBlocked,
			Reason:      "member account has not enabled the secondary region",
			EvidenceRef: "/docs/aws-account-region-coverage-planner",
		}}
		config.ServiceAvailability = []awscontract.CoverageAccountServiceAvailability{{
			AccountID:   secondaryAccount,
			Region:      region,
			Service:     "ecs",
			State:       awscontract.CoverageStateUnsupported,
			Reason:      "ecs inventory is not supported in this exact account-region pairing",
			EvidenceRef: "/docs/aws-service-collector-contract#ecs",
		}}
	}

	switch fixtureState {
	case "permission_denied":
		config.Checkpoints = []awscontract.CoverageCheckpoint{{
			AccountID: secondaryAccount, Service: "iam",
			Region: awsCoveragePlannerGlobalServiceHomeRegion,
			State:  awscontract.CoverageStatePermissionDenied, FailureReason: "AccessDenied: iam:ListRoles denied in member account",
		}}
		diagnostics = append(diagnostics, AWSCoveragePlanDiagnostic{
			Source:      "coverage_planner",
			Scope:       secondaryAccount + "/" + region + "/iam",
			Code:        "permission_denied",
			Message:     "Connector role cannot assume into account " + secondaryAccount + " for read-only IAM enumeration.",
			Remediation: "Deploy the read-only collector role into the member account and re-run the plan.",
			Retryable:   false,
		})
	case "degraded", "partial_failure":
		config.Checkpoints = []awscontract.CoverageCheckpoint{
			{AccountID: accountID, Region: region, Service: "iam", State: awscontract.CoverageStateCovered},
			{AccountID: accountID, Region: region, Service: "lambda", State: awscontract.CoverageStateCovered},
			{AccountID: secondaryAccount, Region: awsCoveragePlanSecondaryRegion(region), Service: "ecs", State: awscontract.CoverageStateFailed, FailureReason: "Throttling: ecs:ListServices throttled after retries", Attempts: 3},
			{AccountID: secondaryAccount, Region: region, Service: "lambda", State: awscontract.CoverageStateInProgress, Cursor: "marker:page-3", Attempts: 1},
		}
		diagnostics = append(diagnostics, AWSCoveragePlanDiagnostic{
			Source:      "coverage_planner",
			Scope:       secondaryAccount + "/" + awsCoveragePlanSecondaryRegion(region) + "/ecs",
			Code:        "partial_failure",
			Message:     "ecs:ListServices was throttled after bounded retries; this target is resumable.",
			Remediation: "Re-run the plan to resume the failed target from its checkpoint.",
			Retryable:   true,
		})
	default:
		// Success: mark a couple of targets covered so coverage percent is meaningful.
		config.Checkpoints = []awscontract.CoverageCheckpoint{
			{AccountID: accountID, Region: region, Service: "iam", State: awscontract.CoverageStateCovered},
			{AccountID: accountID, Region: region, Service: "ec2", State: awscontract.CoverageStateCovered},
			{AccountID: accountID, Region: region, Service: "lambda", State: awscontract.CoverageStateCovered},
		}
	}
	return config, diagnostics, gaps
}

func mapAWSCoveragePlanTargets(targets []awscontract.CoverageTarget) []AWSCoveragePlanTarget {
	out := make([]AWSCoveragePlanTarget, 0, len(targets))
	for _, target := range targets {
		prerequisites := target.Prerequisites
		if prerequisites == nil {
			prerequisites = []string{}
		}
		out = append(out, AWSCoveragePlanTarget{
			Key:           target.Key,
			AccountID:     target.AccountID,
			AccountName:   target.AccountName,
			Region:        target.Region,
			RegionName:    target.RegionName,
			Service:       target.Service,
			ServiceName:   target.ServiceName,
			Collector:     target.Collector,
			Global:        target.Global,
			Enabled:       target.Enabled,
			Priority:      string(target.Priority),
			PriorityRank:  target.PriorityRank,
			Reason:        target.Reason,
			Prerequisites: prerequisites,
			State:         string(target.State),
			Cursor:        target.Cursor,
			FailureReason: target.FailureReason,
			Attempts:      target.Attempts,
			Resumable:     target.Resumable,
			NextAction:    awsCoveragePlanNextAction(target),
			EvidenceRef:   target.EvidenceRef,
			ObservedAt:    target.ObservedAt,
		})
	}
	return out
}

// awsCoveragePlanNextAction translates a target state into the operator's next
// step so the app surface never requires reading logs to decide what to do.
func awsCoveragePlanNextAction(target awscontract.CoverageTarget) string {
	switch target.State {
	case awscontract.CoverageStateDisabled:
		return "Enable the account, region, and service in connector coverage configuration to scan this target."
	case awscontract.CoverageStateBlocked:
		return "Satisfy prerequisites (member-account onboarding or opt-in region enablement) before this target can be scanned."
	case awscontract.CoverageStateCovered:
		return "No action required; rescan on the next scheduled coverage run."
	case awscontract.CoverageStateFailed, awscontract.CoverageStatePartial:
		return "Re-run the plan to resume this target from its checkpoint."
	case awscontract.CoverageStateInProgress, awscontract.CoverageStatePending:
		return "Scan in flight; wait for the fan-out worker to advance this target."
	case awscontract.CoverageStatePermissionDenied:
		return "Grant the read-only collector role access in this account/region and re-run the plan."
	case awscontract.CoverageStateUnsupported:
		return "Remove the unsupported region/service from coverage configuration."
	default:
		return "Queue this target for the next coverage scan run."
	}
}

func mapAWSCoveragePlanSummary(summary awscontract.CoveragePlanSummary) AWSCoveragePlanSummary {
	stateCounts := map[string]int{}
	for state, count := range summary.StateCounts {
		stateCounts[string(state)] = count
	}
	priorityCounts := map[string]int{}
	for priority, count := range summary.PriorityCounts {
		priorityCounts[string(priority)] = count
	}
	prerequisites := summary.Prerequisites
	if prerequisites == nil {
		prerequisites = []string{}
	}
	return AWSCoveragePlanSummary{
		TotalTargets:       summary.TotalTargets,
		EnabledTargets:     summary.EnabledTargets,
		DisabledTargets:    summary.DisabledTargets,
		AccountCount:       summary.AccountCount,
		RegionCount:        summary.RegionCount,
		ServiceCount:       summary.ServiceCount,
		OutstandingTargets: summary.OutstandingTargets,
		CoveredTargets:     summary.CoveredTargets,
		BlockedTargets:     summary.BlockedTargets,
		FailedTargets:      summary.FailedTargets,
		PermissionDenied:   summary.PermissionDenied,
		ResumableTargets:   summary.ResumableTargets,
		CoveragePercent:    summary.CoveragePercent,
		StateCounts:        stateCounts,
		PriorityCounts:     priorityCounts,
		Prerequisites:      prerequisites,
	}
}

func filterAWSCoveragePlanTargets(targets []AWSCoveragePlanTarget, request AWSCoveragePlanRequest) []AWSCoveragePlanTarget {
	account := strings.TrimSpace(request.Account)
	region := strings.ToLower(strings.TrimSpace(request.Region))
	service := strings.ToLower(strings.TrimSpace(request.Service))
	state := strings.ToLower(strings.TrimSpace(request.State))
	if account == "" && region == "" && service == "" && state == "" {
		return targets
	}
	filtered := make([]AWSCoveragePlanTarget, 0, len(targets))
	for _, target := range targets {
		if account != "" && target.AccountID != account {
			continue
		}
		if region != "" && strings.ToLower(target.Region) != region {
			continue
		}
		if service != "" && strings.ToLower(target.Service) != service {
			continue
		}
		if state != "" && strings.ToLower(target.State) != state {
			continue
		}
		filtered = append(filtered, target)
	}
	return filtered
}

func summarizeAWSCoveragePlan(fixtureState string, diagnostics []AWSCoveragePlanDiagnostic, plan awscontract.CoveragePlan) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.3,
			awsCoveragePlanDiagnosticMessages(diagnostics),
			[]string{"Deploy the read-only collector role into denied accounts/regions, then re-run the coverage plan."}
	case "partial_failure", "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72,
			awsCoveragePlanDiagnosticMessages(diagnostics),
			[]string{"Re-run the plan to resume failed and in-progress targets from their checkpoints."}
	default:
		if awsCoveragePlanHasDiagnosticCode(diagnostics, "permission_denied") || plan.Summary.PermissionDenied > 0 {
			return awsPlatformDependencyStatusBlocked, 0.34,
				awsCoveragePlanDiagnosticMessages(diagnostics),
				[]string{"Repair denied read-only AWS access, then rerun the coverage plan from persisted scan cursors."}
		}
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.78,
				awsCoveragePlanDiagnosticMessages(diagnostics),
				[]string{"Refresh stale or malformed scan cursors so retry and resume behavior stays accurate."}
		}
		if plan.Summary.TotalTargets == 0 {
			return awsPlatformDependencyStatusReady, 0.8, nil,
				[]string{"No accounts, regions, or services are configured for coverage; add scan targets to the AWS connector."}
		}
		if plan.Summary.BlockedTargets > 0 {
			return awsPlatformDependencyStatusReady, 0.9, nil,
				[]string{"Onboard member accounts and enable opt-in regions to clear blocked targets, then re-run the plan."}
		}
		return awsPlatformDependencyStatusReady, 0.94, nil,
			[]string{"Coverage plan is deterministic and resumable; schedule the fan-out scan worker to execute outstanding targets."}
	}
}

func awsCoveragePlanHasDiagnosticCode(diagnostics []AWSCoveragePlanDiagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if strings.EqualFold(strings.TrimSpace(diagnostic.Code), code) {
			return true
		}
	}
	return false
}

func awsCoveragePlanDiagnosticMessages(diagnostics []AWSCoveragePlanDiagnostic) []string {
	messages := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if message := strings.TrimSpace(diagnostic.Message); message != "" {
			messages = append(messages, message)
		}
	}
	return dedupeStrings(messages)
}

// awsCoveragePlanSiblingAccount derives a deterministic second 12-digit account
// id from the connection account so multi-account fixtures stay stable.
func awsCoveragePlanSiblingAccount(accountID string) string {
	digits := strings.TrimSpace(accountID)
	if len(digits) != 12 {
		return "222222222222"
	}
	last := digits[11]
	if last == '9' {
		return digits[:11] + "0"
	}
	return digits[:11] + string(last+1)
}

func awsCoveragePlanSecondaryRegion(region string) string {
	if strings.EqualFold(strings.TrimSpace(region), "eu-west-1") {
		return "us-east-1"
	}
	return "eu-west-1"
}
