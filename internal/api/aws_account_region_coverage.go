package api

import (
	"context"
	"sort"
	"strings"
	"time"
)

const awsAccountRegionCoverageAPICurrentIssue = 1503

// AWSAccountRegionCoverageRequest filters the public coverage API.
type AWSAccountRegionCoverageRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	Account      string `json:"account,omitempty"`
	Region       string `json:"region,omitempty"`
	Service      string `json:"service,omitempty"`
	Collector    string `json:"collector,omitempty"`
	State        string `json:"state,omitempty"`
	Status       string `json:"status,omitempty"`
}

// AWSAccountRegionCoverageRecord is one public, metadata-only coverage row.
type AWSAccountRegionCoverageRecord struct {
	Key            string    `json:"key"`
	AccountID      string    `json:"account_id"`
	AccountName    string    `json:"account_name,omitempty"`
	Region         string    `json:"region"`
	RegionName     string    `json:"region_name,omitempty"`
	Service        string    `json:"service"`
	ServiceName    string    `json:"service_name,omitempty"`
	Collector      string    `json:"collector,omitempty"`
	Global         bool      `json:"global"`
	Enabled        bool      `json:"enabled"`
	State          string    `json:"state"`
	CoverageStatus string    `json:"coverage_status"`
	Cursor         string    `json:"cursor,omitempty"`
	Checkpoint     string    `json:"checkpoint,omitempty"`
	Attempts       int       `json:"attempts,omitempty"`
	FailureReason  string    `json:"failure_reason,omitempty"`
	Retryable      bool      `json:"retryable"`
	Stale          bool      `json:"stale"`
	EvidenceRef    string    `json:"evidence_ref"`
	NextAction     string    `json:"next_action"`
	ObservedAt     time.Time `json:"observed_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AWSAccountRegionCoverageSummary is optimized for dashboards and filters.
type AWSAccountRegionCoverageSummary struct {
	TotalRecords            int            `json:"total_records"`
	FilteredRecords         int            `json:"filtered_records"`
	AccountCount            int            `json:"account_count"`
	RegionCount             int            `json:"region_count"`
	ServiceCount            int            `json:"service_count"`
	CoveredRecords          int            `json:"covered_records"`
	MissingRecords          int            `json:"missing_records"`
	DegradedRecords         int            `json:"degraded_records"`
	UnreachableRecords      int            `json:"unreachable_records"`
	SuspendedRecords        int            `json:"suspended_records"`
	DisabledRecords         int            `json:"disabled_records"`
	StaleRecords            int            `json:"stale_records"`
	PermissionDeniedRecords int            `json:"permission_denied_records"`
	RetryableRecords        int            `json:"retryable_records"`
	StatusCounts            map[string]int `json:"status_counts"`
	StateCounts             map[string]int `json:"state_counts"`
	CollectorCounts         map[string]int `json:"collector_counts"`
}

// AWSAccountRegionCoverageResult is the public account/region coverage API.
type AWSAccountRegionCoverageResult struct {
	TenantID           string                           `json:"tenant_id"`
	WorkspaceID        string                           `json:"workspace_id"`
	ProjectID          string                           `json:"project_id"`
	ConnectorID        string                           `json:"connector_id,omitempty"`
	AccountID          string                           `json:"account_id,omitempty"`
	Region             string                           `json:"region,omitempty"`
	ParentIssueNumber  int                              `json:"parent_issue_number"`
	ParentIssueRef     string                           `json:"parent_issue_ref"`
	CurrentIssueNumber int                              `json:"current_issue_number"`
	CurrentIssueRef    string                           `json:"current_issue_ref"`
	Version            string                           `json:"version"`
	Status             string                           `json:"status"`
	FixtureState       string                           `json:"fixture_state,omitempty"`
	Confidence         float64                          `json:"confidence"`
	Summary            AWSAccountRegionCoverageSummary  `json:"summary"`
	Records            []AWSAccountRegionCoverageRecord `json:"records"`
	FailureReasons     []string                         `json:"failure_reasons"`
	RemediationHints   []string                         `json:"remediation_hints"`
	EvidenceLinks      []string                         `json:"evidence_links"`
	CoverageGaps       []AWSCoveragePlanCoverageGap     `json:"coverage_gaps"`
	Diagnostics        []AWSCoveragePlanDiagnostic      `json:"diagnostics"`
	GeneratedAt        time.Time                        `json:"generated_at"`
	UpdatedAt          time.Time                        `json:"updated_at"`
}

// GetAWSAccountRegionCoverage returns the public, row-oriented coverage API for
// account, region, service, and collector status. The API is read-only and
// exposes metadata, cursors, evidence refs, and recovery actions without
// reading customer payloads or secret values.
func (s *Service) GetAWSAccountRegionCoverage(ctx context.Context, workspaceID string, projectID string, request AWSAccountRegionCoverageRequest) (AWSAccountRegionCoverageResult, error) {
	if !validAWSAccountRegionCoverageStatusFilter(request.Status) {
		return AWSAccountRegionCoverageResult{}, ErrInvalidAWSConnectionRequest
	}
	planRequest := AWSCoveragePlanRequest{
		ConnectorID:  request.ConnectorID,
		FixtureState: request.FixtureState,
		Account:      request.Account,
		Region:       request.Region,
		Service:      request.Service,
		State:        request.State,
	}
	plan, err := s.GetAWSCoveragePlan(ctx, workspaceID, projectID, planRequest)
	if err != nil {
		return AWSAccountRegionCoverageResult{}, err
	}
	records := buildAWSAccountRegionCoverageRecords(plan)
	filtered := filterAWSAccountRegionCoverageRecords(records, request)
	summary := summarizeAWSAccountRegionCoverage(records, len(filtered))
	status, confidence, failures, remediations := summarizeAWSAccountRegionCoverageAPI(plan, summary)

	return AWSAccountRegionCoverageResult{
		TenantID:           plan.TenantID,
		WorkspaceID:        plan.WorkspaceID,
		ProjectID:          plan.ProjectID,
		ConnectorID:        plan.ConnectorID,
		AccountID:          plan.AccountID,
		Region:             plan.Region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsAccountRegionCoverageAPICurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsAccountRegionCoverageAPICurrentIssue),
		Version:            "aws-account-region-coverage-api-v1",
		Status:             status,
		FixtureState:       plan.FixtureState,
		Confidence:         confidence,
		Summary:            summary,
		Records:            filtered,
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsAccountRegionCoverageAPICurrentIssue),
			awsIssueURL(awsPartialFailureReportingCurrentIssue),
			awsIssueURL(awsCoveragePlannerCurrentIssue),
			"/docs/aws-account-region-coverage-planner#public-account-region-coverage-api",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURLFromIDs(plan.TenantID, plan.WorkspaceID, plan.ProjectID),
		}),
		CoverageGaps: plan.CoverageGaps,
		Diagnostics:  plan.Diagnostics,
		GeneratedAt:  plan.GeneratedAt,
		UpdatedAt:    plan.UpdatedAt,
	}, nil
}

func buildAWSAccountRegionCoverageRecords(plan AWSCoveragePlanResult) []AWSAccountRegionCoverageRecord {
	staleDiagnostics := awsCoverageStaleDiagnostics(plan.Diagnostics)
	records := make([]AWSAccountRegionCoverageRecord, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		staleDiagnostic, stale := awsCoverageStaleDiagnosticForTarget(staleDiagnostics, target)
		status := awsAccountRegionCoverageStatus(target, stale)
		failureReason := firstNonEmptyAWSValue(target.FailureReason, target.Reason)
		if stale && staleDiagnostic != nil {
			failureReason = firstNonEmptyAWSValue(failureReason, staleDiagnostic.Message)
		}
		collector := firstNonEmptyAWSValue(target.Collector, staleDiagnosticCollector(staleDiagnostic))
		records = append(records, AWSAccountRegionCoverageRecord{
			Key:            target.Key,
			AccountID:      target.AccountID,
			AccountName:    target.AccountName,
			Region:         target.Region,
			RegionName:     target.RegionName,
			Service:        target.Service,
			ServiceName:    target.ServiceName,
			Collector:      collector,
			Global:         target.Global,
			Enabled:        target.Enabled,
			State:          target.State,
			CoverageStatus: status,
			Cursor:         firstNonEmptyAWSValue(target.Cursor, staleDiagnosticCursor(staleDiagnostic)),
			Checkpoint:     firstNonEmptyAWSValue(target.Cursor, staleDiagnosticCursor(staleDiagnostic)),
			Attempts:       target.Attempts,
			FailureReason:  failureReason,
			Retryable:      target.Resumable && status != "covered",
			Stale:          stale,
			EvidenceRef:    target.EvidenceRef,
			NextAction:     awsAccountRegionCoverageNextAction(status, target.NextAction),
			ObservedAt:     target.ObservedAt,
			UpdatedAt:      plan.UpdatedAt,
		})
	}
	return records
}

func awsCoverageStaleDiagnostics(diagnostics []AWSCoveragePlanDiagnostic) map[string]AWSCoveragePlanDiagnostic {
	out := map[string]AWSCoveragePlanDiagnostic{}
	for _, diagnostic := range diagnostics {
		if strings.ToLower(strings.TrimSpace(diagnostic.Code)) != "stale_cursor_expired" {
			continue
		}
		scope := strings.ToLower(strings.TrimSpace(diagnostic.Scope))
		if scope == "" {
			continue
		}
		out[scope] = diagnostic
	}
	return out
}

func awsCoverageStaleDiagnosticForTarget(staleDiagnostics map[string]AWSCoveragePlanDiagnostic, target AWSCoveragePlanTarget) (*AWSCoveragePlanDiagnostic, bool) {
	service := strings.ToLower(strings.TrimSpace(target.Service))
	state := strings.ToLower(strings.TrimSpace(target.State))
	region := strings.ToLower(strings.TrimSpace(target.Region))
	exactScope := strings.Join([]string{target.AccountID, region, service}, "/")
	if diagnostic, ok := staleDiagnostics[exactScope]; ok {
		return &diagnostic, true
	}
	if state == "covered" {
		return nil, false
	}
	if !target.Global {
		return nil, false
	}
	scopes := make([]string, 0, len(staleDiagnostics))
	for scope := range staleDiagnostics {
		parts := strings.Split(scope, "/")
		if len(parts) != 3 {
			continue
		}
		if parts[0] != strings.TrimSpace(target.AccountID) || parts[2] != service {
			continue
		}
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	if len(scopes) > 0 {
		diagnostic := staleDiagnostics[scopes[0]]
		return &diagnostic, true
	}
	return nil, false
}

func staleDiagnosticCursor(diagnostic *AWSCoveragePlanDiagnostic) string {
	if diagnostic == nil {
		return ""
	}
	return strings.TrimSpace(diagnostic.Cursor)
}

func staleDiagnosticCollector(diagnostic *AWSCoveragePlanDiagnostic) string {
	if diagnostic == nil {
		return ""
	}
	return strings.TrimSpace(diagnostic.Collector)
}

func awsAccountRegionCoverageStatus(target AWSCoveragePlanTarget, stale bool) string {
	if stale {
		return "stale"
	}
	state := strings.ToLower(strings.TrimSpace(target.State))
	combined := strings.ToLower(strings.Join([]string{target.Reason, target.FailureReason}, " "))
	switch {
	case state == "covered":
		return "covered"
	case state == "disabled":
		return "disabled"
	case strings.Contains(combined, "suspended"):
		return "suspended"
	case strings.Contains(combined, "unreachable"):
		return "unreachable"
	case state == "permission_denied":
		return "permission_denied"
	case state == "blocked":
		return "missing"
	case state == "planned" || state == "pending" || state == "in_progress":
		return "missing"
	default:
		return "degraded"
	}
}

func awsAccountRegionCoverageNextAction(status string, fallback string) string {
	switch status {
	case "covered":
		return "No action required; rescan on the next scheduled coverage run."
	case "missing":
		return "Queue or resume this account/region/service target in the next fan-out run."
	case "unreachable":
		return "Fix connector reachability for this account and region, then rerun coverage."
	case "suspended":
		return "Exclude or reactivate the suspended account before expecting coverage."
	case "stale":
		return "Refresh this stale cursor so the next run starts from a current checkpoint."
	case "disabled":
		return "Enable this account, region, or service in connector coverage configuration."
	case "permission_denied":
		return "Grant the read-only collector role access, then rerun coverage."
	default:
		return fallback
	}
}

func filterAWSAccountRegionCoverageRecords(records []AWSAccountRegionCoverageRecord, request AWSAccountRegionCoverageRequest) []AWSAccountRegionCoverageRecord {
	collector := strings.ToLower(strings.TrimSpace(request.Collector))
	status := strings.ToLower(strings.TrimSpace(request.Status))
	if collector == "" && status == "" {
		return records
	}
	filtered := make([]AWSAccountRegionCoverageRecord, 0, len(records))
	for _, record := range records {
		if collector != "" && strings.ToLower(strings.TrimSpace(record.Collector)) != collector {
			continue
		}
		if status != "" && strings.ToLower(strings.TrimSpace(record.CoverageStatus)) != status {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func summarizeAWSAccountRegionCoverage(records []AWSAccountRegionCoverageRecord, filteredRecords int) AWSAccountRegionCoverageSummary {
	accounts := map[string]struct{}{}
	regions := map[string]struct{}{}
	services := map[string]struct{}{}
	statusCounts := map[string]int{}
	stateCounts := map[string]int{}
	collectorCounts := map[string]int{}
	summary := AWSAccountRegionCoverageSummary{
		TotalRecords:    len(records),
		FilteredRecords: filteredRecords,
		StatusCounts:    statusCounts,
		StateCounts:     stateCounts,
		CollectorCounts: collectorCounts,
	}
	for _, record := range records {
		accounts[record.AccountID] = struct{}{}
		regions[strings.ToLower(strings.TrimSpace(record.Region))] = struct{}{}
		services[strings.ToLower(strings.TrimSpace(record.Service))] = struct{}{}
		statusCounts[record.CoverageStatus]++
		stateCounts[record.State]++
		if strings.TrimSpace(record.Collector) != "" {
			collectorCounts[record.Collector]++
		}
		if record.Retryable {
			summary.RetryableRecords++
		}
		switch record.CoverageStatus {
		case "covered":
			summary.CoveredRecords++
		case "missing":
			summary.MissingRecords++
		case "degraded":
			summary.DegradedRecords++
		case "unreachable":
			summary.UnreachableRecords++
		case "suspended":
			summary.SuspendedRecords++
		case "disabled":
			summary.DisabledRecords++
		case "stale":
			summary.StaleRecords++
		case "permission_denied":
			summary.PermissionDeniedRecords++
		}
	}
	summary.AccountCount = len(accounts)
	summary.RegionCount = len(regions)
	summary.ServiceCount = len(services)
	return summary
}

func summarizeAWSAccountRegionCoverageAPI(plan AWSCoveragePlanResult, summary AWSAccountRegionCoverageSummary) (string, float64, []string, []string) {
	failures := append([]string{}, plan.FailureReasons...)
	remediations := append([]string{}, plan.RemediationHints...)
	switch {
	case summary.PermissionDeniedRecords > 0:
		return awsPlatformDependencyStatusBlocked, 0.35, failures, dedupeStrings(append(remediations, "Repair denied read-only AWS access, then rerun account/region coverage."))
	case summary.StaleRecords > 0 || summary.DegradedRecords > 0 || summary.UnreachableRecords > 0 || summary.SuspendedRecords > 0:
		return awsPlatformDependencyStatusDegraded, 0.76, failures, dedupeStrings(append(remediations, "Use coverage status filters to rerun only stale, degraded, unreachable, or suspended targets."))
	default:
		return plan.Status, plan.Confidence, failures, remediations
	}
}

func validAWSAccountRegionCoverageStatusFilter(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "covered", "missing", "degraded", "unreachable", "suspended", "disabled", "stale", "permission_denied":
		return true
	default:
		return false
	}
}

func awsBaselineProjectEvidenceURLFromIDs(tenantID string, workspaceID string, projectID string) string {
	return "/app/" + strings.TrimSpace(tenantID) + "/workspaces/" + strings.TrimSpace(workspaceID) + "/projects/" + strings.TrimSpace(projectID) + "/aws"
}
