package api

import (
	"context"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const awsCoveragePlannerCurrentIssue = 1497
const awsCoveragePlannerGlobalServiceHomeRegion = "us-east-1"

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
	FixtureState       string                       `json:"fixture_state"`
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
	return buildAWSCoveragePlan(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSCoveragePlan(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSCoveragePlanRequest, checkedAt time.Time) (AWSCoveragePlanResult, error) {
	fixtureState := normalizeAWSCoveragePlanFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSCoveragePlanResult{}, ErrInvalidAWSConnectionRequest
	}
	if !validAWSCoveragePlanStateFilter(request.State) {
		return AWSCoveragePlanResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "111111111111")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	config, diagnostics, gaps := awsCoveragePlanFixtureConfig(connectorID, accountID, region, fixtureState)
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
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
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

// awsCoveragePlanFixtureConfig returns the deterministic connector coverage
// configuration, prior checkpoints, diagnostics, and gaps for a fixture state.
// The configuration is fed to the real planner so the API exercises the same
// code path operators will run against live connectors.
func awsCoveragePlanFixtureConfig(connectorID, accountID, region, fixtureState string) (awscontract.CoveragePlanConfig, []AWSCoveragePlanDiagnostic, []AWSCoveragePlanCoverageGap) {
	gaps := []AWSCoveragePlanCoverageGap{
		{
			Capability:  "live_account_discovery",
			Status:      "out_of_scope",
			Reason:      "The planner expands the configured account/region/service targets only; AWS Organizations and region availability discovery are later-wave capabilities.",
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
