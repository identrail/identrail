package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	awsPlatformValidationHarnessVersion = "aws-platform-validation-harness-v1"
	awsPlatformValidationCurrentIssue   = 1475

	awsPlatformValidationStatusReady    = "ready"
	awsPlatformValidationStatusDegraded = "degraded"
	awsPlatformValidationStatusBlocked  = "blocked"

	awsPlatformFixtureStateSuccess            = "success"
	awsPlatformFixtureStateEmpty              = "empty"
	awsPlatformFixtureStateDegraded           = "degraded"
	awsPlatformFixtureStatePartialFailure     = "partial_failure"
	awsPlatformFixtureStatePermissionDenied   = "permission_denied"
	awsPlatformFixtureStateUnsupportedService = "unsupported_service"
)

// AWSPlatformValidationHarnessRequest optionally pins connector context used for
// account and region evidence in deterministic validation fixtures.
type AWSPlatformValidationHarnessRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
}

// AWSPlatformValidationHarnessResult describes the reusable app-level proof
// harness future AWS PRs can cite when they touch visible behavior.
type AWSPlatformValidationHarnessResult struct {
	TenantID              string                          `json:"tenant_id"`
	WorkspaceID           string                          `json:"workspace_id"`
	ProjectID             string                          `json:"project_id"`
	ConnectorID           string                          `json:"connector_id,omitempty"`
	AccountID             string                          `json:"account_id,omitempty"`
	Region                string                          `json:"region,omitempty"`
	ParentIssueNumber     int                             `json:"parent_issue_number"`
	ParentIssueRef        string                          `json:"parent_issue_ref"`
	CurrentIssueNumber    int                             `json:"current_issue_number"`
	CurrentIssueRef       string                          `json:"current_issue_ref"`
	Version               string                          `json:"version"`
	Status                string                          `json:"status"`
	Confidence            float64                         `json:"confidence"`
	ScenarioCount         int                             `json:"scenario_count"`
	RequiredScenarioCount int                             `json:"required_scenario_count"`
	FixtureStates         []string                        `json:"fixture_states"`
	FailureReasons        []string                        `json:"failure_reasons"`
	RemediationHints      []string                        `json:"remediation_hints"`
	EvidenceLinks         []string                        `json:"evidence_links"`
	BrowserSteps          []AWSPlatformValidationStep     `json:"browser_steps"`
	APISteps              []AWSPlatformValidationStep     `json:"api_steps"`
	Scenarios             []AWSPlatformValidationScenario `json:"scenarios"`
	GeneratedAt           time.Time                       `json:"generated_at"`
	UpdatedAt             time.Time                       `json:"updated_at"`
}

// AWSPlatformValidationStep records one browser or API proof step that future
// AWS PRs can run and summarize in PR notes.
type AWSPlatformValidationStep struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Flow          string `json:"flow"`
	Label         string `json:"label"`
	Target        string `json:"target"`
	Method        string `json:"method,omitempty"`
	ExpectedState string `json:"expected_state"`
	Required      bool   `json:"required"`
	EvidenceURL   string `json:"evidence_url"`
}

// AWSPlatformValidationScenario is one deterministic fixture state for a core
// AWS app flow. Negative states are expected fixtures, not successful findings.
type AWSPlatformValidationScenario struct {
	ID              string         `json:"id"`
	Flow            string         `json:"flow"`
	FixtureState    string         `json:"fixture_state"`
	Status          string         `json:"status"`
	Label           string         `json:"label"`
	Summary         string         `json:"summary"`
	OperatorMessage string         `json:"operator_message"`
	FailureReason   string         `json:"failure_reason,omitempty"`
	Remediation     string         `json:"remediation,omitempty"`
	NextAction      string         `json:"next_action"`
	EvidenceURL     string         `json:"evidence_url"`
	AccountID       string         `json:"account_id,omitempty"`
	Region          string         `json:"region,omitempty"`
	Required        bool           `json:"required"`
	Confidence      float64        `json:"confidence"`
	Evidence        map[string]any `json:"evidence,omitempty"`
	BrowserStepIDs  []string       `json:"browser_step_ids"`
	APIStepIDs      []string       `json:"api_step_ids"`
	CheckedAt       time.Time      `json:"checked_at"`
}

type awsPlatformValidationScenarioTemplate struct {
	ID              string
	Flow            string
	FixtureState    string
	Label           string
	Summary         string
	OperatorMessage string
	FailureReason   string
	Remediation     string
	NextAction      string
	Required        bool
	Confidence      float64
}

// GetAWSPlatformValidationHarness returns deterministic app validation states
// scoped to one workspace project. It does not call AWS or mutate customer data.
func (s *Service) GetAWSPlatformValidationHarness(ctx context.Context, workspaceID string, projectID string, request AWSPlatformValidationHarnessRequest) (AWSPlatformValidationHarnessResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSPlatformValidationHarnessResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSPlatformValidationHarnessResult{}, err
	}
	return buildAWSPlatformValidationHarness(scope, project, connection, hasConnection, s.Now().UTC()), nil
}

func buildAWSPlatformValidationHarness(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, checkedAt time.Time) AWSPlatformValidationHarnessResult {
	browserSteps := awsPlatformValidationBrowserSteps(scope, project)
	apiSteps := awsPlatformValidationAPISteps(project)
	scenarios := awsPlatformValidationScenarios(scope, project, connection, hasConnection, checkedAt)
	status, confidence, failures, remediations := summarizeAWSPlatformValidationHarness(scenarios, browserSteps, apiSteps)
	fixtureStates := awsPlatformValidationFixtureStates(scenarios)

	result := AWSPlatformValidationHarnessResult{
		TenantID:              scope.TenantID,
		WorkspaceID:           project.WorkspaceID,
		ProjectID:             project.ProjectID,
		ParentIssueNumber:     awsPlatformDependencyParentIssue,
		ParentIssueRef:        awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:    awsPlatformValidationCurrentIssue,
		CurrentIssueRef:       awsIssueRef(awsPlatformValidationCurrentIssue),
		Version:               awsPlatformValidationHarnessVersion,
		Status:                status,
		Confidence:            confidence,
		ScenarioCount:         len(scenarios),
		RequiredScenarioCount: awsPlatformValidationRequiredScenarioCount(scenarios),
		FixtureStates:         fixtureStates,
		FailureReasons:        failures,
		RemediationHints:      remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPlatformValidationCurrentIssue),
			"/docs/aws-platform-validation-harness",
			awsBaselineProjectEvidenceURL(scope, project),
			awsBaselineSetupEvidenceURL(scope, project),
		}),
		BrowserSteps: browserSteps,
		APISteps:     apiSteps,
		Scenarios:    scenarios,
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}
	if hasConnection {
		result.ConnectorID = connection.ConnectorID
		result.AccountID = connection.AccountID
		result.Region = connection.Region
	}
	return result
}

func awsPlatformValidationBrowserSteps(scope db.Scope, project db.TenancyProject) []AWSPlatformValidationStep {
	appURL := awsBaselineProjectEvidenceURL(scope, project)
	setupURL := awsBaselineSetupEvidenceURL(scope, project)
	return []AWSPlatformValidationStep{
		{
			ID:            "browser_connector_setup",
			Kind:          "browser",
			Flow:          "connector_setup",
			Label:         "Open Connect AWS setup",
			Target:        setupURL,
			ExpectedState: "success",
			Required:      true,
			EvidenceURL:   setupURL,
		},
		{
			ID:            "browser_control_center_states",
			Kind:          "browser",
			Flow:          "diagnostics",
			Label:         "Validate AWS Control Center state panels",
			Target:        appURL,
			ExpectedState: "success, empty, degraded, partial_failure, permission_denied, unsupported_service",
			Required:      true,
			EvidenceURL:   appURL,
		},
	}
}

func awsPlatformValidationAPISteps(project db.TenancyProject) []AWSPlatformValidationStep {
	target := fmt.Sprintf("/v1/workspaces/%s/projects/%s/aws/validation-harness", project.WorkspaceID, project.ProjectID)
	return []AWSPlatformValidationStep{
		{
			ID:            "api_validation_harness",
			Kind:          "api",
			Flow:          "validation_harness",
			Label:         "Fetch deterministic AWS validation harness",
			Target:        target,
			Method:        "GET",
			ExpectedState: "all fixture states returned with scoped evidence",
			Required:      true,
			EvidenceURL:   "/docs/aws-platform-validation-harness",
		},
		{
			ID:            "api_baseline_gate",
			Kind:          "api",
			Flow:          "baseline_gate",
			Label:         "Confirm baseline gate remains visible",
			Target:        fmt.Sprintf("/v1/workspaces/%s/projects/%s/aws/baseline", project.WorkspaceID, project.ProjectID),
			Method:        "GET",
			ExpectedState: "ready, blocked, degraded, or not_run is explicit",
			Required:      true,
			EvidenceURL:   "/docs/aws-platform-baseline",
		},
	}
}

func awsPlatformValidationScenarios(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, checkedAt time.Time) []AWSPlatformValidationScenario {
	templates := []awsPlatformValidationScenarioTemplate{
		{
			ID:              "connector_setup_success",
			Flow:            "connector_setup",
			FixtureState:    awsPlatformFixtureStateSuccess,
			Label:           "Connector setup success",
			Summary:         "The app can show a connected AWS role with account, region, permission checks, diagnostics, and evidence links.",
			OperatorMessage: "Use this fixture when a PR changes AWS setup, connector health, CloudFormation launch, or role validation UX.",
			NextAction:      "Capture the Connect AWS and Control Center panels in PR validation notes.",
			Required:        true,
			Confidence:      0.98,
		},
		{
			ID:              "scan_state_empty",
			Flow:            "scan_state",
			FixtureState:    awsPlatformFixtureStateEmpty,
			Label:           "Scan state empty",
			Summary:         "The app can show a successful AWS validation with no collected records without treating the result as a failure.",
			OperatorMessage: "Use this fixture when a collector or scan-state PR needs proof that empty authorized accounts are understandable.",
			NextAction:      "Show the empty-state copy and API payload in PR evidence.",
			Required:        true,
			Confidence:      0.97,
		},
		{
			ID:              "graph_state_degraded",
			Flow:            "graph_state",
			FixtureState:    awsPlatformFixtureStateDegraded,
			Label:           "Graph state degraded",
			Summary:         "The app can show graph evidence that loaded with a known missing source, while preserving tenant and project scope.",
			OperatorMessage: "Use this fixture when graph contracts, relationship displays, or dependency edges change.",
			FailureReason:   "graph relationship source is degraded",
			Remediation:     "Keep partial graph evidence visible and link the missing source remediation before declaring graph coverage complete.",
			NextAction:      "Capture the degraded graph state and remediation hint.",
			Required:        true,
			Confidence:      0.94,
		},
		{
			ID:              "runtime_evidence_partial_failure",
			Flow:            "runtime_evidence",
			FixtureState:    awsPlatformFixtureStatePartialFailure,
			Label:           "Runtime evidence partial failure",
			Summary:         "The app can show runtime evidence where one account, region, or service succeeds while another reports an explicit partial failure.",
			OperatorMessage: "Use this fixture when runtime ingestion, timeline, or account/region fan-out behavior changes.",
			FailureReason:   "one AWS service partition did not return runtime evidence",
			Remediation:     "Keep successful runtime evidence separate from the failed partition and list the retry target.",
			NextAction:      "Summarize successful and failed partitions separately in PR notes.",
			Required:        true,
			Confidence:      0.95,
		},
		{
			ID:              "remediation_permission_denied",
			Flow:            "remediation",
			FixtureState:    awsPlatformFixtureStatePermissionDenied,
			Label:           "Remediation permission denied",
			Summary:         "The app can show an approved remediation path that is blocked by read-only scope or missing approval without hiding the reason.",
			OperatorMessage: "Use this fixture when approval, dry-run, or future executor UX changes.",
			FailureReason:   "live AWS mutation is not permitted by this harness",
			Remediation:     "Require explicit approval and executor scope before any live AWS mutation.",
			NextAction:      "Show the denied action, approval requirement, and rollback guidance.",
			Required:        true,
			Confidence:      0.97,
		},
		{
			ID:              "governance_unsupported_service",
			Flow:            "governance",
			FixtureState:    awsPlatformFixtureStateUnsupportedService,
			Label:           "Governance unsupported service",
			Summary:         "The app can show advisory authorization or governance coverage that does not yet support a service, without reporting success.",
			OperatorMessage: "Use this fixture when governance, advisory decisions, or enforcement labels change.",
			FailureReason:   "service is outside the supported governance contract",
			Remediation:     "Label the service unsupported and link the downstream implementation issue before enabling enforcement.",
			NextAction:      "Capture unsupported-service labeling and no-enforcement copy.",
			Required:        true,
			Confidence:      0.93,
		},
	}

	accountContext := "fixture"
	accountID := ""
	region := ""
	connectorID := ""
	if hasConnection {
		accountContext = "connector"
		accountID = connection.AccountID
		region = connection.Region
		connectorID = connection.ConnectorID
	}

	scenarios := make([]AWSPlatformValidationScenario, 0, len(templates))
	for index, template := range templates {
		browserStepIDs, apiStepIDs := awsPlatformValidationStepIDsForFlow(template.Flow)
		scenarios = append(scenarios, AWSPlatformValidationScenario{
			ID:              template.ID,
			Flow:            template.Flow,
			FixtureState:    template.FixtureState,
			Status:          awsPlatformValidationStatusReady,
			Label:           template.Label,
			Summary:         template.Summary,
			OperatorMessage: template.OperatorMessage,
			FailureReason:   template.FailureReason,
			Remediation:     template.Remediation,
			NextAction:      template.NextAction,
			EvidenceURL:     awsPlatformValidationEvidenceURL(scope, project, template.Flow),
			AccountID:       accountID,
			Region:          region,
			Required:        template.Required,
			Confidence:      template.Confidence,
			Evidence: map[string]any{
				"sequence":        index + 1,
				"account_context": accountContext,
				"connector_id":    connectorID,
				"workspace_id":    project.WorkspaceID,
				"project_id":      project.ProjectID,
				"fixture_state":   template.FixtureState,
				"read_only":       true,
			},
			BrowserStepIDs: browserStepIDs,
			APIStepIDs:     apiStepIDs,
			CheckedAt:      checkedAt,
		})
	}
	return scenarios
}

func awsPlatformValidationStepIDsForFlow(flow string) ([]string, []string) {
	switch flow {
	case "connector_setup":
		return []string{"browser_connector_setup", "browser_control_center_states"}, []string{"api_validation_harness", "api_baseline_gate"}
	case "scan_state", "graph_state", "runtime_evidence", "remediation", "governance":
		return []string{"browser_control_center_states"}, []string{"api_validation_harness"}
	default:
		return []string{"browser_control_center_states"}, []string{"api_validation_harness"}
	}
}

func summarizeAWSPlatformValidationHarness(scenarios []AWSPlatformValidationScenario, browserSteps []AWSPlatformValidationStep, apiSteps []AWSPlatformValidationStep) (string, float64, []string, []string) {
	requiredStates := map[string]struct{}{
		awsPlatformFixtureStateSuccess:            {},
		awsPlatformFixtureStateEmpty:              {},
		awsPlatformFixtureStateDegraded:           {},
		awsPlatformFixtureStatePartialFailure:     {},
		awsPlatformFixtureStatePermissionDenied:   {},
		awsPlatformFixtureStateUnsupportedService: {},
	}
	failures := []string{}
	remediations := []string{}
	seenStates := map[string]struct{}{}
	for _, scenario := range scenarios {
		if scenario.Required && scenario.Status != awsPlatformValidationStatusReady {
			failures = append(failures, fmt.Sprintf("%s is not ready", scenario.ID))
			remediations = append(remediations, firstNonEmptyAWSValue(scenario.Remediation, "Restore the required validation scenario."))
		}
		if _, required := requiredStates[scenario.FixtureState]; required {
			seenStates[scenario.FixtureState] = struct{}{}
		}
	}
	for state := range requiredStates {
		if _, ok := seenStates[state]; !ok {
			failures = append(failures, fmt.Sprintf("missing %s validation fixture", state))
			remediations = append(remediations, "Restore all required AWS validation fixture states.")
		}
	}
	if len(browserSteps) == 0 {
		failures = append(failures, "browser validation steps are missing")
		remediations = append(remediations, "Add browser validation steps before relying on the harness.")
	}
	if len(apiSteps) == 0 {
		failures = append(failures, "api validation steps are missing")
		remediations = append(remediations, "Add API validation steps before relying on the harness.")
	}
	if len(failures) > 0 {
		return awsPlatformValidationStatusBlocked, 0.35, dedupeStrings(failures), dedupeStrings(remediations)
	}
	return awsPlatformValidationStatusReady, 0.98, []string{}, []string{}
}

func awsPlatformValidationRequiredScenarioCount(scenarios []AWSPlatformValidationScenario) int {
	count := 0
	for _, scenario := range scenarios {
		if scenario.Required {
			count++
		}
	}
	return count
}

func awsPlatformValidationFixtureStates(scenarios []AWSPlatformValidationScenario) []string {
	states := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		states = append(states, scenario.FixtureState)
	}
	return dedupeStrings(states)
}

func awsPlatformValidationEvidenceURL(scope db.Scope, project db.TenancyProject, flow string) string {
	switch flow {
	case "connector_setup":
		return awsBaselineSetupEvidenceURL(scope, project)
	default:
		return awsBaselineProjectEvidenceURL(scope, project)
	}
}
