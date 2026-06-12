package api

import (
	"context"
	"strings"
	"time"

	awsconnector "github.com/identrail/identrail/internal/connectors/aws"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	awsStackSetOnboardingCurrentIssue = 1504
)

// AWSStackSetOnboardingRequest pins the connector context and optional fixture
// state used to project StackSet onboarding planning output.
type AWSStackSetOnboardingRequest struct {
	ConnectorID    string `json:"connector_id,omitempty"`
	FixtureState   string `json:"fixture_state,omitempty"`
	DeploymentMode string `json:"deployment_mode,omitempty"`
}

// AWSStackSetOnboardingPrerequisite is one operator-visible prerequisite check.
type AWSStackSetOnboardingPrerequisite struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Satisfied   bool   `json:"satisfied"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSStackSetOnboardingPermissionPreview is one tier of pre-launch permission
// rationale shared with the connector capabilities surface.
type AWSStackSetOnboardingPermissionPreview struct {
	Capability  string                                       `json:"capability"`
	Tier        string                                       `json:"tier"`
	Available   bool                                         `json:"available"`
	Summary     string                                       `json:"summary"`
	Permissions []AWSStackSetOnboardingPermissionPreviewItem `json:"permissions"`
}

// AWSStackSetOnboardingPermissionPreviewItem mirrors PermissionPreviewItem.
type AWSStackSetOnboardingPermissionPreviewItem struct {
	Service   string   `json:"service"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Reason    string   `json:"reason"`
}

// AWSStackSetOnboardingValidation is the high-level pre-launch verdict.
type AWSStackSetOnboardingValidation struct {
	Status           string                              `json:"status"`
	Confidence       float64                             `json:"confidence"`
	BlockingCount    int                                 `json:"blocking_count"`
	AdvisoryCount    int                                 `json:"advisory_count"`
	Prerequisites    []AWSStackSetOnboardingPrerequisite `json:"prerequisites"`
	FailureReasons   []string                            `json:"failure_reasons"`
	RemediationHints []string                            `json:"remediation_hints"`
}

// AWSStackSetOnboardingTargetAccount is one account in the StackSet target set.
type AWSStackSetOnboardingTargetAccount struct {
	AccountID  string `json:"account_id"`
	Name       string `json:"name,omitempty"`
	OUPath     string `json:"ou_path,omitempty"`
	Management bool   `json:"management,omitempty"`
	Suspended  bool   `json:"suspended,omitempty"`
}

// AWSStackSetOnboardingTargetRegion is one region in the StackSet target set.
type AWSStackSetOnboardingTargetRegion struct {
	Region string `json:"region"`
	Name   string `json:"name,omitempty"`
	OptIn  bool   `json:"opt_in,omitempty"`
}

// AWSStackSetOnboardingTargets is the full operator-visible target set.
type AWSStackSetOnboardingTargets struct {
	OrganizationID      string                               `json:"organization_id,omitempty"`
	OrganizationalUnits []AWSStackSetOnboardingOU            `json:"organizational_units"`
	Accounts            []AWSStackSetOnboardingTargetAccount `json:"accounts"`
	Regions             []AWSStackSetOnboardingTargetRegion  `json:"regions"`
}

// AWSStackSetOnboardingOU is one operator-visible organizational unit.
type AWSStackSetOnboardingOU struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	Path     string `json:"path,omitempty"`
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"`
}

// AWSStackSetOnboardingInstance is one operator-visible StackSet instance.
type AWSStackSetOnboardingInstance struct {
	Key             string    `json:"key"`
	AccountID       string    `json:"account_id"`
	AccountName     string    `json:"account_name,omitempty"`
	OUPath          string    `json:"ou_path,omitempty"`
	Region          string    `json:"region"`
	RegionName      string    `json:"region_name,omitempty"`
	State           string    `json:"state"`
	StackID         string    `json:"stack_id,omitempty"`
	OperationID     string    `json:"operation_id,omitempty"`
	FailureReason   string    `json:"failure_reason,omitempty"`
	Attempts        int       `json:"attempts,omitempty"`
	Resumable       bool      `json:"resumable"`
	Suspended       bool      `json:"suspended,omitempty"`
	OptInRegion     bool      `json:"opt_in_region,omitempty"`
	NextAction      string    `json:"next_action"`
	CoverageTargets int       `json:"coverage_targets"`
	EvidenceRef     string    `json:"evidence_ref"`
	ObservedAt      time.Time `json:"observed_at,omitempty"`
}

// AWSStackSetOnboardingCoverageExpectation projects post-launch scan coverage.
type AWSStackSetOnboardingCoverageExpectation struct {
	ExpectedAccounts        int     `json:"expected_accounts"`
	ExpectedRegions         int     `json:"expected_regions"`
	ExpectedInstances       int     `json:"expected_instances"`
	ExpectedCoverageTargets int     `json:"expected_coverage_targets"`
	CoveragePercent         float64 `json:"coverage_percent"`
	GlobalServiceNotes      string  `json:"global_service_notes"`
}

// AWSStackSetOnboardingRecoveryAction is one operator recovery action.
type AWSStackSetOnboardingRecoveryAction struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Targets     []string `json:"targets"`
}

// AWSStackSetOnboardingSummary aggregates the onboarding plan for dashboards.
type AWSStackSetOnboardingSummary struct {
	TargetAccounts       int            `json:"target_accounts"`
	TargetRegions        int            `json:"target_regions"`
	TotalInstances       int            `json:"total_instances"`
	PendingInstances     int            `json:"pending_instances"`
	ActiveInstances      int            `json:"active_instances"`
	BlockedInstances     int            `json:"blocked_instances"`
	FailedInstances      int            `json:"failed_instances"`
	DegradedInstances    int            `json:"degraded_instances"`
	SuspendedInstances   int            `json:"suspended_instances"`
	PermissionDenied     int            `json:"permission_denied_instances"`
	UnsupportedInstances int            `json:"unsupported_instances"`
	ResumableInstances   int            `json:"resumable_instances"`
	DeployedPercent      float64        `json:"deployed_percent"`
	StateCounts          map[string]int `json:"state_counts"`
}

// AWSStackSetOnboardingDiagnostic is one planning/execution diagnostic.
type AWSStackSetOnboardingDiagnostic struct {
	Source      string `json:"source"`
	Scope       string `json:"scope,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSStackSetOnboardingCoverageGap names a deliberate boundary of the planner.
type AWSStackSetOnboardingCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSStackSetOnboardingResult is the full StackSet onboarding response.
type AWSStackSetOnboardingResult struct {
	TenantID            string                                   `json:"tenant_id"`
	WorkspaceID         string                                   `json:"workspace_id"`
	ProjectID           string                                   `json:"project_id"`
	ConnectorID         string                                   `json:"connector_id,omitempty"`
	AccountID           string                                   `json:"account_id,omitempty"`
	Region              string                                   `json:"region,omitempty"`
	OrganizationID      string                                   `json:"organization_id,omitempty"`
	ManagementAccountID string                                   `json:"management_account_id,omitempty"`
	StackSetName        string                                   `json:"stack_set_name"`
	TemplateURL         string                                   `json:"template_url,omitempty"`
	TemplateChecksum    string                                   `json:"template_checksum,omitempty"`
	LaunchURL           string                                   `json:"launch_url,omitempty"`
	DeploymentMode      string                                   `json:"deployment_mode"`
	Partition           string                                   `json:"partition"`
	ParentIssueNumber   int                                      `json:"parent_issue_number"`
	ParentIssueRef      string                                   `json:"parent_issue_ref"`
	CurrentIssueNumber  int                                      `json:"current_issue_number"`
	CurrentIssueRef     string                                   `json:"current_issue_ref"`
	Version             string                                   `json:"version"`
	Status              string                                   `json:"status"`
	FixtureState        string                                   `json:"fixture_state,omitempty"`
	Confidence          float64                                  `json:"confidence"`
	Validation          AWSStackSetOnboardingValidation          `json:"validation"`
	PermissionPreview   []AWSStackSetOnboardingPermissionPreview `json:"permission_preview"`
	Targets             AWSStackSetOnboardingTargets             `json:"targets"`
	Instances           []AWSStackSetOnboardingInstance          `json:"instances"`
	CoverageExpectation AWSStackSetOnboardingCoverageExpectation `json:"coverage_expectation"`
	RecoveryActions     []AWSStackSetOnboardingRecoveryAction    `json:"recovery_actions"`
	Summary             AWSStackSetOnboardingSummary             `json:"summary"`
	FailureReasons      []string                                 `json:"failure_reasons"`
	RemediationHints    []string                                 `json:"remediation_hints"`
	EvidenceLinks       []string                                 `json:"evidence_links"`
	CoverageGaps        []AWSStackSetOnboardingCoverageGap       `json:"coverage_gaps"`
	Diagnostics         []AWSStackSetOnboardingDiagnostic        `json:"diagnostics"`
	GeneratedAt         time.Time                                `json:"generated_at"`
	UpdatedAt           time.Time                                `json:"updated_at"`
}

// GetAWSStackSetOnboarding returns the deterministic AWS Organization StackSet
// onboarding plan for a project. It is read-only and metadata-only: it issues
// no AWS API calls and never mutates AWS state. Fixture states drive
// deterministic loading/empty/degraded/permission-denied/partial-failure
// projections for the operator UI and contract tests.
func (s *Service) GetAWSStackSetOnboarding(ctx context.Context, workspaceID string, projectID string, request AWSStackSetOnboardingRequest) (AWSStackSetOnboardingResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSStackSetOnboardingResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSStackSetOnboardingResult{}, err
	}
	return s.buildAWSStackSetOnboarding(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func (s *Service) buildAWSStackSetOnboarding(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSStackSetOnboardingRequest, checkedAt time.Time) (AWSStackSetOnboardingResult, error) {
	fixtureState := normalizeAWSStackSetFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSStackSetOnboardingResult{}, ErrInvalidAWSConnectionRequest
	}
	deploymentMode := normalizeAWSStackSetDeploymentMode(request.DeploymentMode)
	if deploymentMode == "" {
		return AWSStackSetOnboardingResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(strings.TrimSpace(connection.AccountID), "111111111111")
	region := firstNonEmptyAWSValue(strings.TrimSpace(connection.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(strings.TrimSpace(connection.ConnectorID), strings.TrimSpace(request.ConnectorID), "aws-fixture")

	config, diagnostics, gaps := awsStackSetFixtureConfig(
		connectorID,
		accountID,
		region,
		fixtureState,
		awscontract.StackSetDeploymentMode(deploymentMode),
		strings.TrimSpace(s.AWSCloudFormationTemplateURL),
		strings.TrimSpace(connection.ExternalID),
	)

	plan, err := awscontract.PlanStackSetOnboarding(config, checkedAt)
	if err != nil {
		return AWSStackSetOnboardingResult{}, err
	}

	launchURL := awsconnector.BuildCloudFormationStackSetLaunchURL(awsconnector.CloudFormationStackSetLaunchInput{
		TemplateURL:           plan.TemplateURL,
		Region:                region,
		StackSetName:          plan.StackSetName,
		IdentrailAccountID:    strings.TrimSpace(s.AWSAccountID),
		ExternalID:            strings.TrimSpace(config.ExternalID),
		RoleName:              "IdentrailReadOnly",
		PermissionModel:       awsStackSetPermissionModel(plan.DeploymentMode),
		OrganizationalUnitIDs: collectStackSetOUIDs(plan.Targets.OrganizationalUnits),
		TargetAccountIDs:      collectStackSetAccountIDs(plan.Targets.Accounts),
		TargetRegions:         collectStackSetRegionCodes(plan.Targets.Regions),
	})

	status, confidence, failures, remediations := summarizeAWSStackSetOnboarding(fixtureState, plan, diagnostics)

	return AWSStackSetOnboardingResult{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		AccountID:           accountID,
		Region:              region,
		OrganizationID:      plan.OrganizationID,
		ManagementAccountID: plan.ManagementAccountID,
		StackSetName:        plan.StackSetName,
		TemplateURL:         plan.TemplateURL,
		TemplateChecksum:    plan.TemplateChecksum,
		LaunchURL:           launchURL,
		DeploymentMode:      string(plan.DeploymentMode),
		Partition:           plan.Partition,
		ParentIssueNumber:   awsPlatformDependencyParentIssue,
		ParentIssueRef:      awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:  awsStackSetOnboardingCurrentIssue,
		CurrentIssueRef:     awsIssueRef(awsStackSetOnboardingCurrentIssue),
		Version:             plan.Version,
		Status:              status,
		FixtureState:        fixtureState,
		Confidence:          confidence,
		Validation:          mapAWSStackSetValidation(plan.Validation),
		PermissionPreview:   awsStackSetPermissionPreview(),
		Targets:             mapAWSStackSetTargets(plan.Targets),
		Instances:           mapAWSStackSetInstances(plan.Instances),
		CoverageExpectation: mapAWSStackSetCoverageExpectation(plan.CoverageExpectation),
		RecoveryActions:     mapAWSStackSetRecoveryActions(plan.RecoveryActions),
		Summary:             mapAWSStackSetSummary(plan.Summary),
		FailureReasons:      failures,
		RemediationHints:    remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsStackSetOnboardingCurrentIssue),
			awsIssueURL(awsCoveragePlannerCurrentIssue),
			"/docs/aws-stackset-onboarding",
			"/docs/auth/aws-connector",
			"/docs/aws-account-region-coverage-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: gaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}, nil
}

func normalizeAWSStackSetFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func normalizeAWSStackSetDeploymentMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", string(awscontract.StackSetDeploymentServiceManaged):
		return string(awscontract.StackSetDeploymentServiceManaged)
	case string(awscontract.StackSetDeploymentSelfManaged):
		return string(awscontract.StackSetDeploymentSelfManaged)
	default:
		return ""
	}
}

func awsStackSetPermissionModel(mode awscontract.StackSetDeploymentMode) awsconnector.StackSetLaunchPermissionModel {
	if mode == awscontract.StackSetDeploymentSelfManaged {
		return awsconnector.StackSetLaunchPermissionModelSelfManaged
	}
	return awsconnector.StackSetLaunchPermissionModelServiceManaged
}

// awsStackSetFixtureConfig returns the deterministic StackSet onboarding config,
// diagnostics, and coverage gaps for one fixture state. The planner consumes the
// resulting config so the API exercises the same code path operators will run
// against live connectors.
func awsStackSetFixtureConfig(
	connectorID,
	accountID,
	region,
	fixtureState string,
	deploymentMode awscontract.StackSetDeploymentMode,
	templateURL,
	connectorExternalID string,
) (awscontract.StackSetOnboardingConfig, []AWSStackSetOnboardingDiagnostic, []AWSStackSetOnboardingCoverageGap) {
	gaps := []AWSStackSetOnboardingCoverageGap{
		{
			Capability:  "live_stackset_execution",
			Status:      "out_of_scope",
			Reason:      "Identrail does not execute the StackSet on behalf of operators; the app surface previews and recovers the operation but the operator launches it via the AWS console URL.",
			Remediation: "Use the launch_url to open the AWS console and authorize the StackSet operation.",
		},
		{
			Capability:  "secret_value_inspection",
			Status:      "unsupported",
			Reason:      "Onboarding reads no customer payloads, secret values, or object contents; it only plans where the read-only collector role will be deployed.",
			Remediation: "Inspect values through the owning service outside Identrail.",
		},
	}
	gaps = append(gaps, AWSStackSetOnboardingCoverageGap{
		Capability:  "write_capabilities_excluded",
		Status:      "out_of_scope",
		Reason:      "The StackSet template only grants the read-only discovery tier. Remediation and authorization-enforcement tiers must be granted through a dedicated write role.",
		Remediation: "Use the connector capability tiers surface to plan separate write-tier onboarding when required.",
	})

	pinnedTemplate := strings.TrimSpace(templateURL)
	if pinnedTemplate == "" {
		pinnedTemplate = "https://fixture.identrail.invalid/templates/identrail-readonly-stackset.yaml"
	}

	if fixtureState == "empty" {
		// Empty: no targets configured. The planner will block on the
		// targets-present prerequisite.
		return awscontract.StackSetOnboardingConfig{
			ConnectorID:         connectorID,
			OrganizationID:      "o-fixture",
			ManagementAccountID: accountID,
			StackSetName:        "identrail-readonly-connector-stackset",
			TemplateURL:         pinnedTemplate,
			TemplateChecksum:    "sha256:fixture-empty",
			DeploymentMode:      deploymentMode,
			Partition:           awsStackSetPartition(region),
			TrustedAccessReady:  true,
			DelegatedAdminReady: true,
			ExternalID:          firstNonEmptyAWSValue(connectorExternalID, "external-id-fixture"),
			Targets:             awscontract.StackSetOnboardingTargets{},
		}, nil, gaps
	}

	siblingAccount := awsStackSetSiblingAccount(accountID)
	tertiaryAccount := awsStackSetSiblingAccount(siblingAccount)
	secondaryRegion := awsStackSetSecondaryRegion(region)

	config := awscontract.StackSetOnboardingConfig{
		ConnectorID:         connectorID,
		OrganizationID:      "o-fixture",
		ManagementAccountID: accountID,
		StackSetName:        "identrail-readonly-connector-stackset",
		TemplateURL:         pinnedTemplate,
		TemplateChecksum:    "sha256:fixture-success",
		DeploymentMode:      deploymentMode,
		Partition:           awsStackSetPartition(region),
		TrustedAccessReady:  true,
		DelegatedAdminReady: true,
		ExternalID:          firstNonEmptyAWSValue(connectorExternalID, "external-id-fixture"),
		Targets: awscontract.StackSetOnboardingTargets{
			OrganizationID: "o-fixture",
			OrganizationalUnits: []awscontract.OrganizationUnit{
				{ID: "ou-prod", Name: "Production", Path: "/Root/Production", Enabled: true},
				{ID: "ou-data", Name: "Data", Path: "/Root/Data", Enabled: true},
			},
			Accounts: []awscontract.StackSetOnboardingTargetAccount{
				{AccountID: accountID, Name: "management", Management: true, OUPath: "/Root"},
				{AccountID: siblingAccount, Name: "production", OUPath: "/Root/Production"},
				{AccountID: tertiaryAccount, Name: "data", OUPath: "/Root/Data"},
			},
			Regions: []awscontract.StackSetOnboardingTargetRegion{
				{Region: region},
				{Region: secondaryRegion},
			},
		},
	}

	switch fixtureState {
	case "permission_denied":
		config.TrustedAccessReady = false
		config.ExternalID = ""
	case "degraded":
		config.DelegatedAdminReady = false
		config.Targets.Accounts = append(config.Targets.Accounts, awscontract.StackSetOnboardingTargetAccount{AccountID: awsStackSetSiblingAccount(tertiaryAccount), Name: "retired-sandbox", Suspended: true, OUPath: "/Root/Sandbox"})
		config.Checkpoints = []awscontract.StackSetOnboardingCheckpoint{
			{AccountID: accountID, Region: region, State: awscontract.StackSetStateActive, StackID: "stack-fixture-1"},
			{AccountID: siblingAccount, Region: region, State: awscontract.StackSetStateActive, StackID: "stack-fixture-2"},
		}
	case "partial_failure":
		config.Checkpoints = []awscontract.StackSetOnboardingCheckpoint{
			{AccountID: accountID, Region: region, State: awscontract.StackSetStateActive, StackID: "stack-fixture-1"},
			{AccountID: siblingAccount, Region: region, State: awscontract.StackSetStateActive, StackID: "stack-fixture-2"},
			{AccountID: tertiaryAccount, Region: region, State: awscontract.StackSetStateFailed, FailureReason: "Throttling: CreateStackInstances throttled after retries", Attempts: 3},
			{AccountID: tertiaryAccount, Region: secondaryRegion, State: awscontract.StackSetStatePermissionDenied, FailureReason: "AccessDenied: assume into member account failed"},
		}
	default:
		// success
		config.Checkpoints = []awscontract.StackSetOnboardingCheckpoint{
			{AccountID: accountID, Region: region, State: awscontract.StackSetStateActive, StackID: "stack-fixture-1"},
			{AccountID: siblingAccount, Region: region, State: awscontract.StackSetStateActive, StackID: "stack-fixture-2"},
		}
	}

	diagnostics := []AWSStackSetOnboardingDiagnostic{}
	switch fixtureState {
	case "permission_denied":
		diagnostics = append(diagnostics, AWSStackSetOnboardingDiagnostic{
			Source:      "stackset_onboarding_planner",
			Scope:       "organizations.trusted_access",
			Code:        "trusted_access_disabled",
			Message:     "AWS Organizations trusted access for CloudFormation StackSets is not enabled in this organization.",
			Remediation: "From the management account, enable trusted access for CloudFormation StackSets, then re-run onboarding.",
			Retryable:   false,
		})
	case "partial_failure":
		diagnostics = append(diagnostics, AWSStackSetOnboardingDiagnostic{
			Source:      "stackset_onboarding_planner",
			Scope:       tertiaryAccount + "/" + region,
			Code:        "create_stack_instance_throttled",
			Message:     "AWS throttled CreateStackInstances for one account/region pair after bounded retries; this instance is resumable.",
			Remediation: "Retry this instance from the onboarding surface after the throttle window passes.",
			Retryable:   true,
		})
	case "degraded":
		diagnostics = append(diagnostics, AWSStackSetOnboardingDiagnostic{
			Source:      "stackset_onboarding_planner",
			Scope:       "organizations.delegated_admin",
			Code:        "delegated_admin_missing",
			Message:     "Onboarding is running from the management account because a delegated administrator is not registered.",
			Remediation: "Register a CloudFormation StackSets delegated administrator account to reduce blast radius.",
			Retryable:   true,
		})
	}

	return config, diagnostics, gaps
}

func mapAWSStackSetValidation(validation awscontract.StackSetOnboardingValidation) AWSStackSetOnboardingValidation {
	prereqs := make([]AWSStackSetOnboardingPrerequisite, 0, len(validation.Prerequisites))
	for _, prereq := range validation.Prerequisites {
		prereqs = append(prereqs, AWSStackSetOnboardingPrerequisite{
			ID:          prereq.ID,
			Title:       prereq.Title,
			Severity:    string(prereq.Severity),
			Satisfied:   prereq.Satisfied,
			Reason:      prereq.Reason,
			Remediation: prereq.Remediation,
		})
	}
	failures := validation.FailureReasons
	if failures == nil {
		failures = []string{}
	}
	remediations := validation.RemediationHints
	if remediations == nil {
		remediations = []string{}
	}
	return AWSStackSetOnboardingValidation{
		Status:           string(validation.Status),
		Confidence:       validation.Confidence,
		BlockingCount:    validation.BlockingCount,
		AdvisoryCount:    validation.AdvisoryCount,
		Prerequisites:    prereqs,
		FailureReasons:   failures,
		RemediationHints: remediations,
	}
}

func mapAWSStackSetTargets(targets awscontract.StackSetOnboardingTargets) AWSStackSetOnboardingTargets {
	out := AWSStackSetOnboardingTargets{
		OrganizationID:      strings.TrimSpace(targets.OrganizationID),
		OrganizationalUnits: make([]AWSStackSetOnboardingOU, 0, len(targets.OrganizationalUnits)),
		Accounts:            make([]AWSStackSetOnboardingTargetAccount, 0, len(targets.Accounts)),
		Regions:             make([]AWSStackSetOnboardingTargetRegion, 0, len(targets.Regions)),
	}
	for _, ou := range targets.OrganizationalUnits {
		out.OrganizationalUnits = append(out.OrganizationalUnits, AWSStackSetOnboardingOU{
			ID:       ou.ID,
			Name:     ou.Name,
			ParentID: ou.ParentID,
			Path:     ou.Path,
			Enabled:  ou.Enabled,
			Reason:   ou.Reason,
		})
	}
	for _, account := range targets.Accounts {
		out.Accounts = append(out.Accounts, AWSStackSetOnboardingTargetAccount{
			AccountID:  account.AccountID,
			Name:       account.Name,
			OUPath:     account.OUPath,
			Management: account.Management,
			Suspended:  account.Suspended,
		})
	}
	for _, region := range targets.Regions {
		out.Regions = append(out.Regions, AWSStackSetOnboardingTargetRegion{
			Region: region.Region,
			Name:   region.Name,
			OptIn:  region.OptIn,
		})
	}
	return out
}

func mapAWSStackSetInstances(instances []awscontract.StackSetOnboardingInstance) []AWSStackSetOnboardingInstance {
	out := make([]AWSStackSetOnboardingInstance, 0, len(instances))
	for _, instance := range instances {
		out = append(out, AWSStackSetOnboardingInstance{
			Key:             instance.Key,
			AccountID:       instance.AccountID,
			AccountName:     instance.AccountName,
			OUPath:          instance.OUPath,
			Region:          instance.Region,
			RegionName:      instance.RegionName,
			State:           string(instance.State),
			StackID:         instance.StackID,
			OperationID:     instance.OperationID,
			FailureReason:   instance.FailureReason,
			Attempts:        instance.Attempts,
			Resumable:       instance.Resumable,
			Suspended:       instance.Suspended,
			OptInRegion:     instance.OptInRegion,
			NextAction:      instance.NextAction,
			CoverageTargets: instance.CoverageTargets,
			EvidenceRef:     instance.EvidenceRef,
			ObservedAt:      instance.ObservedAt,
		})
	}
	return out
}

func mapAWSStackSetCoverageExpectation(expectation awscontract.StackSetOnboardingCoverageExpectation) AWSStackSetOnboardingCoverageExpectation {
	return AWSStackSetOnboardingCoverageExpectation{
		ExpectedAccounts:        expectation.ExpectedAccounts,
		ExpectedRegions:         expectation.ExpectedRegions,
		ExpectedInstances:       expectation.ExpectedInstances,
		ExpectedCoverageTargets: expectation.ExpectedCoverage,
		CoveragePercent:         expectation.CoveragePercent,
		GlobalServiceNotes:      expectation.GlobalServiceNotes,
	}
}

func mapAWSStackSetRecoveryActions(actions []awscontract.StackSetOnboardingRecoveryAction) []AWSStackSetOnboardingRecoveryAction {
	out := make([]AWSStackSetOnboardingRecoveryAction, 0, len(actions))
	for _, action := range actions {
		targets := action.Targets
		if targets == nil {
			targets = []string{}
		}
		out = append(out, AWSStackSetOnboardingRecoveryAction{
			ID:          action.ID,
			Title:       action.Title,
			Description: action.Description,
			Targets:     targets,
		})
	}
	return out
}

func mapAWSStackSetSummary(summary awscontract.StackSetOnboardingSummary) AWSStackSetOnboardingSummary {
	stateCounts := map[string]int{}
	for state, count := range summary.StateCounts {
		stateCounts[string(state)] = count
	}
	return AWSStackSetOnboardingSummary{
		TargetAccounts:       summary.TargetAccounts,
		TargetRegions:        summary.TargetRegions,
		TotalInstances:       summary.TotalInstances,
		PendingInstances:     summary.PendingInstances,
		ActiveInstances:      summary.ActiveInstances,
		BlockedInstances:     summary.BlockedInstances,
		FailedInstances:      summary.FailedInstances,
		DegradedInstances:    summary.DegradedInstances,
		SuspendedInstances:   summary.SuspendedInstances,
		PermissionDenied:     summary.PermissionDenied,
		UnsupportedInstances: summary.UnsupportedInstances,
		ResumableInstances:   summary.ResumableInstances,
		DeployedPercent:      summary.DeployedPercent,
		StateCounts:          stateCounts,
	}
}

func awsStackSetPermissionPreview() []AWSStackSetOnboardingPermissionPreview {
	tiers := awsconnector.CapabilityPermissionTiers()
	out := make([]AWSStackSetOnboardingPermissionPreview, 0, len(tiers))
	for _, tier := range tiers {
		items := make([]AWSStackSetOnboardingPermissionPreviewItem, 0, len(tier.Permissions))
		for _, item := range tier.Permissions {
			items = append(items, AWSStackSetOnboardingPermissionPreviewItem{
				Service:   item.Service,
				Actions:   item.Actions,
				Resources: item.Resources,
				Reason:    item.Reason,
			})
		}
		out = append(out, AWSStackSetOnboardingPermissionPreview{
			Capability:  string(tier.Capability),
			Tier:        string(tier.Tier),
			Available:   tier.Available,
			Summary:     tier.Summary,
			Permissions: items,
		})
	}
	return out
}

func summarizeAWSStackSetOnboarding(fixtureState string, plan awscontract.StackSetOnboardingPlan, diagnostics []AWSStackSetOnboardingDiagnostic) (string, float64, []string, []string) {
	failures := append([]string{}, plan.Validation.FailureReasons...)
	remediations := append([]string{}, plan.Validation.RemediationHints...)
	for _, diagnostic := range diagnostics {
		if msg := strings.TrimSpace(diagnostic.Message); msg != "" {
			failures = append(failures, msg)
		}
		if rem := strings.TrimSpace(diagnostic.Remediation); rem != "" {
			remediations = append(remediations, rem)
		}
	}

	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, dedupeStrings(failures),
			dedupeStrings(append(remediations, "Enable trusted access in AWS Organizations, then retry the StackSet onboarding."))
	case "partial_failure", "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72, dedupeStrings(failures),
			dedupeStrings(append(remediations, "Re-run failed instances after the AWS error window resolves."))
	default:
		if plan.Summary.TotalInstances == 0 {
			return awsPlatformDependencyStatusReady, 0.78, nil,
				dedupeStrings(append(remediations, "Select at least one target account/OU and one region before launching the StackSet."))
		}
		switch plan.Validation.Status {
		case awscontract.StackSetValidationBlocked:
			return awsPlatformDependencyStatusBlocked, 0.4, dedupeStrings(failures), dedupeStrings(remediations)
		case awscontract.StackSetValidationDegraded:
			return awsPlatformDependencyStatusDegraded, 0.72, dedupeStrings(failures), dedupeStrings(remediations)
		default:
			return awsPlatformDependencyStatusReady, 0.94, dedupeStrings(failures),
				dedupeStrings(append(remediations, "Open the StackSet console launch URL to deploy the read-only connector across the target accounts."))
		}
	}
}

func collectStackSetOUIDs(units []awscontract.OrganizationUnit) []string {
	out := make([]string, 0, len(units))
	for _, ou := range units {
		if id := strings.TrimSpace(ou.ID); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func collectStackSetAccountIDs(accounts []awscontract.StackSetOnboardingTargetAccount) []string {
	out := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if !account.Suspended {
			out = append(out, account.AccountID)
		}
	}
	return out
}

func collectStackSetRegionCodes(regions []awscontract.StackSetOnboardingTargetRegion) []string {
	out := make([]string, 0, len(regions))
	for _, region := range regions {
		out = append(out, region.Region)
	}
	return out
}

func awsStackSetPartition(region string) string {
	switch {
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(region)), "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(region)), "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}

func awsStackSetSiblingAccount(accountID string) string {
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

func awsStackSetSecondaryRegion(region string) string {
	if strings.EqualFold(strings.TrimSpace(region), "eu-west-1") {
		return "us-east-1"
	}
	return "eu-west-1"
}

// AWSStackSetOnboardingState is an exported coverage-state alias so the OpenAPI
// spec can enumerate the planner's lifecycle states without leaking the
// awscontract package directly.
func AWSStackSetOnboardingStates() []string {
	return []string{
		string(awscontract.StackSetStatePending),
		string(awscontract.StackSetStateValidating),
		string(awscontract.StackSetStateBlocked),
		string(awscontract.StackSetStateDeploying),
		string(awscontract.StackSetStateActive),
		string(awscontract.StackSetStateDegraded),
		string(awscontract.StackSetStateFailed),
		string(awscontract.StackSetStatePermissionDenied),
		string(awscontract.StackSetStateUnsupported),
		string(awscontract.StackSetStateSuspended),
		string(awscontract.StackSetStateCanceled),
	}
}
