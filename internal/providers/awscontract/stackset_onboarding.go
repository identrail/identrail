package awscontract

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// StackSetOnboardingVersion is the stable contract version operators cite when
// persisting or reconciling a StackSet onboarding plan.
const StackSetOnboardingVersion = "aws-stackset-onboarding-v1"

// StackSetOnboardingState is the lifecycle state of one stack instance, the
// overall onboarding plan, or a recovery action. Permission denied, unsupported,
// suspended, and partial states are explicit so onboarding never silently
// reports false success.
type StackSetOnboardingState string

const (
	// StackSetStatePending marks an instance whose deployment has not started.
	StackSetStatePending StackSetOnboardingState = "pending"
	// StackSetStateValidating marks an instance whose prerequisites are being
	// checked (for example trusted-access enablement or opt-in region status).
	StackSetStateValidating StackSetOnboardingState = "validating"
	// StackSetStateBlocked marks an instance whose prerequisites are unmet.
	StackSetStateBlocked StackSetOnboardingState = "blocked"
	// StackSetStateDeploying marks an instance whose stack create/update is
	// in flight.
	StackSetStateDeploying StackSetOnboardingState = "deploying"
	// StackSetStateActive marks an instance that has been deployed and is
	// emitting scan coverage for downstream pipelines.
	StackSetStateActive StackSetOnboardingState = "active"
	// StackSetStateDegraded marks an instance whose deployment succeeded but
	// whose connector role failed validation or drifted.
	StackSetStateDegraded StackSetOnboardingState = "degraded"
	// StackSetStateFailed marks an instance whose deployment failed and is
	// retryable.
	StackSetStateFailed StackSetOnboardingState = "failed"
	// StackSetStatePermissionDenied marks an instance whose account or region
	// rejected the StackSet operation due to a permission gap.
	StackSetStatePermissionDenied StackSetOnboardingState = "permission_denied"
	// StackSetStateUnsupported marks an instance whose region or account class is
	// not supported (for example a closed account or non-opt-in region).
	StackSetStateUnsupported StackSetOnboardingState = "unsupported"
	// StackSetStateSuspended marks an instance whose AWS account is suspended.
	StackSetStateSuspended StackSetOnboardingState = "suspended"
	// StackSetStateCanceled marks an instance whose deployment was canceled by
	// the operator before completing.
	StackSetStateCanceled StackSetOnboardingState = "canceled"
)

// StackSetDeploymentMode is the deployment model the StackSet uses to fan out
// across accounts and regions.
type StackSetDeploymentMode string

const (
	// StackSetDeploymentServiceManaged uses AWS Organizations trusted access to
	// deploy to all member accounts targeted by OU. This is the recommended mode
	// for org-wide onboarding.
	StackSetDeploymentServiceManaged StackSetDeploymentMode = "service_managed"
	// StackSetDeploymentSelfManaged uses operator-provided AdministrationRoleARN
	// + ExecutionRoleName to deploy to a discrete account set, used by orgs that
	// don't enable trusted access.
	StackSetDeploymentSelfManaged StackSetDeploymentMode = "self_managed"
)

// StackSetOnboardingPrerequisiteSeverity orders prerequisite gaps so operators
// see blocking issues before advisory ones.
type StackSetOnboardingPrerequisiteSeverity string

const (
	StackSetPrerequisiteBlocking StackSetOnboardingPrerequisiteSeverity = "blocking"
	StackSetPrerequisiteAdvisory StackSetOnboardingPrerequisiteSeverity = "advisory"
)

// StackSetOnboardingPrerequisite is one named environmental check an operator
// must satisfy before onboarding can proceed.
type StackSetOnboardingPrerequisite struct {
	ID          string                                 `json:"id"`
	Title       string                                 `json:"title"`
	Severity    StackSetOnboardingPrerequisiteSeverity `json:"severity"`
	Satisfied   bool                                   `json:"satisfied"`
	Reason      string                                 `json:"reason"`
	Remediation string                                 `json:"remediation,omitempty"`
}

// StackSetOnboardingTargetAccount is one account in the StackSet target set.
type StackSetOnboardingTargetAccount struct {
	AccountID  string `json:"account_id"`
	Name       string `json:"name,omitempty"`
	OUPath     string `json:"ou_path,omitempty"`
	Management bool   `json:"management,omitempty"`
	Suspended  bool   `json:"suspended,omitempty"`
}

// StackSetOnboardingTargetRegion is one region in the StackSet target set.
type StackSetOnboardingTargetRegion struct {
	Region string `json:"region"`
	Name   string `json:"name,omitempty"`
	OptIn  bool   `json:"opt_in,omitempty"`
}

// StackSetOnboardingTargets is the deterministic target set for the StackSet.
type StackSetOnboardingTargets struct {
	OrganizationID      string                            `json:"organization_id,omitempty"`
	AllAccounts         bool                              `json:"all_accounts,omitempty"`
	OrganizationalUnits []OrganizationUnit                `json:"organizational_units,omitempty"`
	Accounts            []StackSetOnboardingTargetAccount `json:"accounts"`
	Regions             []StackSetOnboardingTargetRegion  `json:"regions"`
}

// StackSetOnboardingCheckpoint is the persisted prior state of one stack
// instance, used to make the onboarding plan resumable across UI refreshes and
// process restarts.
type StackSetOnboardingCheckpoint struct {
	AccountID     string                  `json:"account_id"`
	Region        string                  `json:"region"`
	State         StackSetOnboardingState `json:"state"`
	StackID       string                  `json:"stack_id,omitempty"`
	OperationID   string                  `json:"operation_id,omitempty"`
	FailureReason string                  `json:"failure_reason,omitempty"`
	Attempts      int                     `json:"attempts,omitempty"`
	ObservedAt    time.Time               `json:"observed_at,omitempty"`
}

// StackSetOnboardingConfig is the input to PlanStackSetOnboarding.
type StackSetOnboardingConfig struct {
	ConnectorID         string                         `json:"connector_id,omitempty"`
	OrganizationID      string                         `json:"organization_id,omitempty"`
	ManagementAccountID string                         `json:"management_account_id,omitempty"`
	StackSetName        string                         `json:"stack_set_name,omitempty"`
	TemplateURL         string                         `json:"template_url,omitempty"`
	TemplateChecksum    string                         `json:"template_checksum,omitempty"`
	DeploymentMode      StackSetDeploymentMode         `json:"deployment_mode"`
	Partition           string                         `json:"partition,omitempty"`
	TrustedAccessReady  bool                           `json:"trusted_access_ready"`
	DelegatedAdminReady bool                           `json:"delegated_admin_ready"`
	OperatorRoleARN     string                         `json:"operator_role_arn,omitempty"`
	ExternalID          string                         `json:"external_id,omitempty"`
	Targets             StackSetOnboardingTargets      `json:"targets"`
	Checkpoints         []StackSetOnboardingCheckpoint `json:"checkpoints,omitempty"`
	CoveragePlan        *CoveragePlan                  `json:"coverage_plan,omitempty"`
}

// StackSetOnboardingInstance is one operator-visible stack instance the
// StackSet will create in a target account/region pair.
type StackSetOnboardingInstance struct {
	Key             string                  `json:"key"`
	AccountID       string                  `json:"account_id"`
	AccountName     string                  `json:"account_name,omitempty"`
	OUPath          string                  `json:"ou_path,omitempty"`
	Region          string                  `json:"region"`
	RegionName      string                  `json:"region_name,omitempty"`
	State           StackSetOnboardingState `json:"state"`
	StackID         string                  `json:"stack_id,omitempty"`
	OperationID     string                  `json:"operation_id,omitempty"`
	FailureReason   string                  `json:"failure_reason,omitempty"`
	Attempts        int                     `json:"attempts,omitempty"`
	Resumable       bool                    `json:"resumable"`
	Suspended       bool                    `json:"suspended,omitempty"`
	OptInRegion     bool                    `json:"opt_in_region,omitempty"`
	NextAction      string                  `json:"next_action"`
	EvidenceRef     string                  `json:"evidence_ref"`
	CoverageTargets int                     `json:"coverage_targets"`
	ObservedAt      time.Time               `json:"observed_at,omitempty"`
}

// StackSetOnboardingCoverageExpectation projects how the StackSet's account
// and region target set is expected to translate into scan coverage once
// active, so operators can preview blast radius before launch.
type StackSetOnboardingCoverageExpectation struct {
	ExpectedAccounts   int     `json:"expected_accounts"`
	ExpectedRegions    int     `json:"expected_regions"`
	ExpectedInstances  int     `json:"expected_instances"`
	ExpectedCoverage   int     `json:"expected_coverage_targets"`
	CoveragePercent    float64 `json:"coverage_percent"`
	GlobalServiceNotes string  `json:"global_service_notes"`
}

// StackSetOnboardingRecoveryAction is one re-runnable action the operator can
// take to advance a failed or blocked instance.
type StackSetOnboardingRecoveryAction struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Targets     []string `json:"targets"`
}

// StackSetOnboardingValidationStatus is the high-level pre-launch verdict.
type StackSetOnboardingValidationStatus string

const (
	StackSetValidationReady            StackSetOnboardingValidationStatus = "ready"
	StackSetValidationDegraded         StackSetOnboardingValidationStatus = "degraded"
	StackSetValidationBlocked          StackSetOnboardingValidationStatus = "blocked"
	StackSetValidationPermissionDenied StackSetOnboardingValidationStatus = "permission_denied"
)

// StackSetOnboardingValidation summarizes prerequisite + target feasibility so
// the app surface and CFN preview share one verdict.
type StackSetOnboardingValidation struct {
	Status           StackSetOnboardingValidationStatus `json:"status"`
	Confidence       float64                            `json:"confidence"`
	BlockingCount    int                                `json:"blocking_count"`
	AdvisoryCount    int                                `json:"advisory_count"`
	Prerequisites    []StackSetOnboardingPrerequisite   `json:"prerequisites"`
	FailureReasons   []string                           `json:"failure_reasons"`
	RemediationHints []string                           `json:"remediation_hints"`
}

// StackSetOnboardingSummary aggregates the onboarding plan for dashboards.
type StackSetOnboardingSummary struct {
	TargetAccounts       int                             `json:"target_accounts"`
	TargetRegions        int                             `json:"target_regions"`
	TotalInstances       int                             `json:"total_instances"`
	PendingInstances     int                             `json:"pending_instances"`
	ActiveInstances      int                             `json:"active_instances"`
	BlockedInstances     int                             `json:"blocked_instances"`
	FailedInstances      int                             `json:"failed_instances"`
	DegradedInstances    int                             `json:"degraded_instances"`
	SuspendedInstances   int                             `json:"suspended_instances"`
	PermissionDenied     int                             `json:"permission_denied_instances"`
	UnsupportedInstances int                             `json:"unsupported_instances"`
	ResumableInstances   int                             `json:"resumable_instances"`
	DeployedPercent      float64                         `json:"deployed_percent"`
	StateCounts          map[StackSetOnboardingState]int `json:"state_counts"`
}

// StackSetOnboardingPlan is the deterministic output of PlanStackSetOnboarding.
type StackSetOnboardingPlan struct {
	ConnectorID         string                                `json:"connector_id,omitempty"`
	OrganizationID      string                                `json:"organization_id,omitempty"`
	ManagementAccountID string                                `json:"management_account_id,omitempty"`
	StackSetName        string                                `json:"stack_set_name"`
	TemplateURL         string                                `json:"template_url,omitempty"`
	TemplateChecksum    string                                `json:"template_checksum,omitempty"`
	DeploymentMode      StackSetDeploymentMode                `json:"deployment_mode"`
	Partition           string                                `json:"partition"`
	Version             string                                `json:"version"`
	Validation          StackSetOnboardingValidation          `json:"validation"`
	Targets             StackSetOnboardingTargets             `json:"targets"`
	Instances           []StackSetOnboardingInstance          `json:"instances"`
	CoverageExpectation StackSetOnboardingCoverageExpectation `json:"coverage_expectation"`
	RecoveryActions     []StackSetOnboardingRecoveryAction    `json:"recovery_actions"`
	Summary             StackSetOnboardingSummary             `json:"summary"`
	GeneratedAt         time.Time                             `json:"generated_at"`
}

// defaultStackSetName is used when callers do not pin a name. It mirrors the
// single-stack naming used for one-account onboarding.
const defaultStackSetName = "identrail-readonly-connector-stackset"

// PlanStackSetOnboarding turns an Organizations + StackSet onboarding
// configuration into a deterministic, resumable onboarding plan. It is a pure
// function: identical inputs always produce identical output so the API,
// dashboards, and recovery UI stay reconcilable. It performs no AWS calls,
// reads no customer payloads, and never mutates AWS state.
//
// The planner expands the configured account/region target set into one
// instance per account/region pair, derives prerequisites from the deployment
// mode + topology + partition, replays prior checkpoints, projects coverage
// expectations, and synthesizes recovery actions.
func PlanStackSetOnboarding(config StackSetOnboardingConfig, generatedAt time.Time) (StackSetOnboardingPlan, error) {
	mode := normalizeStackSetDeploymentMode(config.DeploymentMode)
	stackSetName := strings.TrimSpace(config.StackSetName)
	if stackSetName == "" {
		stackSetName = defaultStackSetName
	}
	partition := normalizeOrganizationsPartition(config.Partition)
	accounts, err := normalizeStackSetTargetAccounts(config.Targets.Accounts)
	if err != nil {
		return StackSetOnboardingPlan{}, err
	}
	regions, err := normalizeStackSetTargetRegions(config.Targets.Regions)
	if err != nil {
		return StackSetOnboardingPlan{}, err
	}
	checkpoints, err := indexStackSetCheckpoints(config.Checkpoints)
	if err != nil {
		return StackSetOnboardingPlan{}, err
	}

	prerequisites := evaluateStackSetPrerequisites(config, mode, accounts, regions)
	validation := summarizeStackSetValidation(prerequisites)

	instances := []StackSetOnboardingInstance{}
	for _, account := range accounts {
		for _, region := range regions {
			instance := buildStackSetInstance(config.ConnectorID, account, region, checkpoints, prerequisites, validation, config.CoveragePlan)
			instances = append(instances, instance)
		}
	}
	sort.SliceStable(instances, func(i, j int) bool { return instances[i].Key < instances[j].Key })

	summary := summarizeStackSetInstances(instances, len(accounts), len(regions))
	expectation := projectStackSetCoverage(config.CoveragePlan, accounts, regions)
	recovery := synthesizeStackSetRecoveryActions(instances, prerequisites, mode)

	return StackSetOnboardingPlan{
		ConnectorID:         strings.TrimSpace(config.ConnectorID),
		OrganizationID:      strings.TrimSpace(config.OrganizationID),
		ManagementAccountID: strings.TrimSpace(config.ManagementAccountID),
		StackSetName:        stackSetName,
		TemplateURL:         strings.TrimSpace(config.TemplateURL),
		TemplateChecksum:    strings.TrimSpace(config.TemplateChecksum),
		DeploymentMode:      mode,
		Partition:           partition,
		Version:             StackSetOnboardingVersion,
		Validation:          validation,
		Targets: StackSetOnboardingTargets{
			OrganizationID:      strings.TrimSpace(config.OrganizationID),
			AllAccounts:         config.Targets.AllAccounts,
			OrganizationalUnits: append([]OrganizationUnit(nil), config.Targets.OrganizationalUnits...),
			Accounts:            accounts,
			Regions:             regions,
		},
		Instances:           instances,
		CoverageExpectation: expectation,
		RecoveryActions:     recovery,
		Summary:             summary,
		GeneratedAt:         generatedAt.UTC(),
	}, nil
}

func normalizeStackSetDeploymentMode(mode StackSetDeploymentMode) StackSetDeploymentMode {
	switch StackSetDeploymentMode(strings.ToLower(strings.TrimSpace(string(mode)))) {
	case StackSetDeploymentServiceManaged, StackSetDeploymentSelfManaged:
		return StackSetDeploymentMode(strings.ToLower(strings.TrimSpace(string(mode))))
	default:
		return StackSetDeploymentServiceManaged
	}
}

func normalizeStackSetTargetAccounts(input []StackSetOnboardingTargetAccount) ([]StackSetOnboardingTargetAccount, error) {
	out := make([]StackSetOnboardingTargetAccount, 0, len(input))
	outByID := map[string]int{}
	for _, account := range input {
		accountID := strings.TrimSpace(account.AccountID)
		if !isTwelveDigitAWSAccountID(accountID) {
			return nil, fmt.Errorf("stackset target account id %q must be 12 digits", account.AccountID)
		}
		account.AccountID = accountID
		account.Name = strings.TrimSpace(account.Name)
		account.OUPath = strings.TrimSpace(account.OUPath)
		if mergeIndex, ok := outByID[accountID]; ok {
			merge := &out[mergeIndex]
			merge.Management = merge.Management || account.Management
			merge.Suspended = merge.Suspended || account.Suspended
			if account.Name != "" && (merge.Name == "" || account.Name < merge.Name) {
				merge.Name = account.Name
			}
			if account.OUPath != "" && (merge.OUPath == "" || account.OUPath < merge.OUPath) {
				merge.OUPath = account.OUPath
			}
			continue
		}
		outByID[accountID] = len(out)
		out = append(out, account)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out, nil
}

func normalizeStackSetTargetRegions(input []StackSetOnboardingTargetRegion) ([]StackSetOnboardingTargetRegion, error) {
	out := make([]StackSetOnboardingTargetRegion, 0, len(input))
	seen := map[string]struct{}{}
	for _, region := range input {
		code := strings.ToLower(strings.TrimSpace(region.Region))
		if code == "" {
			return nil, fmt.Errorf("stackset target region code is required")
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		region.Region = code
		out = append(out, region)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Region < out[j].Region })
	return out, nil
}

func indexStackSetCheckpoints(input []StackSetOnboardingCheckpoint) (map[string]StackSetOnboardingCheckpoint, error) {
	index := make(map[string]StackSetOnboardingCheckpoint, len(input))
	for _, checkpoint := range input {
		accountID := strings.TrimSpace(checkpoint.AccountID)
		region := strings.ToLower(strings.TrimSpace(checkpoint.Region))
		if accountID == "" || region == "" {
			return nil, fmt.Errorf("stackset checkpoint requires account and region")
		}
		if checkpoint.State != "" && !validStackSetOnboardingState(checkpoint.State) {
			return nil, fmt.Errorf("stackset checkpoint has invalid state %q", checkpoint.State)
		}
		index[stackSetInstanceKey(accountID, region)] = checkpoint
	}
	return index, nil
}

func evaluateStackSetPrerequisites(config StackSetOnboardingConfig, mode StackSetDeploymentMode, accounts []StackSetOnboardingTargetAccount, regions []StackSetOnboardingTargetRegion) []StackSetOnboardingPrerequisite {
	prereqs := []StackSetOnboardingPrerequisite{}

	templateOK := strings.TrimSpace(config.TemplateURL) != "" && strings.TrimSpace(config.TemplateChecksum) != ""
	prereqs = append(prereqs, StackSetOnboardingPrerequisite{
		ID:        "stackset.template_pinned",
		Title:     "Connector CloudFormation template is pinned",
		Severity:  StackSetPrerequisiteBlocking,
		Satisfied: templateOK,
		Reason: func() string {
			if templateOK {
				return "Template URL and integrity checksum are configured."
			}
			return "Template URL or integrity checksum is missing; the StackSet cannot be launched without a pinned template."
		}(),
		Remediation: "Configure IDENTRAIL_AWS_CFN_TEMPLATE_URL and IDENTRAIL_AWS_CFN_TEMPLATE_SHA256 so the read-only connector template is reproducible.",
	})

	externalIDOK := strings.TrimSpace(config.ExternalID) != ""
	prereqs = append(prereqs, StackSetOnboardingPrerequisite{
		ID:        "stackset.external_id_configured",
		Title:     "External ID is configured for trust",
		Severity:  StackSetPrerequisiteBlocking,
		Satisfied: externalIDOK,
		Reason: func() string {
			if externalIDOK {
				return "An external ID is pinned for the read-only role trust policy."
			}
			return "No external ID is configured; the StackSet cannot launch a role trust without it."
		}(),
		Remediation: "Generate an external ID on the connector before opening the StackSet console launch URL.",
	})

	if mode == StackSetDeploymentServiceManaged {
		prereqs = append(prereqs, StackSetOnboardingPrerequisite{
			ID:        "stackset.trusted_access_enabled",
			Title:     "Trusted access for CloudFormation StackSets is enabled",
			Severity:  StackSetPrerequisiteBlocking,
			Satisfied: config.TrustedAccessReady,
			Reason: func() string {
				if config.TrustedAccessReady {
					return "Service-managed StackSets can deploy to org targets."
				}
				return "Service-managed StackSets require trusted access between AWS Organizations and CloudFormation."
			}(),
			Remediation: "From the management account, enable trusted access for CloudFormation StackSets in AWS Organizations.",
		})
		prereqs = append(prereqs, StackSetOnboardingPrerequisite{
			ID:        "stackset.delegated_admin_registered",
			Title:     "CloudFormation delegated administrator is registered",
			Severity:  StackSetPrerequisiteAdvisory,
			Satisfied: config.DelegatedAdminReady,
			Reason: func() string {
				if config.DelegatedAdminReady {
					return "Onboarding can run from the delegated administrator account."
				}
				return "Without a delegated administrator, onboarding must run from the management account itself."
			}(),
			Remediation: "Register a delegated administrator for CloudFormation StackSets so onboarding does not require the management account.",
		})
	} else {
		hasAdminRole := strings.TrimSpace(config.OperatorRoleARN) != ""
		prereqs = append(prereqs, StackSetOnboardingPrerequisite{
			ID:        "stackset.administration_role_configured",
			Title:     "AdministrationRoleARN is configured for self-managed deployment",
			Severity:  StackSetPrerequisiteBlocking,
			Satisfied: hasAdminRole,
			Reason: func() string {
				if hasAdminRole {
					return "Self-managed StackSet has an administration role ARN."
				}
				return "Self-managed StackSets require an AWSCloudFormationStackSetAdministrationRole ARN."
			}(),
			Remediation: "Provide a working AdministrationRoleARN and ensure ExecutionRoleName is bootstrapped in each target account.",
		})
	}

	targetIntentPresent := len(accounts) > 0 || len(config.Targets.OrganizationalUnits) > 0 || config.Targets.AllAccounts
	prereqs = append(prereqs, StackSetOnboardingPrerequisite{
		ID:        "stackset.targets_present",
		Title:     "At least one target scope and region are configured",
		Severity:  StackSetPrerequisiteBlocking,
		Satisfied: targetIntentPresent && len(regions) > 0,
		Reason: func() string {
			if len(accounts) > 0 && len(regions) > 0 {
				return fmt.Sprintf("Onboarding will create %d instance(s) across %d account(s) and %d region(s).", len(accounts)*len(regions), len(accounts), len(regions))
			}
			if targetIntentPresent && len(regions) > 0 {
				return fmt.Sprintf("Onboarding target scope is configured; AWS resolves member accounts during StackSet deployment across %d region(s).", len(regions))
			}
			return "Onboarding has no target scope or region; nothing would be deployed."
		}(),
		Remediation: "Use Organizations topology and region availability discovery to select target OUs/accounts and regions.",
	})

	// Advisory: warn if any target account is suspended.
	suspended := 0
	for _, account := range accounts {
		if account.Suspended {
			suspended++
		}
	}
	if suspended > 0 {
		prereqs = append(prereqs, StackSetOnboardingPrerequisite{
			ID:          "stackset.suspended_accounts_excluded",
			Title:       fmt.Sprintf("%d suspended account(s) will be skipped", suspended),
			Severity:    StackSetPrerequisiteAdvisory,
			Satisfied:   false,
			Reason:      "Suspended accounts cannot host StackSet deployments and are reported as suspended.",
			Remediation: "Reactivate or remove suspended accounts from the target set if you want them covered.",
		})
	}

	return prereqs
}

func summarizeStackSetValidation(prereqs []StackSetOnboardingPrerequisite) StackSetOnboardingValidation {
	validation := StackSetOnboardingValidation{
		Status:        StackSetValidationReady,
		Confidence:    0.95,
		Prerequisites: prereqs,
	}
	failures := []string{}
	remediations := []string{}
	for _, prereq := range prereqs {
		switch {
		case !prereq.Satisfied && prereq.Severity == StackSetPrerequisiteBlocking:
			validation.BlockingCount++
			failures = append(failures, prereq.Reason)
			if r := strings.TrimSpace(prereq.Remediation); r != "" {
				remediations = append(remediations, r)
			}
		case !prereq.Satisfied && prereq.Severity == StackSetPrerequisiteAdvisory:
			validation.AdvisoryCount++
			if r := strings.TrimSpace(prereq.Remediation); r != "" {
				remediations = append(remediations, r)
			}
		}
	}
	switch {
	case validation.BlockingCount > 0:
		validation.Status = StackSetValidationBlocked
		validation.Confidence = 0.35
	case validation.AdvisoryCount > 0:
		validation.Status = StackSetValidationDegraded
		validation.Confidence = 0.72
	}
	validation.FailureReasons = dedupeSortedCoverageStrings(failures)
	validation.RemediationHints = dedupeSortedCoverageStrings(remediations)
	return validation
}

func buildStackSetInstance(connectorID string, account StackSetOnboardingTargetAccount, region StackSetOnboardingTargetRegion, checkpoints map[string]StackSetOnboardingCheckpoint, prereqs []StackSetOnboardingPrerequisite, validation StackSetOnboardingValidation, plan *CoveragePlan) StackSetOnboardingInstance {
	key := stackSetInstanceKey(account.AccountID, region.Region)
	state := StackSetStatePending
	switch {
	case account.Suspended:
		state = StackSetStateSuspended
	case validation.Status == StackSetValidationBlocked:
		state = StackSetStateBlocked
	}

	instance := StackSetOnboardingInstance{
		Key:             key,
		AccountID:       account.AccountID,
		AccountName:     strings.TrimSpace(account.Name),
		OUPath:          strings.TrimSpace(account.OUPath),
		Region:          region.Region,
		RegionName:      strings.TrimSpace(region.Name),
		State:           state,
		OptInRegion:     region.OptIn,
		Suspended:       account.Suspended,
		EvidenceRef:     stackSetEvidenceRef(connectorID, account.AccountID, region.Region),
		CoverageTargets: coverageTargetsForAccountRegion(plan, account.AccountID, region.Region),
	}

	if checkpoint, ok := checkpoints[key]; ok {
		applyStackSetCheckpoint(&instance, checkpoint)
	}

	instance.Resumable = stackSetInstanceResumable(instance)
	instance.NextAction = stackSetInstanceNextAction(instance, validation)
	return instance
}

func applyStackSetCheckpoint(instance *StackSetOnboardingInstance, checkpoint StackSetOnboardingCheckpoint) {
	// Suspended accounts win over any checkpoint; AWS will reject the operation.
	if instance.State == StackSetStateSuspended {
		return
	}
	if checkpoint.State != "" {
		instance.State = checkpoint.State
	}
	instance.StackID = strings.TrimSpace(checkpoint.StackID)
	instance.OperationID = strings.TrimSpace(checkpoint.OperationID)
	instance.FailureReason = strings.TrimSpace(checkpoint.FailureReason)
	if checkpoint.Attempts > 0 {
		instance.Attempts = checkpoint.Attempts
	}
	if !checkpoint.ObservedAt.IsZero() {
		instance.ObservedAt = checkpoint.ObservedAt.UTC()
	}
}

func stackSetInstanceResumable(instance StackSetOnboardingInstance) bool {
	switch instance.State {
	case StackSetStateFailed, StackSetStateDegraded, StackSetStatePending, StackSetStateDeploying, StackSetStateValidating, StackSetStateBlocked:
		return true
	default:
		return false
	}
}

func stackSetInstanceNextAction(instance StackSetOnboardingInstance, validation StackSetOnboardingValidation) string {
	switch instance.State {
	case StackSetStateActive:
		return "No action; this instance is contributing scan coverage."
	case StackSetStateDeploying, StackSetStateValidating:
		return "CloudFormation operation in flight; wait for AWS to settle the operation."
	case StackSetStatePending:
		if validation.Status == StackSetValidationBlocked {
			return "Resolve blocking prerequisites before launching this StackSet instance."
		}
		return "Open the StackSet console launch URL to create this instance."
	case StackSetStateBlocked:
		return "Resolve blocking prerequisites; this instance cannot launch yet."
	case StackSetStateFailed:
		return "Retry this StackSet instance once the underlying AWS error has been remediated."
	case StackSetStateDegraded:
		return "Re-validate the instance role and rerun connector validation; coverage may be incomplete."
	case StackSetStatePermissionDenied:
		return "Grant trusted access or the self-managed AdministrationRole permission to this account, then rerun."
	case StackSetStateSuspended:
		return "Remove the suspended account from the target set or reactivate it before retrying."
	case StackSetStateUnsupported:
		return "Remove the unsupported region or account from the target set."
	case StackSetStateCanceled:
		return "Re-open the StackSet console launch URL to restart the operation."
	default:
		return "Queue this account/region pair for the next StackSet operation."
	}
}

func summarizeStackSetInstances(instances []StackSetOnboardingInstance, accountCount, regionCount int) StackSetOnboardingSummary {
	summary := StackSetOnboardingSummary{
		TargetAccounts: accountCount,
		TargetRegions:  regionCount,
		TotalInstances: len(instances),
		StateCounts:    map[StackSetOnboardingState]int{},
	}
	for _, instance := range instances {
		summary.StateCounts[instance.State]++
		if instance.Resumable {
			summary.ResumableInstances++
		}
		switch instance.State {
		case StackSetStateActive:
			summary.ActiveInstances++
		case StackSetStatePending, StackSetStateValidating, StackSetStateDeploying:
			summary.PendingInstances++
		case StackSetStateBlocked:
			summary.BlockedInstances++
		case StackSetStateFailed:
			summary.FailedInstances++
		case StackSetStateDegraded:
			summary.DegradedInstances++
		case StackSetStateSuspended:
			summary.SuspendedInstances++
		case StackSetStatePermissionDenied:
			summary.PermissionDenied++
		case StackSetStateUnsupported:
			summary.UnsupportedInstances++
		}
	}
	if summary.TotalInstances > 0 {
		summary.DeployedPercent = roundCoveragePercent(float64(summary.ActiveInstances) / float64(summary.TotalInstances) * 100)
	}
	return summary
}

func projectStackSetCoverage(plan *CoveragePlan, accounts []StackSetOnboardingTargetAccount, regions []StackSetOnboardingTargetRegion) StackSetOnboardingCoverageExpectation {
	expectation := StackSetOnboardingCoverageExpectation{
		ExpectedAccounts:   len(accounts),
		ExpectedRegions:    len(regions),
		ExpectedInstances:  len(accounts) * len(regions),
		GlobalServiceNotes: "Global-scope AWS services (for example IAM) are planned once per account at the global home region; per-region StackSet instances supply other services.",
	}
	if plan == nil {
		return expectation
	}
	accountSet := map[string]struct{}{}
	regionSet := map[string]struct{}{}
	for _, account := range accounts {
		accountSet[account.AccountID] = struct{}{}
	}
	for _, region := range regions {
		regionSet[strings.ToLower(region.Region)] = struct{}{}
	}
	expected := 0
	covered := 0
	for _, target := range plan.Targets {
		if !target.Enabled {
			continue
		}
		if _, ok := accountSet[target.AccountID]; !ok {
			continue
		}
		// Global services are anchored to a single home region. Count them only
		// when that home region appears in the StackSet region set.
		if !target.Global {
			if _, ok := regionSet[strings.ToLower(target.Region)]; !ok {
				continue
			}
		} else if _, ok := regionSet[strings.ToLower(target.Region)]; !ok {
			continue
		}
		expected++
		if target.State == CoverageStateCovered {
			covered++
		}
	}
	expectation.ExpectedCoverage = expected
	if expected > 0 {
		expectation.CoveragePercent = roundCoveragePercent(float64(covered) / float64(expected) * 100)
	}
	return expectation
}

func coverageTargetsForAccountRegion(plan *CoveragePlan, accountID, region string) int {
	if plan == nil {
		return 0
	}
	count := 0
	for _, target := range plan.Targets {
		if !target.Enabled {
			continue
		}
		if target.AccountID != accountID {
			continue
		}
		if target.Global {
			// Global service is anchored once per account at its home region; the
			// instance for the home region carries the count.
			if strings.EqualFold(target.Region, region) {
				count++
			}
			continue
		}
		if strings.EqualFold(target.Region, region) {
			count++
		}
	}
	return count
}

func synthesizeStackSetRecoveryActions(instances []StackSetOnboardingInstance, prereqs []StackSetOnboardingPrerequisite, mode StackSetDeploymentMode) []StackSetOnboardingRecoveryAction {
	actions := []StackSetOnboardingRecoveryAction{}

	for _, prereq := range prereqs {
		if prereq.Satisfied || prereq.Severity != StackSetPrerequisiteBlocking {
			continue
		}
		actions = append(actions, StackSetOnboardingRecoveryAction{
			ID:          "fix-" + prereq.ID,
			Title:       "Resolve " + prereq.Title,
			Description: firstNonEmpty(prereq.Remediation, "Resolve the prerequisite before retrying."),
			Targets:     []string{},
		})
	}

	failed := stackSetInstancesInState(instances, StackSetStateFailed)
	if len(failed) > 0 {
		actions = append(actions, StackSetOnboardingRecoveryAction{
			ID:          "retry-failed-instances",
			Title:       fmt.Sprintf("Retry %d failed StackSet instance(s)", len(failed)),
			Description: "Re-run the StackSet operation for the failed account/region pairs after addressing the AWS error.",
			Targets:     stackSetInstanceTargets(failed),
		})
	}

	denied := stackSetInstancesInState(instances, StackSetStatePermissionDenied)
	if len(denied) > 0 {
		title := "Grant trusted access in member accounts and retry"
		if mode == StackSetDeploymentSelfManaged {
			title = "Bootstrap AWSCloudFormationStackSetExecutionRole in member accounts and retry"
		}
		actions = append(actions, StackSetOnboardingRecoveryAction{
			ID:          "fix-permission-denied",
			Title:       title,
			Description: "AWS rejected the deployment because the management account cannot assume into the targets.",
			Targets:     stackSetInstanceTargets(denied),
		})
	}

	suspended := stackSetInstancesInState(instances, StackSetStateSuspended)
	if len(suspended) > 0 {
		actions = append(actions, StackSetOnboardingRecoveryAction{
			ID:          "remove-suspended-accounts",
			Title:       fmt.Sprintf("Remove %d suspended account(s) from the target set", uniqueAccounts(suspended)),
			Description: "Suspended accounts cannot host StackSet deployments.",
			Targets:     stackSetInstanceTargets(suspended),
		})
	}

	sort.SliceStable(actions, func(i, j int) bool { return actions[i].ID < actions[j].ID })
	return actions
}

func stackSetInstancesInState(instances []StackSetOnboardingInstance, state StackSetOnboardingState) []StackSetOnboardingInstance {
	out := []StackSetOnboardingInstance{}
	for _, instance := range instances {
		if instance.State == state {
			out = append(out, instance)
		}
	}
	return out
}

func stackSetInstanceTargets(instances []StackSetOnboardingInstance) []string {
	out := make([]string, 0, len(instances))
	for _, instance := range instances {
		out = append(out, instance.Key)
	}
	sort.Strings(out)
	return out
}

func uniqueAccounts(instances []StackSetOnboardingInstance) int {
	seen := map[string]struct{}{}
	for _, instance := range instances {
		seen[instance.AccountID] = struct{}{}
	}
	return len(seen)
}

func validStackSetOnboardingState(state StackSetOnboardingState) bool {
	switch state {
	case StackSetStatePending, StackSetStateValidating, StackSetStateBlocked, StackSetStateDeploying,
		StackSetStateActive, StackSetStateDegraded, StackSetStateFailed, StackSetStatePermissionDenied,
		StackSetStateUnsupported, StackSetStateSuspended, StackSetStateCanceled:
		return true
	default:
		return false
	}
}

func stackSetInstanceKey(accountID, region string) string {
	return strings.TrimSpace(accountID) + "|" + strings.ToLower(strings.TrimSpace(region))
}

func stackSetEvidenceRef(connectorID, accountID, region string) string {
	connector := strings.TrimSpace(connectorID)
	if connector == "" {
		connector = "connector"
	}
	return "aws:stackset:" + strings.Join([]string{
		connector,
		strings.TrimSpace(accountID),
		strings.ToLower(strings.TrimSpace(region)),
	}, ":")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if v := strings.TrimSpace(value); v != "" {
			return v
		}
	}
	return ""
}
