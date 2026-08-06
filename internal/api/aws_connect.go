package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	awsconnector "github.com/identrail/identrail/internal/connectors/aws"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

var (
	awsRoleARNPattern   = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
	awsOUIDPattern      = regexp.MustCompile(`^(ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}|r-[a-z0-9]{4,32})$`)
	awsSHA256Pattern    = regexp.MustCompile(`(?i)^(sha256:)?[a-f0-9]{64}$`)
	// awsStackSetNamePattern mirrors the CloudFormation StackSet naming
	// contract: 1–128 characters, must start with an alphabetic character,
	// and only alphanumerics and hyphens after that. Names outside this
	// contract fail CreateStackSet at the AWS console before Identrail
	// can observe deployment, so we reject them at setup time.
	awsStackSetNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,127}$`)
	// awsStackSetRoleNamePattern mirrors the RoleName parameter in the
	// published read-only connector template.
	awsStackSetRoleNamePattern = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
)

const (
	awsExternalIDSecretName     = "external_id"
	awsConnectorSecretRefPrefix = "secret-envelope://aws/"
)

// ErrInvalidAWSConnectionRequest indicates invalid AWS connector input.
var ErrInvalidAWSConnectionRequest = errors.New("invalid aws connection request")

// ErrAWSConnectionNotFound indicates one scoped project AWS connection does not exist.
var ErrAWSConnectionNotFound = errors.New("aws connection not found")

// ErrAWSConnectionValidatorUnavailable indicates live AWS validation is not configured.
var ErrAWSConnectionValidatorUnavailable = errors.New("aws connection validator unavailable")

// ErrAWSConnectorConfigUnavailable indicates the CloudFormation setup flow is not configured.
var ErrAWSConnectorConfigUnavailable = errors.New("aws connector config unavailable")

// ErrAWSConnectorLifecycleBlocked indicates that an operator has deliberately
// stopped this connector and it cannot be used for new validation or work.
var ErrAWSConnectorLifecycleBlocked = errors.New("aws connector lifecycle is blocked")

// AWSConnectorScopeType names the AWS estate boundary the connector is intended
// to cover. It is operator intent only; observed coverage is recorded separately.
type AWSConnectorScopeType string

const (
	AWSConnectorScopeSingleAccount    AWSConnectorScopeType = "single_account"
	AWSConnectorScopeOrganization     AWSConnectorScopeType = "organization"
	AWSConnectorScopeSelectedOUs      AWSConnectorScopeType = "selected_ous"
	AWSConnectorScopeSelectedAccounts AWSConnectorScopeType = "selected_accounts"
	AWSConnectorScopeManualRole       AWSConnectorScopeType = "manual_role"
)

// AWSConnectorDeploymentMethod names the setup mechanism for the selected AWS scope.
type AWSConnectorDeploymentMethod string

const (
	AWSConnectorDeploymentCloudFormation         AWSConnectorDeploymentMethod = "cloudformation"
	AWSConnectorDeploymentStackSetServiceManaged AWSConnectorDeploymentMethod = "stackset_service_managed"
	AWSConnectorDeploymentStackSetSelfManaged    AWSConnectorDeploymentMethod = "stackset_self_managed"
	AWSConnectorDeploymentTerraform              AWSConnectorDeploymentMethod = "terraform"
	AWSConnectorDeploymentManual                 AWSConnectorDeploymentMethod = "manual"
)

// AWSConnectorOnboardingStatus describes setup progress for the app. It is
// separate from connector health, which remains the source of truth for whether
// the role can currently be used.
type AWSConnectorOnboardingStatus string

const (
	AWSConnectorOnboardingDraft         AWSConnectorOnboardingStatus = "draft"
	AWSConnectorOnboardingLaunchReady   AWSConnectorOnboardingStatus = "launch_ready"
	AWSConnectorOnboardingWaitingForAWS AWSConnectorOnboardingStatus = "waiting_for_aws"
	AWSConnectorOnboardingRegistering   AWSConnectorOnboardingStatus = "registering"
	AWSConnectorOnboardingValidating    AWSConnectorOnboardingStatus = "validating"
	AWSConnectorOnboardingConnected     AWSConnectorOnboardingStatus = "connected"
	AWSConnectorOnboardingPartial       AWSConnectorOnboardingStatus = "partial"
	AWSConnectorOnboardingNeedsFix      AWSConnectorOnboardingStatus = "needs_fix"
	AWSConnectorOnboardingExpired       AWSConnectorOnboardingStatus = "expired"
	AWSConnectorOnboardingFailed        AWSConnectorOnboardingStatus = "failed"
)

// AWSConnectorNextAction is one typed operator action the app can render.
type AWSConnectorNextAction string

const (
	AWSConnectorNextActionLaunchStack            AWSConnectorNextAction = "launch_stack"
	AWSConnectorNextActionOpenStackSet           AWSConnectorNextAction = "open_stackset"
	AWSConnectorNextActionEnableTrustedAccess    AWSConnectorNextAction = "enable_trusted_access"
	AWSConnectorNextActionRegisterDelegatedAdmin AWSConnectorNextAction = "register_delegated_admin"
	AWSConnectorNextActionSelectTargets          AWSConnectorNextAction = "select_targets"
	AWSConnectorNextActionValidateRole           AWSConnectorNextAction = "validate_role"
	AWSConnectorNextActionRefreshStatus          AWSConnectorNextAction = "refresh_status"
	AWSConnectorNextActionRepairPermissions      AWSConnectorNextAction = "repair_permissions"
	AWSConnectorNextActionRefreshPolicy          AWSConnectorNextAction = "refresh_policy"
	AWSConnectorNextActionCopyTrustPolicy        AWSConnectorNextAction = "copy_trust_policy"
	AWSConnectorNextActionOpenDocs               AWSConnectorNextAction = "open_docs"
	AWSConnectorNextActionStartIntelligence      AWSConnectorNextAction = "start_intelligence"
)

// AWSConnectorValidator validates one AWS read-only connector setup.
type AWSConnectorValidator interface {
	ValidateAWSConnection(ctx context.Context, request AWSConnectionValidationRequest) (AWSConnectionValidationResult, error)
}

// AWSConnectionUpsertRequest captures one project AWS connector onboarding request.
type AWSConnectionUpsertRequest struct {
	ConnectorID            string                       `json:"connector_id,omitempty"`
	DisplayName            string                       `json:"display_name,omitempty"`
	RoleARN                string                       `json:"role_arn"`
	ExternalID             string                       `json:"external_id,omitempty"`
	Region                 string                       `json:"region,omitempty"`
	SessionName            string                       `json:"session_name,omitempty"`
	Capabilities           []domain.ConnectorCapability `json:"capabilities,omitempty"`
	ScopeType              AWSConnectorScopeType        `json:"scope_type,omitempty"`
	DeploymentMethod       AWSConnectorDeploymentMethod `json:"deployment_method,omitempty"`
	TargetRegions          []string                     `json:"target_regions,omitempty"`
	TargetAccountIDs       []string                     `json:"target_account_ids,omitempty"`
	TargetOUIDs            []string                     `json:"target_ou_ids,omitempty"`
	ExcludedAccountIDs     []string                     `json:"excluded_account_ids,omitempty"`
	AutoOnboardNewAccounts bool                         `json:"auto_onboard_new_accounts,omitempty"`
	allowSetupContract     bool
	preserveLaunchMetadata map[string]any
	lifecycleGeneration    int64
}

// AWSConnectorStartRequest starts the CloudFormation-based AWS connector flow.
type AWSConnectorStartRequest struct {
	WorkspaceID            string                       `json:"workspace_id,omitempty"`
	ProjectID              string                       `json:"project_id,omitempty"`
	ConnectorID            string                       `json:"connector_id,omitempty"`
	DisplayName            string                       `json:"display_name,omitempty"`
	Region                 string                       `json:"region,omitempty"`
	RoleName               string                       `json:"role_name,omitempty"`
	StackName              string                       `json:"stack_name,omitempty"`
	StackSetName           string                       `json:"stack_set_name,omitempty"`
	ScopeType              AWSConnectorScopeType        `json:"scope_type,omitempty"`
	DeploymentMethod       AWSConnectorDeploymentMethod `json:"deployment_method,omitempty"`
	TargetRegions          []string                     `json:"target_regions,omitempty"`
	TargetAccountIDs       []string                     `json:"target_account_ids,omitempty"`
	TargetOUIDs            []string                     `json:"target_ou_ids,omitempty"`
	ExcludedAccountIDs     []string                     `json:"excluded_account_ids,omitempty"`
	AutoOnboardNewAccounts bool                         `json:"auto_onboard_new_accounts,omitempty"`
	RepairOnly             bool                         `json:"repair_only,omitempty"`
}

// AWSConnectorValidateRequest validates a CloudFormation-created AWS connector role.
type AWSConnectorValidateRequest struct {
	WorkspaceID            string                       `json:"workspace_id,omitempty"`
	ProjectID              string                       `json:"project_id,omitempty"`
	RoleARN                string                       `json:"role_arn"`
	ExternalID             string                       `json:"external_id,omitempty"`
	Region                 string                       `json:"region,omitempty"`
	SessionName            string                       `json:"session_name,omitempty"`
	Capabilities           []domain.ConnectorCapability `json:"capabilities,omitempty"`
	ScopeType              AWSConnectorScopeType        `json:"scope_type,omitempty"`
	DeploymentMethod       AWSConnectorDeploymentMethod `json:"deployment_method,omitempty"`
	TargetRegions          []string                     `json:"target_regions,omitempty"`
	TargetAccountIDs       []string                     `json:"target_account_ids,omitempty"`
	TargetOUIDs            []string                     `json:"target_ou_ids,omitempty"`
	ExcludedAccountIDs     []string                     `json:"excluded_account_ids,omitempty"`
	AutoOnboardNewAccounts bool                         `json:"auto_onboard_new_accounts,omitempty"`
}

// AWSConnectorPollRequest resolves project scope for the flat connector poll API.
type AWSConnectorPollRequest struct {
	WorkspaceID string `form:"workspace_id" json:"workspace_id,omitempty"`
	ProjectID   string `form:"project_id" json:"project_id,omitempty"`
}

// AWSConnectorTargetSummary summarizes operator-declared StackSet coverage
// intent. Counts are only marked known when the request included account IDs;
// organization and OU scopes are resolved by AWS during StackSet deployment.
type AWSConnectorTargetSummary struct {
	AccountCount                int  `json:"account_count"`
	AccountCountKnown           bool `json:"account_count_known"`
	OUCount                     int  `json:"ou_count"`
	RegionCount                 int  `json:"region_count"`
	ExcludedAccountCount        int  `json:"excluded_account_count"`
	ExpectedStackInstances      int  `json:"expected_stack_instances"`
	ExpectedStackInstancesKnown bool `json:"expected_stack_instances_known"`
	AllAccounts                 bool `json:"all_accounts"`
}

// AWSConnectorStartResponse returns launch data for the one-click AWS setup flow.
type AWSConnectorStartResponse struct {
	Connection             AWSConnectionStatus                     `json:"connection"`
	ConnectorID            string                                  `json:"connector_id"`
	ExternalID             string                                  `json:"external_id,omitempty"`
	LaunchURL              string                                  `json:"launch_url"`
	TemplateURL            string                                  `json:"template_url"`
	IdentrailAccountID     string                                  `json:"identrail_account_id,omitempty"`
	RoleName               string                                  `json:"role_name"`
	StackName              string                                  `json:"stack_name"`
	StackSetName           string                                  `json:"stack_set_name,omitempty"`
	PolicyHash             string                                  `json:"policy_hash"`
	TemplateChecksum       string                                  `json:"template_checksum,omitempty"`
	ScopeType              AWSConnectorScopeType                   `json:"scope_type"`
	DeploymentMethod       AWSConnectorDeploymentMethod            `json:"deployment_method"`
	OnboardingStatus       AWSConnectorOnboardingStatus            `json:"onboarding_status"`
	TargetRegions          []string                                `json:"target_regions"`
	TargetAccountIDs       []string                                `json:"target_account_ids"`
	TargetOUIDs            []string                                `json:"target_ou_ids"`
	ExcludedAccountIDs     []string                                `json:"excluded_account_ids"`
	AutoOnboardNewAccounts bool                                    `json:"auto_onboard_new_accounts"`
	SetupSummary           string                                  `json:"setup_summary"`
	NextActions            []AWSConnectorNextAction                `json:"next_actions"`
	TargetSummary          *AWSConnectorTargetSummary              `json:"target_summary,omitempty"`
	Prerequisites          []AWSStackSetOnboardingPrerequisite     `json:"prerequisites,omitempty"`
	StackSetOnboarding     *AWSStackSetOnboardingResult            `json:"stackset_onboarding,omitempty"`
	PermissionPreview      []awsconnector.PermissionPreviewItem    `json:"permission_preview"`
	PermissionTiers        []awsconnector.CapabilityPermissionTier `json:"permission_tiers"`
}

// AWSConnectorPolicyResponse exposes the expected read-only policy for review.
type AWSConnectorPolicyResponse struct {
	PolicyHash        string                                  `json:"policy_hash"`
	PolicyDocument    json.RawMessage                         `json:"policy_document"`
	PermissionPreview []awsconnector.PermissionPreviewItem    `json:"permission_preview"`
	PermissionTiers   []awsconnector.CapabilityPermissionTier `json:"permission_tiers"`
}

// AWSConnectionValidationRequest is passed to the provider validator.
type AWSConnectionValidationRequest struct {
	RoleARN     string
	ExternalID  string
	Region      string
	SessionName string
}

// AWSConnectionDiagnostic explains one validation outcome and how to remediate it.
type AWSConnectionDiagnostic struct {
	Code           string                   `json:"code"`
	Severity       string                   `json:"severity,omitempty"`
	AffectedScope  string                   `json:"affected_scope,omitempty"`
	Message        string                   `json:"message"`
	OperatorAction string                   `json:"operator_action,omitempty"`
	Remediation    string                   `json:"remediation,omitempty"`
	Retryable      bool                     `json:"retryable"`
	EvidenceRef    string                   `json:"evidence_ref,omitempty"`
	Tradeoff       string                   `json:"tradeoff,omitempty"`
	Actions        []AWSConnectorNextAction `json:"actions,omitempty"`
}

// AWSConnectionPermissionCheck captures one connector permission sanity check.
type AWSConnectionPermissionCheck struct {
	Name        string `json:"name"`
	Passed      bool   `json:"passed"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSConnectorCapabilityUnavailable names a requested capability that could not be
// granted and explains why, so a validation failure points at the specific tier
// rather than a generic connector error.
type AWSConnectorCapabilityUnavailable struct {
	Capability domain.ConnectorCapability     `json:"capability"`
	Tier       domain.ConnectorCapabilityTier `json:"tier"`
	Reason     string                         `json:"reason"`
}

// AWSConnectorCapabilities reports the requested, validated, and effective
// connector capability tiers for one AWS connector. Effective never exceeds what
// the deployment's capability gate validated, so write-capable tiers cannot be
// granted implicitly.
type AWSConnectorCapabilities struct {
	Requested   []domain.ConnectorCapability        `json:"requested"`
	Validated   []domain.ConnectorCapability        `json:"validated"`
	Effective   []domain.ConnectorCapability        `json:"effective"`
	Unavailable []AWSConnectorCapabilityUnavailable `json:"unavailable"`
}

// AWSConnectionValidationResult contains the live AWS metadata and diagnostics.
type AWSConnectionValidationResult struct {
	AccountID        string                         `json:"account_id,omitempty"`
	PrincipalARN     string                         `json:"principal_arn,omitempty"`
	UserID           string                         `json:"user_id,omitempty"`
	RoleARN          string                         `json:"role_arn,omitempty"`
	Region           string                         `json:"region,omitempty"`
	PermissionChecks []AWSConnectionPermissionCheck `json:"permission_checks"`
	Diagnostics      []AWSConnectionDiagnostic      `json:"diagnostics"`
}

// AWSConnectionStatus describes current AWS connector state for one project.
type AWSConnectionStatus struct {
	Provider               string                              `json:"provider"`
	Connected              bool                                `json:"connected"`
	ConnectorID            string                              `json:"connector_id,omitempty"`
	DisplayName            string                              `json:"display_name,omitempty"`
	Status                 domain.ConnectorStatus              `json:"status"`
	Disabled               bool                                `json:"disabled"`
	LifecycleGeneration    int64                               `json:"lifecycle_generation"`
	HealthStatus           string                              `json:"health_status"`
	RoleARN                string                              `json:"role_arn,omitempty"`
	ExternalIDConfigured   bool                                `json:"external_id_configured"`
	AccountID              string                              `json:"account_id,omitempty"`
	PrincipalARN           string                              `json:"principal_arn,omitempty"`
	UserID                 string                              `json:"user_id,omitempty"`
	Region                 string                              `json:"region,omitempty"`
	OrganizationID         string                              `json:"organization_id,omitempty"`
	ScopeType              AWSConnectorScopeType               `json:"scope_type"`
	DeploymentMethod       AWSConnectorDeploymentMethod        `json:"deployment_method"`
	OnboardingStatus       AWSConnectorOnboardingStatus        `json:"onboarding_status"`
	TargetRegions          []string                            `json:"target_regions"`
	TargetAccountIDs       []string                            `json:"target_account_ids"`
	TargetOUIDs            []string                            `json:"target_ou_ids"`
	ExcludedAccountIDs     []string                            `json:"excluded_account_ids"`
	AutoOnboardNewAccounts bool                                `json:"auto_onboard_new_accounts"`
	SetupSummary           string                              `json:"setup_summary"`
	NextActions            []AWSConnectorNextAction            `json:"next_actions"`
	ExternalID             string                              `json:"-"`
	PermissionChecks       []AWSConnectionPermissionCheck      `json:"permission_checks"`
	Diagnostics            []AWSConnectionDiagnostic           `json:"diagnostics"`
	Capabilities           AWSConnectorCapabilities            `json:"capabilities"`
	RemediationMessage     string                              `json:"remediation_message,omitempty"`
	LaunchURL              string                              `json:"launch_url,omitempty"`
	TemplateURL            string                              `json:"template_url,omitempty"`
	PolicyHash             string                              `json:"policy_hash,omitempty"`
	StackSetName           string                              `json:"stack_set_name,omitempty"`
	TemplateChecksum       string                              `json:"template_checksum,omitempty"`
	TargetSummary          *AWSConnectorTargetSummary          `json:"target_summary,omitempty"`
	Prerequisites          []AWSStackSetOnboardingPrerequisite `json:"prerequisites,omitempty"`
	CreatedAt              *time.Time                          `json:"created_at,omitempty"`
	UpdatedAt              *time.Time                          `json:"updated_at,omitempty"`
	LastValidatedAt        *time.Time                          `json:"last_validated_at,omitempty"`
	CleanupStatus          string                              `json:"cleanup_status,omitempty"`
	CleanupRequired        bool                                `json:"cleanup_required"`
}

type awsConnectorSetupContract struct {
	ScopeType              AWSConnectorScopeType
	DeploymentMethod       AWSConnectorDeploymentMethod
	TargetRegions          []string
	TargetAccountIDs       []string
	TargetOUIDs            []string
	ExcludedAccountIDs     []string
	AutoOnboardNewAccounts bool
}

type awsConnectorSetupInput struct {
	ScopeType               AWSConnectorScopeType
	DeploymentMethod        AWSConnectorDeploymentMethod
	Region                  string
	TargetRegions           []string
	TargetAccountIDs        []string
	TargetOUIDs             []string
	ExcludedAccountIDs      []string
	AutoOnboardNewAccounts  bool
	DefaultScopeType        AWSConnectorScopeType
	DefaultDeploymentMethod AWSConnectorDeploymentMethod
}

func (s *Service) StartAWSConnector(ctx context.Context, request AWSConnectorStartRequest) (AWSConnectorStartResponse, error) {
	if strings.TrimSpace(request.ProjectID) == "" {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	project, scope, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	setup, err := normalizeAWSConnectorSetupContract(awsConnectorSetupInput{
		ScopeType:               request.ScopeType,
		DeploymentMethod:        request.DeploymentMethod,
		Region:                  request.Region,
		TargetRegions:           request.TargetRegions,
		TargetAccountIDs:        request.TargetAccountIDs,
		TargetOUIDs:             request.TargetOUIDs,
		ExcludedAccountIDs:      request.ExcludedAccountIDs,
		AutoOnboardNewAccounts:  request.AutoOnboardNewAccounts,
		DefaultScopeType:        AWSConnectorScopeSingleAccount,
		DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
	})
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	if request.RepairOnly && (setup.ScopeType != AWSConnectorScopeSingleAccount || setup.DeploymentMethod != AWSConnectorDeploymentCloudFormation) {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	if setup.ScopeType == AWSConnectorScopeManualRole && setup.DeploymentMethod == AWSConnectorDeploymentManual {
		return s.startAWSManualConnector(ctx, project, scope, request, setup)
	}
	if awsConnectorDeploymentIsStackSet(setup.DeploymentMethod) {
		return s.startAWSStackSetConnector(ctx, project, scope, request, setup)
	}
	if setup.ScopeType != AWSConnectorScopeSingleAccount || setup.DeploymentMethod != AWSConnectorDeploymentCloudFormation {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	templateURL := strings.TrimSpace(s.AWSCloudFormationTemplateURL)
	accountID := strings.TrimSpace(s.AWSAccountID)
	templateChecksum := normalizeAWSConnectorTemplateChecksum(s.AWSCloudFormationTemplateSHA)
	if templateURL == "" || accountID == "" || templateChecksum == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	connectorID := strings.TrimSpace(request.ConnectorID)
	if request.RepairOnly && connectorID == "" {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	if connectorID == "" {
		connectorID = "aws-" + uuid.NewString()
	} else {
		stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
		if err == nil {
			if err := ensureAWSConnectorLifecycleStartAllowed(stored); err != nil {
				return AWSConnectorStartResponse{}, err
			}
			return s.resumeAWSConnectorStart(ctx, stored, setup, request, templateURL, accountID)
		}
		if !errors.Is(err, db.ErrNotFound) {
			return AWSConnectorStartResponse{}, err
		}
		if request.RepairOnly {
			return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
		}
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		displayName = awsConnectorDefaultDisplayName("AWS account", connectorID)
	}
	if err := validateAWSConnectorStartIdentity(connectorID, displayName); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	externalID, err := generateAWSExternalID()
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	now := s.Now().UTC()
	region := setup.TargetRegions[0]
	registrationProviderARN := s.awsRegistrationTopicARN(region)
	if registrationProviderARN == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	roleName := firstNonEmptyAWSValue(strings.TrimSpace(request.RoleName), "IdentrailReadOnly")
	stackName := firstNonEmptyAWSValue(strings.TrimSpace(request.StackName), "identrail-readonly-connector")
	policyHash, err := awsconnector.ReadOnlyPolicyHash()
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}

	// The one-click CloudFormation flow provisions the read-only role only, so it
	// always starts at the discovery baseline. Write-capable tiers can never be
	// requested through this path.
	capabilities, _, err := s.resolveAWSConnectorCapabilities(domain.DefaultConnectorCapabilities())
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}

	onboardingStatus := AWSConnectorOnboardingWaitingForAWS
	metadata := map[string]any{
		"external_id_configured": true,
		"region":                 region,
		"role_name":              roleName,
		"stack_name":             stackName,
		"template_url":           templateURL,
		"template_checksum":      templateChecksum,
		"template_version":       awsConnectorTemplateVersion,
		"registration_provider":  registrationProviderARN,
		"policy_hash":            policyHash,
		"permission_checks":      []AWSConnectionPermissionCheck{},
		"diagnostics":            []AWSConnectionDiagnostic{},
		"capabilities":           capabilities,
		"last_started_at":        now.Format(time.RFC3339Nano),
	}
	applyAWSConnectorSetupMetadata(metadata, setup, onboardingStatus)
	connector := db.TenancyConnector{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		Type:                domain.ConnectorTypeAWS,
		DisplayName:         displayName,
		Status:              domain.ConnectorStatusPending,
		SecretProvider:      "secret-envelope",
		SecretRefID:         awsExternalIDSecretRef(connectorID),
		SecretRefVersion:    s.connectorSecretManager().ActiveKeyVersion(),
		SecretLastRotatedAt: &now,
		UpdatedAt:           now,
	}
	state := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  connectorID,
		HealthStatus: "unknown",
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	envelope, err := s.newAWSExternalIDSecretEnvelope(scope.TenantID, project.WorkspaceID, project.ProjectID, connectorID, externalID, now)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	stored, created, err := s.Store.CreateTenancyConnectorWithSecretEnvelopeIfAbsent(ctx, connector, state, envelope)
	if err != nil {
		return AWSConnectorStartResponse{}, fmt.Errorf("create aws connector: %w", err)
	}
	if !created {
		return s.resumeAWSConnectorStart(ctx, stored, setup, request, templateURL, accountID)
	}
	attempt, registrationToken, err := s.activeOrNewAWSConnectorOnboardingAttempt(ctx, stored, registrationProviderARN, templateChecksum, region)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	launchURL := awsconnector.BuildCloudFormationLaunchURL(awsconnector.CloudFormationLaunchInput{
		TemplateURL:             templateURL,
		Region:                  region,
		StackName:               stackName,
		IdentrailAccountID:      accountID,
		RoleName:                roleName,
		RegistrationProviderARN: registrationProviderARN,
		RegistrationAttemptID:   attempt.AttemptID,
		RegistrationToken:       registrationToken,
	})
	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.TemplateChecksum = templateChecksum
	return awsConnectorStartResponse(status, "", launchURL, templateURL, accountID, roleName, stackName, policyHash), nil
}

func (s *Service) startAWSStackSetConnector(
	ctx context.Context,
	project db.TenancyProject,
	scope db.Scope,
	request AWSConnectorStartRequest,
	setup awsConnectorSetupContract,
) (AWSConnectorStartResponse, error) {
	templateURL := strings.TrimSpace(s.AWSCloudFormationTemplateURL)
	accountID := strings.TrimSpace(s.AWSAccountID)
	// AWSAccountID gates the launch URL's param_IdentrailAccountId, which
	// the resume path can regenerate — so require it before entering
	// either the new-setup or the resume path so a missing configuration
	// can never persist a launch URL with an empty Identrail account id.
	if accountID == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	templateChecksum := normalizeAWSConnectorTemplateChecksum(s.AWSCloudFormationTemplateSHA)
	connectorID := strings.TrimSpace(request.ConnectorID)
	// Look up an existing connector before enforcing the configured
	// checksum so a stored StackSet setup — including a connected retry
	// or a draft with a persisted template_checksum — can resume after
	// IDENTRAIL_AWS_CFN_TEMPLATE_SHA256 is unset. The resume path
	// re-enforces the checksum only for rebuilt launch plans.
	if connectorID != "" {
		stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
		if err == nil {
			if err := ensureAWSConnectorLifecycleStartAllowed(stored); err != nil {
				return AWSConnectorStartResponse{}, err
			}
			return s.resumeAWSStackSetConnectorStart(ctx, stored, setup, request, templateURL, accountID, templateChecksum)
		}
		if !errors.Is(err, db.ErrNotFound) {
			return AWSConnectorStartResponse{}, err
		}
	}
	if templateURL == "" || templateChecksum == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	if connectorID == "" {
		connectorID = "aws-" + uuid.NewString()
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		displayName = awsConnectorDefaultDisplayName(awsConnectorStackSetDisplayName(setup), connectorID)
	}
	if err := validateAWSConnectorStartIdentity(connectorID, displayName); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	externalID, err := generateAWSExternalID()
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	now := s.Now().UTC()
	region := firstAWSRegion(setup.TargetRegions)
	roleName := firstNonEmptyAWSValue(strings.TrimSpace(request.RoleName), "IdentrailReadOnly")
	if err := validateAWSConnectorStackSetRoleName(roleName); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	stackSetName := firstNonEmptyAWSValue(strings.TrimSpace(request.StackSetName), strings.TrimSpace(request.StackName), "identrail-readonly-connector-stackset")
	if err := validateAWSConnectorStackSetName(stackSetName); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	policyHash, err := awsconnector.ReadOnlyPolicyHash()
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	onboarding, err := s.buildAWSConnectorStackSetOnboarding(scope, project, connectorID, accountID, region, roleName, stackSetName, templateURL, templateChecksum, externalID, setup, now)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	capabilities, _, err := s.resolveAWSConnectorCapabilities(domain.DefaultConnectorCapabilities())
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	onboardingStatus := awsConnectorStackSetOnboardingStatus(onboarding)
	targetSummary := awsConnectorTargetSummary(setup)
	nextActions := awsConnectorStackSetNextActions(setup, onboarding.Validation)
	metadata := map[string]any{
		"external_id_configured": true,
		"region":                 region,
		"role_name":              roleName,
		"stack_set_name":         onboarding.StackSetName,
		"template_url":           templateURL,
		"template_checksum":      templateChecksum,
		"launch_url":             onboarding.LaunchURL,
		"policy_hash":            policyHash,
		"target_summary":         targetSummary,
		"prerequisites":          onboarding.Validation.Prerequisites,
		"permission_checks":      []AWSConnectionPermissionCheck{},
		"diagnostics":            []AWSConnectionDiagnostic{},
		"capabilities":           capabilities,
		"last_started_at":        now.Format(time.RFC3339Nano),
	}
	applyAWSConnectorSetupMetadata(metadata, setup, onboardingStatus)
	metadata["next_actions"] = awsConnectorNextActionStrings(nextActions)
	connector := db.TenancyConnector{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		Type:                domain.ConnectorTypeAWS,
		DisplayName:         displayName,
		Status:              domain.ConnectorStatusPending,
		SecretProvider:      "secret-envelope",
		SecretRefID:         awsExternalIDSecretRef(connectorID),
		SecretRefVersion:    s.connectorSecretManager().ActiveKeyVersion(),
		SecretLastRotatedAt: &now,
		UpdatedAt:           now,
	}
	state := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  connectorID,
		HealthStatus: "unknown",
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	envelope, err := s.newAWSExternalIDSecretEnvelope(scope.TenantID, project.WorkspaceID, project.ProjectID, connectorID, externalID, now)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	stored, created, err := s.Store.CreateTenancyConnectorWithSecretEnvelopeIfAbsent(ctx, connector, state, envelope)
	if err != nil {
		return AWSConnectorStartResponse{}, fmt.Errorf("create aws stackset connector: %w", err)
	}
	if !created {
		return s.resumeAWSStackSetConnectorStart(ctx, stored, setup, request, templateURL, accountID, templateChecksum)
	}
	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalID = externalID
	response := awsConnectorStartResponse(status, externalID, onboarding.LaunchURL, templateURL, accountID, roleName, "", policyHash)
	response.StackSetOnboarding = &onboarding
	return response, nil
}

func (s *Service) startAWSManualConnector(
	ctx context.Context,
	project db.TenancyProject,
	scope db.Scope,
	request AWSConnectorStartRequest,
	setup awsConnectorSetupContract,
) (AWSConnectorStartResponse, error) {
	connectorID := strings.TrimSpace(request.ConnectorID)
	if connectorID == "" {
		connectorID = "aws-" + uuid.NewString()
	} else {
		stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
		if err == nil {
			if err := ensureAWSConnectorLifecycleStartAllowed(stored); err != nil {
				return AWSConnectorStartResponse{}, err
			}
			return s.resumeAWSManualConnectorStart(ctx, stored)
		}
		if !errors.Is(err, db.ErrNotFound) {
			return AWSConnectorStartResponse{}, err
		}
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		displayName = awsConnectorDefaultDisplayName("AWS account", connectorID)
	}
	if err := validateAWSConnectorStartIdentity(connectorID, displayName); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	externalID, err := generateAWSExternalID()
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	accountID := strings.TrimSpace(s.AWSAccountID)
	if accountID == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	now := s.Now().UTC()
	region := firstAWSRegion(setup.TargetRegions)
	if region == "" {
		region = "us-east-1"
	}
	capabilities, _, err := s.resolveAWSConnectorCapabilities(domain.DefaultConnectorCapabilities())
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	onboardingStatus := AWSConnectorOnboardingDraft
	metadata := map[string]any{
		"external_id_configured": true,
		"region":                 region,
		"permission_checks":      []AWSConnectionPermissionCheck{},
		"diagnostics":            []AWSConnectionDiagnostic{},
		"capabilities":           capabilities,
		"last_started_at":        now.Format(time.RFC3339Nano),
	}
	applyAWSConnectorSetupMetadata(metadata, setup, onboardingStatus)
	connector := db.TenancyConnector{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		Type:                domain.ConnectorTypeAWS,
		DisplayName:         displayName,
		Status:              domain.ConnectorStatusPending,
		SecretProvider:      "secret-envelope",
		SecretRefID:         awsExternalIDSecretRef(connectorID),
		SecretRefVersion:    s.connectorSecretManager().ActiveKeyVersion(),
		SecretLastRotatedAt: &now,
		UpdatedAt:           now,
	}
	state := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  connectorID,
		HealthStatus: "unknown",
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	envelope, err := s.newAWSExternalIDSecretEnvelope(scope.TenantID, project.WorkspaceID, project.ProjectID, connectorID, externalID, now)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	stored, created, err := s.Store.CreateTenancyConnectorWithSecretEnvelopeIfAbsent(ctx, connector, state, envelope)
	if err != nil {
		return AWSConnectorStartResponse{}, fmt.Errorf("create manual aws connector: %w", err)
	}
	if !created {
		return s.resumeAWSManualConnectorStart(ctx, stored)
	}
	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalID = externalID
	status.Region = firstNonEmptyAWSValue(status.Region, region)
	return awsConnectorStartResponse(status, externalID, "", "", accountID, "", "", ""), nil
}

func (s *Service) resumeAWSManualConnectorStart(ctx context.Context, stored db.TenancyConnectorWithState) (AWSConnectorStartResponse, error) {
	if stored.Connector.Type != domain.ConnectorTypeAWS {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	if err := ensureAWSConnectorLifecycleStartAllowed(stored); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	defaultScope, defaultDeployment := awsMetadataSetupFallback(stored.State.Metadata)
	setup := awsMetadataSetupContract(stored.State.Metadata, defaultScope, defaultDeployment)
	if setup.ScopeType != AWSConnectorScopeManualRole || setup.DeploymentMethod != AWSConnectorDeploymentManual {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	externalID, externalIDConfigured, err := s.awsExternalIDFromStoredStrict(ctx, stored)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	if !externalIDConfigured || externalID == "" {
		var recoverErr error
		stored, externalID, recoverErr = s.recoverAWSManualConnectorExternalID(ctx, stored)
		if recoverErr != nil {
			return AWSConnectorStartResponse{}, recoverErr
		}
	}
	accountID := strings.TrimSpace(s.AWSAccountID)
	if accountID == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalID = externalID
	status.ExternalIDConfigured = true
	return awsConnectorStartResponse(status, externalID, "", "", accountID, "", "", ""), nil
}

func (s *Service) recoverAWSManualConnectorExternalID(ctx context.Context, stored db.TenancyConnectorWithState) (db.TenancyConnectorWithState, string, error) {
	externalID, err := generateAWSExternalID()
	if err != nil {
		return db.TenancyConnectorWithState{}, "", err
	}
	rotatedAt := s.Now().UTC()
	secret, err := s.newAWSExternalIDSecretEnvelope(
		stored.Connector.TenantID,
		stored.Connector.WorkspaceID,
		stored.Connector.ProjectID,
		stored.Connector.ConnectorID,
		externalID,
		rotatedAt,
	)
	if err != nil {
		return db.TenancyConnectorWithState{}, "", err
	}
	secret, created, err := s.createAWSExternalIDSecretIfCurrent(ctx, stored, secret)
	if err != nil {
		return db.TenancyConnectorWithState{}, "", fmt.Errorf("recover manual aws connector external id envelope: %w", err)
	}
	if !created {
		recoveredExternalID, err := s.decryptAWSExternalIDEnvelope(stored.Connector, secret)
		if err != nil {
			return db.TenancyConnectorWithState{}, "", err
		}
		externalID = recoveredExternalID
	}

	metadata := copyAWSMetadata(stored.State.Metadata)
	delete(metadata, "external_id")
	metadata["external_id_configured"] = strings.TrimSpace(externalID) != ""
	metadata["last_started_at"] = rotatedAt.Format(time.RFC3339Nano)
	stored.State.Metadata = metadata
	stored.State.ObservedAt = rotatedAt
	stored.State.UpdatedAt = rotatedAt
	stored.Connector.SecretProvider = "secret-envelope"
	stored.Connector.SecretRefID = awsExternalIDSecretRef(stored.Connector.ConnectorID)
	stored.Connector.SecretRefVersion = s.connectorSecretManager().ActiveKeyVersion()
	stored.Connector.SecretLastRotatedAt = &rotatedAt
	stored.Connector.UpdatedAt = rotatedAt
	if err := s.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
		return db.TenancyConnectorWithState{}, "", fmt.Errorf("persist recovered manual aws connector external id: %w", err)
	}
	return stored, externalID, nil
}

func (s *Service) resumeAWSStackSetConnectorStart(
	ctx context.Context,
	stored db.TenancyConnectorWithState,
	requestedSetup awsConnectorSetupContract,
	request AWSConnectorStartRequest,
	templateURL string,
	accountID string,
	configuredTemplateChecksum string,
) (AWSConnectorStartResponse, error) {
	if stored.Connector.Type != domain.ConnectorTypeAWS {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	if err := ensureAWSConnectorLifecycleStartAllowed(stored); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	defaultScope, defaultDeployment := awsMetadataSetupFallback(stored.State.Metadata)
	setup := awsMetadataSetupContract(stored.State.Metadata, defaultScope, defaultDeployment)
	if !awsConnectorDeploymentIsStackSet(setup.DeploymentMethod) {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	if !awsConnectorSetupContractsMatch(setup, requestedSetup) {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	externalID, externalIDConfigured, err := s.awsExternalIDFromStoredStrict(ctx, stored)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	generatedExternalID := false
	var rotatedAt time.Time
	if !externalIDConfigured || externalID == "" {
		externalID, err = generateAWSExternalID()
		if err != nil {
			return AWSConnectorStartResponse{}, err
		}
		generatedExternalID = true
		rotatedAt = s.Now().UTC()
		secret, err := s.newAWSExternalIDSecretEnvelope(stored.Connector.TenantID, stored.Connector.WorkspaceID, stored.Connector.ProjectID, stored.Connector.ConnectorID, externalID, rotatedAt)
		if err != nil {
			return AWSConnectorStartResponse{}, err
		}
		secret, created, err := s.createAWSExternalIDSecretIfCurrent(ctx, stored, secret)
		if err != nil {
			return AWSConnectorStartResponse{}, fmt.Errorf("recover aws stackset connector external id envelope: %w", err)
		}
		if !created {
			recoveredExternalID, err := s.decryptAWSExternalIDEnvelope(stored.Connector, secret)
			if err != nil {
				return AWSConnectorStartResponse{}, err
			}
			externalID = recoveredExternalID
			generatedExternalID = false
		}
	}

	region := firstNonEmptyAWSValue(firstAWSRegion(setup.TargetRegions), awsMetadataString(stored.State.Metadata, "region"), "us-east-1")
	storedRoleName := awsMetadataString(stored.State.Metadata, "role_name")
	requestedRoleName := strings.TrimSpace(request.RoleName)
	if requestedRoleName != "" {
		if err := validateAWSConnectorStackSetRoleName(requestedRoleName); err != nil {
			return AWSConnectorStartResponse{}, err
		}
	}
	if requestedRoleName != "" && storedRoleName != "" && !strings.EqualFold(requestedRoleName, storedRoleName) {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	roleName := firstNonEmptyAWSValue(storedRoleName, requestedRoleName, "IdentrailReadOnly")
	if err := validateAWSConnectorStackSetRoleName(roleName); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	storedStackSetName := awsMetadataString(stored.State.Metadata, "stack_set_name")
	requestedStackSetName := firstNonEmptyAWSValue(strings.TrimSpace(request.StackSetName), strings.TrimSpace(request.StackName))
	if requestedStackSetName != "" {
		if err := validateAWSConnectorStackSetName(requestedStackSetName); err != nil {
			return AWSConnectorStartResponse{}, err
		}
	}
	if requestedStackSetName != "" && storedStackSetName != "" && !strings.EqualFold(requestedStackSetName, storedStackSetName) {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	stackSetName := firstNonEmptyAWSValue(storedStackSetName, requestedStackSetName, "identrail-readonly-connector-stackset")
	if err := validateAWSConnectorStackSetName(stackSetName); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	policyHash := awsMetadataString(stored.State.Metadata, "policy_hash")
	if policyHash == "" {
		hash, err := awsconnector.ReadOnlyPolicyHash()
		if err != nil {
			return AWSConnectorStartResponse{}, err
		}
		policyHash = hash
	}
	storedTemplateURL := firstNonEmptyAWSValue(awsMetadataString(stored.State.Metadata, "template_url"), templateURL)
	launchURL := awsMetadataString(stored.State.Metadata, "launch_url")
	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalID = externalID
	status.ExternalIDConfigured = true
	if !generatedExternalID && status.Connected && status.OnboardingStatus == AWSConnectorOnboardingConnected {
		return awsConnectorStartResponse(status, externalID, launchURL, storedTemplateURL, accountID, roleName, "", policyHash), nil
	}

	templateChecksum := firstNonEmptyAWSValue(normalizeAWSConnectorTemplateChecksum(awsMetadataString(stored.State.Metadata, "template_checksum")), configuredTemplateChecksum)
	if templateChecksum == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	onboarding, err := s.buildAWSConnectorStackSetOnboarding(
		db.Scope{TenantID: stored.Connector.TenantID, WorkspaceID: stored.Connector.WorkspaceID},
		db.TenancyProject{TenantID: stored.Connector.TenantID, WorkspaceID: stored.Connector.WorkspaceID, ProjectID: stored.Connector.ProjectID},
		stored.Connector.ConnectorID,
		accountID,
		region,
		roleName,
		stackSetName,
		storedTemplateURL,
		templateChecksum,
		externalID,
		setup,
		s.Now().UTC(),
	)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	if generatedExternalID || launchURL == "" || !awsCloudFormationLaunchURLMatchesExternalID(launchURL, externalID) {
		launchURL = onboarding.LaunchURL
		if rotatedAt.IsZero() {
			rotatedAt = s.Now().UTC()
		}
		stored = persistRecoveredAWSStackSetConnectorLaunchState(stored, setup, externalID, region, roleName, stackSetName, storedTemplateURL, launchURL, policyHash, templateChecksum, onboarding.Validation.Prerequisites, rotatedAt, generatedExternalID, s.connectorSecretManager().ActiveKeyVersion())
		if err := s.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
			return AWSConnectorStartResponse{}, fmt.Errorf("persist recovered aws stackset connector launch state: %w", err)
		}
		onboarding.LaunchURL = launchURL
	}

	status = s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalID = externalID
	status.ExternalIDConfigured = true
	response := awsConnectorStartResponse(status, externalID, launchURL, storedTemplateURL, accountID, roleName, "", policyHash)
	response.StackSetOnboarding = &onboarding
	return response, nil
}

func (s *Service) resumeAWSConnectorStart(
	ctx context.Context,
	stored db.TenancyConnectorWithState,
	requestedSetup awsConnectorSetupContract,
	request AWSConnectorStartRequest,
	templateURL string,
	accountID string,
) (AWSConnectorStartResponse, error) {
	if stored.Connector.Type != domain.ConnectorTypeAWS {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	if err := ensureAWSConnectorLifecycleStartAllowed(stored); err != nil {
		return AWSConnectorStartResponse{}, err
	}
	defaultScope, defaultDeployment := awsMetadataSetupFallback(stored.State.Metadata)
	setup := awsMetadataSetupContract(stored.State.Metadata, defaultScope, defaultDeployment)
	if setup.ScopeType != AWSConnectorScopeSingleAccount || setup.DeploymentMethod != AWSConnectorDeploymentCloudFormation {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}

	externalID, externalIDConfigured, err := s.awsExternalIDFromStoredStrict(ctx, stored)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	generatedExternalID := false
	var rotatedAt time.Time
	if !externalIDConfigured || externalID == "" {
		var err error
		externalID, err = generateAWSExternalID()
		if err != nil {
			return AWSConnectorStartResponse{}, err
		}
		generatedExternalID = true
		rotatedAt = s.Now().UTC()
		secret, err := s.newAWSExternalIDSecretEnvelope(stored.Connector.TenantID, stored.Connector.WorkspaceID, stored.Connector.ProjectID, stored.Connector.ConnectorID, externalID, rotatedAt)
		if err != nil {
			return AWSConnectorStartResponse{}, err
		}
		secret, created, err := s.createAWSExternalIDSecretIfCurrent(ctx, stored, secret)
		if err != nil {
			return AWSConnectorStartResponse{}, fmt.Errorf("recover aws connector external id envelope: %w", err)
		}
		if !created {
			recoveredExternalID, err := s.decryptAWSExternalIDEnvelope(stored.Connector, secret)
			if err != nil {
				return AWSConnectorStartResponse{}, err
			}
			externalID = recoveredExternalID
			generatedExternalID = false
		}
	}

	region := firstAWSRegion(setup.TargetRegions)
	if region == "" {
		region = firstAWSRegion(requestedSetup.TargetRegions)
	}
	region = firstNonEmptyAWSValue(awsMetadataString(stored.State.Metadata, "region"), region, "us-east-1")
	roleName := firstNonEmptyAWSValue(awsMetadataString(stored.State.Metadata, "role_name"), strings.TrimSpace(request.RoleName), "IdentrailReadOnly")
	stackName := firstNonEmptyAWSValue(awsMetadataString(stored.State.Metadata, "stack_name"), strings.TrimSpace(request.StackName), "identrail-readonly-connector")
	policyHash := awsMetadataString(stored.State.Metadata, "policy_hash")
	if policyHash == "" {
		hash, err := awsconnector.ReadOnlyPolicyHash()
		if err != nil {
			return AWSConnectorStartResponse{}, err
		}
		policyHash = hash
	}
	storedTemplateChecksum := normalizeAWSConnectorTemplateChecksum(awsMetadataString(stored.State.Metadata, "template_checksum"))
	templateChecksum := firstNonEmptyAWSValue(storedTemplateChecksum, normalizeAWSConnectorTemplateChecksum(s.AWSCloudFormationTemplateSHA))
	registrationProviderARN := s.awsRegistrationTopicARN(region)
	if templateChecksum == "" || registrationProviderARN == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	// A legacy connector persisted before the automatic-registration template
	// (v2.x) has an old `template_url` in metadata but no `template_checksum`.
	// Pairing that legacy URL with the newly configured v2 checksum would
	// launch a template without the registration parameters, so the connector
	// could never complete automatic registration. Prefer the configured URL
	// whenever the stored metadata predates registration.
	storedTemplateURL := templateURL
	if storedTemplateChecksum != "" {
		storedTemplateURL = firstNonEmptyAWSValue(awsMetadataString(stored.State.Metadata, "template_url"), templateURL)
	}
	if generatedExternalID {
		if rotatedAt.IsZero() {
			rotatedAt = s.Now().UTC()
		}
		stored = persistRecoveredAWSConnectorLaunchState(stored, externalID, region, roleName, stackName, templateURL, "", policyHash, s.connectorSecretManager().ActiveKeyVersion(), rotatedAt, true)
		stored.State.Metadata["template_checksum"] = templateChecksum
		stored.State.Metadata["template_version"] = awsConnectorTemplateVersion
		stored.State.Metadata["registration_provider"] = registrationProviderARN
		delete(stored.State.Metadata, "launch_url")
		if err := s.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
			return AWSConnectorStartResponse{}, fmt.Errorf("persist recovered aws connector launch state: %w", err)
		}
	}
	if request.RepairOnly {
		if !awsConnectorNeedsTrustPolicyRepair(stored) {
			return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
		}
		status := s.awsConnectionStatusFromStored(ctx, stored)
		status.ExternalIDConfigured = true
		status.Region = firstNonEmptyAWSValue(status.Region, region)
		status.TemplateURL = firstNonEmptyAWSValue(status.TemplateURL, templateURL)
		status.PolicyHash = firstNonEmptyAWSValue(status.PolicyHash, policyHash)
		status.TemplateChecksum = templateChecksum
		return awsConnectorStartResponse(status, externalID, "", storedTemplateURL, accountID, roleName, stackName, policyHash), nil
	}
	attempt, registrationToken, err := s.activeOrNewAWSConnectorOnboardingAttempt(ctx, stored, registrationProviderARN, templateChecksum, region)
	if err != nil {
		return AWSConnectorStartResponse{}, err
	}
	// Explicitly restarting an expired/failed/needs_fix connector issues a fresh
	// registration grant, but the stored setup metadata still carries the
	// prior terminal onboarding_status — so the UI would continue to show
	// "Start again" instead of waiting for AWS. Reset the setup metadata to
	// waiting_for_aws once we have a fresh attempt in that state.
	if attempt.Status == db.AWSConnectorOnboardingAttemptWaiting && attempt.BootstrapRequestID == "" {
		if err := s.resetAWSConnectorSetupToWaiting(ctx, &stored, setup, region, roleName, stackName, storedTemplateURL, templateChecksum, registrationProviderARN, policyHash); err != nil {
			return AWSConnectorStartResponse{}, err
		}
	}
	launchURL := awsconnector.BuildCloudFormationLaunchURL(awsconnector.CloudFormationLaunchInput{
		TemplateURL:             storedTemplateURL,
		Region:                  region,
		StackName:               stackName,
		IdentrailAccountID:      accountID,
		RoleName:                roleName,
		RegistrationProviderARN: registrationProviderARN,
		RegistrationAttemptID:   attempt.AttemptID,
		RegistrationToken:       registrationToken,
	})

	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalIDConfigured = true
	status.Region = firstNonEmptyAWSValue(status.Region, region)
	status.TemplateURL = firstNonEmptyAWSValue(status.TemplateURL, templateURL)
	status.PolicyHash = firstNonEmptyAWSValue(status.PolicyHash, policyHash)
	status.TemplateChecksum = templateChecksum
	// A healthy or waiting CloudFormation connector keeps the External ID
	// server-side. A degraded connector needs it exposed so the guided
	// `assume_role_failed` repair can render a `copy_trust_policy` action —
	// otherwise the operator sees an empty trust policy and cannot fix the
	// trust misconfiguration.
	responseExternalID := ""
	if awsConnectorNeedsTrustPolicyRepair(stored) {
		responseExternalID = externalID
	}
	return awsConnectorStartResponse(status, responseExternalID, launchURL, storedTemplateURL, accountID, roleName, stackName, policyHash), nil
}

func awsConnectorNeedsTrustPolicyRepair(stored db.TenancyConnectorWithState) bool {
	if stored.Connector.Status == domain.ConnectorStatusDegraded {
		return true
	}
	if stored.State.HealthStatus == "error" {
		return true
	}
	switch awsMetadataOnboardingStatus(stored.State.Metadata, "onboarding_status") {
	case AWSConnectorOnboardingNeedsFix, AWSConnectorOnboardingFailed, AWSConnectorOnboardingPartial:
		return true
	}
	return false
}

// resetAWSConnectorSetupToWaiting flips a terminal or degraded connector back
// to the waiting_for_aws onboarding state so a freshly issued registration
// attempt is reflected consistently in the API and UI.
func (s *Service) resetAWSConnectorSetupToWaiting(
	ctx context.Context,
	stored *db.TenancyConnectorWithState,
	setup awsConnectorSetupContract,
	region string,
	roleName string,
	stackName string,
	templateURL string,
	templateChecksum string,
	registrationProviderARN string,
	policyHash string,
) error {
	current := awsMetadataOnboardingStatus(stored.State.Metadata, "onboarding_status")
	// If we're already in a pre-registration state, no reset is required.
	switch current {
	case AWSConnectorOnboardingWaitingForAWS, AWSConnectorOnboardingRegistering, AWSConnectorOnboardingValidating, AWSConnectorOnboardingConnected:
		return nil
	}
	metadata := copyAWSMetadata(stored.State.Metadata)
	metadata["region"] = region
	metadata["role_name"] = roleName
	metadata["stack_name"] = stackName
	metadata["template_url"] = templateURL
	metadata["template_checksum"] = templateChecksum
	metadata["template_version"] = awsConnectorTemplateVersion
	metadata["registration_provider"] = registrationProviderARN
	if policyHash != "" {
		metadata["policy_hash"] = policyHash
	}
	delete(metadata, "launch_url")
	applyAWSConnectorSetupMetadata(metadata, setup, AWSConnectorOnboardingWaitingForAWS)
	now := s.Now().UTC()
	stored.State.Metadata = metadata
	stored.State.HealthStatus = "unknown"
	stored.State.LastErrorCode = ""
	stored.State.LastErrorMessage = ""
	stored.State.ObservedAt = now
	stored.State.UpdatedAt = now
	stored.Connector.Status = domain.ConnectorStatusPending
	stored.Connector.UpdatedAt = now
	if err := s.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
		return fmt.Errorf("reset aws connector setup to waiting: %w", err)
	}
	return nil
}

func persistRecoveredAWSConnectorLaunchState(
	stored db.TenancyConnectorWithState,
	externalID string,
	region string,
	roleName string,
	stackName string,
	templateURL string,
	launchURL string,
	policyHash string,
	secretRefVersion string,
	rotatedAt time.Time,
	updateSecretRef bool,
) db.TenancyConnectorWithState {
	metadata := copyAWSMetadata(stored.State.Metadata)
	metadata["external_id_configured"] = strings.TrimSpace(externalID) != ""
	metadata["region"] = region
	metadata["role_name"] = roleName
	metadata["stack_name"] = stackName
	metadata["template_url"] = templateURL
	metadata["launch_url"] = launchURL
	metadata["policy_hash"] = policyHash
	metadata["last_started_at"] = rotatedAt.Format(time.RFC3339Nano)
	stored.State.Metadata = metadata
	stored.State.ObservedAt = rotatedAt
	stored.State.UpdatedAt = rotatedAt
	if updateSecretRef {
		stored.Connector.SecretProvider = "secret-envelope"
		stored.Connector.SecretRefID = awsExternalIDSecretRef(stored.Connector.ConnectorID)
		stored.Connector.SecretRefVersion = secretRefVersion
		stored.Connector.SecretLastRotatedAt = &rotatedAt
	}
	stored.Connector.UpdatedAt = rotatedAt
	return stored
}

func persistRecoveredAWSStackSetConnectorLaunchState(
	stored db.TenancyConnectorWithState,
	setup awsConnectorSetupContract,
	externalID string,
	region string,
	roleName string,
	stackSetName string,
	templateURL string,
	launchURL string,
	policyHash string,
	templateChecksum string,
	prerequisites []AWSStackSetOnboardingPrerequisite,
	rotatedAt time.Time,
	updateSecretRef bool,
	secretRefVersion string,
) db.TenancyConnectorWithState {
	metadata := copyAWSMetadata(stored.State.Metadata)
	metadata["external_id_configured"] = strings.TrimSpace(externalID) != ""
	metadata["region"] = region
	metadata["role_name"] = roleName
	metadata["stack_set_name"] = stackSetName
	metadata["template_url"] = templateURL
	metadata["launch_url"] = launchURL
	metadata["policy_hash"] = policyHash
	metadata["template_checksum"] = templateChecksum
	metadata["target_summary"] = awsConnectorTargetSummary(setup)
	metadata["prerequisites"] = prerequisites
	metadata["last_started_at"] = rotatedAt.Format(time.RFC3339Nano)
	applyAWSConnectorSetupMetadata(metadata, setup, awsConnectorStackSetOnboardingStatusFromPrerequisites(prerequisites))
	metadata["next_actions"] = awsConnectorNextActionStrings(awsConnectorStackSetNextActionsFromPrerequisites(setup, prerequisites))
	stored.State.Metadata = metadata
	stored.State.ObservedAt = rotatedAt
	stored.State.UpdatedAt = rotatedAt
	if updateSecretRef {
		stored.Connector.SecretProvider = "secret-envelope"
		stored.Connector.SecretRefID = awsExternalIDSecretRef(stored.Connector.ConnectorID)
		stored.Connector.SecretRefVersion = secretRefVersion
		stored.Connector.SecretLastRotatedAt = &rotatedAt
	}
	stored.Connector.UpdatedAt = rotatedAt
	return stored
}

func copyAWSMetadata(metadata map[string]any) map[string]any {
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		out[key] = value
	}
	return out
}

func awsConnectorLaunchMetadata(metadata map[string]any) map[string]any {
	keys := []string{
		"role_name",
		"stack_name",
		"stack_set_name",
		"template_url",
		"template_checksum",
		"launch_url",
		"policy_hash",
		"target_summary",
		"prerequisites",
	}
	out := map[string]any{}
	for _, key := range keys {
		if value, ok := metadata[key]; ok {
			out[key] = value
		}
	}
	return out
}

func awsConnectorLaunchMetadataForExternalID(metadata map[string]any, externalID string) map[string]any {
	launchURL := awsMetadataString(metadata, "launch_url")
	if !awsCloudFormationLaunchURLMatchesExternalID(launchURL, externalID) {
		return nil
	}
	return awsConnectorLaunchMetadata(metadata)
}

func awsCloudFormationLaunchURLMatchesExternalID(launchURL string, externalID string) bool {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" {
		return false
	}
	return awsCloudFormationLaunchURLExternalID(launchURL) == externalID
}

func awsCloudFormationLaunchURLExternalID(launchURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(launchURL))
	if err != nil {
		return ""
	}
	rawQuery := parsed.RawQuery
	if fragment := parsed.EscapedFragment(); fragment != "" {
		if index := strings.Index(fragment, "?"); index >= 0 {
			rawQuery = fragment[index+1:]
		}
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(values.Get("param_ExternalId"))
}

func preserveAWSConnectorLaunchMetadata(metadata map[string]any, preserved map[string]any, onboardingStatus AWSConnectorOnboardingStatus) {
	if metadata == nil || len(preserved) == 0 {
		return
	}
	for key, value := range preserved {
		if key == "prerequisites" && onboardingStatus == AWSConnectorOnboardingConnected {
			continue
		}
		metadata[key] = value
	}
}

func publicAWSConnectionStatus(status AWSConnectionStatus) AWSConnectionStatus {
	status.LaunchURL = ""
	return status
}

func awsConnectorSetupPublicConnectionStatus(status AWSConnectionStatus) AWSConnectionStatus {
	status = publicAWSConnectionStatus(status)
	status.ExternalID = ""
	return status
}

func awsConnectorStartResponse(status AWSConnectionStatus, externalID string, launchURL string, templateURL string, identrailAccountID string, roleName string, stackName string, policyHash string) AWSConnectorStartResponse {
	return AWSConnectorStartResponse{
		Connection:             awsConnectorSetupPublicConnectionStatus(status),
		ConnectorID:            status.ConnectorID,
		ExternalID:             externalID,
		LaunchURL:              launchURL,
		TemplateURL:            templateURL,
		IdentrailAccountID:     identrailAccountID,
		RoleName:               roleName,
		StackName:              stackName,
		StackSetName:           status.StackSetName,
		PolicyHash:             policyHash,
		TemplateChecksum:       status.TemplateChecksum,
		ScopeType:              status.ScopeType,
		DeploymentMethod:       status.DeploymentMethod,
		OnboardingStatus:       status.OnboardingStatus,
		TargetRegions:          copyAWSStringSlice(status.TargetRegions),
		TargetAccountIDs:       copyAWSStringSlice(status.TargetAccountIDs),
		TargetOUIDs:            copyAWSStringSlice(status.TargetOUIDs),
		ExcludedAccountIDs:     copyAWSStringSlice(status.ExcludedAccountIDs),
		AutoOnboardNewAccounts: status.AutoOnboardNewAccounts,
		SetupSummary:           status.SetupSummary,
		NextActions:            copyAWSConnectorNextActions(status.NextActions),
		TargetSummary:          status.TargetSummary,
		Prerequisites:          status.Prerequisites,
		PermissionPreview:      awsconnector.PermissionPreview(),
		PermissionTiers:        awsconnector.CapabilityPermissionTiers(),
	}
}

func validateAWSConnectorStackSetName(stackSetName string) error {
	if !awsStackSetNamePattern.MatchString(strings.TrimSpace(stackSetName)) {
		return ErrInvalidAWSConnectionRequest
	}
	return nil
}

func validateAWSConnectorStackSetRoleName(roleName string) error {
	if !awsStackSetRoleNamePattern.MatchString(strings.TrimSpace(roleName)) {
		return ErrInvalidAWSConnectionRequest
	}
	return nil
}

func validateAWSConnectorStartIdentity(connectorID string, displayName string) error {
	connector := domain.Connector{
		ID:          connectorID,
		WorkspaceID: "workspace-placeholder",
		ProjectID:   "project-placeholder",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: displayName,
		Status:      domain.ConnectorStatusPending,
	}
	if err := connector.Validate(); err != nil {
		return ErrInvalidAWSConnectionRequest
	}
	return nil
}

func firstAWSRegion(regions []string) string {
	if len(regions) == 0 {
		return ""
	}
	return strings.TrimSpace(regions[0])
}

func (s *Service) ValidateAWSConnector(ctx context.Context, connectorID string, request AWSConnectorValidateRequest) (AWSConnectionStatus, error) {
	if strings.TrimSpace(request.ProjectID) == "" {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}
	project, _, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	if !awsConnectorLifecycleMutationAllowed(stored) {
		return AWSConnectionStatus{}, ErrAWSConnectorLifecycleBlocked
	}
	externalID := strings.TrimSpace(request.ExternalID)
	if externalID == "" {
		var err error
		externalID, _, err = s.awsExternalIDFromStoredStrict(ctx, stored)
		if err != nil {
			return AWSConnectionStatus{}, err
		}
	}
	requestedCapabilities := request.Capabilities
	if len(requestedCapabilities) == 0 {
		requestedCapabilities = awsMetadataCapabilities(stored.State.Metadata, "capabilities").Requested
	}
	setup := awsMetadataSetupContract(stored.State.Metadata, AWSConnectorScopeSingleAccount, AWSConnectorDeploymentCloudFormation)
	if awsConnectorValidateRequestHasSetupOverride(request) {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}
	status, err := s.UpsertAWSConnection(ctx, project.WorkspaceID, project.ProjectID, AWSConnectionUpsertRequest{
		ConnectorID:            connectorID,
		DisplayName:            stored.Connector.DisplayName,
		RoleARN:                request.RoleARN,
		ExternalID:             externalID,
		Region:                 firstNonEmptyAWSValue(strings.TrimSpace(request.Region), awsMetadataString(stored.State.Metadata, "region")),
		SessionName:            request.SessionName,
		Capabilities:           requestedCapabilities,
		ScopeType:              setup.ScopeType,
		DeploymentMethod:       setup.DeploymentMethod,
		TargetRegions:          setup.TargetRegions,
		TargetAccountIDs:       setup.TargetAccountIDs,
		TargetOUIDs:            setup.TargetOUIDs,
		ExcludedAccountIDs:     setup.ExcludedAccountIDs,
		AutoOnboardNewAccounts: setup.AutoOnboardNewAccounts,
		allowSetupContract:     true,
		preserveLaunchMetadata: awsConnectorLaunchMetadataForExternalID(stored.State.Metadata, externalID),
		lifecycleGeneration:    stored.Connector.LifecycleGeneration,
	})
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	return awsConnectorSetupPublicConnectionStatus(status), nil
}

func (s *Service) PollAWSConnector(ctx context.Context, connectorID string, request AWSConnectorPollRequest) (AWSConnectionStatus, error) {
	if strings.TrimSpace(request.ProjectID) == "" {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}
	project, _, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, strings.TrimSpace(connectorID))
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	if attemptStore, ok := s.Store.(db.AWSConnectorOnboardingAttemptStore); ok {
		attempt, attemptErr := attemptStore.GetActiveAWSConnectorOnboardingAttempt(ctx, project.WorkspaceID, project.ProjectID, strings.TrimSpace(connectorID))
		if attemptErr == nil && !s.Now().UTC().Before(attempt.ExpiresAt) {
			// Persist connector state first, then terminalize the attempt. If
			// the attempt update fails, the connector shows expired but the
			// attempt remains active, so a subsequent poll converges. If we
			// terminalized first, a transient state-write failure would leave
			// the attempt terminal (invisible to GetActive) with the
			// connector permanently `waiting_for_aws`.
			if err := s.persistAWSRegistrationProgress(ctx, stored, AWSConnectorOnboardingExpired, "", "", ""); err != nil {
				return AWSConnectionStatus{}, err
			}
			for updateAttempt := 0; updateAttempt < 3; updateAttempt++ {
				if !awsOnboardingAttemptPending(attempt.Status) || s.Now().UTC().Before(attempt.ExpiresAt) {
					if err := s.reconcileAWSConnectorFromOnboardingAttempt(ctx, attempt); err != nil {
						return AWSConnectionStatus{}, err
					}
					break
				}
				attempt.Status = db.AWSConnectorOnboardingAttemptExpired
				attempt.FailureCode = "registration_expired"
				attempt.FailureMessage = "The AWS connection window expired. Start a new connection."
				attempt.UpdatedAt = s.Now().UTC()
				updated, updateErr := attemptStore.UpdateAWSConnectorOnboardingAttempt(ctx, attempt, attempt.Version)
				if updateErr == nil {
					attempt = updated
					break
				}
				if !errors.Is(updateErr, db.ErrConflict) {
					return AWSConnectionStatus{}, updateErr
				}
				attempt, updateErr = attemptStore.GetAWSConnectorOnboardingAttempt(ctx, project.WorkspaceID, project.ProjectID, attempt.AttemptID)
				if updateErr != nil {
					return AWSConnectionStatus{}, updateErr
				}
				if !awsOnboardingAttemptPending(attempt.Status) {
					if err := s.reconcileAWSConnectorFromOnboardingAttempt(ctx, attempt); err != nil {
						return AWSConnectionStatus{}, err
					}
					break
				}
				if updateAttempt == 2 {
					return AWSConnectionStatus{}, db.ErrConflict
				}
			}
			stored, err = s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, strings.TrimSpace(connectorID))
			if err != nil {
				return AWSConnectionStatus{}, err
			}
		}
	}
	return awsConnectorSetupPublicConnectionStatus(s.awsConnectionStatusFromStored(ctx, stored)), nil
}

func (s *Service) requireAWSConnectorForLifecycleMutation(ctx context.Context, project db.TenancyProject, connectorID string) error {
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
	if err != nil {
		return err
	}
	if stored.Connector.Type != domain.ConnectorTypeAWS {
		return ErrInvalidAWSConnectionRequest
	}
	return nil
}

// DisconnectAWSConnector stops local eligibility immediately, invalidates the
// encrypted external-id envelope, and reports provider cleanup as pending.
// The generation fence prevents callbacks already in flight from reviving it.
func (s *Service) DisconnectAWSConnector(ctx context.Context, connectorID string, request AWSConnectorPollRequest) (AWSConnectionStatus, error) {
	if strings.TrimSpace(request.ProjectID) == "" || strings.TrimSpace(connectorID) == "" {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}
	project, _, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	connectorID = strings.TrimSpace(connectorID)
	if err := s.requireAWSConnectorForLifecycleMutation(ctx, project, connectorID); err != nil {
		return AWSConnectionStatus{}, err
	}
	lifecycleStore, ok := s.Store.(db.TenancyConnectorLifecycleStore)
	if !ok {
		return AWSConnectionStatus{}, ErrAWSConnectorConfigUnavailable
	}
	stored, err := lifecycleStore.DisconnectTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID, s.Now().UTC())
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	return awsConnectorSetupPublicConnectionStatus(s.awsConnectionStatusFromStored(ctx, stored)), nil
}

// SetAWSConnectorDisabled changes the explicit operator eligibility gate while
// retaining the connector and its diagnostic history for later review.
func (s *Service) SetAWSConnectorDisabled(ctx context.Context, connectorID string, request AWSConnectorPollRequest, disabled bool) (AWSConnectionStatus, error) {
	if strings.TrimSpace(request.ProjectID) == "" || strings.TrimSpace(connectorID) == "" {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}
	project, _, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	connectorID = strings.TrimSpace(connectorID)
	if err := s.requireAWSConnectorForLifecycleMutation(ctx, project, connectorID); err != nil {
		return AWSConnectionStatus{}, err
	}
	lifecycleStore, ok := s.Store.(db.TenancyConnectorLifecycleStore)
	if !ok {
		return AWSConnectionStatus{}, ErrAWSConnectorConfigUnavailable
	}
	stored, err := lifecycleStore.SetTenancyConnectorDisabled(ctx, project.WorkspaceID, project.ProjectID, connectorID, disabled, s.Now().UTC())
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	return awsConnectorSetupPublicConnectionStatus(s.awsConnectionStatusFromStored(ctx, stored)), nil
}

func (s *Service) AWSConnectorPolicy(ctx context.Context, connectorID string, request AWSConnectorPollRequest) (AWSConnectorPolicyResponse, error) {
	if strings.TrimSpace(connectorID) != "" {
		if _, err := s.PollAWSConnector(ctx, connectorID, request); err != nil {
			return AWSConnectorPolicyResponse{}, err
		}
	}
	policy, err := awsconnector.ReadOnlyPolicyDocument()
	if err != nil {
		return AWSConnectorPolicyResponse{}, err
	}
	hash, err := awsconnector.ReadOnlyPolicyHash()
	if err != nil {
		return AWSConnectorPolicyResponse{}, err
	}
	return AWSConnectorPolicyResponse{
		PolicyHash:        hash,
		PolicyDocument:    json.RawMessage(policy),
		PermissionPreview: awsconnector.PermissionPreview(),
		PermissionTiers:   awsconnector.CapabilityPermissionTiers(),
	}, nil
}

func (s *Service) UpsertAWSConnection(ctx context.Context, workspaceID string, projectID string, request AWSConnectionUpsertRequest) (AWSConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	normalized, err := normalizeAWSConnectionRequest(request)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	existing, existingErr := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	switch {
	case existingErr == nil:
		if !awsConnectorLifecycleMutationAllowed(existing) {
			return AWSConnectionStatus{}, ErrAWSConnectorLifecycleBlocked
		}
		normalized.lifecycleGeneration = existing.Connector.LifecycleGeneration
	case errors.Is(existingErr, db.ErrNotFound):
		// A first-time manual upsert starts at generation zero. The fenced
		// connector write and secret write below still agree on that generation.
	case existingErr != nil:
		return AWSConnectionStatus{}, existingErr
	}
	setupInput := awsConnectorSetupInput{
		ScopeType:               AWSConnectorScopeManualRole,
		DeploymentMethod:        AWSConnectorDeploymentManual,
		Region:                  normalized.Region,
		DefaultScopeType:        AWSConnectorScopeManualRole,
		DefaultDeploymentMethod: AWSConnectorDeploymentManual,
	}
	if normalized.allowSetupContract {
		setupInput = awsConnectorSetupInput{
			ScopeType:               normalized.ScopeType,
			DeploymentMethod:        normalized.DeploymentMethod,
			Region:                  normalized.Region,
			TargetRegions:           normalized.TargetRegions,
			TargetAccountIDs:        normalized.TargetAccountIDs,
			TargetOUIDs:             normalized.TargetOUIDs,
			ExcludedAccountIDs:      normalized.ExcludedAccountIDs,
			AutoOnboardNewAccounts:  normalized.AutoOnboardNewAccounts,
			DefaultScopeType:        AWSConnectorScopeManualRole,
			DefaultDeploymentMethod: AWSConnectorDeploymentManual,
		}
	} else if awsConnectionUpsertRequestHasUnsupportedSetupOverride(normalized) {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}
	setup, err := normalizeAWSConnectorSetupContract(setupInput)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	if s.AWSConnectorValidator == nil {
		return AWSConnectionStatus{}, ErrAWSConnectionValidatorUnavailable
	}

	validation, err := s.AWSConnectorValidator.ValidateAWSConnection(ctx, AWSConnectionValidationRequest{
		RoleARN:     normalized.RoleARN,
		ExternalID:  normalized.ExternalID,
		Region:      normalized.Region,
		SessionName: normalized.SessionName,
	})
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	if !awsConnectorSelectedAccountIncludesValidationAccount(setup, normalized.RoleARN, validation.AccountID) {
		return AWSConnectionStatus{}, ErrInvalidAWSConnectionRequest
	}

	now := s.Now().UTC()
	status := domain.ConnectorStatusActive
	health := "healthy"
	connected := true
	onboardingStatus := AWSConnectorOnboardingConnected
	if len(failedAWSChecks(validation.PermissionChecks)) > 0 || len(validation.Diagnostics) > 0 {
		status = domain.ConnectorStatusDegraded
		health = "error"
		connected = false
		onboardingStatus = AWSConnectorOnboardingNeedsFix
	}

	checks := scrubAWSPermissionChecks(copyAWSPermissionChecks(validation.PermissionChecks), normalized.ExternalID)
	if connected && len(checks) == 0 {
		checks = []AWSConnectionPermissionCheck{{
			Name:    "sts:AssumeRole",
			Passed:  true,
			Message: "Role assumption succeeded.",
		}}
	}

	// Capability resolution is independent of role-assumption health: a requested
	// tier that the deployment gate denies surfaces as a capability-scoped
	// diagnostic, but it does not degrade a healthy read-only connector.
	capabilities, capabilityDiagnostics, err := s.resolveAWSConnectorCapabilities(normalized.Capabilities)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	diagnostics := awsConnectorSetupDiagnostics(
		setup,
		normalized.RoleARN,
		normalized.ExternalID,
		append(copyAWSDiagnostics(validation.Diagnostics), capabilityDiagnostics...),
		checks,
	)

	metadata := map[string]any{
		"role_arn":               normalized.RoleARN,
		"external_id_configured": normalized.ExternalID != "",
		"account_id":             strings.TrimSpace(validation.AccountID),
		"principal_arn":          strings.TrimSpace(validation.PrincipalARN),
		"user_id":                strings.TrimSpace(validation.UserID),
		"region":                 firstNonEmptyAWSValue(strings.TrimSpace(validation.Region), normalized.Region),
		"permission_checks":      checks,
		"diagnostics":            diagnostics,
		"capabilities":           capabilities,
		"last_validated_at":      now.Format(time.RFC3339Nano),
	}
	applyAWSConnectorSetupMetadata(metadata, setup, onboardingStatus)
	preserveAWSConnectorLaunchMetadata(metadata, normalized.preserveLaunchMetadata, onboardingStatus)
	state := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  normalized.ConnectorID,
		HealthStatus: health,
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	if !connected {
		state.LastErrorCode = "aws_connector_validation_failed"
		state.LastErrorMessage = firstAWSRemediation(copyAWSDiagnostics(validation.Diagnostics), checks)
	}
	connector := db.TenancyConnector{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         normalized.ConnectorID,
		Type:                domain.ConnectorTypeAWS,
		DisplayName:         normalized.DisplayName,
		Status:              status,
		LifecycleGeneration: normalized.lifecycleGeneration,
		UpdatedAt:           now,
	}
	if normalized.ExternalID != "" {
		connector.SecretProvider = "secret-envelope"
		connector.SecretRefID = awsExternalIDSecretRef(normalized.ConnectorID)
		connector.SecretRefVersion = s.connectorSecretManager().ActiveKeyVersion()
		connector.SecretLastRotatedAt = &now
	}
	var secret *db.TenancyConnectorSecretEnvelope
	if normalized.ExternalID != "" {
		envelope, err := s.newAWSExternalIDSecretEnvelope(scope.TenantID, project.WorkspaceID, project.ProjectID, normalized.ConnectorID, normalized.ExternalID, now)
		if err != nil {
			return AWSConnectionStatus{}, err
		}
		secret = &envelope
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: scope.TenantID, WorkspaceID: project.WorkspaceID})
	if err := s.Store.UpsertTenancyConnectorAndSecretEnvelope(scopedCtx, connector, state, awsExternalIDSecretName, secret); err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("persist aws connector and external id atomically: %w", err)
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	if err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("load persisted aws connector: %w", err)
	}
	response := s.awsConnectionStatusFromStored(ctx, stored)

	return publicAWSConnectionStatus(response), nil
}

func (s *Service) GetAWSConnection(ctx context.Context, workspaceID string, projectID string) (AWSConnectionStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}

	items, err := s.Store.ListTenancyConnectors(ctx, project.WorkspaceID, project.ProjectID, domain.ConnectorTypeAWS, 1)
	if err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("list aws connectors: %w", err)
	}
	if len(items) == 0 {
		return AWSConnectionStatus{
			Provider:               "aws",
			Connected:              false,
			Status:                 domain.ConnectorStatusPending,
			HealthStatus:           "unknown",
			ScopeType:              AWSConnectorScopeSingleAccount,
			DeploymentMethod:       AWSConnectorDeploymentCloudFormation,
			OnboardingStatus:       AWSConnectorOnboardingDraft,
			TargetRegions:          []string{"us-east-1"},
			TargetAccountIDs:       []string{},
			TargetOUIDs:            []string{},
			ExcludedAccountIDs:     []string{},
			AutoOnboardNewAccounts: false,
			SetupSummary:           awsConnectorSetupSummary(awsConnectorSetupContract{ScopeType: AWSConnectorScopeSingleAccount, DeploymentMethod: AWSConnectorDeploymentCloudFormation, TargetRegions: []string{"us-east-1"}}, AWSConnectorOnboardingDraft),
			NextActions:            awsConnectorNextActions(awsConnectorSetupContract{ScopeType: AWSConnectorScopeSingleAccount, DeploymentMethod: AWSConnectorDeploymentCloudFormation, TargetRegions: []string{"us-east-1"}}, AWSConnectorOnboardingDraft),
			PermissionChecks:       []AWSConnectionPermissionCheck{},
			Diagnostics:            []AWSConnectionDiagnostic{},
			Capabilities:           defaultAWSConnectorCapabilities(),
		}, nil
	}
	return publicAWSConnectionStatus(s.awsConnectionStatusFromStored(ctx, items[0])), nil
}

// UpsertAWSAccountRegionCoverage stores account/region coverage for future AWS fan-out.
func (s *Service) UpsertAWSAccountRegionCoverage(ctx context.Context, workspaceID string, projectID string, coverage db.AWSAccountRegionCoverage) (db.AWSAccountRegionCoverage, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return db.AWSAccountRegionCoverage{}, err
	}
	coverage.TenantID = scope.TenantID
	coverage.WorkspaceID = project.WorkspaceID
	coverage.ProjectID = project.ProjectID
	if strings.TrimSpace(coverage.ConnectorID) == "" {
		return db.AWSAccountRegionCoverage{}, ErrInvalidAWSConnectionRequest
	}
	return s.Store.UpsertAWSAccountRegionCoverage(ctx, coverage)
}

// ListAWSAccountRegionCoverages lists project-scoped account/region targets for future AWS fan-out.
func (s *Service) ListAWSAccountRegionCoverages(ctx context.Context, workspaceID string, projectID string, filter db.AWSAccountRegionCoverageFilter) ([]db.AWSAccountRegionCoverage, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return nil, err
	}
	filter.WorkspaceID = project.WorkspaceID
	filter.ProjectID = project.ProjectID
	return s.Store.ListAWSAccountRegionCoverages(ctx, filter)
}

func awsConnectorValidateRequestHasSetupOverride(request AWSConnectorValidateRequest) bool {
	return strings.TrimSpace(string(request.ScopeType)) != "" ||
		strings.TrimSpace(string(request.DeploymentMethod)) != "" ||
		len(request.TargetRegions) > 0 ||
		len(request.TargetAccountIDs) > 0 ||
		len(request.TargetOUIDs) > 0 ||
		len(request.ExcludedAccountIDs) > 0 ||
		request.AutoOnboardNewAccounts
}

func awsConnectionUpsertRequestHasUnsupportedSetupOverride(request AWSConnectionUpsertRequest) bool {
	scopeType := AWSConnectorScopeType(strings.TrimSpace(string(request.ScopeType)))
	deploymentMethod := AWSConnectorDeploymentMethod(strings.TrimSpace(string(request.DeploymentMethod)))
	return (scopeType != "" && scopeType != AWSConnectorScopeManualRole) ||
		(deploymentMethod != "" && deploymentMethod != AWSConnectorDeploymentManual) ||
		len(request.TargetRegions) > 0 ||
		len(request.TargetAccountIDs) > 0 ||
		len(request.TargetOUIDs) > 0 ||
		len(request.ExcludedAccountIDs) > 0 ||
		request.AutoOnboardNewAccounts
}

func awsConnectorStackSetDisplayName(setup awsConnectorSetupContract) string {
	switch setup.ScopeType {
	case AWSConnectorScopeOrganization:
		return "AWS organization"
	case AWSConnectorScopeSelectedOUs:
		return "Selected AWS OUs"
	case AWSConnectorScopeSelectedAccounts:
		return "Selected AWS accounts"
	default:
		return "AWS StackSet"
	}
}

// awsConnectorDefaultDisplayName keeps server-generated names unique across
// retained disconnected connector records. A connector ID is immutable for a
// record, so including it prevents a fresh onboarding flow from colliding with
// the database's project/type/display-name uniqueness constraint.
func awsConnectorDefaultDisplayName(prefix string, connectorID string) string {
	prefix = strings.TrimSpace(prefix)
	connectorID = strings.TrimSpace(connectorID)
	if prefix == "" {
		prefix = "AWS connector"
	}
	if connectorID == "" {
		return prefix
	}
	return prefix + " (" + connectorID + ")"
}

func normalizeAWSConnectorTemplateChecksum(checksum string) string {
	trimmed := strings.ToLower(strings.TrimSpace(checksum))
	if trimmed == "" || !awsSHA256Pattern.MatchString(trimmed) {
		return ""
	}
	if !strings.HasPrefix(trimmed, "sha256:") {
		return "sha256:" + trimmed
	}
	return trimmed
}

func awsConnectorTemplateURLPinnedToChecksum(templateURL string, checksum string) bool {
	normalizedChecksum := normalizeAWSConnectorTemplateChecksum(checksum)
	if normalizedChecksum == "" {
		return false
	}
	digest := strings.TrimPrefix(normalizedChecksum, "sha256:")
	parsed, err := url.Parse(strings.TrimSpace(templateURL))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	segments := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	for i := 0; i < len(segments)-1; i++ {
		segment, err := url.PathUnescape(segments[i])
		if err != nil || !strings.EqualFold(segment, "sha256") {
			continue
		}
		next, err := url.PathUnescape(segments[i+1])
		if err == nil && strings.EqualFold(next, digest) {
			return true
		}
	}
	return false
}

func awsConnectorTargetSummary(setup awsConnectorSetupContract) *AWSConnectorTargetSummary {
	// Self-managed selected_accounts deploys directly to the supplied
	// account IDs, so both counts are trustworthy. Service-managed
	// selected_accounts hands the same list to AWS with
	// accountFilterType=INTERSECTION over the OU/root scope, which
	// silently drops accounts outside those OUs — and without an
	// Organizations topology lookup Identrail cannot verify OU
	// membership at setup time, so the counts must stay unknown until
	// AWS resolves the effective targets.
	knownAccounts := setup.ScopeType == AWSConnectorScopeSelectedAccounts &&
		setup.DeploymentMethod == AWSConnectorDeploymentStackSetSelfManaged
	accountCount := 0
	expectedInstances := 0
	expectedKnown := knownAccounts
	deploymentRegionCount := len(awsConnectorStackSetDeploymentRegions(setup))
	if expectedKnown {
		excluded := map[string]struct{}{}
		for _, accountID := range setup.ExcludedAccountIDs {
			excluded[accountID] = struct{}{}
		}
		for _, accountID := range setup.TargetAccountIDs {
			if _, ok := excluded[accountID]; !ok {
				accountCount++
				expectedInstances += deploymentRegionCount
			}
		}
	}
	return &AWSConnectorTargetSummary{
		AccountCount:                accountCount,
		AccountCountKnown:           knownAccounts,
		OUCount:                     len(setup.TargetOUIDs),
		RegionCount:                 len(setup.TargetRegions),
		ExcludedAccountCount:        len(setup.ExcludedAccountIDs),
		ExpectedStackInstances:      expectedInstances,
		ExpectedStackInstancesKnown: expectedKnown,
		AllAccounts:                 setup.ScopeType == AWSConnectorScopeOrganization,
	}
}

func awsConnectorStackSetDeploymentSetup(setup awsConnectorSetupContract) awsConnectorSetupContract {
	deployment := setup
	deployment.TargetRegions = awsConnectorStackSetDeploymentRegions(setup)
	return deployment
}

func awsConnectorStackSetDeploymentRegions(setup awsConnectorSetupContract) []string {
	region := firstAWSRegion(setup.TargetRegions)
	if region == "" {
		return nil
	}
	return []string{region}
}

func awsConnectorStackSetProjectionKnown(setup awsConnectorSetupContract) bool {
	return setup.DeploymentMethod == AWSConnectorDeploymentStackSetSelfManaged
}

func (s *Service) buildAWSConnectorStackSetOnboarding(
	scope db.Scope,
	project db.TenancyProject,
	connectorID string,
	identrailAccountID string,
	region string,
	roleName string,
	stackSetName string,
	templateURL string,
	templateChecksum string,
	externalID string,
	setup awsConnectorSetupContract,
	checkedAt time.Time,
) (AWSStackSetOnboardingResult, error) {
	if !awsConnectorTemplateURLPinnedToChecksum(templateURL, templateChecksum) {
		return AWSStackSetOnboardingResult{}, ErrAWSConnectorConfigUnavailable
	}
	mode := awsConnectorStackSetDeploymentMode(setup.DeploymentMethod)
	deploymentSetup := awsConnectorStackSetDeploymentSetup(setup)
	config := awscontract.StackSetOnboardingConfig{
		ConnectorID:         connectorID,
		ManagementAccountID: "",
		StackSetName:        stackSetName,
		TemplateURL:         templateURL,
		TemplateChecksum:    templateChecksum,
		DeploymentMode:      mode,
		Partition:           awsStackSetPartition(region),
		TrustedAccessReady:  false,
		DelegatedAdminReady: false,
		ExternalID:          externalID,
		Targets:             awsConnectorStackSetTargets(deploymentSetup),
	}
	plan, err := awscontract.PlanStackSetOnboarding(config, checkedAt)
	if err != nil {
		return AWSStackSetOnboardingResult{}, err
	}
	projectionKnown := awsConnectorStackSetProjectionKnown(setup)
	launchURL := awsconnector.BuildCloudFormationStackSetLaunchURL(awsconnector.CloudFormationStackSetLaunchInput{
		TemplateURL:           plan.TemplateURL,
		Region:                region,
		StackSetName:          plan.StackSetName,
		IdentrailAccountID:    identrailAccountID,
		ExternalID:            externalID,
		RoleName:              roleName,
		PermissionModel:       awsStackSetPermissionModel(plan.DeploymentMode),
		OrganizationalUnitIDs: collectStackSetOUIDs(plan.Targets.OrganizationalUnits),
		TargetAccountIDs:      collectStackSetAccountIDs(plan.Targets.Accounts),
		ExcludedAccountIDs:    awsConnectorStackSetLaunchExcludedAccounts(setup),
		TargetRegions:         collectStackSetRegionCodes(plan.Targets.Regions),
		AutoDeploymentEnabled: awsConnectorStackSetAutoDeploymentEnabled(mode, setup),
	})
	diagnostics := []AWSStackSetOnboardingDiagnostic{}
	instances := mapAWSStackSetInstances(plan.Instances)
	coverageExpectation := mapAWSStackSetCoverageExpectation(plan.CoverageExpectation)
	summary := mapAWSStackSetSummary(plan.Summary)
	coverageGaps := []AWSStackSetOnboardingCoverageGap{
		{
			Capability:  "confirmed_stackset_coverage",
			Status:      "planned",
			Reason:      "The connector start request records intended StackSet scope only; observed account and region coverage is confirmed after AWS deployment validation.",
			Remediation: "Launch the StackSet in AWS, then refresh connector status to reconcile observed coverage.",
		},
	}
	if !projectionKnown {
		instances = []AWSStackSetOnboardingInstance{}
		coverageExpectation = unknownAWSStackSetCoverageExpectation(len(plan.Targets.Regions), "Service-managed StackSet scopes are expanded by AWS during deployment; expected accounts, instances, and coverage targets are unknown until AWS resolves effective membership.")
		summary = unknownAWSStackSetSummary(len(plan.Targets.Regions))
		coverageGaps = append(coverageGaps, AWSStackSetOnboardingCoverageGap{
			Capability:  "service_managed_stackset_membership",
			Status:      "unknown",
			Reason:      "AWS expands organization, OU, and selected-account filters at StackSet launch time, so Identrail cannot prove effective account membership before AWS resolves the deployment target set.",
			Remediation: "Launch the StackSet and refresh connector status to reconcile effective account coverage from AWS.",
		})
		diagnostics = append(diagnostics, AWSStackSetOnboardingDiagnostic{
			Source:      "aws_stackset_targets",
			Scope:       string(setup.ScopeType),
			Code:        "service_managed_membership_unresolved",
			Message:     "Service-managed StackSet projections are intentionally hidden until AWS resolves effective account membership.",
			Remediation: "Use the launch URL to let AWS resolve the service-managed target set, then refresh connector status.",
			Retryable:   true,
		})
	}
	status, confidence, failures, remediations := summarizeAWSStackSetOnboarding("success", plan, diagnostics)
	return AWSStackSetOnboardingResult{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		AccountID:           "",
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
		CurrentIssueNumber:  1752,
		CurrentIssueRef:     awsIssueRef(1752),
		Version:             plan.Version,
		Status:              status,
		FixtureState:        "success",
		Confidence:          confidence,
		Validation:          mapAWSStackSetValidation(plan.Validation),
		PermissionPreview:   awsStackSetPermissionPreview(),
		Targets:             mapAWSStackSetTargets(plan.Targets),
		Instances:           instances,
		CoverageExpectation: coverageExpectation,
		RecoveryActions:     mapAWSStackSetRecoveryActions(plan.RecoveryActions),
		Summary:             summary,
		FailureReasons:      failures,
		RemediationHints:    remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(1752),
			"/docs/aws-stackset-onboarding",
			"/docs/auth/aws-connector",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}, nil
}

func awsConnectorStackSetDeploymentMode(method AWSConnectorDeploymentMethod) awscontract.StackSetDeploymentMode {
	if method == AWSConnectorDeploymentStackSetSelfManaged {
		return awscontract.StackSetDeploymentSelfManaged
	}
	return awscontract.StackSetDeploymentServiceManaged
}

func awsConnectorStackSetAutoDeploymentEnabled(mode awscontract.StackSetDeploymentMode, setup awsConnectorSetupContract) *bool {
	if mode != awscontract.StackSetDeploymentServiceManaged {
		return nil
	}
	enabled := setup.AutoOnboardNewAccounts
	return &enabled
}

func awsConnectorStackSetTargets(setup awsConnectorSetupContract) awscontract.StackSetOnboardingTargets {
	excluded := map[string]struct{}{}
	for _, accountID := range setup.ExcludedAccountIDs {
		excluded[accountID] = struct{}{}
	}
	targets := awscontract.StackSetOnboardingTargets{
		AllAccounts:         setup.ScopeType == AWSConnectorScopeOrganization,
		OrganizationalUnits: make([]awscontract.OrganizationUnit, 0, len(setup.TargetOUIDs)),
		Accounts:            make([]awscontract.StackSetOnboardingTargetAccount, 0, len(setup.TargetAccountIDs)),
		Regions:             make([]awscontract.StackSetOnboardingTargetRegion, 0, len(setup.TargetRegions)),
	}
	for _, ouID := range setup.TargetOUIDs {
		targets.OrganizationalUnits = append(targets.OrganizationalUnits, awscontract.OrganizationUnit{
			ID:      ouID,
			Path:    "/" + ouID,
			Enabled: true,
		})
	}
	for _, accountID := range setup.TargetAccountIDs {
		if _, skip := excluded[accountID]; skip {
			continue
		}
		targets.Accounts = append(targets.Accounts, awscontract.StackSetOnboardingTargetAccount{AccountID: accountID})
	}
	for _, region := range setup.TargetRegions {
		targets.Regions = append(targets.Regions, awscontract.StackSetOnboardingTargetRegion{Region: region})
	}
	return targets
}

func awsConnectorStackSetLaunchExcludedAccounts(setup awsConnectorSetupContract) []string {
	if setup.ScopeType == AWSConnectorScopeSelectedAccounts {
		return nil
	}
	return setup.ExcludedAccountIDs
}

func awsConnectorStackSetOnboardingStatus(onboarding AWSStackSetOnboardingResult) AWSConnectorOnboardingStatus {
	if onboarding.Validation.BlockingCount > 0 {
		return AWSConnectorOnboardingNeedsFix
	}
	return AWSConnectorOnboardingLaunchReady
}

func awsConnectorStackSetOnboardingStatusFromPrerequisites(prerequisites []AWSStackSetOnboardingPrerequisite) AWSConnectorOnboardingStatus {
	for _, prerequisite := range prerequisites {
		if !prerequisite.Satisfied && prerequisite.Severity == string(awscontract.StackSetPrerequisiteBlocking) {
			return AWSConnectorOnboardingNeedsFix
		}
	}
	return AWSConnectorOnboardingLaunchReady
}

func awsConnectorStackSetNextActions(setup awsConnectorSetupContract, validation AWSStackSetOnboardingValidation) []AWSConnectorNextAction {
	return awsConnectorStackSetNextActionsFromPrerequisites(setup, validation.Prerequisites)
}

func awsConnectorStackSetNextActionsFromPrerequisites(setup awsConnectorSetupContract, prerequisites []AWSStackSetOnboardingPrerequisite) []AWSConnectorNextAction {
	actions := []AWSConnectorNextAction{}
	for _, prerequisite := range prerequisites {
		if prerequisite.Satisfied {
			continue
		}
		switch prerequisite.ID {
		case "stackset.trusted_access_enabled":
			actions = append(actions, AWSConnectorNextActionEnableTrustedAccess)
		case "stackset.delegated_admin_registered":
			actions = append(actions, AWSConnectorNextActionRegisterDelegatedAdmin)
		case "stackset.targets_present":
			actions = append(actions, AWSConnectorNextActionSelectTargets)
		}
	}
	if len(setup.TargetRegions) == 0 {
		actions = append(actions, AWSConnectorNextActionSelectTargets)
	}
	actions = append(actions, AWSConnectorNextActionOpenStackSet, AWSConnectorNextActionRefreshStatus)
	return dedupeAWSConnectorNextActions(actions)
}

func dedupeAWSConnectorNextActions(actions []AWSConnectorNextAction) []AWSConnectorNextAction {
	out := make([]AWSConnectorNextAction, 0, len(actions))
	seen := map[AWSConnectorNextAction]struct{}{}
	for _, action := range actions {
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		out = append(out, action)
	}
	return out
}

func normalizeAWSConnectorSetupContract(input awsConnectorSetupInput) (awsConnectorSetupContract, error) {
	scopeType := AWSConnectorScopeType(strings.TrimSpace(string(input.ScopeType)))
	if scopeType == "" {
		scopeType = input.DefaultScopeType
	}
	if scopeType == "" {
		scopeType = AWSConnectorScopeSingleAccount
	}
	if !validAWSConnectorScopeType(scopeType) {
		return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
	}

	deploymentMethod := AWSConnectorDeploymentMethod(strings.TrimSpace(string(input.DeploymentMethod)))
	if deploymentMethod == "" {
		deploymentMethod = input.DefaultDeploymentMethod
	}
	if deploymentMethod == "" {
		deploymentMethod = defaultAWSConnectorDeploymentMethod(scopeType)
	}
	if !validAWSConnectorDeploymentMethod(deploymentMethod) {
		return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
	}

	targetRegions, err := normalizeAWSConnectorTargetRegions(input.TargetRegions)
	if err != nil {
		return awsConnectorSetupContract{}, err
	}
	region := strings.TrimSpace(input.Region)
	if region != "" {
		normalizedRegion := awsconnector.NormalizeRegion(region)
		if normalizedRegion != region {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if len(targetRegions) == 0 {
			targetRegions = []string{normalizedRegion}
		}
	}
	if len(targetRegions) == 0 && (scopeType == AWSConnectorScopeSingleAccount || scopeType == AWSConnectorScopeManualRole) {
		targetRegions = []string{"us-east-1"}
	}

	targetAccountIDs, err := normalizeAWSAccountIDs(input.TargetAccountIDs)
	if err != nil {
		return awsConnectorSetupContract{}, err
	}
	targetOUIDs, err := normalizeAWSOUIDs(input.TargetOUIDs)
	if err != nil {
		return awsConnectorSetupContract{}, err
	}
	excludedAccountIDs, err := normalizeAWSAccountIDs(input.ExcludedAccountIDs)
	if err != nil {
		return awsConnectorSetupContract{}, err
	}

	if (deploymentMethod == AWSConnectorDeploymentStackSetServiceManaged || deploymentMethod == AWSConnectorDeploymentStackSetSelfManaged) && len(targetRegions) == 0 {
		return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
	}

	switch scopeType {
	case AWSConnectorScopeSingleAccount:
		if deploymentMethod != AWSConnectorDeploymentCloudFormation && deploymentMethod != AWSConnectorDeploymentTerraform {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if len(targetAccountIDs) > 0 || len(targetOUIDs) > 0 || len(excludedAccountIDs) > 0 || input.AutoOnboardNewAccounts {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
	case AWSConnectorScopeManualRole:
		if deploymentMethod != AWSConnectorDeploymentManual {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if len(targetAccountIDs) > 0 || len(targetOUIDs) > 0 || len(excludedAccountIDs) > 0 || input.AutoOnboardNewAccounts {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
	case AWSConnectorScopeOrganization:
		if !awsConnectorDeploymentIsStackSet(deploymentMethod) {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if deploymentMethod == AWSConnectorDeploymentStackSetSelfManaged {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if len(targetAccountIDs) > 0 || len(targetOUIDs) != 1 || !awsConnectorTargetIDsAreRoots(targetOUIDs) {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
	case AWSConnectorScopeSelectedOUs:
		if !awsConnectorDeploymentIsStackSet(deploymentMethod) || len(targetOUIDs) == 0 {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if deploymentMethod == AWSConnectorDeploymentStackSetSelfManaged {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if !awsConnectorTargetIDsAreOUs(targetOUIDs) {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if len(targetAccountIDs) > 0 {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
	case AWSConnectorScopeSelectedAccounts:
		if !awsConnectorDeploymentIsStackSet(deploymentMethod) || len(targetAccountIDs) == 0 {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if awsConnectorSelectedAccountCountAfterExclusions(targetAccountIDs, excludedAccountIDs) == 0 {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if deploymentMethod == AWSConnectorDeploymentStackSetServiceManaged && len(targetOUIDs) == 0 {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if input.AutoOnboardNewAccounts {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
		if deploymentMethod == AWSConnectorDeploymentStackSetSelfManaged && len(targetOUIDs) > 0 {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
	}

	return awsConnectorSetupContract{
		ScopeType:              scopeType,
		DeploymentMethod:       deploymentMethod,
		TargetRegions:          copyAWSStringSlice(targetRegions),
		TargetAccountIDs:       copyAWSStringSlice(targetAccountIDs),
		TargetOUIDs:            copyAWSStringSlice(targetOUIDs),
		ExcludedAccountIDs:     copyAWSStringSlice(excludedAccountIDs),
		AutoOnboardNewAccounts: input.AutoOnboardNewAccounts,
	}, nil
}

func awsConnectorSelectedAccountCountAfterExclusions(targetAccountIDs []string, excludedAccountIDs []string) int {
	excluded := map[string]struct{}{}
	for _, accountID := range excludedAccountIDs {
		excluded[accountID] = struct{}{}
	}
	count := 0
	for _, accountID := range targetAccountIDs {
		if _, skip := excluded[accountID]; skip {
			continue
		}
		count++
	}
	return count
}

func awsConnectorSelectedAccountIncludesValidationAccount(setup awsConnectorSetupContract, roleARN string, validationAccountID string) bool {
	if setup.ScopeType != AWSConnectorScopeSelectedAccounts {
		return true
	}
	accountID := strings.TrimSpace(validationAccountID)
	if accountID == "" {
		accountID = accountIDFromRoleARN(roleARN)
	}
	if !awsAccountIDPattern.MatchString(accountID) {
		return false
	}
	if slices.Contains(setup.ExcludedAccountIDs, accountID) {
		return false
	}
	return slices.Contains(setup.TargetAccountIDs, accountID)
}

func awsConnectorTargetIDsAreOUs(targetOUIDs []string) bool {
	for _, ouID := range targetOUIDs {
		if !strings.HasPrefix(strings.TrimSpace(ouID), "ou-") {
			return false
		}
	}
	return true
}

func awsConnectorTargetIDsAreRoots(targetOUIDs []string) bool {
	for _, ouID := range targetOUIDs {
		if !strings.HasPrefix(strings.TrimSpace(ouID), "r-") {
			return false
		}
	}
	return true
}

func awsConnectorSetupContractsMatch(stored awsConnectorSetupContract, requested awsConnectorSetupContract) bool {
	return stored.ScopeType == requested.ScopeType &&
		stored.DeploymentMethod == requested.DeploymentMethod &&
		slices.Equal(stored.TargetRegions, requested.TargetRegions) &&
		slices.Equal(stored.TargetAccountIDs, requested.TargetAccountIDs) &&
		slices.Equal(stored.TargetOUIDs, requested.TargetOUIDs) &&
		slices.Equal(stored.ExcludedAccountIDs, requested.ExcludedAccountIDs) &&
		stored.AutoOnboardNewAccounts == requested.AutoOnboardNewAccounts
}

func validAWSConnectorScopeType(scopeType AWSConnectorScopeType) bool {
	switch scopeType {
	case AWSConnectorScopeSingleAccount, AWSConnectorScopeOrganization, AWSConnectorScopeSelectedOUs, AWSConnectorScopeSelectedAccounts, AWSConnectorScopeManualRole:
		return true
	default:
		return false
	}
}

func validAWSConnectorDeploymentMethod(method AWSConnectorDeploymentMethod) bool {
	switch method {
	case AWSConnectorDeploymentCloudFormation, AWSConnectorDeploymentStackSetServiceManaged, AWSConnectorDeploymentStackSetSelfManaged, AWSConnectorDeploymentTerraform, AWSConnectorDeploymentManual:
		return true
	default:
		return false
	}
}

func defaultAWSConnectorDeploymentMethod(scopeType AWSConnectorScopeType) AWSConnectorDeploymentMethod {
	switch scopeType {
	case AWSConnectorScopeManualRole:
		return AWSConnectorDeploymentManual
	case AWSConnectorScopeOrganization, AWSConnectorScopeSelectedOUs, AWSConnectorScopeSelectedAccounts:
		return AWSConnectorDeploymentStackSetServiceManaged
	default:
		return AWSConnectorDeploymentCloudFormation
	}
}

func awsConnectorDeploymentIsStackSet(method AWSConnectorDeploymentMethod) bool {
	return method == AWSConnectorDeploymentStackSetServiceManaged || method == AWSConnectorDeploymentStackSetSelfManaged
}

func normalizeAWSConnectorTargetRegions(regions []string) ([]string, error) {
	out := make([]string, 0, len(regions))
	seen := map[string]struct{}{}
	for _, raw := range regions {
		region := strings.TrimSpace(raw)
		if region == "" {
			continue
		}
		normalized := awsconnector.NormalizeRegion(region)
		if normalized != region {
			return nil, ErrInvalidAWSConnectionRequest
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

func normalizeAWSAccountIDs(accounts []string) ([]string, error) {
	out := make([]string, 0, len(accounts))
	seen := map[string]struct{}{}
	for _, raw := range accounts {
		accountID := strings.TrimSpace(raw)
		if accountID == "" {
			continue
		}
		if !awsAccountIDPattern.MatchString(accountID) {
			return nil, ErrInvalidAWSConnectionRequest
		}
		if _, ok := seen[accountID]; ok {
			continue
		}
		seen[accountID] = struct{}{}
		out = append(out, accountID)
	}
	slices.Sort(out)
	return out, nil
}

func normalizeAWSOUIDs(units []string) ([]string, error) {
	out := make([]string, 0, len(units))
	seen := map[string]struct{}{}
	for _, raw := range units {
		ouID := strings.TrimSpace(raw)
		if ouID == "" {
			continue
		}
		if !awsOUIDPattern.MatchString(ouID) {
			return nil, ErrInvalidAWSConnectionRequest
		}
		if _, ok := seen[ouID]; ok {
			continue
		}
		seen[ouID] = struct{}{}
		out = append(out, ouID)
	}
	slices.Sort(out)
	return out, nil
}

func applyAWSConnectorSetupMetadata(metadata map[string]any, setup awsConnectorSetupContract, onboardingStatus AWSConnectorOnboardingStatus) {
	if metadata == nil {
		return
	}
	metadata["scope_type"] = string(setup.ScopeType)
	metadata["deployment_method"] = string(setup.DeploymentMethod)
	metadata["onboarding_status"] = string(onboardingStatus)
	metadata["target_regions"] = copyAWSStringSlice(setup.TargetRegions)
	metadata["target_account_ids"] = copyAWSStringSlice(setup.TargetAccountIDs)
	metadata["target_ou_ids"] = copyAWSStringSlice(setup.TargetOUIDs)
	metadata["excluded_account_ids"] = copyAWSStringSlice(setup.ExcludedAccountIDs)
	metadata["auto_onboard_new_accounts"] = setup.AutoOnboardNewAccounts
	metadata["setup_summary"] = awsConnectorSetupSummary(setup, onboardingStatus)
	metadata["next_actions"] = awsConnectorNextActionStrings(awsConnectorNextActions(setup, onboardingStatus))
}

func awsConnectorSetupSummary(setup awsConnectorSetupContract, onboardingStatus AWSConnectorOnboardingStatus) string {
	switch onboardingStatus {
	case AWSConnectorOnboardingConnected:
		return "Connected and ready for discovery."
	case AWSConnectorOnboardingWaitingForAWS:
		return "Waiting for AWS stack approval."
	case AWSConnectorOnboardingRegistering:
		return "AWS is creating the read-only connection."
	case AWSConnectorOnboardingValidating:
		return "Verifying read-only access."
	case AWSConnectorOnboardingExpired:
		return "The connection window expired. Start again."
	case AWSConnectorOnboardingNeedsFix, AWSConnectorOnboardingFailed:
		return "The connection needs attention."
	}
	switch setup.ScopeType {
	case AWSConnectorScopeManualRole:
		return "Existing IAM role setup for one AWS account."
	case AWSConnectorScopeOrganization:
		return "AWS Organization setup planned through CloudFormation StackSets."
	case AWSConnectorScopeSelectedOUs:
		return "Selected AWS organizational units setup planned through CloudFormation StackSets."
	case AWSConnectorScopeSelectedAccounts:
		return "Selected AWS accounts setup planned through CloudFormation StackSets."
	default:
		return "One AWS account through CloudFormation."
	}
}

func awsConnectorNextActions(setup awsConnectorSetupContract, onboardingStatus AWSConnectorOnboardingStatus) []AWSConnectorNextAction {
	switch onboardingStatus {
	case AWSConnectorOnboardingConnected:
		return []AWSConnectorNextAction{AWSConnectorNextActionStartIntelligence, AWSConnectorNextActionRefreshStatus}
	case AWSConnectorOnboardingNeedsFix, AWSConnectorOnboardingFailed, AWSConnectorOnboardingPartial:
		return []AWSConnectorNextAction{AWSConnectorNextActionRepairPermissions, AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus}
	case AWSConnectorOnboardingWaitingForAWS, AWSConnectorOnboardingRegistering, AWSConnectorOnboardingValidating:
		return []AWSConnectorNextAction{AWSConnectorNextActionRefreshStatus}
	case AWSConnectorOnboardingExpired:
		return []AWSConnectorNextAction{AWSConnectorNextActionLaunchStack}
	}
	if awsConnectorDeploymentIsStackSet(setup.DeploymentMethod) {
		return []AWSConnectorNextAction{AWSConnectorNextActionOpenStackSet, AWSConnectorNextActionRefreshStatus}
	}
	if setup.ScopeType == AWSConnectorScopeManualRole || setup.DeploymentMethod == AWSConnectorDeploymentManual {
		return []AWSConnectorNextAction{AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus}
	}
	return []AWSConnectorNextAction{AWSConnectorNextActionLaunchStack, AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus}
}

func awsConnectorNextActionStrings(actions []AWSConnectorNextAction) []string {
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		out = append(out, string(action))
	}
	return out
}

func normalizeAWSConnectionRequest(request AWSConnectionUpsertRequest) (AWSConnectionUpsertRequest, error) {
	normalized := request
	normalized.RoleARN = strings.TrimSpace(request.RoleARN)
	if !awsRoleARNPattern.MatchString(normalized.RoleARN) {
		return AWSConnectionUpsertRequest{}, ErrInvalidAWSConnectionRequest
	}
	normalized.ExternalID = strings.TrimSpace(request.ExternalID)
	normalized.Region = strings.TrimSpace(request.Region)
	if normalized.Region == "" {
		normalized.Region = "us-east-1"
	}
	normalized.SessionName = strings.TrimSpace(request.SessionName)
	if normalized.SessionName == "" {
		normalized.SessionName = "identrail-connector-validation"
	}
	normalized.ConnectorID = strings.TrimSpace(request.ConnectorID)
	if normalized.ConnectorID == "" {
		normalized.ConnectorID = "aws-" + accountIDFromRoleARN(normalized.RoleARN)
	}
	normalized.DisplayName = strings.TrimSpace(request.DisplayName)
	if normalized.DisplayName == "" {
		normalized.DisplayName = "AWS account " + accountIDFromRoleARN(normalized.RoleARN)
	}
	connector := domain.Connector{
		ID:          normalized.ConnectorID,
		WorkspaceID: "workspace-placeholder",
		ProjectID:   "project-placeholder",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: normalized.DisplayName,
		Status:      domain.ConnectorStatusPending,
	}
	if err := connector.Validate(); err != nil {
		return AWSConnectionUpsertRequest{}, ErrInvalidAWSConnectionRequest
	}
	return normalized, nil
}

func awsConnectionStatusFromStored(stored db.TenancyConnectorWithState) AWSConnectionStatus {
	metadata := stored.State.Metadata
	createdAt := stored.Connector.CreatedAt
	updatedAt := stored.Connector.UpdatedAt
	validatedAt := awsMetadataTime(metadata, "last_validated_at")
	defaultScope, defaultDeployment := awsMetadataSetupFallback(metadata)
	setup := awsMetadataSetupContract(metadata, defaultScope, defaultDeployment)
	onboardingStatus := awsMetadataOnboardingStatus(metadata, "onboarding_status")
	if onboardingStatus == "" {
		onboardingStatus = awsConnectorOnboardingStatusFromHealth(stored.Connector.Status, stored.State.HealthStatus, awsMetadataString(metadata, "launch_url"))
	}
	status := AWSConnectionStatus{
		Provider:               "aws",
		Connected:              !stored.Connector.Disabled && stored.Connector.Status == domain.ConnectorStatusActive && stored.State.HealthStatus == "healthy",
		ConnectorID:            stored.Connector.ConnectorID,
		DisplayName:            stored.Connector.DisplayName,
		Status:                 stored.Connector.Status,
		Disabled:               stored.Connector.Disabled,
		LifecycleGeneration:    stored.Connector.LifecycleGeneration,
		HealthStatus:           firstNonEmptyAWSValue(stored.State.HealthStatus, "unknown"),
		RoleARN:                awsMetadataString(metadata, "role_arn"),
		ExternalID:             awsMetadataString(metadata, "external_id"),
		ExternalIDConfigured:   awsMetadataBool(metadata, "external_id_configured"),
		AccountID:              awsMetadataString(metadata, "account_id"),
		PrincipalARN:           awsMetadataString(metadata, "principal_arn"),
		UserID:                 awsMetadataString(metadata, "user_id"),
		Region:                 awsMetadataString(metadata, "region"),
		OrganizationID:         awsMetadataString(metadata, "organization_id"),
		ScopeType:              setup.ScopeType,
		DeploymentMethod:       setup.DeploymentMethod,
		OnboardingStatus:       onboardingStatus,
		TargetRegions:          copyAWSStringSlice(setup.TargetRegions),
		TargetAccountIDs:       copyAWSStringSlice(setup.TargetAccountIDs),
		TargetOUIDs:            copyAWSStringSlice(setup.TargetOUIDs),
		ExcludedAccountIDs:     copyAWSStringSlice(setup.ExcludedAccountIDs),
		AutoOnboardNewAccounts: setup.AutoOnboardNewAccounts,
		SetupSummary:           firstNonEmptyAWSValue(awsMetadataString(metadata, "setup_summary"), awsConnectorSetupSummary(setup, onboardingStatus)),
		NextActions:            awsMetadataNextActions(metadata, "next_actions", awsConnectorNextActions(setup, onboardingStatus)),
		PermissionChecks:       awsMetadataPermissionChecks(metadata, "permission_checks"),
		Diagnostics:            awsMetadataDiagnostics(metadata, "diagnostics"),
		Capabilities:           awsMetadataCapabilities(metadata, "capabilities"),
		LaunchURL:              awsMetadataString(metadata, "launch_url"),
		TemplateURL:            awsMetadataString(metadata, "template_url"),
		PolicyHash:             awsMetadataString(metadata, "policy_hash"),
		StackSetName:           awsMetadataString(metadata, "stack_set_name"),
		TemplateChecksum:       awsMetadataString(metadata, "template_checksum"),
		TargetSummary:          awsMetadataTargetSummary(metadata, "target_summary"),
		Prerequisites:          awsMetadataStackSetPrerequisites(metadata, "prerequisites"),
		CreatedAt:              &createdAt,
		UpdatedAt:              &updatedAt,
		LastValidatedAt:        validatedAt,
		CleanupStatus:          awsMetadataString(metadata, "cleanup_status"),
		CleanupRequired:        awsMetadataBool(metadata, "cleanup_required"),
	}
	status.RemediationMessage = firstAWSRemediation(status.Diagnostics, status.PermissionChecks)
	return status
}

func awsConnectorLifecycleMutationAllowed(stored db.TenancyConnectorWithState) bool {
	return !stored.Connector.Disabled && stored.Connector.Status != domain.ConnectorStatusDisconnected
}

func ensureAWSConnectorLifecycleStartAllowed(stored db.TenancyConnectorWithState) error {
	if !awsConnectorLifecycleMutationAllowed(stored) {
		return ErrAWSConnectorLifecycleBlocked
	}
	return nil
}

func (s *Service) awsConnectionStatusFromStored(ctx context.Context, stored db.TenancyConnectorWithState) AWSConnectionStatus {
	status := awsConnectionStatusFromStored(stored)
	if status.ExternalID == "" {
		status.ExternalID = s.awsExternalIDFromStored(ctx, stored)
	}
	status.ExternalIDConfigured = status.ExternalIDConfigured || status.ExternalID != ""
	return status
}

func (s *Service) awsExternalIDFromStored(ctx context.Context, stored db.TenancyConnectorWithState) string {
	externalID, _, err := s.awsExternalIDFromStoredStrict(ctx, stored)
	if err != nil {
		return ""
	}
	return externalID
}

func (s *Service) awsExternalIDFromStoredStrict(ctx context.Context, stored db.TenancyConnectorWithState) (string, bool, error) {
	if s == nil || s.Store == nil {
		externalID := awsMetadataString(stored.State.Metadata, "external_id")
		return externalID, externalID != "", nil
	}
	secret, err := s.Store.GetTenancyConnectorSecretEnvelope(
		db.WithScope(ctx, db.Scope{TenantID: stored.Connector.TenantID, WorkspaceID: stored.Connector.WorkspaceID}),
		stored.Connector.WorkspaceID,
		stored.Connector.ProjectID,
		stored.Connector.ConnectorID,
		awsExternalIDSecretName,
	)
	if err != nil {
		externalID := awsMetadataString(stored.State.Metadata, "external_id")
		if errors.Is(err, db.ErrNotFound) {
			return externalID, externalID != "", nil
		}
		if externalID != "" {
			return externalID, true, nil
		}
		return "", false, fmt.Errorf("load aws connector external id envelope: %w", err)
	}
	externalID, err := s.decryptAWSExternalIDEnvelope(stored.Connector, secret)
	if err != nil {
		return "", true, err
	}
	return externalID, true, nil
}

func (s *Service) decryptAWSExternalIDEnvelope(connector db.TenancyConnector, secret db.TenancyConnectorSecretEnvelope) (string, error) {
	plaintext, err := s.connectorSecretManager().Decrypt(secret.Envelope, awsExternalIDAAD(connector.TenantID, connector.WorkspaceID, connector.ProjectID, connector.ConnectorID))
	if err != nil {
		return "", fmt.Errorf("decrypt aws connector external id envelope: %w", err)
	}
	return strings.TrimSpace(string(plaintext)), nil
}

func (s *Service) persistAWSExternalID(ctx context.Context, tenantID string, workspaceID string, projectID string, connectorID string, externalID string, rotatedAt time.Time, expectedGeneration int64) error {
	if strings.TrimSpace(externalID) == "" {
		return nil
	}
	secret, err := s.newAWSExternalIDSecretEnvelope(tenantID, workspaceID, projectID, connectorID, externalID, rotatedAt)
	if err != nil {
		return err
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: tenantID, WorkspaceID: workspaceID})
	if generationStore, ok := s.Store.(db.TenancyConnectorLifecycleSecretStore); ok {
		if err := generationStore.UpsertTenancyConnectorSecretEnvelopeAtGeneration(scopedCtx, secret, expectedGeneration); err != nil {
			return fmt.Errorf("persist aws connector external id envelope: %w", err)
		}
		return nil
	}
	if err := s.Store.UpsertTenancyConnectorSecretEnvelope(scopedCtx, secret); err != nil {
		return fmt.Errorf("persist aws connector external id envelope: %w", err)
	}
	return nil
}

func (s *Service) newAWSExternalIDSecretEnvelope(tenantID string, workspaceID string, projectID string, connectorID string, externalID string, rotatedAt time.Time) (db.TenancyConnectorSecretEnvelope, error) {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" {
		return db.TenancyConnectorSecretEnvelope{}, nil
	}
	manager := s.connectorSecretManager()
	envelope, err := manager.Encrypt([]byte(externalID), awsExternalIDAAD(tenantID, workspaceID, projectID, connectorID))
	if err != nil {
		return db.TenancyConnectorSecretEnvelope{}, fmt.Errorf("encrypt aws connector external id: %w", err)
	}
	secret := db.TenancyConnectorSecretEnvelope{
		TenantID:        tenantID,
		WorkspaceID:     workspaceID,
		ProjectID:       projectID,
		ConnectorID:     connectorID,
		SecretName:      awsExternalIDSecretName,
		EnvelopeVersion: envelope.Version,
		Envelope:        envelope,
		SecretRefID:     awsExternalIDSecretRef(connectorID),
		RotatedAt:       rotatedAt,
		CreatedAt:       rotatedAt,
		UpdatedAt:       rotatedAt,
	}
	return secret, nil
}

func (s *Service) clearAWSExternalID(ctx context.Context, tenantID string, workspaceID string, projectID string, connectorID string, expectedGeneration int64) error {
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: tenantID, WorkspaceID: workspaceID})
	var err error
	if generationStore, ok := s.Store.(db.TenancyConnectorLifecycleSecretStore); ok {
		err = generationStore.DeleteTenancyConnectorSecretEnvelopeAtGeneration(scopedCtx, workspaceID, projectID, connectorID, awsExternalIDSecretName, expectedGeneration)
	} else {
		err = s.Store.DeleteTenancyConnectorSecretEnvelope(scopedCtx, workspaceID, projectID, connectorID, awsExternalIDSecretName)
	}
	if errors.Is(err, db.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("clear aws connector external id envelope: %w", err)
	}
	return nil
}

func (s *Service) createAWSExternalIDSecretIfCurrent(ctx context.Context, stored db.TenancyConnectorWithState, secret db.TenancyConnectorSecretEnvelope) (db.TenancyConnectorSecretEnvelope, bool, error) {
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: stored.Connector.TenantID, WorkspaceID: stored.Connector.WorkspaceID})
	if generationStore, ok := s.Store.(db.TenancyConnectorLifecycleSecretStore); ok {
		return generationStore.CreateTenancyConnectorSecretEnvelopeIfAbsentAtGeneration(scopedCtx, secret, stored.Connector.LifecycleGeneration)
	}
	current, err := s.Store.GetTenancyConnector(scopedCtx, stored.Connector.WorkspaceID, stored.Connector.ProjectID, stored.Connector.ConnectorID)
	if err != nil {
		return db.TenancyConnectorSecretEnvelope{}, false, err
	}
	if current.Connector.LifecycleGeneration != stored.Connector.LifecycleGeneration || !awsConnectorLifecycleMutationAllowed(current) {
		return db.TenancyConnectorSecretEnvelope{}, false, db.ErrConflict
	}
	return s.Store.CreateTenancyConnectorSecretEnvelopeIfAbsent(scopedCtx, secret)
}

func awsExternalIDAAD(tenantID string, workspaceID string, projectID string, connectorID string) []byte {
	return []byte(strings.Join([]string{"aws", tenantID, workspaceID, projectID, connectorID, awsExternalIDSecretName}, "/"))
}

func awsExternalIDSecretRef(connectorID string) string {
	return awsConnectorSecretRefPrefix + strings.TrimSpace(connectorID) + "/" + awsExternalIDSecretName
}

func generateAWSExternalID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate aws external id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func failedAWSChecks(checks []AWSConnectionPermissionCheck) []AWSConnectionPermissionCheck {
	failed := make([]AWSConnectionPermissionCheck, 0)
	for _, check := range checks {
		if !check.Passed {
			failed = append(failed, check)
		}
	}
	return failed
}

func firstAWSRemediation(diagnostics []AWSConnectionDiagnostic, checks []AWSConnectionPermissionCheck) string {
	for _, diagnostic := range diagnostics {
		if strings.TrimSpace(diagnostic.OperatorAction) != "" {
			return diagnostic.OperatorAction
		}
		if strings.TrimSpace(diagnostic.Remediation) != "" {
			return diagnostic.Remediation
		}
	}
	for _, check := range checks {
		if !check.Passed && strings.TrimSpace(check.Remediation) != "" {
			return check.Remediation
		}
	}
	return ""
}

func copyAWSPermissionChecks(checks []AWSConnectionPermissionCheck) []AWSConnectionPermissionCheck {
	if len(checks) == 0 {
		return []AWSConnectionPermissionCheck{}
	}
	copied := make([]AWSConnectionPermissionCheck, len(checks))
	copy(copied, checks)
	return copied
}

func copyAWSDiagnostics(diagnostics []AWSConnectionDiagnostic) []AWSConnectionDiagnostic {
	if len(diagnostics) == 0 {
		return []AWSConnectionDiagnostic{}
	}
	copied := make([]AWSConnectionDiagnostic, len(diagnostics))
	copy(copied, diagnostics)
	return copied
}

func copyAWSStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	copied := make([]string, len(values))
	copy(copied, values)
	return copied
}

func copyAWSConnectorNextActions(actions []AWSConnectorNextAction) []AWSConnectorNextAction {
	if len(actions) == 0 {
		return []AWSConnectorNextAction{}
	}
	copied := make([]AWSConnectorNextAction, len(actions))
	copy(copied, actions)
	return copied
}

func firstNonEmptyAWSValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func awsMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	raw, ok := metadata[key]
	if !ok || raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func awsMetadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	switch value := metadata[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func awsMetadataStringSlice(metadata map[string]any, key string) []string {
	if metadata == nil || metadata[key] == nil {
		return []string{}
	}
	switch value := metadata[key].(type) {
	case []string:
		return copyAWSStringSlice(value)
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if trimmed := strings.TrimSpace(fmt.Sprint(item)); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	default:
		payload, err := json.Marshal(value)
		if err != nil {
			return []string{}
		}
		var out []string
		if err := json.Unmarshal(payload, &out); err != nil {
			return []string{}
		}
		return copyAWSStringSlice(out)
	}
}

func awsMetadataSetupContract(metadata map[string]any, defaultScope AWSConnectorScopeType, defaultDeployment AWSConnectorDeploymentMethod) awsConnectorSetupContract {
	setup, err := normalizeAWSConnectorSetupContract(awsConnectorSetupInput{
		ScopeType:               AWSConnectorScopeType(awsMetadataString(metadata, "scope_type")),
		DeploymentMethod:        AWSConnectorDeploymentMethod(awsMetadataString(metadata, "deployment_method")),
		Region:                  awsMetadataString(metadata, "region"),
		TargetRegions:           awsMetadataStringSlice(metadata, "target_regions"),
		TargetAccountIDs:        awsMetadataStringSlice(metadata, "target_account_ids"),
		TargetOUIDs:             awsMetadataStringSlice(metadata, "target_ou_ids"),
		ExcludedAccountIDs:      awsMetadataStringSlice(metadata, "excluded_account_ids"),
		AutoOnboardNewAccounts:  awsMetadataBool(metadata, "auto_onboard_new_accounts"),
		DefaultScopeType:        defaultScope,
		DefaultDeploymentMethod: defaultDeployment,
	})
	if err != nil {
		setup, _ = normalizeAWSConnectorSetupContract(awsConnectorSetupInput{
			ScopeType:               defaultScope,
			DeploymentMethod:        defaultDeployment,
			Region:                  awsMetadataString(metadata, "region"),
			DefaultScopeType:        defaultScope,
			DefaultDeploymentMethod: defaultDeployment,
		})
	}
	return setup
}

func awsMetadataSetupFallback(metadata map[string]any) (AWSConnectorScopeType, AWSConnectorDeploymentMethod) {
	if strings.TrimSpace(awsMetadataString(metadata, "scope_type")) != "" || strings.TrimSpace(awsMetadataString(metadata, "deployment_method")) != "" {
		return AWSConnectorScopeSingleAccount, AWSConnectorDeploymentCloudFormation
	}
	if strings.TrimSpace(awsMetadataString(metadata, "launch_url")) != "" || strings.TrimSpace(awsMetadataString(metadata, "template_url")) != "" {
		return AWSConnectorScopeSingleAccount, AWSConnectorDeploymentCloudFormation
	}
	return AWSConnectorScopeManualRole, AWSConnectorDeploymentManual
}

func awsMetadataOnboardingStatus(metadata map[string]any, key string) AWSConnectorOnboardingStatus {
	status := AWSConnectorOnboardingStatus(awsMetadataString(metadata, key))
	switch status {
	case AWSConnectorOnboardingDraft, AWSConnectorOnboardingLaunchReady, AWSConnectorOnboardingWaitingForAWS, AWSConnectorOnboardingValidating, AWSConnectorOnboardingConnected, AWSConnectorOnboardingPartial, AWSConnectorOnboardingNeedsFix, AWSConnectorOnboardingFailed:
		return status
	default:
		return ""
	}
}

func awsConnectorOnboardingStatusFromHealth(status domain.ConnectorStatus, health string, launchURL string) AWSConnectorOnboardingStatus {
	switch {
	case status == domain.ConnectorStatusActive && health == "healthy":
		return AWSConnectorOnboardingConnected
	case status == domain.ConnectorStatusDegraded || health == "error":
		return AWSConnectorOnboardingNeedsFix
	case strings.TrimSpace(launchURL) != "":
		return AWSConnectorOnboardingLaunchReady
	default:
		return AWSConnectorOnboardingDraft
	}
}

func awsMetadataNextActions(metadata map[string]any, key string, fallback []AWSConnectorNextAction) []AWSConnectorNextAction {
	raw := awsMetadataStringSlice(metadata, key)
	if len(raw) == 0 {
		return copyAWSConnectorNextActions(fallback)
	}
	actions := make([]AWSConnectorNextAction, 0, len(raw))
	for _, item := range raw {
		action := AWSConnectorNextAction(strings.TrimSpace(item))
		switch action {
		case AWSConnectorNextActionLaunchStack,
			AWSConnectorNextActionOpenStackSet,
			AWSConnectorNextActionEnableTrustedAccess,
			AWSConnectorNextActionRegisterDelegatedAdmin,
			AWSConnectorNextActionSelectTargets,
			AWSConnectorNextActionValidateRole,
			AWSConnectorNextActionRefreshStatus,
			AWSConnectorNextActionRepairPermissions,
			AWSConnectorNextActionRefreshPolicy,
			AWSConnectorNextActionCopyTrustPolicy,
			AWSConnectorNextActionOpenDocs,
			AWSConnectorNextActionStartIntelligence:
			actions = append(actions, action)
		}
	}
	if len(actions) == 0 {
		return copyAWSConnectorNextActions(fallback)
	}
	return actions
}

func awsMetadataTime(metadata map[string]any, key string) *time.Time {
	value := awsMetadataString(metadata, key)
	if value == "" || value == "<nil>" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	utc := parsed.UTC()
	return &utc
}

func awsMetadataPermissionChecks(metadata map[string]any, key string) []AWSConnectionPermissionCheck {
	if metadata == nil || metadata[key] == nil {
		return []AWSConnectionPermissionCheck{}
	}
	var checks []AWSConnectionPermissionCheck
	payload, err := json.Marshal(metadata[key])
	if err != nil {
		return []AWSConnectionPermissionCheck{}
	}
	if err := json.Unmarshal(payload, &checks); err != nil {
		return []AWSConnectionPermissionCheck{}
	}
	return copyAWSPermissionChecks(checks)
}

func awsMetadataDiagnostics(metadata map[string]any, key string) []AWSConnectionDiagnostic {
	if metadata == nil || metadata[key] == nil {
		return []AWSConnectionDiagnostic{}
	}
	var diagnostics []AWSConnectionDiagnostic
	payload, err := json.Marshal(metadata[key])
	if err != nil {
		return []AWSConnectionDiagnostic{}
	}
	if err := json.Unmarshal(payload, &diagnostics); err != nil {
		return []AWSConnectionDiagnostic{}
	}
	return copyAWSDiagnostics(diagnostics)
}

func awsMetadataTargetSummary(metadata map[string]any, key string) *AWSConnectorTargetSummary {
	if metadata == nil || metadata[key] == nil {
		return nil
	}
	payload, err := json.Marshal(metadata[key])
	if err != nil {
		return nil
	}
	var summary AWSConnectorTargetSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		return nil
	}
	return &summary
}

func awsMetadataStackSetPrerequisites(metadata map[string]any, key string) []AWSStackSetOnboardingPrerequisite {
	if metadata == nil || metadata[key] == nil {
		return nil
	}
	payload, err := json.Marshal(metadata[key])
	if err != nil {
		return nil
	}
	var prerequisites []AWSStackSetOnboardingPrerequisite
	if err := json.Unmarshal(payload, &prerequisites); err != nil {
		return nil
	}
	return prerequisites
}

func accountIDFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return "unknown"
}

// awsCapabilityPolicy returns the configured capability gate, falling back to the
// safe read-only default when the service has none configured.
func (s *Service) awsCapabilityPolicy() awsconnector.CapabilityPolicy {
	if s != nil && s.AWSConnectorCapabilityPolicy.Configured() {
		return s.AWSConnectorCapabilityPolicy
	}
	return awsconnector.DefaultCapabilityPolicy()
}

// resolveAWSConnectorCapabilities resolves a requested capability set against the
// deployment gate and returns both the capability summary and capability-scoped
// diagnostics for any tier that could not be granted. The diagnostics name the
// specific capability so a validation failure is never reported generically.
func (s *Service) resolveAWSConnectorCapabilities(requested []domain.ConnectorCapability) (AWSConnectorCapabilities, []AWSConnectionDiagnostic, error) {
	resolution, err := domain.ResolveConnectorCapabilities(requested, s.awsCapabilityPolicy())
	if err != nil {
		return AWSConnectorCapabilities{}, nil, fmt.Errorf("%w: %v", ErrInvalidAWSConnectionRequest, err)
	}

	capabilities := AWSConnectorCapabilities{
		Requested:   resolution.Requested,
		Validated:   resolution.Validated,
		Effective:   resolution.Effective,
		Unavailable: make([]AWSConnectorCapabilityUnavailable, 0, len(resolution.Unavailable)),
	}
	diagnostics := make([]AWSConnectionDiagnostic, 0, len(resolution.Unavailable))
	for _, unavailable := range resolution.Unavailable {
		capabilities.Unavailable = append(capabilities.Unavailable, AWSConnectorCapabilityUnavailable{
			Capability: unavailable.Capability,
			Tier:       unavailable.Tier,
			Reason:     unavailable.Reason,
		})
		diagnostics = append(diagnostics, AWSConnectionDiagnostic{
			Code:           "capability_unavailable",
			Severity:       "warning",
			AffectedScope:  string(unavailable.Capability),
			Message:        fmt.Sprintf("requested capability %q is unavailable: %s", unavailable.Capability, unavailable.Reason),
			OperatorAction: fmt.Sprintf("Enable the %q capability gate for this deployment before requesting it; write-capable tiers also require a dedicated write role.", unavailable.Capability),
			Remediation:    fmt.Sprintf("Enable the %q capability gate for this deployment before requesting it; write-capable tiers also require a dedicated write role.", unavailable.Capability),
			Retryable:      true,
			EvidenceRef:    fmt.Sprintf("aws-capability:%s/%s", unavailable.Capability, unavailable.Tier),
			Actions:        []AWSConnectorNextAction{AWSConnectorNextActionOpenDocs, AWSConnectorNextActionRefreshPolicy},
		})
	}
	return capabilities, diagnostics, nil
}

func awsConnectorSetupDiagnostics(setup awsConnectorSetupContract, roleARN string, externalID string, diagnostics []AWSConnectionDiagnostic, checks []AWSConnectionPermissionCheck) []AWSConnectionDiagnostic {
	out := make([]AWSConnectionDiagnostic, 0, len(diagnostics)+len(checks))
	for _, diagnostic := range diagnostics {
		out = append(out, scrubAWSConnectionDiagnostic(enrichAWSConnectionDiagnostic(setup, roleARN, diagnostic), externalID))
	}
	for _, check := range checks {
		if check.Passed {
			continue
		}
		out = append(out, scrubAWSConnectionDiagnostic(awsDiagnosticFromPermissionCheck(setup, roleARN, check), externalID))
	}
	return dedupeAWSConnectionDiagnostics(out)
}

func enrichAWSConnectionDiagnostic(setup awsConnectorSetupContract, roleARN string, diagnostic AWSConnectionDiagnostic) AWSConnectionDiagnostic {
	code := normalizeAWSSetupDiagnosticCode(diagnostic.Code, diagnostic.Message+" "+diagnostic.Remediation)
	diagnostic.Code = code
	if strings.TrimSpace(diagnostic.Severity) == "" {
		diagnostic.Severity = awsSetupDiagnosticSeverity(code)
	}
	if strings.TrimSpace(diagnostic.AffectedScope) == "" {
		diagnostic.AffectedScope = awsDiagnosticAffectedScope(setup, roleARN)
	}
	if strings.TrimSpace(diagnostic.OperatorAction) == "" {
		diagnostic.OperatorAction = firstNonEmptyAWSValue(strings.TrimSpace(diagnostic.Remediation), awsSetupDiagnosticAction(code, setup))
	}
	if strings.TrimSpace(diagnostic.Remediation) == "" {
		diagnostic.Remediation = diagnostic.OperatorAction
	}
	if !diagnostic.Retryable {
		diagnostic.Retryable = awsSetupDiagnosticRetryable(code)
	}
	if strings.TrimSpace(diagnostic.EvidenceRef) == "" {
		diagnostic.EvidenceRef = "aws-connector:" + code
	}
	if strings.TrimSpace(diagnostic.Tradeoff) == "" {
		diagnostic.Tradeoff = awsSetupDiagnosticTradeoff(code, setup)
	}
	if len(diagnostic.Actions) == 0 {
		diagnostic.Actions = awsSetupDiagnosticActions(code, setup)
	}
	return diagnostic
}

func awsDiagnosticFromPermissionCheck(setup awsConnectorSetupContract, roleARN string, check AWSConnectionPermissionCheck) AWSConnectionDiagnostic {
	code := "missing_read_only_permission_tier"
	if strings.Contains(strings.ToLower(check.Name+" "+check.Message), "assumerole") {
		code = "assume_role_failed"
	}
	return enrichAWSConnectionDiagnostic(setup, roleARN, AWSConnectionDiagnostic{
		Code:        code,
		Message:     firstNonEmptyAWSValue(strings.TrimSpace(check.Message), "AWS connector validation failed for "+check.Name+"."),
		Remediation: strings.TrimSpace(check.Remediation),
		EvidenceRef: "aws-permission-check:" + strings.TrimSpace(check.Name),
	})
}

func normalizeAWSSetupDiagnosticCode(code string, text string) string {
	normalized := strings.ToLower(strings.TrimSpace(code))
	switch normalized {
	case "assume_role_failed", "external_id_mismatch", "role_arn_malformed", "missing_read_only_permission_tier", "connector_config_missing", "identity_metadata_unexpected", "capability_unavailable":
		return normalized
	case "aws_identity_metadata_unexpected", "aws_identity_metadata_failed":
		return "identity_metadata_unexpected"
	case "aws_capability_unavailable":
		return "capability_unavailable"
	case "aws_access_denied", "access_denied":
		return "assume_role_failed"
	}
	search := strings.ToLower(text + " " + normalized)
	switch {
	case strings.Contains(normalized, "access_denied") || strings.Contains(normalized, "assume") || strings.Contains(search, "assume"):
		return "assume_role_failed"
	case strings.Contains(normalized, "malformed") || (strings.Contains(search, "role arn") && strings.Contains(search, "valid")):
		return "role_arn_malformed"
	case strings.Contains(normalized, "capability") || strings.Contains(normalized, "permission") || strings.Contains(search, "permission"):
		return "missing_read_only_permission_tier"
	case strings.Contains(normalized, "external_id") || strings.Contains(search, "external id") || strings.Contains(search, "externalid"):
		return "external_id_mismatch"
	case normalized == "":
		return "assume_role_failed"
	default:
		return normalized
	}
}

func awsSetupDiagnosticSeverity(code string) string {
	switch code {
	case "delegated_admin_recommended", "partial_stackset_coverage", "capability_unavailable":
		return "warning"
	default:
		return "blocking"
	}
}

func awsDiagnosticAffectedScope(setup awsConnectorSetupContract, roleARN string) string {
	if accountID := awsAccountIDFromRoleARN(roleARN); accountID != "" {
		return "account/" + accountID
	}
	switch setup.ScopeType {
	case AWSConnectorScopeOrganization:
		return "organization"
	case AWSConnectorScopeSelectedOUs:
		return "selected_ous"
	case AWSConnectorScopeSelectedAccounts:
		return "selected_accounts"
	default:
		return "single_account"
	}
}

func awsAccountIDFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) >= 5 && awsAccountIDPattern.MatchString(parts[4]) {
		return parts[4]
	}
	return ""
}

func awsSetupDiagnosticAction(code string, setup awsConnectorSetupContract) string {
	switch code {
	case "external_id_mismatch":
		return "Copy the current External ID guidance into the IAM trust policy, then revalidate the role."
	case "role_arn_malformed":
		return "Paste the full IAM role ARN from AWS, then revalidate."
	case "missing_read_only_permission_tier":
		return "Refresh the expected policy, update the read-only role permissions, then revalidate."
	case "capability_unavailable":
		return "Enable the requested capability gate for this Identrail deployment; the read-only connector will keep collecting in the meantime."
	case "identity_metadata_unexpected":
		return "Retry validation, then check STS endpoint reachability and session-credential integrity from this deployment — sts:GetCallerIdentity requires no permissions, so trust and session policies are not the cause."
	case "connector_config_missing":
		return "Configure the AWS CloudFormation template URL and checksum for this Identrail deployment."
	default:
		if awsConnectorDeploymentIsStackSet(setup.DeploymentMethod) {
			return "Review the StackSet trust and instance status, then refresh connector status."
		}
		return "Update the IAM role trust policy so Identrail can assume the role, then revalidate."
	}
}

func awsSetupDiagnosticTradeoff(code string, setup awsConnectorSetupContract) string {
	switch code {
	case "missing_read_only_permission_tier":
		return "Keeping the narrower policy limits blast radius, but Identrail will not claim coverage for services it cannot read."
	case "capability_unavailable":
		return "Read-only discovery keeps running, but the requested capability stays off until the deployment gate opens it."
	case "external_id_mismatch":
		return "Rotating the trust-policy condition protects this tenant boundary, but the role will stay unavailable until AWS and Identrail match."
	case "assume_role_failed":
		if awsConnectorDeploymentIsStackSet(setup.DeploymentMethod) {
			return "Fixing trust for one StackSet role restores validation without granting write remediation permissions."
		}
		return "Fixing trust restores read-only collection without granting write remediation permissions."
	case "identity_metadata_unexpected":
		return "Trust and permissions already work; STS endpoint reachability or credential integrity is the likely cause, so no policy changes are recommended."
	default:
		return ""
	}
}

func awsSetupDiagnosticRetryable(code string) bool {
	switch code {
	case "connector_config_missing":
		return false
	default:
		return true
	}
}

func awsSetupDiagnosticActions(code string, setup awsConnectorSetupContract) []AWSConnectorNextAction {
	switch code {
	case "external_id_mismatch":
		return []AWSConnectorNextAction{AWSConnectorNextActionCopyTrustPolicy, AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus}
	case "missing_read_only_permission_tier":
		return []AWSConnectorNextAction{AWSConnectorNextActionRefreshPolicy, AWSConnectorNextActionRepairPermissions, AWSConnectorNextActionValidateRole}
	case "capability_unavailable":
		return []AWSConnectorNextAction{AWSConnectorNextActionOpenDocs, AWSConnectorNextActionRefreshPolicy}
	case "identity_metadata_unexpected":
		return []AWSConnectorNextAction{AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus, AWSConnectorNextActionOpenDocs}
	case "role_arn_malformed":
		return []AWSConnectorNextAction{AWSConnectorNextActionValidateRole, AWSConnectorNextActionOpenDocs}
	default:
		if awsConnectorDeploymentIsStackSet(setup.DeploymentMethod) {
			return []AWSConnectorNextAction{AWSConnectorNextActionOpenStackSet, AWSConnectorNextActionRefreshStatus, AWSConnectorNextActionValidateRole}
		}
		return []AWSConnectorNextAction{AWSConnectorNextActionCopyTrustPolicy, AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus}
	}
}

func dedupeAWSConnectionDiagnostics(diagnostics []AWSConnectionDiagnostic) []AWSConnectionDiagnostic {
	out := make([]AWSConnectionDiagnostic, 0, len(diagnostics))
	seen := map[string]struct{}{}
	for _, diagnostic := range diagnostics {
		key := strings.Join([]string{
			strings.TrimSpace(diagnostic.Code),
			strings.TrimSpace(diagnostic.AffectedScope),
		}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, diagnostic)
	}
	return out
}

func scrubAWSConnectionDiagnostic(diagnostic AWSConnectionDiagnostic, externalID string) AWSConnectionDiagnostic {
	secret := strings.TrimSpace(externalID)
	if secret == "" {
		return diagnostic
	}
	diagnostic.Message = strings.ReplaceAll(diagnostic.Message, secret, "[redacted]")
	diagnostic.OperatorAction = strings.ReplaceAll(diagnostic.OperatorAction, secret, "[redacted]")
	diagnostic.Remediation = strings.ReplaceAll(diagnostic.Remediation, secret, "[redacted]")
	diagnostic.EvidenceRef = strings.ReplaceAll(diagnostic.EvidenceRef, secret, "[redacted]")
	diagnostic.Tradeoff = strings.ReplaceAll(diagnostic.Tradeoff, secret, "[redacted]")
	return diagnostic
}

func scrubAWSPermissionChecks(checks []AWSConnectionPermissionCheck, externalID string) []AWSConnectionPermissionCheck {
	secret := strings.TrimSpace(externalID)
	if secret == "" {
		return checks
	}
	for index := range checks {
		checks[index].Message = strings.ReplaceAll(checks[index].Message, secret, "[redacted]")
		checks[index].Remediation = strings.ReplaceAll(checks[index].Remediation, secret, "[redacted]")
	}
	return checks
}

// defaultAWSConnectorCapabilities returns the read-only discovery baseline used
// for connectors persisted before capability tracking existed.
func defaultAWSConnectorCapabilities() AWSConnectorCapabilities {
	base := domain.DefaultConnectorCapabilities()
	return AWSConnectorCapabilities{
		Requested:   base,
		Validated:   base,
		Effective:   base,
		Unavailable: []AWSConnectorCapabilityUnavailable{},
	}
}

func awsMetadataCapabilities(metadata map[string]any, key string) AWSConnectorCapabilities {
	if metadata == nil || metadata[key] == nil {
		return defaultAWSConnectorCapabilities()
	}
	payload, err := json.Marshal(metadata[key])
	if err != nil {
		return defaultAWSConnectorCapabilities()
	}
	var capabilities AWSConnectorCapabilities
	if err := json.Unmarshal(payload, &capabilities); err != nil {
		return defaultAWSConnectorCapabilities()
	}
	if len(capabilities.Effective) == 0 {
		return defaultAWSConnectorCapabilities()
	}
	if capabilities.Unavailable == nil {
		capabilities.Unavailable = []AWSConnectorCapabilityUnavailable{}
	}
	return capabilities
}
