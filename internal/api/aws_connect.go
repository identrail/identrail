package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	awsconnector "github.com/identrail/identrail/internal/connectors/aws"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

var (
	awsRoleARNPattern   = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
	awsOUIDPattern      = regexp.MustCompile(`^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$`)
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
	AWSConnectorOnboardingValidating    AWSConnectorOnboardingStatus = "validating"
	AWSConnectorOnboardingConnected     AWSConnectorOnboardingStatus = "connected"
	AWSConnectorOnboardingPartial       AWSConnectorOnboardingStatus = "partial"
	AWSConnectorOnboardingNeedsFix      AWSConnectorOnboardingStatus = "needs_fix"
	AWSConnectorOnboardingFailed        AWSConnectorOnboardingStatus = "failed"
)

// AWSConnectorNextAction is one typed operator action the app can render.
type AWSConnectorNextAction string

const (
	AWSConnectorNextActionLaunchStack       AWSConnectorNextAction = "launch_stack"
	AWSConnectorNextActionOpenStackSet      AWSConnectorNextAction = "open_stackset"
	AWSConnectorNextActionValidateRole      AWSConnectorNextAction = "validate_role"
	AWSConnectorNextActionRefreshStatus     AWSConnectorNextAction = "refresh_status"
	AWSConnectorNextActionRepairPermissions AWSConnectorNextAction = "repair_permissions"
	AWSConnectorNextActionStartIntelligence AWSConnectorNextAction = "start_intelligence"
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
	ScopeType              AWSConnectorScopeType        `json:"scope_type,omitempty"`
	DeploymentMethod       AWSConnectorDeploymentMethod `json:"deployment_method,omitempty"`
	TargetRegions          []string                     `json:"target_regions,omitempty"`
	TargetAccountIDs       []string                     `json:"target_account_ids,omitempty"`
	TargetOUIDs            []string                     `json:"target_ou_ids,omitempty"`
	ExcludedAccountIDs     []string                     `json:"excluded_account_ids,omitempty"`
	AutoOnboardNewAccounts bool                         `json:"auto_onboard_new_accounts,omitempty"`
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

// AWSConnectorStartResponse returns launch data for the one-click AWS setup flow.
type AWSConnectorStartResponse struct {
	Connection             AWSConnectionStatus                     `json:"connection"`
	ConnectorID            string                                  `json:"connector_id"`
	ExternalID             string                                  `json:"external_id"`
	LaunchURL              string                                  `json:"launch_url"`
	TemplateURL            string                                  `json:"template_url"`
	RoleName               string                                  `json:"role_name"`
	StackName              string                                  `json:"stack_name"`
	PolicyHash             string                                  `json:"policy_hash"`
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
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
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
	Provider               string                         `json:"provider"`
	Connected              bool                           `json:"connected"`
	ConnectorID            string                         `json:"connector_id,omitempty"`
	DisplayName            string                         `json:"display_name,omitempty"`
	Status                 domain.ConnectorStatus         `json:"status"`
	HealthStatus           string                         `json:"health_status"`
	RoleARN                string                         `json:"role_arn,omitempty"`
	ExternalIDConfigured   bool                           `json:"external_id_configured"`
	AccountID              string                         `json:"account_id,omitempty"`
	PrincipalARN           string                         `json:"principal_arn,omitempty"`
	UserID                 string                         `json:"user_id,omitempty"`
	Region                 string                         `json:"region,omitempty"`
	ScopeType              AWSConnectorScopeType          `json:"scope_type"`
	DeploymentMethod       AWSConnectorDeploymentMethod   `json:"deployment_method"`
	OnboardingStatus       AWSConnectorOnboardingStatus   `json:"onboarding_status"`
	TargetRegions          []string                       `json:"target_regions"`
	TargetAccountIDs       []string                       `json:"target_account_ids"`
	TargetOUIDs            []string                       `json:"target_ou_ids"`
	ExcludedAccountIDs     []string                       `json:"excluded_account_ids"`
	AutoOnboardNewAccounts bool                           `json:"auto_onboard_new_accounts"`
	SetupSummary           string                         `json:"setup_summary"`
	NextActions            []AWSConnectorNextAction       `json:"next_actions"`
	ExternalID             string                         `json:"-"`
	PermissionChecks       []AWSConnectionPermissionCheck `json:"permission_checks"`
	Diagnostics            []AWSConnectionDiagnostic      `json:"diagnostics"`
	Capabilities           AWSConnectorCapabilities       `json:"capabilities"`
	RemediationMessage     string                         `json:"remediation_message,omitempty"`
	LaunchURL              string                         `json:"launch_url,omitempty"`
	TemplateURL            string                         `json:"template_url,omitempty"`
	PolicyHash             string                         `json:"policy_hash,omitempty"`
	CreatedAt              *time.Time                     `json:"created_at,omitempty"`
	UpdatedAt              *time.Time                     `json:"updated_at,omitempty"`
	LastValidatedAt        *time.Time                     `json:"last_validated_at,omitempty"`
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
	if setup.ScopeType != AWSConnectorScopeSingleAccount || setup.DeploymentMethod != AWSConnectorDeploymentCloudFormation {
		return AWSConnectorStartResponse{}, ErrInvalidAWSConnectionRequest
	}
	templateURL := strings.TrimSpace(s.AWSCloudFormationTemplateURL)
	accountID := strings.TrimSpace(s.AWSAccountID)
	if templateURL == "" || accountID == "" {
		return AWSConnectorStartResponse{}, ErrAWSConnectorConfigUnavailable
	}
	connectorID := strings.TrimSpace(request.ConnectorID)
	if connectorID == "" {
		connectorID = "aws-" + uuid.NewString()
	} else {
		stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
		if err == nil {
			return s.resumeAWSConnectorStart(ctx, stored, setup, request, templateURL, accountID)
		}
		if !errors.Is(err, db.ErrNotFound) {
			return AWSConnectorStartResponse{}, err
		}
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		displayName = "AWS account"
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
	roleName := firstNonEmptyAWSValue(strings.TrimSpace(request.RoleName), "IdentrailReadOnly")
	stackName := firstNonEmptyAWSValue(strings.TrimSpace(request.StackName), "identrail-readonly-connector")
	launchURL := awsconnector.BuildCloudFormationLaunchURL(awsconnector.CloudFormationLaunchInput{
		TemplateURL:        templateURL,
		Region:             region,
		StackName:          stackName,
		IdentrailAccountID: accountID,
		ExternalID:         externalID,
		RoleName:           roleName,
	})
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

	onboardingStatus := AWSConnectorOnboardingLaunchReady
	metadata := map[string]any{
		"external_id_configured": true,
		"region":                 region,
		"role_name":              roleName,
		"stack_name":             stackName,
		"template_url":           templateURL,
		"launch_url":             launchURL,
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
	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalID = externalID
	return awsConnectorStartResponse(status, externalID, launchURL, templateURL, roleName, stackName, policyHash), nil
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
	setup := awsMetadataSetupContract(stored.State.Metadata, AWSConnectorScopeSingleAccount, AWSConnectorDeploymentCloudFormation)
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
		secret, created, err := s.Store.CreateTenancyConnectorSecretEnvelopeIfAbsent(db.WithScope(ctx, db.Scope{TenantID: stored.Connector.TenantID, WorkspaceID: stored.Connector.WorkspaceID}), secret)
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
	launchURL := ""
	if !generatedExternalID {
		launchURL = awsMetadataString(stored.State.Metadata, "launch_url")
	}
	rebuiltLaunchMetadata := launchURL == "" || (externalID != "" && !strings.Contains(launchURL, externalID))
	if rebuiltLaunchMetadata {
		launchURL = awsconnector.BuildCloudFormationLaunchURL(awsconnector.CloudFormationLaunchInput{
			TemplateURL:        templateURL,
			Region:             region,
			StackName:          stackName,
			IdentrailAccountID: accountID,
			ExternalID:         externalID,
			RoleName:           roleName,
		})
	}
	if generatedExternalID || rebuiltLaunchMetadata {
		if rotatedAt.IsZero() {
			rotatedAt = s.Now().UTC()
		}
		stored = persistRecoveredAWSConnectorLaunchState(stored, externalID, region, roleName, stackName, templateURL, launchURL, policyHash, s.connectorSecretManager().ActiveKeyVersion(), rotatedAt)
		if err := s.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
			return AWSConnectorStartResponse{}, fmt.Errorf("persist recovered aws connector launch state: %w", err)
		}
	}

	status := s.awsConnectionStatusFromStored(ctx, stored)
	status.ExternalID = externalID
	status.ExternalIDConfigured = true
	status.Region = firstNonEmptyAWSValue(status.Region, region)
	status.LaunchURL = firstNonEmptyAWSValue(launchURL, status.LaunchURL)
	status.TemplateURL = firstNonEmptyAWSValue(status.TemplateURL, templateURL)
	status.PolicyHash = firstNonEmptyAWSValue(status.PolicyHash, policyHash)
	return awsConnectorStartResponse(status, externalID, launchURL, status.TemplateURL, roleName, stackName, policyHash), nil
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
	stored.Connector.SecretProvider = "secret-envelope"
	stored.Connector.SecretRefID = awsExternalIDSecretRef(stored.Connector.ConnectorID)
	stored.Connector.SecretRefVersion = secretRefVersion
	stored.Connector.SecretLastRotatedAt = &rotatedAt
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

func awsConnectorStartResponse(status AWSConnectionStatus, externalID string, launchURL string, templateURL string, roleName string, stackName string, policyHash string) AWSConnectorStartResponse {
	return AWSConnectorStartResponse{
		Connection:             status,
		ConnectorID:            status.ConnectorID,
		ExternalID:             externalID,
		LaunchURL:              launchURL,
		TemplateURL:            templateURL,
		RoleName:               roleName,
		StackName:              stackName,
		PolicyHash:             policyHash,
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
		PermissionPreview:      awsconnector.PermissionPreview(),
		PermissionTiers:        awsconnector.CapabilityPermissionTiers(),
	}
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
	return s.UpsertAWSConnection(ctx, project.WorkspaceID, project.ProjectID, AWSConnectionUpsertRequest{
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
	})
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
	return s.awsConnectionStatusFromStored(ctx, stored), nil
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

	checks := copyAWSPermissionChecks(validation.PermissionChecks)
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
	diagnostics := append(copyAWSDiagnostics(validation.Diagnostics), capabilityDiagnostics...)

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
		TenantID:    scope.TenantID,
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
		ConnectorID: normalized.ConnectorID,
		Type:        domain.ConnectorTypeAWS,
		DisplayName: normalized.DisplayName,
		Status:      status,
		UpdatedAt:   now,
	}
	if normalized.ExternalID != "" {
		connector.SecretProvider = "secret-envelope"
		connector.SecretRefID = awsExternalIDSecretRef(normalized.ConnectorID)
		connector.SecretRefVersion = s.connectorSecretManager().ActiveKeyVersion()
		connector.SecretLastRotatedAt = &now
	}
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("persist aws connector: %w", err)
	}
	if normalized.ExternalID != "" {
		if err := s.persistAWSExternalID(ctx, scope.TenantID, project.WorkspaceID, project.ProjectID, normalized.ConnectorID, normalized.ExternalID, now); err != nil {
			return AWSConnectionStatus{}, err
		}
	} else if err := s.clearAWSExternalID(ctx, scope.TenantID, project.WorkspaceID, project.ProjectID, normalized.ConnectorID); err != nil {
		return AWSConnectionStatus{}, err
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	if err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("load persisted aws connector: %w", err)
	}
	response := s.awsConnectionStatusFromStored(ctx, stored)

	return response, nil
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
	return s.awsConnectionStatusFromStored(ctx, items[0]), nil
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
	case AWSConnectorScopeSelectedOUs:
		if !awsConnectorDeploymentIsStackSet(deploymentMethod) || len(targetOUIDs) == 0 {
			return awsConnectorSetupContract{}, ErrInvalidAWSConnectionRequest
		}
	case AWSConnectorScopeSelectedAccounts:
		if !awsConnectorDeploymentIsStackSet(deploymentMethod) || len(targetAccountIDs) == 0 {
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
	if onboardingStatus == AWSConnectorOnboardingConnected {
		return "AWS connector is connected and ready for discovery."
	}
	if onboardingStatus == AWSConnectorOnboardingNeedsFix || onboardingStatus == AWSConnectorOnboardingFailed {
		return "AWS connector setup needs attention before Identrail can use it."
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
		return "Single AWS account read-only setup through CloudFormation."
	}
}

func awsConnectorNextActions(setup awsConnectorSetupContract, onboardingStatus AWSConnectorOnboardingStatus) []AWSConnectorNextAction {
	switch onboardingStatus {
	case AWSConnectorOnboardingConnected:
		return []AWSConnectorNextAction{AWSConnectorNextActionStartIntelligence, AWSConnectorNextActionRefreshStatus}
	case AWSConnectorOnboardingNeedsFix, AWSConnectorOnboardingFailed, AWSConnectorOnboardingPartial:
		return []AWSConnectorNextAction{AWSConnectorNextActionRepairPermissions, AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus}
	case AWSConnectorOnboardingWaitingForAWS:
		return []AWSConnectorNextAction{AWSConnectorNextActionRefreshStatus, AWSConnectorNextActionValidateRole}
	}
	if awsConnectorDeploymentIsStackSet(setup.DeploymentMethod) {
		return []AWSConnectorNextAction{AWSConnectorNextActionOpenStackSet, AWSConnectorNextActionRefreshStatus}
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
	if validatedAt == nil && !stored.State.ObservedAt.IsZero() {
		observed := stored.State.ObservedAt
		validatedAt = &observed
	}
	defaultScope, defaultDeployment := awsMetadataSetupFallback(metadata)
	setup := awsMetadataSetupContract(metadata, defaultScope, defaultDeployment)
	onboardingStatus := awsMetadataOnboardingStatus(metadata, "onboarding_status")
	if onboardingStatus == "" {
		onboardingStatus = awsConnectorOnboardingStatusFromHealth(stored.Connector.Status, stored.State.HealthStatus, awsMetadataString(metadata, "launch_url"))
	}
	status := AWSConnectionStatus{
		Provider:               "aws",
		Connected:              stored.Connector.Status == domain.ConnectorStatusActive && stored.State.HealthStatus == "healthy",
		ConnectorID:            stored.Connector.ConnectorID,
		DisplayName:            stored.Connector.DisplayName,
		Status:                 stored.Connector.Status,
		HealthStatus:           firstNonEmptyAWSValue(stored.State.HealthStatus, "unknown"),
		RoleARN:                awsMetadataString(metadata, "role_arn"),
		ExternalID:             awsMetadataString(metadata, "external_id"),
		ExternalIDConfigured:   awsMetadataBool(metadata, "external_id_configured"),
		AccountID:              awsMetadataString(metadata, "account_id"),
		PrincipalARN:           awsMetadataString(metadata, "principal_arn"),
		UserID:                 awsMetadataString(metadata, "user_id"),
		Region:                 awsMetadataString(metadata, "region"),
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
		CreatedAt:              &createdAt,
		UpdatedAt:              &updatedAt,
		LastValidatedAt:        validatedAt,
	}
	status.RemediationMessage = firstAWSRemediation(status.Diagnostics, status.PermissionChecks)
	return status
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

func (s *Service) persistAWSExternalID(ctx context.Context, tenantID string, workspaceID string, projectID string, connectorID string, externalID string, rotatedAt time.Time) error {
	if strings.TrimSpace(externalID) == "" {
		return nil
	}
	secret, err := s.newAWSExternalIDSecretEnvelope(tenantID, workspaceID, projectID, connectorID, externalID, rotatedAt)
	if err != nil {
		return err
	}
	if err := s.Store.UpsertTenancyConnectorSecretEnvelope(db.WithScope(ctx, db.Scope{TenantID: tenantID, WorkspaceID: workspaceID}), secret); err != nil {
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

func (s *Service) clearAWSExternalID(ctx context.Context, tenantID string, workspaceID string, projectID string, connectorID string) error {
	err := s.Store.DeleteTenancyConnectorSecretEnvelope(
		db.WithScope(ctx, db.Scope{TenantID: tenantID, WorkspaceID: workspaceID}),
		workspaceID,
		projectID,
		connectorID,
		awsExternalIDSecretName,
	)
	if errors.Is(err, db.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("clear aws connector external id envelope: %w", err)
	}
	return nil
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
		case AWSConnectorNextActionLaunchStack, AWSConnectorNextActionOpenStackSet, AWSConnectorNextActionValidateRole, AWSConnectorNextActionRefreshStatus, AWSConnectorNextActionRepairPermissions, AWSConnectorNextActionStartIntelligence:
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
			Code:        fmt.Sprintf("aws_capability_unavailable_%s", unavailable.Capability),
			Message:     fmt.Sprintf("requested capability %q is unavailable: %s", unavailable.Capability, unavailable.Reason),
			Remediation: fmt.Sprintf("Enable the %q capability gate for this deployment before requesting it; write-capable tiers also require a dedicated write role.", unavailable.Capability),
		})
	}
	return capabilities, diagnostics, nil
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
