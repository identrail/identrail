package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	awsconnector "github.com/identrail/identrail/internal/connectors/aws"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

const (
	awsOrganizationRolloutSecretPurpose = "aws-organization-rollout-secret-v1"
	awsOrganizationRolloutLifetime      = 24 * time.Hour
	awsOrganizationRolloutRoleName      = "IdentrailReadOnly"
)

// ErrAWSOrganizationRolloutControllingUnready reports that the controlling
// (management or delegated-admin) account has not been validated. The caller
// must connect and validate that connector before an organization-scale
// rollout can be approved.
var ErrAWSOrganizationRolloutControllingUnready = errors.New("aws controlling account is not validated")

// ErrAWSOrganizationRolloutOUMembershipUnsupported protects test and embedded
// service configurations that do not install a live Organizations inventory
// provider. Production expands OU membership from AWS before persisting a
// rollout, so its expected target set is complete from the first response.
var ErrAWSOrganizationRolloutOUMembershipUnsupported = errors.New("aws rollout ou membership resolver unavailable")

// ErrAWSOrganizationRolloutMixedPartition reports that the requested
// TargetRegions span more than one AWS partition. Every rollout is bound to a
// single partition so member-account stack ARNs, role ARNs, and permission
// checks stay consistent; a rollout that mixes commercial and GovCloud (or
// China) regions would be authenticated against the wrong partition on
// half of its members.
var ErrAWSOrganizationRolloutMixedPartition = errors.New("aws rollout target regions span multiple partitions")

var (
	awsOrganizationRolloutAccountIDPattern      = regexp.MustCompile(`^[0-9]{12}$`)
	awsOrganizationRolloutOrganizationIDPattern = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
)

var ErrAWSOrganizationRolloutMultiRegionUnsupported = errors.New("aws organization rollout multi-region routing is unavailable")

// ErrAWSOrganizationRolloutControllingLifecycleChanged indicates that the
// connector lifecycle decision that approved the rollout is no longer the
// current decision. This is the only controlling-connector failure that
// terminalizes an active rollout; ordinary health loss remains retryable.
var ErrAWSOrganizationRolloutControllingLifecycleChanged = errors.New("aws controlling connector lifecycle changed")

func (s *Service) ensureAWSOrganizationRolloutControllingConnector(ctx context.Context, rollout db.AWSOrganizationRollout) error {
	stored, err := s.Store.GetTenancyConnector(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.ControllingConnectorID)
	if err != nil {
		return err
	}
	if stored.Connector.Type != domain.ConnectorTypeAWS {
		return ErrAWSOrganizationRolloutControllingUnready
	}
	if stored.Connector.LifecycleGeneration != rollout.ControllingConnectorLifecycleGeneration ||
		stored.Connector.Disabled || stored.Connector.Status == domain.ConnectorStatusDisconnected {
		return ErrAWSOrganizationRolloutControllingLifecycleChanged
	}
	if !s.awsConnectionStatusFromStored(ctx, stored).Connected {
		return ErrAWSOrganizationRolloutControllingUnready
	}
	return nil
}

func (s *Service) cancelAWSOrganizationRolloutForLifecycle(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout) {
	if !awsOrganizationRolloutActiveStatus(rollout.Status) && rollout.Status != db.AWSOrganizationRolloutStatusPartial && rollout.Status != db.AWSOrganizationRolloutStatusFailed {
		return
	}
	rollout.Status = db.AWSOrganizationRolloutStatusCanceled
	rollout.FailureCode = "controlling_connector_lifecycle_changed"
	rollout.FailureMessage = "The controlling AWS connector was paused or disconnected."
	rollout.UpdatedAt = s.Now().UTC()
	_, _ = store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version)
}

func awsOrganizationRolloutActiveStatus(status string) bool {
	switch status {
	case db.AWSOrganizationRolloutStatusCreated,
		db.AWSOrganizationRolloutStatusLaunching,
		db.AWSOrganizationRolloutStatusInProgress,
		db.AWSOrganizationRolloutStatusReconciling:
		return true
	default:
		return false
	}
}

// AWSOrganizationRolloutStartRequest is the operator-approved request to open
// a scoped organization rollout envelope from a validated controlling
// connector. Every field is bound into the persisted envelope so a member
// registration event that does not match this exact scope is rejected.
type AWSOrganizationRolloutStartRequest struct {
	WorkspaceID            string   `json:"workspace_id,omitempty"`
	ProjectID              string   `json:"project_id"`
	ControllingConnectorID string   `json:"controlling_connector_id"`
	ControllingRole        string   `json:"controlling_role,omitempty"`
	OrganizationID         string   `json:"organization_id"`
	ManagementAccountID    string   `json:"management_account_id"`
	DeploymentMode         string   `json:"deployment_mode,omitempty"`
	StackSetName           string   `json:"stack_set_name,omitempty"`
	SelectedOUIDs          []string `json:"selected_ou_ids"`
	SelectedAccountIDs     []string `json:"selected_account_ids"`
	ExcludedAccountIDs     []string `json:"excluded_account_ids"`
	TargetRegions          []string `json:"target_regions"`
	AutoDeployNewAccounts  bool     `json:"auto_deploy_new_accounts"`
}

// AWSOrganizationRolloutTargetView is the operator-visible per-target state.
// It is derived from persisted target rows plus the intended expected-set so
// deploying/pending/excluded are distinguishable in the UI.
type AWSOrganizationRolloutTargetView struct {
	AccountID        string     `json:"account_id"`
	Region           string     `json:"region"`
	AccountName      string     `json:"account_name,omitempty"`
	OUPath           string     `json:"ou_path,omitempty"`
	IsManagement     bool       `json:"is_management"`
	State            string     `json:"state"`
	StackInstanceID  string     `json:"stack_instance_id,omitempty"`
	StackID          string     `json:"stack_id,omitempty"`
	RoleARN          string     `json:"role_arn,omitempty"`
	FailureCode      string     `json:"failure_code,omitempty"`
	FailureMessage   string     `json:"failure_message,omitempty"`
	Retryable        bool       `json:"retryable"`
	EvidenceRef      string     `json:"evidence_ref,omitempty"`
	LastTransitionAt time.Time  `json:"last_transition_at"`
	LastValidationAt *time.Time `json:"last_validation_at,omitempty"`
}

// AWSOrganizationRolloutSummary aggregates target states into the honest
// counts the app surfaces. The whole rollout is derived from these totals; a
// single StackSet launch API success never implies coverage.
type AWSOrganizationRolloutSummary struct {
	ExpectedTargets    int            `json:"expected_targets"`
	PendingTargets     int            `json:"pending_targets"`
	DeployingTargets   int            `json:"deploying_targets"`
	RegisteringTargets int            `json:"registering_targets"`
	ValidatingTargets  int            `json:"validating_targets"`
	ConnectedTargets   int            `json:"connected_targets"`
	PartialTargets     int            `json:"partial_targets"`
	FailedTargets      int            `json:"failed_targets"`
	ExcludedTargets    int            `json:"excluded_targets"`
	SuspendedTargets   int            `json:"suspended_targets"`
	RemovedTargets     int            `json:"removed_targets"`
	StateCounts        map[string]int `json:"state_counts"`
	ConnectedPercent   float64        `json:"connected_percent"`
}

// AWSOrganizationRolloutStatus is the full read model returned to the app.
type AWSOrganizationRolloutStatus struct {
	RolloutID              string                             `json:"rollout_id"`
	TenantID               string                             `json:"tenant_id"`
	WorkspaceID            string                             `json:"workspace_id"`
	ProjectID              string                             `json:"project_id"`
	ControllingConnectorID string                             `json:"controlling_connector_id"`
	ControllingRole        string                             `json:"controlling_role"`
	OrganizationID         string                             `json:"organization_id"`
	ManagementAccountID    string                             `json:"management_account_id"`
	Partition              string                             `json:"partition"`
	DeploymentMode         string                             `json:"deployment_mode"`
	StackSetName           string                             `json:"stack_set_name"`
	ExpectedRoleName       string                             `json:"expected_role_name"`
	TemplateVersion        string                             `json:"template_version"`
	TemplateChecksum       string                             `json:"template_checksum"`
	SelectedOUIDs          []string                           `json:"selected_ou_ids"`
	SelectedAccountIDs     []string                           `json:"selected_account_ids"`
	ExcludedAccountIDs     []string                           `json:"excluded_account_ids"`
	TargetRegions          []string                           `json:"target_regions"`
	AutoDeployNewAccounts  bool                               `json:"auto_deploy_new_accounts"`
	Status                 string                             `json:"status"`
	FailureCode            string                             `json:"failure_code,omitempty"`
	FailureMessage         string                             `json:"failure_message,omitempty"`
	LaunchURL              string                             `json:"launch_url,omitempty"`
	ExpiresAt              time.Time                          `json:"expires_at"`
	CreatedAt              time.Time                          `json:"created_at"`
	UpdatedAt              time.Time                          `json:"updated_at"`
	Summary                AWSOrganizationRolloutSummary      `json:"summary"`
	Targets                []AWSOrganizationRolloutTargetView `json:"targets"`
}

func (s *Service) awsOrganizationRolloutStore() (db.AWSOrganizationRolloutStore, error) {
	store, ok := s.Store.(db.AWSOrganizationRolloutStore)
	if !ok || store == nil {
		return nil, ErrAWSConnectorConfigUnavailable
	}
	return store, nil
}

// StartAWSOrganizationRollout opens a rollout envelope from a validated
// controlling connector. The controlling connector must be Connected and
// belong to the requested scope; a rollout cannot be launched from a pending
// or unvalidated management/delegated-admin account. The returned status
// carries the seeded per-target rows so the UI can render the exact expected
// set before AWS reports any StackSet result.
func (s *Service) StartAWSOrganizationRollout(ctx context.Context, request AWSOrganizationRolloutStartRequest) (AWSOrganizationRolloutStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	controllingConnectorID := strings.TrimSpace(request.ControllingConnectorID)
	if controllingConnectorID == "" {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	organizationID := strings.TrimSpace(request.OrganizationID)
	managementAccountID := strings.TrimSpace(request.ManagementAccountID)
	if !awsOrganizationRolloutOrganizationIDPattern.MatchString(organizationID) || !awsOrganizationRolloutAccountIDPattern.MatchString(managementAccountID) {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	regions := trimAndLowerAWSStringSlice(request.TargetRegions)
	if len(regions) == 0 {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	for _, region := range regions {
		if awsconnector.NormalizeRegion(region) != region {
			return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
		}
	}
	partition, err := awsOrganizationRolloutPartitionForRegions(regions)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	if len(regions) > 1 {
		return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutMultiRegionUnsupported
	}

	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, controllingConnectorID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	if stored.Connector.Type != domain.ConnectorTypeAWS {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	connectorScope := AWSConnectorScopeType(awsMetadataString(stored.State.Metadata, "scope_type"))
	connectorDeployment := AWSConnectorDeploymentMethod(awsMetadataString(stored.State.Metadata, "deployment_method"))
	if connectorScope != AWSConnectorScopeOrganization ||
		(connectorDeployment != AWSConnectorDeploymentStackSetServiceManaged && connectorDeployment != AWSConnectorDeploymentStackSetSelfManaged) {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	connection := s.awsConnectionStatusFromStored(ctx, stored)
	if !connection.Connected {
		return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutControllingUnready
	}
	controllingRole := strings.TrimSpace(strings.ToLower(request.ControllingRole))
	if controllingRole == "" {
		controllingRole = db.AWSOrganizationRolloutControllingManagement
	}
	if controllingRole != db.AWSOrganizationRolloutControllingManagement &&
		controllingRole != db.AWSOrganizationRolloutControllingDelegatedAdmin {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	if controllingRole == db.AWSOrganizationRolloutControllingManagement && strings.TrimSpace(connection.AccountID) != managementAccountID {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	deploymentMode := strings.TrimSpace(strings.ToLower(request.DeploymentMode))
	if deploymentMode == "" {
		deploymentMode = db.AWSOrganizationRolloutDeploymentServiceManaged
	}
	if deploymentMode != db.AWSOrganizationRolloutDeploymentServiceManaged &&
		deploymentMode != db.AWSOrganizationRolloutDeploymentSelfManaged {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}

	stackSetName := strings.TrimSpace(request.StackSetName)
	if stackSetName == "" {
		stackSetName = "identrail-readonly-connector-stackset"
	}

	selectedOUs := trimAndDedupeAWSStringSlice(request.SelectedOUIDs)
	selectedAccounts := trimAndDedupeAWSStringSlice(request.SelectedAccountIDs)
	excludedAccounts := trimAndDedupeAWSStringSlice(request.ExcludedAccountIDs)
	var inventorySnapshot *AWSOrganizationInventorySnapshot
	if s.AWSOrganizationInventoryFactory != nil {
		inventory, inventoryErr := s.AWSOrganizationInventoryFactory(ctx, connection)
		if inventoryErr != nil {
			return AWSOrganizationRolloutStatus{}, fmt.Errorf("create aws organization inventory: %w", inventoryErr)
		}
		snapshot, inventoryErr := inventory.Discover(ctx, AWSOrganizationInventoryRequest{StackSetName: stackSetName, ControllingRole: controllingRole})
		if inventoryErr != nil {
			return AWSOrganizationRolloutStatus{}, fmt.Errorf("discover aws organization inventory: %w", inventoryErr)
		}
		if snapshot.OrganizationID != organizationID || snapshot.ManagementAccountID != managementAccountID || snapshot.Partition != partition {
			return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
		}
		knownOUs := map[string]struct{}{}
		for _, unit := range append(append([]AWSOrganizationInventoryOU(nil), snapshot.Roots...), snapshot.OrganizationalUnits...) {
			knownOUs[unit.ID] = struct{}{}
		}
		for _, ouID := range selectedOUs {
			if _, ok := knownOUs[ouID]; !ok {
				return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
			}
		}
		accountsByID := awsOrganizationInventoryAccountMap(snapshot)
		selectedAccounts = awsOrganizationInventorySelectedAccounts(snapshot, selectedOUs, selectedAccounts)
		for _, accountID := range append(append([]string(nil), selectedAccounts...), excludedAccounts...) {
			if _, ok := accountsByID[accountID]; !ok {
				return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
			}
		}
		if controllingRole == db.AWSOrganizationRolloutControllingDelegatedAdmin {
			controlling, ok := accountsByID[strings.TrimSpace(connection.AccountID)]
			if !ok || !awsOrganizationInventoryHasCloudFormationDelegation(controlling) {
				return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutControllingUnready
			}
		}
		inventorySnapshot = &snapshot
	} else if len(selectedOUs) > 0 && len(selectedAccounts) == 0 {
		return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutOUMembershipUnsupported
	}
	if err := awsOrganizationRolloutValidateAccountIDs(selectedAccounts); err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	if err := awsOrganizationRolloutValidateAccountIDs(excludedAccounts); err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	if len(selectedAccounts) == 0 {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}
	deployable := 0
	excluded := make(map[string]struct{}, len(excludedAccounts))
	for _, accountID := range excludedAccounts {
		excluded[accountID] = struct{}{}
	}
	for _, accountID := range selectedAccounts {
		if _, ok := excluded[accountID]; !ok {
			deployable++
		}
	}
	if deployable == 0 {
		return AWSOrganizationRolloutStatus{}, ErrInvalidAWSConnectionRequest
	}

	// Reject before creating the envelope when the launch configuration is
	// missing. Without a pinned template, checksum, Identrail account, or a
	// regional registration provider for the home region, the resulting
	// launch URL would be unusable and the envelope would silently hold the
	// one-active-per-controlling-connector lock.
	templateURL := strings.TrimSpace(s.AWSCloudFormationTemplateURL)
	templateChecksum := strings.TrimSpace(s.AWSCloudFormationTemplateSHA)
	identrailAccountID := strings.TrimSpace(s.AWSAccountID)
	homeRegion := regions[0]
	providerARN := s.awsRegistrationTopicARN(homeRegion)
	if templateURL == "" || templateChecksum == "" || identrailAccountID == "" || providerARN == "" {
		return AWSOrganizationRolloutStatus{}, ErrAWSConnectorConfigUnavailable
	}

	store, err := s.awsOrganizationRolloutStore()
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	now := s.Now().UTC()
	// Sweep any existing envelope whose 24h window has elapsed but was never
	// terminalized so its uniqueness lock does not block the replacement.
	s.expireStaleAWSOrganizationRollout(ctx, store, project.WorkspaceID, project.ProjectID, controllingConnectorID, now)
	rolloutID := uuid.NewString()
	rollout := db.AWSOrganizationRollout{
		RolloutID:                               rolloutID,
		TenantID:                                scope.TenantID,
		WorkspaceID:                             project.WorkspaceID,
		ProjectID:                               project.ProjectID,
		ControllingConnectorID:                  controllingConnectorID,
		ControllingConnectorLifecycleGeneration: stored.Connector.LifecycleGeneration,
		ControllingRole:                         controllingRole,
		OrganizationID:                          organizationID,
		ManagementAccountID:                     managementAccountID,
		Partition:                               partition,
		DeploymentMode:                          deploymentMode,
		StackSetName:                            stackSetName,
		ExpectedRoleName:                        awsOrganizationRolloutRoleName,
		TemplateVersion:                         awsConnectorTemplateVersion,
		TemplateChecksum:                        normalizeAWSConnectorTemplateChecksum(templateChecksum),
		RegistrationSecretKeyVersion:            s.connectorSecretManager().ActiveKeyVersion(),
		SelectedOUIDs:                           selectedOUs,
		SelectedAccountIDs:                      selectedAccounts,
		ExcludedAccountIDs:                      excludedAccounts,
		TargetRegions:                           regions,
		AutoDeployNewAccounts:                   request.AutoDeployNewAccounts,
		Status:                                  db.AWSOrganizationRolloutStatusCreated,
		ExpiresAt:                               now.Add(awsOrganizationRolloutLifetime),
		CreatedAt:                               now,
		UpdatedAt:                               now,
		Version:                                 1,
	}
	secret, err := s.awsOrganizationRolloutSecret(rollout)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	hash := sha256.Sum256([]byte(secret))
	rollout.RegistrationSecretHash = append([]byte(nil), hash[:]...)

	created, err := store.CreateAWSOrganizationRollout(ctx, rollout)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, fmt.Errorf("create aws organization rollout: %w", err)
	}

	expected := expectedAWSOrganizationRolloutTargets(created, managementAccountID)
	accountsByID := map[string]AWSOrganizationInventoryAccount{}
	if inventorySnapshot != nil {
		accountsByID = awsOrganizationInventoryAccountMap(*inventorySnapshot)
	}
	for _, seed := range expected {
		if account, ok := accountsByID[seed.AccountID]; ok {
			seed.AccountName = account.Name
			seed.OUPath = account.OUPath
			if seed.State != db.AWSOrganizationRolloutTargetExcluded && awsOrganizationInventoryAccountInactive(account.Status) {
				seed.State = db.AWSOrganizationRolloutTargetSuspended
				seed.FailureCode = "organization_account_inactive"
				seed.FailureMessage = "AWS Organizations reports this account as inactive."
				seed.Retryable = false
			}
		}
		if _, upsertErr := store.UpsertAWSOrganizationRolloutTarget(ctx, seed); upsertErr != nil {
			// A seed failure must not leave a live envelope holding the
			// one-active-per-controlling-connector lock: the operator would
			// then be blocked from opening a fresh rollout for the full
			// envelope lifetime (24h) even though nothing was actually
			// launched. Terminalize the envelope so a retry is possible.
			s.markAWSOrganizationRolloutFailed(ctx, store, created, "rollout_seed_failed", "Identrail could not persist the expected target set. Start a new rollout to retry.")
			return AWSOrganizationRolloutStatus{}, fmt.Errorf("seed rollout target %s/%s: %w", seed.AccountID, seed.Region, upsertErr)
		}
	}

	return s.buildAWSOrganizationRolloutStatus(ctx, store, created, true)
}

// markAWSOrganizationRolloutFailed best-effort terminalizes an envelope after
// a mid-create failure so the one-active-per-controlling-connector uniqueness
// lock does not permanently block retries. On optimistic-conflict or
// persistence failure it is a no-op: subsequent status reads will still
// reflect the mid-flight state, and the 24h expiry eventually reclaims the
// lock.
func (s *Service) markAWSOrganizationRolloutFailed(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout, code string, message string) {
	rollout.Status = db.AWSOrganizationRolloutStatusFailed
	rollout.FailureCode = code
	rollout.FailureMessage = message
	rollout.UpdatedAt = s.Now().UTC()
	_, _ = store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version)
}

// expireStaleAWSOrganizationRollout terminalizes an active envelope whose
// 24-hour window has elapsed. Without this, an unlaunched rollout would hold
// the one-active-per-controlling-connector uniqueness lock indefinitely and
// block the operator from opening a fresh envelope. Best-effort: any failure
// leaves the sweep to the next call.
func (s *Service) expireStaleAWSOrganizationRollout(ctx context.Context, store db.AWSOrganizationRolloutStore, workspaceID string, projectID string, connectorID string, now time.Time) {
	rollouts, err := store.ListAWSOrganizationRollouts(ctx, workspaceID, projectID, connectorID, 25)
	if err != nil {
		return
	}
	for _, rollout := range rollouts {
		switch rollout.Status {
		case db.AWSOrganizationRolloutStatusCreated,
			db.AWSOrganizationRolloutStatusLaunching,
			db.AWSOrganizationRolloutStatusInProgress,
			db.AWSOrganizationRolloutStatusReconciling:
		default:
			continue
		}
		if now.Before(rollout.ExpiresAt) {
			continue
		}
		rollout.Status = db.AWSOrganizationRolloutStatusExpired
		if rollout.FailureCode == "" {
			rollout.FailureCode = "rollout_envelope_expired"
			rollout.FailureMessage = "The rollout envelope elapsed its 24-hour window before completion. Start a new rollout."
		}
		rollout.UpdatedAt = now
		_, _ = store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version)
	}
}

// GetAWSOrganizationRolloutStatus returns the current rollout + per-target
// state. It never claims coverage from a StackSet operation result alone; the
// counts come from persisted per-target rows updated by authenticated
// registration events and future reconciliation runs.
//
// Read responses always redact the rollout registration secret from the
// launch URL. The secret is a bearer credential that authenticates every
// member-account registration event: returning it under tenancy.read scope
// would let any read-scoped viewer replay a member registration for any
// approved target. Only the initial StartAWSOrganizationRollout response
// (tenancy.write) carries the full launch URL.
func (s *Service) GetAWSOrganizationRolloutStatus(ctx context.Context, workspaceID string, projectID string, rolloutID string) (AWSOrganizationRolloutStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	store, err := s.awsOrganizationRolloutStore()
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	rollout, err := store.GetAWSOrganizationRollout(ctx, project.WorkspaceID, project.ProjectID, rolloutID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	return s.buildAWSOrganizationRolloutStatus(ctx, store, rollout, false)
}

func (s *Service) buildAWSOrganizationRolloutStatus(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout, includeSecret bool) (AWSOrganizationRolloutStatus, error) {
	targets, err := store.ListAWSOrganizationRolloutTargets(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.RolloutID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	views := make([]AWSOrganizationRolloutTargetView, 0, len(targets))
	summary := AWSOrganizationRolloutSummary{StateCounts: map[string]int{}}
	for _, target := range targets {
		views = append(views, AWSOrganizationRolloutTargetView{
			AccountID:        target.AccountID,
			Region:           target.Region,
			AccountName:      target.AccountName,
			OUPath:           target.OUPath,
			IsManagement:     target.IsManagement,
			State:            target.State,
			StackInstanceID:  target.StackInstanceID,
			StackID:          target.StackID,
			RoleARN:          target.RoleARN,
			FailureCode:      target.FailureCode,
			FailureMessage:   target.FailureMessage,
			Retryable:        target.Retryable,
			EvidenceRef:      target.EvidenceRef,
			LastTransitionAt: target.LastTransitionAt,
			LastValidationAt: target.LastValidationAt,
		})
		summary.StateCounts[target.State]++
	}
	summary.ExpectedTargets = len(targets)
	summary.PendingTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetPending]
	summary.DeployingTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetDeploying]
	summary.RegisteringTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetRegistering]
	summary.ValidatingTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetValidating]
	summary.ConnectedTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetConnected]
	summary.PartialTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetPartial]
	summary.FailedTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetFailed]
	summary.ExcludedTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetExcluded]
	summary.SuspendedTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetSuspended]
	summary.RemovedTargets = summary.StateCounts[db.AWSOrganizationRolloutTargetRemoved]
	if summary.ExpectedTargets > 0 {
		summary.ConnectedPercent = float64(summary.ConnectedTargets) / float64(summary.ExpectedTargets)
	}
	launchURL := ""
	// The launch URL must carry the rollout registration parameters so every
	// member-account stack instance can authenticate its callback into this
	// exact envelope. Read responses (includeSecret=false) omit the raw
	// registration secret and the RolloutId so the URL is safe to expose
	// under tenancy.read but is not usable to launch; only the operator
	// who received the initial start response holds a launchable URL.
	rolloutSecret := ""
	if includeSecret {
		if derived, secretErr := s.awsOrganizationRolloutSecret(rollout); secretErr == nil {
			rolloutSecret = derived
		}
	}
	autoDeployment := rollout.AutoDeployNewAccounts
	launchURL = awsconnector.BuildCloudFormationStackSetLaunchURL(awsconnector.CloudFormationStackSetLaunchInput{
		TemplateURL:                 strings.TrimSpace(s.AWSCloudFormationTemplateURL),
		Region:                      firstNonEmptyAWSValue(regionOrEmpty(rollout.TargetRegions)),
		StackSetName:                rollout.StackSetName,
		IdentrailAccountID:          strings.TrimSpace(s.AWSAccountID),
		ExternalID:                  "",
		RoleName:                    rollout.ExpectedRoleName,
		PermissionModel:             awsOrganizationRolloutPermissionModel(rollout.DeploymentMode),
		OrganizationalUnitIDs:       rollout.SelectedOUIDs,
		TargetAccountIDs:            rollout.SelectedAccountIDs,
		ExcludedAccountIDs:          rollout.ExcludedAccountIDs,
		TargetRegions:               rollout.TargetRegions,
		AutoDeploymentEnabled:       &autoDeployment,
		RegistrationProviderARN:     s.awsRegistrationTopicARN(firstNonEmptyAWSValue(regionOrEmpty(rollout.TargetRegions))),
		RolloutID:                   condString(includeSecret, rollout.RolloutID),
		RolloutRegistrationSecret:   rolloutSecret,
		RolloutOrganizationID:       rollout.OrganizationID,
		RolloutManagementAccountID:  rollout.ManagementAccountID,
		RolloutStackSetNameOverride: rollout.StackSetName,
	})
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].IsManagement != views[j].IsManagement {
			return views[i].IsManagement
		}
		if views[i].AccountID == views[j].AccountID {
			return views[i].Region < views[j].Region
		}
		return views[i].AccountID < views[j].AccountID
	})
	return AWSOrganizationRolloutStatus{
		RolloutID:              rollout.RolloutID,
		TenantID:               rollout.TenantID,
		WorkspaceID:            rollout.WorkspaceID,
		ProjectID:              rollout.ProjectID,
		ControllingConnectorID: rollout.ControllingConnectorID,
		ControllingRole:        rollout.ControllingRole,
		OrganizationID:         rollout.OrganizationID,
		ManagementAccountID:    rollout.ManagementAccountID,
		Partition:              rollout.Partition,
		DeploymentMode:         rollout.DeploymentMode,
		StackSetName:           rollout.StackSetName,
		ExpectedRoleName:       rollout.ExpectedRoleName,
		TemplateVersion:        rollout.TemplateVersion,
		TemplateChecksum:       rollout.TemplateChecksum,
		SelectedOUIDs:          rollout.SelectedOUIDs,
		SelectedAccountIDs:     rollout.SelectedAccountIDs,
		ExcludedAccountIDs:     rollout.ExcludedAccountIDs,
		TargetRegions:          rollout.TargetRegions,
		AutoDeployNewAccounts:  rollout.AutoDeployNewAccounts,
		Status:                 rollout.Status,
		FailureCode:            rollout.FailureCode,
		FailureMessage:         rollout.FailureMessage,
		LaunchURL:              launchURL,
		ExpiresAt:              rollout.ExpiresAt,
		CreatedAt:              rollout.CreatedAt,
		UpdatedAt:              rollout.UpdatedAt,
		Summary:                summary,
		Targets:                views,
	}, nil
}

func (s *Service) awsOrganizationRolloutSecret(rollout db.AWSOrganizationRollout) (string, error) {
	identity := strings.Join([]string{
		strings.TrimSpace(rollout.RolloutID),
		strings.TrimSpace(rollout.TenantID),
		strings.TrimSpace(rollout.WorkspaceID),
		strings.TrimSpace(rollout.ProjectID),
		strings.TrimSpace(rollout.ControllingConnectorID),
		strings.TrimSpace(rollout.OrganizationID),
		strings.TrimSpace(rollout.StackSetName),
	}, "\x00")
	digest, err := s.connectorSecretManager().DeriveDigest(rollout.RegistrationSecretKeyVersion, awsOrganizationRolloutSecretPurpose, []byte(identity))
	if err != nil {
		return "", fmt.Errorf("derive rollout secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(digest), nil
}

// AWSOrganizationRolloutSecretForRollout returns the raw one-time secret so it
// can be embedded in the CloudFormation StackSet parameters. It is intended
// for the launch/render path only and must never be persisted; callers must
// treat the returned string as sensitive.
func (s *Service) AWSOrganizationRolloutSecretForRollout(rollout db.AWSOrganizationRollout) (string, error) {
	return s.awsOrganizationRolloutSecret(rollout)
}

func expectedAWSOrganizationRolloutTargets(rollout db.AWSOrganizationRollout, managementAccountID string) []db.AWSOrganizationRolloutTarget {
	accountIDs := make([]string, 0, len(rollout.SelectedAccountIDs)+1)
	seen := map[string]struct{}{}
	// The management/delegated-admin account is always tracked as its own
	// target even when the StackSet does not create a stack instance in it.
	// It is marked management so the UI can display it distinctly and so
	// reconciliation code can special-case its state derivation.
	if managementAccountID != "" {
		accountIDs = append(accountIDs, managementAccountID)
		seen[managementAccountID] = struct{}{}
	}
	excluded := map[string]struct{}{}
	for _, id := range rollout.ExcludedAccountIDs {
		excluded[id] = struct{}{}
	}
	for _, id := range rollout.SelectedAccountIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		accountIDs = append(accountIDs, id)
	}
	targets := make([]db.AWSOrganizationRolloutTarget, 0, len(accountIDs)*len(rollout.TargetRegions))
	for _, accountID := range accountIDs {
		state := db.AWSOrganizationRolloutTargetPending
		if _, ok := excluded[accountID]; ok {
			state = db.AWSOrganizationRolloutTargetExcluded
		}
		for _, region := range rollout.TargetRegions {
			targets = append(targets, db.AWSOrganizationRolloutTarget{
				RolloutID:    rollout.RolloutID,
				AccountID:    accountID,
				Region:       region,
				TenantID:     rollout.TenantID,
				WorkspaceID:  rollout.WorkspaceID,
				ProjectID:    rollout.ProjectID,
				IsManagement: accountID == managementAccountID,
				State:        state,
			})
		}
	}
	return targets
}

func awsOrganizationRolloutPermissionModel(mode string) awsconnector.StackSetLaunchPermissionModel {
	if mode == db.AWSOrganizationRolloutDeploymentSelfManaged {
		return awsconnector.StackSetLaunchPermissionModelSelfManaged
	}
	return awsconnector.StackSetLaunchPermissionModelServiceManaged
}

func regionOrEmpty(regions []string) string {
	if len(regions) == 0 {
		return ""
	}
	return regions[0]
}

// condString returns value when include is true, empty otherwise. Used to
// strip fields from the launch URL under a redacted (read) response so a
// tenancy.read viewer cannot both recover the rollout ID and the secret from
// the same URL.
func condString(include bool, value string) string {
	if include {
		return value
	}
	return ""
}

// awsOrganizationRolloutPartitionForRegions returns the AWS partition shared
// by every requested region, or an error if the request mixes partitions.
// Every rollout is bound to a single partition; a mixed request would emit a
// launch URL and a StackSet template that cannot both be valid in commercial
// and GovCloud (or China) simultaneously, and every affected member would
// fail registration.
func awsOrganizationRolloutPartitionForRegions(regions []string) (string, error) {
	if len(regions) == 0 {
		return "", ErrInvalidAWSConnectionRequest
	}
	first := awsStackSetPartition(regions[0])
	for _, region := range regions[1:] {
		if awsStackSetPartition(region) != first {
			return "", ErrAWSOrganizationRolloutMixedPartition
		}
	}
	return first, nil
}

// awsOrganizationRolloutValidateAccountIDs rejects an account list containing
// anything that is not a syntactically valid 12-digit AWS account ID. This
// mirrors the CHECK constraint on the target table so bad input is refused at
// request normalization rather than at seed time (which would waste an
// envelope) or at StackSet launch time (where the operator has already
// authorized a bogus target set).
func awsOrganizationRolloutValidateAccountIDs(ids []string) error {
	for _, id := range ids {
		if !awsOrganizationRolloutAccountIDPattern.MatchString(id) {
			return ErrInvalidAWSConnectionRequest
		}
	}
	return nil
}

func trimAndDedupeAWSStringSlice(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func trimAndLowerAWSStringSlice(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.ToLower(strings.TrimSpace(v))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
