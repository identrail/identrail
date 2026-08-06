package api

import (
	"context"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const awsOrganizationsTopologyCurrentIssue = 1498

// AWSOrganizationsTopologyRequest filters the Organizations topology result.
type AWSOrganizationsTopologyRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	Account      string `json:"account,omitempty"`
	OU           string `json:"ou,omitempty"`
	State        string `json:"state,omitempty"`
	Status       string `json:"status,omitempty"`
}

// AWSOrganizationsTopologyAccount is one operator-visible Organizations account.
type AWSOrganizationsTopologyAccount struct {
	AccountID                string    `json:"account_id"`
	AccountName              string    `json:"account_name,omitempty"`
	Status                   string    `json:"status"`
	ParentID                 string    `json:"parent_id,omitempty"`
	OUPath                   string    `json:"ou_path,omitempty"`
	Partition                string    `json:"partition"`
	Management               bool      `json:"management"`
	DelegatedAdminServices   []string  `json:"delegated_admin_services"`
	ConnectorScoped          bool      `json:"connector_scoped"`
	ScanEligible             bool      `json:"scan_eligible"`
	State                    string    `json:"state"`
	Cursor                   string    `json:"cursor,omitempty"`
	FailureReason            string    `json:"failure_reason,omitempty"`
	Attempts                 int       `json:"attempts,omitempty"`
	Resumable                bool      `json:"resumable"`
	NextAction               string    `json:"next_action"`
	EvidenceRef              string    `json:"evidence_ref"`
	ObservedAt               time.Time `json:"observed_at,omitempty"`
	EligibilityFailureReason string    `json:"eligibility_failure_reason,omitempty"`
}

// AWSOrganizationsTopologyOU is one OU/root in the topology tree.
type AWSOrganizationsTopologyOU struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	Path     string `json:"path"`
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"`
}

// AWSOrganizationsTopologyRelationship links a parent OU/root to a child OU or account.
type AWSOrganizationsTopologyRelationship struct {
	ParentID     string `json:"parent_id"`
	ChildID      string `json:"child_id"`
	ChildType    string `json:"child_type"`
	Relationship string `json:"relationship"`
}

// AWSOrganizationsTopologySummary aggregates Organizations discovery state.
type AWSOrganizationsTopologySummary struct {
	AccountCount               int            `json:"account_count"`
	OrganizationalUnitCount    int            `json:"organizational_unit_count"`
	ManagementAccountCount     int            `json:"management_account_count"`
	DelegatedAdminAccountCount int            `json:"delegated_admin_account_count"`
	SuspendedAccountCount      int            `json:"suspended_account_count"`
	ConnectorScopedAccounts    int            `json:"connector_scoped_accounts"`
	ScanEligibleAccounts       int            `json:"scan_eligible_accounts"`
	BlockedAccounts            int            `json:"blocked_accounts"`
	PermissionDeniedAccounts   int            `json:"permission_denied_accounts"`
	FailedAccounts             int            `json:"failed_accounts"`
	ResumableAccounts          int            `json:"resumable_accounts"`
	StateCounts                map[string]int `json:"state_counts"`
	StatusCounts               map[string]int `json:"status_counts"`
}

// AWSOrganizationsTopologyDiagnostic carries a deterministic discovery failure.
type AWSOrganizationsTopologyDiagnostic struct {
	Source      string `json:"source"`
	Scope       string `json:"scope,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSOrganizationsTopologyCoverageGap names an explicit limitation.
type AWSOrganizationsTopologyCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSOrganizationsTopologyResult is the project-scoped Organizations topology.
type AWSOrganizationsTopologyResult struct {
	TenantID            string                                 `json:"tenant_id"`
	WorkspaceID         string                                 `json:"workspace_id"`
	ProjectID           string                                 `json:"project_id"`
	ConnectorID         string                                 `json:"connector_id,omitempty"`
	AccountID           string                                 `json:"account_id,omitempty"`
	Region              string                                 `json:"region,omitempty"`
	ParentIssueNumber   int                                    `json:"parent_issue_number"`
	ParentIssueRef      string                                 `json:"parent_issue_ref"`
	CurrentIssueNumber  int                                    `json:"current_issue_number"`
	CurrentIssueRef     string                                 `json:"current_issue_ref"`
	OrganizationID      string                                 `json:"organization_id,omitempty"`
	ManagementAccountID string                                 `json:"management_account_id,omitempty"`
	Partition           string                                 `json:"partition"`
	Version             string                                 `json:"version"`
	Status              string                                 `json:"status"`
	FixtureState        string                                 `json:"fixture_state"`
	Confidence          float64                                `json:"confidence"`
	FilteredAccounts    int                                    `json:"filtered_accounts"`
	Summary             AWSOrganizationsTopologySummary        `json:"summary"`
	OrganizationalUnits []AWSOrganizationsTopologyOU           `json:"organizational_units"`
	Accounts            []AWSOrganizationsTopologyAccount      `json:"accounts"`
	Relationships       []AWSOrganizationsTopologyRelationship `json:"relationships"`
	FailureReasons      []string                               `json:"failure_reasons"`
	RemediationHints    []string                               `json:"remediation_hints"`
	EvidenceLinks       []string                               `json:"evidence_links"`
	CoverageGaps        []AWSOrganizationsTopologyCoverageGap  `json:"coverage_gaps"`
	Diagnostics         []AWSOrganizationsTopologyDiagnostic   `json:"diagnostics"`
	GeneratedAt         time.Time                              `json:"generated_at"`
	UpdatedAt           time.Time                              `json:"updated_at"`
}

// GetAWSOrganizationsTopology returns deterministic AWS Organizations topology
// for a project's connector. It is read-only and metadata-only.
func (s *Service) GetAWSOrganizationsTopology(ctx context.Context, workspaceID string, projectID string, request AWSOrganizationsTopologyRequest) (AWSOrganizationsTopologyResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSOrganizationsTopologyResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSOrganizationsTopologyResult{}, err
	}
	// Reject malformed filters before entering the live branch. Otherwise a
	// bad request still calls AWS Organizations, and its failure is masked as
	// a live discovery error instead of surfacing as a 400 to the caller.
	if !validAWSOrganizationsTopologyFilters(request) {
		return AWSOrganizationsTopologyResult{}, ErrInvalidAWSConnectionRequest
	}
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected && s.AWSOrganizationInventoryFactory != nil {
		inventory, err := s.AWSOrganizationInventoryFactory(ctx, connection)
		if err != nil {
			return buildAWSOrganizationsTopologyLiveFailure(scope, project, connection, request, s.Now().UTC(), "inventory_unavailable"), nil
		}
		snapshot, err := inventory.Discover(ctx, AWSOrganizationInventoryRequest{})
		if err != nil {
			return buildAWSOrganizationsTopologyLiveFailure(scope, project, connection, request, s.Now().UTC(), "organizations_discovery_failed"), nil
		}
		return buildAWSOrganizationsTopologyFromInventory(scope, project, connection, request, snapshot, s.Now().UTC())
	}
	return buildAWSOrganizationsTopology(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSOrganizationsTopologyFromInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, request AWSOrganizationsTopologyRequest, snapshot AWSOrganizationInventorySnapshot, checkedAt time.Time) (AWSOrganizationsTopologyResult, error) {
	if !validAWSOrganizationsTopologyFilters(request) {
		return AWSOrganizationsTopologyResult{}, ErrInvalidAWSConnectionRequest
	}
	units := make([]awscontract.OrganizationUnit, 0, len(snapshot.Roots)+len(snapshot.OrganizationalUnits))
	for _, unit := range append(append([]AWSOrganizationInventoryOU(nil), snapshot.Roots...), snapshot.OrganizationalUnits...) {
		units = append(units, awscontract.OrganizationUnit{ID: unit.ID, Name: unit.Name, ParentID: unit.ParentID, Path: unit.Path, Enabled: true})
	}
	// ConnectorScoped must reflect the connector's own scope, not the raw
	// Organizations inventory. Otherwise a selected-OU or selected-accounts
	// connector reports every account in the tree as scan-eligible for that
	// connector, and downstream rollout planning can pick up accounts the
	// operator never approved.
	scoped := awsOrganizationsTopologyConnectorScopePredicate(connection, snapshot)
	accounts := make([]awscontract.OrganizationAccount, 0, len(snapshot.Accounts))
	checkpoints := make([]awscontract.OrganizationsCheckpoint, 0, len(snapshot.Accounts))
	for _, account := range snapshot.Accounts {
		status := awscontract.OrganizationAccountStatus(strings.ToLower(strings.TrimSpace(account.Status)))
		accounts = append(accounts, awscontract.OrganizationAccount{
			AccountID:              account.AccountID,
			Name:                   account.Name,
			Status:                 status,
			ParentID:               account.ParentID,
			OUPath:                 account.OUPath,
			Partition:              snapshot.Partition,
			Management:             account.Management,
			DelegatedAdminServices: account.DelegatedAdminServices,
			ConnectorScoped:        scoped(account),
		})
		state := awscontract.CoverageStateCovered
		if status != awscontract.OrganizationAccountActive {
			state = awscontract.CoverageStateDisabled
		}
		checkpoints = append(checkpoints, awscontract.OrganizationsCheckpoint{AccountID: account.AccountID, State: state, ObservedAt: snapshot.ObservedAt})
	}
	topology, err := awscontract.PlanOrganizationsTopology(awscontract.OrganizationsTopologyConfig{
		ConnectorID:         connection.ConnectorID,
		OrganizationID:      snapshot.OrganizationID,
		ManagementAccountID: snapshot.ManagementAccountID,
		Partition:           snapshot.Partition,
		OrganizationalUnits: units,
		Accounts:            accounts,
		Checkpoints:         checkpoints,
	}, checkedAt)
	if err != nil {
		return AWSOrganizationsTopologyResult{}, err
	}
	filteredAccounts := filterAWSOrganizationsTopologyAccounts(mapAWSOrganizationsTopologyAccounts(topology.Accounts), request)
	return AWSOrganizationsTopologyResult{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connection.ConnectorID,
		AccountID:           connection.AccountID,
		Region:              connection.Region,
		ParentIssueNumber:   awsPlatformDependencyParentIssue,
		ParentIssueRef:      awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:  awsOrganizationsTopologyCurrentIssue,
		CurrentIssueRef:     awsIssueRef(awsOrganizationsTopologyCurrentIssue),
		OrganizationID:      topology.OrganizationID,
		ManagementAccountID: topology.ManagementAccountID,
		Partition:           topology.Partition,
		Version:             topology.Version,
		Status:              awsPlatformDependencyStatusReady,
		FixtureState:        "live",
		Confidence:          1,
		FilteredAccounts:    len(filteredAccounts),
		Summary:             mapAWSOrganizationsTopologySummary(topology.Summary),
		OrganizationalUnits: mapAWSOrganizationsTopologyOUs(topology.OrganizationalUnits),
		Accounts:            filteredAccounts,
		Relationships:       mapAWSOrganizationsTopologyRelationships(topology.Relationships),
		RemediationHints:    []string{"AWS Organizations inventory is current and ready for scoped rollout reconciliation."},
		EvidenceLinks: dedupeStrings([]string{
			"/docs/aws-organizations-topology",
			"/docs/aws-account-region-coverage-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: []AWSOrganizationsTopologyCoverageGap{{
			Capability:  "live_region_enablement",
			Status:      "separate_control",
			Reason:      "AWS Organizations does not report per-account Region opt-in status.",
			Remediation: "Use the account and Region coverage plan before scheduling regional collection.",
		}},
		GeneratedAt: checkedAt,
		UpdatedAt:   checkedAt,
	}, nil
}

func buildAWSOrganizationsTopologyLiveFailure(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, request AWSOrganizationsTopologyRequest, checkedAt time.Time, code string) AWSOrganizationsTopologyResult {
	message := "Identrail could not read AWS Organizations with the connected role."
	return AWSOrganizationsTopologyResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connection.ConnectorID,
		AccountID:          connection.AccountID,
		Region:             connection.Region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsOrganizationsTopologyCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsOrganizationsTopologyCurrentIssue),
		// Derive the partition from the connector's own region rather than
		// hardcoding "aws". A connector in aws-cn or aws-us-gov would
		// otherwise get a blocked summary that names the wrong partition,
		// while the success and deterministic paths report the real one.
		Partition:        awsStackSetPartition(connection.Region),
		Version:          awscontract.OrganizationsTopologyVersion,
		Status:           awsPlatformDependencyStatusBlocked,
		FixtureState:     "live",
		Confidence:       0,
		Summary:          AWSOrganizationsTopologySummary{StateCounts: map[string]int{}, StatusCounts: map[string]int{}},
		FailureReasons:   []string{message},
		RemediationHints: []string{"Allow the connected role to describe the organization and list roots, OUs, accounts, parents, and delegated administrators, then refresh."},
		Diagnostics: []AWSOrganizationsTopologyDiagnostic{{
			Source:      "organizations_topology",
			Scope:       strings.TrimSpace(request.ConnectorID),
			Code:        code,
			Message:     message,
			Remediation: "Update the connector role from the current Identrail template and validate it again.",
			Retryable:   true,
		}},
		GeneratedAt: checkedAt,
		UpdatedAt:   checkedAt,
	}
}

func buildAWSOrganizationsTopology(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSOrganizationsTopologyRequest, checkedAt time.Time) (AWSOrganizationsTopologyResult, error) {
	fixtureState := normalizeAWSOrganizationsFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" || !validAWSOrganizationsTopologyFilters(request) {
		return AWSOrganizationsTopologyResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "111111111111")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	config, diagnostics, gaps := awsOrganizationsTopologyFixtureConfig(connectorID, accountID, fixtureState)
	topology, err := awscontract.PlanOrganizationsTopology(config, checkedAt)
	if err != nil {
		return AWSOrganizationsTopologyResult{}, err
	}
	summary := mapAWSOrganizationsTopologySummary(topology.Summary)
	accounts := mapAWSOrganizationsTopologyAccounts(topology.Accounts)
	filteredAccounts := filterAWSOrganizationsTopologyAccounts(accounts, request)
	status, confidence, failures, remediations := summarizeAWSOrganizationsTopology(fixtureState, diagnostics, topology)

	return AWSOrganizationsTopologyResult{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		AccountID:           accountID,
		Region:              region,
		ParentIssueNumber:   awsPlatformDependencyParentIssue,
		ParentIssueRef:      awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:  awsOrganizationsTopologyCurrentIssue,
		CurrentIssueRef:     awsIssueRef(awsOrganizationsTopologyCurrentIssue),
		OrganizationID:      topology.OrganizationID,
		ManagementAccountID: topology.ManagementAccountID,
		Partition:           topology.Partition,
		Version:             topology.Version,
		Status:              status,
		FixtureState:        fixtureState,
		Confidence:          confidence,
		FilteredAccounts:    len(filteredAccounts),
		Summary:             summary,
		OrganizationalUnits: mapAWSOrganizationsTopologyOUs(topology.OrganizationalUnits),
		Accounts:            filteredAccounts,
		Relationships:       mapAWSOrganizationsTopologyRelationships(topology.Relationships),
		FailureReasons:      failures,
		RemediationHints:    remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsOrganizationsTopologyCurrentIssue),
			"/docs/aws-organizations-topology",
			"/docs/aws-account-region-coverage-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: gaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}, nil
}

// awsOrganizationsTopologyConnectorScopePredicate returns a function that
// answers, for each Organizations account, whether the connector's own scope
// covers it. It mirrors the resolution the rollout planner and StackSet
// deployment path use: excluded accounts are always out; single_account /
// manual_role only cover the connection's own account; organization covers
// everything except explicit exclusions; selected_ous covers accounts whose
// ancestors intersect the connector's OU list; selected_accounts covers only
// the explicit account list. An unrecognized scope type is treated as
// unscoped so we fail closed rather than leaking accounts through defaults.
func awsOrganizationsTopologyConnectorScopePredicate(connection AWSConnectionStatus, snapshot AWSOrganizationInventorySnapshot) func(AWSOrganizationInventoryAccount) bool {
	excluded := make(map[string]struct{}, len(connection.ExcludedAccountIDs))
	for _, accountID := range connection.ExcludedAccountIDs {
		if id := strings.TrimSpace(accountID); id != "" {
			excluded[id] = struct{}{}
		}
	}
	targets := make(map[string]struct{}, len(connection.TargetAccountIDs))
	for _, accountID := range connection.TargetAccountIDs {
		if id := strings.TrimSpace(accountID); id != "" {
			targets[id] = struct{}{}
		}
	}
	ous := make(map[string]struct{}, len(connection.TargetOUIDs))
	for _, ouID := range connection.TargetOUIDs {
		if id := strings.TrimSpace(ouID); id != "" {
			ous[id] = struct{}{}
		}
	}
	connectionAccountID := strings.TrimSpace(connection.AccountID)
	scopeType := connection.ScopeType
	return func(account AWSOrganizationInventoryAccount) bool {
		if _, blocked := excluded[account.AccountID]; blocked {
			return false
		}
		switch scopeType {
		case AWSConnectorScopeOrganization:
			return true
		case AWSConnectorScopeSelectedOUs:
			for _, ancestorID := range account.AncestorIDs {
				if _, ok := ous[strings.TrimSpace(ancestorID)]; ok {
					return true
				}
			}
			return false
		case AWSConnectorScopeSelectedAccounts:
			_, ok := targets[account.AccountID]
			return ok
		case AWSConnectorScopeSingleAccount, AWSConnectorScopeManualRole:
			return connectionAccountID != "" && account.AccountID == connectionAccountID
		default:
			return false
		}
	}
}

func normalizeAWSOrganizationsFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func validAWSOrganizationsTopologyFilters(request AWSOrganizationsTopologyRequest) bool {
	if !validAWSCoveragePlanStateFilter(request.State) {
		return false
	}
	switch awscontract.OrganizationAccountStatus(strings.ToLower(strings.TrimSpace(request.Status))) {
	case "",
		awscontract.OrganizationAccountActive,
		awscontract.OrganizationAccountSuspended,
		awscontract.OrganizationAccountClosed,
		awscontract.OrganizationAccountPendingActivation,
		awscontract.OrganizationAccountPendingClosure:
		return true
	default:
		return false
	}
}

func awsOrganizationsTopologyFixtureConfig(connectorID, accountID, fixtureState string) (awscontract.OrganizationsTopologyConfig, []AWSOrganizationsTopologyDiagnostic, []AWSOrganizationsTopologyCoverageGap) {
	gaps := []AWSOrganizationsTopologyCoverageGap{
		{
			Capability:  "live_region_enablement",
			Status:      "planned_downstream",
			Reason:      "This topology maps Organizations accounts and OUs; per-account region opt-in discovery is handled by the account/region coverage planner.",
			Remediation: "Join this topology with coverage-plan targets before scheduling regional fan-out scans.",
		},
		{
			Capability:  "customer_payload_collection",
			Status:      "unsupported",
			Reason:      "Organizations topology only records account, OU, status, parent, delegated-admin, cursor, and evidence metadata.",
			Remediation: "Use the owning AWS service for payload inspection outside Identrail.",
		},
	}
	if fixtureState == "empty" {
		return awscontract.OrganizationsTopologyConfig{ConnectorID: connectorID, Partition: "aws"}, nil, gaps
	}

	productionAccount := awsCoveragePlanSiblingAccount(accountID)
	dataAccount := awsOrganizationsTopologyNextAccount(productionAccount)
	sandboxAccount := awsOrganizationsTopologyNextAccount(dataAccount)
	config := awscontract.OrganizationsTopologyConfig{
		ConnectorID:         connectorID,
		OrganizationID:      "o-identrailfixture",
		ManagementAccountID: accountID,
		Partition:           "aws",
		OrganizationalUnits: []awscontract.OrganizationUnit{
			{ID: "r-identrail", Name: "Root", Path: "/", Enabled: true},
			{ID: "ou-prod", Name: "Production", ParentID: "r-identrail", Path: "/Production", Enabled: true},
			{ID: "ou-data", Name: "Data", ParentID: "r-identrail", Path: "/Data", Enabled: true},
			{ID: "ou-sandbox", Name: "Sandbox", ParentID: "r-identrail", Path: "/Sandbox", Enabled: false, Reason: "sandbox OU disabled for read-only scans"},
		},
		Accounts: []awscontract.OrganizationAccount{
			{AccountID: accountID, Name: "management", ParentID: "r-identrail", Status: awscontract.OrganizationAccountActive, ConnectorScoped: true},
			{AccountID: productionAccount, Name: "production", ParentID: "ou-prod", Status: awscontract.OrganizationAccountActive, ConnectorScoped: true, DelegatedAdminServices: []string{"guardduty.amazonaws.com", "securityhub.amazonaws.com"}},
			{AccountID: dataAccount, Name: "data", ParentID: "ou-data", Status: awscontract.OrganizationAccountActive, ConnectorScoped: true, DelegatedAdminServices: []string{"access-analyzer.amazonaws.com"}},
			{AccountID: sandboxAccount, Name: "retired-sandbox", ParentID: "ou-sandbox", Status: awscontract.OrganizationAccountSuspended, ConnectorScoped: true},
		},
	}

	diagnostics := []AWSOrganizationsTopologyDiagnostic{}
	switch fixtureState {
	case "permission_denied":
		config.Checkpoints = []awscontract.OrganizationsCheckpoint{{
			AccountID:     productionAccount,
			State:         awscontract.CoverageStatePermissionDenied,
			FailureReason: "AccessDenied: organizations:ListParents denied for member account",
		}}
		diagnostics = append(diagnostics, AWSOrganizationsTopologyDiagnostic{
			Source:      "organizations_topology",
			Scope:       productionAccount,
			Code:        "permission_denied",
			Message:     "Connector role cannot read AWS Organizations parent relationships for a member account.",
			Remediation: "Grant read-only organizations:ListAccounts, ListParents, ListRoots, ListOrganizationalUnitsForParent, and ListDelegatedAdministrators to the connector role.",
			Retryable:   false,
		})
	case "degraded", "partial_failure":
		config.Checkpoints = []awscontract.OrganizationsCheckpoint{
			{AccountID: accountID, State: awscontract.CoverageStateCovered},
			{AccountID: productionAccount, State: awscontract.CoverageStateCovered},
			{AccountID: dataAccount, State: awscontract.CoverageStateFailed, Cursor: "organizations:accounts-page-2", FailureReason: "Throttling: organizations:ListAccounts after bounded retries", Attempts: 3},
		}
		diagnostics = append(diagnostics, AWSOrganizationsTopologyDiagnostic{
			Source:      "organizations_topology",
			Scope:       dataAccount,
			Code:        "partial_failure",
			Message:     "AWS Organizations pagination stopped after throttling; account discovery is resumable from the stored cursor.",
			Remediation: "Re-run Organizations discovery to continue from the checkpoint cursor.",
			Retryable:   true,
		})
	default:
		config.Checkpoints = []awscontract.OrganizationsCheckpoint{
			{AccountID: accountID, State: awscontract.CoverageStateCovered},
			{AccountID: productionAccount, State: awscontract.CoverageStateCovered},
			{AccountID: dataAccount, State: awscontract.CoverageStateCovered},
		}
	}
	return config, diagnostics, gaps
}

func mapAWSOrganizationsTopologySummary(summary awscontract.OrganizationsTopologySummary) AWSOrganizationsTopologySummary {
	stateCounts := map[string]int{}
	for state, count := range summary.StateCounts {
		stateCounts[string(state)] = count
	}
	statusCounts := map[string]int{}
	for status, count := range summary.StatusCounts {
		statusCounts[string(status)] = count
	}
	return AWSOrganizationsTopologySummary{
		AccountCount:               summary.AccountCount,
		OrganizationalUnitCount:    summary.OrganizationalUnitCount,
		ManagementAccountCount:     summary.ManagementAccountCount,
		DelegatedAdminAccountCount: summary.DelegatedAdminAccountCount,
		SuspendedAccountCount:      summary.SuspendedAccountCount,
		ConnectorScopedAccounts:    summary.ConnectorScopedAccounts,
		ScanEligibleAccounts:       summary.ScanEligibleAccounts,
		BlockedAccounts:            summary.BlockedAccounts,
		PermissionDeniedAccounts:   summary.PermissionDeniedAccounts,
		FailedAccounts:             summary.FailedAccounts,
		ResumableAccounts:          summary.ResumableAccounts,
		StateCounts:                stateCounts,
		StatusCounts:               statusCounts,
	}
}

func mapAWSOrganizationsTopologyAccounts(accounts []awscontract.OrganizationAccount) []AWSOrganizationsTopologyAccount {
	out := make([]AWSOrganizationsTopologyAccount, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, AWSOrganizationsTopologyAccount{
			AccountID:                account.AccountID,
			AccountName:              account.Name,
			Status:                   string(account.Status),
			ParentID:                 account.ParentID,
			OUPath:                   account.OUPath,
			Partition:                account.Partition,
			Management:               account.Management,
			DelegatedAdminServices:   account.DelegatedAdminServices,
			ConnectorScoped:          account.ConnectorScoped,
			ScanEligible:             account.ScanEligible,
			State:                    string(account.State),
			Cursor:                   account.Cursor,
			FailureReason:            account.FailureReason,
			Attempts:                 account.Attempts,
			Resumable:                account.Resumable,
			NextAction:               awsOrganizationsTopologyNextAction(account),
			EvidenceRef:              account.EvidenceRef,
			ObservedAt:               account.ObservedAt,
			EligibilityFailureReason: account.EligibilityFailureReason,
		})
	}
	return out
}

func mapAWSOrganizationsTopologyOUs(units []awscontract.OrganizationUnit) []AWSOrganizationsTopologyOU {
	out := make([]AWSOrganizationsTopologyOU, 0, len(units))
	for _, unit := range units {
		out = append(out, AWSOrganizationsTopologyOU{
			ID:       unit.ID,
			Name:     unit.Name,
			ParentID: unit.ParentID,
			Path:     unit.Path,
			Enabled:  unit.Enabled,
			Reason:   unit.Reason,
		})
	}
	return out
}

func mapAWSOrganizationsTopologyRelationships(relationships []awscontract.OrganizationRelationship) []AWSOrganizationsTopologyRelationship {
	out := make([]AWSOrganizationsTopologyRelationship, 0, len(relationships))
	for _, relationship := range relationships {
		out = append(out, AWSOrganizationsTopologyRelationship{
			ParentID:     relationship.ParentID,
			ChildID:      relationship.ChildID,
			ChildType:    relationship.ChildType,
			Relationship: relationship.Relationship,
		})
	}
	return out
}

func filterAWSOrganizationsTopologyAccounts(accounts []AWSOrganizationsTopologyAccount, request AWSOrganizationsTopologyRequest) []AWSOrganizationsTopologyAccount {
	accountFilter := strings.TrimSpace(request.Account)
	ouFilter := strings.ToLower(strings.TrimSpace(request.OU))
	stateFilter := strings.ToLower(strings.TrimSpace(request.State))
	statusFilter := strings.ToLower(strings.TrimSpace(request.Status))
	filtered := make([]AWSOrganizationsTopologyAccount, 0, len(accounts))
	for _, account := range accounts {
		if accountFilter != "" && account.AccountID != accountFilter {
			continue
		}
		if ouFilter != "" && strings.ToLower(account.ParentID) != ouFilter && strings.ToLower(account.OUPath) != ouFilter {
			continue
		}
		if stateFilter != "" && strings.ToLower(account.State) != stateFilter {
			continue
		}
		if statusFilter != "" && strings.ToLower(account.Status) != statusFilter {
			continue
		}
		filtered = append(filtered, account)
	}
	return filtered
}

func awsOrganizationsTopologyNextAction(account awscontract.OrganizationAccount) string {
	switch account.State {
	case awscontract.CoverageStateCovered:
		return "Use this account and OU context to seed account/region coverage and downstream identity graph collection."
	case awscontract.CoverageStatePermissionDenied:
		return "Grant read-only AWS Organizations permissions to the connector role, then rerun topology discovery."
	case awscontract.CoverageStateFailed, awscontract.CoverageStatePartial:
		return "Rerun Organizations discovery to resume from the stored checkpoint cursor."
	case awscontract.CoverageStateDisabled:
		return "Reactivate the AWS account or leave it excluded from scan fan-out."
	case awscontract.CoverageStateUnsupported:
		return "Add the account to connector scope before scheduling scan targets."
	case awscontract.CoverageStateBlocked:
		if account.EligibilityFailureReason != "" {
			return account.EligibilityFailureReason
		}
		return "Resolve parent OU or connector-scope prerequisites before scanning this account."
	default:
		return "Queue read-only Organizations discovery and persist account, OU, status, and delegated-admin metadata."
	}
}

func summarizeAWSOrganizationsTopology(fixtureState string, diagnostics []AWSOrganizationsTopologyDiagnostic, topology awscontract.OrganizationsTopology) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.32,
			awsOrganizationsDiagnosticMessages(diagnostics),
			[]string{"Grant read-only AWS Organizations permissions and rerun topology discovery."}
	case "partial_failure", "degraded":
		return awsPlatformDependencyStatusDegraded, 0.74,
			awsOrganizationsDiagnosticMessages(diagnostics),
			[]string{"Rerun Organizations discovery to resume from failed account cursors."}
	default:
		if topology.Summary.AccountCount == 0 {
			return awsPlatformDependencyStatusReady, 0.82, nil,
				[]string{"No AWS Organizations accounts were discovered; confirm the connector is scoped to an organization management or delegated administrator account."}
		}
		return awsPlatformDependencyStatusReady, 0.94, nil,
			[]string{"Organizations topology is ready to seed account/region coverage and downstream identity graph collection."}
	}
}

func awsOrganizationsDiagnosticMessages(diagnostics []AWSOrganizationsTopologyDiagnostic) []string {
	messages := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if message := strings.TrimSpace(diagnostic.Message); message != "" {
			messages = append(messages, message)
		}
	}
	return dedupeStrings(messages)
}

func awsOrganizationsTopologyNextAccount(accountID string) string {
	return awsCoveragePlanSiblingAccount(accountID)
}
