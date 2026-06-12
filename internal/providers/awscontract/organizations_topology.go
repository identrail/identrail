package awscontract

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationsTopologyVersion is the stable contract version for AWS
// Organizations account and OU discovery output.
const OrganizationsTopologyVersion = "aws-organizations-topology-v1"

// OrganizationAccountStatus mirrors the AWS Organizations lifecycle values that
// affect scan eligibility.
type OrganizationAccountStatus string

const (
	OrganizationAccountActive            OrganizationAccountStatus = "active"
	OrganizationAccountSuspended         OrganizationAccountStatus = "suspended"
	OrganizationAccountClosed            OrganizationAccountStatus = "closed"
	OrganizationAccountPendingActivation OrganizationAccountStatus = "pending_activation"
	OrganizationAccountPendingClosure    OrganizationAccountStatus = "pending_closure"
)

// OrganizationUnit is one AWS Organizations OU or root-like container.
type OrganizationUnit struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	Path     string `json:"path"`
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"`
}

// OrganizationAccount is one account discovered from AWS Organizations.
type OrganizationAccount struct {
	AccountID                string                    `json:"account_id"`
	Name                     string                    `json:"name,omitempty"`
	Status                   OrganizationAccountStatus `json:"status"`
	ParentID                 string                    `json:"parent_id,omitempty"`
	OUPath                   string                    `json:"ou_path,omitempty"`
	Partition                string                    `json:"partition"`
	Management               bool                      `json:"management,omitempty"`
	DelegatedAdminServices   []string                  `json:"delegated_admin_services"`
	ConnectorScoped          bool                      `json:"connector_scoped"`
	ScanEligible             bool                      `json:"scan_eligible"`
	State                    CoverageState             `json:"state"`
	Cursor                   string                    `json:"cursor,omitempty"`
	FailureReason            string                    `json:"failure_reason,omitempty"`
	Attempts                 int                       `json:"attempts,omitempty"`
	Resumable                bool                      `json:"resumable"`
	EvidenceRef              string                    `json:"evidence_ref"`
	ObservedAt               time.Time                 `json:"observed_at,omitempty"`
	EligibilityFailureReason string                    `json:"eligibility_failure_reason,omitempty"`
}

// OrganizationRelationship records a parent-child topology edge.
type OrganizationRelationship struct {
	ParentID     string `json:"parent_id"`
	ChildID      string `json:"child_id"`
	ChildType    string `json:"child_type"`
	Relationship string `json:"relationship"`
}

// OrganizationsCheckpoint is a prior account discovery state used for
// resumable topology collection.
type OrganizationsCheckpoint struct {
	AccountID     string        `json:"account_id"`
	State         CoverageState `json:"state"`
	Cursor        string        `json:"cursor,omitempty"`
	FailureReason string        `json:"failure_reason,omitempty"`
	Attempts      int           `json:"attempts,omitempty"`
	ObservedAt    time.Time     `json:"observed_at,omitempty"`
}

// OrganizationsTopologyConfig is the normalized Organizations discovery input.
type OrganizationsTopologyConfig struct {
	ConnectorID         string                    `json:"connector_id,omitempty"`
	OrganizationID      string                    `json:"organization_id,omitempty"`
	ManagementAccountID string                    `json:"management_account_id,omitempty"`
	Partition           string                    `json:"partition,omitempty"`
	OrganizationalUnits []OrganizationUnit        `json:"organizational_units,omitempty"`
	Accounts            []OrganizationAccount     `json:"accounts,omitempty"`
	Checkpoints         []OrganizationsCheckpoint `json:"checkpoints,omitempty"`
}

// OrganizationsTopologySummary aggregates the topology for dashboards and
// operator recovery.
type OrganizationsTopologySummary struct {
	AccountCount               int                               `json:"account_count"`
	OrganizationalUnitCount    int                               `json:"organizational_unit_count"`
	ManagementAccountCount     int                               `json:"management_account_count"`
	DelegatedAdminAccountCount int                               `json:"delegated_admin_account_count"`
	SuspendedAccountCount      int                               `json:"suspended_account_count"`
	ConnectorScopedAccounts    int                               `json:"connector_scoped_accounts"`
	ScanEligibleAccounts       int                               `json:"scan_eligible_accounts"`
	BlockedAccounts            int                               `json:"blocked_accounts"`
	PermissionDeniedAccounts   int                               `json:"permission_denied_accounts"`
	FailedAccounts             int                               `json:"failed_accounts"`
	ResumableAccounts          int                               `json:"resumable_accounts"`
	StateCounts                map[CoverageState]int             `json:"state_counts"`
	StatusCounts               map[OrganizationAccountStatus]int `json:"status_counts"`
}

// OrganizationsTopology is the deterministic output of Organizations discovery.
type OrganizationsTopology struct {
	ConnectorID         string                       `json:"connector_id,omitempty"`
	OrganizationID      string                       `json:"organization_id,omitempty"`
	ManagementAccountID string                       `json:"management_account_id,omitempty"`
	Partition           string                       `json:"partition"`
	Version             string                       `json:"version"`
	Summary             OrganizationsTopologySummary `json:"summary"`
	OrganizationalUnits []OrganizationUnit           `json:"organizational_units"`
	Accounts            []OrganizationAccount        `json:"accounts"`
	Relationships       []OrganizationRelationship   `json:"relationships"`
	GeneratedAt         time.Time                    `json:"generated_at"`
}

// PlanOrganizationsTopology normalizes AWS Organizations account/OU discovery
// into deterministic, metadata-only topology output. It performs no AWS calls
// and never carries customer payloads.
func PlanOrganizationsTopology(config OrganizationsTopologyConfig, generatedAt time.Time) (OrganizationsTopology, error) {
	partition := normalizeOrganizationsPartition(config.Partition)
	ous, ouByID, err := normalizeOrganizationUnits(config.OrganizationalUnits)
	if err != nil {
		return OrganizationsTopology{}, err
	}
	checkpoints, err := indexOrganizationsCheckpoints(config.Checkpoints)
	if err != nil {
		return OrganizationsTopology{}, err
	}
	accounts, err := normalizeOrganizationAccounts(config, partition, ouByID, checkpoints)
	if err != nil {
		return OrganizationsTopology{}, err
	}
	relationships := buildOrganizationRelationships(ous, accounts)

	sort.SliceStable(accounts, func(i, j int) bool {
		if accounts[i].OUPath != accounts[j].OUPath {
			return accounts[i].OUPath < accounts[j].OUPath
		}
		return accounts[i].AccountID < accounts[j].AccountID
	})

	return OrganizationsTopology{
		ConnectorID:         strings.TrimSpace(config.ConnectorID),
		OrganizationID:      strings.TrimSpace(config.OrganizationID),
		ManagementAccountID: strings.TrimSpace(config.ManagementAccountID),
		Partition:           partition,
		Version:             OrganizationsTopologyVersion,
		Summary:             summarizeOrganizationsTopology(accounts, len(ous)),
		OrganizationalUnits: ous,
		Accounts:            accounts,
		Relationships:       relationships,
		GeneratedAt:         generatedAt.UTC(),
	}, nil
}

func normalizeOrganizationsPartition(partition string) string {
	out := strings.ToLower(strings.TrimSpace(partition))
	if out == "" {
		return "aws"
	}
	return out
}

func normalizeOrganizationUnits(input []OrganizationUnit) ([]OrganizationUnit, map[string]OrganizationUnit, error) {
	seen := map[string]struct{}{}
	out := make([]OrganizationUnit, 0, len(input))
	for _, item := range input {
		unit := item
		unit.ID = strings.TrimSpace(item.ID)
		if unit.ID == "" {
			return nil, nil, fmt.Errorf("organization unit id is required")
		}
		if _, ok := seen[unit.ID]; ok {
			continue
		}
		seen[unit.ID] = struct{}{}
		unit.Name = strings.TrimSpace(item.Name)
		unit.ParentID = strings.TrimSpace(item.ParentID)
		unit.Path = strings.TrimSpace(item.Path)
		if unit.Path == "" {
			unit.Path = "/" + firstNonEmptyContractString(unit.Name, unit.ID)
		}
		if !strings.HasPrefix(unit.Path, "/") {
			unit.Path = "/" + unit.Path
		}
		unit.Reason = strings.TrimSpace(item.Reason)
		out = append(out, unit)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].ID < out[j].ID
	})
	byID := make(map[string]OrganizationUnit, len(out))
	for _, unit := range out {
		byID[unit.ID] = unit
	}
	return out, byID, nil
}

func normalizeOrganizationAccounts(config OrganizationsTopologyConfig, partition string, ouByID map[string]OrganizationUnit, checkpoints map[string]OrganizationsCheckpoint) ([]OrganizationAccount, error) {
	seen := map[string]struct{}{}
	out := make([]OrganizationAccount, 0, len(config.Accounts))
	for _, item := range config.Accounts {
		account := item
		account.AccountID = strings.TrimSpace(item.AccountID)
		if !validOrganizationsAccountID(account.AccountID) {
			return nil, fmt.Errorf("organization account id must be 12 digits")
		}
		if _, ok := seen[account.AccountID]; ok {
			continue
		}
		seen[account.AccountID] = struct{}{}
		account.Name = strings.TrimSpace(item.Name)
		account.ParentID = strings.TrimSpace(item.ParentID)
		account.Partition = normalizeOrganizationsPartition(firstNonEmptyContractString(item.Partition, partition))
		account.Status = normalizeOrganizationAccountStatus(item.Status)
		account.Management = account.Management || account.AccountID == strings.TrimSpace(config.ManagementAccountID)
		account.DelegatedAdminServices = dedupeSortedCoverageStrings(item.DelegatedAdminServices)
		account.OUPath = strings.TrimSpace(item.OUPath)
		if unit, ok := ouByID[account.ParentID]; ok {
			if account.OUPath == "" {
				account.OUPath = unit.Path
			}
			if !unit.Enabled {
				account.EligibilityFailureReason = firstNonEmptyContractString(unit.Reason, "parent organizational unit is disabled")
			}
		}
		account.ConnectorScoped = item.ConnectorScoped
		account.ScanEligible = account.ConnectorScoped && account.Status == OrganizationAccountActive && account.EligibilityFailureReason == ""
		account.State = initialOrganizationAccountState(account)
		account.EvidenceRef = organizationEvidenceRef(config.ConnectorID, config.OrganizationID, account.AccountID)
		if checkpoint, ok := checkpoints[account.AccountID]; ok {
			applyOrganizationsCheckpoint(&account, checkpoint)
		}
		account.Resumable = coverageTargetResumable(CoverageTarget{State: account.State})
		out = append(out, account)
	}
	return out, nil
}

func normalizeOrganizationAccountStatus(status OrganizationAccountStatus) OrganizationAccountStatus {
	switch OrganizationAccountStatus(strings.ToLower(strings.TrimSpace(string(status)))) {
	case OrganizationAccountActive:
		return OrganizationAccountActive
	case OrganizationAccountSuspended:
		return OrganizationAccountSuspended
	case OrganizationAccountClosed:
		return OrganizationAccountClosed
	case OrganizationAccountPendingActivation:
		return OrganizationAccountPendingActivation
	case OrganizationAccountPendingClosure:
		return OrganizationAccountPendingClosure
	default:
		return OrganizationAccountClosed
	}
}

func initialOrganizationAccountState(account OrganizationAccount) CoverageState {
	switch {
	case !account.ConnectorScoped:
		return CoverageStateUnsupported
	case account.Status == OrganizationAccountSuspended || account.Status == OrganizationAccountClosed || account.Status == OrganizationAccountPendingClosure || account.Status == OrganizationAccountPendingActivation:
		return CoverageStateDisabled
	case account.EligibilityFailureReason != "":
		return CoverageStateBlocked
	default:
		return CoverageStatePlanned
	}
}

func indexOrganizationsCheckpoints(input []OrganizationsCheckpoint) (map[string]OrganizationsCheckpoint, error) {
	out := make(map[string]OrganizationsCheckpoint, len(input))
	for _, checkpoint := range input {
		accountID := strings.TrimSpace(checkpoint.AccountID)
		if !validOrganizationsAccountID(accountID) {
			return nil, fmt.Errorf("organization checkpoint account id must be 12 digits")
		}
		if checkpoint.State != "" && !validCoverageState(checkpoint.State) {
			return nil, fmt.Errorf("organization checkpoint has invalid state %q", checkpoint.State)
		}
		checkpoint.AccountID = accountID
		out[accountID] = checkpoint
	}
	return out, nil
}

func applyOrganizationsCheckpoint(account *OrganizationAccount, checkpoint OrganizationsCheckpoint) {
	if !account.ScanEligible {
		return
	}
	if checkpoint.State == CoverageStateDisabled {
		return
	}
	if checkpoint.State != "" {
		account.State = checkpoint.State
	}
	account.Cursor = strings.TrimSpace(checkpoint.Cursor)
	account.FailureReason = strings.TrimSpace(checkpoint.FailureReason)
	if checkpoint.Attempts > 0 {
		account.Attempts = checkpoint.Attempts
	}
	if !checkpoint.ObservedAt.IsZero() {
		account.ObservedAt = checkpoint.ObservedAt.UTC()
	}
}

func buildOrganizationRelationships(ous []OrganizationUnit, accounts []OrganizationAccount) []OrganizationRelationship {
	relationships := make([]OrganizationRelationship, 0, len(ous)+len(accounts))
	for _, unit := range ous {
		if unit.ParentID == "" {
			continue
		}
		relationships = append(relationships, OrganizationRelationship{
			ParentID:     unit.ParentID,
			ChildID:      unit.ID,
			ChildType:    "organizational_unit",
			Relationship: "contains",
		})
	}
	for _, account := range accounts {
		if account.ParentID == "" {
			continue
		}
		relationships = append(relationships, OrganizationRelationship{
			ParentID:     account.ParentID,
			ChildID:      account.AccountID,
			ChildType:    "account",
			Relationship: "contains",
		})
	}
	sort.SliceStable(relationships, func(i, j int) bool {
		if relationships[i].ParentID != relationships[j].ParentID {
			return relationships[i].ParentID < relationships[j].ParentID
		}
		return relationships[i].ChildID < relationships[j].ChildID
	})
	return relationships
}

func summarizeOrganizationsTopology(accounts []OrganizationAccount, ouCount int) OrganizationsTopologySummary {
	summary := OrganizationsTopologySummary{
		AccountCount:            len(accounts),
		OrganizationalUnitCount: ouCount,
		StateCounts:             map[CoverageState]int{},
		StatusCounts:            map[OrganizationAccountStatus]int{},
	}
	for _, account := range accounts {
		summary.StateCounts[account.State]++
		summary.StatusCounts[account.Status]++
		if account.Management {
			summary.ManagementAccountCount++
		}
		if len(account.DelegatedAdminServices) > 0 {
			summary.DelegatedAdminAccountCount++
		}
		if account.Status == OrganizationAccountSuspended {
			summary.SuspendedAccountCount++
		}
		if account.ConnectorScoped {
			summary.ConnectorScopedAccounts++
		}
		if account.ScanEligible {
			summary.ScanEligibleAccounts++
		}
		switch account.State {
		case CoverageStateBlocked:
			summary.BlockedAccounts++
		case CoverageStatePermissionDenied:
			summary.PermissionDeniedAccounts++
		case CoverageStateFailed, CoverageStatePartial:
			summary.FailedAccounts++
		}
		if account.Resumable {
			summary.ResumableAccounts++
		}
	}
	return summary
}

func organizationEvidenceRef(connectorID, organizationID, accountID string) string {
	parts := []string{"aws-organizations"}
	if connectorID != "" {
		parts = append(parts, strings.TrimSpace(connectorID))
	}
	if organizationID != "" {
		parts = append(parts, strings.TrimSpace(organizationID))
	}
	parts = append(parts, strings.TrimSpace(accountID))
	return strings.Join(parts, ":")
}

func firstNonEmptyContractString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func validOrganizationsAccountID(accountID string) bool {
	if len(accountID) != 12 {
		return false
	}
	for _, char := range accountID {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
