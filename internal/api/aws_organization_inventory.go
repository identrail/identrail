package api

import (
	"context"
	"sort"
	"strings"
	"time"
)

// AWSOrganizationInventory is the live, read-only provider seam used by
// topology and rollout reconciliation. Implementations must paginate every
// AWS list operation and return a complete snapshot or an error; callers never
// treat a partial provider response as complete coverage.
type AWSOrganizationInventory interface {
	Discover(ctx context.Context, request AWSOrganizationInventoryRequest) (AWSOrganizationInventorySnapshot, error)
}

type AWSOrganizationInventoryRequest struct {
	StackSetName    string
	ControllingRole string
}

type AWSOrganizationInventorySnapshot struct {
	OrganizationID      string
	ManagementAccountID string
	Partition           string
	Roots               []AWSOrganizationInventoryOU
	OrganizationalUnits []AWSOrganizationInventoryOU
	Accounts            []AWSOrganizationInventoryAccount
	StackInstances      []AWSOrganizationStackInstance
	ObservedAt          time.Time
}

type AWSOrganizationInventoryOU struct {
	ID          string
	Name        string
	ParentID    string
	Path        string
	AncestorIDs []string
}

type AWSOrganizationInventoryAccount struct {
	AccountID              string
	Name                   string
	Status                 string
	ParentID               string
	OUPath                 string
	AncestorIDs            []string
	Management             bool
	DelegatedAdminServices []string
}

type AWSOrganizationStackInstance struct {
	AccountID            string
	Region               string
	OrganizationalUnitID string
	StackSetID           string
	StackID              string
	Status               string
	DetailedStatus       string
	DriftStatus          string
	StatusReason         string
	LastOperationID      string
	ObservedAt           time.Time
}

func awsOrganizationInventoryAccountMap(snapshot AWSOrganizationInventorySnapshot) map[string]AWSOrganizationInventoryAccount {
	out := make(map[string]AWSOrganizationInventoryAccount, len(snapshot.Accounts))
	for _, account := range snapshot.Accounts {
		if id := strings.TrimSpace(account.AccountID); id != "" {
			out[id] = account
		}
	}
	return out
}

func awsOrganizationInventorySelectedAccounts(snapshot AWSOrganizationInventorySnapshot, selectedOUs []string, selectedAccounts []string) []string {
	selected := make(map[string]struct{}, len(selectedAccounts)+len(snapshot.Accounts))
	for _, accountID := range selectedAccounts {
		if accountID = strings.TrimSpace(accountID); accountID != "" {
			selected[accountID] = struct{}{}
		}
	}
	selectedOUSet := make(map[string]struct{}, len(selectedOUs))
	for _, ouID := range selectedOUs {
		if ouID = strings.TrimSpace(ouID); ouID != "" {
			selectedOUSet[ouID] = struct{}{}
		}
	}
	for _, account := range snapshot.Accounts {
		if len(selectedOUSet) == 0 {
			continue
		}
		for _, ancestorID := range account.AncestorIDs {
			if _, ok := selectedOUSet[ancestorID]; ok {
				selected[account.AccountID] = struct{}{}
				break
			}
		}
	}
	out := make([]string, 0, len(selected))
	for accountID := range selected {
		out = append(out, accountID)
	}
	sort.Strings(out)
	return out
}

func awsOrganizationInventoryAccountInactive(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "suspended", "closed", "pending_closure":
		return true
	default:
		return false
	}
}

func awsOrganizationInventoryHasCloudFormationDelegation(account AWSOrganizationInventoryAccount) bool {
	for _, service := range account.DelegatedAdminServices {
		if strings.Contains(strings.ToLower(strings.TrimSpace(service)), "cloudformation") {
			return true
		}
	}
	return false
}
