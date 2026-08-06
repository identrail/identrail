package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	api "github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/textutil"
)

const maxAWSOrganizationInventoryPages = 10000

type organizationsInventoryAPI interface {
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(context.Context, *organizations.ListOrganizationalUnitsForParentInput, ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(context.Context, *organizations.ListAccountsForParentInput, ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
	ListDelegatedAdministrators(context.Context, *organizations.ListDelegatedAdministratorsInput, ...func(*organizations.Options)) (*organizations.ListDelegatedAdministratorsOutput, error)
	ListDelegatedServicesForAccount(context.Context, *organizations.ListDelegatedServicesForAccountInput, ...func(*organizations.Options)) (*organizations.ListDelegatedServicesForAccountOutput, error)
}

type cloudFormationInventoryAPI interface {
	ListStackInstances(context.Context, *cloudformation.ListStackInstancesInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackInstancesOutput, error)
}

type SDKOrganizationInventory struct {
	organizations  organizationsInventoryAPI
	cloudFormation cloudFormationInventoryAPI
	now            func() time.Time
}

var _ api.AWSOrganizationInventory = (*SDKOrganizationInventory)(nil)

func NewSDKOrganizationInventoryFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string) (api.AWSOrganizationInventory, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, fmt.Errorf("aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = textutil.FirstNonEmpty(strings.TrimSpace(sessionName), "identrail-organization-inventory")
	}}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	return NewSDKOrganizationInventoryFromClients(organizations.NewFromConfig(cfg), cloudformation.NewFromConfig(cfg)), nil
}

func NewSDKOrganizationInventoryFromClients(organizationsClient organizationsInventoryAPI, cloudFormationClient cloudFormationInventoryAPI) api.AWSOrganizationInventory {
	return &SDKOrganizationInventory{
		organizations:  organizationsClient,
		cloudFormation: cloudFormationClient,
		now:            time.Now,
	}
}

func (i *SDKOrganizationInventory) Discover(ctx context.Context, request api.AWSOrganizationInventoryRequest) (api.AWSOrganizationInventorySnapshot, error) {
	if i == nil || i.organizations == nil {
		return api.AWSOrganizationInventorySnapshot{}, fmt.Errorf("aws organizations inventory client is unavailable")
	}
	described, err := i.organizations.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return api.AWSOrganizationInventorySnapshot{}, fmt.Errorf("describe aws organization: %w", err)
	}
	if described.Organization == nil {
		return api.AWSOrganizationInventorySnapshot{}, fmt.Errorf("describe aws organization returned no organization")
	}
	organizationID := strings.TrimSpace(awsv2.ToString(described.Organization.Id))
	managementAccountID := strings.TrimSpace(awsv2.ToString(described.Organization.MasterAccountId))
	if organizationID == "" || managementAccountID == "" {
		return api.AWSOrganizationInventorySnapshot{}, fmt.Errorf("aws organization identity is incomplete")
	}

	delegatedServices, err := i.listDelegatedAdminServices(ctx)
	if err != nil {
		return api.AWSOrganizationInventorySnapshot{}, err
	}
	roots, err := i.listRoots(ctx)
	if err != nil {
		return api.AWSOrganizationInventorySnapshot{}, err
	}
	units := make([]api.AWSOrganizationInventoryOU, 0)
	accounts := make([]api.AWSOrganizationInventoryAccount, 0)
	for _, root := range roots {
		rootAccounts, rootUnits, err := i.walkParent(ctx, root, managementAccountID, delegatedServices)
		if err != nil {
			return api.AWSOrganizationInventorySnapshot{}, err
		}
		accounts = append(accounts, rootAccounts...)
		units = append(units, rootUnits...)
	}
	stackInstances, err := i.listStackInstances(ctx, request)
	if err != nil {
		return api.AWSOrganizationInventorySnapshot{}, err
	}
	sort.Slice(accounts, func(left, right int) bool { return accounts[left].AccountID < accounts[right].AccountID })
	sort.Slice(units, func(left, right int) bool { return units[left].Path < units[right].Path })
	observedAt := time.Now().UTC()
	if i.now != nil {
		observedAt = i.now().UTC()
	}
	return api.AWSOrganizationInventorySnapshot{
		OrganizationID:      organizationID,
		ManagementAccountID: managementAccountID,
		Partition:           awsPartitionFromOrganizationARN(awsv2.ToString(described.Organization.Arn)),
		Roots:               roots,
		OrganizationalUnits: units,
		Accounts:            accounts,
		StackInstances:      stackInstances,
		ObservedAt:          observedAt,
	}, nil
}

func (i *SDKOrganizationInventory) listRoots(ctx context.Context) ([]api.AWSOrganizationInventoryOU, error) {
	var out []api.AWSOrganizationInventoryOU
	var nextToken *string
	for page := 0; page < maxAWSOrganizationInventoryPages; page++ {
		response, err := i.organizations.ListRoots(ctx, &organizations.ListRootsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list aws organization roots: %w", err)
		}
		for _, root := range response.Roots {
			id := strings.TrimSpace(awsv2.ToString(root.Id))
			if id == "" {
				continue
			}
			out = append(out, api.AWSOrganizationInventoryOU{ID: id, Name: strings.TrimSpace(awsv2.ToString(root.Name)), Path: "/", AncestorIDs: []string{id}})
		}
		if strings.TrimSpace(awsv2.ToString(response.NextToken)) == "" {
			return out, nil
		}
		nextToken = response.NextToken
	}
	return nil, fmt.Errorf("list aws organization roots exceeded %d pages", maxAWSOrganizationInventoryPages)
}

func (i *SDKOrganizationInventory) walkParent(ctx context.Context, root api.AWSOrganizationInventoryOU, managementAccountID string, delegatedServices map[string][]string) ([]api.AWSOrganizationInventoryAccount, []api.AWSOrganizationInventoryOU, error) {
	queue := []api.AWSOrganizationInventoryOU{root}
	visited := map[string]struct{}{}
	var accounts []api.AWSOrganizationInventoryAccount
	var units []api.AWSOrganizationInventoryOU
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		if _, ok := visited[parent.ID]; ok {
			continue
		}
		visited[parent.ID] = struct{}{}
		children, err := i.listOrganizationalUnitsForParent(ctx, parent)
		if err != nil {
			return nil, nil, err
		}
		units = append(units, children...)
		queue = append(queue, children...)
		parentAccounts, err := i.listAccountsForParent(ctx, parent, managementAccountID, delegatedServices)
		if err != nil {
			return nil, nil, err
		}
		accounts = append(accounts, parentAccounts...)
	}
	return accounts, units, nil
}

func (i *SDKOrganizationInventory) listOrganizationalUnitsForParent(ctx context.Context, parent api.AWSOrganizationInventoryOU) ([]api.AWSOrganizationInventoryOU, error) {
	var out []api.AWSOrganizationInventoryOU
	var nextToken *string
	for page := 0; page < maxAWSOrganizationInventoryPages; page++ {
		response, err := i.organizations.ListOrganizationalUnitsForParent(ctx, &organizations.ListOrganizationalUnitsForParentInput{ParentId: awsv2.String(parent.ID), NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list organizational units for %s: %w", parent.ID, err)
		}
		for _, unit := range response.OrganizationalUnits {
			id := strings.TrimSpace(awsv2.ToString(unit.Id))
			name := strings.TrimSpace(awsv2.ToString(unit.Name))
			if id == "" {
				continue
			}
			path := strings.TrimSuffix(parent.Path, "/") + "/" + name
			ancestors := append(append([]string(nil), parent.AncestorIDs...), id)
			out = append(out, api.AWSOrganizationInventoryOU{ID: id, Name: name, ParentID: parent.ID, Path: path, AncestorIDs: ancestors})
		}
		if strings.TrimSpace(awsv2.ToString(response.NextToken)) == "" {
			return out, nil
		}
		nextToken = response.NextToken
	}
	return nil, fmt.Errorf("list organizational units for %s exceeded %d pages", parent.ID, maxAWSOrganizationInventoryPages)
}

func (i *SDKOrganizationInventory) listAccountsForParent(ctx context.Context, parent api.AWSOrganizationInventoryOU, managementAccountID string, delegatedServices map[string][]string) ([]api.AWSOrganizationInventoryAccount, error) {
	var out []api.AWSOrganizationInventoryAccount
	var nextToken *string
	for page := 0; page < maxAWSOrganizationInventoryPages; page++ {
		response, err := i.organizations.ListAccountsForParent(ctx, &organizations.ListAccountsForParentInput{ParentId: awsv2.String(parent.ID), NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list accounts for %s: %w", parent.ID, err)
		}
		for _, account := range response.Accounts {
			accountID := strings.TrimSpace(awsv2.ToString(account.Id))
			if accountID == "" {
				continue
			}
			status := strings.ToLower(strings.TrimSpace(string(account.State)))
			if status == "" {
				status = strings.ToLower(strings.TrimSpace(string(account.Status)))
			}
			out = append(out, api.AWSOrganizationInventoryAccount{
				AccountID:              accountID,
				Name:                   strings.TrimSpace(awsv2.ToString(account.Name)),
				Status:                 status,
				ParentID:               parent.ID,
				OUPath:                 parent.Path,
				AncestorIDs:            append([]string(nil), parent.AncestorIDs...),
				Management:             accountID == managementAccountID,
				DelegatedAdminServices: append([]string(nil), delegatedServices[accountID]...),
			})
		}
		if strings.TrimSpace(awsv2.ToString(response.NextToken)) == "" {
			return out, nil
		}
		nextToken = response.NextToken
	}
	return nil, fmt.Errorf("list accounts for %s exceeded %d pages", parent.ID, maxAWSOrganizationInventoryPages)
}

func (i *SDKOrganizationInventory) listDelegatedAdminServices(ctx context.Context) (map[string][]string, error) {
	delegated := map[string][]string{}
	var nextToken *string
	for page := 0; page < maxAWSOrganizationInventoryPages; page++ {
		response, err := i.organizations.ListDelegatedAdministrators(ctx, &organizations.ListDelegatedAdministratorsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list delegated administrators: %w", err)
		}
		for _, administrator := range response.DelegatedAdministrators {
			accountID := strings.TrimSpace(awsv2.ToString(administrator.Id))
			if accountID == "" {
				continue
			}
			services, err := i.listDelegatedServicesForAccount(ctx, accountID)
			if err != nil {
				return nil, err
			}
			delegated[accountID] = services
		}
		if strings.TrimSpace(awsv2.ToString(response.NextToken)) == "" {
			return delegated, nil
		}
		nextToken = response.NextToken
	}
	return nil, fmt.Errorf("list delegated administrators exceeded %d pages", maxAWSOrganizationInventoryPages)
}

func (i *SDKOrganizationInventory) listDelegatedServicesForAccount(ctx context.Context, accountID string) ([]string, error) {
	var out []string
	var nextToken *string
	for page := 0; page < maxAWSOrganizationInventoryPages; page++ {
		response, err := i.organizations.ListDelegatedServicesForAccount(ctx, &organizations.ListDelegatedServicesForAccountInput{AccountId: awsv2.String(accountID), NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list delegated services for %s: %w", accountID, err)
		}
		for _, service := range response.DelegatedServices {
			if principal := strings.TrimSpace(awsv2.ToString(service.ServicePrincipal)); principal != "" {
				out = append(out, principal)
			}
		}
		if strings.TrimSpace(awsv2.ToString(response.NextToken)) == "" {
			sort.Strings(out)
			return out, nil
		}
		nextToken = response.NextToken
	}
	return nil, fmt.Errorf("list delegated services for %s exceeded %d pages", accountID, maxAWSOrganizationInventoryPages)
}

func (i *SDKOrganizationInventory) listStackInstances(ctx context.Context, request api.AWSOrganizationInventoryRequest) ([]api.AWSOrganizationStackInstance, error) {
	stackSetName := strings.TrimSpace(request.StackSetName)
	if stackSetName == "" || i.cloudFormation == nil {
		return nil, nil
	}
	callAs := cloudformationtypes.CallAsSelf
	if strings.EqualFold(strings.TrimSpace(request.ControllingRole), "delegated_admin") {
		callAs = cloudformationtypes.CallAsDelegatedAdmin
	}
	var out []api.AWSOrganizationStackInstance
	var nextToken *string
	for page := 0; page < maxAWSOrganizationInventoryPages; page++ {
		response, err := i.cloudFormation.ListStackInstances(ctx, &cloudformation.ListStackInstancesInput{StackSetName: awsv2.String(stackSetName), CallAs: callAs, NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list stack instances for %s: %w", stackSetName, err)
		}
		observedAt := time.Now().UTC()
		if i.now != nil {
			observedAt = i.now().UTC()
		}
		for _, instance := range response.Summaries {
			detailed := ""
			if instance.StackInstanceStatus != nil {
				detailed = strings.ToLower(strings.TrimSpace(string(instance.StackInstanceStatus.DetailedStatus)))
			}
			out = append(out, api.AWSOrganizationStackInstance{
				AccountID:            strings.TrimSpace(awsv2.ToString(instance.Account)),
				Region:               strings.ToLower(strings.TrimSpace(awsv2.ToString(instance.Region))),
				OrganizationalUnitID: strings.TrimSpace(awsv2.ToString(instance.OrganizationalUnitId)),
				StackSetID:           strings.TrimSpace(awsv2.ToString(instance.StackSetId)),
				StackID:              strings.TrimSpace(awsv2.ToString(instance.StackId)),
				Status:               strings.ToLower(strings.TrimSpace(string(instance.Status))),
				DetailedStatus:       detailed,
				DriftStatus:          strings.ToLower(strings.TrimSpace(string(instance.DriftStatus))),
				StatusReason:         strings.TrimSpace(awsv2.ToString(instance.StatusReason)),
				LastOperationID:      strings.TrimSpace(awsv2.ToString(instance.LastOperationId)),
				ObservedAt:           observedAt,
			})
		}
		if strings.TrimSpace(awsv2.ToString(response.NextToken)) == "" {
			return out, nil
		}
		nextToken = response.NextToken
	}
	return nil, fmt.Errorf("list stack instances for %s exceeded %d pages", stackSetName, maxAWSOrganizationInventoryPages)
}

func awsPartitionFromOrganizationARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
		return strings.TrimSpace(parts[1])
	}
	return "aws"
}
