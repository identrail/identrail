package aws

import (
	"context"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	api "github.com/identrail/identrail/internal/api"
)

type fakeOrganizationsInventoryAPI struct{}

func (fakeOrganizationsInventoryAPI) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{Organization: &organizationtypes.Organization{
		Id: awsv2.String("o-example12345"), MasterAccountId: awsv2.String("111111111111"), Arn: awsv2.String("arn:aws:organizations::111111111111:organization/o-example12345"),
	}}, nil
}

func (fakeOrganizationsInventoryAPI) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: []organizationtypes.Root{{Id: awsv2.String("r-root"), Name: awsv2.String("Root")}}}, nil
}

func (fakeOrganizationsInventoryAPI) ListOrganizationalUnitsForParent(_ context.Context, input *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if awsv2.ToString(input.ParentId) == "r-root" {
		return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: []organizationtypes.OrganizationalUnit{{Id: awsv2.String("ou-prod-12345678"), Name: awsv2.String("Production")}}}, nil
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
}

func (fakeOrganizationsInventoryAPI) ListAccountsForParent(_ context.Context, input *organizations.ListAccountsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	switch awsv2.ToString(input.ParentId) {
	case "r-root":
		return &organizations.ListAccountsForParentOutput{Accounts: []organizationtypes.Account{{Id: awsv2.String("111111111111"), Name: awsv2.String("management"), State: organizationtypes.AccountStateActive}}}, nil
	case "ou-prod-12345678":
		return &organizations.ListAccountsForParentOutput{Accounts: []organizationtypes.Account{{Id: awsv2.String("222222222222"), Name: awsv2.String("production"), State: organizationtypes.AccountStateActive}}}, nil
	default:
		return &organizations.ListAccountsForParentOutput{}, nil
	}
}

func (fakeOrganizationsInventoryAPI) ListDelegatedAdministrators(context.Context, *organizations.ListDelegatedAdministratorsInput, ...func(*organizations.Options)) (*organizations.ListDelegatedAdministratorsOutput, error) {
	return &organizations.ListDelegatedAdministratorsOutput{DelegatedAdministrators: []organizationtypes.DelegatedAdministrator{{Id: awsv2.String("222222222222")}}}, nil
}

func (fakeOrganizationsInventoryAPI) ListDelegatedServicesForAccount(context.Context, *organizations.ListDelegatedServicesForAccountInput, ...func(*organizations.Options)) (*organizations.ListDelegatedServicesForAccountOutput, error) {
	return &organizations.ListDelegatedServicesForAccountOutput{DelegatedServices: []organizationtypes.DelegatedService{{ServicePrincipal: awsv2.String("member.org.stacksets.cloudformation.amazonaws.com")}}}, nil
}

type fakeCloudFormationInventoryAPI struct{}

func (fakeCloudFormationInventoryAPI) ListStackInstances(context.Context, *cloudformation.ListStackInstancesInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackInstancesOutput, error) {
	return &cloudformation.ListStackInstancesOutput{Summaries: []cloudformationtypes.StackInstanceSummary{{
		Account: awsv2.String("222222222222"), Region: awsv2.String("us-east-1"), StackSetId: awsv2.String("stackset-1"), StackId: awsv2.String("stack-1"),
		Status: cloudformationtypes.StackInstanceStatusCurrent, DriftStatus: cloudformationtypes.StackDriftStatusInSync,
	}}}, nil
}

func TestSDKOrganizationInventoryDiscoversNestedScopeAndStackInstances(t *testing.T) {
	inventory := NewSDKOrganizationInventoryFromClients(fakeOrganizationsInventoryAPI{}, fakeCloudFormationInventoryAPI{})
	snapshot, err := inventory.Discover(context.Background(), api.AWSOrganizationInventoryRequest{StackSetName: "identrail-readonly", ControllingRole: "delegated_admin"})
	if err != nil {
		t.Fatalf("discover inventory: %v", err)
	}
	if snapshot.OrganizationID != "o-example12345" || snapshot.ManagementAccountID != "111111111111" || snapshot.Partition != "aws" {
		t.Fatalf("unexpected organization identity: %+v", snapshot)
	}
	if len(snapshot.Accounts) != 2 || len(snapshot.OrganizationalUnits) != 1 || len(snapshot.StackInstances) != 1 {
		t.Fatalf("unexpected inventory size: accounts=%d ous=%d instances=%d", len(snapshot.Accounts), len(snapshot.OrganizationalUnits), len(snapshot.StackInstances))
	}
	for _, account := range snapshot.Accounts {
		if account.AccountID == "222222222222" {
			if account.OUPath != "/Production" || len(account.AncestorIDs) != 2 || len(account.DelegatedAdminServices) != 1 {
				t.Fatalf("unexpected delegated account: %+v", account)
			}
			return
		}
	}
	t.Fatal("expected production account")
}
