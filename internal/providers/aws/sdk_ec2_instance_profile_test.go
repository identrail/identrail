package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeEC2SDKClient struct {
	describeInstancesInput                *ec2.DescribeInstancesInput
	describeLaunchTemplatesInput          *ec2.DescribeLaunchTemplatesInput
	describeLaunchTemplateVersionsInput   *ec2.DescribeLaunchTemplateVersionsInput
	describeLaunchTemplateVersionsInputs  []*ec2.DescribeLaunchTemplateVersionsInput
	describeInstancesOutput               *ec2.DescribeInstancesOutput
	describeLaunchTemplatesOutput         *ec2.DescribeLaunchTemplatesOutput
	describeLaunchTemplateVersionsOut     *ec2.DescribeLaunchTemplateVersionsOutput
	describeLaunchTemplateVersionsOutputs []*ec2.DescribeLaunchTemplateVersionsOutput
	describeInstancesErr                  error
	describeLaunchTemplatesErr            error
	describeLaunchTemplateVersionsErr     error
}

func (f *fakeEC2SDKClient) DescribeInstances(_ context.Context, params *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.describeInstancesInput = params
	if f.describeInstancesErr != nil {
		return nil, f.describeInstancesErr
	}
	return f.describeInstancesOutput, nil
}

func (f *fakeEC2SDKClient) DescribeLaunchTemplates(_ context.Context, params *ec2.DescribeLaunchTemplatesInput, _ ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error) {
	f.describeLaunchTemplatesInput = params
	if f.describeLaunchTemplatesErr != nil {
		return nil, f.describeLaunchTemplatesErr
	}
	return f.describeLaunchTemplatesOutput, nil
}

func (f *fakeEC2SDKClient) DescribeLaunchTemplateVersions(_ context.Context, params *ec2.DescribeLaunchTemplateVersionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	f.describeLaunchTemplateVersionsInput = params
	f.describeLaunchTemplateVersionsInputs = append(f.describeLaunchTemplateVersionsInputs, params)
	if f.describeLaunchTemplateVersionsErr != nil {
		return nil, f.describeLaunchTemplateVersionsErr
	}
	if len(f.describeLaunchTemplateVersionsOutputs) > 0 {
		idx := len(f.describeLaunchTemplateVersionsInputs) - 1
		if idx >= len(f.describeLaunchTemplateVersionsOutputs) {
			return &ec2.DescribeLaunchTemplateVersionsOutput{}, nil
		}
		return f.describeLaunchTemplateVersionsOutputs[idx], nil
	}
	return f.describeLaunchTemplateVersionsOut, nil
}

type fakeIAMInstanceProfileSDKClient struct {
	profiles map[string][]iamtypes.Role
	calls    []string
	err      error
}

func (f *fakeIAMInstanceProfileSDKClient) GetInstanceProfile(_ context.Context, params *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	name := strings.TrimSpace(awsv2.ToString(params.InstanceProfileName))
	f.calls = append(f.calls, name)
	if f.err != nil {
		return nil, f.err
	}
	return &iam.GetInstanceProfileOutput{
		InstanceProfile: &iamtypes.InstanceProfile{
			Arn:                 awsv2.String("arn:aws:iam::123456789012:instance-profile/" + name),
			InstanceProfileId:   awsv2.String("profile-id-" + name),
			InstanceProfileName: awsv2.String(name),
			Roles:               append([]iamtypes.Role(nil), f.profiles[name]...),
		},
	}, nil
}

func TestSDKEC2InstanceProfileAPIMapsInstancesAndLaunchTemplates(t *testing.T) {
	ec2Client := &fakeEC2SDKClient{
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{{
					InstanceId: awsv2.String("i-0477"),
					IamInstanceProfile: &ec2types.IamInstanceProfile{
						Arn: awsv2.String("arn:aws:iam::123456789012:instance-profile/payments-profile"),
						Id:  awsv2.String("AIPAJ477EXAMPLE"),
					},
					MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
						HttpEndpoint:            ec2types.InstanceMetadataEndpointStateEnabled,
						HttpTokens:              ec2types.HttpTokensStateRequired,
						HttpPutResponseHopLimit: awsv2.Int32(2),
					},
					State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					Tags: []ec2types.Tag{
						{Key: awsv2.String("Name"), Value: awsv2.String("payments-api")},
						{Key: awsv2.String("owner"), Value: awsv2.String("platform")},
					},
				}},
			}},
		},
		describeLaunchTemplatesOutput: &ec2.DescribeLaunchTemplatesOutput{
			LaunchTemplates: []ec2types.LaunchTemplate{{
				LaunchTemplateId:     awsv2.String("lt-0477"),
				LaunchTemplateName:   awsv2.String("payments-template"),
				DefaultVersionNumber: awsv2.Int64(2),
				LatestVersionNumber:  awsv2.Int64(2),
			}},
		},
		describeLaunchTemplateVersionsOut: &ec2.DescribeLaunchTemplateVersionsOutput{
			LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{{
				VersionNumber: awsv2.Int64(2),
				LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
					IamInstanceProfile: &ec2types.LaunchTemplateIamInstanceProfileSpecification{
						Name: awsv2.String("template-profile"),
					},
				},
			}},
		},
	}
	iamClient := &fakeIAMInstanceProfileSDKClient{
		profiles: map[string][]iamtypes.Role{
			"payments-profile": {
				{
					Arn:      awsv2.String("arn:aws:iam::123456789012:role/payments-ec2"),
					RoleName: awsv2.String("payments-ec2"),
				},
			},
			"template-profile": {
				{
					Arn:      awsv2.String("arn:aws:iam::123456789012:role/template-ec2"),
					RoleName: awsv2.String("template-ec2"),
				},
			},
		},
	}
	api := NewSDKEC2InstanceProfileAPIFromClients(ec2Client, iamClient, "123456789012", "us-east-1")

	instancePage, err := api.ListInstanceProfiles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list instances: %v", err)
	}
	if got := awsv2.ToInt32(ec2Client.describeInstancesInput.MaxResults); got != 25 {
		t.Fatalf("DescribeInstances MaxResults = %d, want 25", got)
	}
	if instancePage.NextToken != launchTemplatePageTokenPrefix || len(instancePage.Records) != 1 {
		t.Fatalf("unexpected instance page: %+v", instancePage)
	}
	instance := instancePage.Records[0]
	if instance.WorkloadID != "i-0477" || instance.WorkloadName != "payments-api" || instance.RoleName != "payments-ec2" {
		t.Fatalf("unexpected instance record: %+v", instance)
	}
	if instance.InstanceARN != "arn:aws:ec2:us-east-1:123456789012:instance/i-0477" || instance.IMDSHTTPTokens != "required" || instance.IMDSHopLimit != 2 {
		t.Fatalf("expected instance ARN and IMDS posture, got %+v", instance)
	}

	templatePage, err := api.ListInstanceProfiles(context.Background(), instancePage.NextToken, 25)
	if err != nil {
		t.Fatalf("list launch templates: %v", err)
	}
	if templatePage.NextToken != "" || len(templatePage.Records) != 1 {
		t.Fatalf("unexpected launch template page: %+v", templatePage)
	}
	if got := awsv2.ToString(ec2Client.describeLaunchTemplateVersionsInput.LaunchTemplateId); got != "lt-0477" {
		t.Fatalf("DescribeLaunchTemplateVersions template id = %q", got)
	}
	if got := ec2Client.describeLaunchTemplateVersionsInput.Versions; len(got) != 0 {
		t.Fatalf("expected all launch template versions to be scanned, got filter %+v", got)
	}
	template := templatePage.Records[0]
	if template.WorkloadType != "ec2_launch_template" || template.WorkloadID != "lt-0477:2" || template.RoleName != "template-ec2" {
		t.Fatalf("unexpected launch template record: %+v", template)
	}
	if template.InstanceProfileARN != "arn:aws:iam::123456789012:instance-profile/template-profile" || template.InstanceProfileID != "profile-id-template-profile" {
		t.Fatalf("expected launch template instance profile metadata from IAM, got %+v", template)
	}
	if len(iamClient.calls) != 2 || iamClient.calls[0] != "payments-profile" || iamClient.calls[1] != "template-profile" {
		t.Fatalf("unexpected IAM profile lookups: %+v", iamClient.calls)
	}
}

func TestSDKEC2InstanceProfileAPISkipsTerminalInstances(t *testing.T) {
	ec2Client := &fakeEC2SDKClient{
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{
					{
						InstanceId: awsv2.String("i-shutting-down"),
						IamInstanceProfile: &ec2types.IamInstanceProfile{
							Arn: awsv2.String("arn:aws:iam::123456789012:instance-profile/terminal-profile"),
						},
						State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameShuttingDown},
					},
					{
						InstanceId: awsv2.String("i-terminated"),
						IamInstanceProfile: &ec2types.IamInstanceProfile{
							Arn: awsv2.String("arn:aws:iam::123456789012:instance-profile/terminal-profile"),
						},
						State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameTerminated},
					},
					{
						InstanceId: awsv2.String("i-no-profile"),
						State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			}},
		},
	}
	api := NewSDKEC2InstanceProfileAPIFromClients(ec2Client, nil, "123456789012", "us-east-1")

	page, err := api.ListInstanceProfiles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list instances: %v", err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("expected terminal instances to be skipped, got %+v", page.Records)
	}
	if page.NextToken != launchTemplatePageTokenPrefix {
		t.Fatalf("expected scan to advance to launch templates, got next token %q", page.NextToken)
	}
	if !isTerminalEC2InstanceState(ec2types.InstanceStateNameShuttingDown) || !isTerminalEC2InstanceState(ec2types.InstanceStateNameTerminated) {
		t.Fatal("expected shutting-down and terminated states to be terminal")
	}
	if isTerminalEC2InstanceState(ec2types.InstanceStateNameStopped) {
		t.Fatal("expected stopped instances to remain collectible")
	}
}

func TestSDKEC2InstanceProfileAPIScansAllLaunchTemplateVersionPages(t *testing.T) {
	ec2Client := &fakeEC2SDKClient{
		describeLaunchTemplatesOutput: &ec2.DescribeLaunchTemplatesOutput{
			LaunchTemplates: []ec2types.LaunchTemplate{{
				LaunchTemplateId:   awsv2.String("lt-all"),
				LaunchTemplateName: awsv2.String("all-versions-template"),
			}},
		},
		describeLaunchTemplateVersionsOutputs: []*ec2.DescribeLaunchTemplateVersionsOutput{
			{
				LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{{
					VersionNumber: awsv2.Int64(1),
					LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
						IamInstanceProfile: &ec2types.LaunchTemplateIamInstanceProfileSpecification{Name: awsv2.String("legacy-profile")},
					},
				}},
				NextToken: awsv2.String("versions-page-2"),
			},
			{
				LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{
					{
						VersionNumber: awsv2.Int64(3),
						LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
							IamInstanceProfile: &ec2types.LaunchTemplateIamInstanceProfileSpecification{Name: awsv2.String("pinned-profile")},
						},
					},
					{
						VersionNumber:      awsv2.Int64(4),
						LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{},
					},
				},
			},
		},
	}
	iamClient := &fakeIAMInstanceProfileSDKClient{
		profiles: map[string][]iamtypes.Role{
			"legacy-profile": {
				{Arn: awsv2.String("arn:aws:iam::123456789012:role/legacy-role"), RoleName: awsv2.String("legacy-role")},
			},
			"pinned-profile": {
				{Arn: awsv2.String("arn:aws:iam::123456789012:role/pinned-role"), RoleName: awsv2.String("pinned-role")},
			},
		},
	}
	api := NewSDKEC2InstanceProfileAPIFromClients(ec2Client, iamClient, "123456789012", "us-east-1")

	page, err := api.ListInstanceProfiles(context.Background(), launchTemplatePageTokenPrefix, 25)
	if err != nil {
		t.Fatalf("list launch templates: %v", err)
	}
	if len(ec2Client.describeLaunchTemplateVersionsInputs) != 2 {
		t.Fatalf("expected launch template versions to be paged, got %d calls", len(ec2Client.describeLaunchTemplateVersionsInputs))
	}
	firstInput := ec2Client.describeLaunchTemplateVersionsInputs[0]
	if got := awsv2.ToString(firstInput.LaunchTemplateId); got != "lt-all" {
		t.Fatalf("DescribeLaunchTemplateVersions template id = %q", got)
	}
	if len(firstInput.Versions) != 0 {
		t.Fatalf("expected no launch template version filter, got %+v", firstInput.Versions)
	}
	if got := awsv2.ToString(ec2Client.describeLaunchTemplateVersionsInputs[1].NextToken); got != "versions-page-2" {
		t.Fatalf("expected second versions page token, got %q", got)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected records from non-default launch template versions, got %+v", page.Records)
	}
	if page.Records[0].WorkloadID != "lt-all:1" || page.Records[0].RoleName != "legacy-role" {
		t.Fatalf("unexpected first launch template record: %+v", page.Records[0])
	}
	if page.Records[1].WorkloadID != "lt-all:3" || page.Records[1].RoleName != "pinned-role" {
		t.Fatalf("unexpected second launch template record: %+v", page.Records[1])
	}
	if page.Records[1].InstanceProfileARN != "arn:aws:iam::123456789012:instance-profile/pinned-profile" || page.Records[1].InstanceProfileID != "profile-id-pinned-profile" {
		t.Fatalf("expected IAM profile metadata for name-only launch template profile, got %+v", page.Records[1])
	}
}

func TestSDKEC2InstanceProfileAPIHandlesClientErrorsAndHelpers(t *testing.T) {
	missingEC2 := NewSDKEC2InstanceProfileAPIFromClients(nil, nil, "123456789012", "us-east-1")
	if _, err := missingEC2.ListInstanceProfiles(context.Background(), "", 10); err == nil {
		t.Fatal("expected missing EC2 client error")
	}

	ec2Client := &fakeEC2SDKClient{
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{{
					InstanceId: awsv2.String("i-unresolved"),
					IamInstanceProfile: &ec2types.IamInstanceProfile{
						Arn: awsv2.String("arn:aws:iam::123456789012:instance-profile/unresolved-profile"),
					},
				}},
			}},
		},
	}
	missingIAM := NewSDKEC2InstanceProfileAPIFromClients(ec2Client, nil, "123456789012", "us-east-1")
	if _, err := missingIAM.ListInstanceProfiles(context.Background(), "", 10); err == nil || !strings.Contains(err.Error(), "iam sdk client is required") {
		t.Fatalf("expected missing IAM client error, got %v", err)
	}

	ec2Client.describeInstancesErr = errors.New("ec2 unavailable")
	if _, err := NewSDKEC2InstanceProfileAPIFromClients(ec2Client, nil, "123456789012", "us-east-1").ListInstanceProfiles(context.Background(), "", 10); err == nil || !strings.Contains(err.Error(), "ec2 unavailable") {
		t.Fatalf("expected EC2 error, got %v", err)
	}

	if arn, name := firstRoleIdentity([]iamtypes.Role{{Arn: awsv2.String("arn:aws:iam::123456789012:role/path/fallback")}}); name != "fallback" || !strings.Contains(arn, "fallback") {
		t.Fatalf("expected role name fallback from arn, got arn=%q name=%q", arn, name)
	}
	if got := instanceProfileNameFromARN("arn:aws:iam::123456789012:instance-profile/path/payments-profile"); got != "payments-profile" {
		t.Fatalf("instance profile name = %q", got)
	}
	if got := copyEC2Tags([]ec2types.Tag{{Key: awsv2.String(""), Value: awsv2.String("skip")}}); got != nil {
		t.Fatalf("expected empty tag key to be skipped, got %+v", got)
	}
}
