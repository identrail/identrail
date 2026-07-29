package aws

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestReadOnlyTemplateAutomaticRegistrationContract(t *testing.T) {
	templatePath := filepath.Join("..", "..", "..", "deploy", "connectors", "aws", "identrail-readonly.yaml")
	body, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("read CloudFormation template: %v", err)
	}
	var template map[string]any
	if err := yaml.Unmarshal(body, &template); err != nil {
		t.Fatalf("parse CloudFormation template: %v", err)
	}
	parameters := requireYAMLMap(t, template, "Parameters")
	registrationToken := requireYAMLMap(t, parameters, "RegistrationToken")
	if _, hasNoEcho := registrationToken["NoEcho"]; hasNoEcho {
		t.Fatal("RegistrationToken must remain prefillable by AWS quick-create; it is short-lived and grants no AWS access")
	}
	externalID := requireYAMLMap(t, parameters, "ExternalId")
	if externalID["NoEcho"] != true {
		t.Fatal("troubleshooting ExternalId must remain masked")
	}
	resources := requireYAMLMap(t, template, "Resources")
	bootstrap := requireYAMLMap(t, resources, "IdentrailRegistrationBootstrap")
	bootstrapProperties := requireYAMLMap(t, bootstrap, "Properties")
	if bootstrap["Type"] != "Custom::IdentrailAWSConnectorBootstrap" || bootstrapProperties["RegistrationToken"] == nil {
		t.Fatalf("bootstrap must receive the one-time registration token: %+v", bootstrap)
	}
	registration := requireYAMLMap(t, resources, "IdentrailConnectorRegistration")
	registrationProperties := requireYAMLMap(t, registration, "Properties")
	if registration["Type"] != "Custom::IdentrailAWSConnectorRegistration" || registration["DependsOn"] == nil {
		t.Fatalf("registration must wait for the role: %+v", registration)
	}
	if _, leaksToken := registrationProperties["RegistrationToken"]; leaksToken {
		t.Fatal("registration phase must use the stack-bound bootstrap result, not replay the launch token")
	}
}

func requireYAMLMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %s to be a map, got %#v", key, parent[key])
	}
	return value
}

func TestBuildCloudFormationLaunchURL(t *testing.T) {
	tests := []struct {
		name       string
		region     string
		wantHost   string
		wantRegion string
	}{
		{
			name:       "commercial region",
			region:     "eu-west-1",
			wantHost:   "console.aws.amazon.com",
			wantRegion: "eu-west-1",
		},
		{
			name:       "govcloud region",
			region:     "us-gov-west-1",
			wantHost:   "console.amazonaws-us-gov.com",
			wantRegion: "us-gov-west-1",
		},
		{
			name:       "china region",
			region:     "cn-north-1",
			wantHost:   "console.amazonaws.cn",
			wantRegion: "cn-north-1",
		},
		{
			name:       "invalid region defaults to commercial us east",
			region:     "not-a-region",
			wantHost:   "console.aws.amazon.com",
			wantRegion: "us-east-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launchURL := BuildCloudFormationLaunchURL(CloudFormationLaunchInput{
				TemplateURL:        "https://cdn.example.com/identrail-readonly.yaml",
				Region:             tt.region,
				StackName:          "identrail-prod",
				IdentrailAccountID: "123456789012",
				ExternalID:         "external-id",
				RoleName:           "IdentrailReadOnlyProd",
			})

			parsed, err := url.Parse(launchURL)
			if err != nil {
				t.Fatalf("parse launch URL: %v", err)
			}
			if parsed.Scheme != "https" || parsed.Host != tt.wantHost {
				t.Fatalf("unexpected console URL: %s", launchURL)
			}
			if got := parsed.Query().Get("region"); got != tt.wantRegion {
				t.Fatalf("expected region %s, got %q", tt.wantRegion, got)
			}
			if !strings.Contains(parsed.Fragment, "templateURL=https://cdn.example.com/identrail-readonly.yaml") {
				t.Fatalf("expected encoded template URL in fragment, got %q", parsed.Fragment)
			}
			if !strings.Contains(parsed.Fragment, "param_IdentrailAccountId=123456789012") {
				t.Fatalf("expected Identrail account id in fragment, got %q", parsed.Fragment)
			}
			if !strings.Contains(parsed.Fragment, "param_ExternalId=external-id") {
				t.Fatalf("expected external id in fragment, got %q", parsed.Fragment)
			}
		})
	}
}

func TestBuildCloudFormationLaunchURLAutomaticRegistration(t *testing.T) {
	launchURL := BuildCloudFormationLaunchURL(CloudFormationLaunchInput{
		TemplateURL:             "https://cdn.example.com/identrail-readonly.yaml",
		Region:                  "us-east-1",
		StackName:               "identrail-prod",
		IdentrailAccountID:      "123456789012",
		ExternalID:              "external-id-should-not-appear",
		RoleName:                "IdentrailReadOnlyProd",
		RegistrationProviderARN: "arn:aws:sns:us-east-1:123456789012:identrail-registration",
		RegistrationAttemptID:   "attempt-abc-123",
		RegistrationToken:       "token-xyz-789",
	})

	parsed, err := url.Parse(launchURL)
	if err != nil {
		t.Fatalf("parse launch URL: %v", err)
	}
	if !strings.Contains(parsed.Fragment, "param_RegistrationProviderArn=arn:aws:sns:us-east-1:123456789012:identrail-registration") {
		t.Fatalf("expected registration provider ARN in fragment, got %q", parsed.Fragment)
	}
	if !strings.Contains(parsed.Fragment, "param_RegistrationAttemptId=attempt-abc-123") {
		t.Fatalf("expected registration attempt id in fragment, got %q", parsed.Fragment)
	}
	if !strings.Contains(parsed.Fragment, "param_RegistrationToken=token-xyz-789") {
		t.Fatalf("expected registration token in fragment, got %q", parsed.Fragment)
	}
	if strings.Contains(parsed.Fragment, "param_ExternalId") {
		t.Fatalf("automatic registration must not surface param_ExternalId, got %q", parsed.Fragment)
	}
}

func TestBuildCloudFormationStackSetLaunchURL(t *testing.T) {
	autoDeploy := false
	launchURL := BuildCloudFormationStackSetLaunchURL(CloudFormationStackSetLaunchInput{
		TemplateURL:                  "https://cdn.example.com/identrail-readonly.yaml",
		Region:                       "us-east-1",
		StackSetName:                 "identrail-prod-stackset",
		IdentrailAccountID:           "123456789012",
		ExternalID:                   "external-id",
		RoleName:                     "IdentrailReadOnlyProd",
		PermissionModel:              StackSetLaunchPermissionModelServiceManaged,
		OrganizationalUnitIDs:        []string{"ou-xxxx-1", "ou-yyyy-2"},
		ExcludedAccountIDs:           []string{"999900001111"},
		TargetRegions:                []string{"us-east-1", "eu-west-1"},
		AutoDeploymentEnabled:        &autoDeploy,
		RetainStacksOnAccountRemoval: false,
	})
	parsed, err := url.Parse(launchURL)
	if err != nil || parsed.Scheme != "https" {
		t.Fatalf("parse stackset launch URL: %v / %s", err, launchURL)
	}
	if !strings.Contains(parsed.Fragment, "permissionModel=SERVICE_MANAGED") {
		t.Fatalf("expected permission model in fragment, got %q", parsed.Fragment)
	}
	if !strings.Contains(parsed.Fragment, "organizationalUnitIds=ou-xxxx-1,ou-yyyy-2") {
		t.Fatalf("expected OU ids in fragment, got %q", parsed.Fragment)
	}
	if !strings.Contains(parsed.Fragment, "excludedAccounts=999900001111") || !strings.Contains(parsed.Fragment, "accountFilterType=DIFFERENCE") {
		t.Fatalf("expected excluded account filter in fragment, got %q", parsed.Fragment)
	}
	if !strings.Contains(parsed.Fragment, "regions=us-east-1,eu-west-1") {
		t.Fatalf("expected target regions in fragment, got %q", parsed.Fragment)
	}
	if !strings.Contains(parsed.Fragment, "autoDeploymentEnabled=false") ||
		!strings.Contains(parsed.Fragment, "retainStacksOnAccountRemoval=false") {
		t.Fatalf("expected disabled auto-deployment setting in fragment, got %q", parsed.Fragment)
	}
	if !strings.Contains(parsed.Fragment, "stacksets/create") {
		t.Fatalf("expected stacksets/create fragment, got %q", parsed.Fragment)
	}

	autoDeploy = true
	filteredURL := BuildCloudFormationStackSetLaunchURL(CloudFormationStackSetLaunchInput{
		TemplateURL:                  "https://cdn.example.com/identrail-readonly.yaml",
		Region:                       "us-east-1",
		PermissionModel:              StackSetLaunchPermissionModelServiceManaged,
		OrganizationalUnitIDs:        []string{"r-abcd"},
		TargetAccountIDs:             []string{"111122223333"},
		TargetRegions:                []string{"us-east-1"},
		AutoDeploymentEnabled:        &autoDeploy,
		RetainStacksOnAccountRemoval: false,
	})
	filteredParsed, err := url.Parse(filteredURL)
	if err != nil {
		t.Fatalf("parse filtered stackset launch URL: %v", err)
	}
	if !strings.Contains(filteredParsed.Fragment, "organizationalUnitIds=r-abcd") ||
		!strings.Contains(filteredParsed.Fragment, "accounts=111122223333") ||
		!strings.Contains(filteredParsed.Fragment, "accountFilterType=INTERSECTION") {
		t.Fatalf("expected root plus selected-account intersection filter, got %q", filteredParsed.Fragment)
	}
	if !strings.Contains(filteredParsed.Fragment, "autoDeploymentEnabled=true") {
		t.Fatalf("expected enabled auto-deployment setting, got %q", filteredParsed.Fragment)
	}

	// Missing template URL yields empty so the surface can render a blocked state instead of a malformed URL.
	if got := BuildCloudFormationStackSetLaunchURL(CloudFormationStackSetLaunchInput{Region: "us-east-1"}); got != "" {
		t.Fatalf("expected empty URL without template, got %q", got)
	}

	// Unknown permission model defaults to service-managed.
	defaulted := BuildCloudFormationStackSetLaunchURL(CloudFormationStackSetLaunchInput{
		TemplateURL:     "https://cdn.example.com/identrail-readonly.yaml",
		Region:          "us-east-1",
		PermissionModel: StackSetLaunchPermissionModel("bogus"),
	})
	if !strings.Contains(defaulted, "permissionModel=SERVICE_MANAGED") {
		t.Fatalf("expected default service-managed model, got %q", defaulted)
	}
}

func TestNormalizeRegion(t *testing.T) {
	if got := NormalizeRegion("us-gov-west-1"); got != "us-gov-west-1" {
		t.Fatalf("expected gov region to be preserved, got %q", got)
	}
	if got := NormalizeRegion("not-a-region"); got != "us-east-1" {
		t.Fatalf("expected invalid region to default to us-east-1, got %q", got)
	}
}

func TestReadOnlyPolicyDocument(t *testing.T) {
	policy, err := ReadOnlyPolicyDocument()
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !strings.Contains(string(policy), "iam:SimulatePrincipalPolicy") {
		t.Fatalf("expected IAM simulation action in policy")
	}
	if !strings.Contains(string(policy), "eks:ListClusters") || !strings.Contains(string(policy), "eks:DescribePodIdentityAssociation") {
		t.Fatalf("expected EKS workload identity read actions in policy")
	}
	if !strings.Contains(string(policy), "codebuild:ListProjects") || !strings.Contains(string(policy), "codebuild:BatchGetProjects") {
		t.Fatalf("expected CodeBuild service role read actions in policy")
	}
	for _, action := range []string{
		"sagemaker:ListNotebookInstances",
		"sagemaker:DescribeNotebookInstance",
		"sagemaker:ListTrainingJobs",
		"sagemaker:DescribeTrainingJob",
		"sagemaker:ListProcessingJobs",
		"sagemaker:DescribeProcessingJob",
		"sagemaker:ListTransformJobs",
		"sagemaker:DescribeTransformJob",
		"sagemaker:ListModels",
		"sagemaker:DescribeModel",
		"sagemaker:ListEndpoints",
		"sagemaker:DescribeEndpoint",
		"sagemaker:DescribeEndpointConfig",
		"sagemaker:ListPipelines",
		"sagemaker:DescribePipeline",
		"sagemaker:ListDomains",
		"sagemaker:DescribeDomain",
	} {
		// Quote-wrap so DescribeEndpoint does not falsely match
		// DescribeEndpointConfig (and similar prefix overlaps).
		if !strings.Contains(string(policy), "\""+action+"\"") {
			t.Fatalf("expected SageMaker workload-role read action %q in policy", action)
		}
	}
	for _, mutating := range []string{
		"sagemaker:CreatePresignedNotebookInstanceUrl",
		"sagemaker:CreatePresignedDomainUrl",
		"sagemaker:InvokeEndpoint",
	} {
		if strings.Contains(string(policy), "\""+mutating+"\"") {
			t.Fatalf("connector policy must not include sensitive SageMaker action %q", mutating)
		}
	}
	for _, action := range []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketLocation",
		"s3:GetBucketPolicy",
		"s3:GetBucketPublicAccessBlock",
		"s3:GetBucketOwnershipControls",
		"s3:GetEncryptionConfiguration",
		"s3:GetBucketTagging",
		"s3:ListAccessPoints",
	} {
		if !strings.Contains(string(policy), "\""+action+"\"") {
			t.Fatalf("expected S3 reachability read action %q in policy", action)
		}
	}
	for _, sensitive := range []string{
		"s3:GetObject",
		"s3:GetObjectAcl",
		"s3:GetObjectVersion",
		"s3:ListBucket",
	} {
		if strings.Contains(string(policy), "\""+sensitive+"\"") {
			t.Fatalf("connector policy must not include object-level S3 action %q", sensitive)
		}
	}
	for _, action := range []string{
		"kms:ListKeys",
		"kms:DescribeKey",
		"kms:GetKeyPolicy",
		"kms:GetKeyRotationStatus",
		"kms:ListAliases",
		"kms:ListGrants",
		"kms:ListResourceTags",
	} {
		if !strings.Contains(string(policy), "\""+action+"\"") {
			t.Fatalf("expected KMS reachability read action %q in policy", action)
		}
	}
	for _, sensitive := range []string{
		"kms:Decrypt",
		"kms:Encrypt",
		"kms:GenerateDataKey",
		"kms:ReEncryptFrom",
		"kms:ReEncryptTo",
		"kms:Sign",
		"kms:Verify",
		"kms:CreateGrant",
		"kms:PutKeyPolicy",
		"kms:ScheduleKeyDeletion",
	} {
		if strings.Contains(string(policy), "\""+sensitive+"\"") {
			t.Fatalf("connector policy must not include cryptographic or mutating KMS action %q", sensitive)
		}
	}
	for _, action := range []string{
		"sqs:ListQueues",
		"sqs:GetQueueAttributes",
		"sqs:ListQueueTags",
		"sns:ListTopics",
		"sns:GetTopicAttributes",
		"sns:ListSubscriptionsByTopic",
		"sns:GetSubscriptionAttributes",
		"sns:ListTagsForResource",
	} {
		if !strings.Contains(string(policy), "\""+action+"\"") {
			t.Fatalf("expected SQS/SNS reachability read action %q in policy", action)
		}
	}
	for _, sensitive := range []string{
		"sqs:SendMessage",
		"sqs:ReceiveMessage",
		"sqs:DeleteMessage",
		"sqs:PurgeQueue",
		"sns:Publish",
		"sns:Subscribe",
		"sns:SetTopicAttributes",
	} {
		if strings.Contains(string(policy), "\""+sensitive+"\"") {
			t.Fatalf("connector policy must not include message or subscription action %q", sensitive)
		}
	}
	for _, action := range []string{
		"dynamodb:ListTables",
		"dynamodb:DescribeTable",
		"dynamodb:ListTagsOfResource",
		"dynamodb:GetResourcePolicy",
		"rds:DescribeDBInstances",
		"rds:DescribeDBClusters",
		"rds:DescribeDBProxies",
		"rds:ListTagsForResource",
	} {
		if !strings.Contains(string(policy), "\""+action+"\"") {
			t.Fatalf("expected DynamoDB/RDS reachability action %q in policy", action)
		}
	}
	if !permissionPreviewContainsService(PermissionPreview(), "DynamoDB/RDS") {
		t.Fatalf("expected DynamoDB/RDS permission preview entry")
	}
	hash, err := ReadOnlyPolicyHash()
	if err != nil {
		t.Fatalf("hash policy: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("expected sha256 hex hash, got %q", hash)
	}
	if len(PermissionPreview()) == 0 {
		t.Fatalf("expected permission preview entries")
	}
	if !permissionPreviewContainsService(PermissionPreview(), "EKS") {
		t.Fatalf("expected EKS permission preview entry")
	}
	if !permissionPreviewContainsService(PermissionPreview(), "CodeBuild") {
		t.Fatalf("expected CodeBuild permission preview entry")
	}
	if !permissionPreviewContainsService(PermissionPreview(), "SageMaker") {
		t.Fatalf("expected SageMaker permission preview entry")
	}
	if !permissionPreviewContainsService(PermissionPreview(), "S3") {
		t.Fatalf("expected S3 permission preview entry")
	}
	if !permissionPreviewContainsService(PermissionPreview(), "SQS/SNS") {
		t.Fatalf("expected SQS/SNS permission preview entry")
	}
}

func permissionPreviewContainsService(items []PermissionPreviewItem, service string) bool {
	for _, item := range items {
		if item.Service == service {
			return true
		}
	}
	return false
}
