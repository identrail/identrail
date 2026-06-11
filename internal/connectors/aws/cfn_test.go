package aws

import (
	"net/url"
	"strings"
	"testing"
)

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
