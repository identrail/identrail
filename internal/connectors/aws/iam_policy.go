package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const readOnlyPolicyJSON = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IdentityTrustGraphReadOnlyIAM",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetInstanceProfile",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAccountAliases",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:SimulatePrincipalPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlyCompute",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeIamInstanceProfileAssociations",
        "ec2:DescribeInstances",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlyECS",
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:ListTaskDefinitions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlyCodeBuild",
      "Effect": "Allow",
      "Action": [
        "codebuild:BatchGetProjects",
        "codebuild:ListProjects"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlyEKS",
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:DescribeFargateProfile",
        "eks:DescribeNodegroup",
        "eks:DescribePodIdentityAssociation",
        "eks:ListClusters",
        "eks:ListFargateProfiles",
        "eks:ListNodegroups",
        "eks:ListPodIdentityAssociations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlySageMaker",
      "Effect": "Allow",
      "Action": [
        "sagemaker:DescribeDomain",
        "sagemaker:DescribeEndpoint",
        "sagemaker:DescribeEndpointConfig",
        "sagemaker:DescribeModel",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:DescribePipeline",
        "sagemaker:DescribeProcessingJob",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:DescribeTransformJob",
        "sagemaker:ListDomains",
        "sagemaker:ListEndpoints",
        "sagemaker:ListModels",
        "sagemaker:ListNotebookInstances",
        "sagemaker:ListPipelines",
        "sagemaker:ListProcessingJobs",
        "sagemaker:ListTrainingJobs",
        "sagemaker:ListTransformJobs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlyStorage",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "s3:ListAccessPoints",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlyKMS",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:ListKeys"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphCallerIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}`

// PermissionPreviewItem explains one AWS permission family before launch.
type PermissionPreviewItem struct {
	Service   string   `json:"service"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Reason    string   `json:"reason"`
}

// ReadOnlyPolicyDocument returns the validated collector policy JSON.
func ReadOnlyPolicyDocument() ([]byte, error) {
	policy := []byte(readOnlyPolicyJSON)
	if !json.Valid(policy) {
		return nil, fmt.Errorf("embedded AWS read-only policy is invalid JSON")
	}
	copied := append([]byte(nil), policy...)
	return copied, nil
}

// ReadOnlyPolicyHash returns a stable SHA-256 hash for drift detection.
func ReadOnlyPolicyHash() (string, error) {
	policy, err := ReadOnlyPolicyDocument()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(policy)
	return hex.EncodeToString(sum[:]), nil
}

// PermissionPreview returns human-readable rationale for the policy.
func PermissionPreview() []PermissionPreviewItem {
	return []PermissionPreviewItem{
		{
			Service:   "STS",
			Actions:   []string{"sts:GetCallerIdentity"},
			Resources: []string{"*"},
			Reason:    "Confirms Identrail is using the expected assumed role during validation and recurring scans.",
		},
		{
			Service: "IAM",
			Actions: []string{
				"iam:GetAccountSummary",
				"iam:ListAccountAliases",
				"iam:ListRoles",
				"iam:GetInstanceProfile",
				"iam:GetRole",
				"iam:ListRolePolicies",
				"iam:GetRolePolicy",
				"iam:ListAttachedRolePolicies",
				"iam:GetPolicy",
				"iam:GetPolicyVersion",
				"iam:SimulatePrincipalPolicy",
			},
			Resources: []string{"*"},
			Reason:    "Reads role trust policies, attached policy documents, and effective permissions for machine identity graph analysis.",
		},
		{
			Service: "EC2",
			Actions: []string{
				"ec2:DescribeInstances",
				"ec2:DescribeIamInstanceProfileAssociations",
				"ec2:DescribeLaunchTemplates",
				"ec2:DescribeLaunchTemplateVersions",
				"ec2:DescribeRegions",
			},
			Resources: []string{"*"},
			Reason:    "Maps EC2 instances and launch templates back to the IAM roles and instance profiles they can use.",
		},
		{
			Service: "ECS",
			Actions: []string{
				"ecs:ListClusters",
				"ecs:ListServices",
				"ecs:DescribeServices",
				"ecs:ListTaskDefinitions",
				"ecs:DescribeTaskDefinition",
			},
			Resources: []string{"*"},
			Reason:    "Maps ECS services and task definitions back to task roles, execution roles, container images, and metadata-only secret references.",
		},
		{
			Service: "CodeBuild",
			Actions: []string{
				"codebuild:ListProjects",
				"codebuild:BatchGetProjects",
			},
			Resources: []string{"*"},
			Reason:    "Maps CodeBuild projects back to service roles, project sources, artifacts, VPC metadata, and metadata-only secret references.",
		},
		{
			Service: "EKS",
			Actions: []string{
				"eks:ListClusters",
				"eks:DescribeCluster",
				"eks:ListPodIdentityAssociations",
				"eks:DescribePodIdentityAssociation",
				"eks:ListNodegroups",
				"eks:DescribeNodegroup",
				"eks:ListFargateProfiles",
				"eks:DescribeFargateProfile",
			},
			Resources: []string{"*"},
			Reason:    "Maps EKS Pod Identity associations, node roles, Fargate pod execution roles, and cluster OIDC metadata back to IAM roles without reading Kubernetes secrets or payloads.",
		},
		{
			Service: "SageMaker",
			Actions: []string{
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
			},
			Resources: []string{"*"},
			Reason:    "Maps SageMaker notebook, training, processing, transform, model, endpoint, pipeline, and Studio domain workloads back to their execution roles plus the S3 prefix, ECR image, and KMS key references those roles can reach. Metadata-only — no presigned notebook URLs, payload reads, model artifact reads, or endpoint invocations.",
		},
		{
			Service: "S3",
			Actions: []string{
				"s3:ListAllMyBuckets",
				"s3:GetBucketLocation",
				"s3:GetBucketAcl",
				"s3:GetBucketPolicy",
				"s3:GetBucketPublicAccessBlock",
				"s3:GetBucketOwnershipControls",
				"s3:GetEncryptionConfiguration",
				"s3:GetBucketTagging",
				"s3:ListAccessPoints",
			},
			Resources: []string{"*"},
			Reason:    "Reads bucket-level metadata (location, policy, public-access block, ownership controls, default encryption, tags) plus account-scoped access-point metadata to classify identity-to-bucket reachability. Never reads object contents, presigned URLs, or per-object ACLs.",
		},
		{
			Service:   "KMS",
			Actions:   []string{"kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListKeys"},
			Resources: []string{"*"},
			Reason:    "Reads key policies that can grant sensitive machine identities decrypt or administration paths.",
		},
	}
}
