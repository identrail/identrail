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
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityTrustGraphReadOnlyStorage",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
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
			Service:   "EC2",
			Actions:   []string{"ec2:DescribeInstances", "ec2:DescribeIamInstanceProfileAssociations", "ec2:DescribeRegions"},
			Resources: []string{"*"},
			Reason:    "Maps compute workloads back to the IAM roles and instance profiles they can use.",
		},
		{
			Service:   "S3",
			Actions:   []string{"s3:GetBucketAcl", "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:ListAllMyBuckets"},
			Resources: []string{"*"},
			Reason:    "Checks bucket access policies that can expose or constrain machine identities.",
		},
		{
			Service:   "KMS",
			Actions:   []string{"kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListKeys"},
			Resources: []string{"*"},
			Reason:    "Reads key policies that can grant sensitive machine identities decrypt or administration paths.",
		},
	}
}
