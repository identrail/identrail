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
	Service    string     `json:"service"`
	Actions    []string   `json:"actions"`
	Resources  []string   `json:"resources"`
	Reason     string     `json:"reason"`
	Capability Capability `json:"capability"`
	Tier       string     `json:"tier"`
	Included   bool       `json:"included"`
	Gate       string     `json:"gate,omitempty"`
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
			Service:    "STS",
			Actions:    []string{"sts:GetCallerIdentity"},
			Resources:  []string{"*"},
			Reason:     "Confirms Identrail is using the expected assumed role during validation and recurring scans.",
			Capability: CapabilityDiscovery,
			Tier:       "read_only_discovery",
			Included:   true,
		},
		{
			Service:    "IAM",
			Capability: CapabilityDiscovery,
			Tier:       "read_only_discovery",
			Included:   true,
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
			Service:    "EC2",
			Actions:    []string{"ec2:DescribeInstances", "ec2:DescribeIamInstanceProfileAssociations", "ec2:DescribeRegions"},
			Resources:  []string{"*"},
			Reason:     "Maps compute workloads back to the IAM roles and instance profiles they can use.",
			Capability: CapabilityDiscovery,
			Tier:       "read_only_discovery",
			Included:   true,
		},
		{
			Service:    "S3",
			Actions:    []string{"s3:GetBucketAcl", "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:ListAllMyBuckets"},
			Resources:  []string{"*"},
			Reason:     "Checks bucket access policies that can expose or constrain machine identities.",
			Capability: CapabilityDiscovery,
			Tier:       "read_only_discovery",
			Included:   true,
		},
		{
			Service:    "KMS",
			Actions:    []string{"kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListKeys"},
			Resources:  []string{"*"},
			Reason:     "Reads key policies that can grant sensitive machine identities decrypt or administration paths.",
			Capability: CapabilityDiscovery,
			Tier:       "read_only_discovery",
			Included:   true,
		},
		{
			Service:    "CloudTrail",
			Actions:    []string{"cloudtrail:LookupEvents"},
			Resources:  []string{"*"},
			Reason:     "Runtime evidence is intentionally gated and is not granted by the read-only discovery stack.",
			Capability: CapabilityRuntimeEvidence,
			Tier:       "runtime_evidence",
			Included:   false,
			Gate:       "aws_runtime_evidence_capability",
		},
		{
			Service:    "Access Analyzer",
			Actions:    []string{"access-analyzer:ValidatePolicy"},
			Resources:  []string{"*"},
			Reason:     "Remediation planning remains advisory-only until the deployment enables the planning workflow.",
			Capability: CapabilityRemediationPlan,
			Tier:       "remediation_plan",
			Included:   false,
			Gate:       "aws_remediation_plan_capability",
		},
		{
			Service: "IAM",
			Actions: []string{
				"iam:DeleteRolePolicy",
				"iam:DetachRolePolicy",
				"iam:PutRolePolicy",
				"iam:UpdateAssumeRolePolicy",
			},
			Resources:  []string{"*"},
			Reason:     "Approved remediation is write-capable and must be explicitly enabled outside the read-only stack.",
			Capability: CapabilityApprovedRemediation,
			Tier:       "approved_remediation",
			Included:   false,
			Gate:       "aws_approved_remediation_capability",
		},
		{
			Service:    "IAM",
			Actions:    []string{"iam:SimulatePrincipalPolicy"},
			Resources:  []string{"*"},
			Reason:     "Authorization advisory is kept behind its own product gate even when discovery can read IAM policy state.",
			Capability: CapabilityAuthorizationAdvisory,
			Tier:       "authorization_advisory",
			Included:   false,
			Gate:       "aws_authorization_advisory_capability",
		},
		{
			Service: "Organizations",
			Actions: []string{
				"organizations:AttachPolicy",
				"organizations:DetachPolicy",
				"organizations:UpdatePolicy",
			},
			Resources:  []string{"*"},
			Reason:     "Authorization enforcement is a future write-capable mode and is never enabled by the read-only stack.",
			Capability: CapabilityAuthorizationEnforcement,
			Tier:       "authorization_enforcement",
			Included:   false,
			Gate:       "aws_authorization_enforcement_capability",
		},
	}
}
