# Identrail AWS Read-Only Policy

This policy is intentionally narrower than AWS managed `ReadOnlyAccess`. It grants only the read calls Identrail needs to validate a connector and build the first machine identity trust graph.

| Service | Actions | Why Identrail needs it |
| --- | --- | --- |
| STS | `sts:GetCallerIdentity` | Confirms the assumed-role identity during setup and recurring scans. |
| IAM | `iam:GetAccountSummary`, `iam:ListAccountAliases`, `iam:ListRoles`, `iam:GetRole`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:SimulatePrincipalPolicy` | Reads role trust policies, inline and managed permission policies, and effective permission paths. |
| EC2 | `ec2:DescribeInstances`, `ec2:DescribeIamInstanceProfileAssociations`, `ec2:DescribeRegions` | Maps compute workloads to instance profiles and IAM roles. |
| S3 | `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetBucketPublicAccessBlock` | Reads bucket policy edges that can grant or expose machine identities. |
| KMS | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyPolicy` | Reads key policy edges that can grant sensitive decrypt or administration paths. |

The CloudFormation template requires an External ID condition in the trust policy. Identrail generates a unique 32-byte External ID per connector and stores it in the connector secret envelope table, not plaintext connector metadata.
