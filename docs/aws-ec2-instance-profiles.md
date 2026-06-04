# AWS EC2 instance profile collector

Issue #1477 adds the first AWS workload identity collector under parent issue
#1472. It maps EC2 instances and launch templates back to the IAM roles they use
through instance profiles, then exposes that evidence in the AWS machine
identity inventory.

## API

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ec2-instance-profiles
```

Query parameters:

- `connector_id`: optional AWS connector ID used to scope account and region
  evidence.
- `fixture_state`: optional deterministic fixture state for tests and UI
  validation. Supported states are `success`, `empty`, `degraded`,
  `partial_failure`, and `permission_denied`.

The response envelope is:

```json
{
  "inventory": {
    "parent_issue_ref": "#1472",
    "current_issue_ref": "#1477",
    "version": "aws-ec2-instance-profile-inventory-v1",
    "status": "ready",
    "record_count": 2,
    "workload_count": 2,
    "identity_count": 2,
    "relationship_count": 2,
    "records": [],
    "relationships": [],
    "diagnostics": []
  }
}
```

## Collected Evidence

Each record keeps the shared AWS service collector contract fields plus
EC2-specific metadata:

- account, region, service, workload ID, workload type, workload name
- role ARN and role name
- instance ID, instance ARN, instance state, instance profile ARN/name
- launch template ID/name/version when the role comes from a launch template
- IMDS endpoint, required-token posture, hop limit, and tags
- source API, evidence reference, graph node IDs, confidence, and collection time

The collector does not read instance user data, disk contents, S3 object
contents, database rows, prompts, completions, or secret values.

## Graph Mapping

- EC2 instance to IAM role emits `runs_as`.
- Launch template to IAM role emits `attached_to`.
- Instance profile and instance resources are normalized as first-class AWS
  resources so downstream findings can attach evidence to the workload, profile,
  and role separately.

## Failure Modes

- `empty`: authorized account and region with no EC2 instance profile workloads.
- `degraded`: an EC2 workload or profile exists but the role cannot be resolved.
- `partial_failure`: one EC2 partition, such as launch-template collection,
  failed while successful records remain visible.
- `permission_denied`: required read-only permissions are missing and the
  inventory is blocked.

Diagnostics include collector name, source ID, code, message, remediation, and
retryability.

## Required Permissions

The read-only connector needs:

- `ec2:DescribeInstances`
- `ec2:DescribeLaunchTemplates`
- `ec2:DescribeLaunchTemplateVersions`
- `iam:GetInstanceProfile`

These sit alongside the existing IAM role and STS metadata permissions in the
shared AWS service collector contract.
