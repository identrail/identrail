# AWS service collector contract

The AWS service collector contract is the shared language future AWS service
collectors must use before their output can feed the graph, runtime evidence,
intelligence, remediation, or governance engines. It is issue #1476 in the AWS
machine identity program under parent issue #1472.

The contract is deterministic and read-only. It does not call AWS, mutate live
accounts, or collect customer payloads. It gives operators and implementers one
API surface for the required record fields, graph edge semantics, fixture
states, permission boundaries, and failure behavior every downstream collector
PR must satisfy.

## API

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/collector-contract
```

`connector_id` is optional. When supplied, the service uses it only to add AWS
account and region context to the response. The contract itself stays stable
across connectors.

The response envelope is:

```json
{
  "contract": {
    "tenant_id": "tenant-a",
    "workspace_id": "workspace-a",
    "project_id": "production",
    "connector_id": "aws-prod",
    "account_id": "123456789012",
    "region": "us-east-1",
    "parent_issue_ref": "#1472",
    "current_issue_ref": "#1476",
    "version": "aws-service-collector-contract-v1",
    "status": "ready",
    "confidence": 0.97,
    "required_field_count": 17,
    "graph_edge_count": 7,
    "fixture_case_count": 8,
    "required_fixture_case_count": 8,
    "normalized_record_fields": [
      "tenant_id",
      "workspace_id",
      "project_id",
      "connector_id",
      "account_id",
      "region",
      "service",
      "workload_id",
      "workload_type",
      "workload_name",
      "role_arn",
      "source",
      "evidence_ref",
      "confidence",
      "scan_id",
      "collector_name",
      "collected_at"
    ],
    "required_permissions": [
      "sts:GetCallerIdentity",
      "iam:ListRoles",
      "iam:GetRole",
      "iam:GetInstanceProfile",
      "ec2:DescribeInstances",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeLaunchTemplateVersions",
      "ecs:ListClusters",
      "ecs:ListServices",
      "ecs:DescribeServices",
      "ecs:ListTaskDefinitions",
      "ecs:DescribeTaskDefinition"
    ],
    "read_only_boundaries": [
      "collect metadata and policy documents only; never collect secret values, customer payloads, prompts, completions, object contents, or database rows"
    ],
    "checks": [],
    "graph_edges": [],
    "fixture_cases": [],
    "failure_reasons": [],
    "remediation_hints": [],
    "evidence_links": [],
    "generated_at": "2026-06-04T16:45:00Z",
    "updated_at": "2026-06-04T16:45:00Z"
  }
}
```

## Normalized Record Contract

Every AWS service collector must emit records with tenant, workspace, project,
connector, account, region, service, workload, role ARN, source, evidence
reference, confidence, scan metadata, collector name, and collection time.

The helper in `internal/providers/awscontract/contract.go` normalizes and
validates one `ServiceCollectorRecord`. Future collectors should use it in unit
or fixture tests before converting collected data into graph entities.

## Graph Edge Contract

Collectors should emit the precise graph edge they can prove:

| AWS edge name | Identrail relationship |
| --- | --- |
| `runs-on` | `runs_as` |
| `assumes` | `can_assume` |
| `passes-role` | `can_pass_role` |
| `can-access` | `can_access` |
| `references-secret` | `uses_secret` |
| `invokes` | `invokes` |
| `observed-runtime-action` | `observed_action` |

Do not overload `can_access` when a more precise relationship applies.

## Fixture Conventions

Each service collector must cover these deterministic fixture states:

- `success`: authorized collection with scoped metadata evidence.
- `empty`: authorized account, region, and service with zero records.
- `pagination`: multiple pages with stable cursor/page evidence.
- `throttling`: bounded retries end in a retryable degraded diagnostic.
- `partial_failure`: one service, account, region, or partition fails while
  successful partitions remain visible.
- `unsupported_region`: unsupported service/region is explicit and blocked.
- `permission_denied`: missing read-only permission is explicit and blocked.
- `degraded`: malformed or incomplete source record is explicit and degraded.

Negative fixture states are expected evidence, not successful findings.

## Permissions and Boundaries

The foundation contract currently requires metadata-only IAM reads such as
`sts:GetCallerIdentity`, `iam:ListRoles`, `iam:GetRole`,
`iam:GetInstanceProfile`, `iam:ListRolePolicies`, `iam:GetRolePolicy`,
`iam:ListAttachedRolePolicies`, `iam:GetPolicy`, and
`iam:GetPolicyVersion`. The first EC2 workload collector also requires
metadata-only compute reads: `ec2:DescribeInstances`,
`ec2:DescribeLaunchTemplates`, and `ec2:DescribeLaunchTemplateVersions`. The
ECS workload collector adds metadata-only reads: `ecs:ListClusters`,
`ecs:ListServices`, `ecs:DescribeServices`, `ecs:ListTaskDefinitions`, and
`ecs:DescribeTaskDefinition`.

Future service collectors may add service-specific read-only metadata
permissions, but must not add actions that read secret values, object contents,
prompts, completions, browser pages, code-interpreter output, database rows, or
customer payloads by default.

For ECS, `secret_refs` are only secret or parameter names/source references and
`environment_keys` are only variable names. Plaintext environment values and
secret values are intentionally outside the collector contract.

## Validation

Use these checks before opening a downstream AWS collector PR:

```bash
go test ./internal/providers/aws ./internal/api
npm test -- --run src/api/client.test.ts src/productShell.test.tsx
```

PR notes should include the collector contract status, covered fixture states,
graph edge types, and any permission-denied, unsupported-region, partial-failure,
or degraded evidence.
