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
      "ecs:DescribeTaskDefinition",
      "lambda:ListFunctions",
      "lambda:ListAliases",
      "lambda:ListVersionsByFunction",
      "lambda:ListEventSourceMappings",
      "lambda:ListTags",
      "codebuild:ListProjects",
      "codebuild:BatchGetProjects",
      "codepipeline:ListPipelines",
      "codepipeline:GetPipeline",
      "codepipeline:GetPipelineState",
      "eks:ListClusters",
      "eks:DescribeCluster",
      "eks:ListPodIdentityAssociations",
      "eks:DescribePodIdentityAssociation",
      "eks:ListNodegroups",
      "eks:DescribeNodegroup",
      "eks:ListFargateProfiles",
      "eks:DescribeFargateProfile",
      "secretsmanager:ListSecrets",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:ListSecretVersionIds",
      "ssm:DescribeParameters",
      "ssm:ListTagsForResource",
      "ecr:DescribeRepositories",
      "ecr:DescribeImages",
      "ecr:GetRepositoryPolicy",
      "ecr:GetLifecyclePolicy",
      "ecr:GetRegistryScanningConfiguration",
      "ecr:ListTagsForResource"
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
`ecs:DescribeTaskDefinition`. The Lambda workload collector adds metadata-only
reads: `lambda:ListFunctions`, `lambda:ListAliases`,
`lambda:ListVersionsByFunction`, `lambda:ListEventSourceMappings`, and
`lambda:ListTags`. The CodeBuild service-role collector adds metadata-only
reads: `codebuild:ListProjects` and `codebuild:BatchGetProjects`. The
CodePipeline deployment-role collector adds metadata-only reads:
`codepipeline:ListPipelines`, `codepipeline:GetPipeline`, and
`codepipeline:GetPipelineState`. The Step Functions state-machine role
collector adds read-only state-machine reads: `states:ListStateMachines`,
`states:DescribeStateMachine`, and `states:ListTagsForResource`. The EKS
workload identity collector adds metadata-only reads: `eks:ListClusters`, `eks:DescribeCluster`,
`eks:ListPodIdentityAssociations`, `eks:DescribePodIdentityAssociation`,
`eks:ListNodegroups`, `eks:DescribeNodegroup`, `eks:ListFargateProfiles`, and
`eks:DescribeFargateProfile`.

The Secrets Manager metadata collector adds metadata-only reads:
`secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret`,
`secretsmanager:GetResourcePolicy`, and
`secretsmanager:ListSecretVersionIds`. It must not add
`secretsmanager:GetSecretValue`.

The SSM Parameter Store metadata collector adds metadata-only reads:
`ssm:DescribeParameters` and `ssm:ListTagsForResource`. It must not add
`ssm:GetParameter`, `ssm:GetParameters`, `ssm:GetParametersByPath`, or
`ssm:GetParameterHistory`.

The ECR repository metadata collector adds metadata-only reads:
`ecr:DescribeRepositories`, `ecr:DescribeImages`, `ecr:GetRepositoryPolicy`,
`ecr:GetLifecyclePolicy`, `ecr:GetRegistryScanningConfiguration`, and
`ecr:ListTagsForResource`. It must not add `ecr:BatchGetImage`,
`ecr:GetDownloadUrlForLayer`, image manifest APIs, or scan-finding detail APIs.

Future service collectors may add service-specific read-only metadata
permissions, but must not add actions that read secret values, object contents,
prompts, completions, browser pages, code-interpreter output, database rows, or
customer payloads by default.

For ECS, `secret_refs` are only secret or parameter names/source references and
`environment_keys` are only variable names. Plaintext environment values and
secret values are intentionally outside the collector contract.

For CodeBuild, `secret_refs` are only Parameter Store or Secrets Manager source
references and `environment_keys` are only variable names. Build logs, source
contents, artifact contents, plaintext environment values, and secret values are
intentionally outside the collector contract.

For Secrets Manager, records contain secret metadata, policy-grant summaries,
KMS references, tags, version stages, replica status, and resolved workload
reference edges only. `SecretString`, `SecretBinary`, secret descriptions as
operator evidence, and `GetSecretValue` outputs are intentionally outside the
collector contract.

For SSM Parameter Store, records contain parameter metadata, type and tier,
path context, KMS references, parameter-policy summaries, tags, last-modified
identity context, and resolved workload reference edges only. Parameter
values, parameter history, description and allowed-pattern text as operator
evidence, and every `ssm:GetParameter*` output are intentionally outside the
collector contract. SecureString parameters are sensitive metadata only.

For ECR repositories, records contain repository metadata, tag mutability,
encryption configuration, scan configuration, repository-policy and
lifecycle-policy summaries, image counts, tags, and resolved workload
`uses_image` edges only. Image layers, manifests, SBOM contents, vulnerability
finding details, and image payloads are intentionally outside the collector
contract.

For CodePipeline, `configuration_keys` are action configuration key names only.
Configuration values, source contents, action outputs, artifact contents,
deployment payloads, environment variable names, and secret values are
intentionally outside the collector contract.

For Step Functions, raw definitions, execution history, customer payload
examples, object contents, and secret values are intentionally outside the
collector contract. Collectors may retain definition SHA-256 hashes and extracted
ARN/service-integration identifiers only. If a customer-managed KMS key blocks
definition reads, collectors must keep metadata-only execution-role evidence
visible and emit `state_machine_definition_unavailable` instead of dropping the
state machine.

For EKS, AWS-side metadata proves clusters, OIDC issuer relationships, Pod
Identity associations, managed node roles, and Fargate pod execution roles.
IRSA service account annotations require Kubernetes API access; when that access
is missing, collectors must emit degraded AWS-side evidence such as
`irsa_annotation_collection_unconfigured` instead of claiming complete IRSA
coverage.

## Validation

Use these checks before opening a downstream AWS collector PR:

```bash
go test ./internal/providers/aws ./internal/api
npm test -- --run src/api/client.test.ts src/productShell.test.tsx
```

PR notes should include the collector contract status, covered fixture states,
graph edge types, and any permission-denied, unsupported-region, partial-failure,
or degraded evidence.
