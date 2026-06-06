# AWS Collector

## Purpose

The AWS collector family uses a composable service collection layer. IAM remains
the default identity source, and EC2 instance profiles, ECS task/execution roles,
Lambda execution roles, and CodeBuild service roles are collected as workload
identity services without changing IAM collector behavior.

## Composite Architecture

The collection path is:

- `AWSCompositeCollector` (`internal/providers/aws/composite_collector.go`)
  orchestrates multiple AWS service collectors sequentially.
- `AWSCollectorScope` carries shared tenant, workspace, project, connector,
  scan, account, region, and service context for each service invocation.
- `iamCollectorAdapter` wraps the existing IAM collector and preserves existing IAM
  retry and pagination semantics unchanged.
- `EC2InstanceProfileCollector` maps EC2 instances and launch templates to the
  IAM roles attached through instance profiles.
- `ECSTaskRoleCollector` maps ECS services and active/inactive task definitions
  to task roles and execution roles.
- `LambdaExecutionRoleCollector` maps Lambda functions to execution roles, alias
  and version references, event-source mappings, KMS metadata, and secret
  references without collecting function code or environment values.
- `CodeBuildServiceRoleCollector` maps CodeBuild projects to service roles,
  source/provider metadata, environment key names, credential references, VPC
  config, and artifact metadata without collecting build logs, source,
  artifacts, environment values, or secret values.

Behavior:

1. Build service scope from config/connector context.
2. Run each registered service collector in order.
3. Aggregate all service assets and deduplicate deterministically by kind + source ID.
4. Continue collection when a service fails non-fatally (all non-context cancellations/deadlines).
5. Emit source diagnostics for non-fatal service failures with retryable context.
6. Stop immediately on context cancellation/deadline errors.

## Why This Design

- Keeps IAM semantics unchanged for existing behavior and risk controls.
- Provides deterministic execution order and a clean extension point for future services.
- Prevents a single service outage from aborting all AWS collection output.
- Preserves context cancellation behavior for operator-stopped or timed-out scans.

## How to add a new service collector

To add a new AWS service collector:

1. Implement `AWSServiceCollector` in `internal/providers/aws`:
   - `ServiceName() string`
   - `CollectWithDiagnostics(ctx, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error)`
2. Validate the collector output against
   [`ServiceCollectorRecord`](./aws-service-collector-contract.md), required
   fixture states, and graph edge semantics.
3. Append the service in `NewAWSCompositeCollector(...)`.
4. Add unit tests proving:
   - success path and returned assets
   - non-fatal failure path
   - context-propagation (`account`, `region`) to the service.
   - pagination, throttling, partial failure, unsupported region, permission
     denied, empty, and degraded fixture states.

No behavior rewrite is required inside the existing IAM collector.

## Service-level Diagnostics Contract

- IAM diagnostics are preserved through the adapter and enriched with service/account/region context where possible.
- Service collection failures produce:
  - `Code: "service_collection_failed"`
  - `Collector: "aws_<service>/<collector>"` (or `"aws_<service>"` when collector name is unavailable)
  - contextual message suffix including `[service=<service> account=<account_id> region=<region>]`
  - `Retryable: true`
- `context.Canceled` and `context.DeadlineExceeded` are treated as hard failures and
  terminate collection immediately.

## Key Contracts

- `IAMAPI.ListRoles(ctx, nextToken, pageSize)`
- `Collector.Collect(ctx) ([]providers.RawAsset, error)`
- `providers.DiagnosticCollector` contract through `CollectWithDiagnostics(ctx)`
- `AWSServiceCollector` contract through `CollectWithDiagnostics(ctx, scope)`
- `awscontract.AWSServiceCollectorContract()` for record fields, graph edges,
  fixture cases, permissions, and read-only boundaries

`RawAsset` payloads from composite collection are deduplicated and deterministically
ordered by `kind`, then `source_id`.

## Edge Cases Handled

- IAM throttling with exponential backoff
- Non-retryable IAM errors fail fast
- Context cancellation during IAM retries and composite execution
- Duplicate roles/assets across pages and services
- Missing identifiers are handled with diagnostics where appropriate
- EC2 instance profiles with no resolvable role stay visible as degraded records
- Launch template role references emit `attached_to` graph evidence
- EC2 instances with profile roles emit `runs_as` graph evidence and include
  IMDS endpoint/token posture
- ECS cluster-level service failures stay visible as retryable partial-failure
  diagnostics while successful clusters remain available.
- ECS task roles emit `runs_as` graph evidence; ECS execution roles emit
  `attached_to` graph evidence.
- ECS records include container images, secret references, and environment keys,
  but not environment values or secret values.
- Lambda event-source mapping failures are surfaced as partial-failure
  diagnostics while successful function-to-role evidence remains visible.
- Disabled Lambda event sources are explicit degraded metadata, not silent gaps.
- Lambda records include environment key names, KMS key ARNs, and secret/source
  access references, but not function code, logs, environment values, invocation
  payloads, or secret values.
- CodeBuild project batch failures are surfaced as partial-failure diagnostics
  while successfully described project-to-role evidence remains visible.
- CodeBuild records include source/provider metadata, build environment
  metadata, VPC config, artifact metadata, environment key names, and
  Parameter Store or Secrets Manager references, but not build logs, source,
  artifacts, environment values, or secret values.

## Security Posture

- Read-only ingestion only
- No credential persistence in collector module
- No mutation API calls
- No instance user data, disk contents, object contents, database rows, prompt
  bodies, completions, or secret values are collected

## Current Implementation State

- IAM role collection remains implemented through the existing AWS SDK IAM adapter.
- EC2 instance profile collection is implemented through AWS SDK EC2/IAM adapters
  for `DescribeInstances`, `DescribeLaunchTemplates`,
  `DescribeLaunchTemplateVersions`, and `GetInstanceProfile`.
- ECS task/execution role collection is implemented through AWS SDK ECS adapters
  for `ListClusters`, `ListServices`, `DescribeServices`,
  `ListTaskDefinitions`, and `DescribeTaskDefinition`.
- Lambda execution-role collection is implemented through AWS SDK Lambda
  adapters for `ListFunctions`, `ListAliases`, `ListVersionsByFunction`,
  `ListEventSourceMappings`, and `ListTags`.
- CodeBuild service-role collection is implemented through AWS SDK CodeBuild
  adapters for `ListProjects` and `BatchGetProjects`.
- AWS SDK CLI and runtime paths now use `NewAWSScanner`, which wires the
  composite collector with IAM, EC2 instance profile, ECS task role, Lambda
  execution role, CodeBuild service role, and EKS workload identity services.
- The composite layer is now the extension point for future AWS service collection in the CLI/runtime path.
- The service collector contract is exposed through
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/collector-contract`
  and the AWS app surfaces.
- EC2 instance profile inventory is exposed through
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/ec2-instance-profiles`
  and the AWS machine identities page.
- ECS task/execution role inventory is exposed through
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/ecs-task-roles`
  and the AWS machine identities page.
- Lambda execution role inventory is exposed through
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/lambda-execution-roles`
  and the AWS machine identities page.
- CodeBuild service role inventory is exposed through
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/codebuild-service-roles`
  and the AWS machine identities page.
