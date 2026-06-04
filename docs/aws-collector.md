# AWS Collector

## Purpose

The AWS collector family now uses a composable service collection layer. IAM stays
the current implementation and default first service, while new services can be added
without modifying IAM collector behavior.

## Composite Architecture

The collection path is:

- `AWSCompositeCollector` (`internal/providers/aws/composite_collector.go`)
  orchestrates multiple AWS service collectors sequentially.
- `AWSCollectorScope` carries shared context (`account_id`, `region`, `service`)
  for each service invocation.
- `iamCollectorAdapter` wraps the existing IAM collector and preserves existing IAM
  retry and pagination semantics unchanged.

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

## Security Posture

- Read-only ingestion only
- No credential persistence in collector module
- No mutation API calls

## Current Implementation State

- IAM role collection remains implemented through the existing AWS SDK IAM adapter.
- AWS SDK CLI and runtime paths now use `NewAWSScanner`, which wires the composite collector.
- The composite layer is now the extension point for future AWS service collection in the CLI/runtime path.
- The service collector contract is exposed through
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/collector-contract`
  and the AWS app surfaces.
