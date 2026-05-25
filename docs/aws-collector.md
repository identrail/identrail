# AWS Collector

## Purpose

The AWS collector is the first provider ingestion module in Identrail. It reads IAM roles in a strictly read-only mode and emits provider-native raw assets for downstream normalization.

## Why This Design

- Provider API calls are abstracted behind `IAMAPI` so collector logic is testable and independent from SDK wiring details.
- Retry logic is built into collection to handle transient IAM throttling and rate-limit responses.
- Pagination includes a max-page guard to prevent runaway scans in failure scenarios.
- Output is deduplicated by role ARN to keep collection idempotent and stable on reruns.

## Key Contracts

- `IAMAPI.ListRoles(ctx, nextToken, pageSize)`
- `Collector.Collect(ctx) ([]providers.RawAsset, error)`

`RawAsset` payload uses `kind=iam_role` and stores the full role JSON for auditability.

## Edge Cases Handled

- API throttling with exponential backoff
- Non-retryable IAM errors fail fast
- Context cancellation during retries
- Duplicate roles across pages
- Missing ARN rows are ignored as invalid identifiers

## Security Posture

- Read-only ingestion only
- No credential persistence in collector module
- No mutation API calls

## Current Implementation State

- IAM role collection is implemented through a concrete AWS SDK adapter.
- The collector output flows into the normalizer pipeline as `kind=iam_role` raw assets.
- Connectors currently assume the onboarded read-only role at scan time, then perform IAM-only collection.
- Runtime behavior stays IAM-focused and read-only; no live remediation or policy enforcement is executed during collection.
- Cross-service expansion is expected through the separate composite-connector roadmap, not through this IAM collector path today.
