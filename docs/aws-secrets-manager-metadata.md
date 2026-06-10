# AWS Secrets Manager Metadata and References

Issue #1490 adds metadata-only collection for AWS Secrets Manager secrets and
the workload references that point at them.

## What It Collects

- Secret ARN, name, account, region, tags, lifecycle timestamps, and rotation
  state.
- KMS key references from Secrets Manager metadata.
- Resource-policy grant summaries, including public and cross-account
  indicators.
- Version-stage metadata from `ListSecretVersionIds`.
- Replica-region metadata from `DescribeSecret`.
- Workload references emitted by compute collectors through `secret_refs`, with
  graph-ready `uses_secret` edges when a reference resolves to a collected
  secret.

## What It Never Collects

The collector never calls `secretsmanager:GetSecretValue`. It does not read,
store, log, or return `SecretString`, `SecretBinary`, plaintext environment
values, customer payloads, prompts, completions, object contents, database rows,
or browser output. API responses expose `description_present` rather than using
secret descriptions as evidence text.

## Required AWS Permissions

Use read-only metadata permissions:

- `secretsmanager:ListSecrets`
- `secretsmanager:DescribeSecret`
- `secretsmanager:GetResourcePolicy`
- `secretsmanager:ListSecretVersionIds`

Do not add `secretsmanager:GetSecretValue` for this capability.

## API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/secrets-manager-metadata
```

Optional query parameters:

- `connector_id`: scope the response to one AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response includes operator-visible status, confidence, evidence links,
failure reasons, remediation hints, diagnostics, records, and `uses_secret`
relationships.

## Failure States

- `empty`: collection succeeded and no secrets were found.
- `degraded`: metadata is available but one metadata path, such as version-stage
  reads, is incomplete.
- `partial_failure`: some records remain visible while a later metadata read
  failed.
- `permission_denied`: required metadata-only permissions are missing.

Unknown or denied states are explicit; they are not reported as successful
findings.

## Live Validation

Run fixture validation first:

```sh
go test ./internal/providers/aws ./internal/api
```

For live AWS validation, use only an authorized test account and record account,
region, service coverage, and diagnostics. Do not capture secret values or
customer payloads.
