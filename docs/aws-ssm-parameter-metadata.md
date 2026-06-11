# AWS SSM Parameter Store Metadata and References

Issue #1491 adds metadata-only collection for AWS Systems Manager Parameter
Store parameters and the workload references that point at them.

## What It Collects

- Parameter ARN, name, hierarchy path context, account, region, and tags.
- Parameter type (`string`, `string_list`, `secure_string`), tier, data type,
  and version.
- KMS key references for SecureString parameters, with customer-managed vs
  AWS-managed key classification.
- Parameter policy summaries (type, status, and expiration timestamp) without
  raw policy text.
- Last-modified timestamp and the IAM principal that last changed the
  parameter, connecting parameter changes to identities.
- Workload references emitted by compute collectors through `secret_refs`
  (ECS `valueFrom` and CodeBuild `PARAMETER_STORE` environment sources), with
  graph-ready `uses_secret` edges when a reference resolves to a collected
  parameter.

SecureString parameters are treated as sensitive metadata only: the collector
records that a secure value exists and how it is encrypted, never the value.

## What It Never Collects

The collector never calls `ssm:GetParameter`, `ssm:GetParameters`,
`ssm:GetParametersByPath`, or `ssm:GetParameterHistory`. It does not read,
store, log, or return parameter values, plaintext environment values, customer
payloads, prompts, completions, object contents, database rows, or browser
output. API responses expose `description_present` and
`allowed_pattern_present` rather than using description or pattern text as
evidence. Parameters shared into the account through AWS RAM are not
enumerated; this is reported as an explicit coverage gap.

## Required AWS Permissions

Use read-only metadata permissions:

- `ssm:DescribeParameters`
- `ssm:ListTagsForResource`

Do not add any `ssm:GetParameter*` action for this capability.

## API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ssm-parameter-metadata
```

Optional query parameters:

- `connector_id`: scope the response to one AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.
- `parameter_type`: limit records to `string`, `string_list`, or
  `secure_string`.
- `identity`: case-insensitive substring filter matching the last-modified
  principal or referencing workload identifiers.

The response includes operator-visible status, confidence, evidence links,
failure reasons, remediation hints, diagnostics, records, and `uses_secret`
relationships. Plaintext `String` parameters referenced through secret-style
injection channels are flagged with the
`plain_text_parameter_referenced_as_secret` exposure reason so operators can
move them into SecureString or Secrets Manager.

## Failure States

- `empty`: collection succeeded and no parameters were found.
- `degraded`: metadata is available but one metadata path, such as tag reads,
  is incomplete.
- `partial_failure`: some records remain visible while a later metadata page
  failed.
- `permission_denied`: required metadata-only permissions are missing.

Unknown or denied states are explicit; they are not reported as successful
findings.

## Live Validation

Run fixture validation first:

```sh
go test ./internal/providers/aws ./internal/api
```

For live AWS validation, use only an authorized test account and record
account, region, service coverage, and diagnostics. Do not capture parameter
values or customer payloads.
