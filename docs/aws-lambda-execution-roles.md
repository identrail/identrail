# AWS Lambda Execution Roles

## Purpose

Issue #1479 adds metadata-only Lambda execution role inventory to the AWS
machine identity graph. It maps each Lambda function to the IAM role it runs as,
then carries enough context for later least-privilege and blast-radius work.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/lambda-execution-roles
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, `runs_as` relationships,
diagnostics, status, confidence, and issue evidence links.

## Evidence Collected

Each record includes:

- Function ARN, name, version, state, runtime, package type, handler, memory,
  timeout, VPC, subnet, security group, architecture, layer, alias, and version
  metadata.
- Execution role ARN and role name.
- Event-source mapping ARNs and mapping UUIDs.
- Disabled event-source ARNs and state-transition reasons.
- Environment variable names only.
- KMS key ARN and source-access or secret-reference ARNs.
- Tags.

The collector does not read function code, logs, invocation payloads, environment
values, secret values, customer data, prompts, completions, or database rows.

## Diagnostics

Permission denial blocks the inventory because Lambda list permissions are the
entry point. Per-function failures for aliases, versions, tags, or event-source
mappings are degraded partial failures; successful function-role records remain
visible. Disabled event sources are explicit degraded metadata so operators do
not confuse role visibility with complete invocation coverage.

## Graph Shape

Lambda function workloads emit:

```text
lambda_function --runs_as--> iam_role
```

That keeps Lambda aligned with the service collector contract and gives
downstream engines a deterministic machine identity edge without introducing
data-plane reads.
