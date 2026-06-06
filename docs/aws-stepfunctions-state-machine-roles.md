# AWS Step Functions State-Machine Roles

## Purpose

Issue #1483 adds metadata-only Step Functions state-machine role inventory to the
AWS machine identity graph. It maps state machines to execution roles,
downstream service integrations, nested workflow references, and logging config
so operators can see which IAM roles power workflow automation.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/stepfunctions-state-machine-roles
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, `runs_as` relationships,
diagnostics, status, confidence, count summaries, and issue evidence links.

## Evidence Collected

Each record includes:

- State machine ARN, name, type, status, revision ID, account, and region.
- Execution role ARN, role name, and role account ID.
- Definition SHA-256 hash when a definition is available.
- AWS ARNs extracted from definition metadata.
- Task resource ARNs, service integration identifiers, and nested state-machine
  ARNs extracted from definitions.
- Logging level, execution-data logging flag, log group ARNs, tracing flag,
  encryption type, KMS key reference, and tags when available.

The collector never stores raw workflow definitions, execution history,
customer payload examples, object contents, database rows, prompt contents,
completions, browser pages, code-interpreter output, or secret values.

## Required AWS Permissions

The live SDK collector uses read-only metadata APIs only:

- `states:ListStateMachines`
- `states:DescribeStateMachine`
- `states:ListTagsForResource`

`DescribeStateMachine` is called with `METADATA_ONLY` included data so encrypted
state-machine definitions are not decrypted for collection.

## Diagnostics

Permission denial blocks the inventory because the collector cannot prove state
machines or execution roles without Step Functions metadata access. Per-state
machine describe or tag failures are reported as partial failures so successful
role records remain visible. Execution-data logging is surfaced as degraded
metadata because it changes the operator's data-exposure context.

## Graph Shape

State-machine execution role records emit:

```text
stepfunctions_state_machine --runs_as--> iam_role
```

That gives downstream graph, runtime, blast-radius, least-privilege, reasoning,
remediation, and governance features deterministic workflow-role evidence
without collecting workflow payloads or secrets.
