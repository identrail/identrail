# AWS Event-Driven Roles

## Purpose

Issue #1484 adds read-only EventBridge, EventBridge Scheduler, and EventBridge
Pipes role inventory to the AWS machine identity graph. It maps rules,
schedules, and pipes to the IAM roles that invoke targets or execute pipes so
operators can see event-driven automation identities alongside EC2, ECS,
Lambda, CodeBuild, CodePipeline, Step Functions, and EKS evidence.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/event-driven-roles
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, `runs_as` relationships,
diagnostics, status, confidence, count summaries, and issue evidence links.

## Evidence Collected

Each record can include:

- Rule, schedule, or pipe ARN, name, account, region, service, and active or
  disabled state.
- Invocation, schedule target, or pipe execution role ARN, role name, role kind,
  and role account ID.
- Event bus name/ARN, schedule group/expression/time zone, pipe source/target/
  enrichment references, target references, DLQs, retry metadata, log
  destinations, KMS key reference, state reason, and tags.
- SHA-256 hashes for event patterns and input transformer metadata when present.

The collector is metadata-only. It never stores raw event payloads, schedule
target input bodies, pipe source records, enriched payloads, target payloads,
object contents, database rows, prompt contents, completions, browser pages,
code-interpreter output, or secret values.

## Required AWS Permissions

The live SDK collector uses read-only AWS APIs only:

- `events:ListEventBuses`
- `events:ListRules`
- `events:ListTargetsByRule`
- `events:ListTagsForResource`
- `scheduler:ListSchedules`
- `scheduler:GetSchedule`
- `pipes:ListPipes`
- `pipes:DescribePipe`

These permissions are enough to collect identity, target, DLQ, disabled-state,
logging, and hash/reference metadata without collecting runtime payloads.

## Diagnostics

Permission denial blocks the inventory when the collector cannot prove rules,
schedules, pipes, or roles without metadata access. Per-rule target failures,
per-schedule describe failures, and per-pipe describe failures are reported as
partial failures so successful role records remain visible. Pipes execution-data
logging is surfaced as degraded metadata because it changes the operator's
data-exposure context.

## Graph Shape

Event-driven role records emit:

```text
eventbridge_rule --runs_as--> iam_role
scheduler_schedule --runs_as--> iam_role
eventbridge_pipe --runs_as--> iam_role
```

Disabled schedules and rules remain visible as disabled records rather than
being merged with active identities. That gives downstream graph, runtime,
blast-radius, least-privilege, reasoning, remediation, and governance features
deterministic event-driven role evidence without collecting payloads or secrets.
