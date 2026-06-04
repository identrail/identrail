# AWS Platform Dependency Index

The AWS platform dependency index is the canonical, scriptable issue-ordering
ledger for the AWS machine identity program under parent issue #1472. It exists
so implementation PRs only open when their declared blockers are closed.

Issue #1474 is the index itself and is completed. Issue #1476, the AWS service
collector contract, issue #1477, the EC2 instance profile collector, and issue
#1478, the ECS task and execution role collector, are completed too, so issues
#1479 through #1496 are the next ready collector and resource-mapping items.

## API

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/dependency-index
```

The endpoint returns:

```json
{
  "index": {
    "parent_issue_ref": "#1472",
    "current_issue_ref": "#1474",
    "status": "ready",
    "issue_count": 85,
    "wave_count": 11,
    "ready_issue_refs": ["#1479", "#1480", "#1481", "#1482", "#1483", "#1484", "#1485", "#1486", "#1487", "#1488", "#1489", "#1490", "#1491", "#1492", "#1493", "#1494", "#1495", "#1496"],
    "blocked_issue_refs": ["#1497"],
    "completed_issue_refs": ["#1473", "#1474", "#1475", "#1476", "#1477", "#1478"],
    "checks": [],
    "issues": []
  }
}
```

`connector_id` is optional. When supplied, the service uses it only to add AWS
account and region context to the response; the dependency graph itself is
deterministic and does not read AWS credentials or secrets.

## Checks

The index validates these required checks on every read:

- `child_issue_count`: the ledger contains all 85 AWS child issues from the
  parent epic.
- `blocker_reference_format`: blocker references use `#1234` formatting and do
  not repeat within an issue.
- `blocker_reference_existence`: every blocker points to another child issue in
  the same ledger.
- `parent_sequence_ordering`: every blocker appears earlier than the issue it
  blocks.
- `current_issue_readiness`: #1474 remains satisfied because it is completed,
  #1477 and #1478 are completed, and #1479 through #1496 are the next allowed
  implementation issues.

If any required check fails, `status` becomes `blocked`, `confidence` drops, and
`failure_reasons` plus `remediation_hints` explain what to fix before opening a
downstream PR.

## Issue States

Each `issues[]` item includes `blocker_refs`, `downstream_refs`,
`dependency_status`, `ready_for_pr`, `failure_reasons`, `remediation`, and
`next_action`.

- `completed`: the issue is already closed and is only evidence for downstream
  blockers.
- `ready`: every blocker is completed, so a focused implementation PR may be
  opened.
- `blocked`: at least one blocker is still open, so do not open a PR for that
  issue yet.

This rule is intentionally mechanical: blocked AWS child issues must not receive
PRs until every blocker listed in the index is closed.

## Scriptable Handoff

The response is sorted by issue number and stable enough for automation. A
handoff script can read `ready_issue_refs` to find the next allowed work item,
then inspect `issues[]` for the title, wave, downstream consumers, evidence URL,
and next action.

The endpoint is read-only, project-scoped, and covered by the same tenant and
workspace scope headers as other `/v1` project management APIs.
