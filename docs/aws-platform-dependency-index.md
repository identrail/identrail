# AWS Platform Dependency Index

The AWS platform dependency index is the canonical, scriptable issue-ordering
ledger for the AWS machine identity program under parent issue #1472. It exists
so implementation PRs only open when their declared blockers are closed.

Issue #1474 is the index itself and is now completed. Issue #1475, the AWS live
app validation harness, is the next Wave 0 item allowed to proceed because issue
#1473, the AWS platform baseline verification gate, is closed.

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
    "ready_issue_refs": ["#1475"],
    "blocked_issue_refs": ["#1476"],
    "completed_issue_refs": ["#1473", "#1474"],
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
  and #1475 is the next allowed implementation issue.

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
