# AWS governance audit reporting

Issue #1548 adds a metadata-only reporting layer for AWS governance decisions.
It composes existing Identrail governance projections into export-safe rows for
operator review and audit evidence packages.

The endpoint does not enforce, approve, remediate, or call AWS write APIs.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/governance-audit-reporting`

Response shape: `{ "governance_audit_reporting": AWSGovernanceAuditReportingResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`ou`, `identity_id`, `agent_id`, `decision_type`, `approver`, `category`,
`state`, `source_type`, `from`, `to`, and `search`.

`from` and `to` must be RFC3339 timestamps. Invalid timestamps, or a `from`
value later than `to`, return `400`.

## Report categories

- `decision`: advisory authorization and AgentCore gateway policy decisions.
- `approval`: remediation approval workflow records, requestors, approver roles,
  and approval states.
- `remediation`: post-remediation verification and rollback records.
- `enforcement_outcome`: limited enforcement pilot outcomes and hold states.
- `exception`: explicit diagnostics, blocked states, rollback states, kill
  switches, holds, denied approvals, and other report rows operators must review.

## Evidence boundary

Every row carries source IDs, policy version, input hash, confidence, actor or
approver context, account/region, timestamps, evidence refs, and audit trail
metadata.

Rows do not contain rendered policy bodies, secret values, prompts, completions,
browser pages, code-interpreter output, database rows, object contents, customer
payloads, or workload payloads.

## App surface

The AWS Governance page renders an **AWS governance audit reporting** panel with
record category, decision type, state, actor or approver, evidence-ref counts,
audit-row counts, and confidence. Loading, empty, error, degraded, permission
denied, and exception states remain visible.

## Out of scope

- No live AWS mutation.
- No new collector or scanner behavior.
- No raw payload, policy-body, secret, prompt, completion, database, object, or
  workload export.
- No downstream executor beyond reporting over existing governance records.
