# AWS remediation approval workflow and RBAC gates

Issue #1536 adds a metadata-only approval-queue projection for AWS remediation
cases. It turns each remediation case into an explicit approval entry with
risk tier, requestor, required approver roles, RBAC gates, feature flags
(including a tenant-scoped kill switch), idempotency key, scope, audit trail,
rollback plan, verification plan, and evidence refs so operators can see what
must happen before any live AWS mutation runs.

The endpoint is read-only. It never opens, applies, or rolls back any AWS
change, never calls IAM, STS, or Organizations write APIs, and never reads,
exposes, logs, or persists rendered policies, secret values, customer
payloads, prompts, completions, browser pages, code-interpreter output,
database rows, or object contents. Live controlled execution belongs to the
wave 8 executors (#1537–#1542) and is intentionally out of scope here.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/remediation-approval-queue`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `case_id` | source remediation case ID filter |
| `state` | `requested`, `under_review`, `approved`, `denied`, `expired`, or `blocked` |
| `risk_tier` | `critical`, `high`, `medium`, or `low` |
| `scope_type` | `identity`, `resource`, `account`, `ou`, or `org_root` |
| `requestor` | requestor label / owner match |
| `approver_role` | required approver role match |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `ready_for_execution` | `true` / `false` / `yes` / `no` |
| `kill_switch_engaged` | `true` / `false` / `yes` / `no` |
| `search` | free-text search across approval, scope, gate, flag, audit, and evidence fields |

Response shape: `{ "queue": AWSRemediationApprovalResult }` with
tenant/workspace/project metadata, summary counts, ranked entries,
relationships, caveats, failure reasons, remediation hints, evidence links,
coverage gaps, diagnostics, and generated timestamps.

## Entry shape

Each `AWSRemediationApprovalEntry` includes:

- stable `approval_id`, calculation version, source `case_id`, source artifact
  ID, issue refs, score, confidence, severity, and risk tier
- requestor (role/label/required/acknowledged) plus required approver roles
  scaled by risk tier (critical/high require an incident-commander; AI-agent
  and secret-equivalence sources require a data-protection-reviewer)
- explicit `scope` (scope type plus account, region, connector, identity, and
  resource node IDs)
- `rbac_gates` for tenant scope, read-only projection, requestor assignment,
  approver quorum, confidence floor, and approval-required acknowledgement
- `feature_flags` for the always-on approval workflow, the tenant-scoped
  remediation kill switch, the live-AWS-mutation gate (off here), critical-risk
  dual control, and IaC remediation PR requirements when the source is the
  IaC PR generator
- deterministic `idempotency_key` and `dry_run_ref` placeholders so later
  wave executors can wire dry-run, apply, and verify without re-deriving IDs
- `state`, `expires_at` (12h critical / 24h high / 48h medium / 72h default),
  `ready_for_execution` (only when state is `approved`, no kill switch, and no
  gate is blocked), tradeoffs, rollback plan, verification plan, and audit
  trail with `approval_requested` plus per-approver `approval_required` entries

## Failure handling

- **Ready**: upstream remediation case evidence is available and at least one
  approval entry can be composed.
- **Degraded**: partial or degraded upstream evidence is visible with explicit
  diagnostics; composed entries stay visible when safe.
- **Blocked**: permission-denied upstream evidence emits zero entries plus
  failure reasons, remediation hints, diagnostics, and coverage gaps.

Unsupported, empty, partial, degraded, and permission-denied states stay
explicit. The endpoint does not convert absence of upstream evidence into
deterministic approval.

## App surface

The AWS Runtime page renders an **AWS remediation approval workflow and RBAC
gates** panel with approval title, state, risk tier, requestor, required
approvers, scope, gates, and severity/state pill. Loading, empty, degraded,
blocked, and error states are explicit.

## Validation

1. Confirm blocker #1535 is closed.
2. Run upstream remediation cases with `fixture_state=success`.
3. Call the approval queue endpoint with `fixture_state=success` and verify at
   least one entry includes requestor, approver quorum, RBAC gates, feature
   flags (including `remediation_kill_switch`), idempotency key, expiry, and
   audit trail.
4. Filter by `risk_tier=high`, `approver_role=security-reviewer`,
   `ready_for_execution=false`, and `kill_switch_engaged=false`.
5. Run `fixture_state=empty`, `degraded`, `partial_failure`, and
   `permission_denied` and confirm the status, diagnostics, and failure reasons
   stay explicit.

## What is intentionally out of scope

- Live IAM/STS/Organizations write APIs (waves 8.02–8.07 own controlled
  execution).
- Persisting approval state mutations server-side; the endpoint projects
  deterministically from upstream cases and is safe to re-query.
- Rendering policy bodies, IaC bodies, secret values, or workload payloads.
- Opening, pushing, or merging operator source-control PRs.
