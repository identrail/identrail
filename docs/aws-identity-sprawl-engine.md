# AWS identity sprawl engine

Issue #1524 (Wave 6.04) adds a metadata-only engine that ranks IAM identity
sprawl into explainable, actionable findings: **stale**, **ownerless**,
**duplicate**, and **shared** roles. It builds on the IAM identity-bearing
inventories (Lambda execution roles, ECS task/execution roles, EC2 instance
profiles) joined with the runtime-access correlations from Waves 5.06–5.08, and
mirrors the calculation/finding contract established by Waves 6.01–6.03.

## What it produces

Per IAM role, the engine emits zero or more `AWSIdentitySprawlFinding` records
of these types:

- **`stale_identity`** — a role is attached to at least one workload but has
  **no observed runtime access** in the scoped evidence window. Held in
  `review` status unless and until runtime data-event coverage is high enough
  to upgrade it to a cleanup candidate.
- **`ownerless_identity`** — the role has no documented owner via the
  conventional tag keys (`owner`, `team`, `service`, `Owner`, `Team`,
  `Service`, `identrail:owner`). Cleanup or consolidation cannot route to a
  documented owner without one.
- **`duplicate_identity`** — the role shares an attachment-surface signature
  (sorted workload types + a normalized role-name fragment) with at least one
  other role. The cluster id and signature hint are surfaced so consumers can
  group findings.
- **`shared_role`** — a single role is attached to **multiple distinct
  workload types** (e.g. Lambda + ECS + EC2). Severity rises with the number
  of workload types and when no owner is tagged.

Each finding carries a calculation version, severity, score (0–100), confidence,
rationale, impacted nodes/path, evidence references, and a read-only
`remediation_case` preview that downstream remediation surfaces can render.
Findings are ranked by descending score, ties broken by `finding_id`.

## What the engine intentionally does **not** do

- It does **not** parse IAM policy documents. Duplicate clustering uses the
  *attachment surface* (workload types + role-name fragment), which is the
  metadata it has. A low-similarity name match is not a duplicate.
- It does **not** infer owner from anything other than tags. An out-of-band
  runbook does not satisfy `ownerless_identity`; the role must be tagged.
- It does **not** read role permission documents, secret values, prompts,
  completions, browser pages, code-interpreter output, or any customer
  payload.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/identity-sprawl`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | scope filters |
| `identity` | role ARN, name, identity-node id, or display-name search |
| `owner` | owner label or owner-source tag key; the literal `none` / `ownerless` returns only roles without a documented owner |
| `cluster` | duplicate cluster id or cluster kind |
| `finding_type` | `stale_identity`, `ownerless_identity`, `duplicate_identity`, `shared_role` |
| `severity` | `critical`, `high`, `medium`, `low` |
| `status` | `review`, `cleanup_candidate` |

Response shape: `{ "findings": AWSIdentitySprawlResult }` with summary, ranked
findings, cluster index, graph relationships, caveats, coverage gaps,
diagnostics, and the standard envelope fields (tenant/workspace/project
scope, parent + current issue refs, calculation version).

## Inputs and dependencies

- **Identity-bearing inventories** (read-only, metadata-only):
  `aws_ec2_instance_profiles`, `aws_lambda_execution_roles`,
  `aws_ecs_task_roles`. Each contributes `RoleARN`, `RoleName`,
  `WorkloadType`, `WorkloadName`, `WorkloadID`, `Tags`, and an evidence
  reference.
- **Runtime-access correlations** (read-only, metadata-only):
  `aws_secrets_kms_runtime_access`, `aws_s3_runtime_access`,
  `aws_agent_runtime_access`. The engine marks a role as **observed** when any
  of these reports `observed_count > 0` for a matching principal ARN.

## AWS permissions and intentionally excluded data

The engine adds **no** new AWS permissions. It reuses the read-only,
metadata-only permissions already required by the upstream inventory
collectors and the runtime-access correlations (CloudTrail LookupEvents and
optional delivery channels). It does not request, read, or persist role
permission documents, customer payloads, secret values, or runtime data
beyond the metadata fields the existing contracts already surface.

## Failure handling

- **Empty** scope: response carries `status=ready` or `status=degraded` with
  zero findings; the summary reflects this.
- **Degraded** inputs: any single source returning degraded or producing
  diagnostics downgrades the envelope to `status=degraded` and lowers
  confidence to `0.7`.
- **Permission denied**: when every upstream source is blocked, the envelope
  is `status=blocked` with `confidence=0`; partial-coverage scenarios stay at
  `degraded`. Blocked findings remain in `review`; they never become
  `cleanup_candidate`.
- Diagnostics and coverage gaps from upstream inputs are forwarded verbatim so
  operators can act on the root cause without losing context.

## Live validation

1. Confirm the upstream identity-bearing inventories return non-empty results
   under `success` fixture state.
2. Run `GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/identity-sprawl?fixture_state=success` and verify each
   finding type produces records consistent with the underlying inventory
   data.
3. Verify the `owner=none` sentinel filter only returns findings with
   `owner_source=no_owner_tag`.
4. Spot-check that duplicate clusters use the documented signature shape
   (`<sorted-workload-types>|<name-fragment>`).
5. Confirm `permission_denied` fixture state returns `status=blocked` with
   diagnostics and no findings.

## Troubleshooting

- **No `ownerless_identity` findings appear** — every IAM role in your
  inventory carries one of the recognized owner tag keys. This is the desired
  state.
- **Spurious `duplicate_identity` clusters** — review the cluster
  `signature_hint`; the signature combines workload types with the role-name
  fragment after stripping common suffixes (`-execution`, `-runtime`, `-task`,
  `-role`, env tokens). Adjust role naming if the cluster is incorrect.
- **`stale_identity` findings on actively-used roles** — runtime data-event
  coverage for the role's resources may be incomplete. Check the runtime
  correlation surfaces for coverage gaps before treating the finding as
  cleanup-ready.
