# AWS trust policy hardening planner

Issue #1531 (Wave 7.03) adds a metadata-only engine that turns upstream
cross-account-trust findings (#1526) into ranked, read-only trust-policy
hardening plans. Each plan carries the projected principal change,
condition recommendations, before/after statement snippet refs, affected
callers, expected breakage projection, rollback plan, and verification
plan — so a remediation case (#1529) and a future executor wave have the
concrete payload they need to plan, approve, and apply safely.

This issue is the **trust-policy projection** capability of the
Identrail remediation loop. It does not mutate AWS, does not call any
IAM write API, and does not read rendered policy bodies, secret values,
workload payloads, prompts, completions, browser pages, code-interpreter
output, database rows, object contents, or customer payloads.
Approve / execute / verify / rollback / govern transitions belong to
later wave issues.

## What it produces

The engine emits `AWSTrustPolicyHardeningPlan` records, one per upstream
cross-account-trust finding. Every plan carries:

- **Identifiers**: stable `plan_id`, `calculation_version`, and the
  `source_finding_id` it was generated from.
- **`hardening_direction`** ∈ `remove_public_principal`,
  `add_org_or_source_condition`, `scope_to_known_external_principal`,
  `tighten_existing_condition`.
- **Severity / status / score / confidence**: inherited from the
  upstream finding.
- **Resource context**: account, region, service, resource type,
  resource node, resource ARN, resource label.
- **Trust shape flags**: `public_principal`,
  `trusted_within_organization`, `runtime_observed`, `analyzer_backed`.
- **`principal_change`** with `before_principals`, `after_principals`,
  `public_principal_removed`, and a rationale.
- **`condition_recommendations`**: list of
  `{operator, key, value, rationale, evidence_ref}` — the engine
  recommends `aws:PrincipalOrgID`, `aws:PrincipalAccount`,
  `sts:ExternalId`, `aws:SourceIdentity`, `aws:SourceArn`, or
  `aws:SecureTransport` depending on the finding type. Conditions
  already present on the upstream finding are never re-recommended.
- **`statement_snippets`**: one or more
  `AWSTrustPolicyStatementSnippet` entries with `change_kind` ∈
  `public_principal_removed`, `principal_added`, `condition_added`,
  `principal_and_condition_tightened`, `manual_review`. Snippets
  carry `before_ref` / `after_ref` metadata refs and condition-key
  lists only — never rendered JSON policy bodies.
- **`affected_callers`**: the external principal(s) known to use the
  trust path, with org / runtime / analyzer attribution.
- **`breakage_projection`** with `level` ∈ `low`, `medium`, `high`,
  `unknown`, a rationale, and signal counts.
- **`rollback_plan`** (`restore_trust_policy`) and
  **`verification_plan`** (`trust_policy_re_evaluate`).
- **`ready_for_apply: true`** only when *all* hold: principal is not
  public, breakage_level is `low`, at least one condition is
  recommended, and confidence ≥ 0.80.
- **`read_only_projection: true`** on every plan.
- Evidence refs, source signals, impacted graph nodes/path, next action.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/trust-policy-hardening`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `service` | exact match on the upstream AWS service token |
| `resource` | substring search across resource node, ARN, label, type, and service |
| `principal` | substring search across affected caller and proposed principal lists |
| `hardening_direction` | one of the directions above |
| `breakage_level` | `low`, `medium`, `high`, or `unknown` |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `status` | `action_required`, `review`, or `monitor` |
| `ready_for_apply` | `true` / `false` |
| `search` | free-text search across plan, principal change, condition recommendations, statement snippet, affected caller, breakage projection, rollback, and verification fields |

Response shape: `{ "plans": AWSTrustPolicyHardeningResult }` with
summary, ranked plans, graph relationships, caveats, failure reasons,
remediation hints, evidence links, coverage gaps, diagnostics, and the
standard tenant/workspace/project metadata.

## Evidence boundary

The engine never reads, stores, logs, or displays rendered IAM policy
bodies, secret values, prompts, completions, tool inputs/outputs,
browser pages, code-interpreter output, database rows, object
contents, customer payloads, or workload payloads. It composes only
the upstream cross-account-trust finding refs, principal identifiers,
condition-key labels, and runtime/analyzer evidence pointers.

`before_ref` / `after_ref` on each statement snippet carry projection
URIs (e.g. `trust-policy://<finding>/scoped-projection`) — never
rendered JSON.

## AWS permissions

This capability adds no live mutation and requires no additional AWS
permissions beyond what the cross-account-trust engine (#1526) already
needs. It reuses that engine's read-only metadata access.

Do not grant IAM write permissions for this issue.

## Ready-for-apply derivation

A plan is marked `ready_for_apply: true` only when *all* of the
following hold:

1. `public_principal == false`, **and**
2. `breakage_projection.level == "low"` (runtime *and* Access Analyzer
   both confirm the caller set), **and**
3. at least one condition is recommended, **and**
4. `confidence >= 0.80`.

Public principals always stay non-executable; unknown breakage stays
non-executable; plans with no condition recommendation stay
non-executable.

## Failure handling

- **Ready**: cross-account-trust was available and emitted no blocking
  diagnostics.
- **Degraded**: cross-account-trust returned partial, degraded, or
  retryable diagnostics. Plans already composed remain visible.
- **Blocked**: cross-account-trust is permission denied. The response
  has zero plans plus diagnostics and failure reasons.

Unknown, unsupported, partial, degraded, and permission-denied
evidence stays explicit and is not treated as proof that a plan is
safe to apply.

## App surface

The AWS Runtime app surface renders the **AWS trust policy hardening
planner** panel with each plan's resource, hardening direction,
principal change, condition recommendation count, breakage level,
ready-for-apply flag, verification strategy, and evidence refs.
Loading, empty, error, degraded, and permission-denied states are
explicit.

## Live validation

1. Confirm blockers #1526 and #1529 are closed.
2. Run cross-account-trust with `fixture_state=success`.
3. Run the trust-policy hardening endpoint with `fixture_state=success`
   and confirm plans appear for public, cross-account, and runtime
   assumption findings.
4. Filter by `hardening_direction=remove_public_principal`,
   `breakage_level=low`, `ready_for_apply=true`, and `search` to verify
   deterministic drill-down.
5. Run `fixture_state=permission_denied`, `empty`, `degraded`, and
   `partial_failure` and confirm blocked/degraded states are explicit.
6. Confirm the AWS Runtime app panel renders success, empty, degraded,
   permission-denied, and partial-failure states without exposing
   rendered policy bodies or secret values.

## Safety gates

- Read-only. No IAM write API is called by this issue.
- All plans include `read_only_projection: true`.
- All plans include rollback and verification plans, so a future
  executor has the safety scaffolding the moment it can land approved
  changes.
- `ready_for_apply` is derived deterministically — it is a hint to
  consumers, not an instruction to execute.
- Conditions already present on the upstream finding are never
  re-recommended, so the planner cannot accidentally suggest
  duplicate or weaker conditions.
