# AWS IaC remediation PR and verification plan generator

Issue #1535 adds a metadata-only generator that turns IAM least-privilege diffs
(issue #1530) and trust-policy hardening plans (issue #1531) into ranked,
read-only IaC remediation PR plans. Each plan ships file change intent, local
validation hints, cloud verification checks, PR notes, rollback, verification,
and readiness gates so operators can land the change through their own
source-control system instead of guessing how to translate Identrail evidence
into Terraform, CloudFormation, CDK, or policy-as-code edits.

The generator is read-only. It never opens, pushes, or merges a PR, never calls
AWS IAM write APIs, and never reads, exposes, logs, or persists rendered IaC
bodies, rendered policy bodies, secret values, prompts, completions, browser
pages, code-interpreter output, database rows, object contents, customer
payloads, or workload payloads.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/iac-remediation-plans`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `identity` | identity node ID, identity ARN, identity name, resource node ID, or resource ARN match |
| `iac_target` | `terraform`, `cloudformation`, `cdk`, or `policy_as_code` |
| `change_kind` | `iam_policy_diff` or `trust_policy_hardening` |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `status` | upstream-derived plan status |
| `ready_for_apply` | `true` / `false` |
| `search` | free-text search across plan, file change, validation, verification, PR notes, rollback, and evidence fields |

Response shape: `{ "plans": AWSIaCRemediationResult }` with
tenant/workspace/project metadata, summary counts, ranked plans,
relationships, caveats, failure reasons, remediation hints, evidence links,
coverage gaps, diagnostics, and generated timestamps.

## Plan shape

Each `AWSIaCRemediationPlan` includes:

- stable `plan_id`, calculation version, source artifact ID, issue refs, score,
  confidence, status, and severity
- `change_kind` (`iam_policy_diff` or `trust_policy_hardening`) plus `iac_target`
  (`terraform`, `cloudformation`, `cdk`, or `policy_as_code`)
- `file_changes` with path, change intent, IaC resource type, and before/after
  metadata refs
- `validation_hints` describing the local commands the operator should run
  before the PR (e.g. `terraform plan`, `cfn-lint`, `cdk diff`, `conftest test`)
- `cloud_verification` describing the cloud signals to watch after merge (e.g.
  IAM policy simulator, CloudTrail, IAM last-used, Access Analyzer)
- `pr_notes` skeleton (title, summary, labels, evidence refs, reviewers) so the
  operator can paste a consistent PR body in their source-control system
- `diff_intent`, tradeoffs, rollback plan, verification plan, readiness gates,
  impacted graph nodes, and evidence refs
- `ready_for_apply`, which is only a planning signal — Identrail never opens the
  PR, never applies the IaC change, and never calls IAM write APIs

`ready_for_apply` is true only when the upstream IAM diff or trust hardening
plan is itself ready for apply and the IaC readiness gates pass (read-only
projection, upstream readiness, and — for trust hardening — a public-principal
review gate). Plans driven by low-confidence, manual-review, or
public-principal upstream evidence stay blocked.

## Failure handling

- **Ready**: upstream IAM diff and trust hardening are available and at least
  one IaC PR plan can be composed.
- **Degraded**: one or both upstream sources are partial, degraded, or
  diagnostic-bearing; composed plans stay visible when safe.
- **Blocked**: upstream permission-denied evidence emits zero plans plus
  failure reasons, remediation hints, diagnostics, and coverage gaps.

Unsupported, empty, partial, degraded, and permission-denied states stay
explicit. The generator does not convert absence of upstream evidence into a
deterministic IaC PR.

## App surface

The AWS Runtime page renders an **AWS IaC remediation PR generator** panel with
plan title, change kind, IaC target and file count, validation tools, readiness
gate, severity/status pill, and cloud verification count. Loading, empty,
degraded, blocked, and error states are explicit.

## Validation

1. Confirm blockers #1530 and #1531 are closed.
2. Run IAM policy diff and trust hardening upstreams with `fixture_state=success`.
3. Call the IaC remediation endpoint with `fixture_state=success` and verify
   at least one IaC PR plan includes file changes, validation hints, cloud
   verification, PR notes, rollback, and verification.
4. Filter by `iac_target=terraform`, `change_kind=iam_policy_diff`,
   `ready_for_apply=true`, and `search=terraform validate`.
5. Run `fixture_state=empty`, `degraded`, `partial_failure`, and
   `permission_denied` and confirm the status, diagnostics, and failure reasons
   stay explicit.

## What is intentionally out of scope

- Opening, pushing, or merging PRs in the operator's source-control system.
- Live AWS IAM, trust policy, or organization SCP mutation.
- Rendering full IaC bodies, policy bodies, or workload payloads.
- Wave-8 approval, dry-run, apply, and verify executors.
