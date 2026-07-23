# AWS Organization StackSet onboarding

Implements [#1504](https://github.com/identrail/identrail/issues/1504) and the
connector-start backend contract from
[#1752](https://github.com/identrail/identrail/issues/1752). This is the
operator-facing setup flow that previews, launches, and recovers the
organization-wide CloudFormation StackSet that deploys Identrail's read-only AWS
connector role into member accounts.

The implementation is **read-only**, **metadata-only**, and **non-mutating**.
Identrail never executes the StackSet on the operator's behalf — it generates a
deterministic plan, surfaces the AWS console launch URL, and tracks per-instance
state for recovery. Customer payloads, secret values, database rows, and object
contents are never read.

## What this issue ships

- A deterministic planner in `internal/providers/awscontract/stackset_onboarding.go`
  that turns a connector + Organizations topology + coverage plan + checkpoint set
  into a stable, resumable onboarding plan. The same inputs always produce the
  same output.
- A scoped API at
  `GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/stackset-onboarding`
  with `success`, `empty`, `degraded`, `partial_failure`, and `permission_denied`
  fixture states, a `deployment_mode` query parameter (`service_managed` or
  `self_managed`), and explicit failure reasons, recovery actions, and evidence
  links.
- First-class connector setup through `POST /v1/connectors/aws` for
  `scope_type=organization`, `scope_type=selected_ous`, and
  `scope_type=selected_accounts`. The start response returns the StackSet launch
  URL, StackSet name, template checksum, target summary, prerequisites, setup
  lifecycle fields, and unified `stackset_onboarding` payload.
- A CloudFormation StackSet console launch URL builder in
  `internal/connectors/aws/cfn.go` that pins the template URL, parameter set,
  permission model, organizational units, account ids, and home deployment region
  without ever embedding a secret value in the URL.
- A web app surface (`AWS → Accounts`) that renders the validation verdict,
  prerequisites, permission preview, target accounts/OUs/regions, per-instance
  state, coverage expectations, recovery actions, and the StackSet launch
  button. Loading, error, empty, blocked, degraded, and permission-denied
  states are explicit; partial failures keep their resumable cursor.

## Prerequisites

- AWS Organizations is enabled in the management account.
- For **service-managed** deployments, trusted access is enabled for
  CloudFormation StackSets in AWS Organizations (or a delegated administrator
  is registered).
- For **self-managed** deployments, an
  `AWSCloudFormationStackSetAdministrationRole` is reachable from the management
  account and `AWSCloudFormationStackSetExecutionRole` is bootstrapped in each
  target account.
- The Identrail read-only connector template URL is configured on the runtime
  as a content-addressed URL that includes the release SHA-256 digest, and
  StackSet launches also have the matching release checksum configured
  (`IDENTRAIL_AWS_CFN_TEMPLATE_URL` and `IDENTRAIL_AWS_CFN_TEMPLATE_SHA256`).
- An external ID is generated for the connector trust policy.

The planner reports each prerequisite (`stackset.template_pinned`,
`stackset.external_id_configured`, `stackset.trusted_access_enabled`,
`stackset.delegated_admin_registered`,
`stackset.administration_role_configured`, `stackset.targets_present`,
`stackset.suspended_accounts_excluded`) with a `blocking` or `advisory`
severity, a human-readable reason, and a remediation hint.

## API output

The response includes:

- `stack_set_name`, `template_url`, `template_checksum`, `launch_url`,
  `deployment_mode`, and `partition`.
- `target_summary` on connector start/poll responses. For Organization and OU
  scopes, account and expected-instance counts are marked unknown because AWS
  resolves member accounts during StackSet deployment. Self-managed selected
  account scopes report exact counts after exclusions are applied. Service-
  managed selected account scopes mark those counts unknown because AWS applies
  the selected account IDs as an `INTERSECTION` filter inside the supplied root
  or OU and may drop accounts outside that boundary.
- `target_regions` on connector start/poll responses preserve the operator's
  scan-region intent. The StackSet launch itself uses only the first normalized
  region as the home deployment region because the connector template creates a
  fixed-name IAM role, and IAM roles are global within an AWS account.
- `validation` — `ready` / `degraded` / `blocked` / `permission_denied` with
  blocking/advisory prerequisite counts, failure reasons, and remediation hints.
- `permission_preview` — the read-only discovery permission tier (and the
  separate runtime-evidence, remediation-plan, advisory, approved-remediation,
  and authorization-enforcement tiers that are advertised as *unavailable* so
  write tiers are never granted silently).
- `targets` — target accounts (with OU path, management flag, suspended flag),
  target regions (with opt-in flag), and the OU tree.
- `instances` — one row per account/region pair with `state`, `stack_id`,
  `operation_id`, `failure_reason`, `attempts`, `resumable`, `next_action`,
  `coverage_targets`, `evidence_ref`, and `observed_at`.
- `coverage_expectation` — projected accounts, regions, instances, coverage
  targets, and percent coverage when the StackSet succeeds, calculated against
  the existing coverage planner output. Global services (for example IAM) are
  anchored to a single home-region instance per account, not fanned out per
  region.
- `recovery_actions` — operator-actionable recovery for retry-failed-instances,
  fix-permission-denied, and remove-suspended-accounts (plus one
  `fix-*` action per unsatisfied blocking prerequisite).
- `summary` — totals across instance states, deployed percent.
- `diagnostics`, `coverage_gaps`, `evidence_links`, `failure_reasons`,
  `remediation_hints`.

The console `launch_url` carries no AWS access keys, secret access keys, session
tokens, customer payloads, or object contents. It does include setup-safe
CloudFormation parameters such as the generated external ID, pinned template URL,
permission model, target OU IDs, account filters, and the home deployment
region. Additional connector `target_regions` remain scan intent for later
collector fan-out; they are not sent as extra StackSet regions for the read-only
IAM role template.

The start route is still setup-only. It persists declared Organization/OU/account
target intent in connector metadata, but it does not create graph nodes or report
confirmed coverage until a later validation pass observes deployed StackSet
instances.

## Service-managed vs self-managed

- `stackset_service_managed` is the default for AWS Organizations and selected
  OU onboarding. AWS CloudFormation StackSets uses Organizations trusted access
  to deploy into member accounts. Identrail generates the console launch URL and
  prerequisite plan; the operator enables trusted access or delegated admin in
  AWS when required.
- `auto_onboard_new_accounts` is serialized into the service-managed StackSet
  launch URL so the AWS console creates the StackSet with the requested
  automatic-deployment setting instead of relying on console defaults. Identrail
  sets retained-on-removal to false for this connector role so accounts removed
  from targeted OUs do not keep stale read-only access.
- `scope_type=organization` with `stackset_service_managed` must include the
  organization root ID in `target_ou_ids`. Use `scope_type=selected_ous` for OU
  rollout. Organization and selected-OU scopes reject
  `target_account_ids` so their operator-visible scope cannot drift into an
  account-filtered rollout. Selected-OU scope accepts only `ou-...` IDs; roots
  are reserved for organization-wide rollout or selected-account account-filter
  context. `scope_type=selected_accounts` also requires a root or OU target, and
  AWS applies the selected account IDs as an account filter inside that root or
  OU target. If exclusions remove every selected account, or if selected-account
  setup asks for future-account auto-onboarding, the request is rejected instead
  of launching against a broader root or OU.
- `stackset_self_managed` is allowed only for explicit selected account IDs in
  this backend contract. The planner blocks until an administration role is
  configured because self-managed StackSets need operator-managed admin and
  execution roles.

AWS references:

- [CloudFormation StackSets with AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate-cloudformation.html)
- [Create service-managed StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-associate-stackset-with-org.html)
- [Enable trusted access for StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-activate-trusted-access.html)

## Instance state lifecycle

| State | Meaning |
| --- | --- |
| `pending` | Deployment has not started. |
| `validating` | Prerequisites are being checked. |
| `blocked` | Blocking prerequisites are unmet. |
| `deploying` | CloudFormation operation is in flight. |
| `active` | Instance deployed; collector is emitting coverage. |
| `degraded` | Instance succeeded but validation drifted. |
| `failed` | Deployment failed; retryable. |
| `permission_denied` | AWS rejected the StackSet operation; recovery action surfaces the fix. |
| `unsupported` | Region or account class is not supported. |
| `suspended` | Account is suspended; remove or reactivate. |
| `canceled` | Operator canceled before completion. |

`active` and `canceled` are non-resumable; every other state is resumable so the
operator can re-run a focused recovery.

## What is intentionally not collected

- Secret values, parameter values, environment values, database rows, object
  contents, prompts, completions, or browser pages.
- Live StackSet execution — the operator launches the StackSet via the AWS
  console URL Identrail surfaces; Identrail does not call CloudFormation on the
  operator's behalf.
- Write or remediation tiers — the bundled template only grants the read-only
  discovery tier. Remediation, approved-remediation, and
  authorization-enforcement tiers must be granted through a dedicated write
  role.

## Fixture states

- `success` — three target accounts × two regions with two active checkpoints
  and a ready validation verdict.
- `empty` — no target accounts/regions, blocking on `stackset.targets_present`.
- `degraded` — delegated administrator missing, one suspended account in the
  target set, two active instances.
- `partial_failure` — one failed and one permission-denied instance with
  resumable cursors and operator recovery actions.
- `permission_denied` — trusted access disabled and external ID missing,
  validation `blocked`.

## Live validation

1. From the project's AWS surface, open `AWS → Accounts` once a connector is
   active.
2. Confirm the StackSet onboarding panel shows the validation verdict, target
   counts, expected coverage, and prerequisites.
3. Resolve any blocking prerequisites (trusted access, external ID, template
   URL).
4. Click **Open StackSet launch URL** to open the AWS console and authorize
   the operation. Identrail does not execute the StackSet.
5. As CloudFormation operation status changes, re-fetch the onboarding plan;
   per-instance state, cursors, and recovery actions reflect the latest
   checkpoints.

## Out of scope (next-wave issues)

- Live execution of the StackSet operation from Identrail.
- Drift detection across deployed stack instances.
- Deletion / rollback orchestration.
