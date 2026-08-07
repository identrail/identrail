# AWS Organization rollout

This document covers the AWS Organization / StackSet rollout slices (identrail/identrail#1788). It builds on the single-account auto-registration handshake shipped in [#1790](https://github.com/identrail/identrail/pull/1790) (issue #1787), the StackSet backend from [#1768](https://github.com/identrail/identrail/pull/1768), and the org/selected-scope UI from [#1777](https://github.com/identrail/identrail/pull/1777).

## What this slice ships

- Controlling-account validation gate. A rollout cannot be opened unless a management or delegated-administrator AWS connector is Connected. This prevents launching organization-scale infrastructure from an unproven account.
- Rollout envelope service. One approved rollout persists organization ID, selected OUs/accounts, exclusions, regions, auto-deployment intent, expected role name, template version/checksum, tenant and environment scope, expiry, and a random one-time registration secret. Only the SHA-256 hash of the secret is persisted.
- Per-target state persistence. Every expected `(account, region)` pair is seeded on rollout creation and transitions independently as authenticated events arrive. States: `pending`, `deploying`, `registering`, `validating`, `connected`, `partial`, `failed`, `excluded`, `suspended`, `removed`.
- Extension of the existing #1787 registration channel. Member-account stack instances publish to the same regional SNS registration topic; the API routes on the presence of `RolloutId` in the CloudFormation custom-resource properties, verifies scope and secret, and idempotently upserts the target row.
- Progress read model. `GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/rollouts/{rollout_id}` returns aggregate counts and the exact per-target list, sortable in the UI.
- Minimal UI panel in the AWS Connect page. It renders below the existing StackSet progress panel, seeds the operator flow from the same scope form, and polls for status.
- Reconciliation slice. A bounded worker validates registered member roles with STS and IAM read checks, recovers stale registrations, derives aggregate rollout state from target rows, and preserves per-target diagnostics and evidence.
- Live AWS reconciliation. The controlling role reads Organizations and CloudFormation StackSet metadata on every reconciliation pass. OU-only scopes are expanded into exact account IDs, new accounts are added when auto-deploy is enabled, OU moves and removed accounts leave coverage, inactive accounts are suspended, and missing, unhealthy, or drifted StackSet instances become explicit failed targets.
- Repair controls. `Reconcile now` refreshes a rollout immediately; `Retry failed targets` resets only retryable failed targets inside the original approved account/region envelope. Targets with an existing role return directly to validation; targets without a role return to pending registration.

## Deliberate boundaries

The connector remains read-only. Identrail observes Organizations and StackSet
state, validates roles, and gives operators scoped recovery actions; it does not
silently delete or update customer CloudFormation resources. Large-account
load qualification uses deterministic provider fakes in CI, while a controlled
AWS organization remains the release gate for service quotas and throttling.

## Controlling-account setup

1. Connect an AWS account for the organization's management or delegated-administrator role using the existing `POST /v1/connectors/aws` flow. The connector must reach `Connected`.
2. From the AWS Connect page, choose the StackSet scope, review targets, and pick the regions.
3. Click **Start rollout**. The app calls `POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/rollouts` with the exact scope from the form.
4. Open the returned AWS StackSet console launch URL to authorize the rollout. AWS will provision `AWS::CloudFormation::StackInstance` in each eligible member account.
5. As each member instance completes, its `Custom::IdentrailAWSConnectorRegistration` resource publishes to the regional Identrail registration topic. Identrail verifies the rollout binding, upserts the target row, and progresses the rollout to `in_progress`.
6. The worker periodically refreshes Organizations and StackSet state, then validates registered roles. If delivery is delayed beyond the registration timeout, the target receives the retryable `registration_missing` diagnostic. Use **Reconcile now** for an immediate pass or **Retry failed targets** after repairing a retryable AWS-side failure.

## Security properties

- The registration secret is derived server-side from the rollout's stable identity plus a sealed key material version, hashed with SHA-256 for at-rest storage, and compared using constant-time comparison. It is never persisted in plaintext, never logged, and never returned via any API path other than the CloudFormation launch parameters.
- The topic ARN a registration event arrives on must be in the operator-configured allowlist. Any envelope from an unlisted topic is rejected before any persisted state is loaded.
- Every member-account event must match the exact rollout binding: organization ID, stack-set name, template version, expected role name, allowed regions, and (for selected-account rollouts) the explicit account list.
- Cross-account replay is rejected because the stack ARN's account must equal the role ARN's account and the region must be in the rollout's allowed set.
- CloudFormation deletion is never blocked by a missing or expired rollout; the delete callback path from #1787 is reused.

## API summary

- `POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/rollouts` opens a rollout envelope. Requires `tenancy.write`.
- `GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/rollouts/{rollout_id}` returns the current envelope and per-target state. Requires `tenancy.read`.
- `POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/rollouts/{rollout_id}/reconcile` performs one bounded reconciliation pass. Requires `tenancy.write`.
- `POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/rollouts/{rollout_id}/retry` resets selected retryable targets without expanding the approved scope. Requires `tenancy.write`.

Both routes are covered by the OpenAPI v1 spec and the route-policy registry.

## Rollout states

| Status | Meaning |
| ------ | ------- |
| `created` | Envelope created; awaiting first authenticated event or operator launch. |
| `launching` | Reserved for future launch orchestration. |
| `in_progress` | At least one member-account event has landed. |
| `reconciling` | A reconciliation pass is waiting on one or more expected targets. |
| `completed` | All expected targets terminal-healthy. Reconciliation is required to compute this. |
| `partial` | Some targets healthy, others failed. Reconciliation required. |
| `failed` | Whole envelope in an unrecoverable terminal error. |
| `expired` | Envelope aged past its lifetime; a new rollout is required. |
| `canceled` | Explicitly canceled by an operator. |

## Per-target states

| State | Meaning |
| ----- | ------- |
| `pending` | Seeded from expected set; no event yet. |
| `deploying` | Reserved for reconciliation reports of AWS deployment in progress. |
| `registering` | Reserved for a mid-flight registration handshake. |
| `validating` | Authenticated registration event landed and the role is queued for STS/IAM validation. |
| `connected` | Role validated by an authenticated STS check plus required read-only permission checks. |
| `partial` | Multi-region target with some regions healthy. |
| `failed` | Authentication failed, role invalid, or permission checks failed. |
| `excluded` | Operator listed this account in the rollout's exclusion set. |
| `suspended` | Reconciliation detected the account is suspended in AWS Organizations. |
| `removed` | Reconciliation detected the account was removed from the organization. |

## Operations

- `identrail aws-rollout-reconcile` runs the same bounded refresh as the app's
  **Reconcile now** control.
- `identrail aws-disable`, `identrail aws-enable`, and
  `identrail aws-disconnect` mirror the app lifecycle controls. Disconnect
  requires `--confirm` to exactly match the connector ID.
- Update organization connector stacks to template `2.1.0` before expecting
  live Organizations and StackSet inventory. The template adds read-only
  Organizations and `cloudformation:ListStackInstances` permissions.
