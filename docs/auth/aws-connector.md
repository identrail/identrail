# AWS Connector

The hosted AWS connector onboarding path is behind two feature flags:

- Backend: `IDENTRAIL_FEATURE_CONNECTOR_AWS=true`
- Frontend: `VITE_FEATURE_CONNECTOR_AWS=true`

The product path is the standard connector API. Older project-scoped AWS routes are not the product path and should not be used by new UI:

```text
POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/connection
```

The new CloudFormation flow uses:

```text
POST /v1/connectors/aws
GET  /v1/connectors/aws/{connector_id}/poll
POST /v1/connectors/aws/{connector_id}/validate
POST /v1/connectors/aws/{connector_id}/refresh-policy
```

## Required Runtime Configuration

`IDENTRAIL_AWS_CFN_TEMPLATE_URL` points to the published CloudFormation template.

`IDENTRAIL_AWS_ACCOUNT_ID` is the AWS account ID for the Identrail deployment that customer roles should trust.

When a persistent database is configured and AWS connector setup is enabled, `IDENTRAIL_CONNECTOR_SECRET_KEYS` must also be configured. The generated External ID is stored as a connector secret envelope, not plaintext connector metadata.

## Flow

1. The UI calls `POST /v1/connectors/aws` with `workspace_id`, `project_id`, and optional connector display fields.
2. The API normalizes the single-account CloudFormation setup, generates a 32-byte External ID, stores it encrypted, creates a pending AWS connector, and returns an AWS CloudFormation launch URL.
3. The user launches the stack in AWS. The stack creates an `IdentrailReadOnly` role with a trust policy requiring the External ID.
4. The user pastes the created role ARN back into Identrail.
5. The API uses the stored External ID, assumes the role with STS, verifies caller identity, checks scanner-critical IAM read access, and marks the connector active or degraded.

If the app calls `POST /v1/connectors/aws` again with the same `connector_id`, the API resumes the existing setup instead of rotating the External ID or changing the launch parameters. This keeps the AWS trust policy, CloudFormation stack parameters, and Identrail connector record aligned while a user retries or returns to setup. Poll and status responses expose lifecycle fields, setup summary, launch URL, template URL, policy hash, diagnostics, and next actions, but they do not serialize the External ID.

The read-only policy and rationale live together under `deploy/connectors/aws/policies/`.

## Scope Contract

AWS connector setup now carries an explicit onboarding contract in both the
start request and connection status response. The contract describes operator
intent; it does not prove that Identrail has observed every account or region
yet. Runtime coverage remains separate in the account and region coverage
registry.

The contract fields are:

- `scope_type`: `single_account`, `organization`, `selected_ous`,
  `selected_accounts`, or `manual_role`.
- `deployment_method`: `cloudformation`, `stackset_service_managed`,
  `stackset_self_managed`, `terraform`, or `manual`.
- `onboarding_status`: `draft`, `launch_ready`, `waiting_for_aws`,
  `validating`, `connected`, `partial`, `needs_fix`, or `failed`.
- `target_regions`, `target_account_ids`, `target_ou_ids`, and
  `excluded_account_ids`: normalized setup target lists.
- `auto_onboard_new_accounts`: whether future organization accounts should be
  included automatically once StackSet onboarding owns that path.
- `setup_summary` and `next_actions`: short app-facing guidance for the next
  safe operator action.

For backward compatibility, an omitted scope on `POST /v1/connectors/aws`
defaults to `single_account` with `cloudformation`. The legacy direct role
validation path reports `manual_role` with `manual`. Invalid combinations are
rejected before setup is persisted: manual role setup must use `manual`,
organization and selected scopes must use a StackSet deployment method,
selected OUs/accounts must include targets, and malformed AWS account IDs, OU
IDs, and regions fail validation.

The executable `POST /v1/connectors/aws` setup path currently supports
`single_account`/`cloudformation` read-only onboarding. Organization,
selected-OU, selected-account, Terraform, and full manual app flows remain
reserved for the follow-on implementation issues.

## Account and Region Coverage Registry

AWS connector health answers whether Identrail can assume the configured connector role. The account and region coverage registry answers a separate product question: which AWS accounts and regions are currently in scope, covered, pending, or blocked.

The [AWS platform baseline gate](../aws-platform-baseline.md) combines connector
health with graph contract, queue, fixture, and app prerequisites before
project-scoped AWS scans or remediation work can start.

The [AWS platform validation harness](../aws-platform-validation-harness.md)
provides deterministic browser and API proof states for AWS setup, scan, graph,
runtime, remediation, and governance app surfaces as future AWS waves land.

The [AWS service collector contract](../aws-service-collector-contract.md)
defines the normalized record fields, graph edge semantics, fixture cases,
read-only permission boundary, and failure states that future AWS service
collectors must reuse.

The registry is intentionally internal for now because the UI flow is not ready. Services can write coverage rows through the AWS service layer after discovering organization accounts, selected regions, or scan outcomes. Each row is scoped by tenant, workspace, project, connector, account ID, and region, and can store organization metadata, the connector role ARN, coverage status, the last successful scan time, the last scan error, a scan cursor, and account/region availability flags.

Use the registry when a scanner, connector workflow, or future UI needs to distinguish these states:

- `covered`: Identrail has successfully scanned the account and region.
- `pending`: the account and region are known but not scanned yet.
- `gap`: the account and region should be covered but are not currently covered.
- `error`: the latest scan failed and `last_scan_error` should explain why.
- `suspended`, `disabled`, or `unreachable`: AWS reported the account or region cannot currently be scanned.

See [AWS account and region coverage](../aws-account-region-coverage.md) for the storage contract and operating notes.
