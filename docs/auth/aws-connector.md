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

`IDENTRAIL_AWS_CFN_TEMPLATE_URL` points to the published CloudFormation
template. StackSet onboarding requires this URL to be content-addressed with
the same SHA-256 digest supplied in `IDENTRAIL_AWS_CFN_TEMPLATE_SHA256` as a
`/sha256/<digest>/` path segment; mutable template URLs, query-string digests,
and fragments are rejected before Identrail returns a launch URL.

`IDENTRAIL_AWS_CFN_TEMPLATE_SHA256` is the release-provided SHA-256 checksum for
that exact template. Automatic single-account and StackSet onboarding require
it before Identrail returns a launch URL.

`IDENTRAIL_AWS_ACCOUNT_ID` is the AWS account ID for the Identrail deployment that customer roles should trust.

`IDENTRAIL_AWS_REGISTRATION_TOPIC_ARNS` maps every supported setup region to
the Identrail-owned SNS custom-resource provider in that region. Use
`region=topic-arn` entries separated by commas. The API refuses to launch a
single-account stack in a region without a provider.

The worker also needs `IDENTRAIL_AWS_REGISTRATION_QUEUE_URL` and
`IDENTRAIL_AWS_REGISTRATION_QUEUE_REGION`. The Terraform deployment can create
the SNS topic, encrypted SQS queue, dead-letter queue, worker policy, and alarm
with `create_aws_connector_registration_provider=true`.

When a persistent database is configured and AWS connector setup is enabled, `IDENTRAIL_CONNECTOR_SECRET_KEYS` must also be configured. The generated External ID is stored as a connector secret envelope, not plaintext connector metadata.

## Flow

The app presents AWS setup as a scope-first wizard. Supported executable paths
are **Single AWS account** through CloudFormation, **Organization** through a
service-managed StackSet, **Selected OUs**, **Selected accounts**, and
**Existing IAM role** for teams that manage IAM through their own change
process.

1. The operator chooses **Single AWS account**, adds a display name, and picks
   the home region used for setup.
2. The UI calls `POST /v1/connectors/aws` with `workspace_id`, `project_id`,
   display name, region, and the CloudFormation defaults.
3. The API creates an expiring onboarding attempt, stores only its token hash,
   generates and encrypts the connector External ID, and returns a prefilled
   CloudFormation launch URL.
4. The operator reviews and approves the stack in AWS. This is the only AWS-side
   action; no Identrail IDs, ARNs, access keys, or secret keys are copied.
5. The stack's SNS custom resources obtain the External ID, create the
   `IdentrailReadOnly` role, and register the role back to the same pending
   connector. The launch token is single-use, expires after two hours, and
   cannot call AWS APIs.
6. The worker acknowledges CloudFormation, assumes the role with the encrypted
   External ID, verifies `sts:GetCallerIdentity`, checks scanner-critical
   read access, and records a real validation time.
7. The app polls with bounded backoff through **Waiting for approval**,
   **Creating role**, and **Verifying access**, then renders **Connected** or one
   repair action.

The normal CloudFormation path never asks for an External ID, session name, or
role ARN. Manual ARN validation is collapsed under **Troubleshooting** and is
only a recovery path.

If the app calls `POST /v1/connectors/aws` again with the same `connector_id`,
the API resumes the active attempt without rotating its External ID, attempt,
or token. Launch URLs containing the short-lived token are rebuilt on demand
and are never persisted in connector metadata. Poll and status responses expose
only lifecycle, diagnostics, and safe next actions; they never serialize the
token or External ID.

CloudFormation quick-create links do not populate `NoEcho` parameters. The
automatic path therefore does not try to pass the long-lived External ID in the
URL. It passes an expiring registration grant, consumes it during bootstrap,
and returns the encrypted-at-rest External ID through the custom-resource
response with `NoEcho` enabled.

## Manual IAM role setup

Manual setup uses the same standard connector API as the CloudFormation path:

```json
{
  "workspace_id": "workspace-a",
  "project_id": "production",
  "scope_type": "manual_role",
  "deployment_method": "manual",
  "display_name": "Production AWS",
  "region": "us-east-1"
}
```

The API creates a pending AWS connector, generates a connector-specific
External ID, stores it encrypted, and returns that External ID only in the setup
response. The app uses it to render a copyable trust policy for the operator's
IAM change process. Status and poll responses report that an External ID is
configured, but do not return the value.

The customer's role trust policy must allow the Identrail deployment AWS account
to call `sts:AssumeRole` and must require the generated External ID:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<IDENTRAIL_AWS_ACCOUNT_ID>:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "<GENERATED_EXTERNAL_ID>"
        }
      }
    }
  ]
}
```

After the role exists, the app calls
`POST /v1/connectors/aws/{connector_id}/validate` with the role ARN, project
scope, region, and optional session name. If `external_id` is omitted, the API
loads the External ID from the connector-scoped secret envelope. That fallback is
deliberate: validation must never silently use a value from another workspace,
project, or connector.

The read-only policy and rationale live together under `deploy/connectors/aws/policies/`.
The current CloudFormation template is version `2.2.0`; update existing connector
stacks so the role includes the permissions used by every enabled metadata
collector. The standalone and legacy policy artifacts are kept in parity with
that same action contract.

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
  `excluded_account_ids`: normalized setup target lists. For StackSet setup,
  `target_regions` records scan-region intent; the read-only IAM role StackSet
  deploys in the first normalized home region only because the role is global
  within each AWS account.
- `auto_onboard_new_accounts`: whether service-managed Organization or OU
  StackSets should automatically deploy the connector role to future accounts
  added under the target. Selected-account StackSets reject this flag because
  AWS automatic deployments are OU-scoped and do not honor account filters.
- `setup_summary` and `next_actions`: short app-facing guidance for the next
  safe operator action.

For backward compatibility, an omitted scope on `POST /v1/connectors/aws`
defaults to `single_account` with `cloudformation`. The legacy direct role
validation path reports `manual_role` with `manual`. Invalid combinations are
rejected before setup is persisted: manual role setup must use `manual`,
organization and selected scopes must use a StackSet deployment method,
organization scope must include an organization root target,
organization and selected-OU scopes reject `target_account_ids`,
selected-OU scope accepts only `ou-...` IDs and rejects organization roots,
service-managed selected accounts must include account filters, selected-account
exclusions must leave at least one effective account, selected-account
auto-onboarding is rejected, and malformed AWS account IDs, OU IDs, and regions
fail validation.

The executable `POST /v1/connectors/aws` setup path supports
`single_account`/`cloudformation`, `manual_role`/`manual`,
`organization`/`stackset_service_managed`, `selected_ous`/
`stackset_service_managed`, and selected-account StackSet setup. Terraform
remains reserved for follow-on implementation issues.

## Connected State

After validation succeeds, the AWS Connect page opens on a connected summary
instead of the setup wizard. The summary shows the active scope, account and
region coverage, connector health, last validation time, permission health, and
baseline readiness. It links operators into the AWS overview, machine identity
inventory, coverage gaps, and findings when health is degraded.

Setup controls stay hidden for connected environments until the operator chooses
**Manage connection**. Opening management intentionally reveals the existing
wizard for expanding scope, refreshing status, or validating a repaired role.
Switching environments closes management and clears setup drafts so role ARNs,
External IDs, StackSet targets, and stale async responses cannot leak across
project scopes.

Each scope carries an explicit tradeoff in the success state:

- Single account is narrow and predictable; use management to expand coverage.
- Organization scope can include future accounts automatically, unless the
  connector was created with fixed targets.
- Selected OUs follow accounts in those OUs only.
- Selected accounts stay pinned to the listed account IDs.
- Manual role setup leaves IAM trust and permissions under the customer's
  external change process.

The hosted CLI exposes the same status without returning connector secrets:

```bash
identrail aws-status \
  --api-url "$IDENTRAIL_API_URL" \
  --api-key "$IDENTRAIL_API_KEY" \
  --tenant-id tenant-a \
  --workspace-id workspace-a \
  --project-id production
```

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
