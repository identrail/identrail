# AWS Connector

PR 7 adds the hosted AWS connector onboarding path behind two feature flags:

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

1. The UI calls `POST /v1/connectors/aws` with `workspace_id` and `project_id`.
2. The API generates a 32-byte External ID, stores it encrypted, creates a pending AWS connector, and returns an AWS CloudFormation launch URL.
3. The user launches the stack in AWS. The stack creates an `IdentrailReadOnly` role with a trust policy requiring the External ID.
4. The user pastes the created role ARN back into Identrail.
5. The API uses the stored External ID, assumes the role with STS, verifies caller identity, checks scanner-critical IAM read access, and marks the connector active or degraded.

The read-only policy and rationale live together under `deploy/connectors/aws/policies/`.

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
