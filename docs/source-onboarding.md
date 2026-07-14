# Source Onboarding

Identrail source onboarding is available from the authenticated product shell at:

`/app/{tenant_id}/{workspace_id}/projects/{project_id}`

The project detail view presents a guided connect-source wizard for GitHub, AWS, and Kubernetes. It reads current source status first, then uses the current connector onboarding path for AWS, while the other provider flows still use their established project-scoped routes where applicable.

## GitHub

The wizard starts the GitHub App installation flow through:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/github/connect/start`

After installation metadata is available, the wizard saves the project connection through:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/github/connect/complete`

The UI keeps repository selection explicit and stores only credential references plus encrypted webhook-secret metadata returned by the API.

Once the GitHub connection is active, the same project detail view can queue the first repository exposure scan for a selected repository through:

`POST /v1/repo-scans`

The action uses the tenant/workspace scope headers from the product session, shows queued/running/completed/failed scan activity, and leaves repository allowlist, disabled-scan, duplicate-scan, and queue-pressure decisions to the API contract.

## AWS

AWS onboarding uses a scope-first app wizard. The first supported path is
**Single AWS account**: the operator names the account, chooses a setup region,
launches the CloudFormation stack from Identrail, then validates the role AWS
created after the stack finishes. Organization-wide setup, selected OUs/accounts,
and existing manual-role setup are shown as planned paths, not editable raw
forms.

The wizard follows the CloudFormation connector flow:

```text
POST /v1/connectors/aws
GET  /v1/connectors/aws/{connector_id}/poll
POST /v1/connectors/aws/{connector_id}/validate
POST /v1/connectors/aws/{connector_id}/refresh-policy
```

`POST /v1/connectors/aws` starts onboarding and returns an AWS launch URL plus permission preview. Repeating the call with the same `connector_id` resumes the existing setup and preserves the External ID and launch parameters.
`GET /v1/connectors/aws/{connector_id}/poll` returns status for long-running setup without serializing the External ID.
`POST /v1/connectors/aws/{connector_id}/validate` validates the role created by that flow with scanner-critical IAM checks, permission checks, and diagnostics that are surfaced in the connector status.
`POST /v1/connectors/aws/{connector_id}/refresh-policy` regenerates the read-only policy preview and capability matrix for the same connector.

Current product behavior remains IAM-focused and read-only. CloudFormation creates a role with scanner-only permissions and does not execute cloud-side mutation or remediation.

The default screen does not ask for External ID or a role ARN. Identrail
generates and stores the External ID server-side, and the role ARN field appears
only during the post-launch validation step or for an existing connector.

Keep in mind the older project-scoped route remains for compatibility only:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/connection`

This path is not the default product onboarding flow and is maintained only for legacy clients that still call it.

For required environment and policy references, see:

- [`docs/auth/aws-connector.md`](./auth/aws-connector.md)
- [`docs/auth/env-vars-reference.md`](./auth/env-vars-reference.md) (AWS connector env vars)
- [`../deploy/connectors/aws/policies/identrail-readonly-policy.md`](../deploy/connectors/aws/policies/identrail-readonly-policy.md)

## Kubernetes

The wizard runs a non-mutating preflight through:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/kubernetes/connection`

The API runtime uses its configured `kubectl` path and optional context override. The response includes cluster metadata, read-access checks, diagnostics, and remediation text for missing scanner-critical RBAC permissions.

## Operational Notes

- The wizard is scoped by tenant, workspace, and project route params.
- Retry is safe: AWS and Kubernetes validation paths are read-only, and GitHub start state expires server-side.
- Status refresh uses the three provider status endpoints and keeps partial failures visible per source.
