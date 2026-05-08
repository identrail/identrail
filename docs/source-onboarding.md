# Source Onboarding

Identrail source onboarding is available from the authenticated product shell at:

`/app/{tenant_id}/{workspace_id}/projects/{project_id}`

The project detail view presents a guided connect-source wizard for GitHub, AWS, and Kubernetes. It reads current source status first, then runs the existing project-scoped connector APIs when an operator validates or saves a source.

## GitHub

The wizard starts the GitHub App installation flow through:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/github/connect/start`

After installation metadata is available, the wizard saves the project connection through:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/github/connect/complete`

The UI keeps repository selection explicit and stores only credential references plus encrypted webhook-secret metadata returned by the API.

## AWS

The wizard validates and saves one read-only IAM role through:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/connection`

Validation returns account identity, permission checks, diagnostics, and remediation text. A successful validation marks the connector active; failed checks leave the connector diagnosable instead of hiding the issue.

## Kubernetes

The wizard runs a non-mutating preflight through:

`POST /v1/workspaces/{workspace_id}/projects/{project_id}/kubernetes/connection`

The API runtime uses its configured `kubectl` path and optional context override. The response includes cluster metadata, read-access checks, diagnostics, and remediation text for missing scanner-critical RBAC permissions.

## Operational Notes

- The wizard is scoped by tenant, workspace, and project route params.
- Retry is safe: AWS and Kubernetes validation paths are read-only, and GitHub start state expires server-side.
- Status refresh uses the three provider status endpoints and keeps partial failures visible per source.
