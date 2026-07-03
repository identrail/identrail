# AWS machine identity detail page

Issue #1549 adds the read-only detail surface for a single AWS machine identity.
It composes workload bindings, runtime events, least-privilege recommendations,
secret/resource reachability, remediation cases, and governance decisions into
one scoped response that backs the app route
`/app/{tenant_id}/{workspace_id}/aws/identities/detail`.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/machine-identity-detail`

Required query parameters:

- `identity`: IAM role ARN, identity node id, or role name to inspect.

Supported optional filters:

- `connector_id`
- `fixture_state`: `success`, `empty`, `degraded`, `partial_failure`, or `permission_denied`
- `account_id`
- `region`
- `tab`: `graph`, `runtime`, `permissions`, `secrets`, `fixes`, or `governance`
- `service`
- `resource`
- `severity`
- `status`

The response is returned as `{ "detail": ... }` and includes:

- tenant, workspace, project, connector, account, region, issue, version, status, confidence, and applied filters
- normalized identity metadata with principal ARN, role name, node id, and evidence boundary
- tab counts for graph, runtime, permissions, secrets, fixes, and governance
- workload bindings across EC2, ECS, Lambda, CodeBuild, CodePipeline, Step Functions, event-driven roles, managed compute, and EKS
- runtime events, permission summaries, resources reached, security findings, remediation cases, governance decisions, and graph relationships
- diagnostics, coverage gaps, failure reasons, remediation hints, and evidence links

## App behavior

The AWS identities inventory links role-bearing rows to the detail route with
the selected environment and exact identity ARN. The detail page keeps the
environment selector active and reloads when the environment, identity, or tab
changes.

The UI exposes six tabs:

- `graph`: workload bindings and graph relationships
- `runtime`: matching CloudTrail/runtime records
- `permissions`: least-privilege recommendation summaries
- `secrets`: reached resources plus secret, blast-radius, and sprawl findings
- `fixes`: read-only remediation case projections
- `governance`: advisory, approval, remediation, enforcement, and exception records

## Safety boundaries

The contract is read-only and metadata-only. It must not read, expose, log, or
persist secret values, decrypted plaintext, policy document bodies, request or
response payload bodies, prompts, completions, browser pages, code-interpreter
output, database rows, or customer object contents.

The response evidence boundary is
`metadata_only_no_secret_values_no_policy_bodies_no_payloads`. Downstream
collectors may contribute ARNs, names, ids, hashes, timestamps, action names,
and safe evidence references, but not sensitive values or document bodies.

## Failure states

- `empty`: the identity is valid, but no workload, runtime, permission, secret, remediation, or governance evidence matched.
- `degraded`: evidence exists, but one or more collectors returned partial or low-confidence data.
- `partial_failure`: at least one downstream capability failed while retained evidence remains visible.
- `permission_denied`: the selected connector lacks required read-only metadata permissions.

These states remain visible in the detail page through status panels,
diagnostics, coverage gaps, and remediation hints rather than being collapsed
into a successful view.
