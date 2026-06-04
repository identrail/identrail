# AWS platform validation harness

The AWS platform validation harness is the reusable app proof path for AWS
Machine Identity Platform PRs. It gives future AWS work deterministic browser and
API states to validate before a PR claims user-visible behavior is done.

## API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/validation-harness
```

Optional query parameter:

- `connector_id`: adds AWS connector, account, and region context to the
  returned evidence when a project has more than one AWS connector.

The response envelope is:

```json
{
  "harness": {
    "version": "aws-platform-validation-harness-v1",
    "status": "ready",
    "fixture_states": [
      "success",
      "empty",
      "degraded",
      "partial_failure",
      "permission_denied",
      "unsupported_service"
    ]
  }
}
```

## Fixture states

The harness returns one required scenario for each AWS app proof family:

- `connector_setup` with `success`
- `scan_state` with `empty`
- `graph_state` with `degraded`
- `runtime_evidence` with `partial_failure`
- `remediation` with `permission_denied`
- `governance` with `unsupported_service`

Negative fixture states are expected validation states. They must remain visible
as denied, degraded, partial, or unsupported outcomes and must not be counted as
successful findings or successful enforcement.

## Local validation

For any AWS PR that touches user-visible behavior:

1. Start from current `origin/dev`.
2. Run the relevant backend and web tests for the touched code.
3. Fetch the harness API for the workspace/project under test.
4. Open the AWS Control Center and Connect AWS app surfaces.
5. Confirm loading, empty, error, degraded, permission-denied, and unsupported
   states render with evidence, confidence, timestamps, account/region context,
   and next actions.
6. Summarize the API output and screenshots in the PR notes without exposing
   customer payloads.

## Live validation

Live AWS validation must use only an authorized test account. Record account,
region, connector, service, and fixture coverage. Do not expose secret values,
prompt contents, completions, browser pages, code-interpreter output, database
rows, object contents, or customer payloads.

The harness is read-only. It does not execute remediation or governance actions.
Future remediation and enforcement PRs must continue to use approval gates,
dry-run evidence, rollback guidance, and explicit permission-denied states.
