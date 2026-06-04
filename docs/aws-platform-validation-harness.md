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
    "tenant_id": "tenant-a",
    "workspace_id": "workspace-a",
    "project_id": "production",
    "connector_id": "aws-prod",
    "account_id": "123456789012",
    "region": "us-east-1",
    "parent_issue_number": 1472,
    "parent_issue_ref": "#1472",
    "current_issue_number": 1475,
    "current_issue_ref": "#1475",
    "version": "aws-platform-validation-harness-v1",
    "status": "ready",
    "confidence": 0.98,
    "scenario_count": 6,
    "required_scenario_count": 6,
    "fixture_states": [
      "success",
      "empty",
      "degraded",
      "partial_failure",
      "permission_denied",
      "unsupported_service"
    ],
    "failure_reasons": [],
    "remediation_hints": [],
    "evidence_links": [
      "https://github.com/identrail/identrail/issues/1472",
      "https://github.com/identrail/identrail/issues/1475",
      "/docs/aws-platform-validation-harness",
      "/app/tenant-a/workspace-a/aws?environment=production",
      "/app/tenant-a/workspace-a/aws/connect?environment=production"
    ],
    "browser_steps": [
      {
        "id": "browser_control_center_states",
        "kind": "browser",
        "flow": "diagnostics",
        "label": "Validate AWS Control Center state panels",
        "target": "/app/tenant-a/workspace-a/aws?environment=production",
        "expected_state": "success, empty, degraded, partial_failure, permission_denied, unsupported_service",
        "required": true,
        "evidence_url": "/app/tenant-a/workspace-a/aws?environment=production"
      }
    ],
    "api_steps": [
      {
        "id": "api_validation_harness",
        "kind": "api",
        "flow": "validation_harness",
        "label": "Fetch deterministic AWS validation harness",
        "target": "/v1/workspaces/workspace-a/projects/production/aws/validation-harness",
        "method": "GET",
        "expected_state": "all fixture states returned with scoped evidence",
        "required": true,
        "evidence_url": "/docs/aws-platform-validation-harness"
      }
    ],
    "scenarios": [
      {
        "id": "runtime_evidence_partial_failure",
        "flow": "runtime_evidence",
        "fixture_state": "partial_failure",
        "status": "ready",
        "label": "Runtime evidence partial failure",
        "summary": "The app can show runtime evidence where one account, region, or service succeeds while another reports an explicit partial failure.",
        "operator_message": "Use this fixture when runtime ingestion, timeline, or account/region fan-out behavior changes.",
        "failure_reason": "one AWS service partition did not return runtime evidence",
        "remediation": "Keep successful runtime evidence separate from the failed partition and list the retry target.",
        "next_action": "Summarize successful and failed partitions separately in PR notes.",
        "evidence_url": "/app/tenant-a/workspace-a/aws?environment=production",
        "account_id": "123456789012",
        "region": "us-east-1",
        "required": true,
        "confidence": 0.95,
        "evidence": {
          "workspace_id": "workspace-a",
          "project_id": "production",
          "fixture_state": "partial_failure",
          "read_only": true
        },
        "browser_step_ids": ["browser_control_center_states"],
        "api_step_ids": ["api_validation_harness"],
        "checked_at": "2026-06-04T14:00:00Z"
      }
    ],
    "generated_at": "2026-06-04T14:00:00Z",
    "updated_at": "2026-06-04T14:00:00Z"
  }
}
```

The `scenarios` array contains one entry for each fixture state listed above.

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
