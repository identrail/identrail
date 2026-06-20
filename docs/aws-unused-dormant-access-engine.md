# AWS Unused and Dormant Access Engine

The AWS unused and dormant access engine turns metadata-only AWS inventory,
runtime evidence, IAM last-used signals, scan timestamps, and policy scope into
ranked findings for cleanup planning.

It is the Wave 6.03 intelligence layer for issue #1523. The engine is read-only:
it does not mutate AWS, generate IAM policy diffs, disable identities, read
secret values, inspect object contents, or persist customer payloads.

## API

```text
GET /v1/workspaces/:workspace_id/projects/:project_id/aws/unused-dormant-access
```

Query filters:

- `connector_id`: optional AWS connector scope.
- `fixture_state`: `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic contract and UI validation.
- `account_id`, `region`, `identity`, `resource`, `service`, `severity`, and
  `status`.
- `dormancy_state`: `never_used`, `stale`, `no_runtime_evidence`, or
  `unknown`.

The response body is returned as:

```json
{
  "findings": {
    "version": "aws-unused-dormant-access-engine-v1",
    "current_issue_ref": "#1523",
    "status": "ready",
    "summary": {
      "total_findings": 3,
      "cleanup_candidate_count": 1,
      "review_required_count": 2
    },
    "findings": []
  }
}
```

## Finding Contract

Each finding includes:

- stable `finding_id` and `calculation_version`;
- `finding_type`, `dormancy_state`, severity, status, score, and confidence;
- account, region, service, identity, principal ARN, resource, and display
  labels;
- owner context and policy scope;
- rationale, last-used timestamp when available, dormant-days estimate, and
  scan-window days;
- candidate, observed, and granted actions;
- impacted graph nodes/path, metadata-only evidence links, and relationships;
- read-only remediation case preview and next action.

## Dormancy States

- `never_used`: policy or declaration exists, but the scoped metadata-only
  evidence window has no matching runtime use.
- `stale`: IAM last-used or related evidence indicates old access that needs
  owner confirmation before cleanup.
- `no_runtime_evidence`: a candidate has reducible policy scope, but runtime
  evidence is bounded or absent.
- `unknown`: evidence is degraded, permission-denied, unsupported, or otherwise
  insufficient.

Unknown, permission-denied, and partial evidence are explicit states. They do
not become cleanup candidates.

## App Surface

The AWS runtime page renders unused and dormant access findings below runtime,
correlation, blast-radius, and least-privilege evidence. Operators can inspect
dormancy state, policy scope, candidate actions, confidence, owner context,
evidence refs, and next action without reading logs or database rows.

## Safety

The engine composes existing read-only evidence. It never collects or returns
secret values, prompts, completions, browser output, code-interpreter output,
database rows, S3 object contents, or customer payloads. Cleanup remains a
planning preview until downstream owner approval and IAM diff generation are
available.
