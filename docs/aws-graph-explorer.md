# AWS Graph Explorer

The AWS graph explorer is the operator-facing view for issue #1551. It composes
existing AWS machine-identity evidence into one read-only graph surface for
identities, agents, resources, runtime sessions, PassRole paths, blast-radius
paths, least-privilege recommendations, and remediation previews.

## API

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/graph-explorer
```

Supported query parameters:

| Parameter | Description |
| --- | --- |
| `connector_id` | Optional AWS connector scope. |
| `fixture_state` | `success`, `empty`, `degraded`, `partial_failure`, or `permission_denied`. |
| `node_type` | Filters nodes such as `identity`, `agent`, `session`, `resource`, `secret`, `kms_key`, or `s3_bucket`. |
| `edge_type` | Filters edges such as `observed_runtime_action`, `has_runtime_session`, `runtime_session_performed_action`, `agent_invoked_runtime_action`, `can_pass_role`, or `impacted_path`. |
| `evidence` | Matches evidence source or evidence reference. |
| `search` | Searches node labels, edge endpoints, evidence refs, actions, and remediation refs. |
| `expand` | Use `neighbors` to include adjacent nodes for the current page. |
| `cursor` / `limit` | Numeric cursor and page size. The API caps page size at 200. |

The response is wrapped as:

```json
{
  "graph": {
    "status": "ready",
    "current_issue_ref": "#1551",
    "nodes": [],
    "edges": [],
    "paths": [],
    "evidence": [],
    "summary": {
      "total_nodes": 0,
      "filtered_nodes": 0,
      "runtime_action_count": 0,
      "passrole_path_count": 0,
      "remediation_link_count": 0,
      "has_more": false
    },
    "diagnostics": [],
    "coverage_gaps": []
  }
}
```

## App Behavior

The AWS app route `/app/{tenant}/{workspace}/aws/graph` loads this endpoint for
the selected environment and connector. The page shows:

- graph metrics for nodes, edges, paths, confidence, runtime actions, trust
  edges, PassRole paths, and remediation links;
- filtered node and edge tables with account, region, source, status, and
  confidence badges;
- graph paths with next action and read-only remediation references;
- metadata-only evidence drawers for path evidence references.

Loading, empty, error, degraded, and permission-denied states are explicit.
Permission-denied responses do not fabricate graph nodes or successful findings.

## Evidence Boundaries

The explorer only returns metadata references already emitted by upstream AWS
capability contracts. Evidence entries carry `redaction_boundary=metadata_only`.
Identrail does not read, expose, log, or persist secret values, prompt contents,
completion text, browser output, code-interpreter output, database rows, object
contents, or customer payloads through this endpoint.

## Sources

The graph explorer composes these read-only sources:

- AI agent identity inventory;
- runtime events and runtime sessions;
- IAM PassRole relationship inventory;
- blast-radius intelligence paths;
- least-privilege recommendations and remediation previews.

Source diagnostics and coverage gaps are preserved in the explorer response so
operators can distinguish success, empty, degraded, partial failure, unsupported,
and permission-denied states.

## Validation

Use deterministic fixtures to validate:

```text
fixture_state=success
fixture_state=empty
fixture_state=degraded
fixture_state=partial_failure
fixture_state=permission_denied
```

Recommended checks:

1. Confirm success returns identities, agents, resources, sessions, runtime
   action edges, PassRole paths, evidence refs, confidence values, and
   remediation references.
2. Confirm filters for `node_type`, `edge_type`, `evidence`, and `search`
   return scoped nodes and edges without crossing workspace or project scope.
3. Confirm pagination returns a stable `next_cursor` and that `expand=neighbors`
   includes adjacent nodes for the current page.
4. Confirm `permission_denied` returns `status=blocked`, diagnostics, failure
   reasons, and no fabricated graph entries.
5. Confirm degraded and partial-failure fixtures retain successful partial
   evidence while preserving diagnostics and coverage gaps.

## Permissions

The explorer itself performs no AWS mutations. It relies on the upstream
read-only AWS connector capabilities required by the composed sources. Missing
read-only IAM, CloudTrail, Access Analyzer, or metadata permissions are returned
as explicit diagnostics or coverage gaps rather than successful graph evidence.
