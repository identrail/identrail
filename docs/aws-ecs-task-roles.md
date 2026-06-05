# AWS ECS task and execution roles

Issue #1478 adds read-only ECS task and execution role inventory under parent
issue #1472.

## What It Collects

The collector maps ECS workload identity evidence for:

- ECS clusters and services.
- Active and inactive ECS task definitions.
- Task roles and execution roles, kept as separate role kinds.
- Launch type, scheduling strategy, desired/running/pending counts, and task
  definition status.
- Container image names, secret or parameter references, and environment
  variable names.
- Tenant, workspace, project, connector, account, region, scan, source,
  evidence reference, confidence, and collected timestamp.

Task roles are normalized as `runs_as` graph evidence because application code
uses those IAM permissions. Execution roles are normalized as `attached_to`
evidence because they support pull/log/agent activity for the task rather than
the application runtime identity.

## API

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ecs-task-roles
```

Query parameters:

- `connector_id`: optional AWS connector ID used to scope account and region.
- `fixture_state`: optional deterministic state, one of `success`, `empty`,
  `degraded`, `partial_failure`, or `permission_denied`.

The response is returned as:

```json
{
  "inventory": {
    "current_issue_ref": "#1478",
    "version": "aws-ecs-task-role-inventory-v1",
    "status": "ready",
    "record_count": 0,
    "task_role_count": 0,
    "execution_role_count": 0,
    "records": [],
    "relationships": [],
    "diagnostics": []
  }
}
```

## Required Permissions

The read-only AWS policy needs:

- `ecs:ListClusters`
- `ecs:ListServices`
- `ecs:DescribeServices`
- `ecs:ListTaskDefinitions`
- `ecs:DescribeTaskDefinition`

The collector does not need mutation permissions or data-plane permissions.

## Failure States

- `empty`: the account and region were reachable, but no ECS task or execution
  role records were found.
- `degraded`: one or more task definitions are incomplete, such as a task role
  without execution-role evidence.
- `partial_failure`: at least one ECS cluster or task-definition partition
  failed, while successful records remain visible.
- `permission_denied`: required ECS metadata permissions are missing.

Successful records remain visible during partial failures so downstream graph and
UI views can show known evidence without converting unknown partitions into false
success.

## Safety Boundaries

The collector intentionally does not read or persist secret values, plaintext
environment values, customer payloads, object contents, database rows, prompts,
completions, or browser output. `secret_refs` contain only names/source
references needed to prove that a workload references a secret or parameter.
`environment_keys` contain variable names only.

## Validation

Run:

```bash
go test ./internal/providers/aws ./internal/api
npm test -- --run src/api/client.test.ts src/productShell.test.tsx
```

Use fixture states to validate success, empty, degraded, permission-denied, and
partial-failure UI behavior without live AWS credentials. Live AWS validation
must use an authorized test account and should record account, region, cluster,
service, and task-definition coverage without exposing sensitive payloads.
