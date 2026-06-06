# AWS CodePipeline Deployment Roles

## Purpose

Issue #1482 adds metadata-only CodePipeline deployment role inventory to the AWS
machine identity graph. It maps pipeline service roles and explicit action roles
so operators can see which IAM roles power release workflows, cross-account
deployments, cross-region actions, and PassRole-adjacent deployment paths.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/codepipeline-deployment-roles
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, `runs_as` relationships,
diagnostics, status, confidence, count summaries, and issue evidence links.

## Evidence Collected

Each record includes:

- Pipeline ARN, name, version, type, and execution mode.
- Pipeline service role ARN, explicit action role ARN, role name, and role kind.
- Stage, action, category, owner, provider, version, region, namespace, and run
  order metadata.
- Input and output artifact names.
- Artifact store type, bucket/location name, region, and KMS key reference.
- Action configuration key names only.
- Provider identifiers, disabled stage transitions, cross-region artifact store
  state, cross-region action state, role account ID for cross-account action
  roles, cross-account role state, and PassRole-adjacent state.
- Tags when available.

The collector does not read source contents, action configuration values,
artifact contents, action outputs, deployment payloads, secret values, customer
data, prompts, completions, browser pages, code-interpreter output, or database
rows.

## Required AWS Permissions

The live SDK collector uses read-only metadata APIs only:

- `codepipeline:ListPipelines`
- `codepipeline:GetPipeline`
- `codepipeline:GetPipelineState`

`GetPipelineState` is used only to surface disabled stage transitions and state
diagnostics. A failure to read state does not discard successful pipeline/action
role evidence.

## Diagnostics

Permission denial blocks the inventory because the collector cannot prove
pipeline or action roles without CodePipeline metadata access. Per-pipeline
`GetPipeline` or `GetPipelineState` failures are reported as partial failures so
successful deployment-role records remain visible. Disabled stage transitions
are degraded metadata, not false success.

## Graph Shape

Pipeline service role records emit:

```text
codepipeline_pipeline --runs_as--> iam_role
```

Explicit action role records emit:

```text
codepipeline_action --runs_as--> iam_role
```

That gives downstream graph, runtime, blast-radius, least-privilege, reasoning,
and governance features deterministic deployment-role evidence without
collecting deployment payloads or secrets.
