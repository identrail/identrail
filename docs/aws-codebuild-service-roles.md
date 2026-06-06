# AWS CodeBuild Service Roles

## Purpose

Issue #1481 adds metadata-only CodeBuild service role inventory to the AWS
machine identity graph. It maps each CodeBuild project to the IAM role it runs
as, then carries safe build metadata for later CI/CD identity, credential
reference, and blast-radius analysis.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/codebuild-service-roles
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, `runs_as` relationships,
diagnostics, status, confidence, count summaries, and issue evidence links.

## Evidence Collected

Each record includes:

- CodeBuild project ARN, name, visibility, source provider, source location,
  source auth type, source version, and secondary source identifiers.
- Service role ARN and role name.
- Environment type, compute type, image, image-pull credential mode, privileged
  mode, KMS key ARN, cache metadata, log destinations, VPC, subnet, security
  group, artifact type, and artifact location metadata.
- Environment variable names only.
- Parameter Store and Secrets Manager references only.
- Tags.

The collector does not read build logs, source contents, artifacts, environment
values, secret values, customer data, prompts, completions, or database rows.

## Diagnostics

Permission denial blocks the inventory because `ListProjects` and
`BatchGetProjects` are the entry points. Per-page or per-batch failures are
reported as partial failures so successful project-role records remain visible.
Public or privileged projects are surfaced as degraded metadata because they
change the review priority without requiring data-plane reads.

## Graph Shape

CodeBuild project workloads emit:

```text
codebuild_project --runs_as--> iam_role
```

That keeps CI/CD build identity aligned with the AWS service collector contract
and gives downstream engines a deterministic machine identity edge without
collecting build payloads.
