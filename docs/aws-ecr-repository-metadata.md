# AWS ECR repository metadata

Issue #1492 adds metadata-safe ECR repository context to the AWS platform
inventory under parent issue #1472.

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ecr-repository-metadata
```

Optional query parameters:

- `connector_id`: AWS connector to scope account and region context.
- `fixture_state`: deterministic test state (`success`, `empty`, `degraded`,
  `partial_failure`, or `permission_denied`).
- `repository_name`: substring filter over repository name, URI, or ARN.
- `identity`: substring filter over referencing workload identity, workload
  name, resource ARN, or image URI.

The response includes repository counts, mutable/unscanned posture counts,
policy and lifecycle counts, graph-ready `uses_image` relationships,
diagnostics, coverage gaps, evidence links, and safe repository records.

Collected record fields include repository ARN/name/URI, registry/account,
region, tag mutability, encryption type, KMS key ID, scan-on-push and enhanced
scan settings, repository-policy and lifecycle-policy summaries, image summary
counts, last pushed time, tags, exposure classification, confidence, and
workload image references.

## Safety boundary

The collector is read-only and metadata-only. It may call:

- `ecr:DescribeRepositories`
- `ecr:DescribeImages`
- `ecr:GetRepositoryPolicy`
- `ecr:GetLifecyclePolicy`
- `ecr:GetRegistryScanningConfiguration`
- `ecr:ListTagsForResource`

It must not call `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, image
manifest APIs, scan-finding detail APIs, or any API that returns image layers,
image payloads, SBOM contents, customer payloads, prompts, completions, object
contents, or database rows.

## Graph output

Resolved workload image references emit `uses_image` relationships from the
workload node to the ECR repository node. The relationship evidence is the
metadata-safe image URI reference, not the image manifest or layer content.
