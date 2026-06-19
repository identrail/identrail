# AWS Blast Radius Intelligence Engine

Issue: #1521

The AWS blast radius engine ranks identity-centric AWS exposure by composing existing deterministic signals:

- Secrets Manager / KMS runtime access correlation
- S3 runtime access correlation
- AI agent runtime / tool-call correlation
- Static reachability and graph node identifiers projected by those engines

The API is available at:

```text
GET /v1/workspaces/:workspace_id/projects/:project_id/aws/blast-radius
```

It returns an `intelligence` envelope with:

- stable `finding_id` values
- `calculation_version`
- severity, score, confidence, status, and rationale
- impacted graph path and impacted node ids
- sensitive nodes, cross-account edges, runtime actions, and agent/tool paths
- metadata-only evidence references
- read-only remediation case previews
- diagnostics, coverage gaps, failure reasons, and remediation hints

## Scoring

The first calculation version is `aws-blast-radius-engine-v1`.

Scores are deterministic and intentionally conservative:

- Secret/KMS runtime access starts high because it reaches sensitive material.
- S3 access is raised by high sensitivity, external exposure, cross-account reachability, and observed-without-grant evidence.
- Agent/tool paths are raised for undeclared runtime behavior, backing-role mismatches, and other correlation caveats.
- Unknown or unavailable runtime evidence lowers status/confidence. It does not upgrade severity.

Findings are sorted by descending score, then stable finding id.

## Evidence Boundaries

The engine only exposes metadata:

- ARNs and graph node ids
- event/correlation references
- action names and status codes
- confidence and timestamps

It does not expose secret values, object keys, prompts, completions, tool payloads, browser pages, or code-interpreter output.

## Failure States

The engine supports the same deterministic states as the prerequisite AWS wave surfaces:

- `success`
- `empty`
- `degraded`
- `partial_failure`
- `permission_denied`

Blocked evidence returns explicit diagnostics and coverage gaps. Empty evidence returns a degraded result with zero findings rather than fabricating safe conclusions.

## App Surface

The AWS runtime operations page renders blast radius intelligence below the source correlation tables. Operators can see severity, score, identity, impacted path, evidence confidence, next action, caveats, and permission/degraded states.
