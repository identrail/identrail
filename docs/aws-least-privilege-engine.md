# AWS Least-Privilege Recommendation Engine

Issue: #1522

The AWS least-privilege recommendation engine turns existing metadata-only AWS evidence into deterministic keep, remove, and review decisions.

It composes:

- Secrets Manager / KMS runtime access correlation
- S3 runtime access correlation
- AI agent runtime / tool-call correlation
- IAM last-used signals
- Access Analyzer findings
- graph node identifiers and impacted paths produced by the prerequisite AWS engines

The API is available at:

```text
GET /v1/workspaces/:workspace_id/projects/:project_id/aws/least-privilege
```

It returns a `recommendations` envelope with:

- stable `recommendation_id` values
- `calculation_version`
- keep, remove, or review decision
- severity, score, confidence, status, and rationale
- service, identity, resource, impacted graph path, and impacted node ids
- keep actions, remove actions, observed actions, and granted actions
- breakage prediction and breakage rationale
- metadata-only evidence references
- read-only remediation case previews
- diagnostics, coverage gaps, failure reasons, remediation hints, and applied filters

## Decisions

The first calculation version is `aws-least-privilege-recommendation-engine-v1`.

Decisions are intentionally conservative:

- `remove` is used for static grants or declared tool access with no matching runtime evidence in the scoped evidence window.
- `keep` is used when runtime evidence shows the access is actively used or must be authorized before narrowing.
- `review` is used when evidence proves reachability or uncertainty but is not strong enough for deterministic removal.

Access Analyzer findings always become review recommendations. They prove reachability, not application intent.

## Breakage Prediction

Breakage is predicted from observed usage, source confidence, and source caveats:

- `low`: no matching runtime use, high confidence, and no caveats
- `medium`: no observed use, but confidence or scope leaves meaningful uncertainty
- `high`: runtime evidence shows the access is used
- `unknown`: evidence is partial, caveated, or requires owner review

Unknown evidence never becomes an automatic remove decision.

## Filters

The endpoint supports:

- `account_id`
- `region`
- `identity`
- `resource`
- `service`
- `severity`
- `status`
- `decision`
- `fixture_state`

The `resource` filter matches graph node ids, ARNs, and impacted path labels so operators do not need internal node ids to find a recommendation.

## Evidence Boundaries

The engine only exposes metadata:

- ARNs and graph node ids
- action names and service names
- event and correlation references
- confidence, timestamps, status, and caveat context

It does not expose secret values, decrypted plaintext, object bodies, object contents, prompts, completions, browser pages, code-interpreter output, database rows, or customer payloads.

## Failure States

The engine supports deterministic states for validation:

- `success`
- `empty`
- `degraded`
- `partial_failure`
- `permission_denied`

Blocked evidence returns explicit diagnostics and coverage gaps. Empty evidence returns a degraded result with zero recommendations rather than fabricating a safe state.

## App Surface

The AWS runtime operations page renders least-privilege recommendations below the source evidence and blast-radius intelligence. Operators can see the decision, service scope, impacted path, actions, evidence confidence, breakage prediction, next action, caveats, and permission/degraded states.

## Safety

This engine is read-only. It creates remediation case previews only; it does not mutate AWS IAM, resource policies, permission boundaries, SCPs, agent tools, or Identrail governance state. Policy diff generation, approval workflow, and execution are downstream capabilities.
