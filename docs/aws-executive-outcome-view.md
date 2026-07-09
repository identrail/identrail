# AWS executive outcome view

Issue #1555 adds a metadata-only executive rollup for AWS risk, coverage,
remediation, enforcement, governance, and remaining exposure. It composes the
existing AWS evidence APIs into a leadership-ready view without adding a new
collector, executor, or AWS write path.

The endpoint does not enforce, approve, remediate, mutate AWS resources, or
export sensitive payloads.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/executive-outcomes`

Response shape: `{ "executive_outcomes": AWSExecutiveOutcomeViewResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`ou`, `identity_type`, `severity`, `outcome_type`, `trend`, and `search`.

`outcome_type` can be `risk_reduction`, `coverage`, `remediation`,
`enforcement`, `exposure`, or `governance`. `trend` can be `improving`,
`stable`, or `needs_attention`.

## Outcome metrics

- `risk_reduction`: score derived from least-privilege recommendations,
  remediation planning, verified remediation, enforcement readiness, and
  residual exposure.
- `coverage`: account, region, service, and collector coverage for the selected
  AWS connector.
- `remediation`: post-remediation verification and rollback state.
- `enforcement`: limited-enforcement readiness, canary posture, and safety
  gates.
- `exposure`: open blast-radius findings plus least-privilege review work.
- `governance`: export-safe governance decisions, approvals, remediations,
  enforcement outcomes, and exceptions.

## Evidence boundary

Every metric carries source evidence links, confidence, account/region scope,
severity, trend, and a next action. OU values are included only when upstream
governance records provide real OU metadata.

The result does not contain rendered policies, secret values, prompts,
completions, browser pages, code-interpreter output, database rows, object
contents, customer payloads, or workload payloads.

## App surface

The AWS Outcomes page renders summary cards for risk reduction, scan coverage,
verified remediation, enforcement readiness, remaining exposure, and governance
records, followed by a filterable outcome metric table. Loading, empty, error,
degraded, permission-denied, and blocked states remain visible.

## Out of scope

- No live AWS mutation.
- No new collector, scanner, or executor behavior.
- No raw payload, policy-body, secret, prompt, completion, database, object, or
  workload export.
- No replacement for source drill-down pages; executive metrics link back to
  the underlying evidence contracts.
