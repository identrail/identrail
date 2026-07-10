# AWS GA demo hardening

Issue #1557 adds a metadata-only GA walkthrough for the AWS platform. It gives
operators one app/API surface for onboarding, discovery, agent identities,
runtime evidence, risk, remediation, approval, verification, governance
reporting, executive handoff, and platform observability.

Endpoint:

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ga-demo-hardening`

Response shape: `{ "ga_demo_hardening": AWSGADemoHardeningResult }`.

## Query filters

- `connector_id`: pins the AWS connector.
- `fixture_state`: `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied`.
- `account_id` / `region`: scope the composed source evidence.
- `stage`: `onboarding`, `discovery`, `agents`, `runtime`, `risk`,
  `remediation`, `approval`, `verification`, `governance`, `reporting`, or
  `observability`.
- `status`: `ready`, `degraded`, or `blocked`.
- `search`: searches stage titles, summaries, evidence refs, next actions, and
  failure reasons.

## Expected output

The result includes:

- ordered demo stages with status, confidence, account/region context, evidence
  refs, evidence links, next actions, and failure reasons;
- readiness checks for validation fixtures, read-only boundaries, permissions,
  source confidence, and governance export;
- permission prerequisites, safety notes, limitations, troubleshooting, caveats,
  failure reasons, remediation hints, and evidence links;
- stable loading, empty, degraded, permission-denied, filtered, and search
  states for the AWS app page.

## Permissions

The walkthrough depends on read-only AWS metadata APIs such as:

- `sts:GetCallerIdentity`
- IAM role and policy read APIs
- Access Analyzer list/read APIs
- CloudTrail event lookup
- AWS Organizations list APIs
- service inventory list APIs for Lambda, ECS, EKS, Secrets Manager, KMS, and S3

The endpoint does not require AWS write APIs.

## Data intentionally not collected

Identrail does not read, return, log, or persist secret values, prompts,
completions, browser pages, code-interpreter output, database rows, object
contents, rendered policy bodies, or customer payloads for this walkthrough.
Evidence is limited to metadata, source IDs, evidence refs, confidence,
timestamps, account/region context, and operator next actions.

## Limitations

- The demo reflects the configured connector permissions and available source
  evidence.
- Permission-denied and degraded states are explicit outcomes, not successful
  collection.
- Remediation and enforcement remain projections unless a downstream approved,
  safety-gated execution endpoint is invoked.
- Service coverage is bounded by existing collector contracts.

## Troubleshooting

- If onboarding is blocked, verify the connector role ARN, external ID, account
  ID, region, and connection diagnostics.
- If discovery is empty, run success and empty fixtures before treating the
  absence of rows as expected.
- If graph or agent stages are degraded, inspect collector coverage gaps,
  runtime lag, PassRole evidence, and AI-agent diagnostics.
- If remediation, approval, or verification stages are degraded, inspect case
  ownership, approval state, dry-run outcomes, kill-switch state, rollback
  state, and verification evidence.
- If governance or reporting is degraded, export governance rows and resolve
  exceptions before executive handoff.
- If observability is degraded, review queue lag, throttling, collector
  failures, runtime lag, verification alerts, and source confidence.
