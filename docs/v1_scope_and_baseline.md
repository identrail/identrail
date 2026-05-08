# V1 Scope And Baseline (First 20 Priorities)

This document locks the first twenty non-negotiable V1 priorities.

## 1) Scope Freeze

- Core path: AWS + Kubernetes discovery, normalization, graph, risk findings, API, dashboard.
- Optional module: GitHub repository exposure scanner (`repo-scan`) remains separate from core identity scan flow.
- Provider guardrail: startup validation accepts only `aws` or `kubernetes` for V1 runtime.

## 2) Standards Baseline

- Auth baseline: API key auth plus OIDC/OAuth2-compatible bearer auth (Keycloak-compatible issuer/audience model).
- Finding baseline: typed internal finding model enriched with control references.
- Export baseline:
  - OCSF-aligned payload export
  - AWS Security Finding Format (ASFF) export
- Compliance baseline: each finding type maps to CIS/NIST-style control references in evidence.

## 3) Reliability Hardening

- Idempotent persistence for scans, artifacts, findings, and repo findings.
- Single-flight locking for scan execution (`scan:<provider>`, `repo-scan:<target>`).
- AWS collector retries transient IAM failures with bounded exponential backoff and jitter.
- Partial-failure visibility through scan event stream and explicit failed/succeeded scan status transitions.

## 4) Data Contract Hardening

- Graph relationship contract is explicit and validated:
  - `can_assume`
  - `attached_policy`
  - `attached_to`
  - `bound_to`
  - `can_access`
  - `can_impersonate`
- Fixture-based contract tests verify normalized identities and relationship types for AWS and Kubernetes pipelines.

## 5) Risk Engine Productionization

- High-value rules in place:
  - admin-equivalent/overprivileged access
  - wildcard/broad trust
  - stale identities
  - ownerless identities
  - escalation paths
- Findings are typed, deterministic, and include evidence + remediation text.
- Evidence ordering is deterministic across reruns to keep diffing stable.

## 6) Collector Reliability Hardening

- Collectors now support partial failure diagnostics through `CollectWithDiagnostics`.
- Kubernetes kubectl collector has bounded retry/backoff/jitter for transient API failures.
- Source-level decode and collection issues are captured as non-fatal diagnostics.
- AWS collector now reports non-fatal source issues (for example malformed role payload shapes) without dropping full scan runs.

## 7) Scheduler + Scan Idempotency

- Scheduler runner now supports bounded retry attempts and exponential backoff.
- Dead-letter callback hook added for exhausted retry paths.
- Scan lifecycle state tracking now emits: `queued`, `running`, `partial`, `succeeded`, `failed`.
- Partial runs are explicit in scan events when source diagnostics are present.

## 8) Normalization Contract Hardening

- Normalized bundle validator now enforces required identity/workload/policy fields.
- Policy normalized payload contract is strict and explicit (`policy_type`, `identity_id`, statement/principal requirements).
- AWS and Kubernetes fixture pipelines are covered by contract tests to prevent schema drift.

## 9) Graph Contract Hardening

- Graph contract validator now enforces:
  - edge type support
  - endpoint integrity by relationship semantic
  - relationship ID uniqueness
  - semantic tuple uniqueness (`type + from + to`)
  - required discovery timestamp on all edges
- AWS and Kubernetes graph snapshots were added as regression fixtures.

## 10) Risk Rule Reliability Baseline

- Rule outputs remain deterministic for identical inputs.
- Evidence and relationship contracts are now validated before rule execution is persisted.
- Regression tests now cover deterministic and stable graph/rule input expectations across providers.

## 11) API Contract Hardening

- `/v1` namespace is the stable API contract surface.
- List endpoints now support consistent sort contract:
  - `sort_by`
  - `sort_order=asc|desc`
- Cursor pagination and filter behavior remains backward compatible.
- OpenAPI v1 contract published at `docs/openapi-v1.yaml`.

## 12) CLI Hardening

- Stable command paths:
  - `identrail scan`
  - `identrail findings`
  - `identrail repo-scan`
- Output compatibility maintained (`table` and `json`).
- Table output now uses deterministic severity ordering (`critical` first).
- CLI smoke coverage is enforced in CI.

## 13) Dashboard Hardening

- Findings list/detail and scan diff views remain stable on top of `/v1` contracts.
- Added explicit empty/error UX states for:
  - no scans
  - no trend data
  - no explorer graph data
- Web tests now validate happy-path plus empty/error states.

## 14) Persistence Hardening

- Migration engine now supports explicit down migration execution for controlled rollback.
- Added migration roundtrip integration coverage:
  - `up -> down -> up` then scan persistence verification.
- Added migration operator guide: `docs/migrations.md`.

## 15) CI/CD Release Gates

- Go quality + unit + integration + coverage gate remain required.
- Added CLI smoke gate in CI.
- Added dockerized API smoke gate (`postgres + api + fixture scan`) in CI deploy portability job.
- Contract safety now includes OpenAPI presence checks in tests.

## 16) Security Hardening

- Constant-time API key matching added to reduce timing side-channel risk.
- Security warnings now include weak API key length detection.
- Read-only integration policy templates added for AWS and Kubernetes.
- Dedicated security baseline guide added for secret handling and key rotation.

## 17) Observability Baseline

- Expanded Prometheus metrics for success/failure/partial scan tracking.
- Added repository scan reliability metrics.
- Added scanner pipeline tracing spans for each stage.
- Added SLO baseline and alert thresholds in operator docs.

## 18) Deploy-Anywhere Baseline

- Docker Compose remains first-class local/prod-like baseline.
- Added Helm chart for Kubernetes upgrades and repeatable release flow.
- Added Terraform module baseline to deploy Helm with namespace/secret wiring.

## 19) Operator Readiness

- Added operator readiness handoff checklist.
- Added troubleshooting playbook for common failure scenarios.
- Added incident response workflow for high-severity findings.
- Deploy runbook now links all operational docs in one place.

## 20) Governance Docs

- ADR, threat model, and changelog updated for priorities 16-20.
- Governance updates now explicitly include deployment model and observability decisions.

## 21) Backward Compatibility Safeguards

- API response contract snapshots added for:
  - `POST /v1/scans`
  - `GET /v1/findings`
  - `GET /v1/findings/:finding_id/exports`
- Finding payload compatibility snapshots added for:
  - enriched internal finding payload
  - OCSF export payload
  - ASFF export payload
- Migration compatibility integration test added for legacy persisted rows with nullable fields.

## 22) Release Qualification

- Added release qualification runner script: `scripts/v1_release_qualify.sh`.
- Added API latency SLO smoke test for findings list endpoint.
- Added V1 release qualification and tagging playbook: `docs/v1_release_qualification.md`.
- V1 lock process now includes explicit RC and GA tagging steps.
