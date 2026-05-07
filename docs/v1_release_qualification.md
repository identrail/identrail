# V1 Release Qualification

This is the release gate for priorities 21-22.

## Priority 21: Backward Compatibility Safeguards

- API contract snapshot tests:
  - `internal/api/contract_snapshot_test.go`
  - snapshots under `testdata/contracts/`
- Finding payload compatibility snapshots:
  - `internal/findings/standards/compatibility_snapshot_test.go`
  - snapshots under `testdata/contracts/`
- Migration compatibility test for existing rows:
  - `internal/integration/migration_compatibility_integration_test.go`

## Priority 22: Release Qualification

- Full qualification runner:
  - `scripts/v1_release_qualify.sh`
- Release workflow enforcement:
  - `.github/workflows/release.yml` runs the qualification gate before publishing release artifacts.
- Required checks:
  - Go tests
  - Integration tests
  - Web tests/build
  - Docker compose validation
  - Terraform validate
  - Helm lint
  - API latency SLO smoke test

## Tagging Flow

1. Ensure CI for `dev` is green.
2. Create release candidate tag:
   - `git tag -a v1.0.0-rc.1 -m "Identrail v1.0.0 release candidate 1"`
   - `git push origin v1.0.0-rc.1`
3. After final validation, create GA tag:
   - `git tag -a v1.0.0 -m "Identrail v1.0.0 GA"`
   - `git push origin v1.0.0`

## V1 Lock Criteria

- Deterministic, idempotent scans.
- Stable `/v1` API and finding/export contracts.
- CI quality gates green.
- Deployability via Docker, Kubernetes (Helm), and Terraform baseline.
- Operator and incident docs complete.
