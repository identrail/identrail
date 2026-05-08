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
2. Choose the target release version (`vX.Y.Z`).
3. Create release candidate tag:
   - `git tag -a vX.Y.Z-rc.N -m "Identrail vX.Y.Z release candidate N"`
   - `git push origin vX.Y.Z-rc.N`
4. After final validation, create GA tag:
   - `git tag -a vX.Y.Z -m "Identrail vX.Y.Z GA"`
   - `git push origin vX.Y.Z`

Historical note:
- `v1.0.0-rc.1` and `v1.0.0` already exist and represent the original V1 release flow.

## V1 Lock Criteria

- Deterministic, idempotent scans.
- Stable `/v1` API and finding/export contracts.
- CI quality gates green.
- Deployability via Docker, Kubernetes (Helm), and Terraform baseline.
- Operator and incident docs complete.
