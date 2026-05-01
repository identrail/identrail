# Migration Strategy

Simple migration strategy for production safety.

## Principles

- Use versioned SQL files in `migrations/`.
- Keep `*.up.sql` forward-safe and idempotent (`IF NOT EXISTS` where possible).
- Keep matching `*.down.sql` for controlled rollback.
- Treat rollback as an operator action, not an automatic startup action.

## Runtime Behavior

- Shared API/worker deployments must run with `IDENTRAIL_RUN_MIGRATIONS=false`.
- Run schema migrations in a single one-shot migrator process:
  - Kubernetes manifests: `deploy/kubernetes/migration-job.yaml`
  - Helm chart: pre-install/pre-upgrade migration Job hook
- The migrator job sets:
  - `IDENTRAIL_RUN_MIGRATIONS=true`
  - `IDENTRAIL_RUN_MIGRATIONS_ONLY=true`
- Down migrations are intentionally manual.

## Roll Forward (Preferred)

1. Deploy and wait for the dedicated migrator job to complete successfully.
2. Deploy API and worker pods with `IDENTRAIL_RUN_MIGRATIONS=false`.
3. Verify `/healthz` and one scan smoke run.

## Rollback Procedure

1. Stop worker first to prevent new writes.
2. Roll back API image to previous known-good version.
3. Apply the specific down migration(s) only if schema rollback is required.
4. Re-apply previous up migration set if needed.
5. Re-run smoke checks (`/healthz`, one scan trigger, findings list).

## Verification

- CI integration lane now includes migration roundtrip verification:
  - apply up -> apply down -> apply up
  - run scan and verify persistence still works.

## Current Migration Catalog

Current sequence in `migrations/`:

1. `000001_init` - base schema
2. `000002_scan_events` - scan lifecycle event stream
3. `000003_repo_scans` - repo scan persistence tables
4. `000004_performance_indexes` - baseline performance indexes
5. `000005_async_job_queue` - queued scan execution tables/paths
6. `000005_finding_workflow_maturity` - finding triage workflow maturity fields
7. `000006_tenant_workspace_scope` - tenant/workspace scope columns and guards
8. `000007_scope_guardrails_for_triage` - triage scope hardening
9. `000008_postgres_rls_scope_guardrails` - Postgres RLS scope controls
10. `000009_authz_abac_rebac_data` - central authz ABAC/REBAC data model
11. `000010_authz_policy_lifecycle_controls` - policy lifecycle primitives
12. `000011_authz_policy_rollout_staged_controls` - staged rollout controls
13. `000012_tenancy_core_entities` - organization/workspace/member/project tenancy core
14. `000013_connectors_state_scan_policies` - connector instances, connector runtime state, and scan policy persistence with scoped foreign-key integrity

Notes:
- Each migration has matching `.up.sql` and `.down.sql` files.
- Duplicate numeric prefixes are historical and preserved to avoid reordering risk.
