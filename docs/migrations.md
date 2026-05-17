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
  - AWS API hosting: `AWS API Database Migrations` GitHub Actions workflow
  - Kubernetes manifests: `deploy/kubernetes/migration-job.yaml`
  - Helm chart: pre-install/pre-upgrade migration Job hook
- The migrator job sets:
  - `IDENTRAIL_RUN_MIGRATIONS=true`
  - `IDENTRAIL_RUN_MIGRATIONS_ONLY=true`
- Down migrations are intentionally manual.

For the hosted AWS API path, the GitHub Actions workflow fetches
`IDENTRAIL_DATABASE_URL` from AWS Secrets Manager through the configured
`API_DATABASE_URL_SECRET_ARN`, masks the value, and runs the dedicated
`cmd/migrate` one-shot runner. The workflow must be dispatched from `dev` with
the confirmation phrase `run-api-migrations`.

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
5. `000005_finding_workflow_maturity` - finding triage workflow maturity fields
6. `000006_tenant_workspace_scope` - tenant/workspace scope columns and guards
7. `000007_scope_guardrails_for_triage` - triage scope hardening
8. `000008_postgres_rls_scope_guardrails` - Postgres RLS scope controls
9. `000009_authz_abac_rebac_data` - central authz ABAC/REBAC data model
10. `000010_authz_policy_lifecycle_controls` - policy lifecycle primitives
11. `000011_authz_policy_rollout_staged_controls` - staged rollout controls
12. `000012_tenancy_core_entities` - organization/workspace/member/project tenancy core
13. `000013_connectors_state_scan_policies` - connector instances, connector runtime state, and scan policy persistence with scoped foreign-key integrity
14. `000014_connector_secret_envelopes` - encrypted connector secret envelopes with scoped connector foreign keys and rotation index metadata
15. `000015_async_job_queue` - queued scan execution tables/paths
16. `000015_db_constraints_guardrails` - database status, identifier, and non-negative counter constraints
17. `000015_tenancy_connector_rls_scope_enforcement` - enforced tenant/workspace row-level security policies
18. `000015_tenancy_connector_rls_scope_guardrails` - additive tenant/workspace row-level security guardrails
19. `000016_findings_lookup_indexes` - finding-id lookup indexes for API retrieval paths
20. `000017_queue_trace_context` - trace context columns for queued scans
21. `000018_users_and_sessions` - user, identity, and session primitives for the new auth stack
22. `000019_scan_policy_repo_bounds` - scan policy history and finding limit bounds
23. `000020_invitations_domains_connections` - invitation, verified-domain, and enterprise identity connection scaffolding
24. `000021_scan_policy_scheduler_state` - scan policy scheduler tick state and due-policy lookup index
25. `000022_scan_retry_dlq_replay` - scan retry / DLQ replay scaffolding
26. `000023_onboarding_state` - onboarding wizard server-owned state
27. `000024_native_sso_scim_scaffold` - native SAML and SCIM 2.0 schema scaffolding: extends `identity_connections` with native SAML fields + a SCIM bearer token hash, adds a composite-FK-backed `scim_provisioning_events` audit table, and reuses the existing `user_identities` table for SCIM-assigned external ids (no new column on `users`)
28. `000025_saml_relay_states_and_session_saml` - persists in-flight SP-initiated SAML AuthnRequest state across API instances and widens `sessions.auth_method` to accept `'saml'`

Notes:
- Each migration has matching `.up.sql` and `.down.sql` files.
- Duplicate numeric prefixes are historical and preserved to avoid reordering risk.
- Numeric migration versions are unique and tracked in `schema_migrations`.
