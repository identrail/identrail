# Artifact Persistence (Phase 2)

## Purpose

Persist the full scan data graph, not only findings, so future APIs and time-based analysis can query raw and normalized evidence.

## Persisted Artifact Sets

- raw assets (`raw_assets`)
- normalized identities (`identities`)
- normalized policies (`policies`)
- graph relationships (`relationships`)
- semantic permissions (`permissions`)
- findings (`findings`)

## Idempotency Model

All artifact writes use scan-scoped upsert keys:

- `raw_assets`: `(scan_id, source_id, kind)`
- `identities`: `(scan_id, id)`
- `policies`: `(scan_id, id)`
- `relationships`: `(scan_id, id)`
- `permissions`: `(scan_id, identity_id, action, resource, effect)`
- `findings`: `(scan_id, finding_id)`

This allows safe reruns and repeated persistence calls without duplicate row growth.

## Service Flow

`api.Service.RunScan` now persists in order:

1. create scan
2. run scanner pipeline
3. upsert artifacts
4. upsert findings
5. complete scan with counts/status

## Tenancy CRUD Persistence

Tenancy and project management CRUD now has dedicated scoped store operations:

- organizations (`tenancy_organizations`)
- workspaces (`tenancy_workspaces`)
- workspace members (`tenancy_workspace_members`)
- projects (`tenancy_projects`)

Scope boundaries are enforced by requiring request scope (`tenant_id`, `workspace_id`) in all store operations, and workspace-bound CRUD paths deny cross-workspace access even within the same tenant.
