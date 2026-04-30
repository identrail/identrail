# Domain Entity Model (App Mode)

This document defines the normalized multi-tenant app-mode entities introduced for tenancy, project, connector, policy, and remediation workflows.

## Tenancy Core

- `Organization`
  - Fields: `id`, `name`, `slug`, `created_at`, `updated_at`
  - Validation: non-empty id/name/slug with identifier-safe formatting.
- `Workspace`
  - Fields: `id`, `organization_id`, `name`, `slug`, `created_at`, `updated_at`
  - Validation: required org reference and identifier-safe ids/slugs.
- `WorkspaceMember`
  - Fields: `id`, `workspace_id`, `user_id`, `email`, `role`, `status`, `joined_at`, `updated_at`
  - Role enum: `owner|admin|analyst|viewer`
  - Status enum: `invited|active|suspended|removed`

## Project and Connector

- `Project`
  - Fields: `id`, `workspace_id`, `name`, `slug`, `description`, `archived_at`, `created_at`, `updated_at`
  - Validation: required workspace and project identity fields.
- `Connector`
  - Fields: `id`, `workspace_id`, `project_id`, `type`, `display_name`, `status`, `last_sync_at`, `created_at`, `updated_at`
  - Type enum: `github|aws|kubernetes`
  - Status enum: `pending|active|degraded|disconnected`
  - Transition contract:
    - `pending -> active|degraded|disconnected`
    - `active -> degraded|disconnected`
    - `degraded -> active|disconnected`
    - `disconnected -> pending|active`

## Policy Entities

- `ScanPolicy`
  - Fields: `id`, `workspace_id`, `project_id`, `name`, `enabled`, `trigger_mode`, `cron`, `max_concurrent_scans`, `created_at`, `updated_at`
  - Trigger mode enum: `manual|scheduled|event|hybrid`
  - Validation: required ids/name, valid mode, `max_concurrent_scans > 0`.
- `SuppressionPolicy`
  - Fields: `id`, `workspace_id`, `project_id`, `name`, `scope`, `target`, `reason`, `expires_at`, `created_by`, `created_at`, `last_updated_at`
  - Scope enum: `finding|rule|resource`
  - Validation: required ids, scope, target, reason, and creator id.

## Remediation Entity

- `RemediationJob`
  - Fields: `id`, `workspace_id`, `project_id`, `finding_id`, `type`, `status`, `requested_by`, `requested_at`, `started_at`, `completed_at`, `artifact_ref`, `error_message`, `last_updated_at`
  - Type enum: `patch_template|create_fix_pr|ticket`
  - Status enum: `queued|running|succeeded|failed|canceled`
  - Transition contract:
    - `queued -> running|canceled`
    - `running -> succeeded|failed|canceled`
    - `failed -> queued` (retry)
    - `succeeded|canceled` are terminal

## Contracts and Validation

- All entities use snake_case JSON tags for API and persistence contract stability.
- Validation and transition helpers live in:
  - `internal/domain/appmode.go`
- Validation and transition tests live in:
  - `internal/domain/appmode_test.go`
  - `internal/domain/json_tags_test.go`
