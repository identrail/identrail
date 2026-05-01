# Connector Lifecycle Framework

This document defines the shared connector lifecycle contract introduced for app-mode connector management.

## Goal

Standardize connector behavior across provider implementations (GitHub, AWS, Kubernetes) so lifecycle actions are consistent and reusable.

## Shared Model

- Lifecycle status (`domain.ConnectorStatus`):
  - `pending`
  - `active`
  - `degraded`
  - `disconnected`
- Normalized health status (`connectors.HealthStatus`):
  - `unknown`
  - `healthy`
  - `warning`
  - `error`

## Provider Hook Contract

Provider-specific drivers implement:

- `TestConnection(ctx, connector) (ProbeResult, error)`
- `RevokeConnection(ctx, connector) error`
- `ReactivateConnection(ctx, connector) error`

The framework consumes hook results and applies a shared state machine.

## Lifecycle Semantics

- `TestConnection`
  - blocked for `disconnected` connectors until reactivated
  - healthy probe -> `active`
  - warning/error/unknown probe from `pending` -> `degraded`
  - warning/error/unknown probe from `active|degraded` -> keep current status
- `Revoke`
  - transitions to `disconnected`
  - idempotent when already `disconnected`
- `Reactivate`
  - allowed only from `disconnected`
  - transitions to `pending` for safe revalidation

## Health Normalization

Provider health outputs are normalized using `NormalizeHealthStatus`:

- Healthy aliases: `healthy`, `ok`, `pass`, `ready`, `up`, `connected`, `active`
- Warning aliases: `warning`, `warn`, `degraded`, `partial`
- Error aliases: `error`, `failed`, `fail`, `down`, `disconnected`, `revoked`
- Unknown/default: everything else

Probe errors always normalize to `error`.

## Why This Matters

- One lifecycle contract for all provider implementations.
- Predictable revoke/reactivate behavior.
- Consistent health semantics for UI, policy, and automation workflows.
- Reduces provider-specific branching in future connector orchestration code.
