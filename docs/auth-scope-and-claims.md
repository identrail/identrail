# Auth Scope and Claims Mapping

This guide defines how tenant/workspace scope is derived and how OIDC claims map into authorization context.

## Scope Resolution Order

For each request, scope context is resolved in this order:

1. Verified token claims (`tenant`, `workspace` mapped claims)
2. Scope headers (`X-Identrail-Tenant-ID`, `X-Identrail-Workspace-ID`)
3. Runtime defaults (`IDENTRAIL_DEFAULT_TENANT_ID`, `IDENTRAIL_DEFAULT_WORKSPACE_ID`)

## OIDC Claim Mapping

Claim names are configurable:

- `IDENTRAIL_OIDC_TENANT_CLAIM` (default `tenant_id`)
- `IDENTRAIL_OIDC_WORKSPACE_CLAIM` (default `workspace_id`)
- `IDENTRAIL_OIDC_GROUPS_CLAIM` (default `groups`)
- `IDENTRAIL_OIDC_ROLES_CLAIM` (default `roles`)

Issuer/audience controls:

- `IDENTRAIL_OIDC_ISSUER_URL`
- `IDENTRAIL_OIDC_AUDIENCE`

### Keycloak Baseline

For Keycloak-backed OIDC verification, set:

- `IDENTRAIL_OIDC_ISSUER_URL=https://<keycloak-host>/realms/<realm>`
- `IDENTRAIL_OIDC_AUDIENCE=<keycloak-client-id>`

Token requirements for Identrail auth middleware:

- `iss` must exactly match `IDENTRAIL_OIDC_ISSUER_URL`
- `aud` must include `IDENTRAIL_OIDC_AUDIENCE`
- `exp` must be valid (expired tokens are rejected)
- tenant/workspace claims must exist using configured claim names

If your Keycloak token does not already expose `tenant_id` and `workspace_id` as top-level string claims, add protocol mappers for them in the client.

## Write Authorization

Write access is enforced by scope policy for both API keys and OIDC bearer tokens.

- API keys: scoped keys (`write`/`admin`) or legacy write-key config
- OIDC: write scopes configured via `IDENTRAIL_OIDC_WRITE_SCOPES`

## Operator Checks

- verify claim names match your IdP token shape
- verify headers are only trusted from approved proxy paths
- verify defaults are explicit and valid for your tenant/workspace topology
