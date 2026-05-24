# Superseded Auth Roadmap

This file used to describe the original twelve-PR auth and connector sequence.
That sequence is no longer the source of truth. The current roadmap is the
three-track plan below:

1. Enterprise SSO: native SAML plus SCIM.
2. Executive report.
3. Data-residency policy.

The old WorkOS-only SSO admin and WorkOS Directory Sync assumptions were
replaced by native SAML support alongside the existing WorkOS path. Keep WorkOS
login untouched; native SAML and SCIM are opt-in behind
`IDENTRAIL_FEATURE_NATIVE_SSO`.

## Track 1: Enterprise SSO

Track 1 is now implemented on `dev`.

| PR | Scope | Status |
| --- | --- | --- |
| PR-1 | Extend `identity_connections` for native SAML and add SCIM persistence. | Shipped |
| PR-2 | Native SAML connection admin API and Okta/Azure metadata import. | Shipped |
| PR-3 | Native SAML SP-initiated login and ACS via `crewjam/saml`. | Shipped |
| PR-4 | SCIM 2.0 endpoints for Okta and Azure/Entra user provisioning. | Shipped |
| PR-5 | SCIM provisioning workflow audit dispatch and customer setup docs. | Shipped |

Implemented runtime surfaces:

- `POST/GET /v1/enterprise/identity-connections/saml`
- `GET/PUT/DELETE /v1/enterprise/identity-connections/saml/{id}`
- `POST /v1/enterprise/identity-connections/saml/from-metadata`
- `GET /auth/saml/login/{connection_id}`
- `POST /auth/saml/acs/{connection_id}`
- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/Schemas`
- `GET /scim/v2/ResourceTypes`
- `GET/POST /scim/v2/Users`
- `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}`

Important current constraints:

- Native SSO is disabled by default and registers these routes only when
  `IDENTRAIL_FEATURE_NATIVE_SSO=true` or the compatibility alias
  `IDENTRAIL_ENABLE_NATIVE_SSO=true`.
- Native SAML connection creation returns a one-time SCIM bearer token and
  stores only `identity_connections.scim_bearer_token_hash`.
- `sso_required` is persisted on the native SAML connection and should remain
  `false` until the operator has tested SAML and SCIM. The current Track 1 code
  does not yet ship recovery-code generation or a full org lockout-rescue flow.
- JIT user creation is controlled per connection by
  `jit_provisioning_enabled`; unknown SAML users are rejected when it is false.
- SCIM creates, updates, deactivations, and deletes append
  `scim_provisioning_events` and dispatch `workflow.Event` records through the
  existing workflow router.
- Native SAML must not silently replace WorkOS. WorkOS-backed SAML rows and
  native SAML rows are distinct, and the admin API returns a clear conflict when
  an org already has a WorkOS-managed SAML connection of the same type.

Customer setup lives in [`../enterprise-quickstart.md`](../enterprise-quickstart.md).
The API contract lives in [`../openapi-v1.yaml`](../openapi-v1.yaml).

## Track 2: Executive Report

Track 2 restores leadership reporting without server-side PDF generation.

| PR | Scope | Status |
| --- | --- | --- |
| PR-6 | Add `ResolvedAt` on finding triage, migration, and backfill. | Planned |
| PR-7 | Add `/v1/enterprise/reports/executive` JSON endpoint with MTTR. | Planned |
| PR-8 | Add read-only web executive report page with browser print styles. | Planned |

The output target is a page a CISO can bookmark, refresh weekly, and print from
the browser with Cmd+P or Ctrl+P.

## Track 3: Data-Residency Policy

Track 3 is deferred until a customer needs region-level enforcement.

| PR | Scope | Status |
| --- | --- | --- |
| PR-9 | Add `residency_policies` table and CRUD API. | Deferred |
| PR-10 | Add write-boundary enforcement middleware behind a feature flag. | Deferred |

The intended customer path is advisory mode first, then strict mode after the
compliance team has reviewed the audit trail.

## Cross-Cutting Rules

Every follow-up PR should preserve these rules:

- No new daemon, worker, queue, Redis, or second database unless explicitly
  approved.
- Migrations are additive and backward compatible.
- Advanced settings need working defaults.
- New routes are feature-flagged until GA.
- API behavior changes update OpenAPI and customer-visible docs in the same PR.
- Okta and Azure/Entra paths use real provider-shaped fixtures in tests.
- WorkOS remains supported and must not be silently overridden by native SAML.
- Commits are DCO signed.
