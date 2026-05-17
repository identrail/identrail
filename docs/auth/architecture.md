# Auth Architecture

This document is the entry point for how authentication, sessions, and identity
work in Identrail. It describes the contracts currently implemented on `dev`
plus the explicitly planned follow-up tracks. If code and this document
disagree, update this document or the code in the same PR.

## Goals

The auth system needs to do four things well.

1. Let any new user sign up to Identrail Cloud in under 60 seconds without talking to sales, without cloning anything, and without a password.
2. Let self-hosted operators run the same software with the same auth flow, using either a generic OIDC provider they already run or a "manual mode" for local development.
3. Support enterprise SSO (SAML or OIDC), domain verification, group-to-role mapping, and SCIM directory sync without forking the codebase.
4. Stay auditable end to end. Every login, session change, role change, and connector credential change ends up in one audit log.

## Decision: WorkOS plus dual-driver OIDC

Identrail Cloud uses [WorkOS](https://workos.com) as the hosted identity provider. Self-hosted Identrail uses a generic OIDC driver that points at any IdP the operator runs.

We considered Zitadel, Keycloak, Auth0, and rolling our own. Comparison and reasoning:

| Option | Why not |
| --- | --- |
| Roll our own | Three to four engineer-months for v1, plus a permanent CVE tail. A security product that gets popped because of a hand-rolled login is a brand-ending event. |
| Keycloak | Java, 1 to 2 GB JVM footprint. Brutal for self-hosters running on a single VPS. |
| Auth0 | Strong product, but closed SaaS. Bifurcates the codebase between Cloud and self-host the moment we adopt it. Pricing cliff at SSO. |
| Zitadel | Strong technical fit (Go, single binary, Postgres). Stayed on the shortlist; we picked WorkOS for AuthKit's hosted UI and for the SSO/SCIM developer experience. Zitadel remains a viable replacement if WorkOS pricing or fit ever stops working. |

The discipline rule that keeps the dual-driver setup healthy:

> No auth feature ships unless both `WorkOSProvider` and `OIDCProvider` support it.

This is the rule that prevents drift over time. If WorkOS releases a new feature, OSS users either get the equivalent on the OIDC path or the feature does not ship.

## Identity Model

Identrail already has a tenancy model. The auth layer adds three new tables (`users`, `user_identities`, `sessions`) and reuses the rest.

### Existing tables (unchanged)

- `tenancy_organizations` - the tenant
- `tenancy_workspaces` - the workspace inside a tenant
- `tenancy_workspace_members` - which user has which role in which workspace
- `tenancy_projects` - project under a workspace
- `tenancy_connectors` and `tenancy_connector_states` - the AWS, Kubernetes, GitHub connections
- `tenancy_connector_secret_envelopes` - encrypted credentials

### New tables

- `users` - one row per human. Holds `id` (UUID), `primary_email`, `display_name`, `avatar_url`, `status`, `created_at`, `updated_at`, `deleted_at`.
- `user_identities` - one row per (provider, subject) pair pointing at a user. A single user can have many identities (WorkOS, GitHub, Google, future SAML).
- `sessions` - server-side session store. The cookie carries only an opaque session ID; everything else lives in this row.

### Mapping table (the contract)

This is the load-bearing piece. Every later PR refers back to this.

| External thing | Internal thing |
| --- | --- |
| WorkOS Organization | `tenancy_organizations` row |
| WorkOS User | `users` row |
| WorkOS user `sub` claim | `user_identities` row with `provider="workos"`, `subject=<sub>` |
| OIDC `iss` + `sub` (self-host) | `user_identities` row with `provider="oidc:<issuer>"`, `subject=<sub>` |
| `users.id` (UUID) | Referenced by `tenancy_workspace_members.user_uuid` (new FK column, see migration plan below) |

### Migration plan: `tenancy_workspace_members.user_id`

Today, `tenancy_workspace_members.user_id` is a free-text string holding the OIDC `sub` of the member. We do not change that column. We add `user_uuid UUID NULL` next to it (strangler fig pattern).

Stages:

1. Add `user_uuid UUID NULL`. New writes populate both `user_id` and `user_uuid`.
2. WorkOS login populates `user_uuid` for every new sign-in.
3. A backfill job copies `user_uuid` for existing rows by joining on the `(provider, subject)` pair, not `subject` alone. Subjects can collide across IdPs (Google `sub=12345` and Microsoft `sub=12345` are unrelated humans), so the backfill needs the provider too. For each org, the backfill resolves provider from the org's currently-configured OIDC issuer (the common case is one IdP per org); rows that match more than one `user_identities` row are left for manual reconciliation rather than auto-linked. Audit log records every backfill mapping for traceability.
4. After we observe zero non-UUID reads in production telemetry for at least four weeks, a separate migration drops `user_id` and renames `user_uuid` to `user_id`.

This avoids a destabilizing column-type migration on a live production table. Existing self-host users keep working through every stage.

## Auth Modes

Identrail supports four authenticated request types. All four coexist forever. None of them get removed by this work.

| Mode | How it works | Used by |
| --- | --- | --- |
| WorkOS hosted login | Cookie-based session after AuthKit OAuth | Cloud product UI |
| Generic OIDC bearer | `Authorization: Bearer <jwt>` from a self-hosted IdP | Self-host product UI, programmatic clients with OIDC tokens |
| API key | `X-API-Key` header | Programmatic clients (CI, scripts) |
| Manual mode | Local-only, gated by a flag | Self-host development and local quickstart |

Manual mode is intentionally limited. It lets a developer enter a tenant ID, workspace ID, and project ID directly, and it works only when `IDENTRAIL_AUTH_MANUAL_MODE=true`. Hosted Cloud rejects this flag at startup if WorkOS is also configured. The UI shows a "Dev Mode" banner whenever manual mode is active.

## Session Model

Identrail uses opaque server-side sessions, not JWTs in cookies.

- The cookie carries a 32-byte random session ID.
- The server stores a SHA-256 hash of that ID as the primary key in the `sessions` table.
- Lookups happen on every request via the `currentSession` middleware.
- Revocation is real: deleting the row invalidates the cookie immediately, no token expiry to wait for.

Session lifetime:

- 15-minute idle timeout (sliding renewal on each request).
- 14-day absolute timeout (hard cap, no renewal past this point).
- Re-authentication required for: privilege change, SSO enforcement toggle, sensitive admin actions.

See [`cookie-and-session-spec.md`](./cookie-and-session-spec.md) for the full cookie attributes and HMAC key rotation rules.

## Domains

Identrail uses three public domain roles.

| Purpose | Domain | What lives here |
| --- | --- | --- |
| Marketing | `www.identrail.com` and apex `identrail.com` | The marketing site and public auth entry points. No session cookies. |
| Application | `app.identrail.com` | The product UI. |
| API | `api.identrail.com` | API endpoints (`/v1/*`) and auth endpoints (`/auth/*`). |

Cookies are scoped to the API host that issues them, with no leading dot. The marketing site never sees the session cookie. Browser calls from the web origins to `api.identrail.com` require the production CORS allowlist and credentialed requests described in [`production-api-readiness.md`](./production-api-readiness.md).

The canonical production base URL lives in `IDENTRAIL_PUBLIC_BASE_URL`. The doc references this env var rather than hardcoding the string. See [`env-vars-reference.md`](./env-vars-reference.md).

## Endpoint Surface

This section lists the auth, native SSO, SCIM, onboarding, and connector
endpoints that are implemented or intentionally planned. The OpenAPI contract in
[`../openapi-v1.yaml`](../openapi-v1.yaml) is the authoritative machine-readable
shape for shipped routes.

### Sessions and identity

Session context includes `current_org_id`, `current_workspace_id`, and `current_project_id` so project-scoped APIs can resolve tenancy without implicit defaults.

| Method | Path | Status |
| --- | --- | --- |
| GET | `/v1/me` | Shipped |
| GET | `/v1/me/sessions` | Shipped |
| DELETE | `/v1/me/sessions/:id` | Shipped |
| POST | `/v1/me/sessions/revoke-others` | Shipped |
| GET | `/v1/me/auth-events` | Planned |
| POST | `/auth/logout` | Shipped |
| GET | `/v1/auth/config` | Shipped |

### Hosted login

| Method | Path | Status |
| --- | --- | --- |
| GET | `/auth/login?return_to=...` | Shipped |
| GET | `/auth/signup?return_to=...` | Shipped |
| GET | `/auth/callback` | Shipped |
| POST | `/auth/webhooks/workos` | Shipped |

### Onboarding

| Method | Path | Status |
| --- | --- | --- |
| POST | `/v1/onboarding/start` | Shipped |
| GET | `/v1/onboarding/state` | Shipped |
| POST | `/v1/onboarding/state` | Shipped |
| POST | `/v1/onboarding/complete` | Shipped |

### Connectors

Connector endpoints are project-scoped. The route shape stays flat (`/v1/connectors/*`), but every handler resolves `(tenant_id, workspace_id, project_id)` from the authenticated session context, including `sessions.current_project_id`. Requests without an active project context fail fast.

| Method | Path | Status |
| --- | --- | --- |
| GET | `/v1/connectors` | Shipped |
| GET | `/v1/connectors/:id` | Shipped |
| GET | `/v1/connectors/:id/health` | Shipped |
| DELETE | `/v1/connectors/:id` | Shipped |
| POST | `/v1/connectors/:id/disable` | Shipped |
| POST | `/v1/connectors/:id/enable` | Shipped |
| POST | `/v1/connectors/aws` | Shipped |
| POST | `/v1/connectors/aws/:id/validate` | Shipped |
| GET | `/v1/connectors/aws/:id/poll` | Shipped |
| POST | `/v1/connectors/aws/:id/refresh-policy` | Shipped |
| POST | `/v1/connectors/github` | Shipped |
| POST | `/v1/connectors/github/pat` | Shipped |
| POST | `/auth/webhooks/github` | Shipped |
| GET | `/v1/connectors/github/:id/repos` | Shipped |
| POST | `/v1/connectors/k8s` | Shipped |
| POST | `/v1/connectors/k8s/enroll` | Shipped |
| POST | `/v1/connectors/k8s/heartbeat` | Shipped |
| POST | `/v1/connectors/k8s/kubeconfig` | Shipped |

### Native SAML and SCIM

These routes are registered only when `IDENTRAIL_FEATURE_NATIVE_SSO=true` or
the compatibility alias `IDENTRAIL_ENABLE_NATIVE_SSO=true`. Native SAML admin
and login routes also require `IDENTRAIL_FEATURE_NEW_AUTH=true` because they
depend on session-auth middleware and the SAML relay store.

| Method | Path | Status |
| --- | --- | --- |
| POST | `/v1/enterprise/identity-connections/saml` | Shipped |
| GET | `/v1/enterprise/identity-connections/saml` | Shipped |
| GET | `/v1/enterprise/identity-connections/saml/:id` | Shipped |
| PUT | `/v1/enterprise/identity-connections/saml/:id` | Shipped |
| DELETE | `/v1/enterprise/identity-connections/saml/:id` | Shipped |
| POST | `/v1/enterprise/identity-connections/saml/from-metadata` | Shipped |
| GET | `/auth/saml/login/:connection_id` | Shipped |
| POST | `/auth/saml/acs/:connection_id` | Shipped |
| GET | `/scim/v2/ServiceProviderConfig` | Shipped |
| GET | `/scim/v2/Schemas` | Shipped |
| GET | `/scim/v2/ResourceTypes` | Shipped |
| GET | `/scim/v2/Users` | Shipped |
| POST | `/scim/v2/Users` | Shipped |
| GET | `/scim/v2/Users/:id` | Shipped |
| PUT | `/scim/v2/Users/:id` | Shipped |
| PATCH | `/scim/v2/Users/:id` | Shipped |
| DELETE | `/scim/v2/Users/:id` | Shipped |

### Enterprise admin

The invitation, verified-domain, and WorkOS Admin Portal routes from the
original roadmap are no longer the Track 1 source of truth. Keep the current
WorkOS login path working, but use the native SAML admin API above for native
SAML configuration.

### Existing endpoints (unchanged)

The existing API key endpoints, the existing OIDC bearer flow, the existing scan endpoints, and every `/v1/scans/*`, `/v1/findings/*`, `/v1/repo-scans/*` route stays exactly as it is today. None of them change behavior.

## Rate Limit Budgets

Auth and connector endpoints set explicit rate limits. Later route additions should inherit the same configuration shape.

| Endpoint pattern | Limit | Per |
| --- | --- | --- |
| `GET /auth/login`, `GET /auth/signup` | 10 / minute | IP |
| `GET /auth/callback` | 30 / minute | IP |
| `POST /auth/logout` | 100 / minute | session |
| `POST /auth/webhooks/*` | 60 / minute | IP (signature checked first) |
| `POST /v1/onboarding/*` | 30 / minute | session |
| `POST /v1/connectors/*` (creates) | 20 / minute | project |
| `POST /v1/invitations` | 100 / hour | org |
| `GET /v1/me`, `GET /v1/me/*` | 600 / minute | session |
| `DELETE /v1/me/sessions/:id`, `POST /v1/me/sessions/revoke-others` | 30 / minute | session |

Limits are enforced server-side and emit metrics. Hitting a limit returns HTTP 429 with `Retry-After`.

## SSO Rollout Guardrail

Native SAML connections persist two rollout controls:
`sso_required` and `jit_provisioning_enabled`. Both default to `false`.

The current Track 1 implementation stores `sso_required` and exposes it through
the native SAML admin API, but it does not yet ship recovery-code generation,
an IdP-authenticated enforcement toggle, or a full org lockout-rescue flow. Do
not document or rely on those older roadmap features as shipped behavior.

The safe operating sequence is:

1. Create the native SAML connection with `sso_required=false`.
2. Import IdP metadata and verify SAML login with a test admin.
3. Enable SCIM and confirm create, update, deactivate, and delete events.
4. Only then set `sso_required=true` as the org's rollout marker and keep a
   break-glass admin path outside the enforced tenant.

See [`identity-linking-rules.md`](./identity-linking-rules.md) for the rules
around linking identities and joining orgs.

## Native SAML

Native SAML uses `github.com/crewjam/saml` for protocol handling. Identrail
constructs a per-connection service provider from the stored entity ID, SSO
URL, certificate, and public base URL, then delegates assertion parsing,
signature verification, audience/recipient checks, and time-condition checks to
the library.

The SP entity ID is:

```text
${IDENTRAIL_PUBLIC_BASE_URL}/auth/saml/metadata/<connection_id>
```

That value is an identifier used as the SAML audience. The current API does not
serve an SP metadata document at that URL.

Unknown SAML users are rejected unless the connection has
`jit_provisioning_enabled=true`. When JIT is disabled, the ACS returns a clear
admin-actionable failure telling the user to ask an admin to provision them.

## Native SCIM Provisioning

Native SAML connections issue one per-connection SCIM bearer token when the admin creates the connection. The plaintext token is returned once; the database stores only the SHA-256 hash on `identity_connections.scim_bearer_token_hash`.

When `IDENTRAIL_FEATURE_NATIVE_SSO=true` (or the compatibility alias `IDENTRAIL_ENABLE_NATIVE_SSO=true`) the API registers `/scim/v2` endpoints for IdP directory provisioning:

| Endpoint | Purpose |
| --- | --- |
| `GET /scim/v2/ServiceProviderConfig` | SCIM capability discovery |
| `GET /scim/v2/Schemas` | Core User schema discovery |
| `GET /scim/v2/ResourceTypes` | User resource-type discovery |
| `GET /scim/v2/Users` | List users with `startIndex`, `count`, and `filter=userName eq "..."` |
| `POST /scim/v2/Users` | Create a user with a server-assigned SCIM id |
| `GET /scim/v2/Users/{id}` | Read a provisioned user |
| `PUT /scim/v2/Users/{id}` | Replace a provisioned user |
| `PATCH /scim/v2/Users/{id}` | Apply SCIM PATCH `replace` operations |
| `DELETE /scim/v2/Users/{id}` | Deactivate a provisioned user and record a delete event |

SCIM resources reuse the auth tables instead of introducing a separate user
store: `users.id` is the SCIM resource id, and `user_identities` stores
`(provider="scim:<connection_uuid>", subject=<userName>)`. Each create, update,
deactivate, and delete appends a `scim_provisioning_events` row for
tenant-visible audit and dispatches a `scim.provisioned` workflow event through
the existing workflow router. Dispatch failures are audited but do not fail the
SCIM operation.

## Connector Foundation Preview

Every connector (AWS, Kubernetes, GitHub, future ones) implements one Go interface and shares one status state machine and one error taxonomy.

The full spec lives in [`connector-foundation.md`](./connector-foundation.md). The short version: never write a bespoke status string or bespoke error code in a connector. Every connector goes through `pending → validating → active ⇄ degraded → disconnected`. Every error maps to one of seven taxonomy codes. Every connector ships a `Health()` implementation that the heartbeat job calls every 5 minutes.

## Threat Model and Identity-Linking Rules

The two security-critical sections live in their own docs:

- [`threat-model.md`](./threat-model.md) covers cookie theft, OAuth state replay, session fixation, CSRF, host-header injection, account enumeration, and SSO downgrade.
- [`identity-linking-rules.md`](./identity-linking-rules.md) covers the rules around linking provider identities and the account-takeover exploit those rules prevent. Read this one before writing any code that touches `user_identities`.

## Environment Variables

A flat list with defaults, validation, and the PR that introduces each variable lives in [`env-vars-reference.md`](./env-vars-reference.md).

The most important rule: every domain reference in code, config, and email templates reads from `IDENTRAIL_PUBLIC_BASE_URL` rather than a string literal. The docs use `https://app.identrail.com` as the canonical example throughout because we have to write something concrete down, but the production deployment derives that value from the env var. Code paths that hardcode the domain are caught in CI and rejected. The server refuses to start if `IDENTRAIL_PUBLIC_BASE_URL` is unset or invalid.

## Roadmap

The current roadmap lives in [`12-pr-plan.md`](./12-pr-plan.md). The file name
is historical; the content now records the three-track plan.

## Non-Goals for the Auth Foundation

To stay scoped, this work explicitly does not address:

- Stripe or any payment integration. Billing is a separate stream.
- Custom roles beyond `owner`, `admin`, `analyst`, `viewer`. Adding a fifth role is not in scope until at least one design partner needs it.
- A mobile app. Mobile would need PKCE on a different flow; out of scope.
- Breaking the existing API key auth. API keys keep working unchanged forever.
- A full standalone admin/IT portal. Org admin is in `/app/{tenant}/admin/*` inside the existing dashboard.

## Open Questions

These are the questions we have not answered yet and do not need to answer to ship PRs 1 through 5.

- Email provider: Resend vs Postmark vs SES. Default plan is Resend when
  invitation/email work resumes.
- Backend hosting: AWS is the current documented hosted API path; local development still runs through docker-compose.
- Account merge across providers: today an authenticated user can link a second identity. Whether to ever allow merging two existing accounts (one per provider) is deferred. Default answer is no.
- Free-tier abuse defense beyond rate limits. Captcha vs proof-of-work vs domain blocklists. Deferred until we see actual abuse signals.

## Document Map

- [`architecture.md`](./architecture.md) (this file)
- [`threat-model.md`](./threat-model.md)
- [`cookie-and-session-spec.md`](./cookie-and-session-spec.md)
- [`identity-linking-rules.md`](./identity-linking-rules.md)
- [`connector-foundation.md`](./connector-foundation.md)
- [`env-vars-reference.md`](./env-vars-reference.md)
- [`12-pr-plan.md`](./12-pr-plan.md) - historical file name, current three-track roadmap
