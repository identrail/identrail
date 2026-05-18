# Changelog

## Unreleased
- Corrected the `IDENTRAIL_PUBLIC_BASE_URL` documentation so the auth
  env-var reference and the production-readiness guide agree: it is the
  externally reachable API callback origin (`https://api.identrail.com` for
  Identrail Cloud), not the web app origin. The production example now uses
  the API origin, the WorkOS redirect URI example matches the
  code-generated `<base>/auth/callback`, and the docs explicitly contrast
  the API callback origin with web app origins. Docs-only; no behavior
  change. A potential config rename/split
  (`IDENTRAIL_PUBLIC_API_BASE_URL` / `IDENTRAIL_WEB_APP_ORIGINS`) is left to
  a separate tracked change.
- Wired `IDENTRAIL_SESSION_KEY_PREVIOUS` into signed/sealed auth artifact
  verification so rotating `IDENTRAIL_SESSION_KEY` no longer invalidates
  in-flight OAuth `state` or WorkOS MFA pending state. The active key remains
  the only signer/sealer; the previous key, when configured, is accepted for
  verification/decryption only. Updated the cookie-and-session spec to
  accurately list which artifacts this key protects (OAuth state and MFA
  pending state, both 10-minute TTL — not the opaque session cookie or
  random invitation tokens) and to give a correct rotation drain window.
- Made WorkOS webhook delivery idempotent. After signature validation the
  handler claims the provider event ID in a new durable `webhook_events`
  table (status `processing` → `processed`) before applying user-lifecycle
  side effects. A completed duplicate, retry, or replay returns a no-op
  success without reapplying `user.deleted` / `user.email_changed` /
  `user.updated` effects; a duplicate that arrives while the first delivery
  is still in flight is told to retry (HTTP 503) rather than acknowledged,
  so the provider keeps retrying until the effects are durably applied. The
  check is durable across restarts and shared across API instances; a
  transient server-side failure rolls back the claim so a provider retry can
  reprocess, and a claim left behind by a crashed instance is reclaimable
  after a grace period. Each claim carries a token so a superseded stale
  handler cannot complete or erase the reclaiming retry's in-flight claim;
  completion and rollback run on a request-detached context; rows that
  predate the ledger are treated as already-processed; and processed rows
  past a retention window are opportunistically pruned so the ledger does
  not grow unbounded.
- Added the hosted AWS worker deploy path for queued GitHub repository scans.
  The manual AWS API deploy workflow now enables the worker service by default,
  derives the matching immutable worker image from the API image when no
  worker-specific image is supplied, and provisions a queue-only ECS/Fargate
  worker with separate IAM roles, logging, and security group. The worker also
  gained `IDENTRAIL_WORKER_SCAN_ENABLED` so the hosted queue processor can drain
  API-enqueued work without starting unrelated scheduled cloud scans.
- Added per-request defense-in-depth on `/auth/manual`: the handler now
  rejects any request whose resolved client IP (honoring the configured
  trusted-proxy list) is not a loopback address, unless
  `IDENTRAIL_AUTH_MANUAL_MODE_ALLOW_UNSAFE=true`. This layers a runtime
  check on top of the `IDENTRAIL_AUTH_MANUAL_MODE` startup guard, since the
  process cannot observe a Docker port publish, reverse proxy, or ingress
  at boot but can check the actual client at request time.
- Made `IDENTRAIL_AUTH_MANUAL_MODE` a local-development-only feature at
  startup validation. The server now refuses to boot with manual mode
  enabled unless `IDENTRAIL_PUBLIC_BASE_URL` is a loopback origin
  (`http://localhost`, `http://127.0.0.1`, or `http://[::1]`) **and**
  `IDENTRAIL_HTTP_ADDR` binds a loopback interface, so the request-trusting
  `/auth/manual` session endpoint cannot be exposed accidentally — a
  loopback base URL alone does not stop a `0.0.0.0` bind or ingress from
  reaching it. A deliberately non-production test deployment whose
  reachability is constrained another way must opt in explicitly with the
  clearly named `IDENTRAIL_AUTH_MANUAL_MODE_ALLOW_UNSAFE=true`. Manual mode
  now also emits a startup security warning, and the WorkOS mutual-exclusion
  checks are unchanged.
- Added first-class AWS API deployment variables for repository scan runtime
  configuration, including allowlist validation before Terraform so hosted
  GitHub scans cannot be enabled without an explicit target boundary.
- Added a request-side CSRF/origin guard for unsafe (`POST`/`PUT`/`PATCH`/
  `DELETE`) browser session-authenticated `/v1/*` API writes. CORS is no
  longer relied on as a CSRF control: a guarded request must present a
  first-party `Origin` (or `Referer` fallback) matching
  `IDENTRAIL_PUBLIC_BASE_URL` or an explicitly allowed web origin, a
  `Sec-Fetch-Site` that is not `cross-site`, and (when a body is sent)
  `application/json`. API-key, OIDC bearer, SCIM, connector-agent,
  OAuth/SAML callback, and webhook routes are unaffected because they do not
  carry the browser session cookie. Rejected requests return `403`.
- Hardened the WorkOS OAuth login flow with a store-backed, browser-bound
  transaction. The signed `state` token is no longer protected only by a
  process-local replay map: `/auth/login` and `/auth/signup` now persist an
  `oauth_transactions` row and set a short-lived `HttpOnly`, `Secure`,
  `SameSite=Lax` transaction cookie, and `/auth/callback` requires the signed
  state, the transaction cookie, and the persisted row to match before
  atomically consuming it. Replays fail across every API instance that shares
  the database, callbacks without the issuing browser's cookie are rejected,
  and the post-login return target is read from the persisted row instead of
  the URL.
- Fixed the authenticated workspace Settings view so a `whoami` response with
  `scopes: null` renders as `None granted` instead of tripping the app error
  boundary, and replaced the fallback error copy with user-facing workspace
  recovery language.
- Replaced the standalone read-only scan page with a rectangular multi-step
  modal opened by the new `Request Trust Path Review` CTA, keeping
  `/read-only-scan` as a compatibility opener and collecting extra verifiable
  requester, identity-provider, scope, and public repository context before the
  final review-and-submit step.
- Required explicit review before read-only scan intake submission and added
  stronger lead-quality checks for work emails, disposable domains, matching
  company websites, and publicly verifiable company DNS.
- Failed closed when the API does not explicitly advertise self-serve
  onboarding support, so authenticated users without a workspace see the
  existing onboarding-unavailable state instead of entering a wizard that
  immediately fails with a raw `Request failed (404)`.
- Tightened Dependabot metadata handling and linked-issue workflow policy:
  Dependabot metadata is now updated without dropping `pull_request` values while
  preserving current behavior for known bots, and the linked-issue workflow
  exemption now applies only to bot-authored PRs (not to bot trigger events).
- Added the first GitHub repository scan action after connection:
  - the product source screen can queue `POST /v1/repo-scans` for a selected
    GitHub repository, show queued/running/completed/failed activity, and link
    directly into repository findings
  - frontend errors now distinguish disabled scanning, allowlist denials,
    duplicate in-progress scans, and queue pressure instead of showing a
    generic request failure
- Enabled GitHub as the first Identrail Cloud self-serve connector path:
  - the release web environment now ships the GitHub connector UI while still
    honoring the backend feature availability contract
  - the product source screen disables GitHub when the API explicitly reports
    the connector unavailable, avoiding raw 404s from mismatched frontend/API
    flags
  - the AWS API manual deploy path now validates and injects the GitHub App id,
    slug, private-key secret, webhook secret, and durable connector secret
    keyset before enabling `IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=true`
- Hardened the first-use onboarding journey so a newly signed-in user reliably
  ends up with a usable, scoped workspace:
  - `StartOnboarding` now reconciles an unbound onboarding row against an
    existing active workspace membership (partial first attempt, or an
    admin-provisioned user), so refreshes and second tabs resume the correct
    step instead of forking a duplicate tenant/workspace.
  - The organization step can be re-submitted by the onboarding creator before
    a workspace exists (e.g. correcting a typo) instead of failing with a
    spurious "workspace access denied"; the owner/admin gate still applies once
    the user actually belongs to a workspace in the tenant, so a resumed viewer
    still cannot rename the org.
  - Added end-to-end coverage proving a brand-new user reaches a workspace where
    `/v1/me`, the workspaces list, the members list (active owner), the default
    project, and the scoped `/app/<org>/<workspace>` redirect all agree, and
    that re-running start is idempotent.
- Wired public lead capture to a production-style Resend email path: scan
  requests now send an internal notification and requester confirmation when
  `RESEND_API_KEY`, `LEAD_NOTIFY_TO`, and a verified `LEAD_EMAIL_FROM` are
  configured, while preserving the signed webhook forwarding option for
  CRM/automation fanout even when Resend rejects or times out, and accepting
  the submission once either configured delivery channel succeeds or the
  internal team notification has been accepted.
- Redesigned the product page as a full-bleed Vercel-style surface with a dark hero, spread-out trust graph connections, alternating neutral sections, and no centered container around the main product story.
- Exposed backend feature availability to the frontend so the web bundle no
  longer shows a backend-gated self-serve flow purely from a Vite build flag:
  - `/v1/auth/config` now returns a `features` object (`onboarding_wizard` and
    per-connector `github`/`aws`/`kubernetes` booleans). It is additive and
    session-safe — only availability booleans, never credentials or config.
  - The app discovers onboarding/connector availability from the API before
    entering those flows. When the bundle ships a feature the API does not
    serve, it shows a clear "not enabled on this API" state instead of a raw
    `Request failed (404)`, and the onboarding connector picker marks such
    connectors unavailable rather than actionable.
  - Resilient by design: an older API without `features`, or a failed
    `auth/config` call, falls back to the existing Vite-flag behavior; the
    strict block only applies when the API explicitly reports a route missing.
- Redesigned the read-only scan intake page with a full-width black Vercel-style hero, sharper SpaceX-inspired headline typography, and high-contrast intake controls with no blurred or gradient details.
- Extended the production API preflight (`make production-api-preflight`) to probe
  `POST /v1/onboarding/start` so the frontend onboarding wizard cannot be wired
  against an API origin that does not serve the onboarding route:
  - treats the unauthenticated JSON `401` session-required response as success,
    matching the deliberate unauthenticated contract from the onboarding route
    visibility fix
  - fails closed on `404`, plain-text framework `404`, HTML, and frontend-shell
    responses, with a failure prefix (`api-url-wiring`, `missing-route`,
    `non-json`/`unexpected-status`) that names the root cause
  - scoped to route presence and the unauthenticated JSON contract shape;
    backend `IDENTRAIL_FEATURE_ONBOARDING_WIZARD` state is intentionally not
    observable from an unauthenticated probe and stays covered by the
    authenticated post-deploy verification steps in the readiness runbook
  - kept generic for Identrail Cloud and self-hosted production API URLs by
    asserting the contract shape rather than a specific host
  - added offline shell-script tests for the response classification and
    documented the behavior in the production API readiness runbook
- Kept authenticated onboarding API routes registered when the onboarding feature flag is off, returning JSON `401` or `503` responses instead of a raw framework `404` so production flag mismatches are visible and diagnosable.
- Added the `GET /v1/enterprise/reports/executive` endpoint returning the organization's leadership rollup (open volume by severity, top finding types, week-over-week trend, and MTTR):
  - calls the shipped `BuildExecutiveReport` builder; JSON only, no server-side PDF generation
  - extended the report builder with `mean_time_to_resolve`, derived strictly from finding triage `resolved_at` (never the mutable `updated_at`) and omitted when no resolved finding has a trustworthy `resolved_at`
  - 60-second per-organization in-memory cache; responses are scoped to the caller's organization under the existing `enterprise.read` authorization
  - documented in the enterprise quickstart and OpenAPI contract
- Added a server-managed `resolved_at` timestamp to finding triage so the executive report can compute an accurate mean-time-to-resolve (MTTR):
  - exposed on the `FindingTriage` API response, OpenAPI schema, and web client types
  - set when a finding transitions into the resolved state, preserved across edits while it stays resolved, and cleared when it is reopened or moved out of resolved
  - migration `000026_finding_triage_resolved_at` adds the nullable column and best-effort backfills existing resolved rows with `resolved_at = updated_at`
- Mirrored public container image publishing to Docker Hub under `docker.io/identrail/*`,
  made Docker Hub the default public-image quickstart source, and pointed the homepage Docker pull metric at the published Docker Hub repositories.
- Routed successful native SCIM user lifecycle operations through the workflow router:
  - emits `scim.provisioned` events for create/update/deactivate/delete operations so Slack, Jira, and Linear destinations can receive directory-sync deltas
  - extends workflow dispatch audit records with SCIM subject, connection, and operation fields for NDJSON governance review
  - documents Okta and Azure AD native SSO setup, SCIM provisioning, and safe `sso_required` rollout in the enterprise quickstart
- Added native SCIM 2.0 user provisioning endpoints (behind `IDENTRAIL_FEATURE_NATIVE_SSO`, with `IDENTRAIL_ENABLE_NATIVE_SSO` accepted as a compatibility alias):
  - `GET /scim/v2/ServiceProviderConfig`, `/Schemas`, and `/ResourceTypes` return Okta/Azure-friendly discovery documents using SCIM-shaped responses
  - `GET/POST/GET by id/PUT/PATCH/DELETE /scim/v2/Users` supports server-assigned ids, `filter=userName eq "..."`, pagination, full user replacement, PATCH `replace`, and deactivation/delete lifecycle handling
  - Requests authenticate with the per-connection bearer token issued by the native SAML admin API; only active native SAML connections can provision users
  - SCIM users persist through the existing `users` + `user_identities` model with provider `scim:<connection_uuid>`, and every create/update/deactivate/delete writes a `scim_provisioning_events` audit record
- Added migration `000025_saml_relay_states_and_session_saml`:
  - New `saml_relay_states` table persists in-flight SP-initiated SAML AuthnRequest context (handle, connection_id FK, AuthnRequest id, return_to, intent, expires_at, consumed_at) so the matching ACS POST resolves correctly even when callbacks land on a different API instance than the one that issued the redirect
  - Widens the `sessions.auth_method` CHECK constraint to accept `'saml'` so SAML-issued sessions no longer trip a 23514 constraint violation
- Added native SAML 2.0 SP-initiated login (behind `IDENTRAIL_FEATURE_NATIVE_SSO`):
  - `GET /auth/saml/login/{connection_id}` mints an `AuthnRequest`, stores the request id in the existing HMAC-signed state token, and redirects the browser to the IdP SSO URL with `RelayState`
  - `POST /auth/saml/acs/{connection_id}` is the Assertion Consumer Service. SAML response parsing, signature verification (XML-DSig), audience/recipient/InResponseTo checks, and `NotOnOrAfter` enforcement are delegated to `github.com/crewjam/saml` so we do not ship bespoke SAML protocol code. A 60s clock-skew tolerance is layered on top.
  - `UpsertSAMLAssertedUser` resolves users in three steps: existing `saml:<connection_id>` identity → pre-provisioned `scim:<connection_id>` identity → existing user by primary email. When no match exists, the connection's `jit_provisioning_enabled` flag decides whether to create a fresh user or return 403 with an admin-actionable "ask your admin to provision your account" message
  - Sessions issued from the SAML path carry `AuthMethod: "saml"` (new accepted value) and the org id from the connection
  - `/v1/auth/config` exposes `native_saml_enabled` and includes `saml` in the advertised providers list when native SSO is enabled; connection-specific SAML login still comes from the native SAML admin/API flow
  - WorkOS sign-in/sign-up flow is unchanged; both paths share the same `OAuthStateManager` so a `SessionKey` rotation invalidates every half-finished login regardless of which doorway issued it
- Replaced the authenticated Overview and Settings scaffold routes with real product views:
  - Overview now loads workspace projects, repository scans, open repository findings, and trend signals to show operating metrics, risk queue, scan activity, coverage, and next-action routing.
  - Settings now loads live workspace identity, member access counts, current account role/scopes, authentication mode, providers, and links to the routes that manage each setting area.
- Enabled Identrail Cloud self-serve onboarding deployment wiring:
  - production AWS API deploys now set `IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true` by default alongside new auth, with `API_FEATURE_ONBOARDING_WIZARD=false` available as the explicit rollback knob
  - Vercel production deploys upsert `VITE_FEATURE_ONBOARDING_WIZARD` before building the web app, defaulting to `true` and honoring a repository variable override for rollback
  - release and public web image builds now carry the onboarding and GitHub connector build flags from the versioned web release environment
- Added WorkOS MFA continuation for hosted sign-in: when GitHub OAuth requires MFA enrollment or an existing MFA challenge, Identrail now redirects to an app MFA page, keeps the WorkOS pending-auth token in an encrypted HttpOnly cookie, and completes session creation after TOTP verification.
- Fixed hosted GitHub sign-in by requesting GitHub's verified-email OAuth scope through WorkOS, so GitHub users with private primary emails can complete the callback instead of failing during login.
- Added the org-admin API for managing native SAML identity connections (behind `IDENTRAIL_FEATURE_NATIVE_SSO`, defaulted off):
  - `POST/GET/PUT/DELETE /v1/enterprise/identity-connections/saml(/:id)` covers the full connection lifecycle and is gated by org-admin RBAC via the existing route policy bundle
  - `POST /v1/enterprise/identity-connections/saml/from-metadata` accepts either a `metadata_url` (https only, 256 KiB cap, 10s timeout) or an inline `metadata_xml` body and auto-fills `entity_id`, `sso_url`, and `certificate_pem` from Okta- or Azure AD-shaped IdP metadata
  - On create, the API issues a per-connection SCIM bearer token, returns the plaintext value once in the response, and stores only its SHA-256 hash on `identity_connections.scim_bearer_token_hash`
  - Connection list, get, update, and delete operate solely on native SAML rows; pre-existing WorkOS-managed rows are filtered out and remain visible only through the existing WorkOS path
  - The WorkOS sign-in / sign-up flow is unchanged; both flows continue to share session storage and converge on `auth.session` with the appropriate `AuthMethod`
- Added schema scaffolding for native SAML SSO and SCIM 2.0 provisioning alongside the existing WorkOS-managed path (migration `000024_native_sso_scim_scaffold`):
  - `identity_connections` gains nullable `entity_id`, `sso_url`, `certificate_pem`, `attribute_mapping` (JSONB), `jit_provisioning_enabled`, and `scim_bearer_token_hash` columns; a SAML completeness CHECK constraint requires each `provider='saml'` row to be either WorkOS-backed or fully native (https sso_url + entity_id + certificate_pem)
  - SCIM-assigned external ids are stored in the existing `user_identities` table with `provider = 'scim:<connection_uuid>'`, reusing its `UNIQUE (provider, subject)` contract so a per-connection identifier cannot collide with a different tenant's
  - New append-only `scim_provisioning_events` table captures every SCIM op for tenant-visible audit; standard RLS tenant-isolation policy applied, with a composite `(org_id, connection_id)` foreign key to `identity_connections` so events cannot reference a connection in a different tenant
  - `IdentityConnection` Go struct and memory + Postgres CRUD updated; `SCIMProvisioningEventRecord` + `CreateSCIMProvisioningEvent`/`ListSCIMProvisioningEvents` added behind the existing `Store` interface
  - No HTTP routes, no SAML protocol code, and no SCIM endpoints in this change; the WorkOS sign-in/sign-up path is untouched
- Added the foundational enterprise-tier domain models in `internal/enterprise`:
  - `SCIMUser` + `SCIMProvisioningEvent` modelling the core SCIM 2.0 user schema and lifecycle operations (create/update/deactivate/delete) for directory-sync sources
  - `SAMLConnection` with PEM X.509 certificate parsing, https-only SSO URL enforcement, attribute mapping, and `pending → active → disabled` status transitions
  - `ResidencyPolicy` with a curated region allowlist, advisory/strict enforcement modes, case-insensitive evaluation, and deterministic region ordering for governance hashing
  - `BuildExecutiveReport` aggregator producing open findings by severity/type, top-N callouts, and a week-over-week trend rollup; expired suppressions are normalized back to open before rollup so leadership metrics do not under-count lapsed work
- Added a feature-gated authenticated onboarding wizard:
  - persists server-owned setup progress for organization, workspace, connector, first scan, invite, and dashboard-tour steps
  - adds `/v1/onboarding/*` APIs with OpenAPI/authz metadata and memory/Postgres storage
  - wires the web app to resume onboarding safely and hides the wizard unless both backend and frontend flags are enabled
- Added the standard Kubernetes connector foundation:
  - `/v1/connectors/k8s`, `/v1/connectors/k8s/enroll`, `/v1/connectors/k8s/heartbeat`, and `/v1/connectors/k8s/kubeconfig`
  - single-use 24-hour agent enrollment tokens, hashed agent credentials, stale heartbeat degradation, and encrypted kubeconfig fallback storage
  - a read-only Helm chart and agent binary scaffold with no secrets, pods/exec, or mutating RBAC verbs
- Added the standard GitHub connector foundation:
  - GitHub App install URL generation, App JWT signing, installation token caching, HMAC-verified webhooks, and repository pagination helpers
  - `/v1/connectors/github`, `/v1/connectors/github/pat`, `/v1/connectors/github/{connector_id}/repos`, and `/auth/webhooks/github`
  - encrypted PAT storage for GitHub Enterprise fallback connectors and updated product UI to use the standard connector path
- Added an Identrail Cloud API URL fallback for production web deploys:
  - canonical hosted web domains now use `https://api.identrail.com` when no build-time API URL is injected
  - Vercel production deploys default and upsert the same API URL when the GitHub Actions variable is absent
  - refreshed frontend/auth deployment docs so the `api.identrail.com` split is documented consistently
- Added expiring suppression baselines for findings:
  - findings now expose deterministic `confidence_score` values to help analysts judge likely false positives
  - finding suppressions now require a future `suppression_expires_at` when a finding is moved into `suppressed`
  - new `/v1/findings/baseline/export` and `/v1/findings/baseline/import` endpoints let teams carry forward known false positives without auto-suppressing changed future variants
- Added a plan-first AWS API hosting layer:
  - defines ECS/Fargate API service, HTTPS load balancer, task roles, security groups, health checks, and CPU autoscaling primitives
  - keeps API hosting resource creation disabled by default for cost-safe CI validation
  - adds a guarded manual GitHub Actions deploy workflow for API cutover planning and explicitly confirmed applies
  - adds an explicit low-cost public-task bootstrap mode for the first `api.identrail.com` cutover, avoiding NAT Gateway or VPC endpoint hourly charges while keeping inbound traffic behind the ALB security group
  - configures hosted API CORS origins and trusted ALB proxy CIDRs so the split web/API domains preserve browser access and real client IPs
  - validates distinct public/private subnet inputs, public subnet Availability Zone spread, subnet VPC membership, and public-subnet Internet Gateway routes, including inherited main route tables, before planning the load balancer and Fargate service
  - requires operator confirmation that private API task subnets have NAT or VPC endpoint egress before planning Fargate tasks with `assign_public_ip=false`
  - validates the ACM certificate ARN partition against the active AWS provider partition
  - grants ECS secret injection IAM permissions on base Secrets Manager ARNs when `api_secrets` use JSON-key or version selectors
  - keeps long-running ECS API tasks non-migrating so schema changes stay in a dedicated migration step
  - adds a guarded AWS API database migration workflow and dedicated one-shot runner so hosted auth schema changes can be applied deliberately from `dev`
  - rejects pathful CORS URLs so hosted API browser access uses exact bare origins
  - documents operator inputs, Secrets Manager references, DNS cutover, and rollback expectations for `api.identrail.com`
- Added clickable GitHub line links for repository findings:
  - repo findings now expose stable `repository` and `source_url` fields in API payloads
  - the authenticated findings route now lists repository findings and opens a detail view with direct GitHub blob links
  - snapshot-based repo misconfiguration findings now record the resolved HEAD commit SHA on new scans so line links stay pinned to the scanned revision
- Enriched repo findings with stable remediation metadata:
  - exposed `commit`, `file_path`, `line_number`, `detector`, `line_snippet`, and `line_snippet_redacted` in scanner and API finding payloads
  - normalized persisted repo finding evidence so existing rows read back without a storage migration
  - documented the repo-finding contract for API clients and operator workflows
- Hardened GitHub webhook-triggered scan orchestration with dedupe and storm controls:
  - replayed webhook deliveries are now treated idempotently and skipped before queueing duplicate repo scans
  - rapid repeated webhook triggers for the same project/repository now honor a burst window to suppress scan storms
  - persisted webhook status metadata now records last queued scan repository/timestamp for stable throttling behavior
- Added public Docker image publishing and no-build evaluation docs:
  - publishes `ghcr.io/identrail/identrail` as the primary pullable server image
  - keeps worker, web, and API alias images for multi-service deployments
  - adds a public-image Docker Compose stack for local evaluation without cloning or building from source
- Added enterprise auth foundation scaffolding for the new auth rollout:
  - introduced `invitations`, `verified_domains`, and `identity_connections` persistence with tenant RLS policies
  - added memory and Postgres store methods for invitation, domain, and identity connection scaffolds
  - registered 501 route stubs and OpenAPI/authz metadata for invitation, domain verification, and SSO endpoints
- Added the backend identity foundation for the new auth rollout:
  - introduced durable `users`, `user_identities`, and `sessions` persistence with the `tenancy_workspace_members.user_uuid` bridge column
  - added signed session-cookie middleware, `/auth/logout`, `/v1/me`, and current-user session management endpoints
  - documented the session endpoints in OpenAPI and wired feature-flagged startup validation for session-auth configuration
- Added the auth and connector architecture foundation under `docs/auth/`:
  - decided on WorkOS for hosted login plus a dual-driver OIDC path for self-host
  - documented the identity model, cookie and session spec, threat model, identity-linking rules, connector-foundation contract, environment-variables reference, and the original auth delivery roadmap
  - linked the new doc folder from the main documentation index
- Refined the public website homepage presentation:
  - adopted a Browserbase-style navigation rail with centered links and a black demo CTA
  - updated the homepage product preview around Kubernetes, AWS IAM, and PostgreSQL evidence
  - replaced static technology labels with a moving logo strip for reviewed stack coverage
- Polished the public website header navigation and brand treatment:
  - renamed the primary navigation to Product, Docs, Company, Pricing, and Blog
  - removed dropdown chevrons from plain navigation links
  - tightened the IDENTRAIL wordmark and applied Geist typography to the header controls
- Added a project connect-source wizard in the authenticated web app:
  - guided GitHub, AWS, and Kubernetes source onboarding from the project detail route
  - wired live connection status, validation, retry, and remediation feedback to existing project-scoped connector APIs
  - added UI and API-client regression coverage for first-source onboarding
- Added project-scoped scan policy management across API, persistence, and UI:
  - introduced scan-policy CRUD endpoints under project tenancy routes with trigger-mode and enabled filters
  - persisted policy bounds for `history_limit` and `max_findings` with migration and scoped store adapters
  - added a periodic scan-policy scheduler with atomic tick claiming, missed-run recovery, and concurrent-worker duplicate protection
  - embedded a scan policy editor in the project detail page and documented new contracts in `docs/openapi-v1.yaml`
  - rejects negative `max_concurrent_scans` API values instead of silently defaulting them to one
- Hardened connector secret storage and rotation:
  - encrypted GitHub webhook secrets with versioned AES-256-GCM envelopes instead of retaining plaintext service state
  - added a webhook-secret rotation endpoint with audit events and status metadata for key version, algorithm, and rotation due date
  - documented `IDENTRAIL_CONNECTOR_SECRET_KEYS` and added database envelope schema for durable connector secret storage
- Added project-scoped Kubernetes onboarding preflight:
  - new project connection API to validate kubectl context, cluster identity, and scanner-critical RBAC read access
  - runtime wiring for live kubectl preflight checks before marking Kubernetes connectors active or degraded
  - documented connection status, permission diagnostics, and remediation fields in `docs/openapi-v1.yaml`
- Added project-scoped AWS connector onboarding:
  - new API contract to validate and save one read-only AWS role connection per project
  - validates `sts:AssumeRole`, ingests caller/account metadata, and checks IAM role listing access before marking a connector active
  - returns degraded connector state with remediation diagnostics for trust-policy and IAM-permission failures
- Added project-scoped GitHub onboarding and webhook trigger flow:
  - new tenancy APIs to start/complete GitHub connect state, fetch connection status, and manage selected repositories
  - enforced webhook signature validation (`X-Hub-Signature-256`) before accepting repository trigger events
  - mapped verified GitHub webhook events to selected project repositories and queued scoped repo scans automatically
  - documented new connection and webhook contracts in `docs/openapi-v1.yaml`
- Added tenancy persistence migrations for connector and automation policy state:
  - new scoped tables for `tenancy_connectors`, `tenancy_connector_states`, and `tenancy_scan_policies`
  - enforced foreign-key integrity from connectors/policies to tenancy projects and connector-state to connector rows
  - added connector secret metadata reference fields (`secret_provider`, `secret_ref_id`, `secret_ref_version`) without storing raw secrets
  - added scope-aware indexes for connector health/sync state and policy trigger scheduling queries
- Standardized product-entry marketing CTAs to the auth-first app flow:
  - switched canonical marketing app-entry destination to `/app`
  - added explicit `signIn` route mapping to `/app/login` in `siteLinks`
  - updated marketing CTA labels to `Open App` for product-access intent
  - added regression tests for CTA routing and route-guard `next` redirect behavior
- Improved first-run onboarding flow:
  - added `make quickstart` with `scripts/quickstart.sh` to bootstrap local Docker, trigger a first scan, and guide findings retrieval
  - updated README quickstart to include first scan + findings flow (not only `/healthz`)
  - removed `IDENTRAIL_POSTGRES_PASSWORD_URLENCODED` requirement from Docker Compose local path and related docs
- Improved Docker Compose out-of-box web/API connectivity:
  - added `IDENTRAIL_CORS_ALLOWED_ORIGINS=http://localhost:8081` to `deploy/docker/.env.example`
  - documented local CORS default in Docker and deployment guides
- Hardened repository scan API defaults and target restrictions:
  - local filesystem repository paths are now rejected in API/worker repo-scan flow
  - empty repo scan allowlist now denies all targets (explicit allowlist required)
  - startup validation now requires `IDENTRAIL_REPO_SCAN_ALLOWLIST` when `IDENTRAIL_REPO_SCAN_ENABLED=true`
  - default repo scan runtime is now disabled unless explicitly enabled
- Hardened write authorization defaults to remove implicit write access in legacy API-key mode:
  - write endpoints now reject API-key-authenticated requests when `IDENTRAIL_WRITE_API_KEYS` is not configured
  - startup security validation now requires explicit `IDENTRAIL_WRITE_API_KEYS` when using `IDENTRAIL_API_KEYS` without scoped keys
  - added router and security regression tests for empty-write-key misconfiguration paths
- Hardened AWS deterministic ID hashing for findings and relationships:
  - replaced truncated SHA-1 IDs with SHA-256-derived 128-bit ID prefixes
  - reduced collision risk in large multi-account datasets
  - added deterministic ID regression tests for hash format and stability
- Refreshed vulnerability-sensitive Go runtime/dependency baseline:
  - raised project Go version baseline to `1.25.9`
  - upgraded `github.com/quic-go/quic-go` to `v0.57.0` and `qpack` to `v0.6.0`
  - validated compatibility with full test and vet suites
- Hardened repository exposure scanner clone target validation:
  - reject insecure `http://` repository clone URLs
  - allow `https://`, `ssh://`, and `git@` forms
  - added regression tests to ensure insecure targets are blocked before clone execution
- Hardened API rate limiter memory behavior:
  - bounded per-IP limiter cache with deterministic max-cap eviction
  - stale IP limiter entries now expire automatically
  - added regression tests for stale-entry and oldest-entry eviction paths
- Hardened API client IP handling against spoofed `X-Forwarded-For` by default:
  - added trusted proxy configuration (`IDENTRAIL_TRUSTED_PROXIES`)
  - default behavior now trusts no proxy hops unless explicitly configured
  - added validation/tests for trusted proxy IP/CIDR entries
- Fixed Helm chart default to avoid startup failure on nonroot containers:
  - `IDENTRAIL_AUDIT_LOG_FILE` now defaults to empty (opt-in)
  - Helm docs now require writable mount path when enabling file audit sink
- Fixed backward-compatibility read path for legacy findings rows where `remediation` is `NULL`:
  - `ListFindings`, `ListFindingsByScan`, and `ListRepoFindings` now coalesce nullable remediation values
  - added regression test to prevent null-remediation scan failures in CI/integration
- Locked V1 finalization priorities 21-22:
  - snapshot-based backward compatibility tests for core API payloads and finding exports
  - migration compatibility integration check for legacy persisted rows
  - release qualification runner and V1 RC/GA tagging playbook
- Added release-readiness artifacts:
  - `internal/api/contract_snapshot_test.go`
  - `internal/findings/standards/compatibility_snapshot_test.go`
  - `internal/integration/migration_compatibility_integration_test.go`
  - `internal/api/slo_smoke_test.go`
  - `scripts/v1_release_qualify.sh`
  - `docs/v1_release_qualification.md`
- Fixed deploy portability smoke stability:
  - removed forced API audit-file path from Docker Compose default runtime
  - removed default audit volume mount that could fail for non-root container writes
  - CI compose smoke now prints API/Postgres logs when health checks fail
- Locked V1 finalization priorities 16-20:
  - security hardening (constant-time API key checks, key-strength warning, least-privilege policy templates)
  - observability baseline (scan outcome metrics + repo scan metrics + scanner tracing spans)
  - deployment-anywhere baseline extended with Helm chart and Terraform Helm module
  - operator readiness docs (install/handoff guide, troubleshooting, incident workflow)
  - governance updates across ADR, threat model, and V1 baseline docs
- Added infrastructure CI gate:
  - Helm chart lint (`helm lint deploy/helm/identrail`)
  - Terraform format + validation checks for `deploy/terraform`
- Added deployment artifacts:
  - Helm chart: `deploy/helm/identrail`
  - Terraform baseline + module: `deploy/terraform` and `deploy/terraform/modules/identrail-helm`
  - read-only collector policy templates: `deploy/policies/aws/*`, `deploy/policies/kubernetes/*`
- Added operator/security/observability docs:
  - `docs/security-hardening.md`
  - `docs/observability.md`
  - `docs/operator-readiness.md`
  - `docs/troubleshooting.md`
  - `docs/incident-response.md`
- Locked V1 finalization priorities 11-15:
  - API hardening with consistent `sort_by`/`sort_order` list contract
  - published OpenAPI v1 contract (`docs/openapi-v1.yaml`) with contract presence tests
  - CLI hardening with deterministic severity-prioritized table output
  - persistence hardening with explicit down-migration support and rollback roundtrip integration tests
  - CI release gates extended with CLI smoke and dockerized API compose smoke
- Added API list sort support across core list endpoints:
  - findings, scans, scan events, identities, relationships, ownership signals, repo scans, repo findings
  - additive query params preserve backward compatibility
- Added migration operations enhancements:
  - `ApplyDownMigrations` API in store/db migration package
  - integration test for migration roundtrip safety (`up -> down -> up`)
- Added frontend contract hardening:
  - API client now surfaces backend error envelope messages
  - dashboard tests now cover empty and error states
- Locked V1 finalization priorities 6-10:
  - collector reliability hardening with diagnostics and transient kubectl retry/backoff/jitter handling
  - scheduler bounded retry + dead-letter callback support
  - explicit scan lifecycle transitions including `partial`
  - normalized schema contract validation for identities/workloads/policies
  - graph contract validation for endpoint semantics, uniqueness, and discovery timestamp
- Added fixture contract regression coverage:
  - normalized bundle contract tests for AWS and Kubernetes fixture pipelines
  - graph snapshot regression tests for AWS and Kubernetes relationship edges
- Added service-level partial-run event handling:
  - non-fatal source errors are stored as warning scan events
  - lifecycle states now include `queued`, `running`, `partial`, `succeeded`, `failed`
- Locked first five V1 finalization priorities:
  - scope freeze guardrails for `aws|kubernetes` runtime providers
  - standards baseline with OIDC/OAuth2-compatible auth and findings export mappings
  - reliability hardening with AWS retry jitter
  - data contract hardening with explicit supported relationship semantics
  - deterministic risk evidence ordering for stable reruns/diffs
- Added OIDC/OAuth2-compatible API auth path:
  - `IDENTRAIL_OIDC_ISSUER_URL`, `IDENTRAIL_OIDC_AUDIENCE`, `IDENTRAIL_OIDC_WRITE_SCOPES`
  - OIDC-only auth mode now enforced when API keys are absent
  - write endpoints now honor OIDC write scopes
- Added finding standards module wiring:
  - enrich findings with compliance control references and schema metadata
  - new endpoint: `GET /v1/findings/:finding_id/exports` (OCSF + ASFF payloads)
  - exports are available for persisted cloud and repo findings
- Added fixture-based graph contract tests for AWS and Kubernetes pipelines.
- Added distributed lock backend support:
  - `IDENTRAIL_LOCK_BACKEND=auto|postgres|inmemory`
  - `IDENTRAIL_LOCK_NAMESPACE` for lock isolation across environments
  - PostgreSQL advisory lock implementation for scan and repo-scan concurrency control
  - runtime auto-selection defaults to postgres backend in database mode
- Added cursor pagination for list endpoints:
  - supports `cursor` request parameter and `next_cursor` response field
  - applied to findings, scans, identities, relationships, scan events, repo scans, and repo findings APIs
- Added ownership-signal API:
  - `GET /v1/ownership/signals`
  - infers ownership from `owner_hint` and identity tags with confidence scoring
- Added performance index migration:
  - new migration `000004_performance_indexes`
  - adds composite indexes for findings, repo findings, and scan events read patterns
- Expanded sqlc query contract/wrapper coverage for repository read paths (`GetRepoScan`, `ListRepoScans`, `ListRepoFindings`).
- Added optional worker-scheduled repository scans:
  - new worker config controls:
    - `IDENTRAIL_WORKER_REPO_SCAN_ENABLED`
    - `IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW`
    - `IDENTRAIL_WORKER_REPO_SCAN_INTERVAL`
    - `IDENTRAIL_WORKER_REPO_SCAN_TARGETS`
    - `IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT`
    - `IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS`
  - startup validation enforces target presence and allowlist compatibility
  - per-target locking added to service (`repo-scan:<target>`) to prevent API/worker overlap
  - API now returns `409` for in-flight repo target scans
- Added dedicated repository scan persistence layer:
  - new migrations: `repo_scans` and `repo_findings` tables
  - store adapters updated for memory and postgres modes
  - new read APIs:
    - `GET /v1/repo-scans`
    - `GET /v1/repo-scans/:repo_scan_id`
    - `GET /v1/repo-findings`
  - `POST /v1/repo-scans` now persists scan lifecycle + findings
  - backward compatibility maintained for existing `/v1/scans` and `/v1/findings` workflows
- Added repository exposure API trigger and runtime guardrails:
  - new endpoint: `POST /v1/repo-scans` (write-protected)
  - configurable defaults/bounds:
    - `IDENTRAIL_REPO_SCAN_ENABLED`
    - `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT`
    - `IDENTRAIL_REPO_SCAN_MAX_FINDINGS`
    - `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX`
    - `IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX`
  - optional repository target allowlist:
    - `IDENTRAIL_REPO_SCAN_ALLOWLIST` (supports prefix wildcard `*`)
  - runtime validation and warnings for repo scan configuration
- Added repository exposure scanner (`identrail repo-scan`) for public/local git repositories:
  - scans commit history for added secret material (read-only git operations)
  - scans HEAD IaC/CI/runtime files for high-signal misconfigurations
  - redacts secret values and stores only fingerprints/snippets in findings evidence
  - supports repository target as `owner/repo`, URL, or local git path
  - includes history and finding caps (`--history-limit`, `--max-findings`)
- Strengthened Kubernetes RBAC normalization semantics:
  - collector now ingests `roles` and `clusterroles` in kubectl mode
  - fixture mode now supports `Role`/`ClusterRole` assets with stable source IDs
  - normalizer now resolves binding permissions from real RBAC `rules` first
  - role-name heuristic mapping remains as fallback only when role assets are missing
  - added cluster-role fixture and updated default k8s fixture set
- Added AWS live collection mode via AWS SDK:
  - new adapter: `internal/providers/aws/sdk_client.go`
  - source selection: `IDENTRAIL_AWS_SOURCE=fixture|sdk`
  - new config vars: `IDENTRAIL_AWS_REGION`, `IDENTRAIL_AWS_PROFILE`
  - runtime + CLI wiring for fixture/sdk source modes
  - startup validation for allowed AWS source values
- Added Kubernetes live collection mode via kubectl:
  - new collector: `internal/providers/kubernetes/kubectl_collector.go`
  - read-only `kubectl get` ingestion for service accounts, role bindings, cluster role bindings, and pods
  - runtime + CLI source selection via `IDENTRAIL_K8S_SOURCE=fixture|kubectl`
  - new config vars: `IDENTRAIL_KUBECTL_PATH`, `IDENTRAIL_KUBE_CONTEXT`
  - startup validation for allowed Kubernetes source modes
- Added portable deployment assets:
  - multi-stage backend image (`deploy/docker/Dockerfile.backend`) for API/worker
  - web image (`deploy/docker/Dockerfile.web`) with hardened nginx static serving
  - Docker Compose stack (`deploy/docker/docker-compose.yml`) for API/worker/Postgres/web
  - Kubernetes manifests (`deploy/kubernetes/*`) for namespace/config/secret/deployments/service/ingress
  - systemd templates (`deploy/systemd/*`) for VM-based deployments
  - deployment guide (`docs/deployment-anywhere.md`)
- Added Kubernetes phase-4 foundation:
  - fixture collector for service accounts, role bindings, and pods
  - normalizer, permission resolver, graph resolver, and deterministic risk rules
  - findings for overprivileged, escalation-path, and ownerless service accounts
- Added provider-aware runtime/CLI wiring:
  - runtime scanner builder now supports `aws` and `kubernetes`
  - CLI `scan` command now supports Kubernetes provider execution
  - config support for `IDENTRAIL_K8S_FIXTURES`
- Standardized API domain payload fields to explicit `snake_case` JSON tags.
- Added optional scan diff baseline selection:
  - API: `GET /v1/scans/:scan_id/diff?previous_scan_id=...`
  - service-level validation rejects invalid baselines (same scan/newer scan/different provider)
  - UI baseline selector added in dashboard controls
- Expanded web dashboard with:
  - findings table + severity/type filters
  - scan selector + scan diff panel
  - identities/relationships/events explorer snapshot
- Added frontend test stack (Vitest + Testing Library + jsdom) with CI execution.
- Added production CI workflow (`.github/workflows/ci.yml`) with:
  - Go format and vet gates
  - Go test + coverage threshold (>= 80%)
  - Postgres-backed integration test gate
  - Frontend dependency install and build gate
- Added deterministic web lockfile (`web/package-lock.json`) for reproducible CI installs.
- Added findings trends endpoint (`GET /v1/findings/trends`).
- Added explorer endpoints (`GET /v1/identities`, `GET /v1/relationships`).
- Added finding detail endpoint (`GET /v1/findings/:finding_id`).
- Added findings list server-side filters (`scan_id`, `severity`, `type`).
- Added findings trend filters (`severity`, `type`).
- Added scan event level filter (`GET /v1/scans/:scan_id/events?level=`).
- Added optional audit forwarding sink (`IDENTRAIL_AUDIT_FORWARD_URL`) with URL safety checks.
- Added audit forwarding retry/backoff controls (`IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES`, `IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF`).
- Added typed scan event level validation (`debug|info|warn|error`).
- Added sqlc query contract scaffolding (`sqlc/sqlc.yaml`, `sqlc/queries/*`).
- Started Postgres read-path migration to typed query wrappers aligned with sqlc contracts.
- Added integration test lane for Postgres-backed scan/diff flow (`go test -tags=integration ./internal/integration`).
- Added Phase 3 web scaffold (`web/` React + TypeScript + Vite).
- Added scan events persistence and API endpoint (`GET /v1/scans/:scan_id/events`).
- Added scan diff endpoint (`GET /v1/scans/:scan_id/diff`).
- Added findings summary endpoint (`GET /v1/findings/summary`).
- Added webhook retry/backoff controls for transient alert delivery failures.
- Added deployment runbook (`docs/deploy-runbook.md`).
- Replaced raw API key values in audit events with deterministic `api_key_id` fingerprints.
- Added startup validation for scoped-key scope names.
- Added startup validation cap for `IDENTRAIL_ALERT_MAX_FINDINGS`.
- Added scoped read authorization enforcement on `/v1/*` when using scoped API keys.
- Added startup security validation for legacy write key configuration.
- Added startup security warning emission for risky but allowed config states.
- Added high-severity findings webhook alerts with configurable threshold and cap.
- Added optional HMAC signing for alert webhook requests.
- Added webhook safety guardrails (`https` required for remote endpoints).
- Added scoped API key authorization config (`IDENTRAIL_API_KEY_SCOPES`) with legacy fallback behavior.
- Added optional audit file export sink (`IDENTRAIL_AUDIT_LOG_FILE`) for durable API request audit events.
- Added write authorization keys for scan trigger endpoint (`IDENTRAIL_WRITE_API_KEYS`).
- Added API audit logging middleware for `/v1/*` requests.
- Added API key authentication middleware for `/v1/*` endpoints.
- Added per-IP rate limiter middleware.
- Added startup migration runner for Postgres mode.
- Added worker process for scheduled scans (`cmd/worker`).
- Added shared runtime service bootstrap (`internal/runtime`).
- Added worker scheduling config (`IDENTRAIL_SCAN_INTERVAL`, `IDENTRAIL_WORKER_RUN_NOW`).

## 2026-03-16
- Phase 1 foundation completed.
- AWS collector, normalizer, graph, risk engine, and CLI workflow completed.
- Project renamed to `identrail`.
- Phase 2 started: migrations, store layer, persistence-backed API.
- Scheduler lock and single-flight scan trigger support added.
- Full artifact persistence (raw + normalized + findings) added.
- ADR, threat model, and baseline security hardening added.
