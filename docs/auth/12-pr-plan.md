# Twelve-PR Auth and Connector Plan

The full sequence for shipping signup, sign-in, SSO, SCIM, and the AWS, Kubernetes, and GitHub connectors. Each section is the canonical scope for that PR. When opening one of these PRs, copy the matching section into the PR description as a checklist.

Total estimate: roughly 23 engineering days end to end. The critical path to a demo-able SaaS (signup to first AWS finding) is roughly 10 days: PRs 1, 2, 4, 5, 6, 7, 10.

## Sequencing

```
PR 1 (architecture)
   │
   ▼
PR 2 (identity core)
   │
   ├──▶ PR 3 (identity enterprise) ──┐
   │                                 │
   ▼                                 │
PR 4 (WorkOS hosted login)           │
   │                                 │
   ▼                                 │
PR 5 (frontend auth)                 │
   │                                 │
   ├──▶ PR 6 (connector foundation) ──▶ PR 7, 8, 9 (AWS, GitHub, K8s)
   │                                          │
   │                                          ▼
   │                                   PR 10 (onboarding wizard)
   │                                          │
   └──▶ PR 11 (SSO admin) ◄───────────────────┘
                │
                ▼
         PR 12 (SCIM + hardening)
```

## Index

| # | PR | Branch | Effort | Depends on |
| --- | --- | --- | --- | --- |
| 1 | Architecture doc | `docs/auth-architecture-foundation` | 2h | none |
| 2 | Backend identity core | `auth/02-identity-foundation-core` | 1d | 1 |
| 3 | Backend identity enterprise prep | `auth/03-identity-foundation-enterprise` | 1d | 2 |
| 4 | WorkOS hosted login | `auth/04-workos-hosted-login` | 2d | 2 |
| 5 | Frontend auth UI | `auth/05-frontend-auth-ui` | 2d | 4 |
| 6 | Connector foundation | `auth/06-connector-foundation` | 1d | 5 |
| 7 | AWS connector | `auth/07-connector-aws` | 2d | 6 |
| 8 | GitHub connector | `auth/08-connector-github` | 1.5d | 6 |
| 9 | Kubernetes connector | `auth/09-connector-kubernetes` | 3d | 6 |
| 10 | Onboarding wizard | `auth/10-onboarding-wizard` | 2d | 5 + at least one of 7, 8, 9 |
| 11 | Enterprise SSO admin | `auth/11-sso-admin` | 3d | 3, 4, 5 |
| 12 | SCIM and hardening | `auth/12-scim-and-hardening` | 4d | 11 |

---

## PR 1: Architecture Doc

**Goal.** Lock every contract in writing before any code so the next eleven PRs do not conflict.

**Files (all new).**
- `docs/auth/architecture.md`
- `docs/auth/threat-model.md`
- `docs/auth/cookie-and-session-spec.md`
- `docs/auth/identity-linking-rules.md`
- `docs/auth/connector-foundation.md`
- `docs/auth/env-vars-reference.md`
- `docs/auth/12-pr-plan.md` (this file)
- `docs/auth/README.md`

**Acceptance.**
- Every later PR can be planned by reading these docs alone.
- Threat model includes the identity-linking exploit narrative explicitly.
- Every endpoint we plan to add has its shape documented.
- Every env var has a default and a validation rule.

**Out of scope.** Code, schema changes, frontend changes.

**Rollback.** Not applicable.

---

## PR 2: Backend Identity Foundation, Core

**Goal.** `users`, `user_identities`, `sessions` plus the session middleware and `GET /v1/me` and `POST /auth/logout`. Begin the strangler-fig migration on `tenancy_workspace_members.user_id`.

**Schema (migration `000017_users_and_sessions`).**
- `users(id UUID PK, primary_email CITEXT UNIQUE, display_name, avatar_url, status, created_at, updated_at, deleted_at NULL)`.
- `user_identities(id UUID PK, user_id FK, provider TEXT, subject TEXT, email CITEXT, email_verified BOOLEAN NOT NULL DEFAULT FALSE, raw_claims JSONB, last_authenticated_at, created_at, UNIQUE(provider, subject))`.
- `sessions(id BYTEA PK, user_id FK ON DELETE CASCADE, current_org_id, current_workspace_id, current_project_id, auth_method, ip INET, user_agent, idle_expires_at, absolute_expires_at, last_seen_at, revoked_at NULL, created_at)`. `last_seen_at` is bumped to `NOW()` on every authenticated request alongside `idle_expires_at`; powers the "last seen" display on the account/security page.
- `tenancy_workspace_members.user_uuid UUID NULL` added next to existing `user_id`.
- Indexes per the cookie/session spec.

**Files (new or modified).**
- `internal/db/users.go`, `sessions.go`, `user_identities.go` (new).
- `internal/db/store.go`, `memory.go`, `postgres.go` (extend interface and implementations).
- `internal/api/auth/session.go`, `middleware.go` (new).
- `internal/api/router.go` (register `/v1/me`, `/auth/logout`).
- `internal/config/config.go` (add `IDENTRAIL_PUBLIC_BASE_URL`, `IDENTRAIL_SESSION_KEY`, `IDENTRAIL_AUTH_MANUAL_MODE`).
- `migrations/000017_users_and_sessions.up.sql` and `.down.sql`.
- Tests across all of the above.

**New endpoints.**
- `GET /v1/me` returns the current user, org, workspace, project, and role.
- `GET /v1/me/sessions` lists active sessions for the current user (id, ip, user_agent, created_at, last_seen_at, idle_expires_at, current flag).
- `DELETE /v1/me/sessions/:id` revokes one session by id (the current session can be revoked here; the response then clears the cookie too, equivalent to logout).
- `POST /v1/me/sessions/revoke-others` revokes every session for the current user except the one making the call.
- `POST /auth/logout` revokes the current session and clears the cookie.

**Out of scope.** Login routes (PR 4). Frontend (PR 5). WorkOS (PR 4).

**Tests.** Cookie tampering rejected. Expired or revoked session rejected within one request. FK cascade on user delete. Two browsers see independent rows. `IDENTRAIL_AUTH_MANUAL_MODE=true` plus `IDENTRAIL_WORKOS_CLIENT_ID` set refuses to start. `IDENTRAIL_PUBLIC_BASE_URL` missing or invalid refuses to start. Session-list endpoint scopes results to the calling user only. Revoking another user's session id returns 404 (no leakage of session existence). Revoking the current session via `DELETE /v1/me/sessions/:id` clears the cookie and behaves like logout. `revoke-others` keeps the calling session alive and revokes every other row for the same user.

**Acceptance.** Existing OIDC and API key paths unchanged (regression tests pass). PR 4 can build on these primitives without modification. PR 5's `AccountSecurityPage` has the backend endpoints it needs to list and revoke sessions.

**Rollback.** Feature flag `IDENTRAIL_FEATURE_NEW_AUTH=false` disables the new middleware. Old auth paths continue.

---

## PR 3: Backend Identity Foundation, Enterprise Prep

**Goal.** Tables and endpoint stubs for invitations, verified domains, identity connections. No business logic in this PR; just the scaffolding for PRs 6, 11, 12 to fill in.

**Schema (migration `000018_invitations_domains_connections`).**
- `invitations(id UUID PK, org_id, email CITEXT, role, invited_by_user_id, token_hash BYTEA, expires_at, accepted_at NULL, revoked_at NULL, created_at)`.
- `verified_domains(id UUID PK, org_id, domain CITEXT, verification_token, verification_method, verified_at NULL, created_at)`.
- `identity_connections(id UUID PK, org_id, provider, type, workos_connection_id NULL, status, group_role_map JSONB DEFAULT '{}', sso_required BOOLEAN DEFAULT false, created_at, updated_at)`.

`auth_audit_events` is not a separate table. Auth events flow through the existing `audit.AuditEvent` pipeline.

**Files.**
- `internal/db/invitations.go`, `verified_domains.go`, `identity_connections.go` (new).
- `internal/api/auth/audit.go` (helper constructors for `auth.*` events).
- Endpoint stubs in `internal/api/router.go` returning 501.

**Endpoint stubs (return 501 until later PRs fill them in).**
- `POST /v1/invitations`, `GET /v1/me/invitations` (PR 11).
- `POST /v1/orgs/:id/domains`, `POST /v1/orgs/:id/domains/:domain_id/verify` (PR 11).
- `GET /v1/orgs/:id/sso` (PR 11).

**Out of scope.** Implementations. Email sending. WorkOS Directory Sync (PR 12).

**Tests.** Schemas apply cleanly with correct constraints and indexes. Repo methods (Create, Get, List, Revoke). Audit-event helpers produce well-formed events.

**Acceptance.** Tables exist. Endpoints registered (returning 501). PRs 11 and 12 can fill them in without further schema changes.

**Rollback.** Tables harmless if unused. No production impact until later PRs use them.

---

## PR 4: WorkOS Hosted Login

**Goal.** Real login working end to end via WorkOS AuthKit. GitHub OAuth as the primary day-one provider.

**Files.**
- `internal/api/auth/workos.go` (WorkOS client wrapper).
- `internal/api/auth/oauth_state.go` (HMAC-signed single-use state).
- `internal/api/auth/login_handler.go` (`/auth/login`, `/auth/signup`, `/auth/callback`).
- `internal/api/auth/webhook_handler.go` (`/auth/webhooks/workos`).
- `internal/api/router.go` (register routes).
- `internal/config/config.go` (WorkOS env vars).
- `internal/api/service.go` (UpsertUserFromWorkOS, LinkUserIdentity, FindUserByIdentity).
- E2E test against WorkOS test environment.

**New endpoints.**
- `GET /auth/login?return_to=...` (302 to AuthKit).
- `GET /auth/signup?return_to=...` (302 to AuthKit with `screen_hint=sign-up`).
- `GET /auth/callback?code=&state=` (exchange, upsert, set cookie, 302).
- `POST /auth/webhooks/workos` (HMAC-verified, handlers for `user.deleted`, `user.email_changed`).
- `GET /v1/auth/config` (returns whether manual mode is allowed; the frontend uses this to decide if the manual form renders).

**New env vars.** Per `env-vars-reference.md`: `IDENTRAIL_WORKOS_CLIENT_ID`, `IDENTRAIL_WORKOS_API_KEY`, `IDENTRAIL_WORKOS_WEBHOOK_SECRET`, `IDENTRAIL_WORKOS_ENVIRONMENT_ID`.

**First-callback decision tree.**
- Existing user with org membership: 302 to dashboard at last-used org.
- Existing user without org membership: 302 to `/onboarding/org`.
- New user: create rows, 302 to `/onboarding/org`.

**Audit.** All login/logout/signup events flow through existing `AuditEvent{Kind:"action"}` with actions `auth.login.start`, `auth.login.success`, `auth.login.failure`, `auth.logout`, `auth.signup`, `auth.identity.conflict`.

**Rate limits.** Per architecture doc: `/auth/login` 10 per minute per IP, `/auth/callback` 30 per minute per IP, `/auth/logout` 100 per minute per session.

**Identity-linking enforcement.** Per `identity-linking-rules.md`: never auto-link by email. Conflicts return HTTP 409 with explanation.

**Failure modes.** WorkOS unreachable returns 503 with `Retry-After`. WorkOS user.deleted webhook revokes all sessions. Email-change webhook updates `users.primary_email` and audits.

**Out of scope.** Frontend pages (PR 5). Domain auto-join (PR 11). Onboarding bootstrap (PR 10).

**Tests.** E2E against WorkOS test env. State tampering rejected. Replayed state rejected. Webhook signature verification. Identity conflict produces 409, not silent merge. Rate limits enforced.

**Acceptance.** Visiting `https://app.identrail.com/auth/login` redirects to WorkOS AuthKit. After GitHub OAuth, cookie set, user lands at correct destination. New user creates exactly one row in `users` and one in `user_identities`. Existing user signing in again creates zero new rows.

**Rollback.** Feature flag `IDENTRAIL_FEATURE_WORKOS_LOGIN=false` returns auth routes to 404.

---

## PR 5: Frontend Auth UI

**Goal.** Polished sign-in and sign-up plus account/security surface. Marketing site wired up. Manual mode hidden in hosted SaaS, retained behind a flag for self-host and dev.

**Files.**
- `web/src/pages/SignInPage.tsx`, `SignUpPage.tsx`, `AuthCallbackPage.tsx`, `AccountSecurityPage.tsx`, `WhyNoPasswordsPage.tsx` (new).
- `web/src/hooks/useMe.ts` (new).
- `web/src/api/client.ts` (set `credentials: 'include'`, redirect on 401).
- `web/src/productShell.tsx` (delete `inMemoryTokens` and sessionStorage paths; replace with `useMe()`; remove the manual tenant/workspace form).
- `web/src/components/layout/Header.tsx` (Sign In to /signin, Sign Up to /signup).
- `web/src/components/auth/SessionsList.tsx` (new).
- `web/src/components/common/EmptyState.tsx`, `ErrorState.tsx` (new, reusable).
- `web/src/styles/tokens.css` (extended palette, spacing, shadow tokens).
- Routes registered in `App.tsx`: `/signin`, `/signup`, `/auth/callback`, `/why-no-passwords`, `/app/account/security`.

**Pages.**
- `/signin` and `/signup` are the same component, copy variants. Primary "Continue with GitHub" links to `/auth/login` or `/auth/signup`. Secondary "Continue with email" uses the same path with a hint. Footer link to `/why-no-passwords`.
- `/auth/callback` is a branded loading state. Calls `GET /v1/me`, routes based on response.
- `/app/account/security` lists active sessions (IP, UA, location, last seen, "current" badge), revoke per session, revoke all others. The per-user auth-events feed is deferred to PR 12, which adds both the queryable read endpoint and the UI that consumes it; PR 5 leaves a labelled placeholder slot on the page that PR 12 wires up.

**Manual mode visibility.** Frontend reads `GET /v1/auth/config`. If the backend says manual mode is enabled, the manual form renders alongside the OAuth options with a "Dev Mode" banner. Otherwise it does not render.

**Design discipline.** All values from `tokens.css`. Skeleton loaders, not spinners. Reusable empty and error states.

**Out of scope.** Onboarding wizard (PR 10). Org admin pages (PR 11). Connector pages (PRs 6 through 9).

**Tests.** Component tests for the new pages. Playwright E2E covering marketing to /signin to mocked WorkOS to cookie set to `/v1/me`. 401 redirect verified. Cookie persists across reloads. Visual snapshots in light and dark.

**Acceptance.** "Sign In" and "Sign Up" on marketing site go to real working pages. Logged-in user sees their sessions. Manual form does not appear in hosted SaaS. Manual form appears in dev with `IDENTRAIL_AUTH_MANUAL_MODE=true`.

**Rollback.** Feature flag `VITE_FEATURE_NEW_AUTH_UI=false` falls back to old shell.

---

## PR 6: Connector Foundation

**Goal.** Shared types, state machine, error taxonomy, and UI primitives that every connector uses. Ships before the actual connectors so they all conform.

**Files.**
- `internal/connectors/provider.go` (Provider interface).
- `internal/connectors/status.go` (lifecycle status constants and transition validator).
- `internal/connectors/errors.go` (error taxonomy and codes).
- `internal/connectors/health.go` (shared health-check helper).
- `internal/api/router.go` (register `/v1/connectors`, `/v1/connectors/:id`, `/v1/connectors/:id/health`).
- `internal/api/service.go` (ListConnectors, GetConnector, GetConnectorHealth).
- `web/src/components/connector/ConnectorStatusBadge.tsx`, `ConnectorErrorPanel.tsx` (new).
- `web/src/pages/ConnectorsListPage.tsx` (new, route `/app/{tenant}/{workspace}/connectors`).
- `migrations/000019_connector_disabled_flag.up.sql` and `.down.sql` (new). Adds `disabled BOOLEAN NOT NULL DEFAULT FALSE` and `config JSONB NOT NULL DEFAULT '{}'::jsonb` to `tenancy_connectors`. Does not modify the existing `status` CHECK constraint.

**Schema (migration `000019_connector_disabled_flag`).**
- `tenancy_connectors.disabled BOOLEAN NOT NULL DEFAULT FALSE`. Backfills as `false` for existing rows.
- `tenancy_connectors.config JSONB NOT NULL DEFAULT '{}'::jsonb`. Holds provider-specific non-secret configuration (for example GHES base URL or selected repo IDs).

**Contract.** See `connector-foundation.md` for the full Provider interface, the lifecycle status state machine, the `disabled` flag rules, the error taxonomy, and the heartbeat job rules. Lifecycle status values are limited to the four already in the existing schema (`pending`, `active`, `degraded`, `disconnected`); the foundation does not widen that constraint. The transient `validating` step lives in-process only. Connector handlers are project-scoped via session context (`current_project_id`), even though the route prefix remains `/v1/connectors/*`.

**New endpoints.** `GET /v1/connectors`, `GET /v1/connectors/:id`, `GET /v1/connectors/:id/health`, `DELETE /v1/connectors/:id`, `POST /v1/connectors/:id/disable`, `POST /v1/connectors/:id/enable`.

**Heartbeat job.** Existing scheduler. Polls `Health()` every 5 minutes on active and degraded connectors. Drives state transitions per the state machine. Audit event on every transition.

**Out of scope.** Specific providers (PRs 7 through 9).

**Tests.** State machine: every defined transition reachable; undefined transitions rejected. Error code to UI string snapshot. Health endpoint: 404 on non-existent connector. Disconnect calls Provider.Disconnect.

**Acceptance.** ConnectorsListPage renders empty state when no connectors. PRs 7 through 9 import from `internal/connectors` and `web/src/components/connector` without writing duplicate code.

**Rollback.** Backend flag `IDENTRAIL_FEATURE_CONNECTORS_V2=false` returns the new `/v1/connectors*` endpoints to 404. Frontend flag `VITE_FEATURE_CONNECTORS_V2=false` hides the new connectors page. Both default off; turning them on is what activates this PR.

---

## PR 7: AWS Connector

**Goal.** Wiz/Orca-style "Launch CloudFormation Stack" flow with custom least-privilege IAM policy and permission preview.

**Files.**
- `internal/connectors/aws/provider.go` (implement Provider).
- `internal/connectors/aws/cfn.go` (CloudFormation template URL generator).
- `internal/connectors/aws/iam_policy.go` (Go-embedded policy asset).
- `internal/connectors/aws/validator.go` (sts:AssumeRole probe).
- `deploy/connectors/aws/identrail-readonly.yaml` (CFN template, versioned).
- `deploy/connectors/aws/policies/identrail-readonly-policy.json` (strict JSON, no comments).
- `deploy/connectors/aws/policies/identrail-readonly-policy.md` (per-action rationale, kept next to the JSON file).
- `deploy/connectors/aws/policies/audit.go` (CI script that diffs IAM actions called in code against the policy file).
- `web/src/pages/connectors/ConnectAWSPage.tsx`.
- `web/src/components/connector/PermissionPreviewModal.tsx`.

**Flow.**
1. User clicks Connect AWS.
2. Permission preview modal lists every IAM action with a one-line reason.
3. Backend generates 32-byte External ID, creates connector in `pending` state.
4. UI shows "Launch Stack in AWS Console" deep link with template URL and parameters pre-filled.
5. User launches stack. CFN provisions an IAM role with `IdentrailReadOnlyPolicy` and the External ID trust condition.
6. UI polls `/v1/connectors/aws/:id/poll` every 10 seconds (or accepts manual ARN paste fallback).
7. Backend runs `sts:AssumeRole` probe, captures account ID and alias, marks `active`.
8. First scan kicks off automatically.

**New endpoints.** `POST /v1/connectors/aws`, `POST /v1/connectors/aws/:id/validate`, `GET /v1/connectors/aws/:id/poll`, `POST /v1/connectors/aws/:id/refresh-policy`.

**IAM policy rules.** No `ReadOnlyAccess` blanket. Hand-curated minimum: `iam:Get*`, `iam:List*`, `iam:SimulatePrincipalPolicy`, `ec2:Describe*` (scoped), `s3:GetBucketPolicy`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `kms:DescribeKey`, `kms:GetKeyPolicy`. The `.json` file is strict JSON (no comments, since AWS rejects them). Per-action rationale lives in a sibling `identrail-readonly-policy.md` and a `Sid` field per statement names the feature each block supports. `Resource: "*"` is used only where unavoidable, with the rationale captured in the sibling markdown.

**CI policy audit.** Script greps Identrail's AWS SDK calls; diffs against policy. Fails CI when a new SDK call appears without a policy update.

**Secrets.** Role ARN and External ID stored encrypted via existing `tenancy_connector_secret_envelopes`.

**Out of scope.** StackSets multi-account flow. Cross-region scanning UI. CloudTrail Lake.

**Tests.** IAM policy validates against AWS validator. CFN template validates against AWS validator. AssumeRole probe handles success, ExpiredToken, AccessDenied. State transitions correct. Permission preview snapshot. End-to-end with localstack.

**Acceptance.** New user signs up, runs onboarding, connects AWS, sees first scan finding within 5 minutes. IAM policy passes a least-privilege smell test. Permission preview shows every action with a reason.

**Rollback.** Backend flag `IDENTRAIL_FEATURE_CONNECTOR_AWS=false` returns `/v1/connectors/aws*` endpoints to 404. Frontend flag `VITE_FEATURE_CONNECTOR_AWS=false` hides the connect button.

---

## PR 8: GitHub Connector

**Goal.** GitHub App for SaaS GitHub.com. PAT fallback for self-hosted GitHub Enterprise.

**Files.**
- `internal/connectors/github/provider.go` (supersedes legacy `github_connect.go` while keeping it).
- `internal/connectors/github/app.go` (App credential management, JWT signing, installation token minting).
- `internal/connectors/github/pat.go` (PAT path for GHES).
- `internal/connectors/github/webhook.go` (installation lifecycle).
- `deploy/connectors/github/app-manifest.json` (committed for re-creation).
- `web/src/pages/connectors/ConnectGitHubPage.tsx`.

**Flow (App).**
1. User picks "GitHub.com (recommended)". Backend returns App install URL with state.
2. User redirected to GitHub, picks org and repos, installs.
3. Webhook receives `installation.created`. We capture installation ID.
4. List accessible repos, store as scannable targets, first scan begins.

**Flow (PAT).**
1. User picks "GitHub Enterprise / PAT".
2. Inputs PAT and GHES base URL. Backend validates scopes, encrypts, stores.

**App permissions.** Read-only: Contents, Metadata, Pull Requests, Code Scanning Alerts.

**New endpoints.** `POST /v1/connectors/github`, `POST /v1/connectors/github/pat`, `POST /auth/webhooks/github` (HMAC-verified), `GET /v1/connectors/github/:id/repos`.

**New env vars.** `IDENTRAIL_GITHUB_APP_ID`, `IDENTRAIL_GITHUB_APP_PRIVATE_KEY` (PEM), `IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET`, `IDENTRAIL_GITHUB_APP_NAME`.

**Out of scope.** Pushing scan results as PR comments. Code scanning alert ingestion. GraphQL API integration.

**Tests.** App JWT signing. Installation token minting and caching. Webhook signature verification. PAT validation. Repo pagination. End-to-end with mocked GitHub API.

**Acceptance.** User installs Identrail GitHub App on their org. Scanning starts on selected repos within 60 seconds. `installation.deleted` webhook removes connector cleanly. GHES users with PAT can connect.

**Rollback.** Backend flag `IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=false` returns the new `/v1/connectors/github*` and `/auth/webhooks/github` endpoints to 404 (legacy `internal/api/github_connect.go` paths stay). Frontend flag `VITE_FEATURE_CONNECTOR_GITHUB_V2=false` falls back to the legacy connect UI.

---

## PR 9: Kubernetes Connector

**Goal.** In-cluster agent (Helm chart, recommended) plus kubeconfig paste fallback for ad-hoc and dev use.

**Files.**
- `internal/connectors/kubernetes/provider.go`.
- `internal/connectors/kubernetes/agent_handlers.go` (enroll and heartbeat endpoints).
- `internal/connectors/kubernetes/kubeconfig.go` (validation and storage).
- `cmd/identrail-agent/main.go` (the agent binary).
- `deploy/connectors/k8s/identrail-agent/` (Helm chart with Chart.yaml, deployment.yaml, serviceaccount.yaml, clusterrole.yaml, clusterrolebinding.yaml, values.yaml).
- `web/src/pages/connectors/ConnectKubernetesPage.tsx`.

**Flow (Agent).**
1. User picks "Run agent in cluster (recommended)".
2. Backend generates connector ID and a single-use 24-hour enrollment token.
3. UI shows a one-line `helm install` command with token and endpoint.
4. Agent installs as Deployment plus ServiceAccount with cluster-wide read RBAC.
5. Agent calls `/v1/connectors/k8s/enroll` with the token, exchanges for a long-lived agent credential, starts scanning and heartbeating.
6. Heartbeat absent for more than 5 minutes marks the connector degraded.

**Flow (kubeconfig).**
1. User picks "Bring your own kubeconfig".
2. Pastes kubeconfig. Backend validates by listing namespaces, encrypts, stores.

**Agent RBAC.** `get`, `list`, `watch` on read-only resources. No `pods/exec`, no `secrets` by default, no mutating verbs. Optional `--scan-secret-values=true` flag enables explicit secret-content scanning (default off).

**New endpoints.** `POST /v1/connectors/k8s`, `POST /v1/connectors/k8s/enroll` (agent-facing), `POST /v1/connectors/k8s/heartbeat` (agent-facing), `POST /v1/connectors/k8s/kubeconfig`.

`/v1/connectors/k8s/enroll` and `/v1/connectors/k8s/heartbeat` are explicitly non-browser machine-to-machine routes. They are authenticated with enrollment/agent credentials, and they are exempt from browser-only CSRF header checks (`Origin` and `Sec-Fetch-Site`) that apply to interactive cookie-backed endpoints.

**Out of scope.** Public OCI registry publication of the Helm chart. Real-time admission webhook integration. eBPF runtime detection.

**Tests.** Enrollment token: single-use, expiry, tampering rejected. Heartbeat updates state. `helm lint` passes. ClusterRole programmatic check that no secrets, pods/exec, or mutating verbs are granted. End-to-end with `kind` (Kubernetes-in-Docker).

**Acceptance.** User installs agent on a real cluster in under 2 minutes. Heartbeat observable within 30 seconds. API disconnect revokes agent credential within one heartbeat cycle.

**Rollback.** Backend flag `IDENTRAIL_FEATURE_CONNECTOR_K8S=false` returns `/v1/connectors/k8s*` endpoints to 404 (the agent's heartbeat and enroll endpoints share the same flag). Frontend flag `VITE_FEATURE_CONNECTOR_K8S=false` hides the connect button.

---

## PR 10: Onboarding Wizard

**Goal.** Five-step Snyk-style flow tying signup to org to workspace to connector to first scan to invite. The conversion event.

**Files.**
- `web/src/pages/onboarding/OrgPage.tsx`, `WorkspacePage.tsx`, `ConnectPage.tsx`, `ScanPage.tsx`, `InvitePage.tsx`.
- `web/src/components/onboarding/Stepper.tsx`, `SkipForNow.tsx`.
- `internal/api/onboarding/handler.go`.
- `internal/db/onboarding_state.go`.
- `migrations/000020_onboarding_state.up.sql` and `.down.sql` (small auxiliary table).
- Routes registered in `App.tsx`.

**Five steps.** Each at its own URL, resumable on refresh.
1. `/onboarding/org`. Org name (default to GitHub login if available). Required.
2. `/onboarding/workspace`. Workspace name (default "Production"). Required.
3. `/onboarding/connect`. Pick AWS, Kubernetes, or GitHub. Hands off to PR 7, 8, or 9 flows. Skippable.
4. `/onboarding/scan`. First scan inline, live progress, finding count animating up. Skippable only if step 3 was skipped.
5. `/onboarding/invite`. Invite teammates by email. Skippable.

**Schema (migration `000020_onboarding_state`).**
- `onboarding_state(user_id PK, current_step, org_id NULL, workspace_id NULL, connector_id NULL, completed_at NULL, started_at, updated_at)`.

**State management.** Server-driven. Every step writes to backend via `POST /v1/onboarding/state`. Frontend stores nothing in localStorage. Refresh-safe and resume-safe.

**New endpoints.** `POST /v1/onboarding/start`, `POST /v1/onboarding/state`, `POST /v1/onboarding/complete`, `GET /v1/onboarding/state`.

**Done state.** Dashboard with a four-step tooltip overlay. Tooltip is dismissable; the dismissal state persists.

**Out of scope.** Connector-type-specific tours. A/B testing of step order. Email drip campaigns post-onboarding.

**Tests.** Each step persists state. Refresh on any step routes back correctly. Skipping step 3 also skips step 4. Visual snapshots per step in light and dark. End-to-end happy path: signup, onboarding complete, dashboard, first finding visible.

**Acceptance.** New user from a brand-new GitHub account: signup to first finding visible in under 5 minutes, single tab. The connector type chosen in step 3 (AWS, GitHub, or Kubernetes) determines which path produces the finding; whichever PRs among 7, 8, 9 have shipped at the time PR 10 lands are the connectors the wizard can offer. The "first AWS finding" demo path is unblocked specifically once PR 7 ships alongside PR 10.

**Rollback.** Backend flag `IDENTRAIL_FEATURE_ONBOARDING_WIZARD=false` returns `/v1/onboarding/*` endpoints to 404. Frontend flag `VITE_FEATURE_ONBOARDING_WIZARD=false` falls back to the dashboard with no onboarding (user manually creates org and workspace via settings).

---

## PR 11: Enterprise SSO Admin

**Goal.** Per-org SAML or OIDC config via WorkOS Admin Portal launcher. Verified domains. Enforcement guardrails. Group-to-role mapping. Invitations. The PR that makes Identrail enterprise-ready.

**Files.**
- `internal/api/sso/admin_handler.go`.
- `internal/api/sso/portal_session.go` (5-minute Admin Portal token).
- `internal/api/sso/domain_verification.go` (DNS TXT verification poller).
- `internal/api/sso/test_sso.go` (simulated round-trip).
- `internal/api/sso/recovery_codes.go` (8-code generator, single-use, hashed).
- `internal/api/sso/relink_job.go` (force-relink on enable).
- `internal/api/invitations/handler.go` (fills PR 3 stubs).
- `internal/api/auth/audit.go` (extend with SSO-specific events).
- `web/src/pages/admin/SSOAdminPage.tsx`, `DomainsPage.tsx`, `InvitationsPage.tsx`.
- `web/src/components/admin/AdminPortalLaunchButton.tsx`, `RecoveryCodesModal.tsx`.

**New endpoints.**
- `GET /v1/orgs/:id/sso`
- `POST /v1/orgs/:id/sso/connection`
- `POST /v1/orgs/:id/sso/portal-session`
- `POST /v1/orgs/:id/sso/test`
- `POST /v1/orgs/:id/sso/enforce`
- `POST /v1/orgs/:id/sso/relink-all`
- `POST /v1/orgs/:id/sso/recovery-codes`
- `POST /v1/orgs/:id/sso/recovery-codes/use`
- `POST /v1/orgs/:id/domains`
- `POST /v1/orgs/:id/domains/:domain_id/verify`
- `DELETE /v1/orgs/:id/domains/:domain_id`
- `POST /v1/invitations`
- `GET /v1/me/invitations`
- `POST /v1/invitations/:id/accept`
- `DELETE /v1/invitations/:id`

**Verified domain flow.** Claim, generate `verification_token`, user adds DNS TXT record, backend polls or user clicks Verify, backend marks verified. SSO-required only enforceable on verified domains.

**Enforcement guardrail.** The toggle requires the toggling admin to currently hold a session whose `auth_method` was issued by the org's own SSO connection (SAML or OIDC, whichever the connection uses). Otherwise 403. Per `threat-model.md` SSO Lockout section.

**Force-relink job.** On enforce, async job lists all active sessions for org users, schedules invalidation 5 minutes in the future, emails users with re-auth link.

**Recovery codes.** 8 codes, 256-bit entropy each. Generated on enforce, shown once, stored hashed.

**Group to role mapping.** Stored on `identity_connections.group_role_map` JSONB. UI shows WorkOS-reported groups with role dropdowns. Auto-suggestions from common patterns. Unmapped groups default to `viewer` with a warning.

**Email sending.** Provider configurable (default empty/disabled until configured). Branded HTML and plaintext templates. 100 invites per org per hour.

**New env vars.** `IDENTRAIL_EMAIL_PROVIDER`, `IDENTRAIL_EMAIL_API_KEY`, `IDENTRAIL_EMAIL_FROM_ADDRESS`.

**Out of scope.** SCIM (PR 12). Auth audit log UI (PR 12). Cross-org features.

**Tests.** Verified domain flow (TXT absent vs present). SSO enforce toggle rejects an admin whose current session is not from the org's configured SSO connection. Recovery codes generated, single-use, hashed. Force-relink revokes sessions correctly. Test SSO simulates without persisting. Invitation email rendering. Group-to-role persistence.

**Acceptance.** Admin signs up fresh org, enables SSO with test IdP, verifies domain, enforces SSO, invites colleague, colleague signs in via SSO with correct role. Recovery code can rescue locked-out admin.

**Rollback.** Feature flag `IDENTRAIL_FEATURE_SSO_ADMIN=false`.

---

## PR 12: SCIM and Hardening

**Goal.** WorkOS Directory Sync auto-provisioning plus the safety nets every mature security product has plus the entitlements layer.

**Files.**
- `internal/api/scim/handler.go` (Directory Sync webhook receiver).
- `internal/api/scim/queue.go` (provisioning queue).
- `internal/api/scim/jit_provisioning.go` (SAML-before-SCIM-sync fallback).
- `internal/api/auth/account_deletion.go` (self-serve delete with grace).
- `internal/api/audit/export.go` (CSV export, license-gated).
- `internal/scheduler/cleanup_jobs.go` (extended with deletion grace job).
- `internal/license/entitlements.go`.
- `migrations/000021_org_entitlements.up.sql` and `.down.sql`.
- `web/src/pages/admin/AuditLogPage.tsx`, `OrgSessionsPage.tsx`.
- `web/src/pages/account/DeleteAccountPage.tsx`.

**Schema (migration `000021_org_entitlements`).**
- `org_entitlements(org_id PK, plan, max_connectors INT, max_scans_per_day INT, sso_enabled BOOL, scim_enabled BOOL, audit_export_enabled BOOL, expires_at NULL, updated_at)`. Free defaults: 1 connector, 100 scans per day, no SSO, no SCIM, no audit export. Ops set entitlements manually for early customers (no Stripe yet).
- `scim_events_seen(event_id TEXT PRIMARY KEY, received_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`. Idempotency log for WorkOS Directory Sync webhook deliveries. Cleanup job prunes rows older than 30 days.

**SCIM handlers.** `users.created` upserts `users` + `user_identities` + `tenancy_workspace_members`. `users.updated` patches fields. `users.deleted` (or `active=false`) sets `users.status='deactivated'`, revokes all sessions, retains row. `groups.user_added` and `groups.user_removed` update membership.

**Idempotency.** Two distinct concepts kept separate:

- **User mapping** (which Identrail user does this WorkOS event refer to?) uses the existing `user_identities` row keyed by `(provider, subject)` where `provider="workos"` and `subject` is the WorkOS user external id. No new column is needed; the unique constraint already enforces one row per (provider, subject) pair.
- **Event-level deduplication** (have we already processed this exact webhook delivery?) uses the `scim_events_seen` table added by the migration above. Each WorkOS Directory Sync event carries a unique `event_id`; the handler inserts the id with `ON CONFLICT DO NOTHING` and skips processing if the insert was a no-op. A nightly cleanup job prunes rows older than 30 days.

**JIT fallback.** SAML user lands before SCIM has synced them: create user with default role from SAML attributes, audit warning.

**Auth audit log UI.** Org-admin view filterable by user, action, time range, outcome, with CSV export gated by `entitlements.audit_export_enabled`. The same PR ships the per-user feed at `/app/account/security` (the placeholder slot left by PR 5) backed by `GET /v1/me/auth-events?limit=30`. The query is authenticated against the calling session and scoped to that user's events only. Backing the feed requires a queryable persistence path for `audit.AuditEvent` records of `Action LIKE 'auth.%'`; the simplest implementation is to add an `audit_events` Postgres sink alongside the existing file/HTTP sinks and read from it. The migration that adds the `audit_events` table ships in this PR's `000021_org_entitlements.up.sql` migration to keep PR 12's schema work in one place.

**Org-admin session management.** All active sessions across the org. Filter and revoke.

**Self-serve account deletion.** Confirmation modal. 14-day grace, cancellable. Cleanup job hard-deletes after 14 days. Owner deletion blocked unless ownership transferred.

**Dangerous-path tests.**
- Deprovisioning user mid-scan: scan continues under service identity.
- Role downgrade: revokes higher-priv API keys and sessions.
- SSO enforcement: blocks new logins via non-SSO providers; in-flight requests finish.

**Out of scope.** Stripe and billing automation. Custom roles beyond owner, admin, analyst, viewer. SAML attribute mapping UI.

**Tests.** Idempotent SCIM events. Queue absorbs burst of 1000 events. JIT provisioning warning. CSV export blocked when entitlement is off. Account deletion grace and hard-delete. Mid-scan deprovisioning. License gate disables SCIM toggle.

**Acceptance.** 50-user org with WorkOS Directory Sync: all 50 created within 1 minute. User removed from IdP loses access within 30 seconds. Admin can export 30-day audit log as CSV (Pro tier). User can self-serve delete; data fully removed in 14 days.

**Rollback.** Feature flag `IDENTRAIL_FEATURE_SCIM=false` rejects Directory Sync webhooks gracefully. `IDENTRAIL_FEATURE_ENTITLEMENTS=false` defaults to permissive.

---

## Cross-cutting Rules (every PR)

- API key and bearer OIDC paths never break. Repeat in every PR description as a non-removal commitment.
- Feature flag every new endpoint and UI surface. Listed in each PR's Rollback note.
- Telemetry contract: every new endpoint emits structured log plus metric plus audit event.
- Demo-path E2E test grows as PRs land: signup, onboarding, connect AWS, first scan, invite, second-user accept, SSO enable, SCIM sync. Lives in CI from PR 10 onward.
- Docs ship in the same PR. OpenAPI entry for every endpoint.
- Visual snapshots on auth, onboarding, account, admin, connector pages.
- Skeleton, loading, and error states on every async operation.
- Rate limiting on every `/auth/*`, `/onboarding/*`, `/v1/connectors/*` endpoint.
- Branch off `dev`, target `dev`. Auth work never shares a branch with the perf PR or other open PRs.
- DCO sign-off on every commit.
- Two-reviewer minimum on PRs 4, 7, 11, 12 (security-sensitive). Single reviewer is fine for the rest.
