# Changelog

## Unreleased
- Add **SageMaker workload identity collector** (#1486). Read-only inventory
  of notebook, training, processing, transform, model, endpoint, pipeline,
  and Studio domain execution roles, with S3 prefix, ECR image, and KMS key
  evidence. Adds the
  `GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/sagemaker-workload-roles`
  endpoint with `success`, `empty`, `degraded`, `partial_failure`, and
  `permission_denied` fixture states, OpenAPI schema, web API client types,
  runtime/CLI wiring, and operator docs. The collector is metadata-only and
  never reads notebook contents, training payloads, model artifacts, or
  endpoint invocation bodies.
- Reworked the entire **AWS section** (`/app/.../aws*`) so customer pages
  read as a product instead of an engineering progress dashboard.
  - The AWS overview header drops the AWS icon, the `AWS MACHINE
    IDENTITY` eyebrow, and the "Operate AWS connection health, account
    and region scope, permission posture, and the AWS machine-identity
    roadmap from one domain-owned surface." tagline. Title is just
    "AWS" and the subtitle condenses to a single state-aware line
    (`Disconnected · External ID not set` / `123456789012 · us-east-1 ·
    Permissions OK · Baseline ready` / `Loading AWS status…` /
    `Couldn't load AWS status.`).
  - The eight-card KPI strip (Connection / Account & region /
    Permissions / Runtime and actions / Baseline gate / Dependency
    index / Validation harness / Collector contract) is deleted.
  - The three "issue-tracker as UI" panels are removed from every AWS
    customer page: **Issue sequencing / AWS platform dependency index**
    (with its `#1472 · 85 issues · 11 waves · 18 ready · 61 blocked ·
    #1479 …#1496` dump), **App validation / AWS live app validation
    harness** (with its scenario fixture states and per-scenario
    confidence percentages), and **Collector contract / AWS service
    collector contract** (with its fields/fixtures/edges/permissions
    counts and raw graph relationship labels like `Workload to
    Identity`, `CAN PASS ROLE`). The underlying API endpoints
    (`/aws/dependency-index`, `/aws/validation-harness`,
    `/aws/collector-contract`) stay live for engineering tooling — only
    the customer UI calls are removed.
  - The header secondary CTAs (`Accounts` and `Findings` on the
    overview, `AWS home` / `AWS findings` on every subpage) collapse
    into a single state-driven primary CTA (`Connect AWS` when
    disconnected, `Findings` when connected, omitted while loading or
    on a status error).
  - A single contextual banner replaces the "Next actions / What AWS
    can do today / Wired now / Coming waves" panel: `Connect AWS to
    start scanning this environment.` / `Baseline not verified yet for
    this environment.` / `N permission check(s) failing.` — each with
    one action button.
  - Every AWS subpage shell (Connect, Accounts, Identities, Agents,
    Resources, Runtime, Graph, Findings, Remediation, Governance) gets
    the same compact header treatment plus plain-English titles and
    one-line subtitles, replacing the "Coverage inventory / Identity
    inventory / Agent inventory / Reachability inventory / Reserved
    surface / Inventory shell / Coverage shell / Reachability shell"
    LLM-cadence copy and the per-page "Inventory contract" /
    "Wired now / Planned coverage / Current vs planned / Coming wave"
    repeats. Sub-page taglines: `Which AWS account and region you're
    connected to.` / `IAM roles, workload identities, and what they
    can reach.` / `Bedrock and MCP agents Identrail can see.` /
    `Secrets, KMS keys, and S3 buckets your AWS roles can reach.` /
    `What your AWS roles actually did, from CloudTrail.` /
    `How AWS roles can reach things, visualised.` / `Risks Identrail
    found in your AWS setup.` / `AWS fixes Identrail prepares for you
    to approve.` / `Advice on AWS access. Identrail won't apply
    changes for you.`
  - The Connect AWS form keeps every existing CloudFormation install,
    role-ARN validation, permission preview, popup-fallback link,
    baseline gate, and permission diagnostics panel — only the
    surrounding header, KPI strip, "Setup payload" aside, and four
    issue/harness/contract side panels are removed.
  - New features reach the AWS app through the existing feature-flag +
    nav-card pattern (`AWS_CONTROL_CARDS` + the `VITE_FEATURE_*`
    flags). No more roadmap-in-UI: pre-ship surfaces simply stay out
    of the navigation grid until they actually work, and shipped
    surfaces communicate state via real empty states ("No findings
    yet. They'll appear after your first AWS scan.") rather than
    "Coming wave" / "Reserved surface" badges on non-functional pages.
- Slimmed every primary button across the **product app** so short
  labels like `Repositories`, `Queue scan`, `Connect AWS`, `Findings`,
  `Run baseline`, and `AWS overview` actually hug their text. The base
  `.idt-btn` rule is tuned for the marketing surface (44px min-height,
  full pill border-radius, uppercase, 0.08em letter-spacing) which
  made every button in the data-dense product app look oversized with
  visible padding on the right of short labels. A scoped override
  inside `.idt-app-console-layout` reduces min-height to 2.15rem,
  tightens padding to 0.4rem × 0.95rem, swaps the full-pill radius
  for a 8px rounded-rect, drops the uppercase + lets buttons take
  `width: max-content` so they fit content. The marketing site
  buttons are untouched. The existing mobile-stacked
  `width: 100%` override still applies inside the product app on
  narrow viewports.
- Renamed the shared GitHub-overview banner class from
  `.idt-overview-banner` (formerly `.idt-github-overview-banner`) so
  the AWS overview can reuse the same pill-banner shape. The class
  rename is invisible to users — both AWS and GitHub overview
  recommendations now render with the identical pill banner.
- Reworked the GitHub **Repositories** page (`/app/.../github/repositories`)
  with the same compact treatment applied to the overview and Connect
  pages. The header drops the GitHub icon, the `REPOSITORY INVENTORY`
  eyebrow, the "Launch, monitor, and cancel repository scans for the
  selected installation." tagline, the standalone Connected pill, and
  two of the three header CTAs (`Manage connection` and `GitHub home`).
  The title is just `Repositories` and the subtitle is a single
  state-aware line — `15 repositories · 8 recent scans · 2 failed`
  when there is recent activity, just `15 repositories` for a clean
  inventory, `Not connected for this environment.` when disconnected,
  `Loading repositories…` during the first fetch, and `Unable to load
  repositories.` when the status fetch fails. One primary CTA per
  state: `Connect GitHub` (disconnected) or `GitHub findings`
  (connected); the CTA is omitted while loading or in an error state
  so the error panel stays the single source of truth.
  The repository list is rebuilt as a compact table-like grid: each
  row is a single card with the bold repo name and a clean status
  line (`May 27 · 8 findings`, `May 24 · failed · Scan timed out`,
  `full in flight`, or `Not scanned`), and the `Queue scan` / `Cancel
  scan` buttons sit trailing on the same row. The previous bullet-list
  rendering (`<ul>`/`<li>`) with browser default disc markers and the
  inconsistent row heights are gone.
  The `Selected repositories / X repositories in scope` sub-header,
  the floating `Environment t` chrome chip, the `Activity / Recent
  repository scan activity` framing with the `X scans loaded` counter,
  and the `Reference / Scan operations` documentation aside (which
  exposed three meta-bullets including the implementation rule
  "Cancel is only available while a scan is queued or running.") are
  all removed. The activity section header is now just `Recent
  activity`. While loading or in an error state the install/manage
  body, the recent activity section, and the speculative empty states
  are suppressed so the page does not contradict the error panel or
  prompt a user to "Connect GitHub" off an unknown status.
  Backend behaviour is unchanged: `runRepoScan` is still posted with
  `repository`, `project_id`, and `connector_id` (for github_app
  installations) against the same auth context; `cancelRepoScan` is
  still posted with the scan id; `data.reload()` is still called after
  every successful mutation; and the four early-return shells (no
  scope, availability loading, unavailable, missing environment) are
  unchanged.
- Reworked the GitHub **Connect** page (`/app/.../github/connect`) so it
  reads as a product surface rather than an AI-generated onboarding demo.
  The header drops the GitHub icon, the `GITHUB APP ONBOARDING` eyebrow,
  the "GitHub App installation, account scope, and Enterprise/PAT fallback
  live in the GitHub section." tagline, the standalone Connected pill,
  and two of the three header CTAs; the title is just "Connect GitHub"
  and the subtitle condenses connection state to one line
  (`Installation 135895761 · Healthy · 15 repositories` when connected,
  "Not connected for this environment." when not, and "Loading GitHub
  status…" during the first connector-status fetch). The page is now
  state-aware: connected users see an "Installation" panel with account,
  installation id, and selected-repository count plus a Reinstall on
  GitHub button, a Manage Enterprise / PAT link, and a GitHub home link;
  disconnected users see one "Install the Identrail GitHub App" panel
  with the Install button and a Manage Enterprise / PAT fallback. The
  speculative install/manage body is suppressed entirely while the
  status request is still pending or has errored, so the error panel
  stays the single source of truth. The "Connection paths / Pick how to
  attach GitHub" framing, the "Why connect GitHub" Domain Charter aside,
  the standalone STATUS card whose facts are now in the header subtitle,
  and the "Selected repositories lives on the project setup view today
  and will move into this section in a follow-up PR." production-UI
  disclosure of TODO work are all removed. Backend behavior is
  unchanged: the install flow still posts to `startGitHubConnector` with
  `project_id`, `install_account_type=any`, and the same
  `/app/github/callback` redirect URI; the popup-blocked fallback still
  renders an Open GitHub link; the Manage Enterprise / PAT link still
  resolves to the existing project setup view with `source=github`.
- Added the AWS ECS task and execution role collector for #1478. The provider
  now collects ECS clusters, services, active and inactive task definitions,
  task roles, execution roles, launch/scheduling metadata, container images,
  secret references, and environment keys through read-only ECS SDK calls while
  omitting secret values and environment values. Normalization adds ECS
  workload/resource nodes, task roles emit `runs_as` relationships, execution
  roles emit `attached_to` relationships, the API exposes
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/ecs-task-roles`,
  and the AWS machine identities page renders ECS task/execution role rows with
  explicit empty, degraded, partial-failure, and permission-denied states.
- Added the AWS EC2 instance profile collector for #1477. The provider now
  collects EC2 instances, launch-template role references, instance profile
  roles, tags, account, region, and IMDS posture through read-only EC2/IAM SDK
  calls, normalizes EC2 workloads/resources into the AWS graph, emits `runs_as`
  and `attached_to` relationship evidence, and reports degraded,
  partial-failure, empty, and permission-denied fixture states. The API exposes
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/ec2-instance-profiles`,
  the AWS machine identities page renders endpoint-backed EC2 profile rows, and
  OpenAPI, connector permissions, tests, and docs cover the new inventory path.
- Added the AWS service collector contract for #1476. The API now exposes
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/collector-contract`
  as a read-only, project-scoped contract for normalized AWS collector records,
  graph edge semantics, fixture conventions, metadata-only permissions, and
  explicit failure states. The provider layer exports the reusable
  `AWSServiceCollector` interface plus contract helpers for future collectors,
  the AWS Control Center and Connect AWS pages surface contract readiness, and
  the web client, OpenAPI contract, tests, and docs cover the new collector
  foundation.
- Added the AWS live app validation harness for #1475. The API now exposes
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/validation-harness`
  as a read-only, project-scoped proof path for AWS setup, scan state, graph
  state, runtime evidence, remediation, and governance app flows. The harness
  returns deterministic success, empty, degraded, partial-failure,
  permission-denied, and unsupported-service fixture states with evidence,
  confidence, timestamps, account/region context, browser/API validation steps,
  and remediation hints. The AWS Control Center and Connect AWS pages surface
  the harness beside the baseline gate and dependency index, and the web client,
  OpenAPI contract, tests, and docs cover the reusable PR validation workflow.
- Stopped the GitHub overview (`/app/.../github`) from briefly showing a
  "Not connected for this environment" subtitle, an "Install the GitHub
  App" banner, and a Connect GitHub primary CTA on every load before the
  connector-status API actually responded. The page now shows a neutral
  "Loading GitHub status…" subtitle and suppresses the banner and primary
  CTA until either the connection or an error has been observed, so on
  slow networks the app no longer looks like it is denying a real
  installation. The underlying `useGitHubDomainData` hook now starts in
  the loading state when a fetch is going to happen and stays loading
  while the project ID is still being resolved, instead of taking a
  no-op resolved-null code path that left `loading=false` plus
  `connection=null` — the exact state callers treated as "confirmed
  disconnected".
- Added the AWS platform issue dependency index for #1474. The API now exposes
  `GET /v1/workspaces/:workspace_id/projects/:project_id/aws/dependency-index`
  as a read-only, project-scoped ledger for the #1472 AWS child issue graph,
  validating child count, blocker `#1234` formatting, blocker existence,
  parent ordering, and current-issue readiness after #1473. The AWS Control
  Center and Connect AWS pages surface the index as a sequencing gate with
  ready/blocked/completed counts and per-check diagnostics, and the web client,
  OpenAPI contract, tests, and docs cover the scriptable handoff response.
- Reworked the GitHub overview (`/app/.../github`) so the page leads with
  one identity line and one primary action instead of stacking a hero with
  four KPI cards, an installation detail card, a "Next actions"
  recommendation card, and a "Domain charter" aside. The header now drops
  the brand logo, the all-caps eyebrow, and the marketing tagline ("Operate
  repository, workflow, OIDC, and AI/agentic risk coverage from one premium
  control surface"); the title is just "GitHub" and the subtitle is the
  one fact that matters (e.g. `Installation 135895761 · Healthy · Last
  scan May 27`). The standalone Connection / Repositories / Active scans /
  Latest scan KPI strip, the "GitHub installation" detail panel, and the
  "What GitHub owns" charter aside are removed because the same status is
  now on the header and the same exits are in the Sections grid. The
  prior multi-row "Next actions" list collapses to one context-aware
  banner (connect → select repos → triage findings → review failed scan)
  with one action button. Section descriptions ("Manage the GitHub App
  installation, account scope, and PAT fallback.") are tightened to ≤6
  words ("App installation and scope."), and `Connect GitHub` / `Actions /
  OIDC` / `AI / Agentic Risk` are relabeled to `Installation` /
  `Workflows` / `Agent identities` to drop the redundant `GitHub`
  prefix and the "agentic" filler. The redundant `GitHub findings`
  secondary CTA is gone and the primary CTA is `Repositories` (not `Open
  Repositories`). Sections render as a card grid instead of plain links.
  `DomainHeader` accepts `eyebrow: null` and a new `hideLogo` prop to opt
  into the compact layout; the AWS and Kubernetes control centers are
  unchanged.
- Added the AWS platform baseline gate for #1473. The API now persists
  scoped `aws_platform_baseline_results`, exposes
  `GET/POST /v1/workspaces/:workspace_id/projects/:project_id/aws/baseline`,
  and blocks project-scoped AWS scan enqueue/replay with a structured
  `412 aws_platform_baseline_not_ready` payload when required checks fail.
  The gate verifies AWS connector health, graph contract availability, worker
  queue capacity, fixture availability in fixture mode, app route prerequisites,
  source mode, profile/contract versions, timestamps, evidence links, and the
  configured baseline git SHA. The AWS Control Center and Connect AWS surfaces
  now show the gate result and per-check diagnostics.
- Switched the `Enforce Branch Protection` workflow off the long-lived
  `REPO_ADMIN_TOKEN` PAT and onto a dedicated GitHub App that mints a
  short-lived installation token per run via `actions/create-github-app-token`.
  The App is scoped to `Administration: Read & write`, `Contents: Read-only`,
  and `Metadata: Read-only` on this repo only, with webhooks disabled.
  Required secrets are now `BRANCH_PROTECTION_APP_ID` and
  `BRANCH_PROTECTION_APP_PRIVATE_KEY`; see CONTRIBUTING.md → "Repo secrets"
  for the App's expected install state. Eliminates the silent failure mode
  where the daily branch-protection cron broke after a PAT expired.
- Bumped the Go toolchain to `1.25.11` and the backend builder image to the
  matching `golang:1.25.11-alpine` digest to clear stdlib advisories
  GO-2026-5037 and GO-2026-5039, which the daily OSV scan was failing on.
  Added a `docker` ecosystem entry to `.github/dependabot.yml` for
  `deploy/docker/` so future base-image bumps are opened as PRs automatically.
  Dropped the `*-security-updates` groups from every ecosystem so Dependabot
  opens security PRs the moment an advisory fires instead of batching them
  for the weekly Monday run; routine version bumps stay batched as before.
- Added the owner-only workspace Danger Zone on Settings (PR 3 of #1420).
  Workspace owners now see Suspend / Reactivate / Delete / Restore rows
  appended into the existing Danger Zone card alongside the user-account
  rows, with copy that matches the existing account modals: a
  type-to-confirm `SUSPEND` token on Suspend, a type-to-confirm workspace
  slug on Delete, and lightweight checkbox modals on the restorative
  Reactivate and Restore. The rows swap based on
  `tenancy_workspaces.status` (`active` → Suspend + Delete, `suspended` →
  Reactivate + Delete, `deleted` → Restore only) so the visible action
  always matches the next valid transition. Non-owners see exactly the
  two account rows that shipped before, with no layout change. A
  `409 sole_owner_requires_transfer` response renders an inline block
  inside the open modal listing the affected members + a deep link to the
  workspace member-management screen, so an owner can promote another
  owner and retry without losing the destructive flow. The frontend role
  gate is convenience; the backend `policyActionTenancyOwner` action
  shipped in PR 1 remains the authoritative 403.
- Added workspace hard-delete worker (PR 2 of #1420). A daily scheduled
  pass in `internal/workspacepurge` drains soft-deleted workspaces past
  the 30-day grace window: it explicitly purges `scans`, `repo_scans`,
  and `aws_account_region_coverage` rows (those tables carry
  tenant/workspace columns but no FK back to `tenancy_workspaces`), then
  deletes the workspace row itself which cascades through members,
  projects, connectors, secret envelopes (zeroed in the cascade), and
  scan policies in a single transaction. The destructive
  `WHERE status='deleted' AND deleted_at IS NOT NULL` predicate lives on
  the DELETE itself so a concurrent cancel-deletion landing between the
  worker's pre-check and the destructive write cannot drop live data.
  Audit emits `tenancy.workspace.hard_delete` with an anonymized
  `deleted-workspace:<id>` marker so downstream audit consumers can
  recognize references to purged workspaces. Worker is on by default
  (`IDENTRAIL_WORKER_WORKSPACE_PURGE_ENABLED=true`, daily, batch=100).
- Added workspace lifecycle backend for owner-driven suspend, soft-delete with
  30-day grace, and cancel-deletion. New endpoints
  `POST /v1/workspaces/:workspace_id/suspend`,
  `POST /v1/workspaces/:workspace_id/reactivate`,
  `POST /v1/workspaces/:workspace_id/cancel-deletion`, and the existing
  `DELETE /v1/workspaces/:workspace_id` now route through a new
  `policyActionTenancyOwner` authz action and gate destructive transitions
  behind a sole-owner guard that returns `409 sole_owner_requires_transfer`
  with the affected-member list when the only active owner would strand other
  active members. **Behavior change:** `DELETE /v1/workspaces/:workspace_id`
  is now a soft delete that returns `200` with the saved workspace +
  `hard_delete_after` (was a hard delete returning `204`). Migration `000036`
  adds `tenancy_workspaces.status`, `suspended_at`, and `deleted_at`. The
  authenticated lifecycle middleware (`requireCentralPolicyMiddleware`) and
  the public Kubernetes agent routes (`POST /v1/connectors/k8s/enroll` and
  `POST /v1/connectors/k8s/heartbeat`) now both refuse traffic for
  suspended or soft-deleted workspaces with `409 workspace_inactive`, so a
  workspace pause genuinely stops every connector state-change pathway —
  including agents already deployed in remote clusters. The matching
  frontend Danger Zone card ships in PR 3 of #1420.
- Added the Settings Danger Zone UI for self-serve permanent account deletion:
  a "Delete my account permanently" row, primary-email type-to-confirm modal,
  data-export prompt, structured `sole_owner` workspace blocker, success
  redirect to a pending-deletion recovery banner, and sign-in cancellation via
  `POST /v1/me/cancel-deletion`.
- Added self-serve "Download my data" exports. `POST /v1/me/export`
  enqueues an authenticated user export, `GET /v1/me/export/:job_id`
  polls job state and returns a 24-hour signed download URL once ready, and
  the worker writes ZIP bundles containing `user.json`, `workspaces.json`,
  `audit.json`, and `sessions.json` to local/object storage with 7-day
  retention and garbage collection. The Settings Danger Zone now includes a
  non-destructive "Download my data" row that polls until the export is ready,
  triggers the browser download, and surfaces unavailable endpoints gracefully.
- Added self-serve account profile editing in Settings. Authenticated users can
  now `PATCH /v1/me` with `display_name` and/or `avatar_url`; the endpoint
  rejects unknown fields, trims and validates display names, blocks control and
  bidirectional formatting characters, restricts avatars to blank or allowed
  `https://` hosts, registers `me:write` authz coverage, and returns the
  refreshed `CurrentUserContext` without touching account lifecycle fields. The
  Settings page now shows an Account profile card before workspace settings,
  with inline editing, optimistic cache updates, and rollback on save failure.
- Hardened the new GitHub domain pages to address review feedback: the
  Control Center now surfaces a `Unable to load GitHub status` error when
  listing recent repository scans fails instead of silently showing an empty
  timeline, scopes the `Recent scans` panel and `Latest scan` KPI strictly to
  scans for the selected GitHub App repositories (no fallback to all scans),
  and the `Latest scan` KPI reflects the newest completed scan's actual
  outcome rather than preferring an older successful one. The Connect page
  renders an `Open GitHub` fallback link with the App install URL when the
  browser blocks `window.open` after the install request. The Repositories
  activity timeline is scoped to selected repositories. The Connect page
  also forwards `redirect_uri` (`${origin}/app/github/callback`) when
  starting the GitHub App install so completion lands back on the Identrail
  callback handler instead of GitHub's default setup URL. The Repositories
  page disables `Queue scan` and `Cancel scan` while environment data is
  reloading to prevent acting on stale repository rows after switching
  environments.
- Moved GitHub setup, repository scan operation, and the Actions/OIDC
  posture surface out of the legacy `/projects/:projectID` source tab into a
  domain-owned GitHub section. The new `/app/:tenant/:workspace/github`
  Control Center surfaces connection status, installation summary, selected
  repository coverage, recent scan activity, and recommended next actions.
  `/github/connect` owns the GitHub App install entry point and the
  Enterprise/PAT fallback link; `/github/repositories` owns selected
  repository inventory plus repository scan launch and cancel; and
  `/github/actions` is the premium waiting-for-coverage shell for workflow
  permissions, OIDC trust paths, and runner posture. Existing GitHub
  connector, repository scan, and project-scoped API contracts are preserved
  — the new pages call the same `getGitHubConnectorStatus`,
  `startGitHubConnector`, `listRepoScans`, `runRepoScan`, and
  `cancelRepoScan` endpoints, including the internal `project_id` scope, so
  backend behavior is unchanged.
- Added self-serve account permanent deletion with a 30-day reversible grace
  window. `DELETE /v1/me` soft-deletes the authenticated user (status flips to
  `deleted`, `deleted_at` is stamped, every other session is revoked, and the
  sole-owner workspace check is rerun atomically after the write to close the
  pre-flight race) and returns the scheduled hard-delete date. The calling
  cookie is intentionally preserved as the recovery cookie: every other route
  refuses it (status is no longer `active`) but `POST /v1/me/cancel-deletion`
  accepts it through a path-scoped lenient session lookup so the user can
  reverse the deletion from the same browser without re-authenticating. The endpoints refuse with a
  structured `409 sole_owner` listing affected workspaces when the user is the
  sole owner of any workspace, so deletion never orphans an unowned tenant.
  WorkOS sign-in with `intent=login` against a soft-deleted account is refused
  with `ErrAuthAccountPendingDeletion` (mapped to `403 account_pending_deletion`)
  so the frontend can offer cancellation; a new `intent=cancel_deletion` revives
  the row server-side as part of the sign-in. A daily worker pass
  (`IDENTRAIL_WORKER_USER_PURGE_ENABLED`, default on) hard-deletes accounts past
  the grace window: PII is tombstoned (synthetic `deleted-user+<uuid>` email,
  display name and avatar cleared), provider identities and session rows are
  removed, the users row stays so audit references by UUID remain valid. The
  pass is idempotent — already-tombstoned rows are filtered out so re-running
  is a no-op. New audit actions: `auth.account.delete`, `auth.account.delete.cancel`,
  `auth.account.pending_deletion`, `auth.user.delete`, `auth.user.delete.cancel`,
  `auth.user.hard_delete`.
- Extended the shared domain page framework in `web/src/components/app/DomainFoundation.tsx`
  with typed `DomainStatusBadge` variants (connected, disconnected, needs-attention,
  degraded, running-scan, missing-permissions, coming-soon), `DomainCoverageCard`
  with an accessible progress bar, `DomainFindingSummaryCard` keyed to severity,
  `DomainTimeline` rows, a `DomainGraphPlaceholder` panel, a
  `DomainRemediationQueue` with primary/secondary affordances, a `DomainSortControl`
  with a direction toggle, and a focus-trapped `DomainDetailDrawer`. Empty and error
  states now accept `nextAction` and `retryAction` slots so the operational
  states feel like a security product rather than a generic toast. The new
  primitives are reusable across AWS, GitHub, and Kubernetes domain shells and
  follow the WorkOS/GitHub-style premium dark direction without reintroducing
  Projects or global Findings concepts.
- Renamed the hosted API production release workflow to `Deploy to prod` and
  made the normal release path one-click from the `dev` branch. The workflow now
  resolves the current commit's immutable API and worker image tags, verifies CI
  and image publishing succeeded for that exact commit, confirms the GHCR image
  tags exist, records a `production` environment gate, and then runs migrations,
  deploys the API and worker, and smokes the hosted API without requiring
  operators to type confirmation text or paste image tags.
- Added a Settings "Danger zone" with a `Suspend my account` row backed by the
  self-serve `POST /v1/me/deactivate` endpoint. Confirming the modal revokes
  every active session, clears the cookie, signs the user out, and redirects
  to `/signin?reason=account_deactivated` where a banner explains the account
  is suspended and offers a "Reactivate account" link that routes through the
  signup flow (the existing WorkOS signup-intent path auto-reactivates the
  account). Introduces shared `DangerZone`, `DangerZoneRow`, and
  `ConfirmDestructiveModal` components under `web/src/components/settings/`
  with both checkbox and type-to-confirm confirmation variants, ready to be
  reused by the upcoming Delete-account and Workspace-deletion flows.
- Added self-serve account-lifecycle endpoints. `POST /v1/me/deactivate`
  transitions the authenticated user from `active` to `deactivated`, revokes
  every active session, and clears the session cookie. `POST /v1/me/reactivate`
  flips the status back. Both are idempotent and emit `auth.account.deactivate`
  / `auth.account.reactivate` audit actions. Returning deactivated users who
  attempt to sign in through the WorkOS login-intent flow now receive
  `ErrAuthReactivationRequired` instead of being silently auto-reactivated,
  so the frontend can offer the explicit reactivation affordance via the
  signup-intent path. Manual mode (the loopback-only dev convenience path)
  still auto-reactivates on sign-in so a deactivate test cannot lock a
  developer out of their dev tenant.
- Replaced the single-field WorkOS MFA code input with a six-slot segmented
  OTP input (`input-otp`), matching the pattern now standard across premium
  auth flows. Each slot has its own focus ring, the active slot shows a
  blinking caret, filled slots get a brighter border, and the Continue button
  stays disabled until all six digits are entered. The hidden underlying
  input keeps `aria-label="Authentication code"` and
  `autocomplete="one-time-code"` so screen readers and iOS SMS autofill still
  work, and the password-manager push-out strategy is disabled because an
  authenticator code field shouldn't surface a password-manager fill icon.
- Refined the WorkOS MFA verification copy: the heading is now "Enter
  verification code" (replacing the redundant "Verify your sign-in"), the code
  input placeholder reads "6-digit code" instead of a greyed-out "000000", and
  the submit button reads "Continue" instead of "Verify and continue".
- Tightened the WorkOS MFA verification screen: the authenticator code entry now
  appears immediately without the intermediate "Preparing your authenticator
  challenge..." flash (the challenge starts silently in the background, with the
  verify button held disabled for the brief window until it is ready), and the
  layout was simplified to a single centered code input — removing the
  redundant "Enter the code..." helper line, the visible "Authentication code"
  label, and the nested bordered form container that previously sat on top of
  the auth panel.
- Stopped GitHub App webhooks from queueing repository scans unless the project
  has an enabled `event` or `hybrid` scan policy. Manual projects still record
  webhook deliveries without starting scans, low-value pull-request metadata
  events are ignored, and explicit `@identrail review` / `/identrail review`
  commands continue to queue scans.
- Fixed WorkOS MFA enrollment so the browser keeps the pending challenge after
  showing the authenticator QR code, preventing valid setup codes from failing
  with "mfa challenge has not started".
- Added an internal AWS account and region coverage registry for tenant-scoped connector estate coverage, including migration, store methods, service helpers, tests, and documentation.
- Added typed AWS connector capability modes (`discovery`, `runtime_evidence`,
  `remediation_plan`, `approved_remediation`, `authorization_advisory`,
  `authorization_enforcement`). Connector status now reports requested,
  validated, and effective capabilities; the read-only CloudFormation flow stays
  pinned to `discovery`; permission preview is grouped by capability tier so
  read-only discovery is visibly separate from future write/remediation/
  enforcement tiers; and validation emits a capability-scoped diagnostic naming
  any requested tier the deployment gate denies. Write-capable tiers are gated
  behind `IDENTRAIL_AWS_CONNECTOR_CAPABILITIES` and a dedicated write role, and
  no live remediation or enforcement executor is added. See
  `docs/connector-capabilities.md`.
- Expanded the normalized identity graph contract with precise AWS machine and
  agent relationship semantics for workload execution, secrets, KMS decrypt,
  role passing, invocations, tool calls, delegated users, runtime sessions, and
  observed actions, with domain metadata, endpoint validation, tests, and docs.
- Added a Docker Hub repository overview source and sync workflow so
  `identrail/identrail` presents a maintained, container-focused description on
  Docker Hub instead of relying on indexed image layer pages.
- Added GitHub Actions AI-agent prompt-injection detection for workflows that
  feed untrusted PR, issue, review, comment, workflow_run, or repository
  prompt-file content into LLM/agent steps with repository write, secret, OIDC,
  cloud, release, or mutation capabilities.
- Added approval-gated remediation PR publishing for repository findings across
  the API, CLI, and app, so deterministic GitHub exposure fixes can open a
  branch and pull request only after explicit operator approval and a
  write-capable short-lived token.
- Added GitHub organization-level security policy posture as inherited context
  for repository posture. GitHub App-backed posture now distinguishes repository
  controls from organization policy controls such as enforced code security
  configurations, Actions policy, workflow token defaults, reusable-workflow
  allowlists, and central code security posture, with explicit `unsupported` and
  `unknown` states when GitHub cannot prove the control.
- Added structured repository scan diagnostics to API errors and the hosted app
  so enqueue/list failures can distinguish disabled scans, allowlist or
  selected-repository rejection, queue pressure, missing migrations, GitHub App
  token minting failures, and worker timeouts. Cleaned stale documentation by
  aligning current architecture/scope docs with AWS, GitHub, and Kubernetes,
  leading repo exposure docs with `identrail scan owner/repo`, archiving phase
  records, and removing historical leftovers.
- Let GitHub App-backed project scans use the app installation's selected
  repository list as the scoped target guard, so personal and organization repos
  selected in GitHub no longer require a per-repo deployment allowlist update
  before the first scan can be queued.
- Tightened the project source setup surface: the GitHub App install card now
  uses one clear action, optional scan limits and installation details stay
  compact, and repository posture summaries keep raw checks collapsed with
  restored dark-console contrast.
- Ingest open GitHub secret-scanning and Dependabot vulnerability alerts as
  first-class repository findings during GitHub App-backed repo scans, alongside
  the existing code-scanning import. Secret-scanning alerts become redacted
  `secret_exposure` findings (the raw secret value is never fetched or stored),
  and Dependabot alerts become repository findings carrying ecosystem, package,
  GHSA/CVE identifiers, vulnerable range, first patched version, alert URL, and a
  mapped severity. Each alert source is independent enrichment: permission-
  limited, unavailable, or rate-limited endpoints no longer fail the native scan.
  Imported alerts are deduplicated deterministically across scans.
- Added MCP and AI-agent repository exposure detection for committed agent
  configs, sensitive environment-variable references, dangerous tool
  capabilities, and raw provider-shaped secrets in agent config without storing
  raw secret values.
- Polished the repository Findings page styling: softened the summary-tile
  labels from all-caps to sentence case, styled the new metric captions, the
  scan-health banner, and the failed-scan state actions, and set the summary
  grid to the consolidated four-column layout.
- Added the GitHub PR review foundation: the app manifest now requests narrow
  reviewer permissions for PR comments and check runs, subscribes to review
  events, and `@identrail review` / `/identrail review` PR comments enqueue a
  project-scoped repository scan.
- Removed the temporary blank "Opening GitHub..." tab from hosted GitHub App
  setup; the app now opens GitHub only after the install URL is ready and keeps
  the in-app fallback button for browsers that block the popup.
- Simplified hosted GitHub App setup to rely on GitHub's native account picker
  instead of duplicating personal-account and organization selection in the app.
  The versioned GitHub App manifest now includes the callback URL and setup URL,
  keeps update redirects disabled (repository selection changes sync through the
  `installation_repositories` webhook rather than a stateless redirect that the
  callback cannot complete), and operators can compare live app settings with
  `scripts/check_github_app_manifest.py`.
- Reworked the repository Findings page information architecture. Consolidated
  the ten summary tiles into four (open, critical, mean-time-to-fix, completed
  scans) with supporting detail in captions, led with the findings table by
  demoting the risk graph and finding trend below it, and gated the filter panel
  and the finding detail pane so empty scopes no longer show redundant empty
  placeholders.
- Made the repository Findings page state-aware instead of rendering a
  zero-filled dashboard in every empty case. A never-scanned workspace now shows
  a first-scan onboarding prompt, an all-failed scan history surfaces the failure
  reason with a re-run path (so failed scans are no longer silently shown as
  zeros), and a successful scan with no findings shows a clean "no exposure
  found" state. Also removed the redundant "Reload trend" button (Refresh now
  reloads everything) and collapsed the finding trend so it no longer repeats
  empty zero rows.
- Re-scan dependencies with osv-scanner on every push to `dev` so resolved
  dependency CVEs clear from the code-scanning dashboard right after a fix
  merges, instead of waiting for the daily scheduled run. Restyled the README
  OpenSSF Best Practices badge to a shields.io badge that matches the other
  badges (black label, vivid "passing").
- Refreshed the public onboarding docs so first-time users can start from the
  source they care about: GitHub repository scans, AWS machine identity scans,
  Kubernetes machine identity scans, Docker-based runs, or the hosted app. The
  install docs now point at the published Homebrew tap and released CLI image
  instead of pre-publication wording, and the README badges now avoid forced
  green CI states, flaky GitHub-backed version lookup, and include the OpenSSF
  Best Practices badge.
- Fixed the branch-protection enforcement workflow, which had failed on every
  run since `actions/github-script` was bumped to v9. The injected `octokit`
  binding collided with the script's own `const octokit`, producing a parse-time
  `SyntaxError`; the script's admin-token client is now named `adminOctokit`.
- Remediated open security and quality findings. Bumped vulnerable Go
  dependencies (`golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys`)
  and the Go toolchain to `1.25.10` to clear stdlib CVEs, removed the stale
  `golang.org/x/sys` downgrade `replace`, and pinned the backend builder image
  to the matching `golang:1.25.10-alpine` digest. Updated `web` overrides to
  patched `uuid`, `qs`, `ws`, and `basic-ftp` so `npm audit` reports no
  vulnerabilities. Hardened GitHub Actions workflows by pinning every third-party
  and GitHub-owned action to a commit SHA and moving write-scoped
  `GITHUB_TOKEN` permissions from the workflow top level down to the individual
  jobs that need them.
- Changed the homepage "Docker pulls" proof pill to report the primary
  `identrail/identrail` image only, instead of summing pull counts across all
  five published service images. The previous sum overstated adoption because a
  single quickstart/CI run pulls multiple images at once.
- Improved hosted auth and GitHub connector onboarding UX. WorkOS callback
  failures now redirect back to the web sign-in page with user-facing reasons
  instead of raw JSON, login no longer provisions unknown identities, signup can
  reactivate a deactivated/deleted account that still owns the same email, login
  now points retained removed accounts to the reactivation signup path, and the
  GitHub App setup now opens GitHub's account selector in a new tab, backed by a
  public app manifest for Any-account installation.
- Fixed app workspace navigation so route changes inside an already-validated
  workspace no longer rerun the full session gate, and hardened repository
  finding display helpers against partially populated API records.
- Added a manual AWS production release workflow that runs hosted database
  migrations before deploying the selected immutable API/worker image and then
  performs API smoke checks, reducing the chance of code/schema drift during
  hosted releases.
- Fixed web UI polish issues: the workspace overview header no longer crowds the
  "Overview"/"Latest activity" text (the boxed border is removed and the title and
  subtitle get clean spacing with no divider), the sign-in/sign-up logo mark now renders a visible
  tile on the dark auth background instead of disappearing into it, and the
  homepage "Adoption Paths" eyebrow uses the brand accent color in light theme so
  it is no longer washed out. The workspace finder ("Go to anything") modal now
  scrolls its own results and locks the page behind it instead of scrolling the
  background, and the dark app shell uses a slim, subtle scrollbar instead of
  inheriting the heavy near-white light-theme scrollbar.
- Fixed hosted repository scan enqueueing after incremental scan metadata. Empty
  revision and cursor values are now stored as non-null empty strings instead of
  violating the `repo_scans` cursor constraints.
- Added API-backed CLI parity for GitHub repository intelligence. Operators can
  now queue hosted repository scans, list/show/cancel repo scans, filter repo
  findings by lifecycle and confidence, fetch risk graphs, collect GitHub
  repository posture, and preview remediation plans from the terminal.
- Wired GitHub repository intelligence into the product app. Project source
  onboarding now surfaces selected-repository posture checks, and repository
  findings now show risk-graph summaries, top finding scores, and on-demand
  remediation previews.
- Added first-time CLI install and repository scan ergonomics. `identrail scan
  <owner/repo>` now runs the repository exposure scanner while `identrail scan`
  without arguments keeps the existing provider scan behavior, `repo-scan`
  accepts positional targets and the `repo` alias, and release workflows now
  publish a dedicated CLI container image with release documentation for
  binaries, Docker, and Homebrew tap readiness.
- Added Homebrew tap release publishing. Release automation now renders
  `Formula/identrail.rb` from a stable uploaded source archive and can push it
  to `identrail/homebrew-tap`, installing the CLI as `identrail` so
  `identrail scan owner/repo` works after the tap is published.
- Added repository finding lifecycle intelligence. Repo findings now carry
  stable lifecycle keys, first/last seen timestamps, fixed/reopened/suppressed
  state, owner and detector metadata, list filters for lifecycle, ownership,
  confidence, and age, plus dashboard summary metrics for open, fixed,
  reopened, SLA-aged, and MTTR-ready repository risk.
- Redesigned the marketing pricing hero decision console and product trust
  graph visual with larger plan guidance, precise SVG path arrows, and clearer
  trust-path labels.
- Fixed the product trust graph hero so risk badges remain readable and path
  labels no longer collide with destination cards.
- Replaced public demo calendar placeholders with the first-party demo booking
  form, including preferred day/time capture in lead delivery emails and
  clearer dark-page contrast for the demo booking and evidence panels.
- Added repository finding remediation previews. Repo misconfiguration findings
  now map to detector-specific remediation guidance and safe fix-PR plans for
  deterministic patches, while secret findings return rotation guidance only so
  raw secret material is never copied into generated branches or PRs.
- Fixed repository scan cursor safety so quick-scan cursors no longer suppress
  later delta scans for the same head revision, and truncated scans no longer
  advance `cursor_after` or the per-repository cursor before all findings have
  been evaluated.
- Added a scoped repository scan cancellation path. Active queued or running
  repository scans can now be marked terminal from the API and project UI with
  a clear `repository scan canceled by user` activity message, freeing the
  repository target for an immediate retry without operator database edits.
- Added incremental repository scan execution. Repo scans now track scan mode,
  base/head revisions, cursor before/after values, and changed paths; GitHub
  push and pull-request webhooks enqueue delta scans when revision metadata is
  available; scheduled policies continue to enqueue deep scans; and successful
  scans update per-repository cursors so already-current deltas are skipped
  before worker time is spent.
- Added a GitHub repository risk graph domain model for repository findings.
  Repo findings can now be deterministically associated with repository,
  workflow, job, environment, secret/token, OIDC subject, cloud role,
  Kubernetes service-account, GitHub App, and deploy-key nodes when evidence
  exists. The graph deduplicates edges, represents missing blast-radius evidence
  as `unknown` instead of guessing, and attaches inspectable risk-score factors
  for severity, confidence, exploitability, privilege, exposure, environment
  criticality, and freshness.
- Added opt-in external repository finding adapters. SARIF 2.1.0 output and
  GitHub code-scanning alerts can now be normalized into Identrail repo
  findings with adapter name/version/rule/location/confidence evidence,
  severity mapping, secret-like evidence redaction, stable dedupe against
  native findings, and no external scanner execution unless explicitly wired by
  the caller.
- Bounded hosted repository clone size for GitHub App scans. Remote repository
  scans now build a shallow bare repository through a batched, ref-budgeted
  fetch plan, exclude shallow boundary commits from patch-derived findings,
  and preserve selected tags and custom refs without spending the whole worker
  timeout on an unbounded clone before analysis can start.
- Added context-aware GitHub Actions workflow attack analysis to repository
  exposure scans. Workflow findings now distinguish shallow
  `pull_request_target` / `write-all` signals from dangerous combinations such
  as untrusted PR-head checkout, privileged `pull_request_target` jobs,
  unpinned third-party actions, shell interpolation of PR metadata,
  workflow_run privilege chains, broad OIDC trust, cache poisoning, and
  artifact or release publishing reachable from untrusted inputs.
- Added GitHub App repository posture collection. The connector can now collect
  normalized posture checks for selected repositories, including repository
  metadata, default branch protection, branch rulesets, Actions permissions,
  Dependabot security status, code and secret scanning alerts, deploy keys,
  repository webhooks, and deployment environments. Posture checks distinguish
  `secure`, `insecure`, `permission_limited`, and `unavailable` states, capture
  rate-limit metadata, keep webhook evidence redacted, and document the
  read-only GitHub App permissions required for the collector.
- Marked stale hosted repository scans as terminal `failed` records instead of
  requeueing them into another silent `running` loop. Queue workers now emit
  explicit claim-attempt and scan-start lifecycle events so hosted repo scan
  incidents identify the exact boundary before scanner execution.
- Hardened hosted repository scan execution so cancelled git subprocesses are
  terminated as a process group with a bounded wait, preventing worker timeouts
  from leaving scans stuck in `running`. Worker logs now include repository
  queue claim, requeue, success, and failure lifecycle events for CloudWatch
  incident diagnosis.
- Added the runtime `git` dependency to the backend API/worker image so hosted
  repository exposure scans can clone and inspect selected repositories after
  deployment, and added a CI smoke check plus worker-selectable AWS log
  diagnostics for repo scan incidents.
- Added rule-aware confidence classification for repository secret findings.
  Secret detections now carry deterministic `confidence_score`,
  `confidence_state`, and `confidence_reasons` metadata, distinguish likely
  production leaks from samples, placeholders, docs, test fixtures, and
  repository-local fingerprint allowlists, and preserve API/backfill
  compatibility for existing finding records.
- Recovered stale repository scans after worker replacement. Hosted workers now
  requeue `running` repository scan rows older than the worker timeout grace
  period before claiming new work, and repo scan claims refresh the stored
  run timestamp so future recovery decisions measure execution age instead of
  queue age.
- Added GitHub App connector-backed private repository scans. Repo scan queue
  rows now store only non-secret source metadata, while API, scheduled, and
  webhook-triggered scans resolve the selected project connection and workers
  mint short-lived installation tokens at execution time. Clone credentials are
  passed through `GIT_ASKPASS` and redacted from persisted scan failures.
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
