# Cookie and Session Spec

The exact rules for how Identrail issues, validates, rotates, and revokes session cookies. These rules are implemented and later auth work reuses them without modification.

## Cookie

Sessions ride in a single cookie. There is no second auth cookie, no JWT in localStorage, no token in a header from the browser.

| Attribute | Value | Why |
| --- | --- | --- |
| Name | `identrail_session` | Stable, scoped, easy to grep for in logs. |
| Value | 32 random bytes, base64url-encoded | Opaque to the client; lookup key on the server. |
| `Domain` | Host of `IDENTRAIL_PUBLIC_BASE_URL` (no leading dot) | Cookie is scoped to `app.identrail.com` only. The marketing site never sees it. |
| `Path` | `/` | Sent on every product request. |
| `HttpOnly` | true | Blocks JavaScript access; survives XSS-based theft attempts. |
| `Secure` | true (in production) | Refuses to send over plain HTTP. The dev profile sets it to false only when `IDENTRAIL_PUBLIC_BASE_URL` starts with `http://`. |
| `SameSite` | `Lax` | Blocks cross-site POSTs from sending the cookie; allows top-level navigation flows like return-from-OAuth. |
| `Max-Age` | 14 days | Aligns with the absolute session expiry. |
| `Partitioned` | not set | Not needed for our same-origin product. Reconsider if we ever embed the dashboard in a third-party iframe. |

## Session Storage

The cookie value is the session ID. The server stores SHA-256 of that ID as the primary key in the `sessions` table. We never store the plaintext.

`sessions` columns:

| Column | Type | Notes |
| --- | --- | --- |
| `id` | `BYTEA PRIMARY KEY` | SHA-256 of the plaintext session ID. |
| `user_id` | `UUID NOT NULL`, FK to `users(id) ON DELETE CASCADE` | The authenticated user. |
| `current_org_id` | `TEXT NULL` | The org context for this session. NULL during onboarding before org creation. Type matches existing `tenancy_organizations.tenant_id`. |
| `current_workspace_id` | `TEXT NULL` | The workspace context. NULL similarly. Type matches existing `tenancy_workspaces.workspace_id`. |
| `current_project_id` | `TEXT NULL` | The active project context for project-scoped APIs such as connectors. Type matches existing `tenancy_projects.project_id`. |
| `auth_method` | `TEXT NOT NULL` | One of `workos`, `oidc`, `manual`, `saml`. Used by auth auditing and future SSO enforcement checks. |
| `ip` | `INET NULL` | Client IP at session creation. Not updated on every request; the audit log captures per-request IP. |
| `user_agent` | `TEXT NULL` | Client UA at session creation. |
| `idle_expires_at` | `TIMESTAMPTZ NOT NULL` | Sliding renewal target. |
| `absolute_expires_at` | `TIMESTAMPTZ NOT NULL` | Hard cap, no renewal past this. |
| `last_seen_at` | `TIMESTAMPTZ NOT NULL DEFAULT NOW()` | Updated to `NOW()` on every authenticated request, in the same UPDATE that bumps `idle_expires_at`. Powers the "last seen 2 minutes ago" display on the account/security page. |
| `revoked_at` | `TIMESTAMPTZ NULL` | Set on logout or admin revocation. |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT NOW()` | Audit-friendly. |

The session row also carries a compound foreign key on `(current_org_id, current_workspace_id, current_project_id)` referencing `tenancy_projects(tenant_id, workspace_id, project_id)` with `ON DELETE SET NULL`, so deleting a project clears the session pointer rather than orphaning it.

`users.id` is a UUID inside the new `users` table. The existing tenancy tables use TEXT identifiers and stay unchanged. The bridge between the two is `user_identities.subject` (which holds the existing `tenancy_workspace_members.user_id` value during the strangler-fig migration described in the architecture doc).

Indexes:

- `idx_sessions_user_id` on `user_id` to support "list active sessions for user X" and "revoke all sessions for user X."
- `idx_sessions_absolute_expires_at` on `absolute_expires_at` for the cleanup job.

## Session Lifetime

Two timeouts, both required.

- **Idle timeout: 15 minutes.** On every authenticated request, we set `idle_expires_at = now() + 15min`, capped by `absolute_expires_at`. If a request arrives after `idle_expires_at`, the session is rejected and the user is redirected to `/signin?return_to=...`.
- **Absolute timeout: 14 days.** Set at session creation. Never extended. After this point, idle renewal stops working and the user must re-authenticate.

The absolute timeout matters more than the idle one. Without it, an active user could keep a session alive for years.

## Session Creation

Triggered by the auth callback (`/auth/callback` for WorkOS, the OIDC equivalent for self-host, or the manual mode endpoint). The flow:

1. Generate 32 random bytes via `crypto/rand.Read`.
2. Compute SHA-256 of the bytes; this is the row primary key.
3. Insert into `sessions` with `user_id`, `auth_method`, lifetimes, IP, UA.
4. Base64url-encode the plaintext bytes; set as the cookie value with the attributes above.
5. Emit `auth.login.success` audit event.

If session creation fails (database unavailable), the response is HTTP 503 with a `Retry-After` header. We never set a cookie that we cannot verify later.

## Session Lookup

The `currentSession` middleware runs on every request to `/v1/*`, `/auth/logout`, and `/onboarding/*`. The flow:

1. Read the cookie. If absent, the request is unauthenticated and proceeds (the route's own auth check decides what to do).
2. Decode base64url. Reject malformed values without touching the database.
3. SHA-256 the decoded bytes to produce the lookup key.
4. Issue a single `UPDATE sessions SET idle_expires_at = LEAST(NOW() + INTERVAL '15 minutes', absolute_expires_at), last_seen_at = NOW() WHERE id = $1 AND revoked_at IS NULL AND idle_expires_at > NOW() AND absolute_expires_at > NOW() RETURNING ...`. An explicit application-side `subtle.ConstantTimeCompare` is unnecessary here, and not for any timing-safety property of the database. The reason is that the value we look up by is `SHA-256(cookie)`, and SHA-256 is preimage-resistant: any timing difference an attacker could observe in the database would, at most, leak information about the hash, not about the cookie that produced it, and recovering a cookie that hashes to a near-match is computationally infeasible. The cookie itself is generated by `crypto/rand.Read` so an attacker cannot guess one to probe with. The query also enforces all rejection conditions (revoked, idle expired, absolute expired) in the WHERE clause and bumps the sliding renewal and `last_seen_at` in the same write, so there is no SELECT-then-UPDATE TOCTOU window.
5. If the UPDATE returned no row, reject the request with 401.
6. Populate request context with `user_id`, `current_org_id`, `current_workspace_id`, `current_project_id`, `auth_method`, plus the `users` row joined in.

## Session Revocation

Four paths, all going through the same `RevokeSession(ctx, id)` repository method:

- **User-initiated logout.** `POST /auth/logout` revokes the current session (sets `revoked_at = now()`) and clears the cookie.
- **User revoking one of their other sessions.** `DELETE /v1/me/sessions/:id` from the account/security page. The endpoint scopes the lookup by `user_id` so a user cannot revoke someone else's session id. If the target id is the current session, the response also clears the cookie.
- **User revoking every other session.** `POST /v1/me/sessions/revoke-others` revokes every row for the user except the calling session. Used for "Sign me out everywhere else."
- **Admin or system revocation.** SCIM deactivation and role downgrade past API-key scope call `RevokeSession(ctx, id)` in a loop over the affected user's sessions. Future SSO enforcement work should use the same path.

A revoked session is rejected on the next request, no token expiry to wait for. This is the primary reason we use opaque server-side sessions instead of JWTs.

## Session Listing

`GET /v1/me/sessions` returns the active sessions for the calling user. Each row carries id, ip, user_agent, created_at, last_seen_at, idle_expires_at, and a `current` boolean marking the session that owns the calling cookie. The endpoint never returns sessions for any other user, even with admin scope; admin-side org session management is future work.

## Cookie Rotation on Privilege Change

When a user's privilege level meaningfully changes (role downgrade, identity link, sensitive admin action, SSO enforcement turning on), we rotate the session ID. The flow:

1. Generate a new 32-byte ID and its hash.
2. Insert a new row with the same `user_id`, fresh lifetimes.
3. Delete the old row.
4. Set the new cookie on the response.

Rotation prevents session fixation. Also flushes any in-memory caches keyed on the session ID.

## Cleanup

A job in the existing scheduler runs every hour and deletes session rows where `absolute_expires_at < now() - 7 days`. The 7-day grace window keeps audit-relevant session metadata around for a week past expiry.

## HMAC Signing Keys

`IDENTRAIL_SESSION_KEY` is used for HMAC-signed values that travel outside the server: OAuth `state`, invitation tokens (the public part), CSRF tokens. Rules:

1. Required at startup. The server refuses to start if it is missing or shorter than 32 bytes.
2. Treated as a secret. Never logged, never returned in API responses.
3. Rotation supports two simultaneous keys. `IDENTRAIL_SESSION_KEY` is the active signer. `IDENTRAIL_SESSION_KEY_PREVIOUS` is accepted for verification only.
4. To rotate: set `IDENTRAIL_SESSION_KEY_PREVIOUS` to the current value, set `IDENTRAIL_SESSION_KEY` to a fresh value, deploy. Wait long enough for all signed values to expire (longest-lived signed value is the 24-hour invitation token), then unset `IDENTRAIL_SESSION_KEY_PREVIOUS`.
5. Rotation is a manual ops procedure documented in the operator runbook. Automated rotation lands in a follow-up.

## What This Cookie Does Not Do

- It does not carry the user's email, name, role, or any other claim. Those come from the database via `currentSession`. This is deliberate; rotating the secret invalidates JWTs but does not invalidate cookies, which are just IDs.
- It does not work cross-site. Embedding the dashboard in a third-party page would require explicit `SameSite=None; Partitioned` and a security review.
- It does not work for the marketing site. `www.identrail.com` does not see this cookie.

## Test Matrix

| Test | Expected |
| --- | --- |
| Malformed cookie value (invalid base64url) | 401, rejected before DB lookup |
| Tampered cookie value (validly encoded but wrong bytes) | 401, no matching session row found |
| Cookie present, no matching session row | 401 |
| Session expired by idle timeout | 401, redirect to `/signin?return_to=...` |
| Session expired by absolute timeout | 401, redirect to `/signin` (no return_to past 14d) |
| Session revoked | 401 within one request |
| Two browsers logged in: revoke browser A | Browser A 401 next request, Browser B unaffected |
| User soft-deleted | All sessions for that user 401 next request |
| User hard-deleted | FK CASCADE removes sessions |
| `IDENTRAIL_SESSION_KEY` missing at startup | Server refuses to start |
| `IDENTRAIL_PUBLIC_BASE_URL` missing or invalid at startup | Server refuses to start |
| Session creation when DB is down | HTTP 503, no cookie set |
