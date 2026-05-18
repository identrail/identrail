# Auth Threat Model

This document covers the security risks specific to the auth and identity surface. Each section names a real attack, explains how it would work against Identrail, and states the defense we ship.

If you are about to write code that touches sessions, cookies, OAuth state, invitations, or identity linking, read this document first.

## Cookie Theft

**Attack.** An attacker obtains the session cookie (XSS, malware on the user's machine, network capture on a misconfigured TLS path, browser exploit) and replays it.

**Defenses.**

1. The cookie is `HttpOnly`. JavaScript on the page cannot read it, so a successful XSS does not exfiltrate the session.
2. The cookie is `Secure`. The browser refuses to send it over plain HTTP.
3. `SameSite=Lax`. The cookie does not ride along with cross-site POSTs by default.
4. The cookie value is opaque (an ID, not a token with claims). Possession of the cookie still requires the server's `sessions` row to exist and not be revoked.
5. Sessions are server-side and revocable. An admin or the user can kill a session immediately from `/app/account/security`.
6. Every authenticated request emits an audit event with IP and user agent through the existing `audit.AuditEvent` pipeline. Queryable audit-log UI work is separate from Track 1 native SSO.

**What we accept.** A determined attacker with persistent malware on the user's machine can replay the cookie until the session expires or is revoked. This is true of every cookie-based auth system. We mitigate the blast radius (revocation, audit visibility, idle timeout) rather than try to defeat the threat.

## OAuth State Replay

**Attack.** An attacker captures a valid `state` parameter from an OAuth flow and replays it to log themselves into the victim's account on a future flow — including against a different API instance than the one that issued the redirect.

**Defenses.**

1. `state` is HMAC-signed with `IDENTRAIL_SESSION_KEY`. A tampered state fails verification.
2. `state` carries only a fresh random nonce, an intent, a sanitized return path, and an expiry. It never contains the session ID, the user ID, or any other identifier that would leak into IdP logs, browser history, or referer headers.
3. `state` has a 10-minute TTL. Old captures are useless.
4. The signed token is not sufficient on its own. At the moment the redirect is issued, the server persists a row in the `oauth_transactions` table (`nonce`, an opaque browser-bound `cookie_token`, `intent`, sanitized `return_to`, optional `expected_user_id`/`expected_session_id`, `created_at`, `expires_at`) and sets the `cookie_token` in a short-lived `HttpOnly`, `Secure`, `SameSite=Lax` transaction cookie whose name is scoped to the state nonce (so concurrent in-flight logins — double-click, two tabs, switching provider — each keep their own browser-bound token instead of one overwriting another). The `/auth/callback` handler requires the signed state, the transaction cookie, and the persisted row to all match. The row is atomically consumed (`UPDATE ... WHERE consumed_at IS NULL AND expires_at > now() RETURNING`), so a second callback attempt fails even when routed to a different API instance that shares the database. Because consumption is store-backed rather than a process-local map, replay protection holds across the whole fleet. A callback with no transaction cookie, a cookie that does not match the issued row, or an expired/already-consumed row is rejected, and the transaction cookie is cleared on success and on terminal failure. The authoritative post-login `return_to` is read from the persisted row, not the URL, so it cannot be tampered with in transit.
5. `/auth/callback` stays exempt from the generic browser CSRF middleware (it is cross-site by protocol design); this nonce-plus-browser-bound-cookie check is its dedicated, stronger replacement.

## Session Fixation

**Attack.** The attacker sets a known session ID into the victim's browser before login, then uses that same ID after the victim authenticates.

**Defense.** On every successful authentication, we rotate the session ID. The session row before authentication is deleted; a fresh row with a fresh ID is created.

## CSRF

**Attack.** A malicious page tricks the user's browser into sending a state-changing request to Identrail using the victim's session cookie.

**Defenses.**

1. `SameSite=Lax` on the session cookie. The browser does not attach the cookie to cross-site state-changing requests by default. This alone blocks the most common CSRF shapes (forms posted from a malicious page).
2. A request-side CSRF/origin guard on unsafe (`POST`, `PUT`, `PATCH`, `DELETE`) browser session-authenticated dashboard JSON API requests under `/v1/*`. CORS is kept only as a response policy; it is not relied on as the CSRF control. The guard runs after session resolution and only when the request is authenticated by a resolved browser session, so it never interferes with API-key, OIDC bearer, SCIM bearer-token, connector-agent token, OAuth/SAML callback (`/auth/callback`, `/auth/saml/acs/*`), or webhook (`/auth/webhooks/*`) routes — those do not carry the browser session cookie and keep relying on their own auth mechanisms. For a guarded request: a present `Sec-Fetch-Site` header must be `same-origin`, `same-site`, or `none` (`cross-site` is rejected); when a request body content type is present it must be `application/json` (the simple `text/plain` / `application/x-www-form-urlencoded` / `multipart/form-data` types a cross-site HTML form can auto-submit are rejected); and the `Origin` header — or the `Referer` origin when `Origin` is absent — must match a configured first-party origin (`IDENTRAIL_PUBLIC_BASE_URL` plus any explicitly allowed web origins). A cookie-authenticated write with neither `Origin` nor `Referer` is rejected. This stops the same-site-but-cross-subdomain scripted attacks that `SameSite=Lax` does not cover, and rejected requests get `403`.
3. A double-submit CSRF token is issued for the HTML form flows that use a POST (the manual-mode dev login form is the only one in the planned PR set). The token is signed with `IDENTRAIL_SESSION_KEY` and validated server-side.
4. Webhook endpoints (`/auth/webhooks/*`) require an HMAC signature, not a cookie. They reject anything missing the signature.

## Host-Header Injection in Email Links

**Attack.** An attacker spoofs the `Host` header on a request that triggers a password reset, invite, or verification email. If the server uses the request host to build the email link, the link points at the attacker's domain.

**Defenses.**

1. All email links are built from `IDENTRAIL_PUBLIC_BASE_URL`, never from the request host.
2. The server validates `IDENTRAIL_PUBLIC_BASE_URL` at startup. An empty value or an invalid URL refuses to start the server.
3. CI tests check that no code path passes `r.Host` or `c.Request.Host` into a URL builder used for outgoing emails.

## Account Enumeration

**Attack.** An attacker probes signup, login, or password-reset flows and uses the difference between "user exists" and "user does not exist" responses to harvest registered emails.

**Defenses.**

1. We do not run a password flow at all. There is no "wrong password" response to enumerate.
2. WorkOS handles the OAuth and email-OTP flows. Their hosted UI returns identical responses for known and unknown emails.
3. Invitation acceptance and password-style flows we add later use constant-time comparisons (`subtle.ConstantTimeCompare`) and a single generic error message for the "email or token invalid" case.

## SSO Downgrade

**Attack.** Once an org rolls out SSO, an attacker tries to bypass it by hitting a non-SSO login path directly.

**Defenses.**

1. We do not have password endpoints. WorkOS is the auth front door for Cloud, and self-host runs through OIDC.
2. Native SAML and SCIM are feature-flagged behind `IDENTRAIL_FEATURE_NATIVE_SSO`, and native SAML sessions carry `auth_method="saml"` so follow-up enforcement work can distinguish them from WorkOS, OIDC, and manual sessions.
3. Track 1 persists `sso_required` on the native SAML connection but does not yet ship recovery-code generation or a full org lockout-rescue flow. Operators should keep `sso_required=false` until SAML and SCIM have been tested for the tenant.

## SSO Lockout

**Attack** (mostly self-inflicted, not adversarial). An admin enables SSO with a misconfigured IdP and locks themselves out. The IdP itself goes down. The admin's IdP account is suspended.

**Defenses.**

1. Native SAML setup is opt-in and starts with `sso_required=false`.
2. Admins test real SAML login through `/auth/saml/login/{connection_id}` and `/auth/saml/acs/{connection_id}` before changing the rollout marker.
3. Admins enable SCIM and verify create/update/deactivate flows before treating the IdP as the source of truth.
4. The complete recovery-code and enforcement-toggle flow remains follow-up work and should not be represented as shipped Track 1 behavior.

## Identity-Linking Account Takeover

**Attack.** Alice signs up with Google using `alice@acme.com`. Mallory creates a GitHub account claiming `alice@acme.com` as a non-verified secondary email. Mallory signs in to Identrail with GitHub. If Identrail auto-links by email, Mallory now has access to Alice's org.

**Defenses.** This attack has its own document because the rules are subtle and the consequence is severe. See [`identity-linking-rules.md`](./identity-linking-rules.md).

The short version: Identrail never auto-links identities by email. Email-claim equality alone is not proof of ownership. Linking always requires the user to be currently authenticated as the original identity, then explicitly link the second one.

## Invitation Token Replay

**Attack.** An invitation link is leaked (forwarded email, sent through a shared chat). Multiple parties try to accept it, or an attacker tries to accept after the rightful invitee.

**Defenses.**

1. Invitation tokens are 32 random bytes, stored hashed (SHA-256) in the database.
2. Tokens are single-use. The first acceptance marks the row consumed.
3. Tokens expire after 24 hours.
4. The acceptance endpoint requires the accepter's authenticated email (from their session) to match the invitation's target email.
5. If the accepter does not have an existing Identrail account, they go through the normal sign-up flow first, then return to the invitation.

## Mass Session Invalidation Race

**Attack.** When a user is removed via SCIM or future SSO enforcement revokes non-SSO access, we need to invalidate all their sessions quickly. A race could let an in-flight request slip through.

**Defenses.**

1. The session check happens in middleware on every request, against the database. There is no in-memory cache of "session is valid."
2. Revocation marks `sessions.revoked_at` and (in the SCIM hard-delete case) deletes the row outright. The next request from that session fails.
3. Future mass-revoke jobs should process serially per org with a small batch size, so a single org cannot starve other orgs.
4. Per-user revocation is constant-time: one DELETE query keyed on `user_id`.

## Webhook Replay and Forgery

**Attack.** WorkOS or GitHub webhooks are replayed by an attacker, or a forged webhook is posted to our public endpoint.

**Defenses.**

1. Every webhook endpoint requires an HMAC signature header. The signature is verified using a per-provider secret (`IDENTRAIL_WORKOS_WEBHOOK_SECRET`, `IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET`).
2. Verification uses `subtle.ConstantTimeCompare`.
3. Each webhook event has a provider-issued ID. We store seen IDs in a small idempotency table; replays are no-ops.
4. Rate limits on the webhook endpoint absorb floods.

## Connector Credential Leakage

**Attack.** The cloud credentials a customer entrusts to Identrail (AWS role ARN, Kubernetes kubeconfig, GitHub PAT or installation token) are leaked from the database.

**Defenses.**

1. All connector credentials live in `tenancy_connector_secret_envelopes`, encrypted at rest with a key chain rooted at `IDENTRAIL_CONNECTOR_SECRET_KEYS`.
2. AWS credentials use the role-assume pattern with a per-connection External ID. The actual access is scoped by the role's trust policy on the customer's side; we never hold static long-lived AWS keys.
3. GitHub uses the App installation pattern where possible; the token is minted on demand from the installation ID, not stored.
4. Kubernetes uses the agent pattern where possible; the agent's credential lives in-cluster, and we hold only an enrollment record.
5. Audit log entries on credential read/refresh use fingerprinted identifiers, not plaintext.

## DNS and Verified-Domain Spoofing

**Attack.** An attacker tries to claim a domain they do not own to enable domain auto-join into someone else's org or to set up SSO at the victim's domain.

**Defenses.**

1. Domain ownership requires a DNS TXT record placement at a record name we generate (`_identrail-verify.<domain>`). The value is a single-use token tied to the org.
2. We re-verify the TXT record periodically, not just at the moment of first verification. If the record disappears, the domain reverts to unverified and any auto-join behavior tied to it stops.
3. Domain auto-join requires both `verified_domains.verified_at IS NOT NULL` and an admin-toggled `auto_join_enabled` flag. Verification alone does not enable auto-join.

## Privilege Escalation via Stale Sessions

**Attack.** A user's role is downgraded from `admin` to `viewer` (or removed entirely). An existing session keeps using cached `admin` privileges.

**Defenses.**

1. The `currentSession` middleware reads role from the database on every request, not from the session row. Role downgrades take effect on the next request.
2. Role downgrade triggers a session refresh: `tenancy_workspace_members.updated_at` changing causes any cached state in the request handler to be discarded.
3. Session-bound API keys (if the user holds any) are revoked when the user's `tenancy_workspace_members.role` is downgraded below the API key's required scope.

## Time-of-Check vs Time-of-Use in Connector Validation

**Attack.** A user proves they own an AWS account at connector creation. Later, the role's trust policy changes to allow a different account to assume it. Identrail does not notice and continues scanning under what is now an attacker-controlled role.

**Defenses.**

1. The External ID we generate is per-connector and unique. An attacker who somehow gains write access to the customer's IAM cannot redirect Identrail's scanning to a role they control without also rewriting the External ID.
2. Each scan starts with an `sts:GetCallerIdentity` probe. If the account ID changes from what we recorded, the scan is aborted and the connector is marked `disconnected` with an audit event.
3. Connector revocation is one API call, immediate.

## What This Document Is Not

This document does not cover:

- Threats against the marketing site (`www.identrail.com`). That is a static site with different threat surface.
- Threats against the scanned cloud accounts themselves. Identrail is a read-only observer; we do not modify customer infrastructure.
- Insider threats from Identrail employees. That is a separate document covering operational security, key rotation, and audit review processes.
- DDoS at the network layer. That is handled at the CDN and load-balancer layer, not in the auth code.
