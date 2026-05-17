# Identity Linking Rules

This document describes the rules for connecting external provider identities (WorkOS, GitHub, Google, future SAML connections) to Identrail user accounts. The rules look strict on purpose. The exploit they prevent is severe and the consequence of getting it wrong is account takeover.

Read this before writing any code that touches `user_identities`.

## The Exploit We Are Defending Against

Alice signs up to Identrail with Google. Her Google account uses `alice@acme.com`. Identrail creates `users.id = U1` and `user_identities` row `(provider="google", subject="<google sub>", email="alice@acme.com")`.

Mallory creates a GitHub account. They claim `alice@acme.com` as a secondary email. GitHub does not strictly require Mallory to prove ownership of secondary emails in every flow, especially older accounts.

Mallory clicks "Continue with GitHub" on Identrail.

If Identrail naively links by email, the callback handler sees an existing user with `primary_email = "alice@acme.com"` and attaches the new GitHub identity to Alice's account. Mallory now signs in as Alice and inherits every org, workspace, role, and connector Alice has access to.

The defense is simple to state and easy to get wrong: **email match is not proof of ownership**. We never auto-link.

## Rule 1: One identity per user is created at signup

When a callback arrives and we cannot find a matching `(provider, subject)` row in `user_identities`, we treat it as a brand-new user. We never look up existing users by email at this stage, regardless of whether the new identity carries an `email_verified` claim.

`users.primary_email` is `UNIQUE`, which means we cannot persist two `users` rows with the same email. We resolve the collision deliberately rather than auto-linking:

- The new `users` row is created with `primary_email = NULL`. The email captured from the IdP is stored on the new `user_identities` row (`user_identities.email`) for display and audit only.
- The new user can claim the email later from `/app/account/security` by proving ownership through authenticated linking: sign in with the original identity tied to that email and link the new identity. This flow folds the new `user_identities` row under the existing `users` row instead of producing a second account.
- This trades a small amount of UX friction for a clean security property: the schema cannot end up with two distinct users claiming the same canonical email.

## Rule 2: Email-claim equality alone is never proof

When deciding whether to act on the email claim from a provider, we apply two checks:

1. The provider must mark the email as verified. WorkOS, Google, and Microsoft set `email_verified=true` for emails the IdP has confirmed. GitHub returns `verified=true` only for emails the user has confirmed. Any value other than explicit `true` is treated as unverified and the email is treated as opaque text.
2. Even with `email_verified=true`, we use the email for display and matching against pending invitations. We do not use it for linking to an existing account.

Generic OIDC claims `email` and `email_verified` follow OpenID Connect Core 1.0. If your IdP does not set `email_verified`, our middleware logs a warning and treats the email as unverified.

## Rule 3: Linking requires authenticated linking

A user who genuinely wants to use both Google and GitHub for one Identrail account does this:

1. Sign in via the original identity (say, Google). Now have an authenticated session.
2. Visit `/app/account/security`.
3. Click "Link another sign-in method."
4. Get redirected through a fresh OAuth round-trip with the second provider (GitHub). The returning callback verifies the new identity belongs to the same physical user (they had the existing session and they completed a fresh auth on the new provider).
5. The server inserts a new `user_identities` row pointing at the same `users.id`.

Two safety checks during linking:

- The new identity's `(provider, subject)` must not already point at a different `users.id`. If it does, the link fails with a clear error: "This GitHub account is already linked to a different Identrail user."
- The new identity's email, if `email_verified=true`, is recorded on the new `user_identities` row but does not become the user's `primary_email`. Changing `primary_email` is a separate action with its own confirmation flow.

Every link emits `auth.identity.linked` audit event.

## Rule 4: Unlinking always leaves a working path

A user cannot unlink their last remaining identity. The user must always have at least one active `user_identities` row. The unlink endpoint refuses to delete the last row and returns a clear error.

A user with both Google and GitHub linked who unlinks Google: their Google
`user_identities` row is deleted, the Identrail account stays, GitHub still
works. Future recovery-code work can add another break-glass path, but Track 1
native SAML does not ship recovery codes.

Every unlink emits `auth.identity.unlinked` audit event.

## Rule 5: Domain auto-join requires DNS verification AND admin opt-in

Domain auto-join is the convenience feature where someone signing up with `@acme.com` discovers an existing Acme org and can join it. It is not a default behavior.

Two conditions must both be true:

1. The org has a `verified_domains` row matching the new user's email domain, with `verified_at IS NOT NULL`. Verification requires placing a DNS TXT record we generate at `_identrail-verify.<domain>`.
2. An admin has explicitly toggled `auto_join_enabled=true` for that verified domain.

Even when both conditions hold, the new user sees a "Join Acme?" prompt. We never silently add a user to an org. The user must click "Join."

Domain reverification runs as a background job. If the TXT record disappears, `verified_at` is cleared and auto-join stops working until the record is restored.

## Rule 6: Invitation acceptance verifies the accepter

Invitations are emailed to a specific address. The acceptance flow:

1. Invitee receives email with a single-use link.
2. Link goes to `/app/invite/<token>`.
3. If the invitee is not signed in, they go through normal signup or sign-in first, then return to the invite.
4. Once authenticated, the server checks: does the invitee's authenticated email (from their session, via `users.primary_email` or a `user_identities.email` with `email_verified=true`) match the invitation's target email?
5. If yes, the invite is accepted. If no, the invite stays pending and the invitee sees: "This invitation was sent to `<other email>`. Sign in with that email to accept it."

This stops the case where Mallory steals an invite link emailed to Alice and accepts it from Mallory's own account.

## Rule 7: Email change does not propagate identity ownership

`primary_email` can change in two ways: a user-initiated change from inside
Identrail, and an IdP-driven change delivered via the `user.email_changed`
webhook. Both updates write to `users.primary_email` through the same code path
and follow the same rule below: the change is purely cosmetic for relationship
ownership. It does not affect:

- Which `user_identities` rows belong to them.
- Whether they can be invited to a different org tomorrow under the new email.
- Whether they auto-qualify for a different verified-domain auto-join.

Email changes update display, notification destination, and pending-invitation matching for invitations sent in the future. They do not retroactively rewrite existing relationships.

## Provider-Specific Notes

### WorkOS

WorkOS is the primary IdP for hosted Identrail. The WorkOS user `sub` becomes `user_identities.subject` with `provider="workos"`. WorkOS marks emails as verified per provider; we trust the `email_verified` field they pass through.

When WorkOS sends a `user.deleted` webhook, we set the `users.status` to `deactivated`, revoke all sessions, but retain the row for audit. The `user_identities` row stays in place; it is the historical record of which WorkOS account was that user.

If WorkOS requires MFA enrollment or an MFA challenge during hosted sign-in, Identrail does not create a local session from the first callback. The API stores the WorkOS pending-auth token only in a short-lived encrypted HttpOnly cookie scoped to `/auth/mfa`, redirects the browser to the app MFA page, and creates the Identrail session only after WorkOS accepts the TOTP verification response.

### GitHub

GitHub identities use `provider="github"` and `subject` set to the GitHub user ID (numeric, stable, never reused). Do not use the GitHub username as the subject; usernames can be renamed and reassigned.

GitHub returns multiple emails. Hosted WorkOS GitHub OAuth requests GitHub's `user:email` scope so users whose primary email is private can still complete sign-in with a verified email. We use the user's primary email if `verified=true`. If no email is verified, we treat the identity as having no email and do not auto-fill any user fields.

### Google and Microsoft

Both follow OIDC Core. `sub` is the subject. `email_verified=true` is required for the email to be trusted.

### Generic OIDC (self-host)

`provider` is `oidc:<issuer>` so two self-hosters running different IdPs cannot collide. `subject` is the OIDC `sub` claim.

If the OIDC token does not include `email_verified`, the email is treated as unverified.

## Audit Events for Identity Linking

| Event | When |
| --- | --- |
| `auth.signup` | New user created, first identity attached |
| `auth.identity.linked` | Existing user added a second identity |
| `auth.identity.unlinked` | Existing user removed an identity (not their last) |
| `auth.identity.unlink.refused` | User tried to remove their last identity |
| `auth.identity.conflict` | Sign-in attempt produced an identity that points at a different user than the active session |
| `auth.invitation.accepted.email_mismatch` | Invitation accept attempted with wrong email |
| `auth.domain.auto_join.suggested` | User saw the "Join `<Org>`?" prompt |
| `auth.domain.auto_join.declined` | User saw the prompt and clicked away |
| `auth.domain.auto_join.accepted` | User saw the prompt and clicked Join |

All events flow through the existing audit pipeline with `Kind="action"` and the actor field fingerprinted per the existing audit rules.

## Test Matrix (across PRs 4, 5, 11)

| Scenario | Expected |
| --- | --- |
| Sign up with Google `alice@acme.com`. Sign up separately with GitHub claiming `alice@acme.com`. | Two distinct `users` rows. No silent merge. |
| Linked user (Google + GitHub). Sign in via either. | Same session destination. Same `users.id`. |
| Sign in via GitHub when that GitHub identity is already linked to a different `users.id`. | 409 Conflict, audit event `auth.identity.conflict`. |
| Unlink the only `user_identities` row. | 400 Bad Request, audit event `auth.identity.unlink.refused`. |
| Accept an invite while signed in as a different email. | Invite stays pending. UI explains. Audit event recorded. |
| Auto-join enabled on a verified domain. New user signs up with that domain. | Sees "Join `<Org>`?" prompt. Does not silently join. |
| Verified-domain TXT record removed by domain owner. | `verified_at` clears. Auto-join offering stops. |
| OIDC token without `email_verified`. | Email is treated as unverified. No matching against pending invitations. |
| GitHub identity with no verified primary email. | Sign-in succeeds (GitHub `sub` is the identity), no email is recorded on `user_identities`. |
