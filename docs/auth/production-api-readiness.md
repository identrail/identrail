# Production API Readiness

This is the operational bridge between the frontend auth UI and the hosted API.

The frontend auth pages are intentionally unable to call an unknown backend in production. Before Vercel can serve working sign-in and sign-up flows, the public API must exist and the web build must point at it.

## Target Shape

```text
identrail.com       -> Vercel web
www.identrail.com   -> Vercel web
app.identrail.com   -> Vercel web/app
api.identrail.com   -> Identrail API
```

`VITE_IDENTRAIL_API_URL` must point at the API origin:

```text
VITE_IDENTRAIL_API_URL=https://api.identrail.com
```

It must not point at `https://identrail.com`, `https://www.identrail.com`, or `https://app.identrail.com`.
When the production web bundle is served from the canonical Identrail Cloud
domains (`identrail.com`, `www.identrail.com`, or `app.identrail.com`), it uses
`https://api.identrail.com` as a safe default if `VITE_IDENTRAIL_API_URL` was not
injected at build time. Self-hosted and custom-domain deployments still need an
explicit `VITE_IDENTRAIL_API_URL` value so they never guess the wrong API.

## API Requirements

Before wiring the frontend to the production API URL, the API deployment must expose:

- `GET /healthz` returning `200`
- `GET /readyz` returning `200` only after runtime dependencies are ready
- `GET /v1/auth/config` returning JSON, not the web HTML shell
- `POST /v1/onboarding/start` returning the unauthenticated JSON `401`
  session-required response (not a `404`, plain-text framework `404`, or web
  HTML shell) so the onboarding wizard is never enabled against a backend that
  cannot serve `/v1/onboarding/*`
- `IDENTRAIL_CORS_ALLOWED_ORIGINS` containing the web origins that need browser access
- `IDENTRAIL_TRUSTED_PROXIES` containing the ALB/VPC proxy CIDRs so rate limits
  and audit events use the real browser client IP from `X-Forwarded-For`
- `IDENTRAIL_PUBLIC_BASE_URL` set to the API origin when WorkOS callbacks terminate at the API
- `IDENTRAIL_FEATURE_NEW_AUTH=true`
- `IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true` so first-time GitHub/WorkOS users can create their org and workspace after login
- `IDENTRAIL_SESSION_KEY` set from at least 32 bytes of secret key material
- persistent storage through `IDENTRAIL_DATABASE_URL`

For Identrail Cloud, the first production API deployment should use:

```text
IDENTRAIL_CORS_ALLOWED_ORIGINS=https://identrail.com,https://www.identrail.com,https://app.identrail.com
IDENTRAIL_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
IDENTRAIL_PUBLIC_BASE_URL=https://api.identrail.com
IDENTRAIL_FEATURE_NEW_AUTH=true
IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true
VITE_IDENTRAIL_API_URL=https://api.identrail.com
VITE_FEATURE_ONBOARDING_WIZARD=true
```

## Self-serve onboarding activation

The hosted GitHub login path ends in the product app with a server session. If
that user has no workspace membership yet, the production app must route them
into onboarding instead of rendering the workspace-required fallback.

The production deployment paths set this pair by default:

```text
IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true
VITE_FEATURE_ONBOARDING_WIZARD=true
```

`IDENTRAIL_FEATURE_ONBOARDING_WIZARD` enables the `/v1/onboarding/*` API
contract. The AWS API manual deploy workflow sets it through
`API_FEATURE_ONBOARDING_WIZARD`, which defaults to `true` for Identrail Cloud
and can be set to `false` for rollback. `VITE_FEATURE_ONBOARDING_WIZARD` enables
the web route guard that sends logged-in users without `org_id` and
`workspace_id` to `/onboarding/org`. The token-based Vercel production workflow
upserts the web flag before deploy, defaults it to `true`, and reads the
repository variable `VITE_FEATURE_ONBOARDING_WIZARD` so rollback can set both
backend and frontend flags to `false`. Hook-only deploys must keep the Vercel
project env value configured directly.

After deploying both halves, verify:

1. `GET https://api.identrail.com/v1/auth/config` shows hosted GitHub login is available.
2. `POST https://api.identrail.com/v1/onboarding/start` without a session returns JSON `401`, not a plain `404 page not found`.
3. GitHub login returns to Identrail without `{"error":"login failed"}`.
4. A new user with no workspace lands on `/onboarding/org`.
5. Creating organization and workspace redirects to the scoped `/app/<org>/<workspace>` dashboard.

## Checks

Static URL validation catches missing values, non-HTTPS values, and accidental web origins:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-url-check
```

Full preflight probes the live API endpoints — `GET /healthz`,
`GET /v1/auth/config`, and `POST /v1/onboarding/start`:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-preflight
```

The onboarding probe passes only on the unauthenticated JSON `401`
session-required response. It fails closed otherwise, and the failure prefix
names the cause so it is clear whether the problem is API URL wiring, a missing
route registration, or a non-JSON frontend/404 response:

- `api-url-wiring` — an HTML frontend shell was returned; `VITE_IDENTRAIL_API_URL`
  points at the web app instead of the API origin.
- `missing-route` — the route returned `404`; the API build does not register
  `/v1/onboarding/start` (an API image predating the onboarding route, or a
  wrong API base path).
- `non-json` / `unexpected-status` — a plain-text framework `401` or any other
  status; the route is not serving the expected JSON contract.

Scope: this is an unauthenticated check of route presence and JSON contract
shape. The backend `IDENTRAIL_FEATURE_ONBOARDING_WIZARD` flag is intentionally
not observable here — the onboarding routes deliberately answer unauthenticated
callers with the same JSON `401` whether the flag is on or off (an authenticated
caller gets `503 {"error":"onboarding disabled"}` when it is off). Verifying the
flag is enabled is therefore covered by the authenticated post-deploy steps
above (a new user with no workspace must land on `/onboarding/org`), not by this
preflight.

This keeps the check generic for both Identrail Cloud and self-hosted production
API URLs: it asserts the unauthenticated contract shape, not a specific host.

Run the full preflight after DNS and TLS are live for `api.identrail.com`, and before changing Vercel production variables.
