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
2. GitHub login returns to Identrail without `{"error":"login failed"}`.
3. A new user with no workspace lands on `/onboarding/org`.
4. Creating organization and workspace redirects to the scoped `/app/<org>/<workspace>` dashboard.

## Checks

Static URL validation catches missing values, non-HTTPS values, and accidental web origins:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-url-check
```

Full preflight probes the live API endpoints:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-preflight
```

Run the full preflight after DNS and TLS are live for `api.identrail.com`, and before changing Vercel production variables.
