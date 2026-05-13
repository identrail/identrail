# Production API Readiness

PR 6 is the operational bridge between the merged frontend auth UI and the later provider/onboarding work.

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
- `IDENTRAIL_SESSION_KEY` set from at least 32 bytes of secret key material
- persistent storage through `IDENTRAIL_DATABASE_URL`

For Identrail Cloud, the first production API deployment should use:

```text
IDENTRAIL_CORS_ALLOWED_ORIGINS=https://identrail.com,https://www.identrail.com,https://app.identrail.com
IDENTRAIL_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
IDENTRAIL_PUBLIC_BASE_URL=https://api.identrail.com
VITE_IDENTRAIL_API_URL=https://api.identrail.com
```

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
