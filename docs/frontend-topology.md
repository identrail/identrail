# Frontend Topology

Identrail uses `web/` as the active tracked frontend on `dev`. It owns both
the public website routes and the authenticated product dashboard.

## `web/` (Public Website and Product Dashboard)

- Stack: Vite + React
- Purpose: public website, docs/resource pages, and operator-facing app experience tied to API workflows
- Product shell route group: `/app/*` for authenticated workflows
  - Login gateway: `/app/login`
  - Scoped shell paths: `/app/:tenantID/:workspaceID/*`
- Typical runtime: containerized deployment (`deploy/docker/Dockerfile.web`, optional Helm `web.enabled`)
- API URL input: `VITE_IDENTRAIL_API_URL`
- Self-serve onboarding input: `VITE_FEATURE_ONBOARDING_WIZARD=true`
- Vercel (marketing/demo deploy): Identrail Cloud domains default to `https://api.identrail.com`; custom domains should set `VITE_IDENTRAIL_API_URL` in Vercel project environment variables or as a GitHub Actions variable so the deploy workflow upserts it. Identrail Cloud production deploys also upsert `VITE_FEATURE_ONBOARDING_WIZARD`, defaulting to `true`, and the connector build flags (`VITE_FEATURE_CONNECTOR_AWS`, `VITE_FEATURE_CONNECTOR_GITHUB_V2`, `VITE_FEATURE_CONNECTOR_K8S`), defaulting to `false`, so the web bundle cannot drift from the intended connector launch state.
- Production deploys should be triggered from `dev` (example: `make vercel-prod-deploy` / `task vercel-prod-deploy`) to avoid accidentally deploying from a stale local branch.

### `VITE_IDENTRAIL_API_URL` value source

- This value should be the public HTTPS base URL of the Identrail API service (not the website URL).
- Typical value shape: `https://api.<your-domain>`
- If the API is served from the same domain via reverse proxy, use that public API base path.
- Configure the API deployment with `IDENTRAIL_CORS_ALLOWED_ORIGINS` set to the web app origin when the frontend and API use different origins.
- The default Vercel CSP allows `https://api.identrail.com`, the legacy `https://api.identrail.io`, and any configured `VITE_IDENTRAIL_API_URL` origin; update `connect-src` when using another custom API host.
- For Identrail Cloud, the production web bundle falls back to `https://api.identrail.com` when it is served from `identrail.com`, `www.identrail.com`, or `app.identrail.com`. Do not use `https://identrail.com`, `https://www.identrail.com`, or `https://app.identrail.com`; those are web origins.

### Where to configure it

1. GitHub repository variable:
   - `Settings` -> `Secrets and variables` -> `Actions` -> `Variables`
   - Add `VITE_IDENTRAIL_API_URL`
2. Vercel project environment variable:
   - `Project` -> `Settings` -> `Environment Variables`
   - Add `VITE_IDENTRAIL_API_URL` for Production (and Preview if needed)

### Self-serve onboarding flag

Identrail Cloud production web builds should set:

```text
VITE_FEATURE_ONBOARDING_WIZARD=true
```

The token-based Vercel production deploy workflow upserts this value before the deploy action runs. It defaults to `true` for Identrail Cloud and reads the repository variable `VITE_FEATURE_ONBOARDING_WIZARD` when an operator needs to set the matching web rollback value to `false`. If the workflow falls back to a deploy hook, GitHub Actions cannot update Vercel project env values; keep `VITE_FEATURE_ONBOARDING_WIZARD=true` configured directly in Vercel before using hook-only deploys, or flip that Vercel value directly during rollback.

### Connector web flags

Connector UI availability is a two-sided contract:

```text
IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=true
VITE_FEATURE_CONNECTOR_GITHUB_V2=true
```

The API advertises backend availability through `/v1/auth/config`, but the Vercel web bundle must also be built with the matching `VITE_FEATURE_CONNECTOR_*` flag. Otherwise the onboarding connector card renders as "not included in this web build" even when the API can serve the connector route.

For Identrail Cloud production deploys, configure GitHub Actions variables for each connector flag:

```text
VITE_FEATURE_CONNECTOR_AWS=false
VITE_FEATURE_CONNECTOR_GITHUB_V2=true
VITE_FEATURE_CONNECTOR_K8S=false
```

The Vercel production deploy workflow validates these values as `true`/`false` and upserts them into the Vercel project before building. Missing connector variables default to `false`.

For token-based Vercel deployments, if the GitHub Actions variable is missing, the production deploy workflow uses the Identrail Cloud default and upserts `VITE_IDENTRAIL_API_URL=https://api.identrail.com` into Vercel. Hook-only fallback deployments cannot upsert or inspect Vercel project env values from GitHub Actions, so the runtime fallback still protects the canonical Identrail Cloud domains while custom domains must keep `VITE_IDENTRAIL_API_URL` configured directly in Vercel.

### Production API preflight

Before wiring or rotating the Vercel value, run:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-preflight
```

The preflight verifies that `/healthz` and `/v1/auth/config` return API responses instead of the frontend HTML shell. Use `make production-api-url-check` when the API is not live yet and only static URL validation is needed.

See [Production API Readiness](./auth/production-api-readiness.md) for the full API/web domain checklist.

## Operational Guidance

- Treat `web/` as the only frontend release surface coupled to API compatibility.
- Do not restore a separate `site/` tree without a design and deployment review;
  stale frontend roots create duplicated routes, stale env handling, and broken
  docs ownership.
- Keep deployment ownership boundaries explicit: `web/` ships the frontend,
  `internal/api` ships the API, and workers process asynchronous scans.
