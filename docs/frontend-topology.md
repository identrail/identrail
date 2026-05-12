# Frontend Topology

Identrail uses `web/` as the active tracked frontend on `dev`.

## `web/` (product dashboard)

- Stack: Vite + React
- Purpose: operator-facing app experience tied to API workflows
- Product shell route group: `/app/*` for authenticated workflows
  - Login gateway: `/app/login`
  - Scoped shell paths: `/app/:tenantID/:workspaceID/*`
- Typical runtime: containerized deployment (`deploy/docker/Dockerfile.web`, optional Helm `web.enabled`)
- API URL input: `VITE_IDENTRAIL_API_URL`
- Vercel (marketing/demo deploy): set `VITE_IDENTRAIL_API_URL` in Vercel project environment variables (or set GitHub Actions variable `VITE_IDENTRAIL_API_URL` so the deploy workflow upserts it).
- Production deploys should be triggered from `dev` (example: `make vercel-prod-deploy` / `task vercel-prod-deploy`) to avoid accidentally deploying from a stale local branch.

### `VITE_IDENTRAIL_API_URL` value source

- This value should be the public HTTPS base URL of the Identrail API service (not the website URL).
- Typical value shape: `https://api.<your-domain>`
- If the API is served from the same domain via reverse proxy, use that public API base path.
- Configure the API deployment with `IDENTRAIL_CORS_ALLOWED_ORIGINS` set to the web app origin when the frontend and API use different origins.
- The default Vercel CSP allows `https://api.identrail.io`; update `connect-src` when using a custom API host.
- For Identrail Cloud, use `https://api.identrail.com` once that API domain is live. Do not use `https://identrail.com`, `https://www.identrail.com`, or `https://app.identrail.com`; those are web origins.

### Where to configure it

1. GitHub repository variable:
   - `Settings` -> `Secrets and variables` -> `Actions` -> `Variables`
   - Add `VITE_IDENTRAIL_API_URL`
2. Vercel project environment variable:
   - `Project` -> `Settings` -> `Environment Variables`
   - Add `VITE_IDENTRAIL_API_URL` for Production (and Preview if needed)

For token-based Vercel deployments, if the GitHub Actions variable is missing, the production deploy workflow fails before deployment so the web app cannot ship without an explicit API URL. Hook-only fallback deployments cannot read Vercel project env values from GitHub Actions; keep `VITE_IDENTRAIL_API_URL` configured directly in Vercel and run the preflight manually before relying on the hook fallback.

### Production API preflight

Before wiring or rotating the Vercel value, run:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-preflight
```

The preflight verifies that `/healthz` and `/v1/auth/config` return API responses instead of the frontend HTML shell. Use `make production-api-url-check` when the API is not live yet and only static URL validation is needed.

See [Production API Readiness](./auth/production-api-readiness.md) for the full API/web domain checklist.

## `site/` (legacy Next.js marketing surface)

- Stack: Next.js
- Purpose: public marketing/documentation landing pages
- Typical runtime: Vercel-hosted static/dynamic site
- Not part of the core API/worker runtime path
- Not tracked in this branch snapshot; local leftovers can drift from API contract and should not be treated as source of truth.

## Operational Guidance

- Treat `web/` as product UI release surface coupled to API compatibility.
- Treat `site/` as legacy/branch-specific surface unless explicitly restored and reviewed.
- Validate both in CI where relevant, but keep deployment ownership boundaries explicit.
