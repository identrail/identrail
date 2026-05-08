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
- The default Vercel CSP allows `https://api.identrail.io`; update `connect-src` when using a custom API host.

### Where to configure it

1. GitHub repository variable:
   - `Settings` -> `Secrets and variables` -> `Actions` -> `Variables`
   - Add `VITE_IDENTRAIL_API_URL`
2. Vercel project environment variable:
   - `Project` -> `Settings` -> `Environment Variables`
   - Add `VITE_IDENTRAIL_API_URL` for Production (and Preview if needed)

If the GitHub Actions variable is missing, the production deploy workflow fails before deployment so the web app cannot ship without an explicit API URL.

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
