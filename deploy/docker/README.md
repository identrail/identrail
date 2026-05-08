# Docker Deployment

## Files

- `Dockerfile.backend`: builds API or worker image (`TARGET=server|worker`)
- `Dockerfile.web`: builds dashboard web image
  - production builds use the strict nginx CSP by default; Compose passes `NGINX_CONF=default.local.conf` for localhost API access.
- `docker-compose.yml`: local single-host stack
- `.env.example`: environment template

## Quick Start

Fastest local onboarding:

1. `make quickstart`

The quickstart creates `deploy/docker/.env` with `0600` permissions, rotates template
secrets automatically, and prints follow-up commands without exposing raw API keys.

Manual setup:

1. `cp deploy/docker/.env.example deploy/docker/.env`
2. Edit keys and secrets in `deploy/docker/.env`
   - set `IDENTRAIL_POSTGRES_PASSWORD` to a strong value
   - local dashboard CORS is enabled by default via `IDENTRAIL_CORS_ALLOWED_ORIGINS=http://localhost:8081`
   - for live k8s collection: set `IDENTRAIL_K8S_SOURCE=kubectl`
   - optional context override: `IDENTRAIL_KUBE_CONTEXT`
3. `docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build`

## Verify
### Production notes

The default Compose file is a local quickstart profile. Do not reuse its `sslmode=disable` database URLs or localhost web API URL for production. For single-host production-like deployments, adapt `docker-compose.prod.example.yml` with a TLS-enabled Postgres URL, a public HTTPS API URL, and a reverse proxy that owns external ports and TLS.

Apply database migrations before starting API and worker services:

- `docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.prod.example.yml run --rm migrations`
- `docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.prod.example.yml up -d api worker web`


- API health: `curl http://localhost:8080/healthz`
- Web UI: `http://localhost:8081`

Ports bind to `127.0.0.1` by default. For non-local access, put the API and web service behind a TLS reverse proxy or explicitly override the Compose port bindings on a protected host.
