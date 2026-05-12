# Docker Deployment

## Files

- `Dockerfile.backend`: builds API or worker image (`TARGET=server|worker`)
- `Dockerfile.web`: builds dashboard web image
  - production builds use the strict nginx CSP by default; Compose passes `NGINX_CONF=default.local.conf` for localhost API access.
- `docker-compose.yml`: local single-host stack
- `docker-compose.public.yml`: public-image evaluation stack that pulls from GHCR
- `docker-compose.prod.example.yml`: production profile override (TLS URLs, migration service, exposed ports)
- `docker-compose.security.example.yml`: least-privilege runtime hardening override (`read_only`, dropped capabilities, `no-new-privileges`)
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

## Public Images

For a no-build evaluation path, pull the main Identrail image:

```bash
docker pull ghcr.io/identrail/identrail:dev
```

Run the API server by itself with disposable in-memory storage:

```bash
docker run --rm -p 8080:8080 \
  -e IDENTRAIL_ALLOW_MEMORY_STORE=true \
  -e IDENTRAIL_RUN_MIGRATIONS=false \
  -e IDENTRAIL_API_KEYS=identrail-local-read-key-change-me,identrail-local-write-key-change-me \
  -e IDENTRAIL_WRITE_API_KEYS=identrail-local-write-key-change-me \
  ghcr.io/identrail/identrail:dev
```

Then verify it with:

```bash
curl http://localhost:8080/healthz
```

To run the full local stack from public images:

```bash
docker compose -f deploy/docker/docker-compose.public.yml up -d
```

The public stack starts Postgres, API, worker, and web without building from
source. Open `http://localhost:8081` for the web UI and use
`http://localhost:8080` for the API. The `dev` web image pre-fills the local
write API key from this Compose profile so the no-build dashboard can call the
API immediately; change the Compose API keys and build your own web image for
non-local deployments.

Supporting images are published for multi-service deployments:

```bash
docker pull ghcr.io/identrail/identrail-worker:dev
docker pull ghcr.io/identrail/identrail-web:dev
docker pull ghcr.io/identrail/identrail-api:dev
```

Each `dev` publish also creates immutable `sha-<12-char-sha>` tags. Release
images use SemVer tags such as `ghcr.io/identrail/identrail:v1.0.0`.

After the first publish, a repository maintainer may need to make the GHCR
packages public in GitHub Packages if the organization default is private.

Production-style hardening example:

- `docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.prod.example.yml -f deploy/docker/docker-compose.security.example.yml --env-file deploy/docker/.env run --build --rm migrations`
- `docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.prod.example.yml -f deploy/docker/docker-compose.security.example.yml --env-file deploy/docker/.env up -d --build api worker web`

## Verify
### Production notes

The default Compose file is a local quickstart profile. Do not reuse its `sslmode=disable` database URLs or localhost web API URL for production. For single-host production-like deployments, adapt `docker-compose.prod.example.yml` with a TLS-enabled Postgres URL, a public HTTPS API URL, and a reverse proxy that owns external ports and TLS, then layer `docker-compose.security.example.yml` for runtime hardening.

Apply database migrations before starting API and worker services:

- `docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.prod.example.yml -f deploy/docker/docker-compose.security.example.yml run --build --rm migrations`
- `docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.prod.example.yml -f deploy/docker/docker-compose.security.example.yml up -d api worker web`


- API health: `curl http://localhost:8080/healthz`
- Web UI: `http://localhost:8081`

Ports bind to `127.0.0.1` by default. For non-local access, put the API and web service behind a TLS reverse proxy or explicitly override the Compose port bindings on a protected host.
