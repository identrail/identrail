# Docker Deployment

## Files

- `Dockerfile.backend`: builds API or worker image (`TARGET=server|worker`)
- `Dockerfile.web`: builds dashboard web image
  - production builds use the strict nginx CSP by default; Compose passes `NGINX_CONF=default.local.conf` for localhost API access.
- `docker-compose.yml`: local single-host stack
- `docker-compose.public.yml`: public-image evaluation stack that pulls from Docker Hub
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

`docker pull` only downloads an image into Docker's image store. It does not
create a project folder, `.env` file, or runnable multi-service stack on disk.

For a no-clone, no-build evaluation path, download the published Compose file
and run it directly. The public stack pulls from Docker Hub by default:

```bash
mkdir identrail-docker && cd identrail-docker
curl -fsSLO https://raw.githubusercontent.com/identrail/identrail/dev/deploy/docker/docker-compose.public.yml
docker compose -f docker-compose.public.yml up -d
```

Then verify it with:

```bash
curl http://localhost:8080/healthz
```

Open `http://localhost:8081` for the web UI, use **Continue in dev mode**, and
the stack will create a disposable local session against the API container.
The quickstart exposes only the web UI and API on your machine. Postgres stays
inside the Docker network, which avoids conflicting with an existing local
database.

If you want to customize the image tag, local secrets, or ports before running:

```bash
curl -fsSLO https://raw.githubusercontent.com/identrail/identrail/dev/deploy/docker/.env.public.example
cp .env.public.example .env
docker compose -f docker-compose.public.yml --env-file .env up -d
```

If `8081` is already in use on your machine, set `IDENTRAIL_WEB_PORT` in the
downloaded `.env` file before starting the stack. If you change
`IDENTRAIL_WEB_PORT`, update `IDENTRAIL_CORS_ALLOWED_ORIGINS` to the matching
`http://localhost:<port>` value too. The public web image is published against
`http://localhost:8080` for the API, so the no-clone quickstart keeps the API
port fixed on `8080`.

To test the GHCR copies instead, set `IDENTRAIL_IMAGE_REGISTRY=ghcr.io/identrail`
in the downloaded `.env` before starting the stack.

If you need direct access to the quickstart database for debugging, use
`docker compose exec` instead of exposing the port by default:

```bash
docker compose -f docker-compose.public.yml exec postgres psql -U identrail -d identrail
```

You can still pull the main image directly when you want to inspect or run just
the API server:

```bash
docker pull docker.io/identrail/identrail:dev
# GHCR mirror:
docker pull ghcr.io/identrail/identrail:dev
```

Run the API server by itself with disposable in-memory storage:

```bash
docker run --rm -p 8080:8080 \
  -e IDENTRAIL_ALLOW_MEMORY_STORE=true \
  -e IDENTRAIL_RUN_MIGRATIONS=false \
  -e IDENTRAIL_API_KEYS=identrail-local-read-key-change-me,identrail-local-write-key-change-me \
  -e IDENTRAIL_WRITE_API_KEYS=identrail-local-write-key-change-me \
  docker.io/identrail/identrail:dev
```

Then verify it with:

```bash
curl http://localhost:8080/healthz
```

To run the full local stack from public images from a cloned repository:

```bash
docker compose -f deploy/docker/docker-compose.public.yml up -d
```

The public stack starts Postgres, API, worker, and web without building from
source. Open `http://localhost:8081` for the web UI and use
`http://localhost:8080` for the API. The public profile enables the new auth
flow and self-serve onboarding in local-only manual mode, so the dashboard can
establish a disposable session and create its first workspace without any
hosted identity provider. Postgres is intentionally not published onto the host
in this profile, so existing local database services do not block the
quickstart. For anything beyond localhost evaluation, rotate the example
secrets and disable manual mode.

Supporting images are published for multi-service deployments:

```bash
docker pull docker.io/identrail/identrail-worker:dev
docker pull docker.io/identrail/identrail-web:dev
docker pull docker.io/identrail/identrail-api:dev
docker pull docker.io/identrail/identrail-agent:dev
# GHCR mirrors:
docker pull ghcr.io/identrail/identrail-worker:dev
docker pull ghcr.io/identrail/identrail-web:dev
docker pull ghcr.io/identrail/identrail-api:dev
docker pull ghcr.io/identrail/identrail-agent:dev
```

Each `dev` publish also creates immutable `sha-<12-char-sha>` tags. Release
images use SemVer tags such as `ghcr.io/identrail/identrail:v1.0.0` and
`docker.io/identrail/identrail:v1.0.0`.

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
