# Identrail

Identrail is a machine identity security platform for AWS IAM, Kubernetes,
GitHub/OIDC, and repository exposure signals. It helps teams discover risky
trust paths, exposed automation credentials, over-privileged workflows, and
cloud or cluster identity posture issues with evidence-backed findings.

This Docker Hub repository publishes the primary Identrail API image. Use it
directly for API evaluation, or run the public Compose stack when you want the
API, worker, web UI, and database together.

## Quick start with public images

The fastest no-clone path is the public Compose profile:

```bash
mkdir identrail-docker && cd identrail-docker
curl -fsSLO https://raw.githubusercontent.com/identrail/identrail/dev/deploy/docker/docker-compose.public.yml
docker compose -f docker-compose.public.yml up -d
```

Check the API and then open the web UI:

```bash
curl http://localhost:8080/healthz
```

Web UI: `http://localhost:8081`

The public stack is intended for local evaluation. It binds the API and web UI
to `127.0.0.1`, keeps Postgres inside the Docker network, and enables local
manual-mode onboarding so you can create a disposable workspace without a
hosted identity provider.

## Pull the main image

```bash
docker pull docker.io/identrail/identrail:dev
```

Run the API by itself with disposable in-memory storage:

```bash
docker run --rm -p 8080:8080 \
  -e IDENTRAIL_ALLOW_MEMORY_STORE=true \
  -e IDENTRAIL_RUN_MIGRATIONS=false \
  -e IDENTRAIL_API_KEYS=identrail-local-read-key-change-me,identrail-local-write-key-change-me \
  -e IDENTRAIL_WRITE_API_KEYS=identrail-local-write-key-change-me \
  docker.io/identrail/identrail:dev
```

Then verify:

```bash
curl http://localhost:8080/healthz
```

## Images

| Image | Purpose |
| --- | --- |
| `identrail/identrail` | Primary API server and machine identity engine |
| `identrail/identrail-api` | API alias for deployments that prefer explicit service naming |
| `identrail/identrail-worker` | Background scan worker for repository and posture jobs |
| `identrail/identrail-web` | Local web dashboard image |
| `identrail/identrail-cli` | Command-line scanner |
| `identrail/identrail-agent` | Kubernetes connector agent |

GHCR mirrors are also published under `ghcr.io/identrail`.

## Tags

| Tag | Use |
| --- | --- |
| `dev` | Moving image from the `dev` branch. Useful for local evaluation. |
| `sha-<12-char-sha>` | Immutable image for a specific source commit. Prefer this for reviewed deployments. |
| `vX.Y.Z` | Release image when a versioned release is cut. Prefer this for stable installs. |

Avoid using a moving tag for production-like deployments. Pin either a release
tag or an immutable `sha-...` tag so the running container can be traced back to
the exact source commit.

## Platforms

Identrail images are published for:

- `linux/amd64`
- `linux/arm64`

Native Windows container images are not published. Windows users can run these
Linux images with Docker Desktop and WSL2, which is the normal container setup
for local evaluation.

## Security notes

- Rotate all example API keys, session keys, and database passwords before any
  non-local deployment.
- Do not expose the local evaluation stack directly to the internet.
- For production-style single-host deployments, use TLS, a real Postgres
  database, and the hardening examples in the repository deployment docs.
- Repository exposure scans use read-only GitHub evidence collection and do not
  store raw secret values.

## Links

- Website: https://identrail.com
- Source: https://github.com/identrail/identrail
- Docker deployment docs: https://github.com/identrail/identrail/blob/dev/deploy/docker/README.md
