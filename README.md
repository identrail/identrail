<div align="center">
  <picture>
   <img src="./docs/static/images/identrail-logo-bw-white.png" alt="Identrail Logo" width="320" style="margin-bottom: 16px;" />
  </picture>

  <br />
  <br />

  <p><strong>Open-source machine identity security for AWS and Kubernetes.</strong></p>
  <p>Discover trust paths, detect high-signal exposure risk, and apply authorization guardrails with explainable decisions.</p>
</div>

<p align="center">
  <a href="https://github.com/identrail/identrail/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/identrail/identrail/ci.yml?branch=dev&style=flat&label=ci&colorA=000000&colorB=2ea043" alt="CI" /></a>
  <a href="https://github.com/identrail/identrail/tags"><img src="https://img.shields.io/github/v/tag/identrail/identrail?sort=semver&style=flat&label=version&colorA=000000&colorB=0969da" alt="Latest version" /></a>
  <a href="https://github.com/identrail/identrail/stargazers"><img src="https://img.shields.io/github/stars/identrail/identrail?style=flat&colorA=000000&colorB=d4af37" alt="GitHub stars" /></a>
</p>

<p align="center">
  <a href="https://github.com/identrail/identrail/blob/dev/docs/enterprise-quickstart.md"><strong>Enterprise Quickstart</strong></a>
  ·
  <a href="https://www.identrail.com">Website</a>
  ·
  <a href="https://discord.gg/7jSUSnQC">Discord</a>
  ·
  <a href="https://github.com/identrail/identrail/issues">Issues</a>
</p>

## Who This Is For

Identrail is for security and platform teams that need to answer three questions quickly:

- Which machine identities can reach sensitive resources?
- Where does trust sprawl create blast-radius risk?
- How can we enforce safer access with auditable decisions?

Use it when you run AWS and/or Kubernetes workloads and want identity risk visibility plus deployment-safe control surfaces.

## 5-Minute Quickstart

Prerequisites: Docker, Docker Compose, `curl`, `jq`.

Use published images without building from source:

```bash
mkdir identrail-docker && cd identrail-docker
curl -fsSLO https://raw.githubusercontent.com/identrail/identrail/dev/deploy/docker/docker-compose.public.yml
docker compose -f docker-compose.public.yml up -d
curl http://localhost:8080/healthz
```

Open `http://localhost:8081` for the web UI.

`docker pull` by itself only downloads images into Docker; it does not create a
project directory or the Compose file needed to start the full stack.

The no-clone public quickstart keeps the API on `http://localhost:8080`; only
the web and Postgres host ports are intended to be customized in that profile.

For local development from a cloned repository:

```bash
make quickstart
```

What this does:

- Boots API, worker, web, and Postgres with local-safe defaults.
- Triggers an initial scan.
- Prints follow-up commands to inspect findings.

Stop the stack:

```bash
make quickstart-down
```

For enterprise auth scope, tenant/workspace context, and decision audit verification, use the full [Enterprise Quickstart](./docs/enterprise-quickstart.md).

## What Identrail Does

- Discovers machine identities and trust relationships across AWS and Kubernetes.
- Persists raw and normalized scan artifacts for explainability and auditability.
- Produces deterministic findings with risk evidence and remediation context.
- Provides API and web workflows for trends and diff analysis, plus CLI workflows for scans, findings, repo exposure scans, and authz rollback.
- Supports optional repository exposure scanning (secrets and CI/IaC risk) in an isolated pipeline.

## What Identrail Does Not Do

- It is not a cloud SIEM replacement.
- It is not an endpoint runtime agent.
- It is not a generic CSPM for every cloud/provider in V1.

V1 is intentionally focused on machine identity security workflows for AWS and Kubernetes.

## How It Works

```text
Collector -> Raw Assets -> Normalizer -> Graph -> Risk Rules -> Findings Store -> API/CLI/Web
```

Operational model:

- API can enqueue scans (`POST /v1/scans`, `POST /v1/repo-scans`).
- Worker drains queue and runs scheduled jobs.
- Results are queryable via API and CLI with scan-aware filtering and history.

## Deployment Options

Choose the rollout path that matches your environment maturity:

- Local / single host: Docker Compose (`deploy/docker`)
- Cluster-native: Kubernetes manifests (`deploy/kubernetes`)
- Upgrade-safe Kubernetes: Helm chart (`deploy/helm/identrail`)
- IaC rollout: Terraform Helm module (`deploy/terraform`)
- Non-Kubernetes runtime: Linux VM + systemd (`deploy/systemd`)

See [Deployment Anywhere](./docs/deployment-anywhere.md) for exact commands.

## Project Status

Status: **Active** (v1 line in active support).

Current focus:

- Production hardening for scan reliability and auth safety defaults.
- Stronger backward-compatibility and contract testing.
- Operator readiness for repeatable multi-environment rollouts.

Reference docs:

- [Versioning and Support Policy](./docs/versioning-support-policy.md)
- [Architecture](./docs/architecture.md)
- [OpenAPI v1](./docs/openapi-v1.yaml)

Demo video: _coming soon_.

## Comparison (Where Identrail Fits)

- Versus broad CSPM tools: Identrail is narrower and deeper on machine identity trust and authorization workflows.
- Versus secret scanners alone: Identrail includes optional repo exposure scanning, but also links findings into identity risk context.
- Versus policy engines alone: Identrail adds discovery + risk evidence, not only policy evaluation.

## Security and Support SLA

If you discover a vulnerability, please use private reporting only:

- GitHub private advisories: <https://github.com/identrail/identrail/security/advisories/new>
- Email: [security@identrail.com](mailto:security@identrail.com)

Maintainer targets for supported versions:

- Acknowledge valid reports within 72 hours.
- Initial triage within 7 days.
- Weekly status updates until resolution.

Full policy: [SECURITY.md](./SECURITY.md).

## Contributing

- [Contributing Guide](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Issues](https://github.com/identrail/identrail/issues)
