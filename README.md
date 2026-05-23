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

Identrail is AWS/Kubernetes machine identity security first. Use the hosted app
for the full source-onboarding workflow, and use the CLI when you want a quick
repository-exposure scan from your terminal.

### Use the hosted app

Go to [identrail.com](https://www.identrail.com), sign in, create or select a
workspace, and connect the sources your project owns: AWS, Kubernetes, and
GitHub.

For enterprise auth scope, tenant/workspace context, live source setup, and
decision audit verification, use the [Enterprise Quickstart](./docs/enterprise-quickstart.md).

### Install or run the CLI

After the Homebrew tap is published, install the CLI on macOS or Linux:

```bash
brew install identrail/tap/identrail
```

Run the CLI without installing it locally:

```bash
docker run --rm ghcr.io/identrail/identrail-cli:dev scan owner/repo
```

Build from source when you want to contribute or test development code:

```bash
git clone https://github.com/identrail/identrail.git
cd identrail
go build -o ./bin/identrail ./cmd/cli
```

The release workflow publishes the Homebrew formula when the
`identrail/homebrew-tap` repository and `HOMEBREW_TAP_TOKEN` secret are in
place. Until then, use Docker or a source build.

### Scan from the terminal

After installing the CLI, run the AWS/Kubernetes provider scan path:

```bash
identrail scan
```

Scan a public GitHub repository:

```bash
identrail scan owner/repo
```

Scan a local checkout, including a private repository you already cloned:

```bash
identrail scan .
```

Use `IDENTRAIL_PROVIDER=kubernetes identrail scan` when you want the Kubernetes
provider defaults explicitly. If you built from source, use `./bin/identrail`
instead of `identrail` unless you add the binary to your `PATH`. Repository
signals complement the AWS/Kubernetes identity graph; they do not replace it.
For hosted, project-scoped private repository scans, connect the GitHub App in
the Identrail web app. See [Install Identrail](./docs/install.md) for CLI
install details.

## What Identrail Does

- Discovers machine identities and trust relationships across AWS and Kubernetes.
- Adds repository exposure signals for secrets, GitHub Actions, and CI risk.
- Produces explainable findings with evidence, severity, and remediation context.
- Provides CLI, API, worker, and web workflows for local scans, hosted scans, trends, and review.

## What Identrail Does Not Do

- It is not a cloud SIEM replacement.
- It is not an endpoint runtime agent.
- It is not a generic CSPM for every cloud/provider in V1.

V1 is intentionally focused on machine identity security workflows for AWS and Kubernetes.

## How It Works

```text
Collector -> Raw Assets -> Normalizer -> Graph -> Risk Rules -> Findings Store -> API/CLI/Web
```

The CLI runs local scans directly. The API enqueues hosted scans, the worker
processes them, and results are available through the API, CLI, and web UI.

## Deployment Options

Choose the rollout path that matches your environment maturity:

- Local / single host: Docker Compose (`deploy/docker`)
- Cluster-native: Kubernetes manifests (`deploy/kubernetes`)
- Upgrade-safe Kubernetes: Helm chart (`deploy/helm/identrail`)
- IaC rollout: Terraform Helm module (`deploy/terraform`)
- Non-Kubernetes runtime: Linux VM + systemd (`deploy/systemd`)

See [Deployment Anywhere](./docs/deployment-anywhere.md) for exact commands.

## Comparison (Where Identrail Fits)

- Versus broad CSPM tools: Identrail is narrower and deeper on machine identity trust and authorization workflows.
- Versus secret scanners alone: Identrail links repository findings into identity risk context.
- Versus policy engines alone: Identrail adds discovery + risk evidence, not only policy evaluation.

<details>
  <summary><strong>Security and Support SLA</strong></summary>

If you discover a vulnerability, please use private reporting only:

- GitHub private advisories: <https://github.com/identrail/identrail/security/advisories/new>
- Email: [security@identrail.com](mailto:security@identrail.com)

Maintainer targets for supported versions:

- Acknowledge valid reports within 72 hours.
- Initial triage within 7 days.
- Weekly status updates until resolution.

Full policy: [SECURITY.md](./SECURITY.md).

</details>

<details>
  <summary><strong>Contributing</strong></summary>

- [Contributing Guide](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Issues](https://github.com/identrail/identrail/issues)

</details>
