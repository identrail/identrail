<div align="center">
  <picture>
   <img src="./docs/static/images/identrail-logo-bw-white.png" alt="Identrail Logo" width="320" style="margin-bottom: 16px;" />
  </picture>

  <br />
  <br />

  <p><strong>Open-source machine identity security for AWS, GitHub, and Kubernetes.</strong></p>
  <p>Find risky trust paths, repository exposure, and authorization gaps before they become incidents.</p>
</div>

<p align="center">
  <a href="https://github.com/identrail/identrail/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/identrail/identrail/ci.yml?branch=dev&style=flat&label=ci&labelColor=000000" alt="CI status" /></a>
  <a href="https://github.com/identrail/identrail/releases/tag/v1.0.1"><img src="https://img.shields.io/badge/version-v1.0.1-0969da?style=flat&labelColor=000000" alt="Version v1.0.1" /></a>
  <a href="https://www.bestpractices.dev/projects/12950"><img src="https://img.shields.io/cii/level/12950?style=flat&label=openssf%20best%20practices&labelColor=000000" alt="OpenSSF Best Practices" /></a>
  <a href="https://github.com/identrail/identrail/stargazers"><img src="https://img.shields.io/github/stars/identrail/identrail?style=flat&label=stars&labelColor=000000&color=d4af37" alt="GitHub stars" /></a>
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

Identrail is for security and platform teams that need fast answers to practical machine identity questions:

- Which GitHub workflows, secrets, or automation paths can expose sensitive access?
- Which AWS roles and trust relationships create unnecessary blast radius?
- Which Kubernetes service accounts and RBAC bindings can reach more than they should?
- How can teams turn those signals into explainable findings and safer authorization decisions?

Use Identrail when you want read-only visibility first, then a clear path to
hosted scans, source onboarding, trends, and audit-ready evidence.

## Quickstart

Choose the source you want to check first. GitHub, AWS, and Kubernetes each have a separate first-run path.

### 1. Install Identrail

Install the CLI with Homebrew:

```bash
brew install identrail/tap/identrail
```

Or build from source when you want to contribute:

```bash
git clone https://github.com/identrail/identrail.git
cd identrail
go build -o ./bin/identrail ./cmd/cli
```

If you build from source, replace `identrail` with `./bin/identrail` in the
commands below unless you add the binary to your `PATH`.

### 2. Scan a GitHub Repository

Scan a public repository:

```bash
identrail scan owner/repo
```

Use limits when you want a faster first look:

```bash
identrail scan owner/repo --history-limit 5 --max-findings 5
```

Scan a private repository you already cloned:

```bash
cd private-repo
identrail scan .
```

For hosted private-repository scans, sign in to
[identrail.com](https://www.identrail.com), create or select a project, and
connect the Identrail GitHub App.

### 3. Scan AWS

Make sure your terminal has read-only AWS credentials:

```bash
aws sts get-caller-identity
```

Run an AWS machine identity scan:

```bash
IDENTRAIL_PROVIDER=aws \
IDENTRAIL_AWS_SOURCE=sdk \
IDENTRAIL_AWS_REGION=us-east-1 \
identrail scan
```

Change `IDENTRAIL_AWS_REGION` to the AWS region you want to inspect.

### 4. Scan Kubernetes

Make sure `kubectl` can reach the cluster:

```bash
kubectl config current-context
```

Check that your current identity can list the objects Identrail needs:

```bash
kubectl auth can-i list serviceaccounts --all-namespaces
kubectl auth can-i list rolebindings --all-namespaces
kubectl auth can-i list clusterrolebindings
kubectl auth can-i list roles --all-namespaces
kubectl auth can-i list clusterroles
kubectl auth can-i list pods --all-namespaces
```

Run a Kubernetes machine identity scan:

```bash
IDENTRAIL_PROVIDER=kubernetes \
IDENTRAIL_K8S_SOURCE=kubectl \
identrail scan
```

Use a specific kube context when needed:

```bash
IDENTRAIL_PROVIDER=kubernetes \
IDENTRAIL_K8S_SOURCE=kubectl \
IDENTRAIL_KUBE_CONTEXT=my-cluster-context \
identrail scan
```

### 5. Run with Docker

Use Docker when you do not want to install the CLI locally.

Scan a GitHub repository:

```bash
docker run --rm ghcr.io/identrail/identrail-cli:latest scan owner/repo
```

Scan a private repository you already cloned:

```bash
cd private-repo
docker run --rm -v "$PWD:/repo" -w /repo ghcr.io/identrail/identrail-cli:latest scan .
```

Run an AWS scan with a local AWS profile:

```bash
docker run --rm \
  -v "$HOME/.aws:/aws:ro" \
  -e AWS_CONFIG_FILE=/aws/config \
  -e AWS_SHARED_CREDENTIALS_FILE=/aws/credentials \
  -e AWS_PROFILE=default \
  -e IDENTRAIL_PROVIDER=aws \
  -e IDENTRAIL_AWS_SOURCE=sdk \
  -e IDENTRAIL_AWS_REGION=us-east-1 \
  ghcr.io/identrail/identrail-cli:latest scan
```

For live Kubernetes scans, use the Homebrew or source-built CLI where `kubectl`
is installed and configured. The CLI container stays small and does not include
`kubectl`.

### 6. Use the Hosted App

Go to [identrail.com](https://www.identrail.com), sign in, create or select a
workspace, and connect the sources your project owns: GitHub, AWS, and
Kubernetes.

Use the hosted app when you want project-scoped source onboarding, GitHub App
scans, scan history, findings, trends, and owner-ready review workflows.

For production deployment, SSO, tenant/workspace scope, connector secrets, and
audit logging, use the [Enterprise Quickstart](./docs/enterprise-quickstart.md).

## What Identrail Does

- Scans GitHub repositories for secrets, risky GitHub Actions workflows, CI exposure, and repository posture signals.
- Discovers AWS IAM trust paths, role relationships, and machine identity risk from live AWS accounts or fixtures.
- Discovers Kubernetes service accounts, RBAC bindings, and cluster identity paths from live clusters or fixtures.
- Produces explainable findings with evidence, severity, confidence, ownership, and remediation context.
- Provides CLI, Docker, API, worker, and web workflows for local scans, hosted
  scans, source onboarding, trends, and review.

## What Identrail Does Not Do

- It is not a cloud SIEM replacement.
- It is not an endpoint runtime agent.
- It is not a generic CSPM for every cloud and SaaS provider.
- It does not mutate your cloud, cluster, or repository state during read-only scans.

V1 focuses on machine identity security across GitHub, AWS, and Kubernetes.

## How It Works

```text
Source -> Collector -> Normalizer -> Graph -> Risk Rules -> Findings -> CLI/API/Web
```

The CLI runs local scans directly. The API enqueues hosted scans, the worker
processes them, and results are available through the API, CLI, and web UI.

## Deployment Options

Choose the path that matches how you want to run Identrail:

- Hosted app: use [identrail.com](https://www.identrail.com) for source onboarding and scan review.
- Local CLI: use Homebrew, Docker, or a source build for quick read-only scans.
- Local stack: use Docker Compose from `deploy/docker`.
- Kubernetes: use manifests in `deploy/kubernetes` or the Helm chart in `deploy/helm/identrail`.
- Infrastructure as code: use the Terraform modules in `deploy/terraform`.
- Linux VM: use the systemd units in `deploy/systemd`.

See [Deployment Anywhere](./docs/deployment-anywhere.md) for operator commands.

## Comparison (Where Identrail Fits)

- Versus broad CSPM tools: Identrail is narrower and deeper on machine identity
  trust, repository automation exposure, and authorization workflows.
- Versus secret scanners alone: Identrail links repository findings into identity risk context.
- Versus policy engines alone: Identrail adds discovery and risk evidence, not only policy evaluation.

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
