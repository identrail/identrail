# Install Identrail

Use Homebrew for the simplest local install, Docker when you do not want to
install the CLI, and a source build when you want to contribute.

## Homebrew

Install the CLI on macOS or Linux:

```bash
brew install identrail/tap/identrail
```

Run your first GitHub repository scan:

```bash
identrail scan owner/repo
```

The shorter `brew install identrail` command is a later Homebrew core goal and
requires Homebrew to accept an Identrail formula.

## Docker

Scan a GitHub repository without installing Identrail locally:

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

## Source Build

Use this path when you want to contribute or test the latest development code:

```bash
git clone https://github.com/identrail/identrail.git
cd identrail
go build -o ./bin/identrail ./cmd/cli
./bin/identrail scan owner/repo
```

If you want to run `identrail` without the `./bin/` prefix, move the built
binary into a directory on your `PATH`.

## First Scan Commands

These commands assume `identrail` is installed or on your `PATH`. If you built
from source and did not move the binary, replace `identrail` with
`./bin/identrail`.

Scan a public GitHub repository:

```bash
identrail scan owner/repo
```

Limit the scan for a fast first look:

```bash
identrail scan owner/repo --history-limit 5 --max-findings 5
```

Scan a private repository you already cloned:

```bash
cd private-repo
identrail scan .
```

Run an AWS machine identity scan:

```bash
IDENTRAIL_PROVIDER=aws \
IDENTRAIL_AWS_SOURCE=sdk \
IDENTRAIL_AWS_REGION=us-east-1 \
identrail scan
```

Run a Kubernetes machine identity scan:

```bash
kubectl config current-context
kubectl auth can-i list serviceaccounts --all-namespaces
kubectl auth can-i list rolebindings --all-namespaces
kubectl auth can-i list clusterrolebindings
kubectl auth can-i list roles --all-namespaces
kubectl auth can-i list clusterroles
kubectl auth can-i list pods --all-namespaces

IDENTRAIL_PROVIDER=kubernetes \
IDENTRAIL_K8S_SOURCE=kubectl \
identrail scan
```

Repository scans report secrets, GitHub Actions, CI risk, and repository posture
signals. AWS and Kubernetes scans report machine identity trust paths and
authorization risk. Hosted private repository scans use the GitHub App connector
in the Identrail web app.
