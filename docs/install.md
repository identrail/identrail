# Install Identrail

Use Docker when you do not want to install anything locally. Use a source build
when you want to contribute or test the latest development code.

## Docker

Run Identrail without installing it on your machine:

```bash
docker run --rm ghcr.io/identrail/identrail-cli:dev scan owner/repo
```

Example:

```bash
docker run --rm ghcr.io/identrail/identrail-cli:dev scan identrail/identrail
```

For a private repository, clone it first and mount the checkout:

```bash
git clone git@github.com:owner/private-repo.git
cd private-repo
docker run --rm -v "$PWD:/repo" -w /repo ghcr.io/identrail/identrail-cli:dev scan .
```

The Docker image uses the same command shape as the installed CLI. Put CLI
arguments after the image name.

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

## Scan Commands

These commands assume `identrail` is installed or on your `PATH`. If you built
from source and did not move the binary, replace `identrail` with
`./bin/identrail`.

Run the AWS/Kubernetes provider scan path:

```bash
identrail scan
```

Use Kubernetes fixtures/provider defaults explicitly:

```bash
IDENTRAIL_PROVIDER=kubernetes identrail scan
```

Scan a public GitHub repository:

```bash
identrail scan owner/repo
```

Scan a private repository you already cloned:

```bash
cd private-repo
identrail scan .
```

Repository scans report secrets, GitHub Actions, and CI risk. They complement
the AWS/Kubernetes machine identity workflow; they do not replace it. Hosted
private repository scans use the GitHub App connector in the Identrail web app.

The backward-compatible long commands still work for scripts:

```bash
identrail repo-scan --repo owner/repo
identrail repo-scan owner/repo
identrail repo owner/repo
```

## Homebrew Status

Homebrew support is planned, but it is not available yet. The command below will
fail until the `identrail/homebrew-tap` repository is published:

```bash
brew install identrail/tap/identrail
```

The shorter `brew install identrail` command is a later Homebrew core goal. It
requires Homebrew to accept an Identrail formula.
