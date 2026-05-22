# Install Identrail

This page covers the end-user install paths for the Identrail command-line
scanner. The hosted API, worker, and web stack remain documented in the
deployment guides.

## Recommended CLI usage

Use the short repository scan form when you want to inspect a public GitHub
repository:

```bash
identrail scan owner/repo
```

Examples:

```bash
identrail scan identrail/identrail
identrail scan owner/repo --history-limit 50 --max-findings 20
identrail scan https://github.com/owner/repo.git --output json
```

For a private repository, clone it first with your normal GitHub access and
scan the local checkout:

```bash
git clone git@github.com:owner/private-repo.git
cd private-repo
identrail scan .
```

With Docker:

```bash
docker run --rm -v "$PWD:/repo" -w /repo ghcr.io/identrail/identrail-cli:dev scan .
```

Hosted private repository scans use the GitHub App connector in the Identrail
web app.

The longer command remains supported for scripts and backward compatibility:

```bash
identrail repo-scan --repo owner/repo
identrail repo-scan owner/repo
identrail repo owner/repo
```

Running `identrail scan` without a repository still runs the provider scan
pipeline for AWS or Kubernetes identities.

## Download a release binary

Published GitHub releases include `identrail-cli` archives for macOS, Linux,
and Windows:

- macOS Intel and Apple Silicon: `darwin-amd64`, `darwin-arm64`
- Linux Intel and ARM: `linux-amd64`, `linux-arm64`
- Windows Intel: `windows-amd64`

Download the archive that matches your machine from the GitHub release page,
extract it, and put the `identrail-cli-*` binary on your `PATH` as
`identrail`.

## Homebrew (planned)

The release assets and CLI command shape are ready for a Homebrew tap formula,
but the `identrail/homebrew-tap` repository has not been published yet. Once
that tap exists, the install command should be:

```bash
brew install identrail/tap/identrail
```

After Homebrew core acceptance, the shorter command can become:

```bash
brew install identrail
```

Core acceptance is a later distribution step outside this repository PR. It
requires a public Homebrew formula review, stable releases, source-build
support, tests, and enough user adoption for Homebrew maintainers to accept the
formula.

## Docker CLI image

For machines that already use Docker, run the CLI without installing Go:

```bash
docker run --rm ghcr.io/identrail/identrail-cli:dev scan owner/repo
```

The Docker image uses the same `identrail` entrypoint as the binary, so any CLI
arguments after the image name are passed directly to Identrail.

Release tags follow the normal image scheme:

```bash
docker run --rm ghcr.io/identrail/identrail-cli:v1.2.3 scan owner/repo
docker run --rm docker.io/identrail/identrail-cli:v1.2.3 scan owner/repo
```

Use immutable `sha-<12-char-sha>` tags when you need repeatable scans in CI.

## Build from source

Contributors can still build locally from a clone:

```bash
git clone https://github.com/identrail/identrail.git
cd identrail
go build -o ./bin/identrail ./cmd/cli
./bin/identrail scan owner/repo
```
