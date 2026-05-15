# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Prerequisites

- Go `1.25.9` (see `go.mod`)
- Node.js `24` for `web/`
- Docker + Docker Compose for local stack and integration tests
- PostgreSQL (or Docker) for integration tests

## Commands

**Bootstrap:**
```bash
make bootstrap  # go mod download + npm ci --prefix web
```

**Go tests:**
```bash
make test                          # all unit tests with coverage
go test ./internal/<pkg> -run TestName -v  # single test
make test-integration              # requires local Postgres
```

Integration tests require the env var:
```
IDENTRAIL_INTEGRATION_DATABASE_URL='postgres://identrail:secret@127.0.0.1:5432/identrail?sslmode=disable'
```

**Formatting and static checks:**
```bash
make fmt        # gofmt -w on all tracked .go files
make fmt-check  # CI-mode check (no writes)
make vet        # go vet ./...
```

**Web:**
```bash
npm run dev --prefix web       # dev server
npm run test:ci --prefix web   # CI test run with coverage
npm run build --prefix web     # production build
```

**CLI smoke test:**
```bash
state_file="/tmp/identrail-smoke-state.json"
go run ./cmd/cli --state-file "${state_file}" scan \
  --fixture testdata/aws/role_with_policies.json \
  --fixture testdata/aws/role_with_urlencoded_trust.json \
  --output table
go run ./cmd/cli --state-file "${state_file}" findings --output json
```

**Full local CI:**
```bash
make ci   # fmt-check + vet + test + contract checks + web test + web build
```

**Local Docker stack:**
```bash
make quickstart       # boots API, worker, web, Postgres; triggers initial scan
make quickstart-down  # tears it down
```

## Architecture

Identrail is a **modular monolith** for machine identity security across AWS and Kubernetes.

### Data Flow

```
Collector → Raw Assets → Normalizer → Domain Entities
                |                          |
                v                          v
           Raw Storage               Graph Builder
                                          |
                                          v
                                   Risk Rule Engine
                                          |
                                          v
                              Findings Store → API / CLI / Web
```

### Runtime Processes (`cmd/`)

| Process | Purpose |
|---|---|
| `cmd/server` | REST API — health, scans, findings endpoints |
| `cmd/worker` | Scheduled scan executor |
| `cmd/cli` | Operator-facing scanner and findings CLI |
| `cmd/identrail-agent` | Agent entrypoint |

### Key Internal Packages (`internal/`)

- **`providers/`** — provider pipeline implementations. Each provider implements `Collector → Normalizer → RelationshipResolver → RiskRuleSet` interfaces defined in `providers/interfaces.go`. Current providers: `aws/`, `kubernetes/`.
- **`app/`** — `Scanner`: the deterministic scan execution pipeline that orchestrates provider stages.
- **`api/`** — `Service`: scan orchestration + persistence bridge.
- **`db/`** — dual storage backends (`memory.go`, `postgres.go`) behind a single `store.go` interface. Memory mode is for testing/dev; Postgres is production.
- **`domain/`** — core types (`Identity`, `Workload`, `Policy`, `Finding`, `Relationship`). Multi-tenant app-mode entities (`Organization`, `Workspace`, `Project`, `Connector`, `ScanPolicy`) are in `domain/appmode.go`.
- **`connectors/`** — connector lifecycle framework (`lifecycle.go`) with provider hooks for `aws/`, `github/`, `kubernetes/`.
- **`runtime/`** — shared service bootstrap used by server and worker.
- **`scheduler/`** — idempotent scan orchestration.
- **`repoexposure/`** — isolated git history + HEAD scanner for secrets and IaC/CI misconfigurations; results persist in separate repo scan tables.
- **`telemetry/`** — structured logs (zap), Prometheus metrics, OTel tracing.

### Tenancy Model

`Organization → Workspace → Project → Connector`

Connector credentials are never stored in plaintext; they use encrypted secret envelopes (`tenancy_connector_secret_envelopes`). Connector status transitions: `pending → active|degraded|disconnected`.

### Database Migrations (`migrations/`)

Versioned SQL files with matching `.up.sql` / `.down.sql`. Some numeric prefixes are intentionally duplicated (historical; do not reorder). Key rules:
- Migrations run via a **one-shot migrator job** (`IDENTRAIL_RUN_MIGRATIONS_ONLY=true`).
- API and worker processes run with `IDENTRAIL_RUN_MIGRATIONS=false`.
- New migrations must be forward-safe and use `IF NOT EXISTS` where applicable.

### Provider Contract

All providers implement the interfaces in `internal/providers/interfaces.go`:
- `Collector` — reads raw cloud/k8s assets.
- `Normalizer` — converts raw assets into `NormalizedBundle` (Identities, Workloads, Policies).
- `RelationshipResolver` — builds graph edges.
- `RiskRuleSet` — evaluates deterministic risk rules, returns `[]domain.Finding`.

Idempotency is a first-class requirement at every scan stage.

### Web Frontend (`web/`)

React + Vite + TypeScript. Static pre-rendering via `prerender.tsx`. API base URL configured via `VITE_IDENTRAIL_API_URL` (must not point at the web frontend — enforced by `make production-api-url-check`).

## Development Conventions

- Branch from `dev`. Naming: `fix/`, `feat/`, `docs/`, `chore/`.
- PRs must link issues: `Fixes #NNN` or `Closes #NNN`.
- Target `>= 80%` total Go test coverage.
- AI-assisted contributions require disclosure in the PR description (see `CONTRIBUTING.md` for format).
- Run `make fmt` before committing Go changes; CI enforces `make fmt-check`.
- Commit messages: imperative tense, short subject (e.g. `enforce explicit read scope for oidc tokens`).
- `CHANGELOG.md` must be updated for user-facing or operator-facing behavior changes.
