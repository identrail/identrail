# Contributing to Identrail

Thanks for contributing to Identrail.

This guide explains how to propose changes, run validation locally, and open high-signal pull requests.

## Scope

Identrail focuses on machine identity security for cloud and Kubernetes environments.

Good contributions include:
- Bug fixes and reliability improvements
- Security hardening
- Test coverage and contract updates
- Documentation and operator-readiness improvements
- UX and API ergonomics improvements compatible with v1 expectations

## Ways to Contribute

- **Open an issue** to report a bug, request a feature, or suggest an improvement.
  
- **Pick up an existing issue** if you want to contribute code, documentation, tests, or cleanup work.

- **Report bugs clearly** by including reproduction steps, expected behavior, actual behavior, environment details, and any relevant logs or screenshots.
  
- **Link pull requests to issues** by starting your PR description with a closing keyword and issue number, such as `Fixes #500`, `Closes #500`, or `Resolves #500`. This automatically connects the PR to the related issue and helps keep project tracking clean.
  
- **Propose enhancements** with a clear problem statement, why it matters, and a suggested approach if you have one.
  
- **Submit focused pull requests** that address one issue or improvement at a time. Include tests and documentation updates when relevant.
  
- **Improve documentation and runbooks** whenever behavior, setup steps, operations, or troubleshooting guidance changes.

  
## Before You Start

Prerequisites:
- Go `1.25.8` (see `go.mod`)
- Node.js `24` for `web/`
- Docker for local Compose and image validation
- PostgreSQL (or Docker) for integration test flows
- Helm and Terraform only when touching `deploy/helm` or `deploy/terraform`

Recommended first steps:
```bash
git clone https://github.com/Oluwatobi-Mustapha/identrail.git
cd identrail
go mod download
npm ci --prefix web
```

## Development Workflow

1. Create a branch from `main`.
2. Keep each PR focused on one logical change.
3. Add or update tests for behavior changes.
4. Update docs and `CHANGELOG.md` when user-facing or operator-facing behavior changes.
5. Open a draft PR early if you want design feedback before final polish.

Branch naming suggestions:
- `fix/<short-description>`
- `feat/<short-description>`
- `docs/<short-description>`
- `chore/<short-description>`

Commit message suggestions:
- Use imperative tense and short subjects.
- Example: `enforce explicit read scope for oidc tokens`

## Local Quality Gates

Run the same checks CI enforces for your change scope.

Go formatting and static checks:
```bash
git ls-files '*.go' | xargs gofmt -w
go vet ./...
```

Go unit and package tests with coverage:
```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```
Target is `>= 80%` total coverage.

Integration tests (Postgres):
```bash
IDENTRAIL_INTEGRATION_DATABASE_URL='postgres://identrail:secret@127.0.0.1:5432/identrail?sslmode=disable' \
  go test -tags=integration ./internal/integration -count=1 -v
```

CLI smoke checks:
```bash
state_file="/tmp/identrail-smoke-state.json"
go run ./cmd/cli --state-file "${state_file}" scan \
  --fixture testdata/aws/role_with_policies.json \
  --fixture testdata/aws/role_with_urlencoded_trust.json \
  --output table
go run ./cmd/cli --state-file "${state_file}" findings --output json
```

Web tests and build:
```bash
npm run test:ci --prefix web
npm run build --prefix web
```

Infra checks when changing deployment assets:
```bash
helm lint deploy/helm/identrail
terraform fmt -check -recursive deploy/terraform
(
  cd deploy/terraform
  terraform init -backend=false
  terraform validate
)
```

## Pull Request Expectations

Each PR should include:
- What changed
- Why it changed
- Impact and risk
- Validation performed (commands + results summary)

Also include:
- Linked issue if one exists
- API contract updates when API behavior changes
- Snapshot/test fixture updates when contract outputs intentionally change
- Screenshots for meaningful UI changes

Review readiness checklist:
- [ ] Scope is focused and free of unrelated changes
- [ ] New/changed behavior has test coverage
- [ ] Docs and changelog are updated when needed
- [ ] CI-relevant checks were run locally for touched areas
- [ ] No secrets or credentials are present in code, tests, or logs

## AI-Assisted and AI-Generated Code Policy

AI assistance is allowed, but contributor accountability is mandatory.

If AI tools were used for a material part of a change, disclose it in the PR description.

Minimum disclosure format:
- `AI-assisted: yes|no`
- `Tools used:` (for example, Codex, Copilot, ChatGPT)
- `Where used:` (files or subsystems)
- `Human verification performed:` (tests run, manual review steps)

Rules for AI-generated output:
- You are responsible for every submitted line.
- Manually review and understand generated code before committing.
- Do not submit generated code that you cannot explain.
- Do not paste secrets, private keys, tokens, proprietary code, or customer data into AI tools.
- Do not copy generated snippets from sources with unknown or incompatible licensing.
- Keep generated tests meaningful. Avoid superficial tests that only exercise implementation details without asserting behavior.
- Prefer smaller, auditable commits when AI assistance is used heavily.

Maintainers may request revision or rejection when:
- provenance or licensing is unclear
- security posture is weakened
- code quality is below project standards
- contributor cannot explain critical logic
- Contributor has refused to sign DCO - this is a must.

## Security Issues

Do not open public issues for suspected vulnerabilities.

Use GitHub private vulnerability reporting for this repository. If unavailable, contact maintainers directly before public disclosure.

## Code of Conduct

Be respectful and constructive in all interactions.

A dedicated `CODE_OF_CONDUCT.md` may be added separately. Until then, maintain professional and inclusive communication in issues, discussions, and PR reviews.

## License

By contributing, you agree that your contributions are licensed under the repository license.

## Contributor Recognition

This project is configured for the All Contributors specification.

- Config file: `.all-contributorsrc`
- Bot/App: https://allcontributors.org/docs/en/bot/overview

When the All Contributors app is installed, maintainers can trigger attribution comments in pull requests to recognize all contribution types (code, docs, design, security, mentoring, etc.).
