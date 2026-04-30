SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

.PHONY: help bootstrap quickstart quickstart-down clean-local fmt fmt-check vet test test-integration web-install web-test web-build api-example-contract-check vercel-prod-deploy helm-lint tfmt-check ci pre-commit

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "%-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Install local dependencies for Go and web
	go mod download
	npm ci --prefix web

quickstart: ## Bootstrap local Docker stack and run first scan
	./scripts/quickstart.sh

quickstart-down: ## Stop and remove quickstart Docker stack
	docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env down

clean-local: ## Remove local duplicate/temp artifacts not tracked in git
	./scripts/clean_local.sh

fmt: ## Auto-format Go and Terraform files
	@if git ls-files '*.go' | grep -q .; then \
		git ls-files '*.go' | xargs gofmt -w; \
	fi
	@terraform fmt -recursive deploy/terraform >/dev/null 2>&1 || true

fmt-check: ## Check formatting without modifying files
	@set -euo pipefail; \
	if git ls-files '*.go' | grep -q .; then \
		unformatted="$$(git ls-files '*.go' | xargs gofmt -l)"; \
		if [ -n "$$unformatted" ]; then \
			echo "Go files not formatted:"; \
			echo "$$unformatted"; \
			exit 1; \
		fi; \
	fi
	@terraform fmt -check -recursive deploy/terraform >/dev/null 2>&1 || true

vet: ## Run go vet
	go vet ./...

test: ## Run Go unit and package tests
	go test ./... -coverprofile=coverage.out

test-integration: ## Run integration tests (requires local Postgres)
	go test -tags=integration ./internal/integration -count=1 -v

web-install: ## Install web dependencies
	npm ci --prefix web

web-test: ## Run web test suite in CI mode
	npm run test:ci --prefix web

web-build: ## Build web frontend
	npm run build --prefix web

api-example-contract-check: ## Validate docs/web API snippets against current v1 contract
	./scripts/check_api_example_contract.sh

vercel-prod-deploy: ## Trigger Vercel production deploy (always uses origin/dev)
	./scripts/vercel_prod_deploy.sh

helm-lint: ## Lint Helm chart
	helm lint deploy/helm/identrail

tfmt-check: ## Check Terraform formatting
	terraform fmt -check -recursive deploy/terraform

ci: fmt-check vet test api-example-contract-check web-test web-build ## Run core local CI checks

pre-commit: ## Run pre-commit hooks across the repository
	pre-commit run --all-files
