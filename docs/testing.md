# Testing Strategy

## Principles

- Unit tests for core packages and orchestration paths
- Fixture-based tests for provider collection/normalization/rules
- Sqlmock tests for Postgres store behavior
- Scheduler and worker tests for run safety
- CI must fail fast on formatting, static checks, integration failures, or coverage regressions

## Current Focus

- Config defaults and env parsing
- Scoped API key parsing and write authorization behavior
- Scoped read authorization enforcement behavior (`read` or `write`)
- Audit API-key fingerprint generation behavior (no raw key persistence)
- Webhook alerter URL validation, severity filtering, and non-2xx failure handling
- API routes and scan trigger behavior
- API auth and write-authorization middleware behavior
- API rate-limit and audit-log middleware behavior
- Audit sink file export behavior
- Service non-blocking alert callback behavior
- Startup security config validation and warning coverage (scopes, write-key mapping, alert bounds)
- Scan diff, findings summary, and scan event timeline service behavior
- Router coverage for summary/diff/events endpoints and missing-scan handling
- Router coverage for trends/identities/relationships endpoints and missing-scan handling
- Webhook retry/backoff behavior for transient failures
- HTTP audit forwarding sink behavior and multi-sink fanout behavior
- Memory/Postgres persistence logic
- Migration runner behavior
- Integration lane (build tag `integration`) for Postgres-backed run-scan + diff flow
- Artifact and finding idempotent upserts
- Scheduler lock/runner behavior
- Worker startup and cancellation behavior
- Provider contract validation for normalized schema + graph semantics
- Fixture contract tests for AWS and Kubernetes normalization/graph pipelines
- Graph snapshot regression tests for AWS and Kubernetes edge sets
- API contract snapshot tests for critical `/v1` responses
- Finding payload compatibility snapshots (internal enriched + OCSF + ASFF)
- Collector diagnostics and transient retry behavior (kubectl mode)
- Partial scan lifecycle state assertions (`partial` on non-fatal source errors)
- API list sort contract behavior (`sort_by`, `sort_order`) on findings and scans
- OpenAPI v1 contract presence checks for core endpoints and parameters
- Native SAML admin, SAML login/ACS, Okta/Azure metadata import, SCIM 2.0 lifecycle, and SCIM workflow dispatch behavior
- Migration rollback roundtrip integration test (up -> down -> up)
- Migration compatibility integration test for existing nullable legacy rows

## Track 1 Enterprise SSO Checks

Run these before moving dependent work forward:

```bash
go test ./internal/api -run 'Test(SAML|NativeSAML|EnterpriseSCIM)|TestParseSAMLMetadataXML|TestFetchSAMLMetadataXML|TestUpsertSAMLAssertedUser|TestNewSCIMBearerToken'
go test ./internal/config ./internal/db ./internal/enterprise ./internal/workflow
python3 - <<'PY'
import yaml
with open('docs/openapi-v1.yaml') as f:
    doc = yaml.safe_load(f)
required = [
    '/v1/enterprise/identity-connections/saml',
    '/v1/enterprise/identity-connections/saml/{id}',
    '/v1/enterprise/identity-connections/saml/from-metadata',
    '/auth/saml/login/{connection_id}',
    '/auth/saml/acs/{connection_id}',
    '/scim/v2/ServiceProviderConfig',
    '/scim/v2/Schemas',
    '/scim/v2/ResourceTypes',
    '/scim/v2/Users',
    '/scim/v2/Users/{id}',
]
missing = [path for path in required if path not in doc.get('paths', {})]
if missing:
    raise SystemExit('missing Track 1 OpenAPI paths: ' + ', '.join(missing))
print('Track 1 OpenAPI paths present')
PY
```

For a live IdP smoke test:

1. Start the API with `IDENTRAIL_FEATURE_NATIVE_SSO=true`,
   `IDENTRAIL_FEATURE_NEW_AUTH=true`, `IDENTRAIL_PUBLIC_BASE_URL`, and
   `IDENTRAIL_SESSION_KEY` configured. Native SAML admin/login routes depend on
   the session-auth stack; SCIM bearer-token routes use the native SSO flag.
2. Create a native SAML connection with
   `POST /v1/enterprise/identity-connections/saml/from-metadata`, then create
   or update the connection with the parsed `entity_id`, `sso_url`,
   `certificate_pem`, and an `attribute_mapping.email` value.
3. Store the one-time `scim_bearer_token` returned by the create response.
4. Call the SCIM discovery endpoints and perform one create, update, patch, and
   delete against `/scim/v2/Users` using that bearer token.
5. Confirm a `scim_provisioning_events` row and, when a workflow route is
   configured, a `scim.provisioned` dispatch audit record.
6. Configure Okta or Entra with ACS
   `${IDENTRAIL_PUBLIC_BASE_URL}/auth/saml/acs/<connection_id>` and SP Entity
   ID `${IDENTRAIL_PUBLIC_BASE_URL}/auth/saml/metadata/<connection_id>`.
7. Start SAML login through `/auth/saml/login/<connection_id>` and confirm the
   ACS creates a session with `auth_method="saml"`.

## CI Pipeline Gates

GitHub Actions workflow: `.github/workflows/ci.yml`

- `go-quality`
  - `gofmt` enforcement
  - `go vet ./...`
- `go-test`
  - `go test ./... -coverprofile=coverage.out`
  - coverage floor: total >= 80%
- `go-integration`
  - Postgres service container
  - `go test -tags=integration ./internal/integration -count=1 -v`
- `go-cli-smoke`
  - scan command smoke (`table` + persisted state)
  - findings command smoke (`json`)
  - repo-scan command smoke
- `web-build`
  - `npm ci --prefix web`
  - `npm run test:ci --prefix web`
  - `npm run build --prefix web`
- `infra-validate`
  - `helm lint deploy/helm/identrail`
  - `terraform fmt -check -recursive deploy/terraform`
  - `terraform validate` in `deploy/terraform`
- `deploy-portability`
  - docker compose config validation
  - image build validation
  - dockerized API smoke (`postgres + api + fixture scan trigger + findings read`)
