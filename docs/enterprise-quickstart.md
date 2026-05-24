# Enterprise Quickstart

Use this guide when you are setting up Identrail for a team or production-like
environment. It keeps the first run understandable while covering the enterprise
pieces that matter: scoped API access, tenant/workspace context, source
onboarding, SSO, SCIM, audit logging, and executive reporting.

For a quick one-off scan from your terminal, start with the public
[README](../README.md). This guide is for operators who need durable
configuration and repeatable team access.

## What You Will Set Up

- A local Docker Compose stack with API, web, worker, and database services.
- Scoped API keys bound to a tenant and workspace.
- Audit logging for authorization decisions.
- Optional native SAML SSO and SCIM provisioning.
- Source onboarding links for GitHub, AWS, and Kubernetes.
- Executive report verification for leadership-facing review.

## Prerequisites

- Docker + Docker Compose
- `curl` + `jq`
- Admin access to the identity provider if you are configuring SSO or SCIM
- Read-only source access for any GitHub, AWS, or Kubernetes systems you connect

## 1. Configure Environment

```bash
cp deploy/docker/.env.example deploy/docker/.env
```

Edit `deploy/docker/.env` and use scoped API keys for this quickstart:

- `IDENTRAIL_POSTGRES_PASSWORD` with a strong database password
- `IDENTRAIL_API_KEY_SCOPES` (required for this quickstart), for example:
  - `IDENTRAIL_API_KEY_SCOPES=<reader-key>:read,tenant:tenant-a,workspace:workspace-a;<writer-key>:read,write,tenant:tenant-a,workspace:workspace-a;<admin-key>:read,write,admin,tenant:tenant-a,workspace:workspace-a`
- `IDENTRAIL_AUDIT_LOG_FILE=/tmp/identrail-audit.jsonl`
- `IDENTRAIL_CONNECTOR_SECRET_KEYS=v1:<base64-32-byte-key>` and `IDENTRAIL_CONNECTOR_SECRET_KEYS_REQUIRED=true` for durable connector credential storage
- `IDENTRAIL_AUDIT_FINGERPRINT_SECRET=<strong-secret>` for keyed audit pseudonymization

Do not also provision `IDENTRAIL_API_KEYS`/`IDENTRAIL_WRITE_API_KEYS` for this quickstart. Those legacy key lists are an alternative mode for simpler local deployments; when `IDENTRAIL_API_KEY_SCOPES` is set, scoped keys are the authorization source of truth.

Scoped API key bindings are enforced before tenant/workspace headers are accepted. For API key callers, `X-Identrail-Tenant-ID` and `X-Identrail-Workspace-ID` must match the key binding metadata.

Optional hardening:
- `IDENTRAIL_AUDIT_FORWARD_URL=https://audit.example.com/events`
- `IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET=<strong-secret>`

## 2. Start the Stack

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
```

## 3. Export Command Variables

Use the exact keys configured in `deploy/docker/.env`:

```bash
export IDENTRAIL_API_URL="http://localhost:8080"
export IDENTRAIL_WEB_URL="http://localhost:8081"
export IDENTRAIL_TENANT_ID="tenant-a"
export IDENTRAIL_WORKSPACE_ID="workspace-a"
export IDENTRAIL_READER_KEY="<reader-key-from-.env>"
export IDENTRAIL_WRITER_KEY="<writer-key-from-.env>"
export IDENTRAIL_ADMIN_KEY="<admin-key-from-.env>"
```

If you are using the web dashboard:
- Hosted deployments sign in through the normal session-auth routes. Local
  Docker quickstarts can use manual workspace entry only for disposable
  development.
- Manual workspace entry is disabled by default for production-safe deployments.
- Demo-only local override: set `VITE_ALLOW_MANUAL_PRODUCT_SESSION=true` in `deploy/docker/.env`, then rebuild the web image so Vite receives the flag at build time (for example: `docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build web`).

## 4. Health and Auth Smoke Checks

```bash
curl -sS "${IDENTRAIL_API_URL}/healthz"
```

```bash
curl -sS "${IDENTRAIL_API_URL}/v1/scans?limit=5" \
  -H "X-API-Key: ${IDENTRAIL_READER_KEY}" \
  -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
  -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" | jq .
```

## 5. Choose a Source Onboarding Path

For team deployments, connect sources through project-scoped onboarding so
findings stay tied to the tenant, workspace, and project that owns the risk.

- GitHub App repository scans: [GitHub connector](./auth/github-connector.md)
- AWS account onboarding: [AWS connector](./auth/aws-connector.md)
- Kubernetes cluster onboarding: [Kubernetes connector](./auth/kubernetes-connector.md)

Keep the first connector read-only. After it validates cleanly, trigger a scan
and review findings in the web app or API.

## 6. Trigger and Verify a Scan

```bash
SCAN_ID=$(
  curl -sS -X POST "${IDENTRAIL_API_URL}/v1/scans" \
    -H "X-API-Key: ${IDENTRAIL_WRITER_KEY}" \
    -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
    -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" \
  | jq -r '.scan.id'
)
echo "scan_id=${SCAN_ID}"
```

```bash
curl -sS "${IDENTRAIL_API_URL}/v1/scans/${SCAN_ID}/events?limit=10" \
  -H "X-API-Key: ${IDENTRAIL_READER_KEY}" \
  -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
  -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" | jq .
```

## 7. Verify AuthZ Decision Explainability

`/v1/authz/policies/simulate` requires an API key mapped to `admin` scope.

```bash
curl -sS -X POST "${IDENTRAIL_API_URL}/v1/authz/policies/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${IDENTRAIL_ADMIN_KEY}" \
  -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
  -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" \
  -d '{
    "subject": {"type":"subject","id":"user-1","roles":["admin"]},
    "action": "findings.read",
    "resource": {"type":"finding","id":"finding-1"},
    "context": {"request_path":"/v1/findings","request_method":"GET"}
  }' | jq '{decision, trace}'
```

Expected:
- `decision` contains `allowed`, `stage`, `reason`
- `trace` includes ordered stages from tenant isolation through default deny

## 8. Verify Decision Audit Log

```bash
docker exec identrail-api sh -lc 'tail -n 50 /tmp/identrail-audit.jsonl' \
  | jq -c 'select(.authz != null) | {method,path,status,authz}'
```

Confirm:
- authz decision block exists for protected routes
- no raw API key values in audit payload
- subject/resource IDs appear only as hashed identifiers (`*_id_hash`)

## 9. Set Up Native SAML SSO (Optional)

Native enterprise SSO requires `IDENTRAIL_FEATURE_NATIVE_SSO=true` on the API.
Native SAML admin and login routes also require
`IDENTRAIL_FEATURE_NEW_AUTH=true`, `IDENTRAIL_PUBLIC_BASE_URL`, and
`IDENTRAIL_SESSION_KEY`. Provider consoles change often, so this guide uses the
generic SAML labels you will see in most IdPs instead of maintaining separate
vendor click paths.

Identrail values to copy into your IdP's SAML app:
- **ACS URL / Reply URL:** `${IDENTRAIL_API_URL}/auth/saml/acs/<connection_id>`
- **Audience / SP Entity ID:** `${IDENTRAIL_API_URL}/auth/saml/metadata/<connection_id>`
- **Start URL / Sign-on URL:** `${IDENTRAIL_API_URL}/auth/saml/login/<connection_id>`
- **Name ID format:** email address
- **Name ID value:** the user's verified email address

The SP Entity ID is a SAML audience identifier. The current API does not serve
an SP metadata document from that URL.

Generic setup flow:
1. Create the Identrail SAML connection in the API or app and note the returned `connection_id`.
2. In your IdP, create a custom SAML application named `Identrail`.
3. Paste the ACS URL and SP Entity ID above into the IdP's SAML settings.
4. Configure the Name ID to send a verified user email address.
5. Save the app and copy the IdP metadata URL or metadata XML.
6. Import that metadata into the Identrail SAML connection and confirm the parsed Entity ID, SSO URL, and certificate fingerprint.
7. Assign only a small admin test group until the first login and SCIM checks pass.

## 10. Enable SCIM Provisioning (Optional)

Each native SAML connection receives one SCIM bearer token when it is created. Identrail returns the plaintext token once; store it in the IdP immediately. The API stores only the token hash.

SCIM values:
- **Base URL / Tenant URL:** `${IDENTRAIL_API_URL}/scim/v2`
- **Secret Token / Bearer token:** the one-time SCIM token from the Identrail connection response
- **Supported resources:** Users only; Groups are intentionally deferred
- **Supported filter:** `userName eq "value"`

Generic SCIM setup flow:
1. Open the provisioning settings for the same SAML app in your IdP.
2. Enable SCIM or API provisioning.
3. Paste `${IDENTRAIL_API_URL}/scim/v2` as the Base URL or Tenant URL.
4. Paste the one-time Identrail SCIM bearer token as the Secret Token or API Token.
5. Test the credentials from the IdP.
6. Enable create, update, deactivate, and delete operations for users.
7. Keep group provisioning disabled until Identrail adds group-resource support.

## 11. Roll Out SSO-Only (`sso_required`)

Keep `sso_required=false` until at least one SAML admin has completed a
successful sign-in and SCIM provisioning has created or matched the expected
users. The API persists the flag on the connection as the org's rollout
marker; it does not yet ship recovery-code generation or a full
lockout-rescue flow.

Recommended rollout:
1. Create the native SAML connection with `sso_required=false`.
2. Assign a small admin test group in your IdP.
3. Confirm SAML login creates a `saml:<connection_id>` identity for the admin.
4. Enable SCIM provisioning and confirm a test create/update/deactivate writes one `scim_provisioning_events` row and, when a workflow router is configured, one workflow dispatch audit record.
5. Flip `sso_required=true` only after the operator has verified the break-glass path they intend to use.
6. Keep a break-glass admin path outside the enforced tenant while the first customer tenant is onboarding.

Workflow dispatch verification, when a router is configured:
```bash
docker exec identrail-api sh -lc 'tail -n 50 /tmp/identrail-audit.jsonl' \
  | jq -c 'select(.event_kind == "scim.provisioned") | {event_kind,subject_id,connection_id,scim_op,destination,success}'
```

Confirm:
- one `scim.provisioned` workflow audit record appears for each SCIM create/update/deactivate/delete dispatch attempt
- `connection_id` matches the native SAML connection
- `scim_op` matches the SCIM lifecycle operation
- failed Slack/Jira/Linear attempts include `success=false` and an `error` string

## 12. Executive Report (Board-Ready)

Fetch the leadership rollup for the current organization. The response is
JSON only — there is no server-side PDF; use the printable web report page
and your browser's Save as PDF for a board-ready document.

Open the web route after signing in:
```text
${IDENTRAIL_WEB_URL}/reports/executive
```

Use the browser print dialog (`Cmd+P` on macOS or `Ctrl+P` on Windows/Linux)
and choose Save as PDF. The print stylesheet removes navigation and action
chrome so the exported document contains only the executive report.

```bash
curl -fsS "${IDENTRAIL_API_URL}/v1/enterprise/reports/executive" \
  -H "Cookie: ${IDENTRAIL_SESSION_COOKIE}" | jq
```

Notes:

- Requires the `enterprise.read` scope and an organization-scoped session.
- Responses are cached per organization for 60 seconds, so rapid refreshes
  return the same snapshot.
- `mean_time_to_resolve` is present only when at least one resolved finding
  carries a trustworthy `resolved_at`; it is derived solely from `resolved_at`
  (never the mutable `updated_at`), so the figure is not a guess.

## 13. Clean Shutdown

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env down
```
