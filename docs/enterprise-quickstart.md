# Enterprise 5-Minute Quickstart

This quickstart gets Identrail running with enterprise-safe defaults for auth scope, tenant/workspace context, and decision audit logging.

## Prerequisites

- Docker + Docker Compose
- `curl` + `jq`

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
export IDENTRAIL_TENANT_ID="tenant-a"
export IDENTRAIL_WORKSPACE_ID="workspace-a"
export IDENTRAIL_READER_KEY="<reader-key-from-.env>"
export IDENTRAIL_WRITER_KEY="<writer-key-from-.env>"
export IDENTRAIL_ADMIN_KEY="<admin-key-from-.env>"
```

If you are using the web dashboard:
- Preferred: sign in through OIDC (`/app/login`) so API credentials and scope come from the identity provider session.
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

## 5. Trigger and Verify a Scan

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

## 6. Verify AuthZ Decision Explainability

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

## 7. Verify Decision Audit Log

```bash
docker exec identrail-api sh -lc 'tail -n 50 /tmp/identrail-audit.jsonl' \
  | jq -c 'select(.authz != null) | {method,path,status,authz}'
```

Confirm:
- authz decision block exists for protected routes
- no raw API key values in audit payload
- subject/resource IDs appear only as hashed identifiers (`*_id_hash`)

## 8. Set Up SSO With Okta

Native enterprise SSO requires `IDENTRAIL_FEATURE_NATIVE_SSO=true` on the API. Create the Identrail SAML connection first, then paste the IdP metadata URL into Identrail so the connection can validate Okta assertions.

Identrail values to copy into Okta:
- **Single sign-on URL / ACS URL:** `${IDENTRAIL_API_URL}/auth/saml/acs/<connection_id>`
- **Audience URI / SP Entity ID:** `${IDENTRAIL_API_URL}/auth/saml/metadata/<connection_id>`
- **Name ID format:** `EmailAddress`
- **Application username:** `Email`

Okta click path:
1. Open **Okta Admin Console -> Applications -> Applications -> Create App Integration**.
2. Select **SAML 2.0**, then **Next**.
3. Enter `Identrail` as the app name.
4. On **Configure SAML**, paste the Identrail ACS URL into **Single sign-on URL**.
5. Paste the Identrail SP Entity ID into **Audience URI (SP Entity ID)**.
6. Set **Name ID format** to `EmailAddress` and **Application username** to `Email`.
7. Finish the wizard.
8. Open the new app's **Sign On** tab.
9. In **SAML Signing Certificates**, copy **Identity Provider metadata** or **Metadata URL**.
10. In Identrail, open the enterprise SSO connection and paste the metadata URL, then confirm the parsed Entity ID, SSO URL, and certificate fingerprint.

Screenshot placeholders:
- `[Screenshot placeholder: Okta Create App Integration modal with SAML 2.0 selected]`
- `[Screenshot placeholder: Okta Configure SAML page showing Single sign-on URL and Audience URI fields]`
- `[Screenshot placeholder: Okta Sign On tab showing Identity Provider metadata link]`

## 9. Set Up SSO With Azure AD

Microsoft now labels Azure AD as **Microsoft Entra ID** in the admin center. The click path below uses the current Entra labels while keeping the Azure AD wording operators still recognize.

Identrail values to copy into Azure AD:
- **Identifier (Entity ID):** `${IDENTRAIL_API_URL}/auth/saml/metadata/<connection_id>`
- **Reply URL (Assertion Consumer Service URL):** `${IDENTRAIL_API_URL}/auth/saml/acs/<connection_id>`
- **Sign on URL:** `${IDENTRAIL_API_URL}/auth/saml/login/<connection_id>`
- **Unique User Identifier / Name ID:** `user.mail` or `user.userprincipalname`

Azure AD / Entra click path:
1. Open **Microsoft Entra admin center -> Identity -> Applications -> Enterprise applications**.
2. Select **New application -> Create your own application**.
3. Name it `Identrail`, select **Integrate any other application you don't find in the gallery (Non-gallery)**, then **Create**.
4. Open **Single sign-on -> SAML**.
5. In **Basic SAML Configuration**, paste the Identrail Entity ID into **Identifier (Entity ID)**.
6. Paste the Identrail ACS URL into **Reply URL (Assertion Consumer Service URL)**.
7. Paste the Identrail SAML login URL into **Sign on URL**.
8. In **Attributes & Claims**, confirm the Name ID claim resolves to the user's email address.
9. In **SAML Certificates**, copy **App Federation Metadata Url**.
10. In Identrail, open the enterprise SSO connection and paste the metadata URL, then confirm the parsed Entity ID, SSO URL, and certificate fingerprint.

Screenshot placeholders:
- `[Screenshot placeholder: Entra Enterprise applications page with New application selected]`
- `[Screenshot placeholder: Entra SAML Basic SAML Configuration editor]`
- `[Screenshot placeholder: Entra SAML Certificates area showing App Federation Metadata Url]`

## 10. Enable SCIM Provisioning

Each native SAML connection receives one SCIM bearer token when it is created. Identrail returns the plaintext token once; store it in the IdP immediately. The API stores only the token hash.

SCIM values:
- **Base URL / Tenant URL:** `${IDENTRAIL_API_URL}/scim/v2`
- **Secret Token / Bearer token:** the one-time SCIM token from the Identrail connection response
- **Supported resources:** Users only; Groups are intentionally deferred
- **Supported filter:** `userName eq "value"`

Okta SCIM click path:
1. Open **Okta Admin Console -> Applications -> Applications -> Identrail**.
2. Open the **General** tab.
3. In **App Settings**, set **Provisioning** to `SCIM`, then save.
4. Open the **Provisioning** tab.
5. Select **Integration -> Configure API Integration**.
6. Check **Enable API integration**.
7. Paste `${IDENTRAIL_API_URL}/scim/v2` into **Base URL**.
8. Paste the Identrail SCIM bearer token into **API Token**.
9. Select **Test API Credentials** and confirm success.
10. Under **To App**, enable **Create Users**, **Update User Attributes**, and **Deactivate Users**.

Azure AD / Entra SCIM click path:
1. Open **Microsoft Entra admin center -> Identity -> Applications -> Enterprise applications -> Identrail**.
2. Open **Provisioning**.
3. Select **Get started** if provisioning has not been configured.
4. Set **Provisioning Mode** to `Automatic`.
5. Paste `${IDENTRAIL_API_URL}/scim/v2` into **Tenant URL**.
6. Paste the Identrail SCIM bearer token into **Secret Token**.
7. Select **Test Connection** and confirm success.
8. Save the provisioning configuration.
9. Keep the default user attribute mappings for `userName`, `active`, `displayName`, and `emails`.
10. Set **Provisioning Status** to `On` when ready.

Screenshot placeholders:
- `[Screenshot placeholder: Okta Provisioning Integration tab with Base URL and API Token fields]`
- `[Screenshot placeholder: Okta To App tab with Create, Update, and Deactivate enabled]`
- `[Screenshot placeholder: Entra Provisioning page with Tenant URL and Secret Token fields]`
- `[Screenshot placeholder: Entra Provisioning Status set to On]`

## 11. Enforce SSO-Only (`sso_required`)

Set `sso_required=true` only after at least one SAML admin has completed a successful sign-in and SCIM provisioning has created or matched the expected users. Enforcing too early can lock out local/manual fallback users.

Recommended rollout:
1. Create the native SAML connection with `sso_required=false`.
2. Assign a small admin test group in Okta or Azure AD.
3. Confirm SAML login creates a `saml:<connection_id>` identity for the admin.
4. Enable SCIM provisioning and confirm a test create/update/deactivate writes one `scim_provisioning_events` row and, when a workflow router is configured, one workflow dispatch audit record.
5. Flip `sso_required=true` on the connection.
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

## 12. Clean Shutdown

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env down
```
