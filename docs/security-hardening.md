# Security Hardening Guide

This page is the v1 security baseline for operators.

## 1) Secret Handling

- Never commit real keys or database URLs.
- Use environment injection through:
  - Docker `.env` (dev only)
  - Kubernetes Secret
  - Terraform sensitive variables
- Treat local `.env.local` OIDC tokens as ephemeral credentials and regenerate on demand.
- Prefer OIDC (`IDENTRAIL_OIDC_ISSUER_URL` + `IDENTRAIL_OIDC_AUDIENCE`) over static API keys for human access.
- See local handling runbook: `local-token-hygiene.md`.

## 2) API Key Hardening

- Keep separate read/write keys.
- Generate high-entropy keys (24+ chars).
- Keep overlap during rotation: old + new keys at the same time, then remove old keys.
- Write endpoints always require write scope/key.

## 3) Key Rotation Hook (No Downtime)

1. Add new keys/scopes to secret/env.
2. Roll API and worker.
3. Move clients to new keys.
4. Remove old keys.
5. Roll API and worker again.

This works because Identrail supports multi-key auth during transition.

## 4) Least-Privilege Integration

- AWS policy template:
  - `deploy/policies/aws/identrail-readonly-iam-policy.json`
- Kubernetes RBAC template:
  - `deploy/policies/kubernetes/identrail-readonly-clusterrole.yaml`

Use dedicated scanner identities. Do not reuse admin credentials.

## 5) Audit and Alert Integrity

- Enable durable audit sink (`IDENTRAIL_AUDIT_LOG_FILE`).
- Use signed audit forwarding (`IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET`).
- Use signed alert webhooks (`IDENTRAIL_ALERT_HMAC_SECRET`).
- Keep remote endpoints on HTTPS.
