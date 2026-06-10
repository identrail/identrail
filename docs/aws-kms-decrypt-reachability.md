# AWS KMS Key Policy and Decrypt Reachability Collector

## Purpose

Issue #1489 adds a read-only, metadata-only collector for AWS KMS keys and
the identity reachability inferred from each key's policy *and* its live
KMS grants. The collector emits one normalized record per key, capturing
key manager (customer vs AWS), key state and spec, multi-region replica
linkage, rotation status, aliases, the parsed key-policy grants, and the
live KMS grants surfaced via `ListGrants`. Each key is classified into
one of `public`, `cross_account`, `restricted`, `managed_by_iam`,
`managed_by_aws`, `private_with_grants`, or `private`.

The collector **never decrypts, encrypts, signs, verifies, or generates
data keys**, never reads ciphertext or plaintext, never reads CloudTrail
event bodies, and never reads encryption-context *values* (only the
constraint *keys*, since the values can carry tenant-identifying data).

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/kms-decrypt-reachability
```

Optional query parameters:

- `connector_id`: scopes the account, region, and read-only inventory
  evidence to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`,
  or `permission_denied` for deterministic UI/contract validation.

The response returns `inventory`, including records, `can_decrypt`
relationships, diagnostics, coverage gaps, status, confidence, exposure
counts, grant counts, and issue evidence links.

## Evidence Collected

Per key:

- Key ARN, key id, region, account, key manager (`CUSTOMER` or `AWS`),
  state, usage (`ENCRYPT_DECRYPT` / `SIGN_VERIFY` / ...), spec, origin,
  description, and `enabled` flag.
- Aliases attached to the key (names only; ARN form is deterministic and
  derivable).
- Rotation surface: whether rotation *can* be enabled for this key type
  (symmetric customer-managed keys with `AWS_KMS` or `EXTERNAL` origin)
  and whether it *is* enabled today.
- Multi-region linkage: whether the key is multi-region, whether it is
  the primary, and the ARNs of the primary and replica keys.
- Key policy: presence, statement count, whether the canonical
  `EnableIAMUserPermissions` IAM-delegation statement is present, plus
  one inferred grant per `(principal, action, effect)` tuple. Each grant
  carries the action list, a capability bucket
  (`decrypt`, `encrypt`, `admin`, `grant`, `sign`), condition keys,
  cross-account / public flags, and the statement Sid.
- Live KMS grants (a separate AWS primitive from key policies):
  grant id, grantee principal (or service principal), retiring
  principal, issuing account, operation list, capability bucket, the
  *keys* (not values) of any encryption-context constraint, and a
  cross-account flag.
- Tag map.
- Exposure classification + reasons (e.g.
  `kms_key_policy_allow_to_wildcard_principal`,
  `kms_key_policy_explicit_deny_to_all`,
  `kms_key_policy_delegates_to_iam`,
  `kms_live_grant_to_cross_account_principal`,
  `kms_managed_by_aws`).
- Confidence tier:
  - `0.95` for public exposure.
  - `0.92` for cross-account exposure.
  - `0.90` for explicit-deny restricted keys.
  - `0.88` for IAM-delegation-only keys.
  - `0.87` for private keys with specific grants.
  - `0.85` for AWS-managed keys (not customer-actionable).
  - `0.84` for fully private keys.
  - `0.70` when classification is unknown.

For each resolved IAM principal granted Allow access via either the key
policy or a live KMS grant, a graph edge is emitted (`can_decrypt`, from
the principal node to the key). Wildcard principals (`*`), service
principals (e.g. `lambda.amazonaws.com`), federated principals, and Deny
statements are surfaced in the record's grants but do not produce
directed edges. Edges record both the source (`key_policy` vs
`kms_grant`) and the capability bucket so downstream code can filter
"who can decrypt this key" without re-parsing actions.

## Required AWS Permissions

The connector role (`internal/connectors/aws/iam_policy.go`) grants the
following read-only KMS actions:

- `kms:ListKeys`
- `kms:DescribeKey`
- `kms:GetKeyPolicy`
- `kms:GetKeyRotationStatus`
- `kms:ListAliases`
- `kms:ListGrants`
- `kms:ListResourceTags`

These are metadata-only calls. The connector role is forbidden from
holding `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey*`,
`kms:ReEncrypt*`, `kms:Sign`, `kms:Verify`, `kms:CreateGrant`,
`kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, or any other cryptographic
or mutating KMS action.

## What Is Intentionally Not Collected

- Plaintext, ciphertext, derived data keys, signatures, and verification
  results.
- CloudTrail KMS event bodies and per-call audit records.
- Encryption-context *values* on live grants. The *keys* are recorded
  because they describe the constraint shape; the values can encode
  tenant or customer identifiers and are surfaced as a documented
  coverage gap (`encryption_context_values`).
- Subset-match grant constraint evaluation. The wave records the
  constraint keys but does not yet evaluate whether a caller's
  encryption context satisfies the subset relation
  (`grant_constraint_subset_match`).
- Resolution of `kms:ViaService` and `kms:CallerAccount` condition
  values into specific identity nodes
  (`via_service_condition_resolution`). The condition *keys* are
  recorded; resolving them into specific service or account identities
  is tracked separately.

## Fixture States

| State              | Purpose                                                                                          |
|--------------------|--------------------------------------------------------------------------------------------------|
| `success`          | Five keys: one private-with-grants CMK, one public CMK, one cross-account CMK, one AWS-managed key, one explicit-deny restricted CMK. |
| `empty`            | No keys; coverage gaps still surfaced.                                                           |
| `degraded`         | The public CMK loses rotation and reports degraded status + `kms_rotation_disabled` diagnostic.   |
| `partial_failure`  | First three keys remain; a `kms_list_grants_failed` diagnostic explains the gap.                  |
| `permission_denied`| Inventory is blocked; a `permission_denied` diagnostic is returned.                              |

## Live Validation

When running against a real AWS account:

```bash
export IDENTRAIL_AWS_SOURCE=sdk
export IDENTRAIL_AWS_REGION="<region>"
export IDENTRAIL_AWS_ACCOUNT_ID="<account_id>"

state_file="/tmp/identrail-kms-state.json"
go run ./cmd/cli --state-file "${state_file}" scan --output table
```

Verify that:

- Every emitted record has a non-empty `key_arn` and `key_id`.
- `exposure_classification` is one of `public`, `cross_account`,
  `restricted`, `managed_by_iam`, `managed_by_aws`,
  `private_with_grants`, or `private`.
- AWS-managed keys (alias prefix `alias/aws/`) classify as
  `managed_by_aws` and never trigger findings.
- `EnableIAMUserPermissions`-only customer-managed keys classify as
  `managed_by_iam`, not `private_with_grants` or `public`.
- Encryption-context *values* never appear in the response — only the
  *keys* on `grants[].encryption_context_keys`.
- No call output references `Decrypt`, `Encrypt`, `GenerateDataKey`,
  `Sign`, `Verify`, or any other cryptographic operation.

## Troubleshooting

| Diagnostic code                                | Likely cause                                                | Operator action                                                                              |
|------------------------------------------------|-------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `permission_denied`                            | Connector role missing read-only KMS metadata permissions   | Grant the actions listed above; do not enable cryptographic APIs.                            |
| `kms_decrypt_reachability_page_failed`         | `ListKeys` throttled or denied                              | Retry; already-collected records remain visible.                                              |
| `kms_decrypt_reachability_page_limit_exceeded` | Key pagination exceeded max-pages cap                       | Increase the page cap or scope the connector to a smaller account before retrying.            |
| `kms_describe_key_failed`                      | `DescribeKey` failed for one key                            | Retry only the failed call; preserve previously-collected evidence.                           |
| `kms_key_policy_failed`                        | `GetKeyPolicy` failed for one key                           | Retry; an absent policy is not a diagnostic, a denied call is.                                |
| `kms_key_policy_parse_failed`                  | Key policy is not valid JSON                                | Audit the policy in the AWS console; the collector skips unparseable policies.                |
| `kms_key_rotation_failed`                      | `GetKeyRotationStatus` denied                               | Retry; rotation-unsupported key types are recognised separately and do not produce a diagnostic. |
| `kms_rotation_disabled`                        | Rotation-capable customer-managed key has rotation disabled | Enable automatic rotation or document the exception.                                          |
| `kms_list_grants_failed`                       | `ListGrants` failed for one key                             | Retry only the failed call; preserve previously-collected evidence.                           |
| `kms_list_aliases_failed`                      | Account-level `ListAliases` denied or throttled             | Retry; without aliases the per-key alias list will be empty but classification is unaffected. |
| `kms_list_tags_failed`                         | `ListResourceTags` denied or throttled                      | Retry; absence of tags is silent.                                                             |
| `kms_key_id_missing`                           | A `ListKeys` summary did not include an id or ARN           | Confirm the response shape upstream; the collector skips ambiguous records.                   |
| `malformed_kms_decrypt_reachability_record`    | Record has no key id after normalization                    | Confirm `ListKeys` returned keys with ids; the collector skips ambiguous records.             |
