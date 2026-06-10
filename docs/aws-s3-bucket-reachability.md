# AWS S3 Resource and Bucket-Policy Reachability Collector

## Purpose

Issue #1488 adds a read-only, metadata-only collector for S3 buckets and the
identity reachability inferred from their bucket policies. The collector
emits one normalized record per bucket, capturing public-access-block (PAB)
state, ownership controls, default encryption, access points, tags, and the
identity grants extracted from the bucket policy. It also classifies each
bucket's exposure (`public`, `cross_account`, `restricted`,
`private_with_grants`, or `private`).

The collector **never reads object contents**, never lists bucket objects,
never issues presigned URLs, and never inspects per-object ACL grants.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/s3-bucket-reachability
```

Optional query parameters:

- `connector_id`: scopes the account, region, and read-only inventory
  evidence to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`,
  or `permission_denied` for deterministic UI/contract validation.

The response returns `inventory`, including records, `can_access`
relationships, diagnostics, coverage gaps, status, confidence, exposure
counts, grant counts, and issue evidence links.

## Evidence Collected

Per bucket:

- Bucket name, ARN (partition-aware), region, and creation time.
- Whether a bucket policy exists, its statement count, and the parsed
  identity grants (one per `(principal, action, effect)` tuple).
- PublicAccessBlock state (`block_public_acls`, `ignore_public_acls`,
  `block_public_policy`, `restrict_public_buckets`).
- Ownership controls (e.g. `BucketOwnerEnforced`).
- Default encryption algorithm and KMS key ARN if present, plus
  `bucket_key_enabled`.
- Access point names, ARNs, network origin (`Internet` / `VPC`), and VPC IDs.
- Tag map.
- Exposure classification + reasons (e.g.
  `bucket_policy_allow_to_wildcard_principal`,
  `public_access_block_fully_enabled`,
  `bucket_policy_explicit_deny_to_all`).
- Confidence tier:
  - `0.95` for public exposure.
  - `0.92` for cross-account exposure.
  - `0.90` for explicit-deny restricted buckets.
  - `0.88` for private buckets with grants.
  - `0.86` for fully private buckets.
  - `0.70` when classification is unknown.

For each resolved IAM principal granted Allow access, a graph edge is
emitted (`can_access`, from the principal node to the bucket). Wildcard
principals (`*`), service principals (e.g. `lambda.amazonaws.com`), and
Deny statements are surfaced in the record's `identity_grants` but do not
produce directed edges.

## Required AWS Permissions

The connector role (`internal/connectors/aws/iam_policy.go`) grants the
following read-only S3 actions:

- `s3:ListAllMyBuckets`
- `s3:GetBucketLocation`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketOwnershipControls`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketTagging`
- `s3:ListAccessPoints`

These are metadata-only calls. The connector role is forbidden from holding
`s3:GetObject*`, `s3:ListBucket`, or any write/delete actions.

## What Is Intentionally Not Collected

- Object contents, presigned URLs, object versions, or object metadata.
- Per-object ACL grants. Buckets with Object Ownership =
  `BucketOwnerEnforced` make this moot; on others, this is a documented
  coverage gap (`object_acl_grants`).
- Access point policy documents. Names, ARNs, and VPC origins are recorded;
  the policy parser is tracked as a separate coverage gap
  (`access_point_policies`).
- VPC endpoint policy reachability. Surfaced as
  `vpc_endpoint_policies` coverage gap.
- S3 inventory configurations, lifecycle rules, replication rules, and
  notification configurations — these are not reachability signals.

## Fixture States

| State              | Purpose                                                                                              |
|--------------------|------------------------------------------------------------------------------------------------------|
| `success`          | Four buckets: one public, one cross-account, one restricted (deny-all + KMS), one private-with-grants. |
| `empty`            | No buckets; coverage gaps still surfaced.                                                            |
| `degraded`         | The public bucket loses PAB and reports degraded status + missing-PAB diagnostic.                    |
| `partial_failure`  | First three buckets remain; a `s3_bucket_policy_failed` diagnostic explains the gap.                 |
| `permission_denied`| Inventory is blocked; a `permission_denied` diagnostic is returned.                                  |

## Live Validation

When running against a real AWS account:

```bash
export IDENTRAIL_AWS_SOURCE=sdk
export IDENTRAIL_AWS_REGION="<region>"
export IDENTRAIL_AWS_ACCOUNT_ID="<account_id>"

state_file="/tmp/identrail-s3-state.json"
go run ./cmd/cli --state-file "${state_file}" scan --output table
```

Verify that:

- Every emitted record has a non-empty `bucket_arn` and `bucket_name`.
- `exposure_classification` is one of `public`, `cross_account`,
  `restricted`, `private_with_grants`, or `private`.
- No object-level evidence (no presigned URLs, no `GetObject` references)
  appears in the output.
- Cross-account grants carry `is_cross_account: true` only when the
  principal's account differs from the bucket-owning account.

## Troubleshooting

| Diagnostic code                            | Likely cause                                                  | Operator action                                                                              |
|--------------------------------------------|---------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `permission_denied`                        | Connector role missing read-only S3 metadata permissions      | Grant the actions listed above; do not enable object-content APIs.                            |
| `s3_bucket_reachability_page_failed`       | `ListBuckets` throttled or denied                             | Retry; already-collected records remain visible.                                              |
| `s3_bucket_reachability_page_limit_exceeded` | Bucket pagination exceeded max-pages cap                   | Increase the page cap or scope the connector to a smaller account before retrying.            |
| `s3_bucket_policy_failed`                  | `GetBucketPolicy` failed for one bucket                       | Retry only the failed call; preserve previously-collected evidence.                           |
| `s3_public_access_block_failed`            | `GetPublicAccessBlock` denied or throttled                    | Retry; an absent PAB on its own is not a diagnostic, but a denied call is.                    |
| `s3_public_access_block_absent`            | The bucket has no PublicAccessBlock configuration             | Enable PAB on the bucket and re-scan.                                                         |
| `s3_ownership_controls_failed`             | `GetBucketOwnershipControls` denied or throttled              | Retry; absent ownership controls are not a diagnostic, denied calls are.                      |
| `s3_bucket_encryption_failed`              | `GetBucketEncryption` denied or throttled                     | Retry; legacy unencrypted buckets simply lack `default_encryption_algorithm`.                 |
| `s3_bucket_tagging_failed`                 | `GetBucketTagging` denied or throttled                        | Retry; absence of tags is silent.                                                             |
| `s3_bucket_location_failed`                | `GetBucketLocation` denied or throttled                       | Retry; without region the bucket may show an empty region.                                    |
| `s3_access_points_failed`                  | `ListAccessPoints` (s3control) denied or throttled            | Retry; absence of access points is silent.                                                    |
| `s3_bucket_policy_parse_failed`            | Bucket policy is not valid JSON                               | Audit the policy in the AWS console; the collector skips unparseable policies.                |
| `malformed_s3_bucket_reachability_record`  | Record has no ARN or name after normalization                 | Confirm `ListBuckets` returned a bucket with a name; the collector skips ambiguous records.   |
