# AWS Normalizer and Graph

## Purpose

This module converts raw IAM role assets into normalized domain entities and graph edges that the risk engine can evaluate consistently.

## Components

- `RoleNormalizer`
- `PolicyPermissionResolver`
- `RelationshipBuilder`

## Flow

1. Raw IAM role assets are normalized into `Identity` and `Policy` records.
2. Permission policies are expanded into semantic permission tuples (`identity`, `action`, `resource`, `effect`).
3. Graph relationships are built:
   - `attached_policy` (identity -> policy)
   - `can_assume` (principal -> identity)
   - `can_access` (identity -> access node)

The wider graph contract also supports precise AWS machine and agent identity
edges such as `runs_as`, `uses_secret`, `can_decrypt`, `can_pass_role`,
`invokes`, `calls_tool`, `acts_for_user`, `has_runtime_session`, and
`observed_action`. The current IAM graph builder only emits edges it can prove
from collected IAM role and policy evidence; later collectors should use the
precise edge types instead of overloading `can_access` when runtime, secret,
KMS, agent, or delegation evidence is available.

## Key Decisions

- Trust and permission policies are retained as normalized policy records, preserving explainability.
- IDs are deterministic so reruns remain idempotent.
- URL-encoded trust policy documents are supported to match real IAM API behavior.
- Duplicate identities, policies, permission tuples, and edges are deduplicated.

## Edge Cases Covered

- malformed role payloads
- malformed policy documents
- context cancellation during normalization/resolution
- mixed principal formats (`string`, `[]string`)
- policy statement shapes (`object` or `array`)

## Test Strategy

Fixture-based tests validate realistic role payloads from `testdata/aws/`, including trust + permission policy combinations and URL-encoded trust documents.
