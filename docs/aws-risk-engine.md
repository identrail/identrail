# AWS Risk Engine

## Purpose

The AWS risk engine evaluates normalized identities and graph relationships to produce typed, explainable findings.

## Findings Implemented

- `overprivileged_identity`
- `risky_trust_policy`
- `escalation_path`
- `stale_identity`
- `ownerless_identity`
- `aws-blast-radius:*` intelligence records from the AWS blast radius engine

## Rule Inputs

- Normalized identities from the AWS normalizer
- Relationship edges from the graph builder (`can_assume`, `can_access`, `attached_policy`)
- AWS runtime correlation surfaces for Secrets Manager / KMS, S3, and agent/tool paths

## Detection Logic (v1)

- Overprivileged: wildcard/admin-capable actions or wildcard resources
- Risky trust: wildcard or cross-account trust principals
- Escalation path: risky trust combined with escalation-capable access
- Stale: last used (or created) exceeds threshold (default 90 days)
- Ownerless: no owner hint present

## Design Decisions

- Deterministic finding IDs to keep reruns idempotent
- Severity ordering is stable (`critical` -> `high` -> `medium` ...)
- Evidence-first findings with machine-readable context and clear remediation text
- Encoded access nodes to avoid ARN delimiter parsing issues
- Unknown runtime evidence lowers confidence instead of becoming deterministic truth

## Blast Radius Intelligence

The Wave 6.01 blast-radius engine is documented in [aws-blast-radius-engine.md](aws-blast-radius-engine.md). It composes existing AWS runtime and reachability signals into ranked, explainable identity findings with impacted paths, evidence references, confidence, calculation version, and read-only remediation previews.

The Wave 6.07 secret-to-permission equivalence engine is documented in
[aws-secret-permission-equivalence-engine.md](aws-secret-permission-equivalence-engine.md).
It treats readable secrets, provider keys, and KMS-backed credentials as
permission-bearing capabilities while preserving the metadata-only evidence
boundary.

## Tunables

- `WithStaleAfter(duration)`
- `WithRuleClock(nowFunc)`
