# Auth Documentation

This folder holds the architectural foundation for Identrail's signup, sign-in, SSO, SCIM, and connector onboarding work. The docs are the source of truth for the twelve-PR delivery sequence.

## Read Order

Start at the top. Each later doc fills in detail for one section of the first.

1. [`architecture.md`](./architecture.md) - the entry point. Reads in 10 minutes. Decisions, identity model, endpoint surface, domain plan.
2. [`threat-model.md`](./threat-model.md) - the attacks we are defending against and the defense for each.
3. [`identity-linking-rules.md`](./identity-linking-rules.md) - how we connect provider identities to Identrail accounts. Has the account-takeover exploit narrative.
4. [`cookie-and-session-spec.md`](./cookie-and-session-spec.md) - exact cookie attributes, session lifetimes, rotation rules.
5. [`connector-foundation.md`](./connector-foundation.md) - the Provider interface, status state machine, and error taxonomy that every connector implements.
6. [`env-vars-reference.md`](./env-vars-reference.md) - flat list of every environment variable across the twelve PRs.
7. [`12-pr-plan.md`](./12-pr-plan.md) - the canonical scope for each of the twelve PRs.

## When to Update These Docs

Update the doc before changing the code. If a PR changes a contract documented here, that PR updates the doc in the same commit. The doc is part of the PR, not an afterthought.

When a doc and the code disagree, the doc is wrong. Fix the doc. Then either change the code to match or change the doc to match new agreed reality.

## Related Existing Docs

- [`../auth-scope-and-claims.md`](../auth-scope-and-claims.md) covers OIDC claim mapping and scope resolution. Stays valid alongside the new work.
- [`../authz-operator-runbook.md`](../authz-operator-runbook.md) covers RBAC and ABAC operations. Unaffected by this work.
- [`../authz-policy-rollout-runbook.md`](../authz-policy-rollout-runbook.md) covers policy rollout. Unaffected.

## Status

This doc set lands in PR 1 of the twelve-PR sequence. The other eleven PRs implement what these docs describe.
