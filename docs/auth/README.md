# Auth Documentation

This folder holds the architectural foundation for Identrail's signup, sign-in,
SSO, SCIM, and connector onboarding work. The current implementation ships
WorkOS hosted login plus opt-in native SAML and SCIM behind
`IDENTRAIL_FEATURE_NATIVE_SSO`.

## Read Order

Start at the top. Each later doc fills in detail for one section of the first.

1. [`architecture.md`](./architecture.md) - the entry point. Reads in 10 minutes. Decisions, identity model, endpoint surface, domain plan.
2. [`threat-model.md`](./threat-model.md) - the attacks we are defending against and the defense for each.
3. [`identity-linking-rules.md`](./identity-linking-rules.md) - how we connect provider identities to Identrail accounts. Has the account-takeover exploit narrative.
4. [`cookie-and-session-spec.md`](./cookie-and-session-spec.md) - exact cookie attributes, session lifetimes, rotation rules.
5. [`connector-foundation.md`](./connector-foundation.md) - the Provider interface, status state machine, and error taxonomy that every connector implements.
6. [`aws-connector.md`](./aws-connector.md) - the standard AWS CloudFormation connector path.
7. [`github-connector.md`](./github-connector.md) - the standard GitHub App and GitHub Enterprise connector path.
8. [`kubernetes-connector.md`](./kubernetes-connector.md) - the standard in-cluster agent and kubeconfig fallback path.
9. [`production-api-readiness.md`](./production-api-readiness.md) - the production web/API split required before the frontend auth UI can work on Vercel.
10. [`env-vars-reference.md`](./env-vars-reference.md) - flat list of authentication-related environment variables.
11. [`12-pr-plan.md`](./12-pr-plan.md) - superseded roadmap file that now records the current three-track plan.

## When to Update These Docs

Update the doc before changing the code. If a PR changes a contract documented here, that PR updates the doc in the same commit. The doc is part of the PR, not an afterthought.

When a doc and the code disagree, the doc is wrong. Fix the doc. Then either change the code to match or change the doc to match new agreed reality.

## Related Existing Docs

- [`../auth-scope-and-claims.md`](../auth-scope-and-claims.md) covers OIDC claim mapping and scope resolution. Stays valid alongside the new work.
- [`../authz-operator-runbook.md`](../authz-operator-runbook.md) covers RBAC and ABAC operations. Unaffected by this work.
- [`../authz-policy-rollout-runbook.md`](../authz-policy-rollout-runbook.md) covers policy rollout. Unaffected.

## Status

The original twelve-PR sequence has been superseded by the three-track roadmap
in [`12-pr-plan.md`](./12-pr-plan.md). When implementation and docs disagree,
the implementation on `dev` wins and the docs should be corrected in the same
PR.
