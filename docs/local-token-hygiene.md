# Local Token Hygiene (Vercel OIDC)

This runbook prevents accidental leaks of short-lived local tokens pulled into `.env.local`.

## Why this matters

`VERCEL_OIDC_TOKEN` is a bearer credential. Even though `.env.local` is gitignored, leakage can still happen through:
- copied terminal output
- screenshots
- pasted debug files
- local artifact sharing

## Safe local workflow

1. Link the project when needed:
   - `vercel link`
2. Pull fresh local env values only when needed:
   - `vercel env pull .env.local`
3. Treat the token as ephemeral:
   - regenerate with `vercel env pull .env.local` when expired
   - do not reuse old copied values

## Rotation and containment

If token exposure is suspected:

1. Regenerate immediately:
   - `vercel env pull .env.local`
2. Remove local copies from scratch files, screenshots, and logs.
3. Re-run any failing local auth flow with the fresh token.

## Built-in guardrail

This repository ships an optional pre-push hook:
- script: `scripts/check-local-token-hygiene.sh`
- hook id: `local-token-hygiene` in `.pre-commit-config.yaml`

When enabled via pre-commit, pushes are blocked if `.env.local` contains a JWT-shaped `VERCEL_OIDC_TOKEN`.
