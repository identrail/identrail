# PR 03: phase1: add exact location resolver

## Summary
This PR introduces the design and implementation contract for **phase1: add exact location resolver**.

## Why
We need this slice to improve finding quality, reduce false positives, and enable safe remediation workflows without creating merge risk.

## Scope
- Define detailed technical contract for this slice.
- Define data model/API implications.
- Define validation and rollout requirements.
- Define acceptance criteria and non-goals.

## Detailed Plan
Resolve path, line, column, and commit metadata consistently for all findings.

Implementation checklist:
- [ ] Data model changes documented.
- [ ] Detection pipeline touchpoints documented.
- [ ] Output compatibility behavior documented.
- [ ] Tests/gates explicitly defined.
- [ ] Rollout and fallback path documented.

## Acceptance Criteria
- Clear, testable acceptance criteria exist for engineering implementation.
- Compatibility and migration impact is described.
- Failure modes and rollback strategy are captured.

## Validation
- Self-review completed for clarity, scope boundaries, and merge safety.
- Markdown content is lint-friendly and rendered correctly in GitHub preview.
- Branch is rebased from origin/dev and changes are isolated to one roadmap file.

## Risks & Mitigations
- Risk: scope creep in implementation.
  - Mitigation: enforce strict PR boundaries to this single slice.
- Risk: drift from baseline output contracts.
  - Mitigation: include compatibility notes and migration guards in implementation.

## AI Assistance Disclosure
Prepared with AI-assisted drafting; technical decisions and boundaries were explicitly reviewed before opening.

## Related Issues
- Roadmap item 03.
