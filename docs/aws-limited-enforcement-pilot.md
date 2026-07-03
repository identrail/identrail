# AWS high-confidence limited enforcement pilot

Issue #1547 adds the pilot path over the limited enforcement framework
(#1546). The pilot evaluates every framework entry against a stricter,
high-confidence-only rule set and marks the survivors pilot-ready for a
downstream executor. Everything else is an explicit `ineligible`,
`override_hold`, or `blocked_by_kill_switch` state.

The endpoint is metadata-only. Identrail never calls AWS write APIs at
this layer; downstream executors own any live control change.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/limited-enforcement-pilot`

Response shape:
`{ "limited_enforcement_pilot": AWSLimitedEnforcementPilotResult }`.

Safety config (`feature_flag`, `kill_switch`, `cohort`, `canary_percent`)
is forwarded to the framework so the pilot evaluates the operator's
explicit configuration; the pilot always requests the framework in
`limited_enforce` mode. `operator_override=hold|pause` holds every pilot
decision; unknown override values are rejected with a 400 so a typo can
never silently resume a held pilot.

Filters: `account_id`, `region`, `pilot_state`, `source_type`, `outcome`,
`enforcement_id`, `severity`, and `search`.

## Eligibility rules

Every framework entry is evaluated against the full rule set; the first
failed rule is named in the decision's rationale:

1. `limited_enforce_mode` — the entry reached limited-enforce mode with
   explicit safety config.
2. `high_confidence` — upstream confidence >= 90 percent (stricter than
   the framework's 80 percent gate).
3. `framework_gates_passed` — every framework gate passed.
4. `canary_within_pilot_cap` — canary percent is greater than zero and at
   most 25 percent; broader rollout belongs to a later wave.
5. `kill_switch_off` — tenant kill switch is off and the entry is not
   kill-switch blocked.
6. `operator_override_clear` — no operator hold is active.

## Pilot states

- `pilot_canary_ready`: every rule passed; the entry is enrolled in the
  pilot canary cohort.
- `pilot_enforce_ready`: every rule passed and the framework entry is
  limited-enforce ready within the pilot cap.
- `ineligible`: at least one eligibility rule failed; the rationale names
  the rule.
- `override_hold`: an operator hold pauses the decision until explicitly
  resumed.
- `blocked_by_kill_switch`: the tenant kill switch removes every entry
  from the pilot.

Safety controls order above eligibility: kill switch first, then operator
hold, then the rule set.

## Rollback thresholds

Every decision carries the deterministic rollback contract a downstream
executor must honor:

- `max_denial_regression_pct: 1` — auto-rollback the canary when denial
  regressions exceed 1 percent of canary traffic.
- `observation_window: 24h` — the canary must hold for the window before
  expansion.
- `auto_rollback_on_kill_switch: true` and
  `operator_override_halts_pilot: true` — either control halts the pilot
  immediately.

## Metrics and audit

Each decision records deterministic counters (eligibility rules
passed/total, framework gates passed/total, confidence percent, canary
percent) and an immutable `limited_enforcement_pilot_projected` audit row
carrying the enforcement ID, pilot state, override, and policy version.
The input hash covers the framework entry's input hash, pilot state,
override, canary percent, cohort, and pilot policy version so operators
can detect drift.

## Safety, evidence, and out of scope

- Metadata-only projection; no IAM, STS, Organizations, Bedrock, or
  AgentCore write APIs are called at this layer.
- The pilot cannot activate from defaults: it inherits the framework's
  explicit safety config requirement and adds the high-confidence floor,
  the canary cap, and the override control on top.
- Tenant, workspace, project, connector, account, and region boundaries
  are preserved.
- Unknown, permission-denied, and partial-failure states surface as
  explicit states, not as successful findings.

## App Surface

The AWS Governance page renders an **AWS limited enforcement pilot**
panel below the framework panel with the decision title, source,
pilot state, eligibility rule counts, confidence, and readiness pill,
including loading, empty, degraded, permission-denied, and error states.
