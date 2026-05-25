# Connector Capability Modes

Identrail connectors are read-only by default. The AWS machine-identity
control-plane roadmap, however, needs more than one permission tier: discovery,
runtime evidence, remediation planning, approved remediation, advisory
authorization, and eventually limited enforcement.

Rather than silently widening the read-only role or blurring write-capable
permissions into the existing connector path, capabilities are modeled
explicitly. Every connector tracks which capabilities were **requested**,
**validated**, and are **effective**, and any requested-but-denied tier surfaces
a precise diagnostic.

## Capability tiers

| Capability | Tier | Available today | Purpose |
|---|---|---|---|
| `discovery` | read-only | yes (default) | Inventory and machine-identity graph collection. Granted by the one-click read-only CloudFormation role. |
| `runtime_evidence` | read-only | no | Runtime activity (last-used data, CloudTrail, access-analyzer findings) proving whether risky permissions are exercised. |
| `remediation_plan` | read-only | no | Generates proposed least-privilege fixes by simulation only. Never applies changes. |
| `authorization_advisory` | read-only | no | Recommends session-policy / boundary decisions without applying them. |
| `approved_remediation` | **write** | no | Applies operator-approved IAM fixes. |
| `authorization_enforcement` | **write** | no | Enforces authorization via permission boundaries or SCPs. |

`discovery` is always the baseline. It is the only tier the default connector
flow grants, and it is the only tier currently available; the others are modeled
now so write behavior can be added later without reshaping the connector model.

## Why each tier is separate

- **Blast radius is explicit.** Read-only tiers can never mutate the connected
  account. Write-capable tiers (`approved_remediation`,
  `authorization_enforcement`) are clearly marked and gated.
- **No accidental escalation.** The read-only CloudFormation onboarding flow
  always starts a connector at `discovery`. Write-capable tiers cannot be
  requested through that path.
- **Defense in depth.** Even when a tier is requested, it only becomes effective
  if the deployment's capability gate permits it. `effective` never exceeds
  `validated`.

## Enabling additional tiers

Capabilities beyond `discovery` are gated by
`IDENTRAIL_AWS_CONNECTOR_CAPABILITIES`, a comma-separated list of tier names. For
example, to allow runtime evidence collection:

```
IDENTRAIL_AWS_CONNECTOR_CAPABILITIES=runtime_evidence
```

Unknown names are ignored so a typo cannot widen access. Write-capable tiers
require both an entry here **and** a dedicated write-capable role; the read-only
connector role never grants them. No live remediation or enforcement executor
ships with this capability model — enabling a write tier only makes the request
representable and validated, not executed.

## API surface

`AWSConnectionStatus` includes a `capabilities` object:

```json
{
  "capabilities": {
    "requested": ["discovery", "approved_remediation"],
    "validated": ["discovery"],
    "effective": ["discovery"],
    "unavailable": [
      {
        "capability": "approved_remediation",
        "tier": "write",
        "reason": "write-capable capability approved_remediation is disabled; it requires a dedicated write role and an explicit feature gate, and is never granted by the read-only connector"
      }
    ]
  }
}
```

When a requested capability is unavailable, validation also emits an
`aws_capability_unavailable` diagnostic that names the specific tier and how to
enable it, so a failure is never reported as a generic connector error.

The connector start and policy responses additionally return `permission_tiers`,
which group the AWS actions each capability needs and flag whether each tier is
available today. This lets operators see read-only discovery separately from the
future write/remediation/enforcement tiers before granting anything.
