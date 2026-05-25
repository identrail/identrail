# Graph Relationship Contract

The normalized graph contract defines the only relationship semantics that
provider pipelines may emit. Relationship types are canonical in
`internal/domain/types.go`, contract metadata is canonical in
`internal/domain/relationship_contract.go`, and endpoint validation is enforced
by `internal/providers/graph_contract.go`.

Provider collectors should prefer precise relationship types whenever the
source evidence proves a specific semantic. Use `can_access` only for a generic
permission on an action/resource tuple when no more precise edge type applies.
For example, use `can_decrypt` for KMS decrypt capability, `can_pass_role` for
AWS role delegation, and `uses_secret` for explicit secret material usage
instead of collapsing those edges into generic `can_access`.

## Supported relationships

| Relationship | Direction | Required endpoints | Evidence expectation |
| --- | --- | --- | --- |
| `can_assume` | principal or identity -> identity | source is an existing identity or `aws:principal:` node; target is an existing identity | Trust policy, federation mapping, or provider delegation record naming the target identity. |
| `attached_policy` | identity -> policy | source is an existing identity; target is an existing policy | Provider policy attachment or inline policy source. |
| `attached_to` | workload -> identity | source is an existing workload; target is an existing identity | Provider workload-to-identity attachment record. |
| `bound_to` | workload -> identity | source is an existing workload; target is an existing identity | Provider binding record such as Kubernetes RBAC or service-account binding. |
| `can_access` | identity -> access node | source is an existing identity; target starts with `aws:access:` or `k8s:access:` | Normalized permission statement granting the action/resource pair. |
| `can_impersonate` | identity or workload -> identity | source is an existing identity or workload; target is an existing identity | Provider impersonation, token exchange, or workload identity binding evidence. |
| `runs_as` | workload -> identity | source is an existing workload; target is an existing identity | Runtime or workload configuration proving the identity used at execution time. |
| `uses_secret` | actor -> secret node | source is an existing identity, existing workload, or `agent:` node; target starts with `secret:`, `aws:secret:`, or `k8s:secret:` | Secret reference, environment mount, runtime configuration, or observed secret fetch. |
| `can_decrypt` | identity -> KMS key node | source is an existing identity; target starts with `kms:` or `aws:kms:` | Key policy or permission statement granting decrypt on the key. |
| `can_pass_role` | identity -> role identity | source is an existing identity; target is an existing `role` identity | Permission statement granting `iam:PassRole` or provider-equivalent delegation. |
| `invokes` | actor -> invocable node | source is an existing identity, existing workload, or `agent:` node; target is an existing workload or starts with `invocable:`, `aws:lambda:`, `aws:service:`, `aws:resource:`, `k8s:workload:`, or `agent:` | Permission, trigger, trace, or runtime event proving the invocation path. |
| `calls_tool` | actor -> tool node | source is an existing identity, existing workload, or `agent:` node; target starts with `tool:`, `mcp:tool:`, or `agent:tool:` | Agent configuration, MCP manifest, trace, or runtime event proving the tool call. |
| `acts_for_user` | actor -> user identity | source is an existing identity, existing workload, or `agent:` node; target is an existing `user` identity | Delegation token, session binding, audit event, or authorization grant naming the user. |
| `has_runtime_session` | actor -> runtime session node | source is an existing identity, existing workload, or `agent:` node; target starts with `session:`, `runtime:session:`, `aws:session:`, or `k8s:session:` | Runtime session, STS credential session, pod execution, or trace correlation record. |
| `observed_action` | actor or runtime session -> action node | source is an existing identity, existing workload, `agent:` node, or runtime session node; target is an access node or starts with `action:`, `aws:action:`, or `k8s:action:` | Audit log, trace span, runtime event, or provider activity record. |

## Compatibility

Existing AWS and Kubernetes graph emitters remain compatible. This contract
change reserves and validates the expanded relationship vocabulary; it does not
require collectors to emit new edges until follow-up collector work has concrete
source evidence.
