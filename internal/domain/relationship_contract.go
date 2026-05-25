package domain

// RelationshipEndpointKind names the endpoint shape required by a relationship
// semantic in the normalized graph contract.
type RelationshipEndpointKind string

const (
	RelationshipEndpointIdentity             RelationshipEndpointKind = "identity"
	RelationshipEndpointIdentityOrPrincipal  RelationshipEndpointKind = "identity_or_aws_principal"
	RelationshipEndpointIdentityOrWorkload   RelationshipEndpointKind = "identity_or_workload"
	RelationshipEndpointWorkload             RelationshipEndpointKind = "workload"
	RelationshipEndpointPolicy               RelationshipEndpointKind = "policy"
	RelationshipEndpointAccess               RelationshipEndpointKind = "access"
	RelationshipEndpointSecret               RelationshipEndpointKind = "secret"
	RelationshipEndpointKMSKey               RelationshipEndpointKind = "kms_key"
	RelationshipEndpointRoleIdentity         RelationshipEndpointKind = "role_identity"
	RelationshipEndpointActor                RelationshipEndpointKind = "identity_workload_or_agent"
	RelationshipEndpointInvocable            RelationshipEndpointKind = "invocable"
	RelationshipEndpointTool                 RelationshipEndpointKind = "tool"
	RelationshipEndpointUserIdentity         RelationshipEndpointKind = "user_identity"
	RelationshipEndpointRuntimeSession       RelationshipEndpointKind = "runtime_session"
	RelationshipEndpointActorOrRuntime       RelationshipEndpointKind = "identity_workload_agent_or_runtime_session"
	RelationshipEndpointObservedActionTarget RelationshipEndpointKind = "observed_action_target"
)

// RelationshipContract documents the direction, required endpoint kinds, and
// evidence expectation for a supported graph relationship semantic.
type RelationshipContract struct {
	Type        RelationshipType
	From        RelationshipEndpointKind
	To          RelationshipEndpointKind
	Evidence    string
	Description string
}

var relationshipContracts = map[RelationshipType]RelationshipContract{
	RelationshipCanAssume: {
		Type:        RelationshipCanAssume,
		From:        RelationshipEndpointIdentityOrPrincipal,
		To:          RelationshipEndpointIdentity,
		Evidence:    "trust policy, federation mapping, or provider delegation record naming the target identity",
		Description: "A principal or identity is allowed to assume another identity.",
	},
	RelationshipAttachedPolicy: {
		Type:        RelationshipAttachedPolicy,
		From:        RelationshipEndpointIdentity,
		To:          RelationshipEndpointPolicy,
		Evidence:    "provider policy attachment or inline policy source",
		Description: "A policy document is attached to an identity.",
	},
	RelationshipAttachedTo: {
		Type:        RelationshipAttachedTo,
		From:        RelationshipEndpointWorkload,
		To:          RelationshipEndpointIdentity,
		Evidence:    "provider workload-to-identity attachment record",
		Description: "A workload is attached to an identity by platform configuration.",
	},
	RelationshipBoundTo: {
		Type:        RelationshipBoundTo,
		From:        RelationshipEndpointWorkload,
		To:          RelationshipEndpointIdentity,
		Evidence:    "provider binding record such as Kubernetes RBAC or service-account binding",
		Description: "A workload is bound to an identity through an authorization binding.",
	},
	RelationshipCanAccess: {
		Type:        RelationshipCanAccess,
		From:        RelationshipEndpointIdentity,
		To:          RelationshipEndpointAccess,
		Evidence:    "normalized permission statement granting the action/resource pair",
		Description: "An identity can access an action/resource tuple when no more precise edge applies.",
	},
	RelationshipCanImpersonate: {
		Type:        RelationshipCanImpersonate,
		From:        RelationshipEndpointIdentityOrWorkload,
		To:          RelationshipEndpointIdentity,
		Evidence:    "provider impersonation, token exchange, or workload identity binding evidence",
		Description: "An identity or workload can impersonate another identity.",
	},
	RelationshipRunsAs: {
		Type:        RelationshipRunsAs,
		From:        RelationshipEndpointWorkload,
		To:          RelationshipEndpointIdentity,
		Evidence:    "runtime or workload configuration proving the identity used at execution time",
		Description: "A workload executes as the target machine identity.",
	},
	RelationshipUsesSecret: {
		Type:        RelationshipUsesSecret,
		From:        RelationshipEndpointActor,
		To:          RelationshipEndpointSecret,
		Evidence:    "secret reference, environment mount, runtime configuration, or observed secret fetch",
		Description: "An actor uses a secret material source.",
	},
	RelationshipCanDecrypt: {
		Type:        RelationshipCanDecrypt,
		From:        RelationshipEndpointIdentity,
		To:          RelationshipEndpointKMSKey,
		Evidence:    "key policy or permission statement granting decrypt on the key",
		Description: "An identity can decrypt data with a cryptographic key.",
	},
	RelationshipCanPassRole: {
		Type:        RelationshipCanPassRole,
		From:        RelationshipEndpointIdentity,
		To:          RelationshipEndpointRoleIdentity,
		Evidence:    "permission statement granting iam:PassRole or provider-equivalent delegation",
		Description: "An identity can pass a role identity to another AWS service or workload.",
	},
	RelationshipInvokes: {
		Type:        RelationshipInvokes,
		From:        RelationshipEndpointActor,
		To:          RelationshipEndpointInvocable,
		Evidence:    "permission, trigger, trace, or runtime event proving the invocation path",
		Description: "An actor invokes a workload, function, service, or agent endpoint.",
	},
	RelationshipCallsTool: {
		Type:        RelationshipCallsTool,
		From:        RelationshipEndpointActor,
		To:          RelationshipEndpointTool,
		Evidence:    "agent configuration, MCP manifest, trace, or runtime event proving the tool call",
		Description: "An agent-capable actor can call a tool.",
	},
	RelationshipActsForUser: {
		Type:        RelationshipActsForUser,
		From:        RelationshipEndpointActor,
		To:          RelationshipEndpointUserIdentity,
		Evidence:    "delegation token, session binding, audit event, or authorization grant naming the user",
		Description: "An actor performs work delegated by or on behalf of a user identity.",
	},
	RelationshipRuntimeSession: {
		Type:        RelationshipRuntimeSession,
		From:        RelationshipEndpointActor,
		To:          RelationshipEndpointRuntimeSession,
		Evidence:    "runtime session, STS credential session, pod execution, or trace correlation record",
		Description: "An actor has an observed runtime session.",
	},
	RelationshipObservedAction: {
		Type:        RelationshipObservedAction,
		From:        RelationshipEndpointActorOrRuntime,
		To:          RelationshipEndpointObservedActionTarget,
		Evidence:    "audit log, trace span, runtime event, or provider activity record",
		Description: "An actor or runtime session was observed performing an action.",
	},
}

// RelationshipContractFor returns the canonical contract metadata for a
// supported relationship semantic.
func RelationshipContractFor(rel RelationshipType) (RelationshipContract, bool) {
	contract, ok := relationshipContracts[rel]
	return contract, ok
}

// RelationshipContracts returns a copy of the canonical relationship contract
// metadata so callers cannot mutate the package-level contract.
func RelationshipContracts() map[RelationshipType]RelationshipContract {
	contracts := make(map[RelationshipType]RelationshipContract, len(relationshipContracts))
	for rel, contract := range relationshipContracts {
		contracts[rel] = contract
	}
	return contracts
}
