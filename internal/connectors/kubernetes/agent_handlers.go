package kubernetes

type AgentEnrollRequest struct {
	EnrollmentToken  string                       `json:"enrollment_token"`
	ConnectorID      string                       `json:"connector_id,omitempty"`
	AgentID          string                       `json:"agent_id,omitempty"`
	Cluster          string                       `json:"cluster,omitempty"`
	Server           string                       `json:"server,omitempty"`
	GitVersion       string                       `json:"git_version,omitempty"`
	Platform         string                       `json:"platform,omitempty"`
	PermissionChecks []AgentPermissionCheckResult `json:"permission_checks,omitempty"`
	Diagnostics      []AgentDiagnostic            `json:"diagnostics,omitempty"`
}

type AgentHeartbeatRequest struct {
	ConnectorID      string                       `json:"connector_id,omitempty"`
	AgentID          string                       `json:"agent_id,omitempty"`
	Cluster          string                       `json:"cluster,omitempty"`
	Server           string                       `json:"server,omitempty"`
	GitVersion       string                       `json:"git_version,omitempty"`
	Platform         string                       `json:"platform,omitempty"`
	PermissionChecks []AgentPermissionCheckResult `json:"permission_checks,omitempty"`
	Diagnostics      []AgentDiagnostic            `json:"diagnostics,omitempty"`
}

// AgentPermissionCheckResult captures one in-cluster access check reported by the agent.
type AgentPermissionCheckResult struct {
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	Scope       string `json:"scope"`
	Allowed     bool   `json:"allowed"`
	Diagnostic  string `json:"diagnostic,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// AgentDiagnostic captures one in-cluster discovery or RBAC problem reported by the agent.
type AgentDiagnostic struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}
