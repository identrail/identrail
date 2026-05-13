package kubernetes

type AgentEnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	ConnectorID     string `json:"connector_id,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
	Cluster         string `json:"cluster,omitempty"`
	Server          string `json:"server,omitempty"`
	GitVersion      string `json:"git_version,omitempty"`
	Platform        string `json:"platform,omitempty"`
}

type AgentHeartbeatRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	Cluster     string `json:"cluster,omitempty"`
	Server      string `json:"server,omitempty"`
	GitVersion  string `json:"git_version,omitempty"`
	Platform    string `json:"platform,omitempty"`
}
