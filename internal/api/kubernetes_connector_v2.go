package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/connectors"
	k8sconnector "github.com/identrail/identrail/internal/connectors/kubernetes"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	k8sprovider "github.com/identrail/identrail/internal/providers/kubernetes"
)

var (
	ErrKubernetesConnectorTokenInvalid      = errors.New("invalid kubernetes connector token")
	ErrKubernetesConnectorTokenExpired      = errors.New("expired kubernetes connector token")
	ErrKubernetesConnectorTokenUsed         = errors.New("used kubernetes connector token")
	ErrKubernetesConnectorCredentialDenied  = errors.New("invalid kubernetes connector credential")
	ErrKubernetesConnectorSecretUnavailable = errors.New("kubernetes connector secret unavailable")
)

type KubernetesConnectorStartRequest struct {
	WorkspaceID string `json:"workspace_id,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	ConnectorID string `json:"connector_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	APIURL      string `json:"api_url,omitempty"`
}

type KubernetesConnectorStartResponse struct {
	Connection          KubernetesConnectionStatus `json:"connection"`
	EnrollmentToken     string                     `json:"enrollment_token"`
	EnrollmentExpiresAt time.Time                  `json:"enrollment_expires_at"`
	HelmCommand         string                     `json:"helm_command"`
}

type KubernetesConnectorKubeconfigRequest struct {
	WorkspaceID string `json:"workspace_id,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	ConnectorID string `json:"connector_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Kubeconfig  string `json:"kubeconfig"`
	Context     string `json:"context,omitempty"`
}

type KubernetesAgentEnrollResponse struct {
	ConnectorID  string    `json:"connector_id"`
	AgentID      string    `json:"agent_id"`
	AgentToken   string    `json:"agent_token"`
	HeartbeatURL string    `json:"heartbeat_url"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type KubernetesAgentHeartbeatResponse struct {
	Connection KubernetesConnectionStatus `json:"connection"`
	DegradedAt time.Time                  `json:"degraded_at"`
}

type kubernetesEnrollmentLocator struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	ConnectorID string `json:"connector_id"`
}

func (s *Service) StartKubernetesConnector(ctx context.Context, request KubernetesConnectorStartRequest) (KubernetesConnectorStartResponse, error) {
	project, scope, normalized, err := s.normalizeKubernetesConnectorStart(ctx, request)
	if err != nil {
		return KubernetesConnectorStartResponse{}, err
	}
	now := s.Now().UTC()
	expiresAt := now.Add(k8sconnector.EnrollmentTTL)
	secret, err := k8sconnector.GenerateCredential()
	if err != nil {
		return KubernetesConnectorStartResponse{}, err
	}
	token, err := buildKubernetesEnrollmentToken(scope.TenantID, project.WorkspaceID, project.ProjectID, normalized.ConnectorID, secret)
	if err != nil {
		return KubernetesConnectorStartResponse{}, err
	}
	metadata, err := persistedKubernetesConnectorState{
		ConnectionMode:      k8sconnector.AgentMode,
		EnrollmentTokenHash: k8sconnector.HashCredential(token),
		EnrollmentExpiresAt: &expiresAt,
	}.toMap()
	if err != nil {
		return KubernetesConnectorStartResponse{}, fmt.Errorf("encode kubernetes connector metadata: %w", err)
	}
	connector := db.TenancyConnector{
		TenantID:    scope.TenantID,
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
		ConnectorID: normalized.ConnectorID,
		Type:        domain.ConnectorTypeKubernetes,
		DisplayName: normalized.DisplayName,
		Status:      domain.ConnectorStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	state := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  normalized.ConnectorID,
		HealthStatus: string(connectors.HealthStatusUnknown),
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return KubernetesConnectorStartResponse{}, fmt.Errorf("persist kubernetes connector enrollment: %w", err)
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	if err != nil {
		return KubernetesConnectorStartResponse{}, fmt.Errorf("load kubernetes connector enrollment: %w", err)
	}
	status, err := s.kubernetesConnectionStatusFromStored(stored)
	if err != nil {
		return KubernetesConnectorStartResponse{}, err
	}
	return KubernetesConnectorStartResponse{
		Connection:          status,
		EnrollmentToken:     token,
		EnrollmentExpiresAt: expiresAt,
		HelmCommand:         kubernetesHelmCommand(request.APIURL, token),
	}, nil
}

func (s *Service) GetKubernetesConnectorStatus(ctx context.Context, workspaceID string, projectID string) (KubernetesConnectionStatus, error) {
	return s.GetKubernetesConnection(ctx, workspaceID, projectID)
}

func (s *Service) EnrollKubernetesAgent(ctx context.Context, request k8sconnector.AgentEnrollRequest, apiBaseURL string) (KubernetesAgentEnrollResponse, error) {
	token := strings.TrimSpace(request.EnrollmentToken)
	locator, err := parseKubernetesEnrollmentToken(token)
	if err != nil {
		return KubernetesAgentEnrollResponse{}, err
	}
	if strings.TrimSpace(request.ConnectorID) != "" && strings.TrimSpace(request.ConnectorID) != locator.ConnectorID {
		return KubernetesAgentEnrollResponse{}, ErrKubernetesConnectorTokenInvalid
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: locator.TenantID, WorkspaceID: locator.WorkspaceID})
	stored, err := s.Store.GetTenancyConnector(scopedCtx, locator.WorkspaceID, locator.ProjectID, locator.ConnectorID)
	if err != nil {
		return KubernetesAgentEnrollResponse{}, err
	}
	metadata, err := decodePersistedKubernetesConnectorState(stored.State.Metadata)
	if err != nil {
		return KubernetesAgentEnrollResponse{}, err
	}
	now := s.Now().UTC()
	if metadata.EnrollmentTokenUsedAt != nil {
		return KubernetesAgentEnrollResponse{}, ErrKubernetesConnectorTokenUsed
	}
	if metadata.EnrollmentExpiresAt == nil || now.After(metadata.EnrollmentExpiresAt.UTC()) {
		return KubernetesAgentEnrollResponse{}, ErrKubernetesConnectorTokenExpired
	}
	if !k8sconnector.CredentialMatches(token, metadata.EnrollmentTokenHash) {
		return KubernetesAgentEnrollResponse{}, ErrKubernetesConnectorTokenInvalid
	}
	agentSecret, err := k8sconnector.GenerateCredential()
	if err != nil {
		return KubernetesAgentEnrollResponse{}, err
	}
	agentToken, err := buildKubernetesEnrollmentToken(locator.TenantID, locator.WorkspaceID, locator.ProjectID, locator.ConnectorID, agentSecret)
	if err != nil {
		return KubernetesAgentEnrollResponse{}, err
	}
	agentID := strings.TrimSpace(request.AgentID)
	if agentID == "" {
		agentID = "identrail-agent-" + locator.ConnectorID
	}
	usedAt := now
	metadata.ConnectionMode = k8sconnector.AgentMode
	metadata.EnrollmentTokenUsedAt = &usedAt
	metadata.AgentCredentialHash = k8sconnector.HashCredential(agentToken)
	metadata.AgentID = agentID
	metadata.LastHeartbeatAt = &now
	metadata.Cluster = firstNonEmptyKubernetesValue(request.Cluster, metadata.Cluster)
	metadata.Server = firstNonEmptyKubernetesValue(request.Server, metadata.Server)
	metadata.GitVersion = firstNonEmptyKubernetesValue(request.GitVersion, metadata.GitVersion)
	metadata.Platform = firstNonEmptyKubernetesValue(request.Platform, metadata.Platform)
	metadata.PermissionChecks = kubernetesAgentPermissionChecks(request.PermissionChecks)
	metadata.Diagnostics = kubernetesAgentDiagnostics(request.Diagnostics)
	metadata.LastValidatedAt = &now
	status, health := kubernetesAgentStatus(&metadata)
	metadataPayload, err := metadata.toMap()
	if err != nil {
		return KubernetesAgentEnrollResponse{}, fmt.Errorf("encode kubernetes agent metadata: %w", err)
	}
	lastErrorCode := ""
	lastErrorMessage := ""
	if status != domain.ConnectorStatusActive || health != string(connectors.HealthStatusHealthy) {
		lastErrorCode = "kubernetes_agent_probe_failed"
		lastErrorMessage = firstKubernetesRemediation(metadata.Diagnostics, metadata.PermissionChecks)
	}
	claimed, err := s.Store.ClaimKubernetesEnrollmentToken(
		scopedCtx,
		locator.WorkspaceID,
		locator.ProjectID,
		locator.ConnectorID,
		metadata.EnrollmentTokenHash,
		metadataPayload,
		status,
		health,
		lastErrorCode,
		lastErrorMessage,
		now,
		now,
	)
	if err != nil {
		return KubernetesAgentEnrollResponse{}, err
	}
	if !claimed {
		return KubernetesAgentEnrollResponse{}, ErrKubernetesConnectorTokenUsed
	}
	return KubernetesAgentEnrollResponse{
		ConnectorID:  locator.ConnectorID,
		AgentID:      agentID,
		AgentToken:   agentToken,
		HeartbeatURL: strings.TrimRight(apiBaseURL, "/") + k8sconnector.DefaultAgentHeartbeatPath,
		ExpiresAt:    now.Add(365 * 24 * time.Hour),
	}, nil
}

func (s *Service) HeartbeatKubernetesAgent(ctx context.Context, request k8sconnector.AgentHeartbeatRequest, bearerToken string) (KubernetesAgentHeartbeatResponse, error) {
	agentCredential := strings.TrimPrefix(strings.TrimSpace(bearerToken), "Bearer ")
	locator, err := parseKubernetesEnrollmentToken(agentCredential)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	if strings.TrimSpace(request.ConnectorID) != "" && strings.TrimSpace(request.ConnectorID) != locator.ConnectorID {
		return KubernetesAgentHeartbeatResponse{}, ErrKubernetesConnectorCredentialDenied
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: locator.TenantID, WorkspaceID: locator.WorkspaceID})
	stored, err := s.Store.GetTenancyConnector(scopedCtx, locator.WorkspaceID, locator.ProjectID, locator.ConnectorID)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	metadata, err := decodePersistedKubernetesConnectorState(stored.State.Metadata)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	if !k8sconnector.CredentialMatches(agentCredential, metadata.AgentCredentialHash) {
		return KubernetesAgentHeartbeatResponse{}, ErrKubernetesConnectorCredentialDenied
	}
	now := s.Now().UTC()
	metadata.ConnectionMode = k8sconnector.AgentMode
	metadata.AgentID = firstNonEmptyKubernetesValue(request.AgentID, metadata.AgentID)
	metadata.LastHeartbeatAt = &now
	metadata.Cluster = firstNonEmptyKubernetesValue(request.Cluster, metadata.Cluster)
	metadata.Server = firstNonEmptyKubernetesValue(request.Server, metadata.Server)
	metadata.GitVersion = firstNonEmptyKubernetesValue(request.GitVersion, metadata.GitVersion)
	metadata.Platform = firstNonEmptyKubernetesValue(request.Platform, metadata.Platform)
	metadata.PermissionChecks = kubernetesAgentPermissionChecks(request.PermissionChecks)
	metadata.Diagnostics = kubernetesAgentDiagnostics(request.Diagnostics)
	metadata.LastValidatedAt = &now
	response := KubernetesAgentEnrollResponse{}
	status, health := kubernetesAgentStatus(&metadata)
	_, err = s.persistKubernetesAgentMetadata(scopedCtx, stored, metadata, status, health, now, response)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	reloaded, err := s.Store.GetTenancyConnector(scopedCtx, stored.Connector.WorkspaceID, stored.Connector.ProjectID, stored.Connector.ConnectorID)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	connectionStatus, err := s.kubernetesConnectionStatusFromStored(reloaded)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	return KubernetesAgentHeartbeatResponse{
		Connection: connectionStatus,
		DegradedAt: now.Add(k8sconnector.HeartbeatDegradedAfter),
	}, nil
}

func (s *Service) UpsertKubernetesKubeconfigConnector(ctx context.Context, request KubernetesConnectorKubeconfigRequest) (KubernetesConnectionStatus, error) {
	project, scope, normalized, err := s.normalizeKubernetesConnectorStart(ctx, KubernetesConnectorStartRequest{
		WorkspaceID: request.WorkspaceID,
		ProjectID:   request.ProjectID,
		ConnectorID: request.ConnectorID,
		DisplayName: request.DisplayName,
	})
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}
	summary, err := k8sconnector.ValidateKubeconfig(request.Kubeconfig, request.Context)
	if err != nil {
		return KubernetesConnectionStatus{}, ErrInvalidKubernetesConnectionRequest
	}
	now := s.Now().UTC()
	metadata, err := persistedKubernetesConnectorState{
		ConnectionMode:  k8sconnector.KubeconfigMode,
		Context:         summary.CurrentContext,
		Cluster:         summary.Cluster,
		Server:          summary.Server,
		LastValidatedAt: &now,
	}.toMap()
	if err != nil {
		return KubernetesConnectionStatus{}, fmt.Errorf("encode kubernetes kubeconfig metadata: %w", err)
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return KubernetesConnectionStatus{}, fmt.Errorf("load kubernetes kubeconfig connector: %w", err)
	}
	connector := stored.Connector
	state := stored.State
	if errors.Is(err, db.ErrNotFound) {
		connector = db.TenancyConnector{
			TenantID:    scope.TenantID,
			WorkspaceID: project.WorkspaceID,
			ProjectID:   project.ProjectID,
			ConnectorID: normalized.ConnectorID,
			Type:        domain.ConnectorTypeKubernetes,
			DisplayName: normalized.DisplayName,
			Status:      domain.ConnectorStatusPending,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		state = db.TenancyConnectorState{
			TenantID:     scope.TenantID,
			WorkspaceID:  project.WorkspaceID,
			ProjectID:    project.ProjectID,
			ConnectorID:  normalized.ConnectorID,
			HealthStatus: string(connectors.HealthStatusUnknown),
			Metadata:     metadata,
			ObservedAt:   now,
			UpdatedAt:    now,
		}
		if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
			return KubernetesConnectionStatus{}, fmt.Errorf("persist kubernetes kubeconfig connector: %w", err)
		}
	}
	if err := s.persistKubernetesKubeconfig(ctx, scope.TenantID, project.WorkspaceID, project.ProjectID, normalized.ConnectorID, request.Kubeconfig, now); err != nil {
		return KubernetesConnectionStatus{}, err
	}
	connector.Type = domain.ConnectorTypeKubernetes
	connector.DisplayName = normalized.DisplayName
	connector.Status = domain.ConnectorStatusActive
	connector.UpdatedAt = now
	connector.SecretProvider = "identrail"
	connector.SecretRefID = k8sconnector.SecretRef(normalized.ConnectorID, k8sconnector.KubeconfigSecretName)
	connector.SecretLastRotatedAt = &now
	state.HealthStatus = string(connectors.HealthStatusHealthy)
	state.Metadata = metadata
	state.ObservedAt = now
	state.UpdatedAt = now
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return KubernetesConnectionStatus{}, fmt.Errorf("activate kubernetes kubeconfig connector: %w", err)
	}
	stored, err = s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	if err != nil {
		return KubernetesConnectionStatus{}, fmt.Errorf("load kubernetes kubeconfig connector: %w", err)
	}
	return s.kubernetesConnectionStatusFromStored(stored)
}

func (s *Service) normalizeKubernetesConnectorStart(ctx context.Context, request KubernetesConnectorStartRequest) (db.TenancyProject, db.Scope, KubernetesConnectionUpsertRequest, error) {
	project, scope, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		if errors.Is(err, ErrInvalidGitHubConnectionRequest) {
			return db.TenancyProject{}, db.Scope{}, KubernetesConnectionUpsertRequest{}, ErrInvalidKubernetesConnectionRequest
		}
		return db.TenancyProject{}, db.Scope{}, KubernetesConnectionUpsertRequest{}, err
	}
	normalized, err := normalizeKubernetesConnectionRequest(project, KubernetesConnectionUpsertRequest{
		ConnectorID: request.ConnectorID,
		DisplayName: request.DisplayName,
	})
	if err != nil {
		return db.TenancyProject{}, db.Scope{}, KubernetesConnectionUpsertRequest{}, err
	}
	if strings.TrimSpace(request.ConnectorID) == "" {
		items, err := s.Store.ListTenancyConnectors(ctx, project.WorkspaceID, project.ProjectID, domain.ConnectorTypeKubernetes, 1)
		if err != nil {
			return db.TenancyProject{}, db.Scope{}, KubernetesConnectionUpsertRequest{}, fmt.Errorf("list kubernetes connectors: %w", err)
		}
		if len(items) > 0 {
			normalized.ConnectorID = items[0].Connector.ConnectorID
			if strings.TrimSpace(request.DisplayName) == "" {
				normalized.DisplayName = firstNonEmptyKubernetesValue(items[0].Connector.DisplayName, normalized.DisplayName)
			}
		}
	}
	return project, scope, normalized, nil
}

func (s *Service) persistKubernetesAgentMetadata(ctx context.Context, stored db.TenancyConnectorWithState, metadata persistedKubernetesConnectorState, status domain.ConnectorStatus, health string, observedAt time.Time, response KubernetesAgentEnrollResponse) (KubernetesAgentEnrollResponse, error) {
	meta, err := metadata.toMap()
	if err != nil {
		return KubernetesAgentEnrollResponse{}, fmt.Errorf("encode kubernetes agent metadata: %w", err)
	}
	connector := stored.Connector
	connector.Status = status
	connector.UpdatedAt = observedAt
	state := stored.State
	state.HealthStatus = health
	state.Metadata = meta
	state.ObservedAt = observedAt
	state.UpdatedAt = observedAt
	state.LastErrorCode = ""
	state.LastErrorMessage = ""
	if status != domain.ConnectorStatusActive || health != string(connectors.HealthStatusHealthy) {
		state.LastErrorCode = "kubernetes_agent_probe_failed"
		state.LastErrorMessage = firstKubernetesRemediation(metadata.Diagnostics, metadata.PermissionChecks)
	}
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return KubernetesAgentEnrollResponse{}, fmt.Errorf("persist kubernetes agent metadata: %w", err)
	}
	return response, nil
}

func kubernetesAgentPermissionChecks(checks []k8sconnector.AgentPermissionCheckResult) []k8sprovider.KubernetesPermissionCheckResult {
	if len(checks) == 0 {
		return []k8sprovider.KubernetesPermissionCheckResult{}
	}
	result := make([]k8sprovider.KubernetesPermissionCheckResult, 0, len(checks))
	for _, check := range checks {
		result = append(result, k8sprovider.KubernetesPermissionCheckResult{
			KubernetesPermissionCheck: k8sprovider.KubernetesPermissionCheck{
				Verb:     strings.TrimSpace(check.Verb),
				Resource: strings.TrimSpace(check.Resource),
				Scope:    strings.TrimSpace(check.Scope),
			},
			Allowed:     check.Allowed,
			Diagnostic:  strings.TrimSpace(check.Diagnostic),
			Remediation: strings.TrimSpace(check.Remediation),
		})
	}
	return result
}

func kubernetesAgentDiagnostics(diagnostics []k8sconnector.AgentDiagnostic) []k8sprovider.KubernetesPreflightDiagnostic {
	result := make([]k8sprovider.KubernetesPreflightDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		code := strings.TrimSpace(diagnostic.Code)
		message := strings.TrimSpace(diagnostic.Message)
		if code == "" || message == "" {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(diagnostic.Severity))
		if severity == "" {
			severity = "warning"
		}
		result = append(result, k8sprovider.KubernetesPreflightDiagnostic{
			Code:        code,
			Severity:    severity,
			Message:     message,
			Remediation: strings.TrimSpace(diagnostic.Remediation),
		})
	}
	return result
}

func kubernetesAgentStatus(metadata *persistedKubernetesConnectorState) (domain.ConnectorStatus, string) {
	diagnostics := copyKubernetesDiagnostics(metadata.Diagnostics)
	if strings.TrimSpace(metadata.Cluster) == "" || strings.TrimSpace(metadata.Server) == "" {
		diagnostics = append(diagnostics, k8sprovider.KubernetesPreflightDiagnostic{
			Code:        "kubernetes_agent_cluster_probe_missing",
			Severity:    "error",
			Message:     "The Kubernetes agent heartbeat did not include verified cluster identity.",
			Remediation: "Upgrade or restart the identrail-agent deployment so it can report in-cluster API discovery.",
		})
	}
	if missingChecks := missingKubernetesAgentPermissionChecks(metadata.PermissionChecks); len(missingChecks) > 0 {
		diagnostics = append(diagnostics, k8sprovider.KubernetesPreflightDiagnostic{
			Code:        "kubernetes_agent_rbac_probe_missing",
			Severity:    "error",
			Message:     "The Kubernetes agent heartbeat did not include every required RBAC read check: " + describeKubernetesPermissionChecks(missingChecks) + ".",
			Remediation: "Upgrade or restart the identrail-agent deployment with the standard read-only ClusterRole.",
		})
	}
	health := connectors.HealthStatusHealthy
	for _, check := range metadata.PermissionChecks {
		if !check.Allowed {
			health = connectors.HealthStatusError
			break
		}
	}
	if health != connectors.HealthStatusError {
		for _, diagnostic := range diagnostics {
			switch strings.ToLower(strings.TrimSpace(diagnostic.Severity)) {
			case "error":
				health = connectors.HealthStatusError
			case "warning":
				if health == connectors.HealthStatusHealthy {
					health = connectors.HealthStatusWarning
				}
			}
		}
	}
	metadata.Diagnostics = diagnostics
	if health == connectors.HealthStatusHealthy {
		return domain.ConnectorStatusActive, string(connectors.HealthStatusHealthy)
	}
	return domain.ConnectorStatusDegraded, string(health)
}

func missingKubernetesAgentPermissionChecks(checks []k8sprovider.KubernetesPermissionCheckResult) []k8sprovider.KubernetesPermissionCheck {
	reported := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		reported[kubernetesPermissionCheckKey(check.Verb, check.Resource, check.Scope)] = struct{}{}
	}
	required := k8sprovider.RequiredKubernetesPreflightChecks()
	missing := make([]k8sprovider.KubernetesPermissionCheck, 0, len(required))
	for _, check := range required {
		if _, ok := reported[kubernetesPermissionCheckKey(check.Verb, check.Resource, check.Scope)]; !ok {
			missing = append(missing, check)
		}
	}
	return missing
}

func kubernetesPermissionCheckKey(verb string, resource string, scope string) string {
	return strings.ToLower(strings.TrimSpace(verb)) + "/" + strings.ToLower(strings.TrimSpace(resource)) + "/" + strings.ToLower(strings.TrimSpace(scope))
}

func describeKubernetesPermissionChecks(checks []k8sprovider.KubernetesPermissionCheck) string {
	labels := make([]string, 0, len(checks))
	for _, check := range checks {
		labels = append(labels, strings.Trim(strings.Join([]string{strings.TrimSpace(check.Verb), strings.TrimSpace(check.Resource), strings.TrimSpace(check.Scope)}, " "), " "))
	}
	return strings.Join(labels, ", ")
}

func (s *Service) persistKubernetesKubeconfig(ctx context.Context, tenantID string, workspaceID string, projectID string, connectorID string, kubeconfig string, rotatedAt time.Time) error {
	manager := s.connectorSecretManager()
	envelope, err := manager.Encrypt([]byte(kubeconfig), kubernetesKubeconfigAAD(tenantID, workspaceID, projectID, connectorID))
	if err != nil {
		return ErrKubernetesConnectorSecretUnavailable
	}
	secret := db.TenancyConnectorSecretEnvelope{
		TenantID:        tenantID,
		WorkspaceID:     workspaceID,
		ProjectID:       projectID,
		ConnectorID:     connectorID,
		SecretName:      k8sconnector.KubeconfigSecretName,
		EnvelopeVersion: envelope.Version,
		Envelope:        envelope,
		SecretRefID:     k8sconnector.SecretRef(connectorID, k8sconnector.KubeconfigSecretName),
		RotatedAt:       rotatedAt,
		CreatedAt:       rotatedAt,
		UpdatedAt:       rotatedAt,
	}
	if err := s.Store.UpsertTenancyConnectorSecretEnvelope(db.WithScope(ctx, db.Scope{TenantID: tenantID, WorkspaceID: workspaceID}), secret); err != nil {
		return fmt.Errorf("persist kubernetes kubeconfig envelope: %w", err)
	}
	return nil
}

func buildKubernetesEnrollmentToken(tenantID string, workspaceID string, projectID string, connectorID string, secret string) (string, error) {
	payload, err := json.Marshal(kubernetesEnrollmentLocator{
		TenantID:    tenantID,
		WorkspaceID: workspaceID,
		ProjectID:   projectID,
		ConnectorID: connectorID,
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + strings.TrimSpace(secret), nil
}

func parseKubernetesEnrollmentToken(token string) (kubernetesEnrollmentLocator, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return kubernetesEnrollmentLocator{}, ErrKubernetesConnectorTokenInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return kubernetesEnrollmentLocator{}, ErrKubernetesConnectorTokenInvalid
	}
	var locator kubernetesEnrollmentLocator
	if err := json.Unmarshal(payload, &locator); err != nil {
		return kubernetesEnrollmentLocator{}, ErrKubernetesConnectorTokenInvalid
	}
	if strings.TrimSpace(locator.TenantID) == "" || strings.TrimSpace(locator.WorkspaceID) == "" || strings.TrimSpace(locator.ProjectID) == "" || strings.TrimSpace(locator.ConnectorID) == "" {
		return kubernetesEnrollmentLocator{}, ErrKubernetesConnectorTokenInvalid
	}
	return locator, nil
}

func kubernetesHelmCommand(apiURL string, token string) string {
	endpoint := strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if endpoint == "" {
		endpoint = "https://api.identrail.com"
	}
	return fmt.Sprintf("helm upgrade --install identrail-agent deploy/connectors/k8s/identrail-agent --namespace identrail --create-namespace --set api.url=%s --set enrollment.token=%s", shellQuote(endpoint), shellQuote(token))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func kubernetesKubeconfigAAD(tenantID string, workspaceID string, projectID string, connectorID string) []byte {
	return []byte(strings.Join([]string{"kubernetes", tenantID, workspaceID, projectID, connectorID, k8sconnector.KubeconfigSecretName}, "/"))
}
