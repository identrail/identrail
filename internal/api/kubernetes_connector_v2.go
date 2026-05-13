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
	agentID := strings.TrimSpace(request.AgentID)
	if agentID == "" {
		agentID = "identrail-agent-" + locator.ConnectorID
	}
	usedAt := now
	metadata.ConnectionMode = k8sconnector.AgentMode
	metadata.EnrollmentTokenUsedAt = &usedAt
	metadata.AgentCredentialHash = k8sconnector.HashCredential(token)
	metadata.AgentID = agentID
	metadata.LastHeartbeatAt = &now
	metadata.Cluster = firstNonEmptyKubernetesValue(request.Cluster, metadata.Cluster)
	metadata.Server = firstNonEmptyKubernetesValue(request.Server, metadata.Server)
	metadata.GitVersion = firstNonEmptyKubernetesValue(request.GitVersion, metadata.GitVersion)
	metadata.Platform = firstNonEmptyKubernetesValue(request.Platform, metadata.Platform)
	metadata.LastValidatedAt = &now
	return s.persistKubernetesAgentMetadata(scopedCtx, stored, metadata, domain.ConnectorStatusActive, string(connectors.HealthStatusHealthy), now, KubernetesAgentEnrollResponse{
		ConnectorID:  locator.ConnectorID,
		AgentID:      agentID,
		AgentToken:   token,
		HeartbeatURL: strings.TrimRight(apiBaseURL, "/") + k8sconnector.DefaultAgentHeartbeatPath,
		ExpiresAt:    now.Add(365 * 24 * time.Hour),
	})
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
	metadata.LastValidatedAt = &now
	response := KubernetesAgentEnrollResponse{}
	_, err = s.persistKubernetesAgentMetadata(scopedCtx, stored, metadata, domain.ConnectorStatusActive, string(connectors.HealthStatusHealthy), now, response)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	reloaded, err := s.Store.GetTenancyConnector(scopedCtx, stored.Connector.WorkspaceID, stored.Connector.ProjectID, stored.Connector.ConnectorID)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	status, err := s.kubernetesConnectionStatusFromStored(reloaded)
	if err != nil {
		return KubernetesAgentHeartbeatResponse{}, err
	}
	return KubernetesAgentHeartbeatResponse{
		Connection: status,
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
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return KubernetesAgentEnrollResponse{}, fmt.Errorf("persist kubernetes agent metadata: %w", err)
	}
	return response, nil
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
	return fmt.Sprintf("helm upgrade --install identrail-agent deploy/connectors/k8s/identrail-agent --namespace identrail --create-namespace --set api.url=%q --set enrollment.token=%q", endpoint, token)
}

func kubernetesKubeconfigAAD(tenantID string, workspaceID string, projectID string, connectorID string) []byte {
	return []byte(strings.Join([]string{"kubernetes", tenantID, workspaceID, projectID, connectorID, k8sconnector.KubeconfigSecretName}, "/"))
}
