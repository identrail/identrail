package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/connectors"
	k8sconnector "github.com/identrail/identrail/internal/connectors/kubernetes"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	k8sprovider "github.com/identrail/identrail/internal/providers/kubernetes"
)

// ErrInvalidKubernetesConnectionRequest indicates invalid Kubernetes connector input.
var ErrInvalidKubernetesConnectionRequest = errors.New("invalid kubernetes connection request")

// ErrKubernetesPreflightUnavailable indicates live Kubernetes preflight is not configured.
var ErrKubernetesPreflightUnavailable = errors.New("kubernetes preflight unavailable")

// KubernetesConnectorPreflightRunner performs one Kubernetes connector preflight.
type KubernetesConnectorPreflightRunner interface {
	Preflight(ctx context.Context) k8sprovider.KubernetesPreflightResult
}

// KubernetesConnectorPreflightFactory builds preflight runners for project-scoped contexts.
type KubernetesConnectorPreflightFactory func(contextName string) KubernetesConnectorPreflightRunner

// KubernetesConnectionUpsertRequest captures one project Kubernetes connector onboarding request.
type KubernetesConnectionUpsertRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Context     string `json:"context,omitempty"`
}

// KubernetesConnectionStatus describes current Kubernetes connector state for one project.
type KubernetesConnectionStatus struct {
	Provider            string                                        `json:"provider"`
	Connected           bool                                          `json:"connected"`
	ConnectorID         string                                        `json:"connector_id,omitempty"`
	DisplayName         string                                        `json:"display_name,omitempty"`
	Status              domain.ConnectorStatus                        `json:"status"`
	HealthStatus        string                                        `json:"health_status"`
	Context             string                                        `json:"context,omitempty"`
	Cluster             string                                        `json:"cluster,omitempty"`
	Server              string                                        `json:"server,omitempty"`
	GitVersion          string                                        `json:"git_version,omitempty"`
	Platform            string                                        `json:"platform,omitempty"`
	ConnectionMode      string                                        `json:"connection_mode,omitempty"`
	AgentID             string                                        `json:"agent_id,omitempty"`
	PermissionChecks    []k8sprovider.KubernetesPermissionCheckResult `json:"permission_checks"`
	Diagnostics         []k8sprovider.KubernetesPreflightDiagnostic   `json:"diagnostics"`
	RemediationMessage  string                                        `json:"remediation_message,omitempty"`
	CreatedAt           *time.Time                                    `json:"created_at,omitempty"`
	UpdatedAt           *time.Time                                    `json:"updated_at,omitempty"`
	LastValidatedAt     *time.Time                                    `json:"last_validated_at,omitempty"`
	LastHeartbeatAt     *time.Time                                    `json:"last_heartbeat_at,omitempty"`
	EnrollmentExpiresAt *time.Time                                    `json:"enrollment_expires_at,omitempty"`
}

type kubernetesProjectConnection struct {
	TenantID            string
	WorkspaceID         string
	ProjectID           string
	ConnectorID         string
	DisplayName         string
	Status              domain.ConnectorStatus
	HealthStatus        string
	Context             string
	Cluster             string
	Server              string
	GitVersion          string
	Platform            string
	ConnectionMode      string
	AgentID             string
	PermissionChecks    []k8sprovider.KubernetesPermissionCheckResult
	Diagnostics         []k8sprovider.KubernetesPreflightDiagnostic
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastValidatedAt     time.Time
	LastHeartbeatAt     *time.Time
	EnrollmentExpiresAt *time.Time
}

type persistedKubernetesConnectorState struct {
	Context               string                                        `json:"context,omitempty"`
	Cluster               string                                        `json:"cluster,omitempty"`
	Server                string                                        `json:"server,omitempty"`
	GitVersion            string                                        `json:"git_version,omitempty"`
	Platform              string                                        `json:"platform,omitempty"`
	ConnectionMode        string                                        `json:"connection_mode,omitempty"`
	EnrollmentTokenHash   string                                        `json:"enrollment_token_sha256,omitempty"`
	EnrollmentExpiresAt   *time.Time                                    `json:"enrollment_expires_at,omitempty"`
	EnrollmentTokenUsedAt *time.Time                                    `json:"enrollment_token_used_at,omitempty"`
	AgentCredentialHash   string                                        `json:"agent_credential_sha256,omitempty"`
	AgentID               string                                        `json:"agent_id,omitempty"`
	LastHeartbeatAt       *time.Time                                    `json:"last_heartbeat_at,omitempty"`
	PermissionChecks      []k8sprovider.KubernetesPermissionCheckResult `json:"permission_checks,omitempty"`
	Diagnostics           []k8sprovider.KubernetesPreflightDiagnostic   `json:"diagnostics,omitempty"`
	LastValidatedAt       *time.Time                                    `json:"last_validated_at,omitempty"`
}

// UpsertKubernetesConnection runs preflight and records the project Kubernetes connector state.
func (s *Service) UpsertKubernetesConnection(ctx context.Context, workspaceID string, projectID string, request KubernetesConnectionUpsertRequest) (KubernetesConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}
	normalized, err := normalizeKubernetesConnectionRequest(project, request)
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}
	var existing db.TenancyConnectorWithState
	hasExisting := false
	if strings.TrimSpace(request.ConnectorID) == "" {
		items, err := s.Store.ListTenancyConnectors(ctx, project.WorkspaceID, project.ProjectID, domain.ConnectorTypeKubernetes, 1)
		if err != nil {
			return KubernetesConnectionStatus{}, fmt.Errorf("list kubernetes connectors: %w", err)
		}
		if len(items) > 0 {
			normalized.ConnectorID = items[0].Connector.ConnectorID
			existing = items[0]
			hasExisting = true
		}
	} else {
		existing, err = s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return KubernetesConnectionStatus{}, fmt.Errorf("load kubernetes connector: %w", err)
		}
		if err == nil {
			hasExisting = true
		}
	}
	if s.KubernetesPreflightFactory == nil {
		return KubernetesConnectionStatus{}, ErrKubernetesPreflightUnavailable
	}
	preflight := s.KubernetesPreflightFactory(normalized.Context)
	if preflight == nil {
		return KubernetesConnectionStatus{}, ErrKubernetesPreflightUnavailable
	}

	result := preflight.Preflight(ctx)
	now := s.Now().UTC()
	validatedAt := result.ObservedAt.UTC()
	if validatedAt.IsZero() {
		validatedAt = now
	}
	status := domain.ConnectorStatusDegraded
	connected := false
	if result.Health == connectors.HealthStatusHealthy {
		status = domain.ConnectorStatusActive
		connected = true
	}
	connection := kubernetesProjectConnection{
		TenantID:         scope.TenantID,
		WorkspaceID:      project.WorkspaceID,
		ProjectID:        project.ProjectID,
		ConnectorID:      normalized.ConnectorID,
		DisplayName:      normalized.DisplayName,
		Status:           status,
		HealthStatus:     string(result.Health),
		Context:          firstNonEmptyKubernetesValue(result.Cluster.Context, normalized.Context),
		Cluster:          strings.TrimSpace(result.Cluster.Cluster),
		Server:           strings.TrimSpace(result.Cluster.Server),
		GitVersion:       strings.TrimSpace(result.Cluster.GitVersion),
		Platform:         strings.TrimSpace(result.Cluster.Platform),
		PermissionChecks: copyKubernetesPermissionChecks(result.Checks),
		Diagnostics:      copyKubernetesDiagnostics(result.Diagnostics),
		UpdatedAt:        now,
		LastValidatedAt:  validatedAt,
	}
	metadataState := persistedKubernetesConnectorState{
		Context:          connection.Context,
		Cluster:          connection.Cluster,
		Server:           connection.Server,
		GitVersion:       connection.GitVersion,
		Platform:         connection.Platform,
		PermissionChecks: copyKubernetesPermissionChecks(connection.PermissionChecks),
		Diagnostics:      copyKubernetesDiagnostics(connection.Diagnostics),
		LastValidatedAt:  &validatedAt,
	}
	if hasExisting {
		existingMetadata, err := decodePersistedKubernetesConnectorState(existing.State.Metadata)
		if err != nil {
			return KubernetesConnectionStatus{}, fmt.Errorf("decode existing kubernetes connector metadata: %w", err)
		}
		if existingMetadata.ConnectionMode == k8sconnector.AgentMode {
			metadataState.ConnectionMode = existingMetadata.ConnectionMode
			metadataState.EnrollmentTokenHash = existingMetadata.EnrollmentTokenHash
			metadataState.EnrollmentExpiresAt = utcTimePtr(existingMetadata.EnrollmentExpiresAt)
			metadataState.EnrollmentTokenUsedAt = utcTimePtr(existingMetadata.EnrollmentTokenUsedAt)
			metadataState.AgentCredentialHash = existingMetadata.AgentCredentialHash
			metadataState.AgentID = existingMetadata.AgentID
			metadataState.LastHeartbeatAt = utcTimePtr(existingMetadata.LastHeartbeatAt)
		}
	}
	metadata, err := metadataState.toMap()
	if err != nil {
		return KubernetesConnectionStatus{}, fmt.Errorf("encode kubernetes connector metadata: %w", err)
	}
	state := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  normalized.ConnectorID,
		HealthStatus: connection.HealthStatus,
		Metadata:     metadata,
		ObservedAt:   validatedAt,
		UpdatedAt:    now,
	}
	if !connected {
		state.LastErrorCode = "kubernetes_connector_validation_failed"
		state.LastErrorMessage = firstKubernetesRemediation(connection.Diagnostics, connection.PermissionChecks)
	}
	connector := existing.Connector
	if !hasExisting {
		connector = db.TenancyConnector{
			TenantID:    scope.TenantID,
			WorkspaceID: project.WorkspaceID,
			ProjectID:   project.ProjectID,
			ConnectorID: normalized.ConnectorID,
		}
	}
	connector.Type = domain.ConnectorTypeKubernetes
	connector.DisplayName = normalized.DisplayName
	connector.Status = status
	connector.UpdatedAt = now
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return KubernetesConnectionStatus{}, fmt.Errorf("persist kubernetes connector: %w", err)
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	if err != nil {
		return KubernetesConnectionStatus{}, fmt.Errorf("load persisted kubernetes connector: %w", err)
	}
	response, err := s.kubernetesConnectionStatusFromStored(stored)
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}
	return response, nil
}

// GetKubernetesConnection returns one project Kubernetes connector state.
func (s *Service) GetKubernetesConnection(ctx context.Context, workspaceID string, projectID string) (KubernetesConnectionStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}
	items, err := s.Store.ListTenancyConnectors(ctx, project.WorkspaceID, project.ProjectID, domain.ConnectorTypeKubernetes, 1)
	if err != nil {
		return KubernetesConnectionStatus{}, fmt.Errorf("list kubernetes connectors: %w", err)
	}
	if len(items) == 0 {
		return KubernetesConnectionStatus{
			Provider:         "kubernetes",
			Connected:        false,
			Status:           domain.ConnectorStatusPending,
			HealthStatus:     string(connectors.HealthStatusUnknown),
			PermissionChecks: []k8sprovider.KubernetesPermissionCheckResult{},
			Diagnostics:      []k8sprovider.KubernetesPreflightDiagnostic{},
		}, nil
	}
	return s.kubernetesConnectionStatusFromStored(items[0])
}

func normalizeKubernetesConnectionRequest(project db.TenancyProject, request KubernetesConnectionUpsertRequest) (KubernetesConnectionUpsertRequest, error) {
	normalized := request
	normalized.ConnectorID = strings.TrimSpace(request.ConnectorID)
	if normalized.ConnectorID == "" {
		normalized.ConnectorID = "kubernetes-" + uuid.NewString()
	}
	normalized.DisplayName = strings.TrimSpace(request.DisplayName)
	if normalized.DisplayName == "" {
		normalized.DisplayName = "Kubernetes Cluster"
	}
	normalized.Context = strings.TrimSpace(request.Context)
	connector := domain.Connector{
		ID:          normalized.ConnectorID,
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
		Type:        domain.ConnectorTypeKubernetes,
		DisplayName: normalized.DisplayName,
		Status:      domain.ConnectorStatusPending,
	}
	if err := connector.Validate(); err != nil {
		return KubernetesConnectionUpsertRequest{}, ErrInvalidKubernetesConnectionRequest
	}
	return normalized, nil
}

func toKubernetesConnectionStatus(connection kubernetesProjectConnection) KubernetesConnectionStatus {
	createdAt := connection.CreatedAt.UTC()
	updatedAt := connection.UpdatedAt.UTC()
	validatedAt := connection.LastValidatedAt.UTC()
	return KubernetesConnectionStatus{
		Provider:            "kubernetes",
		Connected:           connection.Status == domain.ConnectorStatusActive && connection.HealthStatus == string(connectors.HealthStatusHealthy),
		ConnectorID:         connection.ConnectorID,
		DisplayName:         connection.DisplayName,
		Status:              connection.Status,
		HealthStatus:        connection.HealthStatus,
		Context:             connection.Context,
		Cluster:             connection.Cluster,
		Server:              connection.Server,
		GitVersion:          connection.GitVersion,
		Platform:            connection.Platform,
		ConnectionMode:      connection.ConnectionMode,
		AgentID:             connection.AgentID,
		PermissionChecks:    copyKubernetesPermissionChecks(connection.PermissionChecks),
		Diagnostics:         copyKubernetesDiagnostics(connection.Diagnostics),
		RemediationMessage:  firstKubernetesRemediation(connection.Diagnostics, connection.PermissionChecks),
		CreatedAt:           &createdAt,
		UpdatedAt:           &updatedAt,
		LastValidatedAt:     &validatedAt,
		LastHeartbeatAt:     utcTimePtr(connection.LastHeartbeatAt),
		EnrollmentExpiresAt: utcTimePtr(connection.EnrollmentExpiresAt),
	}
}

func (s *Service) kubernetesConnectionStatusFromStored(stored db.TenancyConnectorWithState) (KubernetesConnectionStatus, error) {
	connection, err := kubernetesConnectionFromStored(stored)
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}
	if connection.ConnectionMode == k8sconnector.AgentMode &&
		connection.Status == domain.ConnectorStatusActive &&
		connection.LastHeartbeatAt != nil &&
		s.Now().UTC().Sub(connection.LastHeartbeatAt.UTC()) > k8sconnector.HeartbeatDegradedAfter {
		connection.Status = domain.ConnectorStatusDegraded
		connection.HealthStatus = string(connectors.HealthStatusError)
		connection.Diagnostics = append(connection.Diagnostics, k8sprovider.KubernetesPreflightDiagnostic{
			Code:        "kubernetes_agent_heartbeat_stale",
			Severity:    "error",
			Message:     "Identrail has not received a recent heartbeat from the Kubernetes agent.",
			Remediation: "Verify the identrail-agent Deployment is running and can reach the Identrail API.",
		})
	}
	return toKubernetesConnectionStatus(connection), nil
}

func kubernetesConnectionStatusFromStored(stored db.TenancyConnectorWithState) (KubernetesConnectionStatus, error) {
	connection, err := kubernetesConnectionFromStored(stored)
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}
	return toKubernetesConnectionStatus(connection), nil
}

func kubernetesConnectionFromStored(stored db.TenancyConnectorWithState) (kubernetesProjectConnection, error) {
	metadata, err := decodePersistedKubernetesConnectorState(stored.State.Metadata)
	if err != nil {
		return kubernetesProjectConnection{}, fmt.Errorf("decode kubernetes connector metadata: %w", err)
	}
	connection := kubernetesProjectConnection{
		TenantID:            stored.Connector.TenantID,
		WorkspaceID:         stored.Connector.WorkspaceID,
		ProjectID:           stored.Connector.ProjectID,
		ConnectorID:         stored.Connector.ConnectorID,
		DisplayName:         stored.Connector.DisplayName,
		Status:              stored.Connector.Status,
		HealthStatus:        stored.State.HealthStatus,
		Context:             metadata.Context,
		Cluster:             metadata.Cluster,
		Server:              metadata.Server,
		GitVersion:          metadata.GitVersion,
		Platform:            metadata.Platform,
		ConnectionMode:      metadata.ConnectionMode,
		AgentID:             metadata.AgentID,
		PermissionChecks:    copyKubernetesPermissionChecks(metadata.PermissionChecks),
		Diagnostics:         copyKubernetesDiagnostics(metadata.Diagnostics),
		CreatedAt:           stored.Connector.CreatedAt,
		UpdatedAt:           stored.Connector.UpdatedAt,
		LastHeartbeatAt:     utcTimePtr(metadata.LastHeartbeatAt),
		EnrollmentExpiresAt: utcTimePtr(metadata.EnrollmentExpiresAt),
	}
	if metadata.LastValidatedAt != nil {
		connection.LastValidatedAt = metadata.LastValidatedAt.UTC()
	} else if !stored.State.ObservedAt.IsZero() {
		connection.LastValidatedAt = stored.State.ObservedAt.UTC()
	}
	return connection, nil
}

func utcTimePtr(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func (state persistedKubernetesConnectorState) toMap() (map[string]any, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var metadata map[string]any
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func decodePersistedKubernetesConnectorState(metadata map[string]any) (persistedKubernetesConnectorState, error) {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return persistedKubernetesConnectorState{}, err
	}
	var state persistedKubernetesConnectorState
	if err := json.Unmarshal(payload, &state); err != nil {
		return persistedKubernetesConnectorState{}, err
	}
	if state.PermissionChecks == nil {
		state.PermissionChecks = []k8sprovider.KubernetesPermissionCheckResult{}
	}
	if state.Diagnostics == nil {
		state.Diagnostics = []k8sprovider.KubernetesPreflightDiagnostic{}
	}
	return state, nil
}

func copyKubernetesPermissionChecks(checks []k8sprovider.KubernetesPermissionCheckResult) []k8sprovider.KubernetesPermissionCheckResult {
	if len(checks) == 0 {
		return []k8sprovider.KubernetesPermissionCheckResult{}
	}
	copied := make([]k8sprovider.KubernetesPermissionCheckResult, len(checks))
	copy(copied, checks)
	return copied
}

func copyKubernetesDiagnostics(diagnostics []k8sprovider.KubernetesPreflightDiagnostic) []k8sprovider.KubernetesPreflightDiagnostic {
	if len(diagnostics) == 0 {
		return []k8sprovider.KubernetesPreflightDiagnostic{}
	}
	copied := make([]k8sprovider.KubernetesPreflightDiagnostic, len(diagnostics))
	copy(copied, diagnostics)
	return copied
}

func firstKubernetesRemediation(diagnostics []k8sprovider.KubernetesPreflightDiagnostic, checks []k8sprovider.KubernetesPermissionCheckResult) string {
	for _, diagnostic := range diagnostics {
		if remediation := strings.TrimSpace(diagnostic.Remediation); remediation != "" {
			return remediation
		}
	}
	for _, check := range checks {
		if !check.Allowed {
			if remediation := strings.TrimSpace(check.Remediation); remediation != "" {
				return remediation
			}
		}
	}
	return ""
}

func firstNonEmptyKubernetesValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
