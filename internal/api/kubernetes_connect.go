package api

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/connectors"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	k8sprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/kubernetes"
	"github.com/google/uuid"
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
	Provider           string                                        `json:"provider"`
	Connected          bool                                          `json:"connected"`
	ConnectorID        string                                        `json:"connector_id,omitempty"`
	DisplayName        string                                        `json:"display_name,omitempty"`
	Status             domain.ConnectorStatus                        `json:"status"`
	HealthStatus       string                                        `json:"health_status"`
	Context            string                                        `json:"context,omitempty"`
	Cluster            string                                        `json:"cluster,omitempty"`
	Server             string                                        `json:"server,omitempty"`
	GitVersion         string                                        `json:"git_version,omitempty"`
	Platform           string                                        `json:"platform,omitempty"`
	PermissionChecks   []k8sprovider.KubernetesPermissionCheckResult `json:"permission_checks"`
	Diagnostics        []k8sprovider.KubernetesPreflightDiagnostic   `json:"diagnostics"`
	RemediationMessage string                                        `json:"remediation_message,omitempty"`
	CreatedAt          *time.Time                                    `json:"created_at,omitempty"`
	UpdatedAt          *time.Time                                    `json:"updated_at,omitempty"`
	LastValidatedAt    *time.Time                                    `json:"last_validated_at,omitempty"`
}

type kubernetesProjectConnection struct {
	TenantID         string
	WorkspaceID      string
	ProjectID        string
	ConnectorID      string
	DisplayName      string
	Status           domain.ConnectorStatus
	HealthStatus     string
	Context          string
	Cluster          string
	Server           string
	GitVersion       string
	Platform         string
	PermissionChecks []k8sprovider.KubernetesPermissionCheckResult
	Diagnostics      []k8sprovider.KubernetesPreflightDiagnostic
	CreatedAt        time.Time
	UpdatedAt        time.Time
	LastValidatedAt  time.Time
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

	s.kubernetesConnectMu.Lock()
	s.ensureKubernetesConnectionsState()
	key := kubernetesConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)
	createdAt := now
	if existing, exists := s.kubernetesConnections[key]; exists {
		createdAt = existing.CreatedAt
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
		CreatedAt:        createdAt,
		UpdatedAt:        now,
		LastValidatedAt:  validatedAt,
	}
	s.kubernetesConnections[key] = connection
	response := toKubernetesConnectionStatus(connection)
	response.Connected = connected
	s.kubernetesConnectMu.Unlock()

	return response, nil
}

// GetKubernetesConnection returns one project Kubernetes connector state.
func (s *Service) GetKubernetesConnection(ctx context.Context, workspaceID string, projectID string) (KubernetesConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return KubernetesConnectionStatus{}, err
	}

	key := kubernetesConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)
	s.kubernetesConnectMu.RLock()
	connection, exists := s.kubernetesConnections[key]
	s.kubernetesConnectMu.RUnlock()
	if !exists {
		return KubernetesConnectionStatus{
			Provider:         "kubernetes",
			Connected:        false,
			Status:           domain.ConnectorStatusPending,
			HealthStatus:     string(connectors.HealthStatusUnknown),
			PermissionChecks: []k8sprovider.KubernetesPermissionCheckResult{},
			Diagnostics:      []k8sprovider.KubernetesPreflightDiagnostic{},
		}, nil
	}
	return toKubernetesConnectionStatus(connection), nil
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
		Provider:           "kubernetes",
		Connected:          connection.Status == domain.ConnectorStatusActive && connection.HealthStatus == string(connectors.HealthStatusHealthy),
		ConnectorID:        connection.ConnectorID,
		DisplayName:        connection.DisplayName,
		Status:             connection.Status,
		HealthStatus:       connection.HealthStatus,
		Context:            connection.Context,
		Cluster:            connection.Cluster,
		Server:             connection.Server,
		GitVersion:         connection.GitVersion,
		Platform:           connection.Platform,
		PermissionChecks:   copyKubernetesPermissionChecks(connection.PermissionChecks),
		Diagnostics:        copyKubernetesDiagnostics(connection.Diagnostics),
		RemediationMessage: firstKubernetesRemediation(connection.Diagnostics, connection.PermissionChecks),
		CreatedAt:          &createdAt,
		UpdatedAt:          &updatedAt,
		LastValidatedAt:    &validatedAt,
	}
}

func kubernetesConnectionKey(tenantID string, workspaceID string, projectID string) string {
	return strings.Join([]string{strings.TrimSpace(tenantID), strings.TrimSpace(workspaceID), strings.TrimSpace(projectID)}, "\x00")
}

func (s *Service) ensureKubernetesConnectionsState() {
	if s.kubernetesConnections == nil {
		s.kubernetesConnections = make(map[string]kubernetesProjectConnection)
	}
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
