package api

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/google/uuid"
)

var awsRoleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)

// ErrInvalidAWSConnectionRequest indicates invalid AWS connector input.
var ErrInvalidAWSConnectionRequest = errors.New("invalid aws connection request")

// ErrAWSConnectionNotFound indicates one scoped project AWS connection does not exist.
var ErrAWSConnectionNotFound = errors.New("aws connection not found")

// ErrAWSConnectionValidatorUnavailable indicates live AWS validation is not configured.
var ErrAWSConnectionValidatorUnavailable = errors.New("aws connection validator unavailable")

// AWSConnectorValidator validates one AWS read-only connector setup.
type AWSConnectorValidator interface {
	ValidateAWSConnection(ctx context.Context, request AWSConnectionValidationRequest) (AWSConnectionValidationResult, error)
}

// AWSConnectionUpsertRequest captures one project AWS connector onboarding request.
type AWSConnectionUpsertRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	RoleARN     string `json:"role_arn"`
	ExternalID  string `json:"external_id,omitempty"`
	Region      string `json:"region,omitempty"`
	SessionName string `json:"session_name,omitempty"`
}

// AWSConnectionValidationRequest is passed to the provider validator.
type AWSConnectionValidationRequest struct {
	RoleARN     string
	ExternalID  string
	Region      string
	SessionName string
}

// AWSConnectionDiagnostic explains one validation outcome and how to remediate it.
type AWSConnectionDiagnostic struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSConnectionPermissionCheck captures one connector permission sanity check.
type AWSConnectionPermissionCheck struct {
	Name        string `json:"name"`
	Passed      bool   `json:"passed"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSConnectionValidationResult contains the live AWS metadata and diagnostics.
type AWSConnectionValidationResult struct {
	AccountID        string                         `json:"account_id,omitempty"`
	PrincipalARN     string                         `json:"principal_arn,omitempty"`
	UserID           string                         `json:"user_id,omitempty"`
	RoleARN          string                         `json:"role_arn,omitempty"`
	Region           string                         `json:"region,omitempty"`
	PermissionChecks []AWSConnectionPermissionCheck `json:"permission_checks"`
	Diagnostics      []AWSConnectionDiagnostic      `json:"diagnostics"`
}

// AWSConnectionStatus describes current AWS connector state for one project.
type AWSConnectionStatus struct {
	Provider             string                         `json:"provider"`
	Connected            bool                           `json:"connected"`
	ConnectorID          string                         `json:"connector_id,omitempty"`
	DisplayName          string                         `json:"display_name,omitempty"`
	Status               domain.ConnectorStatus         `json:"status"`
	HealthStatus         string                         `json:"health_status"`
	RoleARN              string                         `json:"role_arn,omitempty"`
	ExternalIDConfigured bool                           `json:"external_id_configured"`
	AccountID            string                         `json:"account_id,omitempty"`
	PrincipalARN         string                         `json:"principal_arn,omitempty"`
	UserID               string                         `json:"user_id,omitempty"`
	Region               string                         `json:"region,omitempty"`
	PermissionChecks     []AWSConnectionPermissionCheck `json:"permission_checks"`
	Diagnostics          []AWSConnectionDiagnostic      `json:"diagnostics"`
	RemediationMessage   string                         `json:"remediation_message,omitempty"`
	CreatedAt            *time.Time                     `json:"created_at,omitempty"`
	UpdatedAt            *time.Time                     `json:"updated_at,omitempty"`
	LastValidatedAt      *time.Time                     `json:"last_validated_at,omitempty"`
}

type awsProjectConnection struct {
	TenantID             string
	WorkspaceID          string
	ProjectID            string
	ConnectorID          string
	DisplayName          string
	Status               domain.ConnectorStatus
	HealthStatus         string
	RoleARN              string
	ExternalIDConfigured bool
	AccountID            string
	PrincipalARN         string
	UserID               string
	Region               string
	PermissionChecks     []AWSConnectionPermissionCheck
	Diagnostics          []AWSConnectionDiagnostic
	CreatedAt            time.Time
	UpdatedAt            time.Time
	LastValidatedAt      time.Time
}

func (s *Service) UpsertAWSConnection(ctx context.Context, workspaceID string, projectID string, request AWSConnectionUpsertRequest) (AWSConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	normalized, err := normalizeAWSConnectionRequest(request)
	if err != nil {
		return AWSConnectionStatus{}, err
	}
	if s.AWSConnectorValidator == nil {
		return AWSConnectionStatus{}, ErrAWSConnectionValidatorUnavailable
	}

	validation, err := s.AWSConnectorValidator.ValidateAWSConnection(ctx, AWSConnectionValidationRequest{
		RoleARN:     normalized.RoleARN,
		ExternalID:  normalized.ExternalID,
		Region:      normalized.Region,
		SessionName: normalized.SessionName,
	})
	if err != nil {
		return AWSConnectionStatus{}, err
	}

	now := s.Now().UTC()
	key := awsConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)
	status := domain.ConnectorStatusActive
	health := "healthy"
	connected := true
	if len(failedAWSChecks(validation.PermissionChecks)) > 0 || len(validation.Diagnostics) > 0 {
		status = domain.ConnectorStatusDegraded
		health = "error"
		connected = false
	}

	s.awsConnectMu.Lock()
	s.ensureAWSConnectionsState()
	createdAt := now
	if existing, exists := s.awsConnections[key]; exists {
		createdAt = existing.CreatedAt
	}
	connection := awsProjectConnection{
		TenantID:             scope.TenantID,
		WorkspaceID:          project.WorkspaceID,
		ProjectID:            project.ProjectID,
		ConnectorID:          normalized.ConnectorID,
		DisplayName:          normalized.DisplayName,
		Status:               status,
		HealthStatus:         health,
		RoleARN:              normalized.RoleARN,
		ExternalIDConfigured: normalized.ExternalID != "",
		AccountID:            strings.TrimSpace(validation.AccountID),
		PrincipalARN:         strings.TrimSpace(validation.PrincipalARN),
		UserID:               strings.TrimSpace(validation.UserID),
		Region:               firstNonEmptyAWSValue(strings.TrimSpace(validation.Region), normalized.Region),
		PermissionChecks:     copyAWSPermissionChecks(validation.PermissionChecks),
		Diagnostics:          copyAWSDiagnostics(validation.Diagnostics),
		CreatedAt:            createdAt,
		UpdatedAt:            now,
		LastValidatedAt:      now,
	}
	if connected && len(connection.PermissionChecks) == 0 {
		connection.PermissionChecks = []AWSConnectionPermissionCheck{{
			Name:    "sts:AssumeRole",
			Passed:  true,
			Message: "Role assumption succeeded.",
		}}
	}
	s.awsConnections[key] = connection
	response := toAWSConnectionStatus(connection)
	s.awsConnectMu.Unlock()

	return response, nil
}

func (s *Service) GetAWSConnection(ctx context.Context, workspaceID string, projectID string) (AWSConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}

	key := awsConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)
	s.awsConnectMu.RLock()
	connection, exists := s.awsConnections[key]
	s.awsConnectMu.RUnlock()
	if !exists {
		return AWSConnectionStatus{
			Provider:         "aws",
			Connected:        false,
			Status:           domain.ConnectorStatusPending,
			HealthStatus:     "unknown",
			PermissionChecks: []AWSConnectionPermissionCheck{},
			Diagnostics:      []AWSConnectionDiagnostic{},
		}, nil
	}
	return toAWSConnectionStatus(connection), nil
}

func normalizeAWSConnectionRequest(request AWSConnectionUpsertRequest) (AWSConnectionUpsertRequest, error) {
	normalized := request
	normalized.RoleARN = strings.TrimSpace(request.RoleARN)
	if !awsRoleARNPattern.MatchString(normalized.RoleARN) {
		return AWSConnectionUpsertRequest{}, ErrInvalidAWSConnectionRequest
	}
	normalized.ExternalID = strings.TrimSpace(request.ExternalID)
	normalized.Region = strings.TrimSpace(request.Region)
	if normalized.Region == "" {
		normalized.Region = "us-east-1"
	}
	normalized.SessionName = strings.TrimSpace(request.SessionName)
	if normalized.SessionName == "" {
		normalized.SessionName = "identrail-connector-validation"
	}
	normalized.ConnectorID = strings.TrimSpace(request.ConnectorID)
	if normalized.ConnectorID == "" {
		normalized.ConnectorID = "aws-" + uuid.NewString()
	}
	normalized.DisplayName = strings.TrimSpace(request.DisplayName)
	if normalized.DisplayName == "" {
		normalized.DisplayName = "AWS account " + accountIDFromRoleARN(normalized.RoleARN)
	}
	connector := domain.Connector{
		ID:          normalized.ConnectorID,
		WorkspaceID: "workspace-placeholder",
		ProjectID:   "project-placeholder",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: normalized.DisplayName,
		Status:      domain.ConnectorStatusPending,
	}
	if err := connector.Validate(); err != nil {
		return AWSConnectionUpsertRequest{}, ErrInvalidAWSConnectionRequest
	}
	return normalized, nil
}

func toAWSConnectionStatus(connection awsProjectConnection) AWSConnectionStatus {
	createdAt := connection.CreatedAt
	updatedAt := connection.UpdatedAt
	validatedAt := connection.LastValidatedAt
	status := AWSConnectionStatus{
		Provider:             "aws",
		Connected:            connection.Status == domain.ConnectorStatusActive && connection.HealthStatus == "healthy",
		ConnectorID:          connection.ConnectorID,
		DisplayName:          connection.DisplayName,
		Status:               connection.Status,
		HealthStatus:         connection.HealthStatus,
		RoleARN:              connection.RoleARN,
		ExternalIDConfigured: connection.ExternalIDConfigured,
		AccountID:            connection.AccountID,
		PrincipalARN:         connection.PrincipalARN,
		UserID:               connection.UserID,
		Region:               connection.Region,
		PermissionChecks:     copyAWSPermissionChecks(connection.PermissionChecks),
		Diagnostics:          copyAWSDiagnostics(connection.Diagnostics),
		CreatedAt:            &createdAt,
		UpdatedAt:            &updatedAt,
		LastValidatedAt:      &validatedAt,
	}
	status.RemediationMessage = firstAWSRemediation(status.Diagnostics, status.PermissionChecks)
	return status
}

func awsConnectionKey(tenantID string, workspaceID string, projectID string) string {
	return strings.Join([]string{tenantID, workspaceID, projectID}, "\x00")
}

func (s *Service) ensureAWSConnectionsState() {
	if s.awsConnections == nil {
		s.awsConnections = make(map[string]awsProjectConnection)
	}
}

func failedAWSChecks(checks []AWSConnectionPermissionCheck) []AWSConnectionPermissionCheck {
	failed := make([]AWSConnectionPermissionCheck, 0)
	for _, check := range checks {
		if !check.Passed {
			failed = append(failed, check)
		}
	}
	return failed
}

func firstAWSRemediation(diagnostics []AWSConnectionDiagnostic, checks []AWSConnectionPermissionCheck) string {
	for _, diagnostic := range diagnostics {
		if strings.TrimSpace(diagnostic.Remediation) != "" {
			return diagnostic.Remediation
		}
	}
	for _, check := range checks {
		if !check.Passed && strings.TrimSpace(check.Remediation) != "" {
			return check.Remediation
		}
	}
	return ""
}

func copyAWSPermissionChecks(checks []AWSConnectionPermissionCheck) []AWSConnectionPermissionCheck {
	if len(checks) == 0 {
		return []AWSConnectionPermissionCheck{}
	}
	copied := make([]AWSConnectionPermissionCheck, len(checks))
	copy(copied, checks)
	return copied
}

func copyAWSDiagnostics(diagnostics []AWSConnectionDiagnostic) []AWSConnectionDiagnostic {
	if len(diagnostics) == 0 {
		return []AWSConnectionDiagnostic{}
	}
	copied := make([]AWSConnectionDiagnostic, len(diagnostics))
	copy(copied, diagnostics)
	return copied
}

func firstNonEmptyAWSValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func accountIDFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return "unknown"
}
