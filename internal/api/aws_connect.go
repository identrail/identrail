package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/textutil"
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
	ExternalID           string                         `json:"-"`
	PermissionChecks     []AWSConnectionPermissionCheck `json:"permission_checks"`
	Diagnostics          []AWSConnectionDiagnostic      `json:"diagnostics"`
	RemediationMessage   string                         `json:"remediation_message,omitempty"`
	CreatedAt            *time.Time                     `json:"created_at,omitempty"`
	UpdatedAt            *time.Time                     `json:"updated_at,omitempty"`
	LastValidatedAt      *time.Time                     `json:"last_validated_at,omitempty"`
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
	status := domain.ConnectorStatusActive
	health := "healthy"
	connected := true
	if len(failedAWSChecks(validation.PermissionChecks)) > 0 || len(validation.Diagnostics) > 0 {
		status = domain.ConnectorStatusDegraded
		health = "error"
		connected = false
	}

	checks := copyAWSPermissionChecks(validation.PermissionChecks)
	if connected && len(checks) == 0 {
		checks = []AWSConnectionPermissionCheck{{
			Name:    "sts:AssumeRole",
			Passed:  true,
			Message: "Role assumption succeeded.",
		}}
	}
	metadata := map[string]any{
		"role_arn":               normalized.RoleARN,
		"external_id":            normalized.ExternalID,
		"external_id_configured": normalized.ExternalID != "",
		"account_id":             strings.TrimSpace(validation.AccountID),
		"principal_arn":          strings.TrimSpace(validation.PrincipalARN),
		"user_id":                strings.TrimSpace(validation.UserID),
		"region":                 textutil.FirstNonEmpty(strings.TrimSpace(validation.Region), normalized.Region),
		"permission_checks":      checks,
		"diagnostics":            copyAWSDiagnostics(validation.Diagnostics),
		"last_validated_at":      now.Format(time.RFC3339Nano),
	}
	state := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  normalized.ConnectorID,
		HealthStatus: health,
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	if !connected {
		state.LastErrorCode = "aws_connector_validation_failed"
		state.LastErrorMessage = firstAWSRemediation(copyAWSDiagnostics(validation.Diagnostics), checks)
	}
	connector := db.TenancyConnector{
		TenantID:    scope.TenantID,
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
		ConnectorID: normalized.ConnectorID,
		Type:        domain.ConnectorTypeAWS,
		DisplayName: normalized.DisplayName,
		Status:      status,
		UpdatedAt:   now,
	}
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("persist aws connector: %w", err)
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, normalized.ConnectorID)
	if err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("load persisted aws connector: %w", err)
	}
	response := awsConnectionStatusFromStored(stored)

	return response, nil
}

func (s *Service) GetAWSConnection(ctx context.Context, workspaceID string, projectID string) (AWSConnectionStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSConnectionStatus{}, err
	}

	items, err := s.Store.ListTenancyConnectors(ctx, project.WorkspaceID, project.ProjectID, domain.ConnectorTypeAWS, 1)
	if err != nil {
		return AWSConnectionStatus{}, fmt.Errorf("list aws connectors: %w", err)
	}
	if len(items) == 0 {
		return AWSConnectionStatus{
			Provider:         "aws",
			Connected:        false,
			Status:           domain.ConnectorStatusPending,
			HealthStatus:     "unknown",
			PermissionChecks: []AWSConnectionPermissionCheck{},
			Diagnostics:      []AWSConnectionDiagnostic{},
		}, nil
	}
	return awsConnectionStatusFromStored(items[0]), nil
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
		normalized.ConnectorID = "aws-" + accountIDFromRoleARN(normalized.RoleARN)
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

func awsConnectionStatusFromStored(stored db.TenancyConnectorWithState) AWSConnectionStatus {
	metadata := stored.State.Metadata
	createdAt := stored.Connector.CreatedAt
	updatedAt := stored.Connector.UpdatedAt
	validatedAt := awsMetadataTime(metadata, "last_validated_at")
	if validatedAt == nil && !stored.State.ObservedAt.IsZero() {
		observed := stored.State.ObservedAt
		validatedAt = &observed
	}
	status := AWSConnectionStatus{
		Provider:             "aws",
		Connected:            stored.Connector.Status == domain.ConnectorStatusActive && stored.State.HealthStatus == "healthy",
		ConnectorID:          stored.Connector.ConnectorID,
		DisplayName:          stored.Connector.DisplayName,
		Status:               stored.Connector.Status,
		HealthStatus:         textutil.FirstNonEmpty(stored.State.HealthStatus, "unknown"),
		RoleARN:              awsMetadataString(metadata, "role_arn"),
		ExternalID:           awsMetadataString(metadata, "external_id"),
		ExternalIDConfigured: awsMetadataBool(metadata, "external_id_configured"),
		AccountID:            awsMetadataString(metadata, "account_id"),
		PrincipalARN:         awsMetadataString(metadata, "principal_arn"),
		UserID:               awsMetadataString(metadata, "user_id"),
		Region:               awsMetadataString(metadata, "region"),
		PermissionChecks:     awsMetadataPermissionChecks(metadata, "permission_checks"),
		Diagnostics:          awsMetadataDiagnostics(metadata, "diagnostics"),
		CreatedAt:            &createdAt,
		UpdatedAt:            &updatedAt,
		LastValidatedAt:      validatedAt,
	}
	status.RemediationMessage = firstAWSRemediation(status.Diagnostics, status.PermissionChecks)
	return status
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

func awsMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	raw, ok := metadata[key]
	if !ok || raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func awsMetadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	switch value := metadata[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func awsMetadataTime(metadata map[string]any, key string) *time.Time {
	value := awsMetadataString(metadata, key)
	if value == "" || value == "<nil>" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	utc := parsed.UTC()
	return &utc
}

func awsMetadataPermissionChecks(metadata map[string]any, key string) []AWSConnectionPermissionCheck {
	if metadata == nil || metadata[key] == nil {
		return []AWSConnectionPermissionCheck{}
	}
	var checks []AWSConnectionPermissionCheck
	payload, err := json.Marshal(metadata[key])
	if err != nil {
		return []AWSConnectionPermissionCheck{}
	}
	if err := json.Unmarshal(payload, &checks); err != nil {
		return []AWSConnectionPermissionCheck{}
	}
	return copyAWSPermissionChecks(checks)
}

func awsMetadataDiagnostics(metadata map[string]any, key string) []AWSConnectionDiagnostic {
	if metadata == nil || metadata[key] == nil {
		return []AWSConnectionDiagnostic{}
	}
	var diagnostics []AWSConnectionDiagnostic
	payload, err := json.Marshal(metadata[key])
	if err != nil {
		return []AWSConnectionDiagnostic{}
	}
	if err := json.Unmarshal(payload, &diagnostics); err != nil {
		return []AWSConnectionDiagnostic{}
	}
	return copyAWSDiagnostics(diagnostics)
}

func accountIDFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return "unknown"
}
