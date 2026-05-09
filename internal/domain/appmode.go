package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var appModeIdentifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$`)

// MemberRole enumerates tenancy-level permissions within a workspace.
type MemberRole string

const (
	MemberRoleOwner   MemberRole = "owner"
	MemberRoleAdmin   MemberRole = "admin"
	MemberRoleAnalyst MemberRole = "analyst"
	MemberRoleViewer  MemberRole = "viewer"
)

// MemberStatus tracks workspace membership lifecycle state.
type MemberStatus string

const (
	MemberStatusInvited   MemberStatus = "invited"
	MemberStatusActive    MemberStatus = "active"
	MemberStatusSuspended MemberStatus = "suspended"
	MemberStatusRemoved   MemberStatus = "removed"
)

// ConnectorType identifies one onboarded source connector.
type ConnectorType string

const (
	ConnectorTypeGitHub     ConnectorType = "github"
	ConnectorTypeAWS        ConnectorType = "aws"
	ConnectorTypeKubernetes ConnectorType = "kubernetes"
)

// ConnectorStatus represents connector health and lifecycle state.
type ConnectorStatus string

const (
	ConnectorStatusPending      ConnectorStatus = "pending"
	ConnectorStatusActive       ConnectorStatus = "active"
	ConnectorStatusDegraded     ConnectorStatus = "degraded"
	ConnectorStatusDisconnected ConnectorStatus = "disconnected"
)

// ScanTriggerMode controls scan initiation mode.
type ScanTriggerMode string

const (
	ScanTriggerModeManual    ScanTriggerMode = "manual"
	ScanTriggerModeScheduled ScanTriggerMode = "scheduled"
	ScanTriggerModeEvent     ScanTriggerMode = "event"
	ScanTriggerModeHybrid    ScanTriggerMode = "hybrid"
)

// SuppressionScope controls suppression blast radius.
type SuppressionScope string

const (
	SuppressionScopeFinding  SuppressionScope = "finding"
	SuppressionScopeRule     SuppressionScope = "rule"
	SuppressionScopeResource SuppressionScope = "resource"
)

// RemediationJobType identifies one remediation class.
type RemediationJobType string

const (
	RemediationJobTypePatchTemplate RemediationJobType = "patch_template"
	RemediationJobTypeCreateFixPR   RemediationJobType = "create_fix_pr"
	RemediationJobTypeTicket        RemediationJobType = "ticket"
)

// RemediationJobStatus tracks remediation execution lifecycle.
type RemediationJobStatus string

const (
	RemediationJobStatusQueued    RemediationJobStatus = "queued"
	RemediationJobStatusRunning   RemediationJobStatus = "running"
	RemediationJobStatusSucceeded RemediationJobStatus = "succeeded"
	RemediationJobStatusFailed    RemediationJobStatus = "failed"
	RemediationJobStatusCanceled  RemediationJobStatus = "canceled"
)

// Organization models one tenant boundary.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Workspace models one collaboration boundary within an organization.
type Workspace struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// WorkspaceMember models one user assignment in a workspace.
type WorkspaceMember struct {
	ID          string       `json:"id"`
	WorkspaceID string       `json:"workspace_id"`
	UserID      string       `json:"user_id"`
	Email       string       `json:"email"`
	Role        MemberRole   `json:"role"`
	Status      MemberStatus `json:"status"`
	JoinedAt    time.Time    `json:"joined_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Project models one scoped application or service boundary in a workspace.
type Project struct {
	ID          string     `json:"id"`
	WorkspaceID string     `json:"workspace_id"`
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	Description string     `json:"description,omitempty"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Connector models one project integration source.
type Connector struct {
	ID          string          `json:"id"`
	WorkspaceID string          `json:"workspace_id"`
	ProjectID   string          `json:"project_id"`
	Type        ConnectorType   `json:"type"`
	DisplayName string          `json:"display_name"`
	Status      ConnectorStatus `json:"status"`
	LastSyncAt  *time.Time      `json:"last_sync_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ScanPolicy models scan scheduling and trigger limits for one project.
type ScanPolicy struct {
	ID                 string          `json:"id"`
	WorkspaceID        string          `json:"workspace_id"`
	ProjectID          string          `json:"project_id"`
	Name               string          `json:"name"`
	Enabled            bool            `json:"enabled"`
	TriggerMode        ScanTriggerMode `json:"trigger_mode"`
	Cron               string          `json:"cron,omitempty"`
	MaxConcurrentScans int             `json:"max_concurrent_scans"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// SuppressionPolicy models policy-based finding suppressions.
type SuppressionPolicy struct {
	ID            string           `json:"id"`
	WorkspaceID   string           `json:"workspace_id"`
	ProjectID     string           `json:"project_id"`
	Name          string           `json:"name"`
	Scope         SuppressionScope `json:"scope"`
	Target        string           `json:"target"`
	Reason        string           `json:"reason"`
	ExpiresAt     *time.Time       `json:"expires_at,omitempty"`
	CreatedBy     string           `json:"created_by"`
	CreatedAt     time.Time        `json:"created_at"`
	LastUpdatedAt time.Time        `json:"last_updated_at"`
}

// RemediationJob models one remediation execution request.
type RemediationJob struct {
	ID            string               `json:"id"`
	WorkspaceID   string               `json:"workspace_id"`
	ProjectID     string               `json:"project_id"`
	FindingID     string               `json:"finding_id"`
	Type          RemediationJobType   `json:"type"`
	Status        RemediationJobStatus `json:"status"`
	RequestedBy   string               `json:"requested_by"`
	RequestedAt   time.Time            `json:"requested_at"`
	StartedAt     *time.Time           `json:"started_at,omitempty"`
	CompletedAt   *time.Time           `json:"completed_at,omitempty"`
	ArtifactRef   string               `json:"artifact_ref,omitempty"`
	ErrorMessage  string               `json:"error_message,omitempty"`
	LastUpdatedAt time.Time            `json:"last_updated_at"`
}

func (o Organization) Validate() error {
	if err := validateAppModeIdentifier("organization.id", o.ID); err != nil {
		return err
	}
	if strings.TrimSpace(o.Name) == "" {
		return fmt.Errorf("organization.name is required")
	}
	if err := validateAppModeIdentifier("organization.slug", o.Slug); err != nil {
		return err
	}
	return nil
}

func (w Workspace) Validate() error {
	if err := validateAppModeIdentifier("workspace.id", w.ID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("workspace.organization_id", w.OrganizationID); err != nil {
		return err
	}
	if strings.TrimSpace(w.Name) == "" {
		return fmt.Errorf("workspace.name is required")
	}
	if err := validateAppModeIdentifier("workspace.slug", w.Slug); err != nil {
		return err
	}
	return nil
}

func (m WorkspaceMember) Validate() error {
	if err := validateAppModeIdentifier("workspace_member.id", m.ID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("workspace_member.workspace_id", m.WorkspaceID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("workspace_member.user_id", m.UserID); err != nil {
		return err
	}
	if strings.TrimSpace(m.Email) == "" {
		return fmt.Errorf("workspace_member.email is required")
	}
	if !validMemberRole(m.Role) {
		return fmt.Errorf("workspace_member.role is invalid")
	}
	if !validMemberStatus(m.Status) {
		return fmt.Errorf("workspace_member.status is invalid")
	}
	return nil
}

func (p Project) Validate() error {
	if err := validateAppModeIdentifier("project.id", p.ID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("project.workspace_id", p.WorkspaceID); err != nil {
		return err
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("project.name is required")
	}
	if err := validateAppModeIdentifier("project.slug", p.Slug); err != nil {
		return err
	}
	return nil
}

func (c Connector) Validate() error {
	if err := validateAppModeIdentifier("connector.id", c.ID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("connector.workspace_id", c.WorkspaceID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("connector.project_id", c.ProjectID); err != nil {
		return err
	}
	if !validConnectorType(c.Type) {
		return fmt.Errorf("connector.type is invalid")
	}
	if strings.TrimSpace(c.DisplayName) == "" {
		return fmt.Errorf("connector.display_name is required")
	}
	if !validConnectorStatus(c.Status) {
		return fmt.Errorf("connector.status is invalid")
	}
	return nil
}

func (p ScanPolicy) Validate() error {
	if err := validateAppModeIdentifier("scan_policy.id", p.ID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("scan_policy.workspace_id", p.WorkspaceID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("scan_policy.project_id", p.ProjectID); err != nil {
		return err
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("scan_policy.name is required")
	}
	if !validScanTriggerMode(p.TriggerMode) {
		return fmt.Errorf("scan_policy.trigger_mode is invalid")
	}
	if p.TriggerMode == ScanTriggerModeScheduled && strings.TrimSpace(p.Cron) == "" {
		return fmt.Errorf("scan_policy.cron is required for scheduled trigger_mode")
	}
	if p.MaxConcurrentScans <= 0 {
		return fmt.Errorf("scan_policy.max_concurrent_scans must be > 0")
	}
	return nil
}

func (p SuppressionPolicy) Validate() error {
	if err := validateAppModeIdentifier("suppression_policy.id", p.ID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("suppression_policy.workspace_id", p.WorkspaceID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("suppression_policy.project_id", p.ProjectID); err != nil {
		return err
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("suppression_policy.name is required")
	}
	if !validSuppressionScope(p.Scope) {
		return fmt.Errorf("suppression_policy.scope is invalid")
	}
	if strings.TrimSpace(p.Target) == "" {
		return fmt.Errorf("suppression_policy.target is required")
	}
	if strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("suppression_policy.reason is required")
	}
	if err := validateAppModeIdentifier("suppression_policy.created_by", p.CreatedBy); err != nil {
		return err
	}
	return nil
}

func (j RemediationJob) Validate() error {
	if err := validateAppModeIdentifier("remediation_job.id", j.ID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("remediation_job.workspace_id", j.WorkspaceID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("remediation_job.project_id", j.ProjectID); err != nil {
		return err
	}
	if err := validateAppModeIdentifier("remediation_job.finding_id", j.FindingID); err != nil {
		return err
	}
	if !validRemediationType(j.Type) {
		return fmt.Errorf("remediation_job.type is invalid")
	}
	if !validRemediationStatus(j.Status) {
		return fmt.Errorf("remediation_job.status is invalid")
	}
	if err := validateAppModeIdentifier("remediation_job.requested_by", j.RequestedBy); err != nil {
		return err
	}
	return nil
}

func CanTransitionConnectorStatus(from ConnectorStatus, to ConnectorStatus) bool {
	if !validConnectorStatus(from) || !validConnectorStatus(to) {
		return false
	}
	if from == to {
		return true
	}
	switch from {
	case ConnectorStatusPending:
		return to == ConnectorStatusActive || to == ConnectorStatusDisconnected || to == ConnectorStatusDegraded
	case ConnectorStatusActive:
		return to == ConnectorStatusDegraded || to == ConnectorStatusDisconnected
	case ConnectorStatusDegraded:
		return to == ConnectorStatusActive || to == ConnectorStatusDisconnected
	case ConnectorStatusDisconnected:
		return to == ConnectorStatusPending || to == ConnectorStatusActive
	default:
		return false
	}
}

func canTransitionRemediationJobStatus(from RemediationJobStatus, to RemediationJobStatus) bool {
	if from == to {
		return true
	}
	switch from {
	case RemediationJobStatusQueued:
		return to == RemediationJobStatusRunning || to == RemediationJobStatusCanceled
	case RemediationJobStatusRunning:
		return to == RemediationJobStatusSucceeded || to == RemediationJobStatusFailed || to == RemediationJobStatusCanceled
	case RemediationJobStatusFailed:
		return to == RemediationJobStatusQueued
	case RemediationJobStatusSucceeded, RemediationJobStatusCanceled:
		return false
	default:
		return false
	}
}

func validateAppModeIdentifier(field string, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%s is required", field)
	}
	if value != trimmed {
		return fmt.Errorf("%s must not contain surrounding whitespace", field)
	}
	if !appModeIdentifierPattern.MatchString(trimmed) {
		return fmt.Errorf("%s must match %s", field, appModeIdentifierPattern.String())
	}
	return nil
}

func validMemberRole(role MemberRole) bool {
	switch role {
	case MemberRoleOwner, MemberRoleAdmin, MemberRoleAnalyst, MemberRoleViewer:
		return true
	default:
		return false
	}
}

func validMemberStatus(status MemberStatus) bool {
	switch status {
	case MemberStatusInvited, MemberStatusActive, MemberStatusSuspended, MemberStatusRemoved:
		return true
	default:
		return false
	}
}

func validConnectorType(connectorType ConnectorType) bool {
	switch connectorType {
	case ConnectorTypeGitHub, ConnectorTypeAWS, ConnectorTypeKubernetes:
		return true
	default:
		return false
	}
}

func validConnectorStatus(status ConnectorStatus) bool {
	switch status {
	case ConnectorStatusPending, ConnectorStatusActive, ConnectorStatusDegraded, ConnectorStatusDisconnected:
		return true
	default:
		return false
	}
}

func validScanTriggerMode(mode ScanTriggerMode) bool {
	switch mode {
	case ScanTriggerModeManual, ScanTriggerModeScheduled, ScanTriggerModeEvent, ScanTriggerModeHybrid:
		return true
	default:
		return false
	}
}

func validSuppressionScope(scope SuppressionScope) bool {
	switch scope {
	case SuppressionScopeFinding, SuppressionScopeRule, SuppressionScopeResource:
		return true
	default:
		return false
	}
}

func validRemediationType(remediationType RemediationJobType) bool {
	switch remediationType {
	case RemediationJobTypePatchTemplate, RemediationJobTypeCreateFixPR, RemediationJobTypeTicket:
		return true
	default:
		return false
	}
}

func validRemediationStatus(status RemediationJobStatus) bool {
	switch status {
	case RemediationJobStatusQueued, RemediationJobStatusRunning, RemediationJobStatusSucceeded, RemediationJobStatusFailed, RemediationJobStatusCanceled:
		return true
	default:
		return false
	}
}
