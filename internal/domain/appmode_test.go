package domain

import (
	"testing"
	"time"
)

func TestAppModeEntitiesValidate(t *testing.T) {
	now := time.Now().UTC()
	org := Organization{
		ID:        "org-core",
		Name:      "Core Org",
		Slug:      "core-org",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := org.Validate(); err != nil {
		t.Fatalf("expected valid organization, got %v", err)
	}

	workspace := Workspace{
		ID:             "workspace-core",
		OrganizationID: org.ID,
		Name:           "Core Workspace",
		Slug:           "core-workspace",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := workspace.Validate(); err != nil {
		t.Fatalf("expected valid workspace, got %v", err)
	}

	member := WorkspaceMember{
		ID:          "member-1",
		WorkspaceID: workspace.ID,
		UserID:      "user-1",
		Email:       "user@example.com",
		Role:        MemberRoleAdmin,
		Status:      MemberStatusActive,
		JoinedAt:    now,
		UpdatedAt:   now,
	}
	if err := member.Validate(); err != nil {
		t.Fatalf("expected valid member, got %v", err)
	}

	project := Project{
		ID:          "project-payments",
		WorkspaceID: workspace.ID,
		Name:        "Payments",
		Slug:        "payments",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := project.Validate(); err != nil {
		t.Fatalf("expected valid project, got %v", err)
	}

	connector := Connector{
		ID:          "connector-gh",
		WorkspaceID: workspace.ID,
		ProjectID:   project.ID,
		Type:        ConnectorTypeGitHub,
		DisplayName: "GitHub Source",
		Status:      ConnectorStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := connector.Validate(); err != nil {
		t.Fatalf("expected valid connector, got %v", err)
	}

	policy := ScanPolicy{
		ID:                 "policy-1",
		WorkspaceID:        workspace.ID,
		ProjectID:          project.ID,
		Name:               "default policy",
		Enabled:            true,
		TriggerMode:        ScanTriggerModeHybrid,
		Cron:               "0 */6 * * *",
		MaxConcurrentScans: 2,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("expected valid scan policy, got %v", err)
	}

	suppression := SuppressionPolicy{
		ID:          "suppression-1",
		WorkspaceID: workspace.ID,
		ProjectID:   project.ID,
		Name:        "temporary exception",
		Scope:       SuppressionScopeRule,
		Target:      "secret_exposure",
		Reason:      "approved exception",
		CreatedBy:   "admin-user",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := suppression.Validate(); err != nil {
		t.Fatalf("expected valid suppression policy, got %v", err)
	}

	remediation := RemediationJob{
		ID:          "remediation-1",
		WorkspaceID: workspace.ID,
		ProjectID:   project.ID,
		FindingID:   "finding-123",
		Type:        RemediationJobTypeCreateFixPR,
		Status:      RemediationJobStatusQueued,
		RequestedBy: "admin-user",
		RequestedAt: now,
		UpdatedAt:   now,
	}
	if err := remediation.Validate(); err != nil {
		t.Fatalf("expected valid remediation job, got %v", err)
	}
}

func TestAppModeEntityValidationFailsOnMissingRequiredFields(t *testing.T) {
	if err := (Organization{}).Validate(); err == nil {
		t.Fatal("expected organization validation to fail")
	}
	if err := (Workspace{}).Validate(); err == nil {
		t.Fatal("expected workspace validation to fail")
	}
	if err := (WorkspaceMember{}).Validate(); err == nil {
		t.Fatal("expected workspace member validation to fail")
	}
	if err := (Project{}).Validate(); err == nil {
		t.Fatal("expected project validation to fail")
	}
	if err := (Connector{}).Validate(); err == nil {
		t.Fatal("expected connector validation to fail")
	}
	if err := (ScanPolicy{}).Validate(); err == nil {
		t.Fatal("expected scan policy validation to fail")
	}
	if err := (SuppressionPolicy{}).Validate(); err == nil {
		t.Fatal("expected suppression policy validation to fail")
	}
	if err := (RemediationJob{}).Validate(); err == nil {
		t.Fatal("expected remediation job validation to fail")
	}
}

func TestAppModeIdentifierRejectsSurroundingWhitespace(t *testing.T) {
	org := Organization{
		ID:   "  org-1  ",
		Name: "Org One",
		Slug: "org-one",
	}
	if err := org.Validate(); err == nil {
		t.Fatal("expected identifier with surrounding whitespace to fail")
	}
}

func TestWorkspaceMemberValidationRequiresEmail(t *testing.T) {
	now := time.Now().UTC()
	member := WorkspaceMember{
		ID:          "member-1",
		WorkspaceID: "workspace-core",
		UserID:      "user-1",
		Email:       "   ",
		Role:        MemberRoleViewer,
		Status:      MemberStatusInvited,
		JoinedAt:    now,
		UpdatedAt:   now,
	}
	if err := member.Validate(); err == nil {
		t.Fatal("expected workspace member email validation to fail")
	}
}

func TestScanPolicyScheduledValidationRequiresCron(t *testing.T) {
	now := time.Now().UTC()
	policy := ScanPolicy{
		ID:                 "policy-1",
		WorkspaceID:        "workspace-core",
		ProjectID:          "project-core",
		Name:               "scheduled policy",
		Enabled:            true,
		TriggerMode:        ScanTriggerModeScheduled,
		MaxConcurrentScans: 1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := policy.Validate(); err == nil {
		t.Fatal("expected scan policy scheduled validation to fail when cron is missing")
	}
}

func TestRemediationJobValidationRequiresValidFindingID(t *testing.T) {
	now := time.Now().UTC()
	job := RemediationJob{
		ID:          "remediation-1",
		WorkspaceID: "workspace-core",
		ProjectID:   "project-core",
		FindingID:   "finding bad",
		Type:        RemediationJobTypeCreateFixPR,
		Status:      RemediationJobStatusQueued,
		RequestedBy: "admin-user",
		RequestedAt: now,
		UpdatedAt:   now,
	}
	if err := job.Validate(); err == nil {
		t.Fatal("expected remediation job finding_id validation to fail")
	}
}

func TestConnectorStatusTransitions(t *testing.T) {
	if !CanTransitionConnectorStatus(ConnectorStatusPending, ConnectorStatusActive) {
		t.Fatal("expected pending -> active transition to be valid")
	}
	if CanTransitionConnectorStatus(ConnectorStatusActive, ConnectorStatusPending) {
		t.Fatal("expected active -> pending transition to be invalid")
	}
	if !CanTransitionConnectorStatus(ConnectorStatusDegraded, ConnectorStatusActive) {
		t.Fatal("expected degraded -> active transition to be valid")
	}
}

func TestRemediationStatusTransitions(t *testing.T) {
	if !CanTransitionRemediationJobStatus(RemediationJobStatusQueued, RemediationJobStatusRunning) {
		t.Fatal("expected queued -> running transition to be valid")
	}
	if !CanTransitionRemediationJobStatus(RemediationJobStatusRunning, RemediationJobStatusSucceeded) {
		t.Fatal("expected running -> succeeded transition to be valid")
	}
	if CanTransitionRemediationJobStatus(RemediationJobStatusSucceeded, RemediationJobStatusQueued) {
		t.Fatal("expected succeeded -> queued transition to be invalid")
	}
	if !CanTransitionRemediationJobStatus(RemediationJobStatusFailed, RemediationJobStatusQueued) {
		t.Fatal("expected failed -> queued transition to be valid for retry")
	}
	if CanTransitionRemediationJobStatus(RemediationJobStatusSucceeded, RemediationJobStatusSucceeded) {
		t.Fatal("expected succeeded -> succeeded self-transition to be invalid")
	}
	if CanTransitionRemediationJobStatus(RemediationJobStatusCanceled, RemediationJobStatusCanceled) {
		t.Fatal("expected canceled -> canceled self-transition to be invalid")
	}
}
