package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
)

const (
	onboardingStepOrg       = "org"
	onboardingStepWorkspace = "workspace"
	onboardingStepConnect   = "connect"
	onboardingStepScan      = "scan"
	onboardingStepInvite    = "invite"
	onboardingStepComplete  = "complete"
)

var (
	// ErrInvalidOnboardingRequest indicates a malformed onboarding transition.
	ErrInvalidOnboardingRequest        = errors.New("invalid onboarding request")
	ErrOnboardingWorkspaceAccessDenied = errors.New("onboarding workspace access denied")
	onboardingSlugUnsafe               = regexp.MustCompile(`[^a-z0-9]+`)
)

// OnboardingStateUpdateRequest captures one resumable setup transition.
type OnboardingStateUpdateRequest struct {
	CurrentStep            string `json:"current_step,omitempty"`
	OrgName                string `json:"org_name,omitempty"`
	OrgSlug                string `json:"org_slug,omitempty"`
	WorkspaceName          string `json:"workspace_name,omitempty"`
	WorkspaceSlug          string `json:"workspace_slug,omitempty"`
	ProjectName            string `json:"project_name,omitempty"`
	ProjectID              string `json:"project_id,omitempty"`
	ConnectorID            string `json:"connector_id,omitempty"`
	ConnectorType          string `json:"connector_type,omitempty"`
	ConnectorSkipped       *bool  `json:"connector_skipped,omitempty"`
	ScanSkipped            *bool  `json:"scan_skipped,omitempty"`
	DashboardTourDismissed *bool  `json:"dashboard_tour_dismissed,omitempty"`
}

// OnboardingStateResponse is the API-shaped state wrapper used by the wizard.
type OnboardingStateResponse struct {
	State        db.OnboardingState `json:"state"`
	RedirectPath string             `json:"redirect_path,omitempty"`
}

// StartOnboarding creates or returns the current user's onboarding progress.
func (s *Service) StartOnboarding(ctx context.Context, current sessionauth.CurrentSession) (OnboardingStateResponse, error) {
	if s == nil || s.Store == nil {
		return OnboardingStateResponse{}, errors.New("service unavailable")
	}
	userID := strings.TrimSpace(current.Session.UserID)
	if userID == "" {
		return OnboardingStateResponse{}, ErrInvalidOnboardingRequest
	}
	if state, err := s.Store.GetOnboardingState(ctx, userID); err == nil {
		return onboardingResponse(state), nil
	} else if !errors.Is(err, db.ErrNotFound) {
		return OnboardingStateResponse{}, err
	}

	now := s.onboardingNow()
	state := db.OnboardingState{
		UserID:      userID,
		CurrentStep: onboardingStepOrg,
		StartedAt:   now,
		UpdatedAt:   now,
	}
	if current.Session.CurrentOrgID != "" && current.Session.CurrentWorkspaceID != "" {
		state.OrgID = current.Session.CurrentOrgID
		state.WorkspaceID = current.Session.CurrentWorkspaceID
		state.ProjectID = current.Session.CurrentProjectID
		state.CurrentStep = onboardingStepForExistingWorkspace(ctx, s.Store, state.OrgID, state.WorkspaceID, &state.ProjectID)
	} else if member, err := s.Store.FindFirstWorkspaceMemberByUserUUID(ctx, userID); err == nil {
		state.OrgID = member.TenantID
		state.WorkspaceID = member.WorkspaceID
		scopedCtx := db.WithScope(ctx, db.Scope{TenantID: member.TenantID, WorkspaceID: member.WorkspaceID})
		if projects, listErr := s.Store.ListProjects(scopedCtx, member.WorkspaceID, false, 1); listErr == nil && len(projects) > 0 {
			state.ProjectID = projects[0].ProjectID
		}
		state.CurrentStep = onboardingStepForExistingWorkspace(ctx, s.Store, state.OrgID, state.WorkspaceID, &state.ProjectID)
		_, _ = s.Store.UpdateSessionContext(ctx, userID, current.IDHash, member.TenantID, member.WorkspaceID, state.ProjectID, now)
	} else if !errors.Is(err, db.ErrNotFound) {
		return OnboardingStateResponse{}, err
	}

	saved, err := s.Store.UpsertOnboardingState(ctx, state)
	if err != nil {
		return OnboardingStateResponse{}, err
	}
	return onboardingResponse(saved), nil
}

// GetOnboardingState returns current progress without mutating it.
func (s *Service) GetOnboardingState(ctx context.Context, current sessionauth.CurrentSession) (OnboardingStateResponse, error) {
	if s == nil || s.Store == nil {
		return OnboardingStateResponse{}, errors.New("service unavailable")
	}
	state, err := s.Store.GetOnboardingState(ctx, current.Session.UserID)
	if err != nil {
		return OnboardingStateResponse{}, err
	}
	return onboardingResponse(state), nil
}

// UpdateOnboardingState applies one wizard step and persists it server-side.
func (s *Service) UpdateOnboardingState(ctx context.Context, current sessionauth.CurrentSession, request OnboardingStateUpdateRequest) (OnboardingStateResponse, error) {
	if s == nil || s.Store == nil {
		return OnboardingStateResponse{}, errors.New("service unavailable")
	}
	started, err := s.StartOnboarding(ctx, current)
	if err != nil {
		return OnboardingStateResponse{}, err
	}
	state := started.State
	now := s.onboardingNow()
	state.UpdatedAt = now

	if request.DashboardTourDismissed != nil && *request.DashboardTourDismissed {
		state.DashboardTourDismissedAt = &now
	}
	if request.ConnectorSkipped != nil {
		state.ConnectorSkipped = *request.ConnectorSkipped
	}
	if request.ScanSkipped != nil {
		state.ScanSkipped = *request.ScanSkipped
	}
	if connectorType := strings.ToLower(strings.TrimSpace(request.ConnectorType)); connectorType != "" {
		if !validOnboardingConnectorType(connectorType) {
			return OnboardingStateResponse{}, ErrInvalidOnboardingRequest
		}
		state.ConnectorType = connectorType
	}
	if connectorID := strings.TrimSpace(request.ConnectorID); connectorID != "" {
		state.ConnectorID = connectorID
	}

	step := strings.ToLower(strings.TrimSpace(request.CurrentStep))
	if step == "" {
		saved, err := s.Store.UpsertOnboardingState(ctx, state)
		if err != nil {
			return OnboardingStateResponse{}, err
		}
		return onboardingResponse(saved), nil
	}

	switch step {
	case onboardingStepOrg:
		var applyErr error
		state, applyErr = s.applyOnboardingOrganization(ctx, current, state, request, now)
		if applyErr != nil {
			return OnboardingStateResponse{}, applyErr
		}
	case onboardingStepWorkspace:
		var applyErr error
		state, applyErr = s.applyOnboardingWorkspace(ctx, current, state, request, now)
		if applyErr != nil {
			return OnboardingStateResponse{}, applyErr
		}
	case onboardingStepConnect:
		if state.ConnectorSkipped {
			state.ConnectorType = ""
			state.ConnectorID = ""
		}
		state.CurrentStep = onboardingStepScan
	case onboardingStepScan:
		if state.ConnectorSkipped {
			state.ScanSkipped = true
		}
		state.CurrentStep = onboardingStepInvite
	case onboardingStepInvite:
		state.CurrentStep = onboardingStepInvite
	default:
		return OnboardingStateResponse{}, ErrInvalidOnboardingRequest
	}

	saved, err := s.Store.UpsertOnboardingState(ctx, state)
	if err != nil {
		return OnboardingStateResponse{}, err
	}
	return onboardingResponse(saved), nil
}

// CompleteOnboarding marks the wizard complete and returns the dashboard target.
func (s *Service) CompleteOnboarding(ctx context.Context, current sessionauth.CurrentSession) (OnboardingStateResponse, error) {
	if s == nil || s.Store == nil {
		return OnboardingStateResponse{}, errors.New("service unavailable")
	}
	state, err := s.Store.GetOnboardingState(ctx, current.Session.UserID)
	if err != nil {
		return OnboardingStateResponse{}, err
	}
	if strings.TrimSpace(state.OrgID) == "" || strings.TrimSpace(state.WorkspaceID) == "" {
		return OnboardingStateResponse{}, ErrInvalidOnboardingRequest
	}
	now := s.onboardingNow()
	state.CurrentStep = onboardingStepComplete
	state.CompletedAt = &now
	state.UpdatedAt = now
	saved, err := s.Store.UpsertOnboardingState(ctx, state)
	if err != nil {
		return OnboardingStateResponse{}, err
	}
	return onboardingResponse(saved), nil
}

func (s *Service) applyOnboardingOrganization(ctx context.Context, current sessionauth.CurrentSession, state db.OnboardingState, request OnboardingStateUpdateRequest, now time.Time) (db.OnboardingState, error) {
	orgName := strings.TrimSpace(request.OrgName)
	if orgName == "" {
		return db.OnboardingState{}, ErrInvalidOnboardingRequest
	}
	creatingOrg := strings.TrimSpace(state.OrgID) == ""
	if state.OrgID == "" {
		state.OrgID = onboardingScopedID(orgName, "org")
	}
	if !creatingOrg {
		workspaceID := strings.TrimSpace(state.WorkspaceID)
		if workspaceID == "" {
			workspaceID = strings.TrimSpace(current.Session.CurrentWorkspaceID)
		}
		if err := s.requireOnboardingOrganizationAdmin(ctx, current.Session.UserID, state.OrgID, workspaceID); err != nil {
			return db.OnboardingState{}, err
		}
	}
	orgSlug := onboardingSlug(request.OrgSlug, "")
	if orgSlug == "" {
		orgSlug = onboardingGeneratedOrganizationSlug(orgName, state.OrgID)
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: state.OrgID, WorkspaceID: db.DefaultWorkspaceID})
	if err := s.Store.UpsertOrganization(scopedCtx, db.TenancyOrganization{
		TenantID:    state.OrgID,
		DisplayName: orgName,
		Slug:        orgSlug,
		CreatedAt:   state.StartedAt,
		UpdatedAt:   now,
	}); err != nil {
		return db.OnboardingState{}, err
	}
	state.CurrentStep = onboardingStepWorkspace
	return state, nil
}

func (s *Service) applyOnboardingWorkspace(ctx context.Context, current sessionauth.CurrentSession, state db.OnboardingState, request OnboardingStateUpdateRequest, now time.Time) (db.OnboardingState, error) {
	if state.OrgID == "" {
		return db.OnboardingState{}, ErrInvalidOnboardingRequest
	}
	reusingWorkspace := strings.TrimSpace(state.WorkspaceID) != ""
	workspaceName := strings.TrimSpace(request.WorkspaceName)
	if workspaceName == "" {
		workspaceName = "Production"
	}
	workspaceID := state.WorkspaceID
	if workspaceID == "" {
		workspaceID = onboardingSlug(request.WorkspaceSlug, "")
	}
	if workspaceID == "" {
		workspaceID = onboardingSlug(workspaceName, "production")
	}
	projectName := strings.TrimSpace(request.ProjectName)
	if projectName == "" {
		projectName = workspaceName
	}
	projectID := state.ProjectID
	if projectID == "" {
		projectID = onboardingSlug(request.ProjectID, "")
	}
	if projectID == "" {
		projectID = onboardingSlug(projectName, "production")
	}

	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: state.OrgID, WorkspaceID: workspaceID})
	if reusingWorkspace {
		if err := s.requireOnboardingWorkspaceAdmin(scopedCtx, current.Session.UserID, workspaceID); err != nil {
			return db.OnboardingState{}, err
		}
	}
	if err := s.Store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{
		TenantID:    state.OrgID,
		WorkspaceID: workspaceID,
		DisplayName: workspaceName,
		Slug:        onboardingSlug(request.WorkspaceSlug, workspaceID),
		CreatedAt:   state.StartedAt,
		UpdatedAt:   now,
	}); err != nil {
		return db.OnboardingState{}, err
	}
	if err := s.Store.UpsertProject(scopedCtx, db.TenancyProject{
		TenantID:    state.OrgID,
		WorkspaceID: workspaceID,
		ProjectID:   projectID,
		Name:        projectName,
		Slug:        onboardingSlug(request.ProjectID, projectID),
		Description: "Default project created during onboarding.",
		CreatedAt:   state.StartedAt,
		UpdatedAt:   now,
	}); err != nil {
		return db.OnboardingState{}, err
	}
	if !reusingWorkspace {
		user, err := s.Store.GetUser(ctx, current.Session.UserID)
		if err != nil {
			return db.OnboardingState{}, err
		}
		if err := s.Store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
			TenantID:    state.OrgID,
			WorkspaceID: workspaceID,
			MemberID:    onboardingMemberID(current.Session.UserID),
			UserID:      current.Session.UserID,
			UserUUID:    current.Session.UserID,
			Email:       user.PrimaryEmail,
			Role:        "owner",
			Status:      "active",
			JoinedAt:    now,
			UpdatedAt:   now,
		}); err != nil {
			return db.OnboardingState{}, err
		}
	}
	if _, err := s.Store.UpdateSessionContext(ctx, current.Session.UserID, current.IDHash, state.OrgID, workspaceID, projectID, now); err != nil {
		return db.OnboardingState{}, err
	}

	state.WorkspaceID = workspaceID
	state.ProjectID = projectID
	state.CurrentStep = onboardingStepConnect
	return state, nil
}

func (s *Service) requireOnboardingWorkspaceAdmin(ctx context.Context, userID string, workspaceID string) error {
	member, err := s.Store.GetWorkspaceMemberByUserUUID(ctx, workspaceID, strings.TrimSpace(userID))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrOnboardingWorkspaceAccessDenied
		}
		return err
	}
	if member.Status != "active" {
		return ErrOnboardingWorkspaceAccessDenied
	}
	switch member.Role {
	case "owner", "admin":
		return nil
	default:
		return ErrOnboardingWorkspaceAccessDenied
	}
}

func (s *Service) requireOnboardingOrganizationAdmin(ctx context.Context, userID string, orgID string, workspaceID string) error {
	workspaceID = strings.TrimSpace(workspaceID)
	if strings.TrimSpace(orgID) == "" || workspaceID == "" {
		return ErrOnboardingWorkspaceAccessDenied
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: orgID, WorkspaceID: workspaceID})
	return s.requireOnboardingWorkspaceAdmin(scopedCtx, userID, workspaceID)
}

func (s *Service) onboardingNow() time.Time {
	if s != nil && s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func onboardingResponse(state db.OnboardingState) OnboardingStateResponse {
	return OnboardingStateResponse{
		State:        state,
		RedirectPath: onboardingRedirectPath(state),
	}
}

func onboardingRedirectPath(state db.OnboardingState) string {
	if state.CurrentStep == onboardingStepComplete {
		if state.OrgID != "" && state.WorkspaceID != "" {
			return "/app/" + url.PathEscape(state.OrgID) + "/" + url.PathEscape(state.WorkspaceID)
		}
		return "/app"
	}
	if _, ok := map[string]struct{}{
		onboardingStepOrg:       {},
		onboardingStepWorkspace: {},
		onboardingStepConnect:   {},
		onboardingStepScan:      {},
		onboardingStepInvite:    {},
	}[state.CurrentStep]; ok {
		return "/onboarding/" + state.CurrentStep
	}
	return "/onboarding/org"
}

func onboardingStepForExistingWorkspace(ctx context.Context, store db.Store, orgID string, workspaceID string, projectID *string) string {
	if strings.TrimSpace(orgID) == "" || strings.TrimSpace(workspaceID) == "" {
		return onboardingStepOrg
	}
	if projectID != nil && strings.TrimSpace(*projectID) != "" {
		*projectID = strings.TrimSpace(*projectID)
		return onboardingStepConnect
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: orgID, WorkspaceID: workspaceID})
	if projects, err := store.ListProjects(scopedCtx, workspaceID, false, 1); err == nil && len(projects) > 0 {
		if projectID != nil {
			*projectID = projects[0].ProjectID
		}
		return onboardingStepConnect
	}
	return onboardingStepWorkspace
}

func onboardingSlug(value string, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = onboardingSlugUnsafe.ReplaceAllString(normalized, "-")
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		normalized = fallback
	}
	if len(normalized) > 64 {
		normalized = strings.Trim(normalized[:64], "-")
	}
	if normalized == "" {
		return fallback
	}
	return normalized
}

func onboardingScopedID(value string, fallback string) string {
	base := onboardingSlug(value, fallback)
	token := strings.ReplaceAll(uuid.NewString(), "-", "")
	if len(token) > 8 {
		token = token[:8]
	}
	return fmt.Sprintf("%s-%s", base, token)
}

func onboardingGeneratedOrganizationSlug(value string, scopedID string) string {
	base := onboardingSlug(value, "organization")
	token := onboardingScopedIDToken(scopedID)
	if token == "" {
		return base
	}
	maxBaseLen := 64 - len(token) - 1
	if maxBaseLen < 1 {
		return token
	}
	if len(base) > maxBaseLen {
		base = strings.Trim(base[:maxBaseLen], "-")
	}
	if base == "" {
		base = "organization"
	}
	return base + "-" + token
}

func onboardingScopedIDToken(scopedID string) string {
	normalized := strings.ToLower(strings.TrimSpace(scopedID))
	normalized = onboardingSlugUnsafe.ReplaceAllString(normalized, "-")
	normalized = strings.Trim(normalized, "-")
	index := strings.LastIndex(normalized, "-")
	if index == -1 || index == len(normalized)-1 {
		return ""
	}
	token := normalized[index+1:]
	if len(token) != 8 {
		return ""
	}
	return token
}

func onboardingMemberID(userID string) string {
	token := strings.ReplaceAll(strings.TrimSpace(userID), "-", "")
	if len(token) > 12 {
		token = token[:12]
	}
	if token == "" {
		token = strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	}
	return "member-" + token
}

func validOnboardingConnectorType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "aws", "github", "kubernetes":
		return true
	default:
		return false
	}
}
