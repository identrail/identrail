package api

import (
	"bytes"
	"context"
	"errors"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
)

// CurrentUserContext is the response model for GET /v1/me.
type CurrentUserContext struct {
	User         db.User                 `json:"user"`
	OrgID        string                  `json:"org_id,omitempty"`
	WorkspaceID  string                  `json:"workspace_id,omitempty"`
	ProjectID    string                  `json:"project_id,omitempty"`
	Role         string                  `json:"role,omitempty"`
	Organization *db.TenancyOrganization `json:"organization,omitempty"`
	Workspace    *db.TenancyWorkspace    `json:"workspace,omitempty"`
	Project      *db.TenancyProject      `json:"project,omitempty"`
}

// SessionListItem is the safe account/security representation of a session.
type SessionListItem struct {
	ID            string    `json:"id"`
	IP            string    `json:"ip,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	AuthMethod    string    `json:"auth_method"`
	CreatedAt     time.Time `json:"created_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	IdleExpiresAt time.Time `json:"idle_expires_at"`
	Current       bool      `json:"current"`
}

// GetCurrentUserContext resolves the current session into user and tenancy context.
func (s *Service) GetCurrentUserContext(ctx context.Context, current sessionauth.CurrentSession) (CurrentUserContext, error) {
	if s == nil || s.Store == nil {
		return CurrentUserContext{}, errors.New("service unavailable")
	}
	user := current.Session.User
	if user == nil {
		loaded, err := s.Store.GetUser(ctx, current.Session.UserID)
		if err != nil {
			return CurrentUserContext{}, err
		}
		user = &loaded
	}
	result := CurrentUserContext{
		User:        *user,
		OrgID:       current.Session.CurrentOrgID,
		WorkspaceID: current.Session.CurrentWorkspaceID,
		ProjectID:   current.Session.CurrentProjectID,
	}
	if result.OrgID == "" || result.WorkspaceID == "" {
		return result, nil
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: result.OrgID, WorkspaceID: result.WorkspaceID})
	if member, err := s.Store.GetWorkspaceMemberByUserUUID(scopedCtx, result.WorkspaceID, result.User.ID); err == nil {
		if member.Status == "active" {
			result.Role = member.Role
		}
	} else if !errors.Is(err, db.ErrNotFound) {
		return CurrentUserContext{}, err
	}
	if organization, err := s.Store.GetOrganization(scopedCtx); err == nil {
		result.Organization = &organization
	} else if !errors.Is(err, db.ErrNotFound) {
		return CurrentUserContext{}, err
	}
	if workspace, err := s.Store.GetWorkspace(scopedCtx, result.WorkspaceID); err == nil {
		result.Workspace = &workspace
	} else if !errors.Is(err, db.ErrNotFound) {
		return CurrentUserContext{}, err
	}
	if result.ProjectID != "" {
		if project, err := s.Store.GetProject(scopedCtx, result.WorkspaceID, result.ProjectID); err == nil {
			result.Project = &project
		} else if !errors.Is(err, db.ErrNotFound) {
			return CurrentUserContext{}, err
		}
	}
	return result, nil
}

// ListCurrentUserSessions returns active sessions scoped to the current user.
func (s *Service) ListCurrentUserSessions(ctx context.Context, current sessionauth.CurrentSession) ([]SessionListItem, error) {
	if s == nil || s.Store == nil {
		return nil, errors.New("service unavailable")
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	sessions, err := s.Store.ListUserSessions(ctx, current.Session.UserID, now, sessionauth.DefaultSessionListLimit)
	if err != nil {
		return nil, err
	}
	items := make([]SessionListItem, 0, len(sessions))
	for _, session := range sessions {
		items = append(items, SessionListItem{
			ID:            sessionauth.EncodePublicSessionID(session.ID),
			IP:            session.IP,
			UserAgent:     session.UserAgent,
			AuthMethod:    session.AuthMethod,
			CreatedAt:     session.CreatedAt,
			LastSeenAt:    session.LastSeenAt,
			IdleExpiresAt: session.IdleExpiresAt,
			Current:       bytes.Equal(session.ID, current.IDHash),
		})
	}
	return items, nil
}
