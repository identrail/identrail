package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
)

var ErrAuthIdentityConflict = errors.New("auth identity conflicts with existing user")

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

type WorkOSLoginResult struct {
	User             db.User
	Identity         db.UserIdentity
	NewUser          bool
	CurrentOrgID     string
	CurrentWorkspace string
	RedirectPath     string
}

// UpsertWorkOSUser safely maps a WorkOS AuthKit profile into Identrail's local account model.
func (s *Service) UpsertWorkOSUser(ctx context.Context, profile sessionauth.WorkOSProfile) (WorkOSLoginResult, error) {
	if s == nil || s.Store == nil {
		return WorkOSLoginResult{}, errors.New("service unavailable")
	}
	subject := strings.TrimSpace(profile.ID)
	email := strings.ToLower(strings.TrimSpace(profile.Email))
	if subject == "" || email == "" {
		return WorkOSLoginResult{}, errors.New("workos profile missing subject or email")
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	displayName := strings.TrimSpace(strings.Join([]string{profile.FirstName, profile.LastName}, " "))
	if displayName == "" {
		displayName = email
	}
	rawClaims := profile.RawClaims
	if len(rawClaims) == 0 || !json.Valid(rawClaims) {
		rawClaims, _ = json.Marshal(profile)
	}

	identity, err := s.Store.GetUserIdentity(ctx, sessionauth.WorkOSProvider, subject)
	if err == nil {
		user, getErr := s.Store.GetUser(ctx, identity.UserID)
		if getErr != nil {
			return WorkOSLoginResult{}, getErr
		}
		if existing, emailErr := s.Store.GetUserByPrimaryEmail(ctx, email); emailErr == nil && existing.ID != user.ID {
			auditAuthAction(ctx, "auth.identity.conflict", existing.ID, "denied")
			return WorkOSLoginResult{}, ErrAuthIdentityConflict
		} else if emailErr != nil && !errors.Is(emailErr, db.ErrNotFound) {
			return WorkOSLoginResult{}, emailErr
		}
		user.PrimaryEmail = email
		user.DisplayName = displayName
		user.AvatarURL = strings.TrimSpace(profile.ProfilePictureURL)
		user.Status = "active"
		user.UpdatedAt = now
		savedUser, saveErr := s.Store.UpsertUser(ctx, user)
		if saveErr != nil {
			return WorkOSLoginResult{}, saveErr
		}
		identity.Email = email
		identity.EmailVerified = profile.EmailVerified
		identity.RawClaims = rawClaims
		identity.LastAuthenticatedAt = now
		savedIdentity, saveIdentityErr := s.Store.UpsertUserIdentity(ctx, identity)
		if saveIdentityErr != nil {
			return WorkOSLoginResult{}, saveIdentityErr
		}
		return s.decorateWorkOSLoginResult(ctx, WorkOSLoginResult{User: savedUser, Identity: savedIdentity}, profile.OrganizationID)
	}
	if !errors.Is(err, db.ErrNotFound) {
		return WorkOSLoginResult{}, err
	}
	if existing, emailErr := s.Store.GetUserByPrimaryEmail(ctx, email); emailErr == nil {
		auditAuthAction(ctx, "auth.identity.conflict", existing.ID, "denied")
		return WorkOSLoginResult{}, ErrAuthIdentityConflict
	} else if emailErr != nil && !errors.Is(emailErr, db.ErrNotFound) {
		return WorkOSLoginResult{}, emailErr
	}

	user, err := s.Store.UpsertUser(ctx, db.User{
		PrimaryEmail: email,
		DisplayName:  displayName,
		AvatarURL:    strings.TrimSpace(profile.ProfilePictureURL),
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			auditAuthAction(ctx, "auth.identity.conflict", "", "denied")
			return WorkOSLoginResult{}, ErrAuthIdentityConflict
		}
		return WorkOSLoginResult{}, err
	}
	identity, err = s.Store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             subject,
		Email:               email,
		EmailVerified:       profile.EmailVerified,
		RawClaims:           rawClaims,
		LastAuthenticatedAt: now,
		CreatedAt:           now,
	})
	if err != nil {
		return WorkOSLoginResult{}, err
	}
	return s.decorateWorkOSLoginResult(ctx, WorkOSLoginResult{User: user, Identity: identity, NewUser: true}, profile.OrganizationID)
}

func (s *Service) DeactivateWorkOSUser(ctx context.Context, subject string) (int, error) {
	if s == nil || s.Store == nil {
		return 0, errors.New("service unavailable")
	}
	identity, err := s.Store.GetUserIdentity(ctx, sessionauth.WorkOSProvider, subject)
	if err != nil {
		return 0, err
	}
	user, err := s.Store.GetUser(ctx, identity.UserID)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	user.Status = "deactivated"
	user.UpdatedAt = now
	user.DeletedAt = nil
	if _, err := s.Store.UpsertUser(ctx, user); err != nil {
		return 0, err
	}
	revoked, err := s.Store.RevokeAllUserSessions(ctx, user.ID, now)
	if err != nil {
		return 0, err
	}
	auditAuthAction(ctx, "auth.user.deactivate", user.ID, "success")
	return revoked, nil
}

func (s *Service) UpdateWorkOSUserEmail(ctx context.Context, subject string, email string) error {
	if s == nil || s.Store == nil {
		return errors.New("service unavailable")
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if normalizedEmail == "" {
		return errors.New("email is required")
	}
	identity, err := s.Store.GetUserIdentity(ctx, sessionauth.WorkOSProvider, subject)
	if err != nil {
		return err
	}
	user, err := s.Store.GetUser(ctx, identity.UserID)
	if err != nil {
		return err
	}
	if existing, emailErr := s.Store.GetUserByPrimaryEmail(ctx, normalizedEmail); emailErr == nil && existing.ID != user.ID {
		auditAuthAction(ctx, "auth.identity.conflict", existing.ID, "denied")
		return ErrAuthIdentityConflict
	} else if emailErr != nil && !errors.Is(emailErr, db.ErrNotFound) {
		return emailErr
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	user.PrimaryEmail = normalizedEmail
	user.UpdatedAt = now
	if _, err := s.Store.UpsertUser(ctx, user); err != nil {
		return err
	}
	identity.Email = normalizedEmail
	identity.LastAuthenticatedAt = now
	if _, err := s.Store.UpsertUserIdentity(ctx, identity); err != nil {
		return err
	}
	auditAuthAction(ctx, "auth.email.update", user.ID, "success")
	return nil
}

func (s *Service) decorateWorkOSLoginResult(ctx context.Context, result WorkOSLoginResult, selectedOrgID string) (WorkOSLoginResult, error) {
	selectedOrgID = strings.TrimSpace(selectedOrgID)
	var (
		member db.TenancyWorkspaceMember
		err    error
	)
	if selectedOrgID != "" {
		member, err = s.Store.FindFirstWorkspaceMemberByUserUUIDAndTenantID(ctx, result.User.ID, selectedOrgID)
	} else {
		member, err = s.Store.FindFirstWorkspaceMemberByUserUUID(ctx, result.User.ID)
	}
	if err == nil {
		result.CurrentOrgID = member.TenantID
		result.CurrentWorkspace = member.WorkspaceID
		result.RedirectPath = "/app/" + member.TenantID + "/" + member.WorkspaceID
		return result, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return WorkOSLoginResult{}, err
	}
	result.RedirectPath = "/onboarding/org"
	return result, nil
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

func auditAuthAction(ctx context.Context, action string, resourceID string, outcome string) {
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       action,
		ResourceType: "auth",
		ResourceID:   resourceID,
		Outcome:      outcome,
	})
}
