package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
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

type ManualLoginInput struct {
	TenantID    string
	WorkspaceID string
	ProjectID   string
	Email       string
	DisplayName string
}

type ManualLoginResult struct {
	User               db.User
	CurrentOrgID       string
	CurrentWorkspaceID string
	CurrentProjectID   string
	RedirectPath       string
}

var ErrAuthInvalidManualLogin = errors.New("manual login requires tenant and workspace")

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

// SAMLAssertedProfile is the subset of a SAML assertion Identrail consumes to
// resolve or provision a user. The connection id is captured so the persisted
// identity is scoped to the originating IdP — two tenants federating with the
// same NameID cannot collide because the provider value is connection-specific.
type SAMLAssertedProfile struct {
	ConnectionID string
	OrgID        string
	NameID       string
	Email        string
	DisplayName  string
	Groups       []string
	RawAssertion []byte
}

// SAMLLoginResult mirrors WorkOSLoginResult so the ACS handler can reuse the
// same session-issuance plumbing as the WorkOS callback path.
type SAMLLoginResult struct {
	User             db.User
	Identity         db.UserIdentity
	NewUser          bool
	CurrentOrgID     string
	CurrentWorkspace string
	RedirectPath     string
}

// ErrSAMLUnprovisionedUser is returned when a SAML assertion arrives for a
// user that has no matching identity and the connection has not opted into
// JIT provisioning. The ACS handler maps it to a 403 so the admin knows to
// either pre-provision via SCIM or enable JIT on the connection.
var ErrSAMLUnprovisionedUser = errors.New("saml asserted user is not provisioned and connection has JIT disabled")

// UpsertSAMLAssertedUser resolves or provisions an Identrail user from a SAML
// assertion. Lookup order:
//
//  1. user_identities row with provider = "saml:<connection_id>" and the
//     asserted NameID — the canonical mapping once a user has logged in once.
//  2. user_identities row with provider = "scim:<connection_id>" and the
//     asserted NameID, then the email — covers users pre-provisioned via SCIM
//     before their first SAML login.
//  3. users row with primary_email == asserted email — falls back to email
//     when JIT-enabled connections need to attach a new IdP identity to an
//     existing manually-created Identrail user.
//
// If no match is found and the connection has JIT disabled, returns
// ErrSAMLUnprovisionedUser without creating any row.
func (s *Service) UpsertSAMLAssertedUser(ctx context.Context, conn db.IdentityConnection, profile SAMLAssertedProfile) (SAMLLoginResult, error) {
	if s == nil || s.Store == nil {
		return SAMLLoginResult{}, errors.New("service unavailable")
	}
	email := strings.ToLower(strings.TrimSpace(profile.Email))
	if email == "" {
		return SAMLLoginResult{}, errors.New("saml profile missing email")
	}
	nameID := strings.TrimSpace(profile.NameID)
	if nameID == "" {
		// samlProfileFromAssertion already accepts assertions whose NameID
		// is empty by treating the email attribute as the NameID; mirror
		// that here so a NameID-less but email-bearing profile resolves
		// instead of failing the upsert with a hard error.
		nameID = email
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	displayName := strings.TrimSpace(profile.DisplayName)
	if displayName == "" {
		displayName = email
	}
	rawClaims := profile.RawAssertion
	if len(rawClaims) == 0 || !json.Valid(rawClaims) {
		summary := map[string]any{
			"nameid":        nameID,
			"email":         email,
			"display_name":  displayName,
			"groups":        profile.Groups,
			"connection_id": conn.ID,
		}
		rawClaims, _ = json.Marshal(summary)
	}

	samlProvider := "saml:" + strings.TrimSpace(conn.ID)
	scimProvider := "scim:" + strings.TrimSpace(conn.ID)

	// Path 1: existing SAML identity from a prior login on this connection.
	if identity, err := s.Store.GetUserIdentity(ctx, samlProvider, nameID); err == nil {
		return s.refreshSAMLIdentity(ctx, conn, identity, email, displayName, rawClaims, now)
	} else if !errors.Is(err, db.ErrNotFound) {
		return SAMLLoginResult{}, err
	}

	// Path 2: pre-provisioned via SCIM (subject = NameID/email, then primary email).
	for _, scimSubject := range []string{nameID, email} {
		if scimSubject == "" {
			continue
		}
		if identity, err := s.Store.GetUserIdentity(ctx, scimProvider, scimSubject); err == nil {
			return s.attachSAMLIdentityToExistingUser(ctx, conn, identity.UserID, nameID, email, displayName, rawClaims, now)
		} else if !errors.Is(err, db.ErrNotFound) {
			return SAMLLoginResult{}, err
		}
	}
	if email != "" {
		if existing, err := s.Store.GetUserByPrimaryEmail(ctx, email); err == nil {
			if _, err := s.Store.GetUserIdentityByProviderUserID(ctx, scimProvider, existing.ID); err == nil {
				return s.attachSAMLIdentityToExistingUser(ctx, conn, existing.ID, nameID, email, displayName, rawClaims, now)
			} else if !errors.Is(err, db.ErrNotFound) {
				return SAMLLoginResult{}, err
			}
		} else if !errors.Is(err, db.ErrNotFound) {
			return SAMLLoginResult{}, err
		}
	}

	// Path 3: existing user by email (JIT attaches a new SAML identity).
	//
	// Email is a globally unique credential in users.primary_email but the
	// SAML assertion is org-scoped: a stranger who happens to share an email
	// with a user from a different org must not have their SAML assertion
	// bound to that account. Require the candidate user to already be a
	// member of the connection's org before linking.
	if existing, err := s.Store.GetUserByPrimaryEmail(ctx, email); err == nil {
		if !conn.JITProvisioningEnabled {
			auditAuthAction(ctx, "auth.saml.unprovisioned", existing.ID, "denied")
			return SAMLLoginResult{}, ErrSAMLUnprovisionedUser
		}
		if _, membershipErr := s.Store.FindFirstWorkspaceMemberByUserUUIDAndTenantID(ctx, existing.ID, conn.OrgID); membershipErr != nil {
			if errors.Is(membershipErr, db.ErrNotFound) {
				// The email-matched user belongs to a different tenant.
				// Refuse to silently bind the assertion to them.
				auditAuthAction(ctx, "auth.saml.cross_tenant_email_match", existing.ID, "denied")
				return SAMLLoginResult{}, ErrSAMLUnprovisionedUser
			}
			return SAMLLoginResult{}, membershipErr
		}
		return s.attachSAMLIdentityToExistingUser(ctx, conn, existing.ID, nameID, email, displayName, rawClaims, now)
	} else if !errors.Is(err, db.ErrNotFound) {
		return SAMLLoginResult{}, err
	}

	// No prior identity, no matching user. Require JIT to create a fresh one.
	if !conn.JITProvisioningEnabled {
		auditAuthAction(ctx, "auth.saml.unprovisioned", "", "denied")
		return SAMLLoginResult{}, ErrSAMLUnprovisionedUser
	}
	user, err := s.Store.UpsertUser(ctx, db.User{
		PrimaryEmail: email,
		DisplayName:  displayName,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			auditAuthAction(ctx, "auth.identity.conflict", "", "denied")
			return SAMLLoginResult{}, ErrAuthIdentityConflict
		}
		return SAMLLoginResult{}, err
	}
	identity, err := s.Store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            samlProvider,
		Subject:             nameID,
		Email:               email,
		EmailVerified:       true,
		RawClaims:           rawClaims,
		LastAuthenticatedAt: now,
		CreatedAt:           now,
	})
	if err != nil {
		return SAMLLoginResult{}, err
	}
	return s.decorateSAMLLoginResult(ctx, SAMLLoginResult{User: user, Identity: identity, NewUser: true}, conn.OrgID)
}

func (s *Service) refreshSAMLIdentity(ctx context.Context, conn db.IdentityConnection, identity db.UserIdentity, email, displayName string, rawClaims []byte, now time.Time) (SAMLLoginResult, error) {
	user, err := s.Store.GetUser(ctx, identity.UserID)
	if err != nil {
		return SAMLLoginResult{}, err
	}
	if user.Status != "active" {
		auditAuthAction(ctx, "auth.saml.deprovisioned", user.ID, "denied")
		return SAMLLoginResult{}, ErrSAMLUnprovisionedUser
	}
	user.PrimaryEmail = email
	user.DisplayName = displayName
	user.Status = "active"
	user.UpdatedAt = now
	savedUser, err := s.Store.UpsertUser(ctx, user)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			auditAuthAction(ctx, "auth.identity.conflict", user.ID, "denied")
			return SAMLLoginResult{}, ErrAuthIdentityConflict
		}
		return SAMLLoginResult{}, err
	}
	identity.Email = email
	identity.EmailVerified = true
	identity.RawClaims = rawClaims
	identity.LastAuthenticatedAt = now
	savedIdentity, err := s.Store.UpsertUserIdentity(ctx, identity)
	if err != nil {
		return SAMLLoginResult{}, err
	}
	return s.decorateSAMLLoginResult(ctx, SAMLLoginResult{User: savedUser, Identity: savedIdentity}, conn.OrgID)
}

func (s *Service) attachSAMLIdentityToExistingUser(ctx context.Context, conn db.IdentityConnection, userID, nameID, email, displayName string, rawClaims []byte, now time.Time) (SAMLLoginResult, error) {
	user, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return SAMLLoginResult{}, err
	}
	if user.Status != "active" {
		auditAuthAction(ctx, "auth.saml.deprovisioned", user.ID, "denied")
		return SAMLLoginResult{}, ErrSAMLUnprovisionedUser
	}
	user.PrimaryEmail = email
	user.DisplayName = displayName
	user.Status = "active"
	user.UpdatedAt = now
	savedUser, err := s.Store.UpsertUser(ctx, user)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			auditAuthAction(ctx, "auth.identity.conflict", user.ID, "denied")
			return SAMLLoginResult{}, ErrAuthIdentityConflict
		}
		return SAMLLoginResult{}, err
	}
	identity, err := s.Store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              savedUser.ID,
		Provider:            "saml:" + strings.TrimSpace(conn.ID),
		Subject:             nameID,
		Email:               email,
		EmailVerified:       true,
		RawClaims:           rawClaims,
		LastAuthenticatedAt: now,
		CreatedAt:           now,
	})
	if err != nil {
		return SAMLLoginResult{}, err
	}
	return s.decorateSAMLLoginResult(ctx, SAMLLoginResult{User: savedUser, Identity: identity}, conn.OrgID)
}

// decorateSAMLLoginResult attaches the org/workspace context the session
// needs. The SAML connection is org-scoped, so we always force that org id
// regardless of the user's prior selection.
//
// The Postgres `sessions` table requires CurrentOrgID and CurrentWorkspaceID
// to either both be populated or both be empty. When a SAML-asserted user
// has no workspace membership yet — common for the JIT happy path — we
// leave both empty and redirect to onboarding so session insertion does not
// trip the constraint.
func (s *Service) decorateSAMLLoginResult(ctx context.Context, result SAMLLoginResult, orgID string) (SAMLLoginResult, error) {
	candidateOrg := strings.TrimSpace(orgID)
	member, err := s.Store.FindFirstWorkspaceMemberByUserUUIDAndTenantID(ctx, result.User.ID, candidateOrg)
	if err == nil {
		result.CurrentOrgID = member.TenantID
		result.CurrentWorkspace = member.WorkspaceID
		result.RedirectPath = "/app/" + member.TenantID + "/" + member.WorkspaceID
		return result, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return SAMLLoginResult{}, err
	}
	// No workspace membership yet — leave the session org/workspace empty
	// (both NULL, matching the table CHECK) and send the user through
	// onboarding to bind a workspace.
	result.CurrentOrgID = ""
	result.CurrentWorkspace = ""
	result.RedirectPath = "/onboarding/org"
	return result, nil
}

// UpsertManualUserSessionContext creates the local user and tenancy context used by dev-only manual mode.
func (s *Service) UpsertManualUserSessionContext(ctx context.Context, input ManualLoginInput) (ManualLoginResult, error) {
	if s == nil || s.Store == nil {
		return ManualLoginResult{}, errors.New("service unavailable")
	}
	tenantID := strings.TrimSpace(input.TenantID)
	workspaceID := strings.TrimSpace(input.WorkspaceID)
	projectID := strings.TrimSpace(input.ProjectID)
	if tenantID == "" || workspaceID == "" {
		return ManualLoginResult{}, ErrAuthInvalidManualLogin
	}
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" {
		email = "manual+" + manualAuthSlug(tenantID+"-"+workspaceID) + "@local.identrail.test"
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		displayName = "Manual developer"
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}

	user, err := s.Store.GetUserByPrimaryEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return ManualLoginResult{}, err
		}
		user = db.User{
			PrimaryEmail: email,
			DisplayName:  displayName,
			Status:       "active",
			CreatedAt:    now,
			UpdatedAt:    now,
		}
	} else {
		user.DisplayName = displayName
		user.Status = "active"
		user.UpdatedAt = now
	}
	user, err = s.Store.UpsertUser(ctx, user)
	if err != nil {
		return ManualLoginResult{}, err
	}

	identity, err := s.Store.GetUserIdentity(ctx, "manual", email)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return ManualLoginResult{}, err
		}
		identity = db.UserIdentity{
			UserID:    user.ID,
			Provider:  "manual",
			Subject:   email,
			Email:     email,
			RawClaims: json.RawMessage(`{"mode":"manual"}`),
			CreatedAt: now,
		}
	} else if identity.UserID != user.ID {
		auditAuthAction(ctx, "auth.identity.conflict", identity.UserID, "denied")
		return ManualLoginResult{}, ErrAuthIdentityConflict
	}
	identity.UserID = user.ID
	identity.Email = email
	identity.EmailVerified = true
	identity.LastAuthenticatedAt = now
	if _, err := s.Store.UpsertUserIdentity(ctx, identity); err != nil {
		return ManualLoginResult{}, err
	}

	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: tenantID, WorkspaceID: workspaceID})
	if err := s.Store.UpsertOrganization(scopedCtx, db.TenancyOrganization{
		DisplayName: "Manual " + tenantID,
		Slug:        manualAuthSlug(tenantID),
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		return ManualLoginResult{}, err
	}
	if err := s.Store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{
		WorkspaceID: workspaceID,
		DisplayName: "Manual " + workspaceID,
		Slug:        manualAuthSlug(workspaceID),
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		return ManualLoginResult{}, err
	}
	if err := s.Store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: workspaceID,
		MemberID:    "manual-" + user.ID,
		UserID:      "manual:" + email,
		UserUUID:    user.ID,
		Email:       email,
		Role:        "owner",
		Status:      "active",
		JoinedAt:    now,
		UpdatedAt:   now,
	}); err != nil {
		return ManualLoginResult{}, err
	}
	if projectID != "" {
		if err := s.Store.UpsertProject(scopedCtx, db.TenancyProject{
			WorkspaceID: workspaceID,
			ProjectID:   projectID,
			Name:        "Manual " + projectID,
			Slug:        manualAuthSlug(projectID),
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			return ManualLoginResult{}, err
		}
	}

	redirectPath := "/app/" + url.PathEscape(tenantID) + "/" + url.PathEscape(workspaceID)
	if projectID != "" {
		redirectPath += "/projects/" + url.PathEscape(projectID)
	}
	return ManualLoginResult{
		User:               user,
		CurrentOrgID:       tenantID,
		CurrentWorkspaceID: workspaceID,
		CurrentProjectID:   projectID,
		RedirectPath:       redirectPath,
	}, nil
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

func manualAuthSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		isAllowed := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAllowed {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if builder.Len() > 0 && !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(builder.String(), "-")
	if slug == "" {
		return "manual"
	}
	if len(slug) > 63 {
		slug = strings.Trim(slug[:63], "-")
	}
	if slug == "" {
		return "manual"
	}
	return slug
}
