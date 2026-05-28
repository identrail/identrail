package api

import (
	"context"
	"errors"
	"testing"
	"time"

	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
)

func TestUpsertWorkOSUserExistingIdentityUsesMembershipContext(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{PrimaryEmail: "old@example.com", DisplayName: "Old Name"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_existing",
		Email:               "old@example.com",
		LastAuthenticatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	scope := db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	scopedCtx := db.WithScope(ctx, scope)
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "subject-a",
		UserUUID:    user.ID,
		Email:       "new@example.com",
		Role:        "admin",
		Status:      "active",
		JoinedAt:    now,
	}); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	result, err := svc.UpsertWorkOSUser(ctx, sessionauth.WorkOSProfile{
		ID:                "user_workos_existing",
		Email:             "new@example.com",
		FirstName:         "New",
		LastName:          "Name",
		EmailVerified:     true,
		ProfilePictureURL: "https://cdn.example/avatar.png",
	})
	if err != nil {
		t.Fatalf("upsert workos user: %v", err)
	}
	if result.NewUser {
		t.Fatal("expected existing identity to update existing user")
	}
	if result.CurrentOrgID != "tenant-a" || result.CurrentWorkspace != "workspace-a" || result.RedirectPath != "/app/tenant-a/workspace-a" {
		t.Fatalf("unexpected membership context: %+v", result)
	}
	if result.User.PrimaryEmail != "new@example.com" || result.User.DisplayName != "New Name" || result.User.AvatarURL == "" {
		t.Fatalf("expected profile update, got %+v", result.User)
	}
}

func TestUpsertWorkOSUserRespectsSelectedOrganization(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{PrimaryEmail: "owner@example.com", DisplayName: "Owner"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_multi_org",
		Email:               "owner@example.com",
		LastAuthenticatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	tenantA := db.WithScope(ctx, db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(tenantA, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed tenant a: %v", err)
	}
	if err := store.UpsertWorkspace(tenantA, db.TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("seed workspace a: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantA, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "subject-a",
		UserUUID:    user.ID,
		Email:       "owner@example.com",
		Role:        "admin",
		Status:      "active",
		JoinedAt:    now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed member a: %v", err)
	}
	tenantB := db.WithScope(ctx, db.Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	if err := store.UpsertOrganization(tenantB, db.TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("seed tenant b: %v", err)
	}
	if err := store.UpsertWorkspace(tenantB, db.TenancyWorkspace{WorkspaceID: "workspace-b", DisplayName: "Workspace B", Slug: "workspace-b"}); err != nil {
		t.Fatalf("seed workspace b: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantB, db.TenancyWorkspaceMember{
		WorkspaceID: "workspace-b",
		MemberID:    "member-b",
		UserID:      "subject-b",
		UserUUID:    user.ID,
		Email:       "owner@example.com",
		Role:        "viewer",
		Status:      "active",
		JoinedAt:    now,
	}); err != nil {
		t.Fatalf("seed member b: %v", err)
	}

	result, err := svc.UpsertWorkOSUser(ctx, sessionauth.WorkOSProfile{
		ID:             "user_workos_multi_org",
		Email:          "owner@example.com",
		OrganizationID: "tenant-a",
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("upsert workos user: %v", err)
	}
	if result.CurrentOrgID != "tenant-a" || result.CurrentWorkspace != "workspace-a" || result.RedirectPath != "/app/tenant-a/workspace-a" {
		t.Fatalf("expected selected organization membership, got %+v", result)
	}
}

func TestUpsertWorkOSUserLoginIntentRejectsUnknownIdentity(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")

	_, err := svc.UpsertWorkOSUserForIntent(context.Background(), sessionauth.WorkOSProfile{
		ID:            "user_workos_unknown",
		Email:         "unknown@example.com",
		EmailVerified: true,
	}, "login")
	if !errors.Is(err, ErrAuthAccountNotFound) {
		t.Fatalf("expected account not found, got %v", err)
	}
	if _, err := store.GetUserByPrimaryEmail(context.Background(), "unknown@example.com"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("login intent must not create a user, got %v", err)
	}
}

func TestUpsertWorkOSUserLoginIntentPromptsSignupForDeactivatedEmail(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "revoked@example.com",
		DisplayName:  "Old Name",
		Status:       "deactivated",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	_, err = svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:            "user_workos_new_subject",
		Email:         "revoked@example.com",
		EmailVerified: true,
	}, "login")
	if !errors.Is(err, ErrAuthReactivationRequired) {
		t.Fatalf("expected reactivation required, got %v", err)
	}
	unchanged, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("load retained user: %v", err)
	}
	if unchanged.Status != "deactivated" {
		t.Fatalf("login prompt must not reactivate retained user, got %+v", unchanged)
	}
	if _, err := store.GetUserIdentity(ctx, sessionauth.WorkOSProvider, "user_workos_new_subject"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("login prompt must not create identity, got %v", err)
	}
}

func TestUpsertWorkOSUserSignupIntentReactivatesDeactivatedEmail(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-time.Hour)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "revoked@example.com",
		DisplayName:  "Old Name",
		Status:       "deactivated",
		DeletedAt:    &deletedAt,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	result, err := svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:                "user_workos_reactivated",
		Email:             "Revoked@Example.COM",
		FirstName:         "Fresh",
		LastName:          "Owner",
		EmailVerified:     true,
		ProfilePictureURL: "https://cdn.example/new.png",
	}, "signup")
	if err != nil {
		t.Fatalf("signup should reactivate deactivated user: %v", err)
	}
	if result.User.ID != user.ID {
		t.Fatalf("expected existing user to be reused, got %s want %s", result.User.ID, user.ID)
	}
	if result.User.Status != "active" || result.User.DeletedAt != nil {
		t.Fatalf("expected active restored user, got %+v", result.User)
	}
	if result.User.PrimaryEmail != "revoked@example.com" || result.User.DisplayName != "Fresh Owner" || result.User.AvatarURL == "" {
		t.Fatalf("expected profile refresh, got %+v", result.User)
	}
	identity, err := store.GetUserIdentity(ctx, sessionauth.WorkOSProvider, "user_workos_reactivated")
	if err != nil {
		t.Fatalf("expected reactivated identity: %v", err)
	}
	if identity.UserID != user.ID {
		t.Fatalf("expected identity on reactivated user, got %+v", identity)
	}
}

func TestUpsertWorkOSUserSignupIntentRequiresVerifiedEmailForReactivation(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-time.Hour)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "revoked@example.com",
		DisplayName:  "Old Name",
		Status:       "deactivated",
		DeletedAt:    &deletedAt,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	_, err = svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:            "user_workos_unverified_reactivation",
		Email:         "revoked@example.com",
		EmailVerified: false,
	}, "signup")
	if !errors.Is(err, ErrAuthIdentityConflict) {
		t.Fatalf("expected identity conflict for unverified reactivation email, got %v", err)
	}
	unchanged, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("load retained user: %v", err)
	}
	if unchanged.Status != "deactivated" || unchanged.DeletedAt == nil {
		t.Fatalf("unverified email must not reactivate retained user, got %+v", unchanged)
	}
	if _, err := store.GetUserIdentity(ctx, sessionauth.WorkOSProvider, "user_workos_unverified_reactivation"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("unverified email must not create identity, got %v", err)
	}
}

func TestUpsertWorkOSUserSignupIntentRejectsActiveEmailConflict(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	if _, err := store.UpsertUser(context.Background(), db.User{PrimaryEmail: "taken@example.com"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	_, err := svc.UpsertWorkOSUserForIntent(context.Background(), sessionauth.WorkOSProfile{
		ID:            "user_workos_conflict",
		Email:         "taken@example.com",
		EmailVerified: true,
	}, "signup")
	if !errors.Is(err, ErrAuthIdentityConflict) {
		t.Fatalf("expected identity conflict, got %v", err)
	}
}

func TestUpdateWorkOSUserEmailRejectsConflictingEmail(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := context.Background()
	svc := NewService(store, fakeScanner{}, "aws")
	user, err := store.UpsertUser(ctx, db.User{PrimaryEmail: "owner@example.com"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if _, err := store.UpsertUser(ctx, db.User{PrimaryEmail: "taken@example.com"}); err != nil {
		t.Fatalf("seed taken: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_owner",
		LastAuthenticatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if err := svc.UpdateWorkOSUserEmail(ctx, "user_workos_owner", "taken@example.com"); !errors.Is(err, ErrAuthIdentityConflict) {
		t.Fatalf("expected identity conflict, got %v", err)
	}
}

func TestUpsertWorkOSUserLoginIntentRefusesReturningDeactivatedIdentity(t *testing.T) {
	// A user with an existing WorkOS identity who has been deactivated must
	// not be auto-reactivated on a subsequent login-intent sign-in. The
	// frontend uses ErrAuthReactivationRequired to surface the dedicated
	// reactivation affordance instead.
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "returning@example.com",
		DisplayName:  "Returning User",
		Status:       "deactivated",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_returning",
		Email:               "returning@example.com",
		LastAuthenticatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	_, err = svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:            "user_workos_returning",
		Email:         "returning@example.com",
		EmailVerified: true,
	}, "login")
	if !errors.Is(err, ErrAuthReactivationRequired) {
		t.Fatalf("expected reactivation required, got %v", err)
	}
	unchanged, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if unchanged.Status != "deactivated" {
		t.Fatalf("login intent must not auto-reactivate, got %q", unchanged.Status)
	}
}

func TestUpsertWorkOSUserSignupIntentClearsDeletedAtOnIdentityResolvedPath(t *testing.T) {
	// Regression: when a returning user already has a WorkOS identity row and
	// the underlying account was previously soft-deleted, signup-intent must
	// clear DeletedAt as well as flipping status. Without that, downstream
	// callers of workOSUserCanBeReactivated keep treating the account as
	// reactivatable and the soft-delete sentinel survives.
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 28, 9, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-24 * time.Hour)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "returning@example.com",
		DisplayName:  "Returning",
		Status:       "deleted",
		DeletedAt:    &deletedAt,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_returning_softdeleted",
		Email:               "returning@example.com",
		LastAuthenticatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	result, err := svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:            "user_workos_returning_softdeleted",
		Email:         "returning@example.com",
		EmailVerified: true,
	}, "signup")
	if err != nil {
		t.Fatalf("signup-intent reactivation: %v", err)
	}
	if result.User.Status != "active" {
		t.Fatalf("expected status=active after reactivation, got %q", result.User.Status)
	}
	if result.User.DeletedAt != nil {
		t.Fatalf("expected DeletedAt cleared after reactivation, got %v", result.User.DeletedAt)
	}
	stored, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("load reactivated user: %v", err)
	}
	if stored.DeletedAt != nil {
		t.Fatalf("expected stored DeletedAt cleared, got %v", stored.DeletedAt)
	}
}

func TestUpsertManualUserSessionContextAutoReactivatesDeactivatedAccount(t *testing.T) {
	// Manual mode is the loopback-only dev convenience path and has no
	// signup-intent escape hatch like the WorkOS flow. Treating manual
	// sign-in as an implicit reactivation keeps a deactivate test from
	// permanently locking a developer out of their dev tenant. The
	// production refusal lives in the WorkOS path and is covered by
	// TestUpsertWorkOSUserLoginIntentRefusesReturningDeactivatedIdentity.
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := context.Background()
	deletedAt := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(ctx, db.User{
		PrimaryEmail: "manual@example.com",
		DisplayName:  "Manual",
		Status:       "deactivated",
		DeletedAt:    &deletedAt,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	result, err := svc.UpsertManualUserSessionContext(ctx, ManualLoginInput{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		Email:       "manual@example.com",
	})
	if err != nil {
		t.Fatalf("manual reactivation: %v", err)
	}
	if result.User.Status != "active" {
		t.Fatalf("expected manual reactivation to flip status, got %q", result.User.Status)
	}
	if result.User.DeletedAt != nil {
		t.Fatalf("expected manual reactivation to clear DeletedAt, got %v", result.User.DeletedAt)
	}
	stored, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("load reactivated user: %v", err)
	}
	if stored.Status != "active" || stored.DeletedAt != nil {
		t.Fatalf("expected stored row reactivated, got status=%q deleted_at=%v", stored.Status, stored.DeletedAt)
	}
}

type samlProfileUpdateStore struct {
	*db.MemoryStore
	upsertUserCalls    int
	updateProfileCalls int
}

func (s *samlProfileUpdateStore) UpsertUser(ctx context.Context, user db.User) (db.User, error) {
	s.upsertUserCalls++
	// Simulate a racing deactivation happening after stale status was read but before
	// the write is persisted.
	user.Status = "deactivated"
	return s.MemoryStore.UpsertUser(ctx, user)
}

func (s *samlProfileUpdateStore) UpdateUserProfile(ctx context.Context, user db.User) (db.User, error) {
	s.updateProfileCalls++
	return s.MemoryStore.UpdateUserProfile(ctx, user)
}

func TestRefreshSAMLIdentityPreservesLifecycleStatus(t *testing.T) {
	base := db.NewMemoryStore()
	store := &samlProfileUpdateStore{MemoryStore: base}
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	ctx := context.Background()
	user, err := base.UpsertUser(ctx, db.User{
		PrimaryEmail: "saml-refresh@example.com",
		DisplayName:  "SAML Refresh",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	identity, err := base.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            "saml:conn-refresh",
		Subject:             "name-id-refresh",
		Email:               "saml-refresh@example.com",
		EmailVerified:       true,
		LastAuthenticatedAt: now,
		CreatedAt:           now,
	})
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	result, err := svc.refreshSAMLIdentity(ctx, db.IdentityConnection{ID: "conn-refresh"}, identity, "saml-refresh@example.com", "SAML Refresh New", []byte("{}"), now)
	if err != nil {
		t.Fatalf("refresh SAML identity: %v", err)
	}
	if result.User.Status != "active" {
		t.Fatalf("expected lifecycle status preserved as active, got %q", result.User.Status)
	}
	if store.updateProfileCalls != 1 {
		t.Fatalf("expected UpdateUserProfile to be called, got %d", store.updateProfileCalls)
	}
	if store.upsertUserCalls != 0 {
		t.Fatalf("expected UpsertUser to not be used by SAML refresh path, got %d", store.upsertUserCalls)
	}
}

func TestAttachSAMLIdentityToExistingUserPreservesLifecycleStatus(t *testing.T) {
	base := db.NewMemoryStore()
	store := &samlProfileUpdateStore{MemoryStore: base}
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 5, 28, 11, 0, 0, 0, time.UTC)
	ctx := context.Background()
	user, err := base.UpsertUser(ctx, db.User{
		PrimaryEmail: "saml-attach@example.com",
		DisplayName:  "SAML Attach",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	result, err := svc.attachSAMLIdentityToExistingUser(ctx, db.IdentityConnection{ID: "conn-attach"}, user.ID, "name-id-attach", "saml-attach@example.com", "SAML Attach New", []byte("{}"), now)
	if err != nil {
		t.Fatalf("attach SAML identity: %v", err)
	}
	if result.User.Status != "active" {
		t.Fatalf("expected lifecycle status preserved as active, got %q", result.User.Status)
	}
	if store.updateProfileCalls != 1 {
		t.Fatalf("expected UpdateUserProfile to be called, got %d", store.updateProfileCalls)
	}
	if store.upsertUserCalls != 0 {
		t.Fatalf("expected UpsertUser to not be used by SAML attach path, got %d", store.upsertUserCalls)
	}
}

type workOSReactivationStore struct {
	*db.MemoryStore
	upsertUserCalls    int
	updateProfileCalls int
	setStatusCalls     int
}

type staleReadWorkOSStore struct {
	*db.MemoryStore
	getUserCalls int
}

func (s *workOSReactivationStore) UpsertUser(ctx context.Context, user db.User) (db.User, error) {
	s.upsertUserCalls++
	return s.MemoryStore.UpsertUser(ctx, user)
}

func (s *workOSReactivationStore) UpdateUserProfile(ctx context.Context, user db.User) (db.User, error) {
	s.updateProfileCalls++
	return s.MemoryStore.UpdateUserProfile(ctx, user)
}

func (s *staleReadWorkOSStore) GetUser(ctx context.Context, userID string) (db.User, error) {
	user, err := s.MemoryStore.GetUser(ctx, userID)
	if err != nil {
		return db.User{}, err
	}
	s.getUserCalls++
	if s.getUserCalls == 1 {
		user.Status = "active"
	}
	return user, nil
}

func (s *workOSReactivationStore) SetUserStatus(ctx context.Context, userID string, status string, now time.Time) (db.User, error) {
	s.setStatusCalls++
	return s.MemoryStore.SetUserStatus(ctx, userID, status, now)
}

func TestUpsertWorkOSUserForIntentSignupReactivationUsesProfileUpdateThenStatusUpdate(t *testing.T) {
	base := db.NewMemoryStore()
	store := &workOSReactivationStore{MemoryStore: base}
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	user, err := base.UpsertUser(ctx, db.User{
		PrimaryEmail: "reactivating@example.com",
		DisplayName:  "Reacting",
		Status:       "deactivated",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := base.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "user_workos_reactivate_identity",
		Email:               "reactivating@example.com",
		EmailVerified:       true,
		LastAuthenticatedAt: now.Add(-time.Hour),
		CreatedAt:           now,
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	result, err := svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:                "user_workos_reactivate_identity",
		Email:             "reactivating-new@example.com",
		FirstName:         "Active",
		LastName:          "Tester",
		EmailVerified:     true,
		ProfilePictureURL: "https://cdn.example/reactivated.png",
	}, "signup")
	if err != nil {
		t.Fatalf("signup reactivation: %v", err)
	}
	if result.User.Status != "active" {
		t.Fatalf("expected active status, got %q", result.User.Status)
	}
	if store.updateProfileCalls != 1 {
		t.Fatalf("expected one profile update, got %d", store.updateProfileCalls)
	}
	if store.setStatusCalls != 1 {
		t.Fatalf("expected one status update, got %d", store.setStatusCalls)
	}
	if store.upsertUserCalls != 0 {
		t.Fatalf("expected no upsert during reactivation, got %d", store.upsertUserCalls)
	}
	if result.User.PrimaryEmail != "reactivating-new@example.com" {
		t.Fatalf("expected refreshed primary email, got %q", result.User.PrimaryEmail)
	}
}

func TestUpsertWorkOSUserForIntentLoginUsesFreshStateBeforeSessionFlip(t *testing.T) {
	base := db.NewMemoryStore()
	store := &staleReadWorkOSStore{MemoryStore: base}
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := context.Background()
	user, err := base.UpsertUser(ctx, db.User{
		PrimaryEmail: "stale@example.com",
		DisplayName:  "Stale User",
		Status:       "deactivated",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := base.UpsertUserIdentity(ctx, db.UserIdentity{
		UserID:              user.ID,
		Provider:            sessionauth.WorkOSProvider,
		Subject:             "workos-stale",
		Email:               "stale@example.com",
		LastAuthenticatedAt: time.Now().UTC(),
		CreatedAt:           time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	_, err = svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:            "workos-stale",
		Email:         "stale@example.com",
		EmailVerified: true,
	}, "login")
	if !errors.Is(err, ErrAuthReactivationRequired) {
		t.Fatalf("expected reactivation required after fresh read catches deactivation, got %v", err)
	}
	stored, err := base.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("load stored user: %v", err)
	}
	if stored.Status != "deactivated" {
		t.Fatalf("expected stored user to remain deactivated, got %q", stored.Status)
	}
}

func TestUpsertWorkOSUserForIntentEmailResolvedReactivationUsesProfileUpdateThenStatusUpdate(t *testing.T) {
	base := db.NewMemoryStore()
	store := &workOSReactivationStore{MemoryStore: base}
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := base.UpsertUser(ctx, db.User{
		PrimaryEmail: "rea-email@example.com",
		DisplayName:  "Email React",
		Status:       "deactivated",
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	result, err := svc.UpsertWorkOSUserForIntent(ctx, sessionauth.WorkOSProfile{
		ID:                "rea-email-subject",
		Email:             "rea-email@example.com",
		FirstName:         "Email",
		LastName:          "Reactivated",
		EmailVerified:     true,
		ProfilePictureURL: "https://cdn.example/rea.png",
	}, "signup")
	if err != nil {
		t.Fatalf("signup reactivation by email: %v", err)
	}
	if result.User.Status != "active" {
		t.Fatalf("expected active status, got %q", result.User.Status)
	}
	if store.updateProfileCalls != 1 {
		t.Fatalf("expected one profile update, got %d", store.updateProfileCalls)
	}
	if store.setStatusCalls != 1 {
		t.Fatalf("expected one status update, got %d", store.setStatusCalls)
	}
	if store.upsertUserCalls != 0 {
		t.Fatalf("expected no upsert during reactivation, got %d", store.upsertUserCalls)
	}
}
