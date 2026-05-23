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
