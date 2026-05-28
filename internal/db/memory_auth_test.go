package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestMemoryAuthUserIdentityAndSessionLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)

	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: " Alice@Example.COM ",
		DisplayName:  " Alice ",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if user.PrimaryEmail != "alice@example.com" || user.DisplayName != "Alice" || user.Status != "active" {
		t.Fatalf("user was not normalized: %+v", user)
	}
	if byEmail, err := store.GetUserByPrimaryEmail(ctx, "ALICE@example.com"); err != nil || byEmail.ID != user.ID {
		t.Fatalf("expected lookup by primary email, got user=%+v err=%v", byEmail, err)
	}
	if _, err := store.UpsertUser(ctx, User{
		ID:           "44444444-4444-4444-4444-444444444444",
		PrimaryEmail: "alice@example.com",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate primary email conflict, got %v", err)
	}

	identity, err := store.UpsertUserIdentity(ctx, UserIdentity{
		ID:                  "22222222-2222-2222-2222-222222222222",
		UserID:              user.ID,
		Provider:            " GitHub ",
		Subject:             "alice-subject",
		Email:               "ALICE@EXAMPLE.COM",
		RawClaims:           []byte(`{"login":"alice"}`),
		LastAuthenticatedAt: now,
	})
	if err != nil {
		t.Fatalf("upsert identity: %v", err)
	}
	if identity.Provider != "github" || identity.Email != "alice@example.com" {
		t.Fatalf("identity was not normalized: %+v", identity)
	}
	gotIdentity, err := store.GetUserIdentity(ctx, "GITHUB", "alice-subject")
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if gotIdentity.ID != identity.ID {
		t.Fatalf("unexpected identity: %+v", gotIdentity)
	}
	if _, err := store.UpsertUserIdentity(ctx, UserIdentity{
		ID:                  identity.ID,
		UserID:              user.ID,
		Provider:            "github",
		Subject:             "alice-subject-renamed",
		Email:               "alice@example.com",
		RawClaims:           []byte(`{"login":"alice-renamed"}`),
		LastAuthenticatedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("rename identity subject: %v", err)
	}
	if _, err := store.GetUserIdentity(ctx, "github", "alice-subject"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old identity subject should not remain aliased, got %v", err)
	}
	gotIdentity, err = store.GetUserIdentity(ctx, "github", "alice-subject-renamed")
	if err != nil {
		t.Fatalf("get renamed identity: %v", err)
	}
	if gotIdentity.ID != identity.ID {
		t.Fatalf("unexpected renamed identity: %+v", gotIdentity)
	}
	gotIdentityByUserID, err := store.GetUserIdentityByProviderUserID(ctx, "github", user.ID)
	if err != nil {
		t.Fatalf("get identity by provider user id: %v", err)
	}
	if gotIdentityByUserID.Subject != "alice-subject-renamed" {
		t.Fatalf("unexpected identity by user id: %+v", gotIdentityByUserID)
	}
	providerIdentities, err := store.ListUserIdentitiesByProvider(ctx, "GITHUB", 10)
	if err != nil {
		t.Fatalf("list identities by provider: %v", err)
	}
	if len(providerIdentities) != 1 || providerIdentities[0].ID != identity.ID {
		t.Fatalf("unexpected provider identities: %+v", providerIdentities)
	}
	if err := store.DeleteUserIdentity(ctx, "github", "alice-subject-renamed"); err != nil {
		t.Fatalf("delete identity: %v", err)
	}
	if _, err := store.GetUserIdentity(ctx, "github", "alice-subject-renamed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected deleted identity to be missing, got %v", err)
	}
	if err := store.DeleteUserIdentity(ctx, "github", "alice-subject-renamed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected deleting missing identity to return ErrNotFound, got %v", err)
	}

	firstHash := sha256.Sum256([]byte("first-session"))
	secondHash := sha256.Sum256([]byte("second-session"))
	otherHash := sha256.Sum256([]byte("other-session"))
	_, err = store.CreateSession(ctx, Session{
		ID:                firstHash[:],
		UserID:            user.ID,
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		LastSeenAt:        now,
		CreatedAt:         now,
	})
	if err != nil {
		t.Fatalf("create first session: %v", err)
	}
	_, err = store.CreateSession(ctx, Session{
		ID:                secondHash[:],
		UserID:            user.ID,
		AuthMethod:        "workos",
		IdleExpiresAt:     now.Add(30 * time.Minute),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		LastSeenAt:        now.Add(time.Minute),
		CreatedAt:         now,
	})
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}
	otherUser, err := store.UpsertUser(ctx, User{
		ID:           "33333333-3333-3333-3333-333333333333",
		PrimaryEmail: "other@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert other user: %v", err)
	}
	_, err = store.CreateSession(ctx, Session{
		ID:                otherHash[:],
		UserID:            otherUser.ID,
		AuthMethod:        "oidc",
		IdleExpiresAt:     now.Add(30 * time.Minute),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		LastSeenAt:        now.Add(2 * time.Minute),
		CreatedAt:         now,
	})
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}

	items, err := store.ListUserSessions(ctx, user.ID, now, 1)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(items) != 1 || !bytes.Equal(items[0].ID, secondHash[:]) {
		t.Fatalf("expected newest user session only, got %+v", items)
	}

	touched, err := store.TouchSession(ctx, firstHash[:], now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("touch session: %v", err)
	}
	if touched.User == nil || touched.User.ID != user.ID {
		t.Fatalf("expected joined user on touched session: %+v", touched)
	}
	if !touched.LastSeenAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("unexpected last seen: %v", touched.LastSeenAt)
	}

	updated, err := store.UpdateSessionContext(ctx, user.ID, firstHash[:], "tenant-a", "workspace-b", "", now.Add(6*time.Minute))
	if err != nil {
		t.Fatalf("update session context: %v", err)
	}
	if updated.CurrentOrgID != "tenant-a" || updated.CurrentWorkspaceID != "workspace-b" || !updated.LastSeenAt.Equal(now.Add(6*time.Minute)) {
		t.Fatalf("unexpected updated session context: %+v", updated)
	}

	if _, err := store.RevokeUserSession(ctx, user.ID, otherHash[:], now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-user revoke to hide session, got %v", err)
	}
	if _, err := store.RevokeUserSession(ctx, user.ID, secondHash[:], now); err != nil {
		t.Fatalf("revoke second session: %v", err)
	}
	count, err := store.RevokeOtherUserSessions(ctx, user.ID, firstHash[:], now)
	if err != nil {
		t.Fatalf("revoke other sessions: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no remaining other active sessions, got %d", count)
	}
	items, err = store.ListUserSessions(ctx, user.ID, now, 0)
	if err != nil {
		t.Fatalf("list active sessions: %v", err)
	}
	if len(items) != 1 || !bytes.Equal(items[0].ID, firstHash[:]) {
		t.Fatalf("expected only first session active, got %+v", items)
	}
	count, err = store.RevokeAllUserSessions(ctx, user.ID, now)
	if err != nil {
		t.Fatalf("revoke all sessions: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one remaining session revoked, got %d", count)
	}
	items, err = store.ListUserSessions(ctx, user.ID, now, 0)
	if err != nil {
		t.Fatalf("list sessions after revoke all: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected no active sessions after revoke all, got %+v", items)
	}
}

func TestMemoryAuthRejectsMissingRecordsAndExpiredSessions(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	hash := sha256.Sum256([]byte("expired-session"))

	if _, err := store.GetUser(ctx, "11111111-1111-1111-1111-111111111111"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing user to return ErrNotFound, got %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, UserIdentity{
		UserID:   "11111111-1111-1111-1111-111111111111",
		Provider: "github",
		Subject:  "missing",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing identity user to return ErrNotFound, got %v", err)
	}
	if _, err := store.CreateSession(ctx, Session{
		ID:                hash[:],
		UserID:            "11111111-1111-1111-1111-111111111111",
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing session user to return ErrNotFound, got %v", err)
	}

	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "expired@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if _, err := store.CreateSession(ctx, Session{
		ID:                hash[:],
		UserID:            user.ID,
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		CreatedAt:         now,
	}); err != nil {
		t.Fatalf("create expiring session: %v", err)
	}
	if _, err := store.TouchSession(ctx, hash[:], now.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected expired session to return ErrNotFound, got %v", err)
	}
}

func TestMemoryCreateSessionRejectsInactiveUsers(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	sessionHash := sha256.Sum256([]byte("inactive-user-session"))
	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "inactive@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if _, err := store.CreateSession(ctx, Session{
		ID:                sessionHash[:],
		UserID:            user.ID,
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		CreatedAt:         now,
	}); err != nil {
		t.Fatalf("create session for active user: %v", err)
	}
	if _, err := store.SetUserStatus(ctx, user.ID, "deactivated", now.Add(time.Minute)); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
	sessionHash2 := sha256.Sum256([]byte("deactivated-user-session"))
	if _, err := store.CreateSession(ctx, Session{
		ID:                sessionHash2[:],
		UserID:            user.ID,
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		CreatedAt:         now,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected deactivated user session to return ErrNotFound, got %v", err)
	}

	deletedAt := now.Add(-time.Minute)
	if _, err := store.UpsertUser(ctx, User{
		ID:           user.ID,
		PrimaryEmail: "inactive@example.com",
		Status:       "deleted",
		DeletedAt:    &deletedAt,
		UpdatedAt:    now.Add(2 * time.Minute),
		CreatedAt:    user.CreatedAt,
	}); err != nil {
		t.Fatalf("mark user deleted: %v", err)
	}
	sessionHash3 := sha256.Sum256([]byte("deleted-user-session"))
	if _, err := store.CreateSession(ctx, Session{
		ID:                sessionHash3[:],
		UserID:            user.ID,
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		CreatedAt:         now,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected deleted user session to return ErrNotFound, got %v", err)
	}
}

func TestMemoryUpdateUserProfilePreservesStatus(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "status-pinned@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if _, err := store.SetUserStatus(ctx, user.ID, "deactivated", now.Add(time.Minute)); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
	updated, err := store.UpdateUserProfile(ctx, User{
		ID:           user.ID,
		PrimaryEmail: "status-pinned@example.com",
		DisplayName:  "Updated",
		UpdatedAt:    now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("update user profile: %v", err)
	}
	if updated.Status != "deactivated" {
		t.Fatalf("expected status to remain deactivated, got %q", updated.Status)
	}
}

func TestAuthNormalizationRejectsInvalidInputs(t *testing.T) {
	now := time.Date(2026, 5, 12, 11, 0, 0, 0, time.UTC)
	if _, err := NormalizeUserForWrite(User{ID: "not-a-uuid", PrimaryEmail: "user@example.com"}); err == nil {
		t.Fatal("expected invalid user id to fail")
	}
	if _, err := NormalizeUserForWrite(User{ID: "11111111-1111-1111-1111-111111111111"}); err == nil {
		t.Fatal("expected missing primary email to fail")
	}
	if _, err := NormalizeUserForWrite(User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "user@example.com",
		Status:       "locked",
	}); err == nil {
		t.Fatal("expected invalid user status to fail")
	}

	if _, err := NormalizeUserIdentityForWrite(UserIdentity{UserID: "bad", Provider: "github", Subject: "subject"}); err == nil {
		t.Fatal("expected invalid identity user id to fail")
	}
	if _, err := NormalizeUserIdentityForWrite(UserIdentity{
		UserID:    "11111111-1111-1111-1111-111111111111",
		Provider:  "github",
		Subject:   "subject",
		RawClaims: []byte(`{bad`),
	}); err == nil {
		t.Fatal("expected invalid raw claims to fail")
	}
	if _, err := NormalizeUserIdentityForWrite(UserIdentity{
		UserID:   "11111111-1111-1111-1111-111111111111",
		Provider: " ",
		Subject:  "subject",
	}); err == nil {
		t.Fatal("expected missing provider to fail")
	}

	sessionHash := sha256.Sum256([]byte("normalization-session"))
	revokedAt := now.Add(time.Minute)
	user := &User{ID: "11111111-1111-1111-1111-111111111111", PrimaryEmail: "user@example.com"}
	normalized, err := NormalizeSessionForWrite(Session{
		ID:                sessionHash[:],
		UserID:            "11111111-1111-1111-1111-111111111111",
		AuthMethod:        "MANUAL",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		RevokedAt:         &revokedAt,
		User:              user,
	})
	if err != nil {
		t.Fatalf("normalize valid session: %v", err)
	}
	if normalized.AuthMethod != "manual" || normalized.RevokedAt == nil || normalized.User == user {
		t.Fatalf("expected normalized auth method, revoked time, and copied user, got %+v", normalized)
	}
	if _, err := NormalizeSessionForWrite(Session{
		ID:                []byte("short"),
		UserID:            "11111111-1111-1111-1111-111111111111",
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}); err == nil {
		t.Fatal("expected short session hash to fail")
	}
	if _, err := NormalizeSessionForWrite(Session{
		ID:                sessionHash[:],
		UserID:            "11111111-1111-1111-1111-111111111111",
		AuthMethod:        "password",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}); err == nil {
		t.Fatal("expected invalid auth method to fail")
	}
	if _, err := NormalizeSessionForWrite(Session{
		ID:                sessionHash[:],
		UserID:            "11111111-1111-1111-1111-111111111111",
		AuthMethod:        "manual",
		AbsoluteExpiresAt: now.Add(time.Hour),
	}); err == nil {
		t.Fatal("expected missing idle expiry to fail")
	}
}

func TestMemorySetUserStatusTransitionsAndIdempotency(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	created := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "carol@example.com",
		DisplayName:  "Carol",
		CreatedAt:    created,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}

	deactivatedAt := created.Add(time.Hour)
	deactivated, err := store.SetUserStatus(ctx, user.ID, "deactivated", deactivatedAt)
	if err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if deactivated.Status != "deactivated" {
		t.Fatalf("expected status=deactivated, got %q", deactivated.Status)
	}
	if !deactivated.UpdatedAt.Equal(deactivatedAt) {
		t.Fatalf("expected updated_at=%s, got %s", deactivatedAt, deactivated.UpdatedAt)
	}

	// Idempotent: setting the same status returns the row without error.
	again, err := store.SetUserStatus(ctx, user.ID, "deactivated", deactivatedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("repeat deactivate: %v", err)
	}
	if again.Status != "deactivated" {
		t.Fatalf("expected idempotent deactivate, got %q", again.Status)
	}

	reactivated, err := store.SetUserStatus(ctx, user.ID, "active", deactivatedAt.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if reactivated.Status != "active" {
		t.Fatalf("expected status=active after reactivate, got %q", reactivated.Status)
	}
}

func TestMemorySetUserStatusRejectsInvalidInput(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "dan@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}

	if _, err := store.SetUserStatus(ctx, user.ID, "locked", now); err == nil {
		t.Fatal("expected invalid status to fail")
	}
	if _, err := store.SetUserStatus(ctx, "22222222-2222-2222-2222-222222222222", "deactivated", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing user, got %v", err)
	}
}
