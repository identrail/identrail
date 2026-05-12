package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresAuthUserIdentityAndSessionLifecycle(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC)
	userID := "11111111-1111-1111-1111-111111111111"
	identityID := "22222222-2222-2222-2222-222222222222"
	sessionHash := sha256.Sum256([]byte("postgres-session"))

	mock.ExpectQuery("INSERT INTO users").
		WithArgs(userID, "alice@example.com", "Alice", "", "active", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(postgresAuthUserRows(now).AddRow(userID, "alice@example.com", "Alice", "", "active", now, now, nil))
	user, err := store.UpsertUser(ctx, User{
		ID:           userID,
		PrimaryEmail: "alice@example.com",
		DisplayName:  "Alice",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if user.ID != userID || user.PrimaryEmail != "alice@example.com" {
		t.Fatalf("unexpected user: %+v", user)
	}

	mock.ExpectQuery("FROM users").
		WithArgs(userID).
		WillReturnRows(postgresAuthUserRows(now).AddRow(userID, "alice@example.com", "Alice", "", "active", now, now, nil))
	gotUser, err := store.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if gotUser.ID != userID {
		t.Fatalf("unexpected fetched user: %+v", gotUser)
	}

	mock.ExpectQuery("INSERT INTO user_identities").
		WithArgs(identityID, userID, "github", "alice-subject", sqlmock.AnyArg(), true, `{"login":"alice"}`, now, now).
		WillReturnRows(postgresAuthIdentityRows(now).AddRow(identityID, userID, "github", "alice-subject", "alice@example.com", true, []byte(`{"login":"alice"}`), now, now))
	identity, err := store.UpsertUserIdentity(ctx, UserIdentity{
		ID:                  identityID,
		UserID:              userID,
		Provider:            "github",
		Subject:             "alice-subject",
		Email:               "alice@example.com",
		EmailVerified:       true,
		RawClaims:           []byte(`{"login":"alice"}`),
		LastAuthenticatedAt: now,
		CreatedAt:           now,
	})
	if err != nil {
		t.Fatalf("upsert identity: %v", err)
	}
	if identity.ID != identityID || !identity.EmailVerified {
		t.Fatalf("unexpected identity: %+v", identity)
	}

	mock.ExpectQuery("FROM user_identities").
		WithArgs("github", "alice-subject").
		WillReturnRows(postgresAuthIdentityRows(now).AddRow(identityID, userID, "github", "alice-subject", "alice@example.com", true, []byte(`{"login":"alice"}`), now, now))
	gotIdentity, err := store.GetUserIdentity(ctx, "GITHUB", "alice-subject")
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if gotIdentity.ID != identityID {
		t.Fatalf("unexpected fetched identity: %+v", gotIdentity)
	}

	mock.ExpectQuery("WITH inserted AS").
		WithArgs(sessionHash[:], userID, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "manual", "203.0.113.10", sqlmock.AnyArg(), now.Add(15*time.Minute), now.Add(24*time.Hour), now, sqlmock.AnyArg(), now).
		WillReturnRows(postgresAuthSessionRows().AddRow(sessionHash[:], userID, "tenant-a", "workspace-a", "project-a", "manual", "203.0.113.10", "browser", now.Add(15*time.Minute), now.Add(24*time.Hour), now, nil, now, userID, "alice@example.com", "Alice", "", "active", now, now, nil))
	session, err := store.CreateSession(ctx, Session{
		ID:                 sessionHash[:],
		UserID:             userID,
		CurrentOrgID:       "tenant-a",
		CurrentWorkspaceID: "workspace-a",
		CurrentProjectID:   "project-a",
		AuthMethod:         "manual",
		IP:                 "203.0.113.10",
		UserAgent:          "browser",
		IdleExpiresAt:      now.Add(15 * time.Minute),
		AbsoluteExpiresAt:  now.Add(24 * time.Hour),
		LastSeenAt:         now,
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if session.User == nil || session.User.ID != userID || !bytes.Equal(session.ID, sessionHash[:]) {
		t.Fatalf("unexpected session: %+v", session)
	}

	mock.ExpectQuery("WITH touched AS").
		WithArgs(sessionHash[:], now.Add(time.Minute)).
		WillReturnRows(postgresAuthSessionRows().AddRow(sessionHash[:], userID, "tenant-a", "workspace-a", nil, "manual", "203.0.113.10", "browser", now.Add(16*time.Minute), now.Add(24*time.Hour), now.Add(time.Minute), nil, now, userID, "alice@example.com", "Alice", "", "active", now, now, nil))
	touched, err := store.TouchSession(ctx, sessionHash[:], now.Add(time.Minute))
	if err != nil {
		t.Fatalf("touch session: %v", err)
	}
	if touched.CurrentProjectID != "" || touched.CurrentWorkspaceID != "workspace-a" {
		t.Fatalf("unexpected touched session context: %+v", touched)
	}

	mock.ExpectQuery("FROM sessions s").
		WithArgs(userID, now, 10).
		WillReturnRows(postgresAuthSessionRows().AddRow(sessionHash[:], userID, "tenant-a", "workspace-a", nil, "manual", "203.0.113.10", "browser", now.Add(16*time.Minute), now.Add(24*time.Hour), now.Add(time.Minute), nil, now, userID, "alice@example.com", "Alice", "", "active", now, now, nil))
	sessions, err := store.ListUserSessions(ctx, userID, now, 10)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 || !bytes.Equal(sessions[0].ID, sessionHash[:]) {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}

	mock.ExpectQuery("WITH revoked AS").
		WithArgs(userID, sessionHash[:], now.Add(2*time.Minute)).
		WillReturnRows(postgresAuthSessionRows().AddRow(sessionHash[:], userID, "tenant-a", "workspace-a", nil, "manual", "203.0.113.10", "browser", now.Add(16*time.Minute), now.Add(24*time.Hour), now.Add(time.Minute), now.Add(2*time.Minute), now, userID, "alice@example.com", "Alice", "", "active", now, now, nil))
	revoked, err := store.RevokeUserSession(ctx, userID, sessionHash[:], now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("expected revoked_at to be populated")
	}

	mock.ExpectExec("UPDATE sessions").
		WithArgs(userID, sessionHash[:], now.Add(3*time.Minute)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	count, err := store.RevokeOtherUserSessions(ctx, userID, sessionHash[:], now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("revoke other sessions: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected two sessions revoked, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func postgresAuthUserRows(time.Time) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "primary_email", "display_name", "avatar_url", "status", "created_at", "updated_at", "deleted_at"})
}

func postgresAuthIdentityRows(time.Time) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "user_id", "provider", "subject", "email", "email_verified", "raw_claims", "last_authenticated_at", "created_at"})
}

func postgresAuthSessionRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id",
		"user_id",
		"current_org_id",
		"current_workspace_id",
		"current_project_id",
		"auth_method",
		"ip",
		"user_agent",
		"idle_expires_at",
		"absolute_expires_at",
		"last_seen_at",
		"revoked_at",
		"created_at",
		"user_id_text",
		"primary_email",
		"display_name",
		"avatar_url",
		"status",
		"user_created_at",
		"user_updated_at",
		"deleted_at",
	})
}
