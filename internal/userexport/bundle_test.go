package userexport_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/userexport"
)

func seedUserWithMembership(t *testing.T, store *db.MemoryStore, email string) db.User {
	t.Helper()
	user, err := store.UpsertUser(context.Background(), db.User{
		PrimaryEmail: email,
		DisplayName:  "Test User",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-export", WorkspaceID: "ws-export"})
	if err := store.UpsertOrganization(scopedCtx, db.TenancyOrganization{
		TenantID:    "tenant-export",
		DisplayName: "Tenant Export",
		Slug:        "tenant-export",
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := store.UpsertWorkspace(scopedCtx, db.TenancyWorkspace{
		TenantID:    "tenant-export",
		WorkspaceID: "ws-export",
		DisplayName: "Workspace Export",
		Slug:        "ws-export",
	}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedCtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-export",
		WorkspaceID: "ws-export",
		MemberID:    "member-1",
		UserID:      user.ID,
		UserUUID:    user.ID,
		Email:       email,
		Role:        "owner",
		Status:      "active",
		JoinedAt:    time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	return user
}

func TestBundleWriteContainsExpectedFiles(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "export@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	result, err := userexport.Write(context.Background(), store, user.ID, now, &buf)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.SizeBytes != int64(buf.Len()) {
		t.Fatalf("size mismatch: %d vs %d", result.SizeBytes, buf.Len())
	}
	if result.SHA256 == "" {
		t.Fatal("expected sha256")
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	want := map[string]bool{
		"manifest.json":   false,
		"user.json":       false,
		"workspaces.json": false,
		"audit.json":      false,
		"sessions.json":   false,
	}
	for _, f := range reader.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("bundle missing %s", name)
		}
	}

	userPayload := decodeFile[userexport.UserPayload](t, reader, "user.json")
	if userPayload.PrimaryEmail != "export@example.com" {
		t.Fatalf("unexpected email: %q", userPayload.PrimaryEmail)
	}
	workspaces := decodeFile[[]userexport.WorkspacePayload](t, reader, "workspaces.json")
	if len(workspaces) != 1 || workspaces[0].WorkspaceID != "ws-export" {
		t.Fatalf("unexpected workspaces: %+v", workspaces)
	}
	manifest := decodeFile[userexport.Manifest](t, reader, "manifest.json")
	if manifest.UserID != user.ID {
		t.Fatalf("manifest user mismatch: %s vs %s", manifest.UserID, user.ID)
	}
	if manifest.SchemaVersion != userexport.BundleSchemaVersion {
		t.Fatal("manifest schema mismatch")
	}
}

func TestBundleWriteIncludesWorkspaceMembershipsAcrossTenants(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "multi-tenant@example.com")
	tenantBCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-b", WorkspaceID: "ws-b"})
	if err := store.UpsertOrganization(tenantBCtx, db.TenancyOrganization{
		TenantID:    "tenant-b",
		DisplayName: "Tenant B",
		Slug:        "tenant-b",
	}); err != nil {
		t.Fatalf("seed tenant b: %v", err)
	}
	if err := store.UpsertWorkspace(tenantBCtx, db.TenancyWorkspace{
		TenantID:    "tenant-b",
		WorkspaceID: "ws-b",
		DisplayName: "Workspace B",
		Slug:        "ws-b",
	}); err != nil {
		t.Fatalf("seed workspace b: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantBCtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-b",
		WorkspaceID: "ws-b",
		MemberID:    "member-b",
		UserID:      user.ID,
		UserUUID:    user.ID,
		Email:       user.PrimaryEmail,
		Role:        "viewer",
		Status:      "active",
		JoinedAt:    time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seed tenant b member: %v", err)
	}

	var buf bytes.Buffer
	if _, err := userexport.Write(context.Background(), store, user.ID, time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	workspaces := decodeFile[[]userexport.WorkspacePayload](t, reader, "workspaces.json")
	if len(workspaces) != 2 || workspaces[0].TenantID != "tenant-b" && workspaces[1].TenantID != "tenant-b" {
		t.Fatalf("expected memberships from both tenants, got %+v", workspaces)
	}
}

func TestBundleWriteIncludesSessionsDeletedUserAndOnboardingAudit(t *testing.T) {
	store := db.NewMemoryStore()
	user := seedUserWithMembership(t, store, "history@example.com")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessionHash := sha256.Sum256([]byte("session-for-export"))
	if _, err := store.CreateSession(context.Background(), db.Session{
		ID:                 sessionHash[:],
		UserID:             user.ID,
		CurrentOrgID:       "tenant-export",
		CurrentWorkspaceID: "ws-export",
		AuthMethod:         "manual",
		IP:                 "203.0.113.10",
		UserAgent:          "test browser",
		CreatedAt:          now.Add(-3 * time.Hour),
		LastSeenAt:         now.Add(-time.Hour),
		IdleExpiresAt:      now.Add(time.Hour),
		AbsoluteExpiresAt:  now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	completedAt := now.Add(-30 * time.Minute)
	if _, err := store.UpsertOnboardingState(context.Background(), db.OnboardingState{
		UserID:      user.ID,
		CurrentStep: "complete",
		OrgID:       "tenant-export",
		WorkspaceID: "ws-export",
		CompletedAt: &completedAt,
		StartedAt:   now.Add(-4 * time.Hour),
		UpdatedAt:   completedAt,
	}); err != nil {
		t.Fatalf("seed onboarding: %v", err)
	}
	deletedAt := now.Add(-15 * time.Minute)
	if _, err := store.UpsertUser(context.Background(), db.User{
		ID:           user.ID,
		PrimaryEmail: user.PrimaryEmail,
		DisplayName:  user.DisplayName,
		Status:       "deleted",
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    deletedAt,
		DeletedAt:    &deletedAt,
	}); err != nil {
		t.Fatalf("soft delete user: %v", err)
	}

	var buf bytes.Buffer
	if _, err := userexport.Write(context.Background(), store, user.ID, now, &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}

	userPayload := decodeFile[userexport.UserPayload](t, reader, "user.json")
	if userPayload.DeletedAt == nil || userPayload.Status != "deleted" {
		t.Fatalf("expected deleted user payload, got %+v", userPayload)
	}
	sessions := decodeFile[[]userexport.SessionPayload](t, reader, "sessions.json")
	if len(sessions) != 1 || sessions[0].AuthMethod != "manual" || sessions[0].IP != "203.0.113.10" {
		t.Fatalf("unexpected sessions payload: %+v", sessions)
	}
	auditEvents := decodeFile[[]userexport.AuditPayload](t, reader, "audit.json")
	for _, action := range []string{"auth.session.create", "auth.user.delete", "onboarding.start", "onboarding.complete"} {
		if !hasAuditAction(auditEvents, action) {
			t.Fatalf("expected audit action %s in %+v", action, auditEvents)
		}
	}
}

func TestBundleWriteHandlesUsersWithoutWorkspaceMembership(t *testing.T) {
	store := db.NewMemoryStore()
	user, err := store.UpsertUser(context.Background(), db.User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "nomember@example.com",
		DisplayName:  "No Member",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	var buf bytes.Buffer
	if _, err := userexport.Write(context.Background(), store, user.ID, time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	workspaces := decodeFile[[]userexport.WorkspacePayload](t, reader, "workspaces.json")
	if len(workspaces) != 0 {
		t.Fatalf("expected empty workspaces, got %+v", workspaces)
	}
}

func TestBundleWriteValidationAndSourceErrors(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if _, err := userexport.Write(context.Background(), nil, "user-1", now, &bytes.Buffer{}); err == nil {
		t.Fatal("expected nil source error")
	}
	if _, err := userexport.Write(context.Background(), stubBundleSource{}, "", now, &bytes.Buffer{}); err == nil {
		t.Fatal("expected blank user id error")
	}

	user := db.User{
		ID:           "22222222-2222-2222-2222-222222222222",
		PrimaryEmail: "source@example.com",
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	sessionErr := errors.New("session store unavailable")
	if _, err := userexport.Write(context.Background(), stubBundleSource{user: user, sessionsErr: sessionErr}, user.ID, now, &bytes.Buffer{}); !errors.Is(err, sessionErr) {
		t.Fatalf("expected session error, got %v", err)
	}
	onboardingErr := errors.New("onboarding store unavailable")
	if _, err := userexport.Write(context.Background(), stubBundleSource{user: user, onboardingErr: onboardingErr}, user.ID, now, &bytes.Buffer{}); !errors.Is(err, onboardingErr) {
		t.Fatalf("expected onboarding error, got %v", err)
	}
	workspaceErr := errors.New("workspace store unavailable")
	if _, err := userexport.Write(context.Background(), stubBundleSource{
		user:         user,
		workspaceErr: workspaceErr,
	}, user.ID, now, &bytes.Buffer{}); !errors.Is(err, workspaceErr) {
		t.Fatalf("expected workspace list error, got %v", err)
	}
}

func TestBundleWriteIncludesRevokedSessionsFromSource(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	user := db.User{
		ID:           "33333333-3333-3333-3333-333333333333",
		PrimaryEmail: "revoked@example.com",
		Status:       "active",
		CreatedAt:    now.Add(-24 * time.Hour),
		UpdatedAt:    now.Add(-24 * time.Hour),
	}
	revokedAt := now.Add(-time.Hour)
	sessionHash := sha256.Sum256([]byte("revoked-session"))
	var buf bytes.Buffer
	if _, err := userexport.Write(context.Background(), stubBundleSource{
		user: user,
		sessions: []db.Session{{
			ID:                 sessionHash[:],
			UserID:             user.ID,
			AuthMethod:         "manual",
			CreatedAt:          now.Add(-2 * time.Hour),
			LastSeenAt:         now.Add(-90 * time.Minute),
			IdleExpiresAt:      now.Add(time.Hour),
			AbsoluteExpiresAt:  now.Add(24 * time.Hour),
			RevokedAt:          &revokedAt,
			CurrentOrgID:       "tenant-export",
			CurrentWorkspaceID: "ws-export",
		}},
	}, user.ID, now, &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	sessions := decodeFile[[]userexport.SessionPayload](t, reader, "sessions.json")
	if len(sessions) != 1 || sessions[0].RevokedAt == nil {
		t.Fatalf("expected revoked session payload, got %+v", sessions)
	}
	auditEvents := decodeFile[[]userexport.AuditPayload](t, reader, "audit.json")
	if !hasAuditAction(auditEvents, "auth.session.revoke") {
		t.Fatalf("expected session revoke audit event in %+v", auditEvents)
	}
}

func decodeFile[T any](t *testing.T, r *zip.Reader, name string) T {
	t.Helper()
	for _, f := range r.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		defer rc.Close()
		body, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var out T
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return out
	}
	t.Fatalf("missing %s", name)
	var zero T
	return zero
}

func TestBundleScopingRefusesUnknownUser(t *testing.T) {
	store := db.NewMemoryStore()
	var buf bytes.Buffer
	_, err := userexport.Write(context.Background(), store, "00000000-0000-0000-0000-000000000000", time.Now().UTC(), &buf)
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func hasAuditAction(events []userexport.AuditPayload, action string) bool {
	for _, event := range events {
		if event.Action == action {
			return true
		}
	}
	return false
}

type stubBundleSource struct {
	user          db.User
	workspaces    []db.TenancyWorkspaceMember
	workspaceErr  error
	sessions      []db.Session
	sessionsErr   error
	onboardingErr error
}

func (s stubBundleSource) GetUser(ctx context.Context, userID string) (db.User, error) {
	if s.user.ID == "" {
		return db.User{}, db.ErrNotFound
	}
	return s.user, nil
}

func (s stubBundleSource) ListUserSessionHistory(ctx context.Context, userID string, limit int) ([]db.Session, error) {
	if s.sessionsErr != nil {
		return nil, s.sessionsErr
	}
	return s.sessions, nil
}

func (s stubBundleSource) ListUserSessions(ctx context.Context, userID string, _ time.Time, _ int) ([]db.Session, error) {
	return s.ListUserSessionHistory(ctx, userID, 0)
}

func (s stubBundleSource) ListWorkspaceMembershipsByUserUUID(ctx context.Context, userUUID string) ([]db.TenancyWorkspaceMember, error) {
	if s.workspaceErr != nil {
		return nil, s.workspaceErr
	}
	return s.workspaces, nil
}

func (s stubBundleSource) GetOnboardingState(ctx context.Context, userID string) (db.OnboardingState, error) {
	if s.onboardingErr != nil {
		return db.OnboardingState{}, s.onboardingErr
	}
	return db.OnboardingState{}, db.ErrNotFound
}
