package userexport

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
)

type testSource struct {
	users               map[string]db.User
	sessions            map[string][]db.Session
	workspaces          map[string][]db.TenancyWorkspaceMember
	onboarding          map[string]db.OnboardingState
	onboardingErrors    map[string]error
	getUserErrors       map[string]error
	listSessionErrors   map[string]error
	listWorkspaceErrors map[string]error
}

func (s *testSource) GetUser(_ context.Context, userID string) (db.User, error) {
	if s.users == nil {
		s.users = map[string]db.User{}
	}
	if err, exists := s.getUserErrors[userID]; exists {
		return db.User{}, err
	}
	user, ok := s.users[userID]
	if !ok {
		return db.User{}, errors.New("user not found")
	}
	return user, nil
}

func (s *testSource) ListUserSessions(_ context.Context, userID string, _ time.Time, _ int) ([]db.Session, error) {
	return s.ListUserSessionHistory(context.Background(), userID, 0)
}

func (s *testSource) ListUserSessionHistory(_ context.Context, userID string, _ int) ([]db.Session, error) {
	if err, exists := s.listSessionErrors[userID]; exists {
		return nil, err
	}
	if s.sessions == nil {
		return nil, nil
	}
	rows := append([]db.Session(nil), s.sessions[userID]...)
	return rows, nil
}

func (s *testSource) ListWorkspaceMembershipsByUserUUID(_ context.Context, userUUID string) ([]db.TenancyWorkspaceMember, error) {
	if err, exists := s.listWorkspaceErrors[userUUID]; exists {
		return nil, err
	}
	if s.workspaces == nil {
		return nil, nil
	}
	return append([]db.TenancyWorkspaceMember(nil), s.workspaces[userUUID]...), nil
}

func (s *testSource) GetOnboardingState(_ context.Context, userID string) (db.OnboardingState, error) {
	if err, exists := s.onboardingErrors[userID]; exists {
		return db.OnboardingState{}, err
	}
	state, ok := s.onboarding[userID]
	if !ok {
		return db.OnboardingState{}, db.ErrNotFound
	}
	return state, nil
}

type fakeStorage struct {
	putErr      error
	openErr     error
	deleteErr   error
	stored      map[string][]byte
	openedKeys  []string
	deletedKeys []string
}

func (s *fakeStorage) Put(key string, r io.Reader) (string, error) {
	if s.stored == nil {
		s.stored = map[string][]byte{}
	}
	if s.putErr != nil {
		return "", s.putErr
	}
	contents, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	s.stored[key] = contents
	return key, nil
}

func (s *fakeStorage) Open(key string) (io.ReadCloser, error) {
	s.openedKeys = append(s.openedKeys, key)
	if s.openErr != nil {
		return nil, s.openErr
	}
	contents, ok := s.stored[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(contents)), nil
}

func (s *fakeStorage) Delete(key string) error {
	s.deletedKeys = append(s.deletedKeys, key)
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.stored, key)
	return nil
}

type fakeJobStore struct {
	failErrByJobID     map[string]error
	completeErrByJob   map[string]error
	markErrByJobID     map[string]error
	failStaleJobs      []db.UserDataExport
	failStaleErr       error
	failStaleErrByJob  map[string]error
	claims             []db.UserDataExport
	claimIndex         int
	claimErr           error
	completeJobs       []db.UserDataExport
	failJobs           []db.UserDataExport
	pendingPurge       []db.UserDataExport
	markPurgedJobs     []db.UserDataExport
	listPurgeErr       error
	claimJobIDToUserID map[string]string
}

func (s *fakeJobStore) ClaimNextQueuedUserDataExport(_ context.Context, _ time.Time) (db.UserDataExport, error) {
	if s.claimErr != nil {
		return db.UserDataExport{}, s.claimErr
	}
	if s.claimIndex >= len(s.claims) {
		return db.UserDataExport{}, db.ErrNotFound
	}
	job := s.claims[s.claimIndex]
	s.claimIndex++
	if s.claimJobIDToUserID != nil && s.claimJobIDToUserID[job.ID] != "" {
		job.UserID = s.claimJobIDToUserID[job.ID]
	}
	return job, nil
}

func (s *fakeJobStore) CompleteUserDataExport(_ context.Context, jobID string, bundlePath string, sizeBytes int64, sha256Hex string, completedAt time.Time, downloadExpiresAt time.Time, purgeAfter time.Time) (db.UserDataExport, error) {
	if s.completeErrByJob != nil {
		if err, ok := s.completeErrByJob[jobID]; ok {
			if err != nil {
				return db.UserDataExport{}, err
			}
		}
	}
	job := db.UserDataExport{
		ID:                jobID,
		UserID:            "u1",
		Status:            db.UserDataExportStatusReady,
		BundlePath:        bundlePath,
		BundleSizeBytes:   sizeBytes,
		BundleSHA256:      sha256Hex,
		CompletedAt:       &completedAt,
		DownloadExpiresAt: &downloadExpiresAt,
		PurgeAfter:        &purgeAfter,
	}
	s.completeJobs = append(s.completeJobs, job)
	return job, nil
}

func (s *fakeJobStore) FailUserDataExport(_ context.Context, jobID string, errMsg string, failedAt time.Time) (db.UserDataExport, error) {
	if err, ok := s.failErrByJobID[jobID]; ok {
		return db.UserDataExport{}, err
	}
	job := db.UserDataExport{
		ID:           jobID,
		UserID:       "u1",
		Status:       db.UserDataExportStatusFailed,
		ErrorMessage: errMsg,
		CompletedAt:  &failedAt,
	}
	s.failJobs = append(s.failJobs, job)
	return job, nil
}

func (s *fakeJobStore) ListUserDataExportsPendingPurge(_ context.Context, _ time.Time, _ int) ([]db.UserDataExport, error) {
	if s.listPurgeErr != nil {
		return nil, s.listPurgeErr
	}
	return append([]db.UserDataExport(nil), s.pendingPurge...), nil
}

func (s *fakeJobStore) MarkUserDataExportPurged(_ context.Context, jobID string, now time.Time) (db.UserDataExport, error) {
	if s.markErrByJobID != nil {
		if err, ok := s.markErrByJobID[jobID]; ok {
			if err != nil {
				return db.UserDataExport{}, err
			}
		}
	}
	job := db.UserDataExport{
		ID:       jobID,
		UserID:   "u1",
		Status:   db.UserDataExportStatusExpired,
		PurgedAt: &now,
	}
	s.markPurgedJobs = append(s.markPurgedJobs, job)
	return job, nil
}

func (s *fakeJobStore) FailStaleRunningUserDataExports(_ context.Context, _ time.Time, _ time.Time, _ int, _ string) ([]db.UserDataExport, error) {
	if s.failStaleErr != nil {
		return nil, s.failStaleErr
	}
	if s.failStaleErrByJob != nil {
		if len(s.failStaleJobs) > 0 {
			jobID := s.failStaleJobs[0].ID
			if err, ok := s.failStaleErrByJob[jobID]; ok && err != nil {
				return nil, err
			}
		}
	}
	return append([]db.UserDataExport(nil), s.failStaleJobs...), nil
}

func readZipEntries(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("create zip reader: %v", err)
	}
	entries := map[string][]byte{}
	for _, file := range reader.File {
		r, err := file.Open()
		if err != nil {
			t.Fatalf("open zip file %s: %v", file.Name, err)
		}
		payload, err := io.ReadAll(r)
		if err != nil {
			_ = r.Close()
			t.Fatalf("read zip file %s: %v", file.Name, err)
		}
		_ = r.Close()
		entries[file.Name] = payload
	}
	return entries
}

func TestStorageAndBundleRoundTrip(t *testing.T) {
	source := &testSource{
		users: map[string]db.User{
			"user-a": {
				ID:           "user-a",
				PrimaryEmail: "user@example.com",
				DisplayName:  "User A",
				Status:       "active",
				CreatedAt:    time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
				UpdatedAt:    time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			},
		},
		sessions: map[string][]db.Session{
			"user-a": {
				{AuthMethod: "pwd", UserID: "user-a", LastSeenAt: time.Date(2025, 2, 2, 10, 0, 0, 0, time.UTC), CreatedAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), IdleExpiresAt: time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC), AbsoluteExpiresAt: time.Date(2025, 2, 2, 11, 0, 0, 0, time.UTC)},
				{AuthMethod: "oauth", UserID: "user-a", LastSeenAt: time.Date(2025, 2, 3, 10, 0, 0, 0, time.UTC), CreatedAt: time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC), IdleExpiresAt: time.Date(2025, 2, 3, 12, 0, 0, 0, time.UTC), AbsoluteExpiresAt: time.Date(2025, 2, 3, 11, 0, 0, 0, time.UTC), RevokedAt: ptrTime(time.Date(2025, 2, 3, 10, 30, 0, 0, time.UTC))},
			},
		},
		workspaces: map[string][]db.TenancyWorkspaceMember{
			"user-a": {
				{TenantID: "tenant-b", WorkspaceID: "ws-2", UserID: "user-a", Role: "viewer", Status: "active", JoinedAt: time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC)},
				{TenantID: "tenant-a", WorkspaceID: "ws-1", UserID: "user-a", Role: "admin", Status: "active", JoinedAt: time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC)},
			},
		},
		onboarding: map[string]db.OnboardingState{
			"user-a": {
				UserID:      "user-a",
				StartedAt:   time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC),
				CompletedAt: ptrTime(time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC)),
			},
		},
	}

	b := &bytes.Buffer{}
	now := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	result, err := Write(context.Background(), source, "user-a", now, b)
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if result.SizeBytes == 0 {
		t.Fatalf("expected non-zero size")
	}
	if result.SHA256 == "" {
		t.Fatalf("expected checksum")
	}

	entries := readZipEntries(t, b.Bytes())
	if _, ok := entries["manifest.json"]; !ok {
		t.Fatalf("manifest not found")
	}
	if _, ok := entries["workspaces.json"]; !ok {
		t.Fatalf("workspaces not found")
	}

	var manifest Manifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.UserID != "user-a" || manifest.SchemaVersion != BundleSchemaVersion {
		t.Fatalf("unexpected manifest payload")
	}

	var sessions []SessionPayload
	if err := json.Unmarshal(entries["sessions.json"], &sessions); err != nil {
		t.Fatalf("unmarshal sessions: %v", err)
	}
	if got := len(sessions); got != 2 {
		t.Fatalf("expected two sessions, got %d", got)
	}
	if !sessions[0].LastSeenAt.After(sessions[1].LastSeenAt) {
		t.Fatalf("sessions not sorted by last seen")
	}

	var audit []AuditPayload
	if err := json.Unmarshal(entries["audit.json"], &audit); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}
	if len(audit) == 0 {
		t.Fatalf("expected audit entries")
	}
}

func TestLoadWorkspacesOrOnboardingErrorBranches(t *testing.T) {
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	user := db.User{ID: "user-a", PrimaryEmail: "user@example.com", Status: "active", CreatedAt: baseTime, UpdatedAt: baseTime}
	source := &testSource{
		users: map[string]db.User{"user-a": user},
	}

	var sink bytes.Buffer
	if _, err := Write(context.Background(), source, "user-a", baseTime, &sink); err != nil {
		t.Fatalf("expected success when onboarding/workspace data missing: %v", err)
	}

	source.listWorkspaceErrors = map[string]error{"user-a": errors.New("boom")}
	if _, err := Write(context.Background(), source, "user-a", baseTime, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected workspace lookup error")
	}

	source.listWorkspaceErrors = nil
	source.onboardingErrors = map[string]error{"user-a": errors.New("bad")}
	if _, err := Write(context.Background(), source, "user-a", baseTime, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected onboarding lookup error")
	}

	if got, err := loadWorkspaces(context.Background(), source, "missing"); err != nil || len(got) != 0 {
		t.Fatalf("expected empty list for missing user, got %v, %v", got, err)
	}
}

func TestStoragePutOpenDeleteFlow(t *testing.T) {
	temp := t.TempDir()
	storage, err := NewLocalDiskStorage(temp)
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}

	if _, err := storage.Put("../bad", strings.NewReader("x")); err == nil {
		t.Fatalf("expected invalid key rejection")
	}
	path, err := storage.Put("user-a/export.zip", strings.NewReader("export"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if want := filepath.Join(temp, "user-a", "export.zip"); path != want {
		t.Fatalf("expected path %s got %s", want, path)
	}
	f, err := storage.Open("user-a/export.zip")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "export" {
		t.Fatalf("unexpected content: %q", string(got))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := storage.Delete("user-a/export.zip"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := storage.Open("user-a/export.zip"); err == nil {
		t.Fatalf("expected file deleted")
	}

	if err := storage.Delete("user-a/missing.zip"); err != nil {
		t.Fatalf("delete missing should be no-op")
	}
	if _, err := NewLocalDiskStorage("   "); err == nil {
		t.Fatalf("expected empty path to fail")
	}
}

func TestStorageCloseErrorPath(t *testing.T) {
	var readerErr errorReader
	temp := t.TempDir()
	storage, err := NewLocalDiskStorage(temp)
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	if _, err := storage.Put("user-a/data", readerErr); err == nil {
		t.Fatalf("expected io copy error")
	}
}

func TestSignedDownloadTokenRoundTrip(t *testing.T) {
	secret := []byte("abc")
	expires := time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)
	token, err := SignedDownloadURL(secret, "job-a", expires)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jobID, err := VerifySignedDownloadURL(secret, token, expires.Add(-time.Second))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if jobID != "job-a" {
		t.Fatalf("unexpected job %s", jobID)
	}

	if _, err := SignedDownloadURL(nil, "job-a", expires); err == nil {
		t.Fatalf("expected sign error")
	}
	if _, err := SignedDownloadURL(secret, " ", expires); err == nil {
		t.Fatalf("expected sign error for empty job")
	}

	if _, err := VerifySignedDownloadURL(secret, "malformed", time.Now()); err == nil {
		t.Fatalf("expected malformed error")
	}
	if _, err := VerifySignedDownloadURL(secret, token, expires.Add(time.Hour)); err == nil {
		t.Fatalf("expected expired error")
	}
	if _, err := VerifySignedDownloadURL(secret, token+"x", time.Now()); err == nil {
		t.Fatalf("expected invalid format error")
	}

	parts := strings.Split(token, ".")
	parts[2] = "bad"
	if _, err := VerifySignedDownloadURL(secret, strings.Join(parts, "."), time.Now()); err == nil {
		t.Fatalf("expected signature mismatch")
	}
	parts[1] = "nonnumeric"
	if _, err := VerifySignedDownloadURL(secret, strings.Join(parts, "."), time.Now()); err == nil {
		t.Fatalf("expected expiry parse error")
	}
}

func TestTokenUsesSecret(t *testing.T) {
	secret := []byte("abc")
	other := []byte("other")
	expires := time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)
	token, err := SignedDownloadURL(secret, "job-a", expires)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifySignedDownloadURL(other, token, time.Now()); err == nil {
		t.Fatalf("expected mismatch with different secret")
	}
}

func TestRunnerRunFlow(t *testing.T) {
	store := &fakeJobStore{
		completeErrByJob: map[string]error{"fail-complete": errors.New("complete fail")},
		failErrByJobID:   map[string]error{},
	}
	storage := &fakeStorage{}
	source := &testSource{
		users: map[string]db.User{
			"u1": {ID: "u1", PrimaryEmail: "one@e.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()},
			"u2": {ID: "u2", PrimaryEmail: "two@e.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()},
		},
		sessions: map[string][]db.Session{},
	}

	runner := &Runner{
		Source:  source,
		Store:   store,
		Storage: storage,
		Now:     func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
	}

	job := db.UserDataExport{ID: "success", UserID: "u1", Status: db.UserDataExportStatusQueued}
	if _, err := runner.Run(context.Background(), job); err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if got := len(store.completeJobs); got != 1 {
		t.Fatalf("expected complete call got %d", got)
	}

	if _, err := runner.Run(context.Background(), db.UserDataExport{ID: "missing", UserID: "missing"}); err == nil {
		t.Fatalf("expected missing source failure")
	}

	if got := len(store.failJobs); got != 1 {
		t.Fatalf("expected fail call got %d", got)
	}

	if _, err := runner.Run(context.Background(), db.UserDataExport{ID: "fail-complete", UserID: "u2"}); err == nil {
		t.Fatalf("expected complete failure")
	}
}

func TestRunnerNilAndMissingDependencies(t *testing.T) {
	if _, err := (&Runner{}).Run(context.Background(), db.UserDataExport{}); err == nil {
		t.Fatalf("expected nil runner error")
	}
	r := &Runner{Source: &testSource{users: map[string]db.User{}}}
	if _, err := r.Run(context.Background(), db.UserDataExport{}); err == nil {
		t.Fatalf("expected missing dependency error")
	}
}

func TestQueueAndGCRunners(t *testing.T) {
	queueStore := &fakeJobStore{claims: []db.UserDataExport{{ID: "q1", UserID: "u1", Status: db.UserDataExportStatusQueued}, {ID: "q2", UserID: "u2", Status: db.UserDataExportStatusQueued}, {ID: "q3", UserID: "u3", Status: db.UserDataExportStatusQueued}}}
	queueStore.claimJobIDToUserID = map[string]string{"q1": "u1", "q2": "u2", "q3": "u3"}
	queueStore.completeErrByJob = map[string]error{}

	store := &fakeJobStore{
		listPurgeErr:     nil,
		completeErrByJob: map[string]error{},
		failErrByJobID:   map[string]error{},
		markErrByJobID:   map[string]error{},
		pendingPurge:     []db.UserDataExport{{ID: "old", UserID: "u1", BundlePath: "u1/old.zip"}, {ID: "older", UserID: "u2", BundlePath: "u2/older.zip"}},
	}
	source := &testSource{
		users: map[string]db.User{
			"u1": {ID: "u1", PrimaryEmail: "u1@example.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()},
			"u2": {ID: "u2", PrimaryEmail: "u2@example.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()},
		},
		getUserErrors: map[string]error{"u2": errors.New("missing source data")},
	}
	runner := &Runner{Source: source, Store: store, Storage: &fakeStorage{stored: map[string][]byte{"u1/q1": []byte("ok")}}, Now: func() time.Time { return time.Now() }}

	queue := &QueueRunner{Store: queueStore, Runner: runner, BatchSize: 5}
	result, err := queue.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("queue run: %v", err)
	}
	if result.Examined != 3 {
		t.Fatalf("expected 3 examined, got %d", result.Examined)
	}
	if result.Failed != 2 {
		t.Fatalf("expected 2 failed, got %d", result.Failed)
	}
	if result.Succeeded != 1 {
		t.Fatalf("expected 1 succeeded, got %d", result.Succeeded)
	}

	_, err = (&QueueRunner{}).RunOnce(context.Background())
	if err == nil {
		t.Fatalf("expected nil queue error")
	}

	gcStorage := &fakeStorage{stored: map[string][]byte{"u1/old.zip": []byte("old"), "u2/older.zip": []byte("older")}}
	gc := &GCRunner{Store: store, Storage: gcStorage, BatchSize: 1}
	gcResult, err := gc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("gc run: %v", err)
	}
	if gcResult.Examined != 2 {
		t.Fatalf("expected 2 examined, got %d", gcResult.Examined)
	}
	if gcResult.Purged != 2 {
		t.Fatalf("expected 2 purged, got %d", gcResult.Purged)
	}
	if got := len(store.markPurgedJobs); got != 2 {
		t.Fatalf("expected 2 mark calls got %d", got)
	}

	_, err = (&GCRunner{}).RunOnce(context.Background())
	if err == nil {
		t.Fatalf("expected gc nil error")
	}
}

func TestQueueRunnerStopsOnContextCanceled(t *testing.T) {
	queue := &QueueRunner{Store: &fakeJobStore{claims: []db.UserDataExport{{ID: "x", UserID: "u", Status: db.UserDataExportStatusQueued}}}, Runner: &Runner{Storage: &fakeStorage{}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queue.RunOnce(ctx); err != context.Canceled {
		t.Fatalf("expected canceled error, got %v", err)
	}
}

func TestGCRunnerErrorPaths(t *testing.T) {
	store := &fakeJobStore{pendingPurge: []db.UserDataExport{{ID: "x", UserID: "u", BundlePath: "u/x.zip"}}, markErrByJobID: map[string]error{"x": errors.New("mark failed")}}
	storage := &fakeStorage{deleteErr: nil}
	storage.stored = map[string][]byte{"u/x.zip": []byte("hi")}
	result, err := (&GCRunner{Store: store, Storage: storage, BatchSize: 1}).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("expected gc to keep going on mark error: %v", err)
	}
	if result.Errors != 1 {
		t.Fatalf("expected 1 error got %d", result.Errors)
	}
}

func TestStorageKey(t *testing.T) {
	job := db.UserDataExport{UserID: "tenant", ID: "job"}
	if got := StorageKey(job); got != "tenant/job.zip" {
		t.Fatalf("unexpected storage key: %s", got)
	}
}

type errorReader struct{}

func (errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("read failed")
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
