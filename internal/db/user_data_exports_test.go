package db

import (
	"context"
	"database/sql/driver"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMemoryStoreUserDataExportLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.FixedZone("WAT", 60*60))
	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-1111-1111-111111111111",
		PrimaryEmail: "owner@example.com",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	job, err := store.CreateUserDataExport(ctx, UserDataExport{
		UserID:      " " + user.ID + " ",
		RequestedAt: now,
	})
	if err != nil {
		t.Fatalf("create export: %v", err)
	}
	if job.ID == "" || job.Status != UserDataExportStatusQueued || !job.RequestedAt.Equal(now.UTC()) {
		t.Fatalf("unexpected created job: %+v", job)
	}
	if _, err := store.CreateUserDataExport(ctx, UserDataExport{ID: job.ID, UserID: user.ID, RequestedAt: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict for duplicate id, got %v", err)
	}
	if _, err := store.CreateUserDataExport(ctx, UserDataExport{UserID: "22222222-2222-2222-2222-222222222222", RequestedAt: now}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found for unknown user, got %v", err)
	}

	fetched, err := store.GetUserDataExport(ctx, " "+user.ID+" ", " "+job.ID+" ")
	if err != nil {
		t.Fatalf("get scoped export: %v", err)
	}
	if fetched.ID != job.ID || fetched.UserID != user.ID {
		t.Fatalf("unexpected scoped export: %+v", fetched)
	}
	if _, err := store.GetUserDataExport(ctx, "22222222-2222-2222-2222-222222222222", job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scoped not found, got %v", err)
	}
	if _, err := store.GetUserDataExportByID(ctx, " "+job.ID+" "); err != nil {
		t.Fatalf("get by id: %v", err)
	}

	older, err := store.CreateUserDataExport(ctx, UserDataExport{
		ID:          "22222222-2222-2222-2222-222222222222",
		UserID:      user.ID,
		RequestedAt: now.Add(-time.Hour),
		Status:      UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create older export: %v", err)
	}
	listed, err := store.ListUserDataExports(ctx, user.ID, 1)
	if err != nil {
		t.Fatalf("list exports: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != job.ID {
		t.Fatalf("expected newest export first with limit, got %+v", listed)
	}

	claimed, err := store.ClaimNextQueuedUserDataExport(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("claim export: %v", err)
	}
	if claimed.ID != older.ID || claimed.Status != UserDataExportStatusRunning || claimed.StartedAt == nil {
		t.Fatalf("expected oldest queued export to be running, got %+v", claimed)
	}
	completed, err := store.CompleteUserDataExport(
		ctx,
		claimed.ID,
		"/tmp/bundle.zip",
		1234,
		"abc123",
		now.Add(2*time.Minute),
		now.Add(24*time.Hour),
		now.Add(7*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("complete export: %v", err)
	}
	if completed.Status != UserDataExportStatusReady || completed.BundlePath == "" || completed.DownloadExpiresAt == nil || completed.PurgeAfter == nil {
		t.Fatalf("expected ready export with bundle metadata, got %+v", completed)
	}
	if _, err := store.CompleteUserDataExport(ctx, completed.ID, "again.zip", 1, "sha", now, now, now); err == nil {
		t.Fatal("expected terminal export completion to fail")
	}
	if _, err := store.FailUserDataExport(ctx, completed.ID, "late failure", now.Add(3*time.Minute)); err == nil {
		t.Fatal("expected terminal export failure to be rejected")
	}

	failed, err := store.FailUserDataExport(ctx, job.ID, "builder failed", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("fail export: %v", err)
	}
	if failed.Status != UserDataExportStatusFailed || failed.ErrorMessage != "builder failed" || failed.CompletedAt == nil {
		t.Fatalf("unexpected failed export: %+v", failed)
	}

	pending, err := store.ListUserDataExportsPendingPurge(ctx, now.Add(8*24*time.Hour), 0)
	if err != nil {
		t.Fatalf("list pending purge: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != completed.ID {
		t.Fatalf("expected completed export pending purge, got %+v", pending)
	}
	purged, err := store.MarkUserDataExportPurged(ctx, completed.ID, now.Add(8*24*time.Hour))
	if err != nil {
		t.Fatalf("mark purged: %v", err)
	}
	if purged.Status != UserDataExportStatusExpired || purged.BundlePath != "" || purged.PurgedAt == nil {
		t.Fatalf("unexpected purged export: %+v", purged)
	}
	pending, err = store.ListUserDataExportsPendingPurge(ctx, now.Add(9*24*time.Hour), 10)
	if err != nil {
		t.Fatalf("list pending purge after mark: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("purged export should not be pending again: %+v", pending)
	}
}

func TestMemoryStoreUserDataExportPendingPurgeSortsBeforeLimit(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(ctx, User{
		ID:           "77777777-7777-7777-7777-777777777777",
		PrimaryEmail: "purge-order@example.com",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for _, item := range []struct {
		id        string
		purgeHour int
	}{
		{id: "99999999-9999-9999-9999-999999999999", purgeHour: 4},
		{id: "88888888-8888-8888-8888-888888888888", purgeHour: 1},
		{id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", purgeHour: 2},
	} {
		completed := now.Add(time.Duration(item.purgeHour) * time.Hour)
		if _, err := store.CreateUserDataExport(ctx, UserDataExport{
			ID:                item.id,
			UserID:            user.ID,
			Status:            UserDataExportStatusReady,
			RequestedAt:       now.Add(-time.Hour),
			CompletedAt:       &completed,
			DownloadExpiresAt: &completed,
			PurgeAfter:        &completed,
		}); err != nil {
			t.Fatalf("seed export %s: %v", item.id, err)
		}
	}
	pending, err := store.ListUserDataExportsPendingPurge(ctx, now.Add(5*time.Hour), 2)
	if err != nil {
		t.Fatalf("list pending purge: %v", err)
	}
	if len(pending) != 2 || pending[0].ID != "88888888-8888-8888-8888-888888888888" || pending[1].ID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" {
		t.Fatalf("expected earliest purge candidates before limit, got %+v", pending)
	}
}

func TestMemoryStoreUserDataExportValidationAndClonePointers(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.FixedZone("WAT", 60*60))
	user, err := store.UpsertUser(ctx, User{
		ID:           "33333333-3333-3333-3333-333333333333",
		PrimaryEmail: "clone@example.com",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	for name, export := range map[string]UserDataExport{
		"missing user":   {RequestedAt: now},
		"missing time":   {UserID: user.ID},
		"invalid status": {UserID: user.ID, RequestedAt: now, Status: "bogus"},
		"unknown user":   {UserID: "44444444-4444-4444-4444-444444444444", RequestedAt: now},
	} {
		_, err := store.CreateUserDataExport(ctx, export)
		if name == "unknown user" {
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: expected ErrNotFound, got %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}

	started := now.Add(time.Minute)
	completed := now.Add(2 * time.Minute)
	expires := now.Add(24 * time.Hour)
	purgeAfter := now.Add(7 * 24 * time.Hour)
	purged := now.Add(8 * 24 * time.Hour)
	job, err := store.CreateUserDataExport(ctx, UserDataExport{
		ID:                "66666666-6666-6666-6666-666666666666",
		UserID:            user.ID,
		Status:            UserDataExportStatusReady,
		BundlePath:        "bundle.zip",
		RequestedAt:       now,
		StartedAt:         &started,
		CompletedAt:       &completed,
		DownloadExpiresAt: &expires,
		PurgeAfter:        &purgeAfter,
		PurgedAt:          &purged,
	})
	if err != nil {
		t.Fatalf("create export with pointers: %v", err)
	}
	job.StartedAt = nil
	job.CompletedAt = nil
	job.DownloadExpiresAt = nil
	job.PurgeAfter = nil
	job.PurgedAt = nil

	fetched, err := store.GetUserDataExportByID(ctx, "66666666-6666-6666-6666-666666666666")
	if err != nil {
		t.Fatalf("get pointer export: %v", err)
	}
	if fetched.StartedAt == nil || fetched.CompletedAt == nil || fetched.DownloadExpiresAt == nil || fetched.PurgeAfter == nil || fetched.PurgedAt == nil {
		t.Fatalf("stored pointer fields must survive caller mutation: %+v", fetched)
	}
	if _, err := store.GetUserDataExportByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing export not found, got %v", err)
	}
	if _, err := store.ClaimNextQueuedUserDataExport(ctx, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected no queued exports, got %v", err)
	}
	if _, err := store.CompleteUserDataExport(ctx, "missing", "", 0, "", now, now, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected complete missing not found, got %v", err)
	}
	if _, err := store.FailUserDataExport(ctx, "missing", "err", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected fail missing not found, got %v", err)
	}
	if _, err := store.MarkUserDataExportPurged(ctx, "missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected purge missing not found, got %v", err)
	}
}

func TestMemoryStoreFailStaleRunningUserDataExports(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	user, err := store.UpsertUser(ctx, User{
		ID:           "22222222-2222-2222-2222-222222222222",
		PrimaryEmail: "stale@example.com",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	staleJob, err := store.CreateUserDataExport(ctx, UserDataExport{
		ID:          "11111111-1111-1111-1111-111111111111",
		UserID:      user.ID,
		RequestedAt: now.Add(-time.Hour),
		Status:      UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create stale export: %v", err)
	}
	liveJob, err := store.CreateUserDataExport(ctx, UserDataExport{
		ID:          "33333333-3333-3333-3333-333333333333",
		UserID:      user.ID,
		RequestedAt: now.Add(-30 * time.Minute),
		Status:      UserDataExportStatusQueued,
	})
	if err != nil {
		t.Fatalf("create live export: %v", err)
	}

	_, err = store.ClaimQueuedUserDataExport(ctx, staleJob.ID, now.Add(-50*time.Minute))
	if err != nil {
		t.Fatalf("claim stale export: %v", err)
	}
	_, err = store.ClaimQueuedUserDataExport(ctx, liveJob.ID, now.Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("claim live export: %v", err)
	}

	stale, err := store.FailStaleRunningUserDataExports(ctx, now.Add(-30*time.Minute), now, 5, "stale")
	if err != nil {
		t.Fatalf("fail stale exports: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("expected one stale export, got %d", len(stale))
	}
	if stale[0].ID != staleJob.ID {
		t.Fatalf("expected stale export %s got %s", staleJob.ID, stale[0].ID)
	}
	if stale[0].Status != UserDataExportStatusFailed {
		t.Fatalf("expected stale export to be failed, got %s", stale[0].Status)
	}

	live, err := store.GetUserDataExportByID(ctx, liveJob.ID)
	if err != nil {
		t.Fatalf("load live export: %v", err)
	}
	if live.Status != UserDataExportStatusRunning {
		t.Fatalf("expected live export to remain running, got %s", live.Status)
	}
}

func TestPostgresStoreUserDataExportLifecycle(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.FixedZone("WAT", 60*60)).UTC()
	jobID := "11111111-1111-1111-1111-111111111111"
	userID := "22222222-2222-2222-2222-222222222222"
	ready := UserDataExport{
		ID:                jobID,
		UserID:            userID,
		Status:            UserDataExportStatusReady,
		BundlePath:        "exports/user/job.zip",
		BundleSizeBytes:   1234,
		BundleSHA256:      "abc123",
		RequestedAt:       now,
		StartedAt:         ptrTime(now.Add(time.Minute)),
		CompletedAt:       ptrTime(now.Add(2 * time.Minute)),
		DownloadExpiresAt: ptrTime(now.Add(24 * time.Hour)),
		PurgeAfter:        ptrTime(now.Add(7 * 24 * time.Hour)),
	}

	mock.ExpectQuery("INSERT INTO user_data_exports").
		WithArgs(jobID, userID, UserDataExportStatusQueued, now).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(UserDataExport{
			ID:          jobID,
			UserID:      userID,
			Status:      UserDataExportStatusQueued,
			RequestedAt: now,
		})...))
	created, err := store.CreateUserDataExport(ctx, UserDataExport{
		ID:          " " + jobID + " ",
		UserID:      " " + userID + " ",
		RequestedAt: now,
	})
	if err != nil {
		t.Fatalf("create export: %v", err)
	}
	if created.ID != jobID || created.Status != UserDataExportStatusQueued {
		t.Fatalf("unexpected created export: %+v", created)
	}

	mock.ExpectQuery("FROM user_data_exports\\s+WHERE id = NULLIF\\(\\$1, ''\\)::uuid\\s+AND user_id = NULLIF\\(\\$2, ''\\)::uuid").
		WithArgs(jobID, userID).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(ready)...))
	scoped, err := store.GetUserDataExport(ctx, userID, jobID)
	if err != nil {
		t.Fatalf("get scoped export: %v", err)
	}
	if scoped.DownloadExpiresAt == nil || scoped.PurgeAfter == nil {
		t.Fatalf("expected nullable times to scan: %+v", scoped)
	}
	if _, err := store.GetUserDataExport(ctx, userID, "not-a-uuid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected malformed id to return not found, got %v", err)
	}

	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = NULLIF($1, '')::uuid")).
		WithArgs(jobID).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(ready)...))
	if _, err := store.GetUserDataExportByID(ctx, jobID); err != nil {
		t.Fatalf("get by id: %v", err)
	}

	mock.ExpectQuery("FROM user_data_exports").
		WithArgs(userID, 25).
		WillReturnRows(postgresUserDataExportRows().
			AddRow(postgresUserDataExportRow(ready)...).
			AddRow(postgresUserDataExportRow(UserDataExport{
				ID:          "33333333-3333-3333-3333-333333333333",
				UserID:      userID,
				Status:      UserDataExportStatusQueued,
				RequestedAt: now.Add(-time.Hour),
			})...))
	listed, err := store.ListUserDataExports(ctx, userID, 0)
	if err != nil {
		t.Fatalf("list exports: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected two listed exports, got %+v", listed)
	}

	running := ready
	running.Status = UserDataExportStatusRunning
	running.StartedAt = ptrTime(now.Add(3 * time.Minute))
	mock.ExpectQuery("WITH claimed AS").
		WithArgs(now.Add(3 * time.Minute)).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(running)...))
	claimed, err := store.ClaimNextQueuedUserDataExport(ctx, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("claim export: %v", err)
	}
	if claimed.Status != UserDataExportStatusRunning || claimed.StartedAt == nil {
		t.Fatalf("unexpected claimed export: %+v", claimed)
	}

	mock.ExpectQuery("UPDATE user_data_exports").
		WithArgs(jobID, ready.BundlePath, ready.BundleSizeBytes, ready.BundleSHA256, *ready.CompletedAt, *ready.DownloadExpiresAt, *ready.PurgeAfter).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(ready)...))
	completed, err := store.CompleteUserDataExport(ctx, " "+jobID+" ", ready.BundlePath, ready.BundleSizeBytes, ready.BundleSHA256, *ready.CompletedAt, *ready.DownloadExpiresAt, *ready.PurgeAfter)
	if err != nil {
		t.Fatalf("complete export: %v", err)
	}
	if completed.Status != UserDataExportStatusReady || completed.BundlePath == "" {
		t.Fatalf("unexpected completed export: %+v", completed)
	}

	failedAt := now.Add(4 * time.Minute)
	failed := ready
	failed.Status = UserDataExportStatusFailed
	failed.ErrorMessage = "builder failed"
	failed.CompletedAt = &failedAt
	mock.ExpectQuery("UPDATE user_data_exports").
		WithArgs(jobID, "builder failed", failedAt).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(failed)...))
	failedOut, err := store.FailUserDataExport(ctx, " "+jobID+" ", "builder failed", failedAt)
	if err != nil {
		t.Fatalf("fail export: %v", err)
	}
	if failedOut.Status != UserDataExportStatusFailed || failedOut.ErrorMessage == "" {
		t.Fatalf("unexpected failed export: %+v", failedOut)
	}

	purgeNow := now.Add(8 * 24 * time.Hour)
	mock.ExpectQuery("FROM user_data_exports").
		WithArgs(purgeNow, 100).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(ready)...))
	pending, err := store.ListUserDataExportsPendingPurge(ctx, purgeNow, 0)
	if err != nil {
		t.Fatalf("list pending purge: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != jobID {
		t.Fatalf("unexpected pending purge rows: %+v", pending)
	}

	expired := ready
	expired.Status = UserDataExportStatusExpired
	expired.BundlePath = ""
	expired.PurgedAt = &purgeNow
	mock.ExpectQuery("UPDATE user_data_exports").
		WithArgs(jobID, purgeNow).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(expired)...))
	purged, err := store.MarkUserDataExportPurged(ctx, " "+jobID+" ", purgeNow)
	if err != nil {
		t.Fatalf("mark purged: %v", err)
	}
	if purged.Status != UserDataExportStatusExpired || purged.BundlePath != "" || purged.PurgedAt == nil {
		t.Fatalf("unexpected purged export: %+v", purged)
	}

	mock.ExpectQuery("UPDATE user_data_exports").
		WithArgs(jobID, "bundle.zip", int64(1), "sha", now, now, now).
		WillReturnRows(postgresUserDataExportRows())
	if _, err := store.CompleteUserDataExport(ctx, jobID, "bundle.zip", 1, "sha", now, now, now); err == nil {
		t.Fatal("expected not found/terminal completion error")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresStoreFailStaleRunningUserDataExports(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()
	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.FixedZone("WAT", 60*60)).UTC()
	jobID := "55555555-5555-5555-5555-555555555555"
	userID := "66666666-6666-6666-6666-666666666666"
	ready := UserDataExport{
		ID:          jobID,
		UserID:      userID,
		Status:      UserDataExportStatusFailed,
		RequestedAt: now,
	}
	mock.ExpectQuery("UPDATE user_data_exports.*FROM stale").
		WithArgs(now.Add(-30*time.Minute), now, "stale", 100).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(ready)...))
	expired, err := store.FailStaleRunningUserDataExports(ctx, now.Add(-30*time.Minute), now, 0, "stale")
	if err != nil {
		t.Fatalf("fail stale exports: %v", err)
	}
	if len(expired) != 1 {
		t.Fatalf("expected one stale export, got %d", len(expired))
	}
	if expired[0].ID != jobID {
		t.Fatalf("expected stale export %s got %s", jobID, expired[0].ID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresStoreClaimQueuedUserDataExport(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	if _, err := store.ClaimQueuedUserDataExport(ctx, "", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for blank job id, got %v", err)
	}
	if _, err := store.ClaimQueuedUserDataExport(ctx, "not-a-uuid", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for malformed job id, got %v", err)
	}

	jobID := "11111111-1111-1111-1111-111111111111"
	userID := "22222222-2222-2222-2222-222222222222"
	mock.ExpectQuery("UPDATE user_data_exports").
		WithArgs(jobID, now).
		WillReturnRows(postgresUserDataExportRows().AddRow(postgresUserDataExportRow(UserDataExport{
			ID:          jobID,
			UserID:      userID,
			Status:      UserDataExportStatusRunning,
			RequestedAt: now,
			StartedAt:   ptrTime(now),
		})...))
	claimed, err := store.ClaimQueuedUserDataExport(ctx, " "+jobID+" ", now)
	if err != nil {
		t.Fatalf("claim queued export: %v", err)
	}
	if claimed.ID != jobID || claimed.Status != UserDataExportStatusRunning || claimed.StartedAt == nil {
		t.Fatalf("unexpected claimed export: %+v", claimed)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresStoreFailUserDataExportTerminalError(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := context.Background()

	jobID := "33333333-3333-3333-3333-333333333333"
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("UPDATE user_data_exports").
		WithArgs(jobID, "still running", now).
		WillReturnRows(postgresUserDataExportRows())
	_, err = store.FailUserDataExport(ctx, " "+jobID+" ", "still running", now)
	if err == nil || err.Error() != "user_data_export  "+jobID+"  not in queued/running state" {
		t.Fatalf("expected terminal-state failure, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func ptrTime(t time.Time) *time.Time {
	utc := t.UTC()
	return &utc
}

func postgresUserDataExportRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id",
		"user_id",
		"status",
		"bundle_path",
		"bundle_size_bytes",
		"bundle_sha256",
		"error_message",
		"requested_at",
		"started_at",
		"completed_at",
		"download_expires_at",
		"purge_after",
		"purged_at",
	})
}

func postgresUserDataExportRow(export UserDataExport) []driver.Value {
	return []driver.Value{
		export.ID,
		export.UserID,
		export.Status,
		export.BundlePath,
		export.BundleSizeBytes,
		export.BundleSHA256,
		export.ErrorMessage,
		export.RequestedAt,
		nullableTimePointer(export.StartedAt),
		nullableTimePointer(export.CompletedAt),
		nullableTimePointer(export.DownloadExpiresAt),
		nullableTimePointer(export.PurgeAfter),
		nullableTimePointer(export.PurgedAt),
	}
}
