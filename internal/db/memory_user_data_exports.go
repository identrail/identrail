package db

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CreateUserDataExport inserts a queued export job for the user.
func (m *MemoryStore) CreateUserDataExport(ctx context.Context, export UserDataExport) (UserDataExport, error) {
	normalized, err := normalizeUserDataExportForCreate(export)
	if err != nil {
		return UserDataExport{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[normalized.UserID]; !exists {
		return UserDataExport{}, ErrNotFound
	}
	if _, exists := m.userDataExports[normalized.ID]; exists {
		return UserDataExport{}, ErrConflict
	}
	m.userDataExports[normalized.ID] = normalized
	return cloneUserDataExport(normalized), nil
}

// GetUserDataExport returns the export job iff it belongs to the named user.
func (m *MemoryStore) GetUserDataExport(ctx context.Context, userID string, jobID string) (UserDataExport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	export, exists := m.userDataExports[strings.TrimSpace(jobID)]
	if !exists || export.UserID != strings.TrimSpace(userID) {
		return UserDataExport{}, ErrNotFound
	}
	return cloneUserDataExport(export), nil
}

// GetUserDataExportByID returns the export job by id, ignoring caller scoping.
// The caller is responsible for authorizing the access (the download route
// proves authorization via HMAC token).
func (m *MemoryStore) GetUserDataExportByID(ctx context.Context, jobID string) (UserDataExport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	export, exists := m.userDataExports[strings.TrimSpace(jobID)]
	if !exists {
		return UserDataExport{}, ErrNotFound
	}
	return cloneUserDataExport(export), nil
}

// ListUserDataExports returns the user's exports newest-first.
func (m *MemoryStore) ListUserDataExports(ctx context.Context, userID string, limit int) ([]UserDataExport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 25
	}
	normalizedUserID := strings.TrimSpace(userID)
	items := make([]UserDataExport, 0, limit)
	for _, export := range m.userDataExports {
		if export.UserID != normalizedUserID {
			continue
		}
		items = append(items, cloneUserDataExport(export))
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].RequestedAt.After(items[j].RequestedAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// ClaimNextQueuedUserDataExport pops the oldest queued job and marks it
// running. Returns ErrNotFound when nothing is queued.
func (m *MemoryStore) ClaimNextQueuedUserDataExport(ctx context.Context, now time.Time) (UserDataExport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var oldestID string
	var oldestRequested time.Time
	for id, export := range m.userDataExports {
		if export.Status != UserDataExportStatusQueued {
			continue
		}
		if oldestID == "" || export.RequestedAt.Before(oldestRequested) {
			oldestID = id
			oldestRequested = export.RequestedAt
		}
	}
	if oldestID == "" {
		return UserDataExport{}, ErrNotFound
	}
	when := now.UTC()
	export := m.userDataExports[oldestID]
	export.Status = UserDataExportStatusRunning
	export.StartedAt = &when
	m.userDataExports[oldestID] = export
	return cloneUserDataExport(export), nil
}

// ClaimQueuedUserDataExport marks the named queued job running. Returns
// ErrNotFound when the job is already claimed or terminal.
func (m *MemoryStore) ClaimQueuedUserDataExport(ctx context.Context, jobID string, now time.Time) (UserDataExport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	export, exists := m.userDataExports[strings.TrimSpace(jobID)]
	if !exists || export.Status != UserDataExportStatusQueued {
		return UserDataExport{}, ErrNotFound
	}
	when := now.UTC()
	export.Status = UserDataExportStatusRunning
	export.StartedAt = &when
	m.userDataExports[export.ID] = export
	return cloneUserDataExport(export), nil
}

// CompleteUserDataExport marks the job ready and records bundle metadata.
func (m *MemoryStore) CompleteUserDataExport(ctx context.Context, jobID string, bundlePath string, sizeBytes int64, sha256Hex string, completedAt time.Time, downloadExpiresAt time.Time, purgeAfter time.Time) (UserDataExport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	export, exists := m.userDataExports[strings.TrimSpace(jobID)]
	if !exists {
		return UserDataExport{}, ErrNotFound
	}
	if export.Status != UserDataExportStatusRunning && export.Status != UserDataExportStatusQueued {
		return UserDataExport{}, fmt.Errorf("user_data_export %s cannot complete from status %q", jobID, export.Status)
	}
	completed := completedAt.UTC()
	expires := downloadExpiresAt.UTC()
	purge := purgeAfter.UTC()
	export.Status = UserDataExportStatusReady
	export.BundlePath = bundlePath
	export.BundleSizeBytes = sizeBytes
	export.BundleSHA256 = sha256Hex
	export.CompletedAt = &completed
	export.DownloadExpiresAt = &expires
	export.PurgeAfter = &purge
	export.ErrorMessage = ""
	m.userDataExports[export.ID] = export
	return cloneUserDataExport(export), nil
}

// FailUserDataExport marks a job failed.
func (m *MemoryStore) FailUserDataExport(ctx context.Context, jobID string, errMsg string, failedAt time.Time) (UserDataExport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	export, exists := m.userDataExports[strings.TrimSpace(jobID)]
	if !exists {
		return UserDataExport{}, ErrNotFound
	}
	if export.Status != UserDataExportStatusRunning && export.Status != UserDataExportStatusQueued {
		return UserDataExport{}, fmt.Errorf("user_data_export %s cannot fail from status %q", jobID, export.Status)
	}
	when := failedAt.UTC()
	export.Status = UserDataExportStatusFailed
	export.ErrorMessage = errMsg
	export.CompletedAt = &when
	m.userDataExports[export.ID] = export
	return cloneUserDataExport(export), nil
}

// FailStaleRunningUserDataExports marks old running jobs failed so interrupted
// workers cannot leave exports stuck running forever.
func (m *MemoryStore) FailStaleRunningUserDataExports(ctx context.Context, startedBefore time.Time, failedAt time.Time, limit int, errMsg string) ([]UserDataExport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	cutoff := startedBefore.UTC()
	candidates := make([]UserDataExport, 0)
	for _, export := range m.userDataExports {
		if export.Status != UserDataExportStatusRunning || export.StartedAt == nil || !export.StartedAt.Before(cutoff) {
			continue
		}
		candidates = append(candidates, export)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].StartedAt.Before(*candidates[j].StartedAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	when := failedAt.UTC()
	updated := make([]UserDataExport, 0, len(candidates))
	for _, export := range candidates {
		export.Status = UserDataExportStatusFailed
		export.ErrorMessage = errMsg
		export.CompletedAt = &when
		m.userDataExports[export.ID] = export
		updated = append(updated, cloneUserDataExport(export))
	}
	return updated, nil
}

// ListUserDataExportsPendingPurge returns ready jobs past their retention
// window whose bundle file has not yet been removed.
func (m *MemoryStore) ListUserDataExportsPendingPurge(ctx context.Context, now time.Time, limit int) ([]UserDataExport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	cutoff := now.UTC()
	items := make([]UserDataExport, 0)
	for _, export := range m.userDataExports {
		if export.PurgedAt != nil {
			continue
		}
		if export.PurgeAfter == nil || export.PurgeAfter.After(cutoff) {
			continue
		}
		items = append(items, cloneUserDataExport(export))
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].PurgeAfter.Before(*items[j].PurgeAfter)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// MarkUserDataExportPurged transitions a job to expired and stamps purged_at.
func (m *MemoryStore) MarkUserDataExportPurged(ctx context.Context, jobID string, now time.Time) (UserDataExport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	export, exists := m.userDataExports[strings.TrimSpace(jobID)]
	if !exists {
		return UserDataExport{}, ErrNotFound
	}
	when := now.UTC()
	export.Status = UserDataExportStatusExpired
	export.PurgedAt = &when
	// Clear bundle pointer so a later download attempt cannot reach a deleted
	// file.
	export.BundlePath = ""
	m.userDataExports[export.ID] = export
	return cloneUserDataExport(export), nil
}

func normalizeUserDataExportForCreate(export UserDataExport) (UserDataExport, error) {
	normalized := export
	normalized.ID = strings.TrimSpace(normalized.ID)
	normalized.UserID = strings.TrimSpace(normalized.UserID)
	if normalized.UserID == "" {
		return UserDataExport{}, errors.New("user_data_export: user_id is required")
	}
	if normalized.RequestedAt.IsZero() {
		return UserDataExport{}, errors.New("user_data_export: requested_at is required")
	}
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	}
	if normalized.Status == "" {
		normalized.Status = UserDataExportStatusQueued
	}
	if _, ok := validUserDataExportStatuses[normalized.Status]; !ok {
		return UserDataExport{}, fmt.Errorf("user_data_export: invalid status %q", normalized.Status)
	}
	normalized.RequestedAt = normalized.RequestedAt.UTC()
	if normalized.StartedAt != nil {
		t := normalized.StartedAt.UTC()
		normalized.StartedAt = &t
	}
	if normalized.CompletedAt != nil {
		t := normalized.CompletedAt.UTC()
		normalized.CompletedAt = &t
	}
	if normalized.DownloadExpiresAt != nil {
		t := normalized.DownloadExpiresAt.UTC()
		normalized.DownloadExpiresAt = &t
	}
	if normalized.PurgeAfter != nil {
		t := normalized.PurgeAfter.UTC()
		normalized.PurgeAfter = &t
	}
	return normalized, nil
}

func cloneUserDataExport(export UserDataExport) UserDataExport {
	clone := export
	if export.StartedAt != nil {
		t := export.StartedAt.UTC()
		clone.StartedAt = &t
	}
	if export.CompletedAt != nil {
		t := export.CompletedAt.UTC()
		clone.CompletedAt = &t
	}
	if export.DownloadExpiresAt != nil {
		t := export.DownloadExpiresAt.UTC()
		clone.DownloadExpiresAt = &t
	}
	if export.PurgeAfter != nil {
		t := export.PurgeAfter.UTC()
		clone.PurgeAfter = &t
	}
	if export.PurgedAt != nil {
		t := export.PurgedAt.UTC()
		clone.PurgedAt = &t
	}
	return clone
}
