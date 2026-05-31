package db

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/audit"
)

func userIdentityLookupKey(provider string, subject string) string {
	return strings.ToLower(strings.TrimSpace(provider)) + "\x00" + strings.TrimSpace(subject)
}

func sessionHashKey(hash []byte) string {
	return hex.EncodeToString(hash)
}

// UpsertUser persists one account row.
func (m *MemoryStore) UpsertUser(ctx context.Context, user User) (User, error) {
	normalized, err := NormalizeUserForWrite(user)
	if err != nil {
		return User{}, err
	}
	m.mu.Lock()
	for id, existing := range m.users {
		if existing.PrimaryEmail == normalized.PrimaryEmail && id != normalized.ID {
			m.mu.Unlock()
			return User{}, ErrConflict
		}
	}
	m.users[normalized.ID] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.upsert",
		ResourceType: "user",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return normalized, nil
}

// UpdateUserProfile refreshes user metadata without changing account status.
func (m *MemoryStore) UpdateUserProfile(ctx context.Context, user User) (User, error) {
	normalized, err := NormalizeUserForWrite(user)
	if err != nil {
		return User{}, err
	}
	m.mu.Lock()
	existing, exists := m.users[normalized.ID]
	if !exists {
		m.mu.Unlock()
		return User{}, ErrNotFound
	}
	for id, other := range m.users {
		if other.PrimaryEmail == normalized.PrimaryEmail && id != normalized.ID {
			m.mu.Unlock()
			return User{}, ErrConflict
		}
	}
	existing.PrimaryEmail = normalized.PrimaryEmail
	existing.DisplayName = normalized.DisplayName
	existing.AvatarURL = normalized.AvatarURL
	existing.UpdatedAt = normalized.UpdatedAt
	existing.DeletedAt = normalized.DeletedAt
	m.users[normalized.ID] = existing
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.profile_update",
		ResourceType: "user",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return existing, nil
}

// UpdateCurrentUserProfile updates only self-service mutable profile fields.
// It leaves email and lifecycle fields untouched and requires an active row.
func (m *MemoryStore) UpdateCurrentUserProfile(ctx context.Context, userID string, displayName *string, avatarURL *string, updatedAt time.Time) (User, error) {
	id := strings.TrimSpace(userID)
	m.mu.Lock()
	existing, exists := m.users[id]
	if !exists || existing.Status != "active" {
		m.mu.Unlock()
		return User{}, ErrNotFound
	}
	if displayName != nil {
		existing.DisplayName = strings.TrimSpace(*displayName)
	}
	if avatarURL != nil {
		existing.AvatarURL = strings.TrimSpace(*avatarURL)
	}
	existing.UpdatedAt = updatedAt.UTC()
	m.users[id] = existing
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.profile_update",
		ResourceType: "user",
		ResourceID:   id,
		Outcome:      "success",
	})
	return existing, nil
}

// GetUser returns one account by UUID.
func (m *MemoryStore) GetUser(ctx context.Context, userID string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, exists := m.users[strings.TrimSpace(userID)]
	if !exists {
		return User{}, ErrNotFound
	}
	return user, nil
}

// GetUserByPrimaryEmail returns one account by normalized primary email.
func (m *MemoryStore) GetUserByPrimaryEmail(ctx context.Context, email string) (User, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, user := range m.users {
		if user.PrimaryEmail == normalizedEmail {
			return user, nil
		}
	}
	return User{}, ErrNotFound
}

// SetUserStatus transitions one account between lifecycle states. Calling with
// the user's current status is a no-op write and still returns the row, so the
// API layer can treat double-clicks as idempotent successes.
func (m *MemoryStore) SetUserStatus(ctx context.Context, userID string, status string, now time.Time) (User, error) {
	normalizedStatus := strings.ToLower(strings.TrimSpace(status))
	if _, ok := validUserStatuses[normalizedStatus]; !ok {
		return User{}, fmt.Errorf("invalid user status")
	}
	id := strings.TrimSpace(userID)
	m.mu.Lock()
	user, exists := m.users[id]
	if !exists {
		m.mu.Unlock()
		return User{}, ErrNotFound
	}
	user.Status = normalizedStatus
	user.UpdatedAt = now.UTC()
	m.users[id] = user
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.status.update",
		ResourceType: "user",
		ResourceID:   id,
		Outcome:      "success",
	})
	return user, nil
}

// SoftDeleteUser flips the account to status=deleted and stamps deleted_at to
// open the reversible grace window. Re-deleting an already-deleted account is a
// no-op that preserves the original deleted_at so the purge deadline cannot be
// pushed back by repeat calls.
func (m *MemoryStore) SoftDeleteUser(ctx context.Context, userID string, now time.Time) (User, error) {
	id := strings.TrimSpace(userID)
	when := now.UTC()
	m.mu.Lock()
	user, exists := m.users[id]
	if !exists {
		m.mu.Unlock()
		return User{}, ErrNotFound
	}
	if user.DeletedAt == nil {
		deletedAt := when
		user.DeletedAt = &deletedAt
	}
	user.Status = "deleted"
	user.UpdatedAt = when
	m.users[id] = user
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.delete",
		ResourceType: "user",
		ResourceID:   id,
		Outcome:      "success",
	})
	return user, nil
}

// CancelUserDeletion reverses a soft delete: it clears deleted_at and returns
// the account to active.
func (m *MemoryStore) CancelUserDeletion(ctx context.Context, userID string, now time.Time) (User, error) {
	id := strings.TrimSpace(userID)
	when := now.UTC()
	m.mu.Lock()
	user, exists := m.users[id]
	if !exists {
		m.mu.Unlock()
		return User{}, ErrNotFound
	}
	user.Status = "active"
	user.DeletedAt = nil
	user.UpdatedAt = when
	m.users[id] = user
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.delete.cancel",
		ResourceType: "user",
		ResourceID:   id,
		Outcome:      "success",
	})
	return user, nil
}

// ListUsersPendingHardDelete returns soft-deleted accounts whose grace window
// closed and whose PII has not already been purged.
func (m *MemoryStore) ListUsersPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]User, error) {
	cutoff := deletedBefore.UTC()
	if limit <= 0 {
		limit = 100
	}
	m.mu.RLock()
	pending := make([]User, 0)
	for _, user := range m.users {
		if user.Status != "deleted" || user.DeletedAt == nil {
			continue
		}
		if !user.DeletedAt.UTC().Before(cutoff) {
			continue
		}
		if IsHardDeletedTombstoneEmailForUser(user.PrimaryEmail, user.ID) {
			continue
		}
		pending = append(pending, user)
	}
	m.mu.RUnlock()
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].DeletedAt.Equal(*pending[j].DeletedAt) {
			return pending[i].ID < pending[j].ID
		}
		return pending[i].DeletedAt.Before(*pending[j].DeletedAt)
	})
	if len(pending) > limit {
		pending = pending[:limit]
	}
	return pending, nil
}

// HardDeleteUser purges PII from a soft-deleted account while keeping the row
// so audit references by UUID remain valid. It deletes provider identities
// (which carry raw IdP claims) and any session rows, and is safely re-runnable.
func (m *MemoryStore) HardDeleteUser(ctx context.Context, userID string, now time.Time) (User, error) {
	id := strings.TrimSpace(userID)
	when := now.UTC()
	m.mu.Lock()
	user, exists := m.users[id]
	if !exists {
		m.mu.Unlock()
		return User{}, ErrNotFound
	}
	// Refuse unless the row is actually pending deletion. Without this guard
	// a misuse against an active account would silently purge PII. The worker
	// only ever invokes this on rows returned by ListUsersPendingHardDelete,
	// but the defense keeps a programming error from being unrecoverable.
	if user.Status != "deleted" || user.DeletedAt == nil {
		m.mu.Unlock()
		return User{}, fmt.Errorf("hard delete: user %s is not pending deletion (status=%q)", id, user.Status)
	}
	user.PrimaryEmail = HardDeletedTombstoneEmail(id)
	user.DisplayName = ""
	user.AvatarURL = ""
	user.Status = "deleted"
	user.UpdatedAt = when
	m.users[id] = user
	for identityID, identity := range m.userIdentityByID {
		if identity.UserID != id {
			continue
		}
		delete(m.userIdentityByID, identityID)
		for key, mappedID := range m.userIdentityByProviderSubject {
			if mappedID == identityID {
				delete(m.userIdentityByProviderSubject, key)
			}
		}
	}
	for key, session := range m.sessions {
		if session.UserID == id {
			delete(m.sessions, key)
		}
	}
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.hard_delete",
		ResourceType: "user",
		ResourceID:   id,
		Outcome:      "success",
	})
	return user, nil
}

// UpsertUserIdentity persists one provider identity mapping.
func (m *MemoryStore) UpsertUserIdentity(ctx context.Context, identity UserIdentity) (UserIdentity, error) {
	normalized, err := NormalizeUserIdentityForWrite(identity)
	if err != nil {
		return UserIdentity{}, err
	}
	m.mu.Lock()
	if _, exists := m.users[normalized.UserID]; !exists {
		m.mu.Unlock()
		return UserIdentity{}, ErrNotFound
	}
	lookupKey := userIdentityLookupKey(normalized.Provider, normalized.Subject)
	if existingID, exists := m.userIdentityByProviderSubject[lookupKey]; exists && existingID != normalized.ID {
		delete(m.userIdentityByID, existingID)
	}
	for key, existingID := range m.userIdentityByProviderSubject {
		if existingID == normalized.ID && key != lookupKey {
			delete(m.userIdentityByProviderSubject, key)
		}
	}
	m.userIdentityByID[normalized.ID] = normalized
	m.userIdentityByProviderSubject[lookupKey] = normalized.ID
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity.upsert",
		ResourceType: "user_identity",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return normalized, nil
}

// GetUserIdentity returns one provider identity by provider and subject.
func (m *MemoryStore) GetUserIdentity(ctx context.Context, provider string, subject string) (UserIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, exists := m.userIdentityByProviderSubject[userIdentityLookupKey(provider, subject)]
	if !exists {
		return UserIdentity{}, ErrNotFound
	}
	identity, exists := m.userIdentityByID[id]
	if !exists {
		return UserIdentity{}, ErrNotFound
	}
	return identity, nil
}

// GetUserIdentityByProviderUserID returns one provider identity for a user.
func (m *MemoryStore) GetUserIdentityByProviderUserID(ctx context.Context, provider string, userID string) (UserIdentity, error) {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	normalizedUserID := strings.TrimSpace(userID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	var match UserIdentity
	found := false
	for _, identity := range m.userIdentityByID {
		if identity.Provider != normalizedProvider || identity.UserID != normalizedUserID {
			continue
		}
		if found {
			return UserIdentity{}, ErrConflict
		}
		match = identity
		found = true
	}
	if !found {
		return UserIdentity{}, ErrNotFound
	}
	return match, nil
}

// ListUserIdentitiesByProvider returns provider identities ordered by newest first.
// A non-positive limit returns all matching identities.
func (m *MemoryStore) ListUserIdentitiesByProvider(ctx context.Context, provider string, limit int) ([]UserIdentity, error) {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]UserIdentity, 0)
	for _, identity := range m.userIdentityByID {
		if identity.Provider != normalizedProvider {
			continue
		}
		items = append(items, identity)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// DeleteUserIdentity removes one provider identity by provider and subject.
func (m *MemoryStore) DeleteUserIdentity(ctx context.Context, provider string, subject string) error {
	lookupKey := userIdentityLookupKey(provider, subject)
	m.mu.Lock()
	id, exists := m.userIdentityByProviderSubject[lookupKey]
	if !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	for key, mappedID := range m.userIdentityByProviderSubject {
		if mappedID == id {
			delete(m.userIdentityByProviderSubject, key)
		}
	}
	delete(m.userIdentityByID, id)
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity.delete",
		ResourceType: "user_identity",
		ResourceID:   id,
		Outcome:      "success",
	})
	return nil
}

// CreateSession persists one server-side session.
func (m *MemoryStore) CreateSession(ctx context.Context, session Session) (Session, error) {
	normalized, err := NormalizeSessionForWrite(session)
	if err != nil {
		return Session{}, err
	}
	m.mu.Lock()
	user, exists := m.users[normalized.UserID]
	if !exists {
		m.mu.Unlock()
		return Session{}, ErrNotFound
	}
	if user.DeletedAt != nil || user.Status != "active" {
		m.mu.Unlock()
		return Session{}, ErrNotFound
	}
	normalized.User = &user
	m.sessions[sessionHashKey(normalized.ID)] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.create",
		ResourceType: "session",
		ResourceID:   sessionHashKey(normalized.ID),
		Outcome:      "success",
	})
	return normalized, nil
}

// TouchSession renews idle expiry and returns the joined session/user row.
func (m *MemoryStore) TouchSession(ctx context.Context, sessionIDHash []byte, now time.Time) (Session, error) {
	return m.touchSessionInternal(sessionIDHash, now, false)
}

// TouchSessionAllowingPendingDeletion is the lenient variant the cancel-deletion
// route mounts: it accepts cookies belonging to users whose status is `deleted`
// and whose grace window has not closed yet, so a freshly-soft-deleted user can
// still hit `/v1/me/cancel-deletion` while every other route keeps refusing.
func (m *MemoryStore) TouchSessionAllowingPendingDeletion(ctx context.Context, sessionIDHash []byte, now time.Time) (Session, error) {
	return m.touchSessionInternal(sessionIDHash, now, true)
}

func (m *MemoryStore) touchSessionInternal(sessionIDHash []byte, now time.Time, allowPendingDeletion bool) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sessionHashKey(sessionIDHash)
	session, exists := m.sessions[key]
	if !exists {
		return Session{}, ErrNotFound
	}
	if session.RevokedAt != nil || !session.IdleExpiresAt.After(now) || !session.AbsoluteExpiresAt.After(now) {
		return Session{}, ErrNotFound
	}
	user, exists := m.users[session.UserID]
	if !exists {
		return Session{}, ErrNotFound
	}
	userActive := user.DeletedAt == nil && user.Status == "active"
	if !userActive {
		if !allowPendingDeletion {
			return Session{}, ErrNotFound
		}
		// Lenient path: accept soft-deleted accounts so the cancel-deletion
		// handler can serve them. The 30-day grace gate is enforced at the
		// handler level (returning 410 past the window) rather than here, so
		// the past-grace branch stays reachable for callers to receive a
		// well-formed `grace_period_expired` response instead of a bare 401.
		if user.Status != "deleted" || user.DeletedAt == nil {
			return Session{}, ErrNotFound
		}
	}
	seenAt := now.UTC()
	session.LastSeenAt = seenAt
	nextIdle := seenAt.Add(SessionIdleTimeout)
	if nextIdle.After(session.AbsoluteExpiresAt) {
		nextIdle = session.AbsoluteExpiresAt
	}
	session.IdleExpiresAt = nextIdle
	session.User = &user
	m.sessions[key] = session
	return session, nil
}

// UpdateSessionContext persists the active tenancy context for one browser session.
func (m *MemoryStore) UpdateSessionContext(ctx context.Context, userID string, sessionIDHash []byte, orgID string, workspaceID string, projectID string, now time.Time) (Session, error) {
	m.mu.Lock()
	key := sessionHashKey(sessionIDHash)
	session, exists := m.sessions[key]
	if !exists || session.UserID != strings.TrimSpace(userID) || session.RevokedAt != nil {
		m.mu.Unlock()
		return Session{}, ErrNotFound
	}
	if !session.IdleExpiresAt.After(now) || !session.AbsoluteExpiresAt.After(now) {
		m.mu.Unlock()
		return Session{}, ErrNotFound
	}
	user, exists := m.users[session.UserID]
	if !exists || user.DeletedAt != nil || user.Status != "active" {
		m.mu.Unlock()
		return Session{}, ErrNotFound
	}
	session.CurrentOrgID = strings.TrimSpace(orgID)
	session.CurrentWorkspaceID = strings.TrimSpace(workspaceID)
	session.CurrentProjectID = strings.TrimSpace(projectID)
	session.LastSeenAt = now.UTC()
	session.User = &user
	m.sessions[key] = session
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.scope_update",
		ResourceType: "session",
		ResourceID:   key,
		Outcome:      "success",
	})
	return session, nil
}

// ListUserSessions returns active sessions for one user.
func (m *MemoryStore) ListUserSessions(ctx context.Context, userID string, now time.Time, limit int) ([]Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	items := make([]Session, 0, limit)
	for _, session := range m.sessions {
		if session.UserID != strings.TrimSpace(userID) {
			continue
		}
		if session.RevokedAt != nil || !session.IdleExpiresAt.After(now) || !session.AbsoluteExpiresAt.After(now) {
			continue
		}
		items = append(items, session)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].LastSeenAt.After(items[j].LastSeenAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// RevokeUserSession revokes one active session if it belongs to the user.
func (m *MemoryStore) RevokeUserSession(ctx context.Context, userID string, sessionIDHash []byte, revokedAt time.Time) (Session, error) {
	m.mu.Lock()
	key := sessionHashKey(sessionIDHash)
	session, exists := m.sessions[key]
	if !exists || session.UserID != strings.TrimSpace(userID) || session.RevokedAt != nil {
		m.mu.Unlock()
		return Session{}, ErrNotFound
	}
	when := revokedAt.UTC()
	session.RevokedAt = &when
	m.sessions[key] = session
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.revoke",
		ResourceType: "session",
		ResourceID:   key,
		Outcome:      "success",
	})
	return session, nil
}

// RevokeOtherUserSessions revokes every active session except the caller's.
func (m *MemoryStore) RevokeOtherUserSessions(ctx context.Context, userID string, currentSessionIDHash []byte, revokedAt time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	when := revokedAt.UTC()
	count := 0
	for key, session := range m.sessions {
		if session.UserID != strings.TrimSpace(userID) || session.RevokedAt != nil {
			continue
		}
		if bytes.Equal(session.ID, currentSessionIDHash) {
			continue
		}
		session.RevokedAt = &when
		m.sessions[key] = session
		count++
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.revoke_others",
		ResourceType: "session",
		ResourceID:   strings.TrimSpace(userID),
		Outcome:      "success",
	})
	return count, nil
}

// RevokeAllUserSessions revokes every active session for one user.
func (m *MemoryStore) RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	when := revokedAt.UTC()
	count := 0
	for key, session := range m.sessions {
		if session.UserID != strings.TrimSpace(userID) || session.RevokedAt != nil {
			continue
		}
		session.RevokedAt = &when
		m.sessions[key] = session
		count++
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.revoke_all",
		ResourceType: "session",
		ResourceID:   strings.TrimSpace(userID),
		Outcome:      "success",
	})
	return count, nil
}
