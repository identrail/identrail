package db

import (
	"bytes"
	"context"
	"encoding/hex"
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
	session.LastSeenAt = now.UTC()
	nextIdle := now.Add(15 * time.Minute).UTC()
	if nextIdle.After(session.AbsoluteExpiresAt) {
		nextIdle = session.AbsoluteExpiresAt
	}
	session.IdleExpiresAt = nextIdle
	user, exists := m.users[session.UserID]
	if !exists || user.DeletedAt != nil || user.Status != "active" {
		return Session{}, ErrNotFound
	}
	session.User = &user
	m.sessions[key] = session
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
