package db

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/audit"
)

func orgScopedKey(orgID string, id string) string {
	return strings.TrimSpace(orgID) + "\x00" + strings.TrimSpace(id)
}

// CreateInvitation persists one invitation scaffold.
func (m *MemoryStore) CreateInvitation(ctx context.Context, invitation Invitation) (Invitation, error) {
	normalized, err := NormalizeInvitationForWrite(invitation)
	if err != nil {
		return Invitation{}, err
	}
	m.mu.Lock()
	if _, exists := m.organizations[normalized.OrgID]; !exists {
		m.mu.Unlock()
		return Invitation{}, ErrNotFound
	}
	if normalized.InvitedByUserID != "" {
		if _, exists := m.users[normalized.InvitedByUserID]; !exists {
			m.mu.Unlock()
			return Invitation{}, ErrNotFound
		}
	}
	key := orgScopedKey(normalized.OrgID, normalized.ID)
	if _, exists := m.invitations[key]; exists {
		m.mu.Unlock()
		return Invitation{}, ErrConflict
	}
	for _, existing := range m.invitations {
		if existing.OrgID == normalized.OrgID &&
			strings.EqualFold(existing.Email, normalized.Email) &&
			existing.AcceptedAt == nil &&
			existing.RevokedAt == nil {
			m.mu.Unlock()
			return Invitation{}, ErrConflict
		}
	}
	m.invitations[key] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.invitation.create",
		TenantID:     normalized.OrgID,
		ResourceType: "invitation",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return normalized, nil
}

// GetInvitation returns one organization invitation scaffold.
func (m *MemoryStore) GetInvitation(ctx context.Context, orgID string, invitationID string) (Invitation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	invitation, exists := m.invitations[orgScopedKey(orgID, invitationID)]
	if !exists {
		return Invitation{}, ErrNotFound
	}
	return invitation, nil
}

// ListInvitations returns organization invitations ordered by newest first.
func (m *MemoryStore) ListInvitations(ctx context.Context, orgID string, limit int) ([]Invitation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	orgID = strings.TrimSpace(orgID)
	items := make([]Invitation, 0, limit)
	for _, invitation := range m.invitations {
		if invitation.OrgID != orgID {
			continue
		}
		items = append(items, invitation)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// RevokeInvitation marks one pending invitation revoked.
func (m *MemoryStore) RevokeInvitation(ctx context.Context, orgID string, invitationID string, revokedAt time.Time) (Invitation, error) {
	m.mu.Lock()
	key := orgScopedKey(orgID, invitationID)
	invitation, exists := m.invitations[key]
	if !exists || invitation.RevokedAt != nil {
		m.mu.Unlock()
		return Invitation{}, ErrNotFound
	}
	when := revokedAt.UTC()
	invitation.RevokedAt = &when
	m.invitations[key] = invitation
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.invitation.revoke",
		TenantID:     strings.TrimSpace(orgID),
		ResourceType: "invitation",
		ResourceID:   strings.TrimSpace(invitationID),
		Outcome:      "success",
	})
	return invitation, nil
}

// CreateVerifiedDomain persists one domain-verification scaffold.
func (m *MemoryStore) CreateVerifiedDomain(ctx context.Context, domain VerifiedDomain) (VerifiedDomain, error) {
	normalized, err := NormalizeVerifiedDomainForWrite(domain)
	if err != nil {
		return VerifiedDomain{}, err
	}
	m.mu.Lock()
	if _, exists := m.organizations[normalized.OrgID]; !exists {
		m.mu.Unlock()
		return VerifiedDomain{}, ErrNotFound
	}
	key := orgScopedKey(normalized.OrgID, normalized.ID)
	if _, exists := m.verifiedDomains[key]; exists {
		m.mu.Unlock()
		return VerifiedDomain{}, ErrConflict
	}
	for _, existing := range m.verifiedDomains {
		if existing.OrgID == normalized.OrgID && strings.EqualFold(existing.Domain, normalized.Domain) {
			m.mu.Unlock()
			return VerifiedDomain{}, ErrConflict
		}
	}
	m.verifiedDomains[key] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.domain.create",
		TenantID:     normalized.OrgID,
		ResourceType: "verified_domain",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return normalized, nil
}

// GetVerifiedDomain returns one organization domain-verification scaffold.
func (m *MemoryStore) GetVerifiedDomain(ctx context.Context, orgID string, domainID string) (VerifiedDomain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	domain, exists := m.verifiedDomains[orgScopedKey(orgID, domainID)]
	if !exists {
		return VerifiedDomain{}, ErrNotFound
	}
	return domain, nil
}

// ListVerifiedDomains returns organization domain-verification scaffolds ordered by newest first.
func (m *MemoryStore) ListVerifiedDomains(ctx context.Context, orgID string, limit int) ([]VerifiedDomain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	orgID = strings.TrimSpace(orgID)
	items := make([]VerifiedDomain, 0, limit)
	for _, domain := range m.verifiedDomains {
		if domain.OrgID != orgID {
			continue
		}
		items = append(items, domain)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// CreateIdentityConnection persists one enterprise identity connection scaffold.
func (m *MemoryStore) CreateIdentityConnection(ctx context.Context, connection IdentityConnection) (IdentityConnection, error) {
	normalized, err := NormalizeIdentityConnectionForWrite(connection)
	if err != nil {
		return IdentityConnection{}, err
	}
	m.mu.Lock()
	if _, exists := m.organizations[normalized.OrgID]; !exists {
		m.mu.Unlock()
		return IdentityConnection{}, ErrNotFound
	}
	key := orgScopedKey(normalized.OrgID, normalized.ID)
	if _, exists := m.identityConnections[key]; exists {
		m.mu.Unlock()
		return IdentityConnection{}, ErrConflict
	}
	for _, existing := range m.identityConnections {
		if existing.OrgID == normalized.OrgID &&
			existing.Provider == normalized.Provider &&
			existing.Type == normalized.Type {
			m.mu.Unlock()
			return IdentityConnection{}, ErrConflict
		}
		if normalized.WorkOSConnectionID != "" && existing.WorkOSConnectionID == normalized.WorkOSConnectionID {
			m.mu.Unlock()
			return IdentityConnection{}, ErrConflict
		}
	}
	m.identityConnections[key] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity_connection.create",
		TenantID:     normalized.OrgID,
		ResourceType: "identity_connection",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return normalized, nil
}

// GetIdentityConnection returns one organization identity connection scaffold.
func (m *MemoryStore) GetIdentityConnection(ctx context.Context, orgID string, connectionID string) (IdentityConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	connection, exists := m.identityConnections[orgScopedKey(orgID, connectionID)]
	if !exists {
		return IdentityConnection{}, ErrNotFound
	}
	return connection, nil
}

// ListIdentityConnections returns organization identity connection scaffolds ordered by newest first.
func (m *MemoryStore) ListIdentityConnections(ctx context.Context, orgID string, limit int) ([]IdentityConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	orgID = strings.TrimSpace(orgID)
	items := make([]IdentityConnection, 0, limit)
	for _, connection := range m.identityConnections {
		if connection.OrgID != orgID {
			continue
		}
		items = append(items, connection)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
