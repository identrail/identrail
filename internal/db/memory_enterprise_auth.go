package db

import (
	"context"
	"fmt"
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

// GetIdentityConnectionByID resolves a connection by its globally unique
// UUID. Used by entry points that do not know the org id yet (e.g. the SAML
// SP-initiated login route).
//
// Memory mode does not have the SQL UNIQUE constraint Postgres uses to
// guarantee global uuid uniqueness, so a buggy seed could insert two rows
// with the same id. Return ErrConflict in that case rather than picking a
// non-deterministic match.
func (m *MemoryStore) GetIdentityConnectionByID(ctx context.Context, connectionID string) (IdentityConnection, error) {
	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" {
		return IdentityConnection{}, ErrNotFound
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var match IdentityConnection
	found := false
	for _, connection := range m.identityConnections {
		if connection.ID != connectionID {
			continue
		}
		if found {
			return IdentityConnection{}, ErrConflict
		}
		match = connection
		found = true
	}
	if !found {
		return IdentityConnection{}, ErrNotFound
	}
	return match, nil
}

// GetIdentityConnectionBySCIMBearerTokenHash resolves a connection by its
// stored SCIM bearer-token hash for unauthenticated SCIM entry points.
func (m *MemoryStore) GetIdentityConnectionBySCIMBearerTokenHash(ctx context.Context, tokenHash string) (IdentityConnection, error) {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return IdentityConnection{}, ErrNotFound
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var match IdentityConnection
	found := false
	for _, connection := range m.identityConnections {
		if connection.SCIMBearerTokenHash != tokenHash {
			continue
		}
		if found {
			return IdentityConnection{}, ErrConflict
		}
		match = connection
		found = true
	}
	if !found {
		return IdentityConnection{}, ErrNotFound
	}
	return match, nil
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

// UpdateIdentityConnection replaces one persisted identity connection scoped
// to the (org_id, id) pair. The Postgres path enforces the create-time
// uniqueness invariants via SQL UNIQUE constraints and preserves the SCIM
// bearer token hash via COALESCE; this method mirrors both behaviors for
// memory mode so a parity bug cannot let callers do something through the
// memory store that Postgres would reject.
func (m *MemoryStore) UpdateIdentityConnection(ctx context.Context, connection IdentityConnection) (IdentityConnection, error) {
	normalized, err := NormalizeIdentityConnectionForWrite(connection)
	if err != nil {
		return IdentityConnection{}, err
	}
	m.mu.Lock()
	key := orgScopedKey(normalized.OrgID, normalized.ID)
	existing, exists := m.identityConnections[key]
	if !exists {
		m.mu.Unlock()
		return IdentityConnection{}, ErrNotFound
	}
	// Re-check the create-time uniqueness invariants against other rows so a
	// caller cannot UPDATE one row to collide with another. Postgres has the
	// equivalent UNIQUE constraints; memory mode would silently accept it.
	for otherKey, other := range m.identityConnections {
		if otherKey == key {
			continue
		}
		if other.OrgID == normalized.OrgID &&
			other.Provider == normalized.Provider &&
			other.Type == normalized.Type {
			m.mu.Unlock()
			return IdentityConnection{}, ErrConflict
		}
		if normalized.WorkOSConnectionID != "" && other.WorkOSConnectionID == normalized.WorkOSConnectionID {
			m.mu.Unlock()
			return IdentityConnection{}, ErrConflict
		}
	}
	// Preserve the SCIM bearer token hash when the caller omits it — matches
	// the Postgres COALESCE($14, scim_bearer_token_hash) clause so a routine
	// cert rotation through the admin API does not drop the token.
	if normalized.SCIMBearerTokenHash == "" {
		normalized.SCIMBearerTokenHash = existing.SCIMBearerTokenHash
	}
	m.identityConnections[key] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity_connection.update",
		TenantID:     normalized.OrgID,
		ResourceType: "identity_connection",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return normalized, nil
}

// DeleteIdentityConnection removes one persisted identity connection scoped
// to the (org_id, id) pair, cascading to its SCIM provisioning events. The
// cascade matches the ON DELETE CASCADE clause on scim_provisioning_events
// in Postgres so memory mode does not retain orphan audit rows for a
// connection that no longer exists.
func (m *MemoryStore) DeleteIdentityConnection(ctx context.Context, orgID, connectionID string) error {
	trimmedOrg := strings.TrimSpace(orgID)
	trimmedID := strings.TrimSpace(connectionID)
	m.mu.Lock()
	key := orgScopedKey(trimmedOrg, trimmedID)
	if _, exists := m.identityConnections[key]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.identityConnections, key)
	for eventID, event := range m.scimEvents {
		if event.OrgID == trimmedOrg && event.ConnectionID == trimmedID {
			delete(m.scimEvents, eventID)
		}
	}
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity_connection.delete",
		TenantID:     trimmedOrg,
		ResourceType: "identity_connection",
		ResourceID:   trimmedID,
		Outcome:      "success",
	})
	return nil
}

// CreateSAMLRelayState persists one SP-initiated SAML AuthnRequest record
// keyed by the opaque relay handle. Used by /auth/saml/login; consumed
// (one-shot) by /auth/saml/acs.
func (m *MemoryStore) CreateSAMLRelayState(ctx context.Context, state SAMLRelayState) (SAMLRelayState, error) {
	state.Handle = strings.TrimSpace(state.Handle)
	if state.Handle == "" {
		return SAMLRelayState{}, fmt.Errorf("saml relay handle is required")
	}
	if strings.TrimSpace(state.ConnectionID) == "" || strings.TrimSpace(state.SAMLRequestID) == "" {
		return SAMLRelayState{}, fmt.Errorf("saml relay state requires connection_id and saml_request_id")
	}
	state.ConnectionID = strings.TrimSpace(state.ConnectionID)
	state.SAMLRequestID = strings.TrimSpace(state.SAMLRequestID)
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now().UTC()
	} else {
		state.CreatedAt = state.CreatedAt.UTC()
	}
	if state.ExpiresAt.IsZero() {
		return SAMLRelayState{}, fmt.Errorf("saml relay state requires expires_at")
	}
	state.ExpiresAt = state.ExpiresAt.UTC()
	m.mu.Lock()
	if _, exists := m.samlRelayStates[state.Handle]; exists {
		m.mu.Unlock()
		return SAMLRelayState{}, ErrConflict
	}
	matches := 0
	for _, connection := range m.identityConnections {
		if connection.ID == state.ConnectionID {
			matches++
		}
	}
	switch matches {
	case 0:
		m.mu.Unlock()
		return SAMLRelayState{}, ErrNotFound
	case 1:
	default:
		m.mu.Unlock()
		return SAMLRelayState{}, ErrConflict
	}
	m.samlRelayStates[state.Handle] = state
	m.mu.Unlock()
	return state, nil
}

// ConsumeSAMLRelayState atomically marks one handle consumed and returns the
// stored state. Re-consuming the same handle returns ErrNotFound so the
// RelayState value cannot be replayed.
func (m *MemoryStore) ConsumeSAMLRelayState(ctx context.Context, handle string, now time.Time) (SAMLRelayState, error) {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return SAMLRelayState{}, ErrNotFound
	}
	now = now.UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Sweep expired entries first.
	for h, s := range m.samlRelayStates {
		if !s.ExpiresAt.After(now) {
			delete(m.samlRelayStates, h)
		}
	}
	state, exists := m.samlRelayStates[handle]
	if !exists {
		return SAMLRelayState{}, ErrNotFound
	}
	if state.ConsumedAt != nil {
		return SAMLRelayState{}, ErrNotFound
	}
	consumed := now
	state.ConsumedAt = &consumed
	delete(m.samlRelayStates, handle)
	return state, nil
}

// CreateSCIMProvisioningEvent appends one SCIM provisioning event to the
// append-only audit log scoped to the org + connection.
func (m *MemoryStore) CreateSCIMProvisioningEvent(ctx context.Context, event SCIMProvisioningEventRecord) (SCIMProvisioningEventRecord, error) {
	normalized, err := NormalizeSCIMProvisioningEventForWrite(event)
	if err != nil {
		return SCIMProvisioningEventRecord{}, err
	}
	m.mu.Lock()
	if _, exists := m.organizations[normalized.OrgID]; !exists {
		m.mu.Unlock()
		return SCIMProvisioningEventRecord{}, ErrNotFound
	}
	if _, exists := m.identityConnections[orgScopedKey(normalized.OrgID, normalized.ConnectionID)]; !exists {
		m.mu.Unlock()
		return SCIMProvisioningEventRecord{}, ErrNotFound
	}
	// Mirror the Postgres FK on users(id): a non-null UserID must reference an
	// existing user row. Memory mode otherwise silently accepts events that
	// would FK-fail in production.
	if normalized.UserID != "" {
		if _, exists := m.users[normalized.UserID]; !exists {
			m.mu.Unlock()
			return SCIMProvisioningEventRecord{}, ErrNotFound
		}
	}
	if _, exists := m.scimEvents[normalized.ID]; exists {
		m.mu.Unlock()
		return SCIMProvisioningEventRecord{}, ErrConflict
	}
	m.scimEvents[normalized.ID] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.scim_provisioning_event.create",
		TenantID:     normalized.OrgID,
		ResourceType: "scim_provisioning_event",
		ResourceID:   normalized.ID,
		Outcome:      "success",
	})
	return normalized, nil
}

// ListSCIMProvisioningEvents returns events for one connection ordered newest
// first, capped at limit (default 100).
func (m *MemoryStore) ListSCIMProvisioningEvents(ctx context.Context, orgID string, connectionID string, limit int) ([]SCIMProvisioningEventRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	orgID = strings.TrimSpace(orgID)
	connectionID = strings.TrimSpace(connectionID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]SCIMProvisioningEventRecord, 0)
	for _, event := range m.scimEvents {
		if event.OrgID != orgID || event.ConnectionID != connectionID {
			continue
		}
		items = append(items, event)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
