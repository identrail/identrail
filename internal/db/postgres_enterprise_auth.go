package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/audit"
)

func scanInvitation(row rowScanner) (Invitation, error) {
	var invitation Invitation
	var invitedBy sql.NullString
	var acceptedAt, revokedAt sql.NullTime
	if err := row.Scan(
		&invitation.ID,
		&invitation.OrgID,
		&invitation.Email,
		&invitation.Role,
		&invitedBy,
		&invitation.TokenHash,
		&invitation.ExpiresAt,
		&acceptedAt,
		&revokedAt,
		&invitation.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Invitation{}, ErrNotFound
		}
		if isTenancyFKViolation(err) {
			return Invitation{}, ErrNotFound
		}
		return Invitation{}, err
	}
	if invitedBy.Valid {
		invitation.InvitedByUserID = invitedBy.String
	}
	if acceptedAt.Valid {
		invitation.AcceptedAt = &acceptedAt.Time
	}
	if revokedAt.Valid {
		invitation.RevokedAt = &revokedAt.Time
	}
	return invitation, nil
}

// CreateInvitation persists one invitation scaffold.
func (p *PostgresStore) CreateInvitation(ctx context.Context, invitation Invitation) (Invitation, error) {
	normalized, err := NormalizeInvitationForWrite(invitation)
	if err != nil {
		return Invitation{}, err
	}
	saved, err := scanInvitation(p.queryRowContext(
		ctx,
		`INSERT INTO invitations (
		     id, org_id, email, role, invited_by_user_id, token_hash, expires_at, accepted_at, revoked_at, created_at
		 )
		 VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid, $6, $7, $8, $9, $10)
		 RETURNING id::text, org_id, email::text, role, invited_by_user_id::text, token_hash, expires_at, accepted_at, revoked_at, created_at`,
		normalized.ID,
		normalized.OrgID,
		normalized.Email,
		normalized.Role,
		normalized.InvitedByUserID,
		normalized.TokenHash,
		normalized.ExpiresAt,
		nullTime(normalized.AcceptedAt),
		nullTime(normalized.RevokedAt),
		normalized.CreatedAt,
	))
	if err != nil {
		if isTenancyUniqueViolation(err) {
			return Invitation{}, ErrConflict
		}
		return Invitation{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.invitation.create",
		TenantID:     saved.OrgID,
		ResourceType: "invitation",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

// GetInvitation returns one organization invitation scaffold.
func (p *PostgresStore) GetInvitation(ctx context.Context, orgID string, invitationID string) (Invitation, error) {
	return scanInvitation(p.queryRowContext(
		ctx,
		`SELECT id::text, org_id, email::text, role, invited_by_user_id::text, token_hash, expires_at, accepted_at, revoked_at, created_at
		 FROM invitations
		 WHERE org_id = $1
		   AND id = NULLIF($2, '')::uuid`,
		strings.TrimSpace(orgID),
		strings.TrimSpace(invitationID),
	))
}

// ListInvitations returns organization invitations ordered by newest first.
func (p *PostgresStore) ListInvitations(ctx context.Context, orgID string, limit int) ([]Invitation, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id::text, org_id, email::text, role, invited_by_user_id::text, token_hash, expires_at, accepted_at, revoked_at, created_at
		 FROM invitations
		 WHERE org_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		strings.TrimSpace(orgID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Invitation, 0)
	for rows.Next() {
		item, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// RevokeInvitation marks one pending invitation revoked.
func (p *PostgresStore) RevokeInvitation(ctx context.Context, orgID string, invitationID string, revokedAt time.Time) (Invitation, error) {
	saved, err := scanInvitation(p.queryRowContext(
		ctx,
		`UPDATE invitations
		 SET revoked_at = $3
		 WHERE org_id = $1
		   AND id = NULLIF($2, '')::uuid
		   AND revoked_at IS NULL
		 RETURNING id::text, org_id, email::text, role, invited_by_user_id::text, token_hash, expires_at, accepted_at, revoked_at, created_at`,
		strings.TrimSpace(orgID),
		strings.TrimSpace(invitationID),
		revokedAt.UTC(),
	))
	if err != nil {
		return Invitation{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.invitation.revoke",
		TenantID:     saved.OrgID,
		ResourceType: "invitation",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

func scanVerifiedDomain(row rowScanner) (VerifiedDomain, error) {
	var domain VerifiedDomain
	var verifiedAt sql.NullTime
	if err := row.Scan(
		&domain.ID,
		&domain.OrgID,
		&domain.Domain,
		&domain.VerificationToken,
		&domain.VerificationMethod,
		&verifiedAt,
		&domain.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VerifiedDomain{}, ErrNotFound
		}
		if isTenancyFKViolation(err) {
			return VerifiedDomain{}, ErrNotFound
		}
		return VerifiedDomain{}, err
	}
	if verifiedAt.Valid {
		domain.VerifiedAt = &verifiedAt.Time
	}
	return domain, nil
}

// CreateVerifiedDomain persists one domain-verification scaffold.
func (p *PostgresStore) CreateVerifiedDomain(ctx context.Context, domain VerifiedDomain) (VerifiedDomain, error) {
	normalized, err := NormalizeVerifiedDomainForWrite(domain)
	if err != nil {
		return VerifiedDomain{}, err
	}
	saved, err := scanVerifiedDomain(p.queryRowContext(
		ctx,
		`INSERT INTO verified_domains (
		     id, org_id, domain, verification_token, verification_method, verified_at, created_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id::text, org_id, domain::text, verification_token, verification_method, verified_at, created_at`,
		normalized.ID,
		normalized.OrgID,
		normalized.Domain,
		normalized.VerificationToken,
		normalized.VerificationMethod,
		nullTime(normalized.VerifiedAt),
		normalized.CreatedAt,
	))
	if err != nil {
		if isTenancyUniqueViolation(err) {
			return VerifiedDomain{}, ErrConflict
		}
		return VerifiedDomain{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.domain.create",
		TenantID:     saved.OrgID,
		ResourceType: "verified_domain",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

// GetVerifiedDomain returns one organization domain-verification scaffold.
func (p *PostgresStore) GetVerifiedDomain(ctx context.Context, orgID string, domainID string) (VerifiedDomain, error) {
	return scanVerifiedDomain(p.queryRowContext(
		ctx,
		`SELECT id::text, org_id, domain::text, verification_token, verification_method, verified_at, created_at
		 FROM verified_domains
		 WHERE org_id = $1
		   AND id = NULLIF($2, '')::uuid`,
		strings.TrimSpace(orgID),
		strings.TrimSpace(domainID),
	))
}

// ListVerifiedDomains returns organization domain-verification scaffolds ordered by newest first.
func (p *PostgresStore) ListVerifiedDomains(ctx context.Context, orgID string, limit int) ([]VerifiedDomain, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id::text, org_id, domain::text, verification_token, verification_method, verified_at, created_at
		 FROM verified_domains
		 WHERE org_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		strings.TrimSpace(orgID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]VerifiedDomain, 0)
	for rows.Next() {
		item, err := scanVerifiedDomain(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func scanIdentityConnection(row rowScanner) (IdentityConnection, error) {
	var connection IdentityConnection
	var workOSConnectionID sql.NullString
	var entityID sql.NullString
	var ssoURL sql.NullString
	var certificatePEM sql.NullString
	var scimBearerTokenHash sql.NullString
	var groupRoleMap []byte
	var attributeMapping []byte
	if err := row.Scan(
		&connection.ID,
		&connection.OrgID,
		&connection.Provider,
		&connection.Type,
		&workOSConnectionID,
		&connection.Status,
		&groupRoleMap,
		&connection.SSORequired,
		&connection.JITProvisioningEnabled,
		&entityID,
		&ssoURL,
		&certificatePEM,
		&attributeMapping,
		&scimBearerTokenHash,
		&connection.CreatedAt,
		&connection.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IdentityConnection{}, ErrNotFound
		}
		if isTenancyFKViolation(err) {
			return IdentityConnection{}, ErrNotFound
		}
		return IdentityConnection{}, err
	}
	if workOSConnectionID.Valid {
		connection.WorkOSConnectionID = workOSConnectionID.String
	}
	if entityID.Valid {
		connection.EntityID = entityID.String
	}
	if ssoURL.Valid {
		connection.SSOURL = ssoURL.String
	}
	if certificatePEM.Valid {
		connection.CertificatePEM = certificatePEM.String
	}
	if scimBearerTokenHash.Valid {
		connection.SCIMBearerTokenHash = scimBearerTokenHash.String
	}
	if len(groupRoleMap) > 0 {
		if err := json.Unmarshal(groupRoleMap, &connection.GroupRoleMap); err != nil {
			return IdentityConnection{}, err
		}
	}
	if connection.GroupRoleMap == nil {
		connection.GroupRoleMap = map[string]string{}
	}
	if len(attributeMapping) > 0 {
		if err := json.Unmarshal(attributeMapping, &connection.AttributeMapping); err != nil {
			return IdentityConnection{}, err
		}
	}
	if connection.AttributeMapping == nil {
		connection.AttributeMapping = map[string]string{}
	}
	return connection, nil
}

const identityConnectionColumns = "id::text, org_id, provider, type, workos_connection_id, status, group_role_map, sso_required, jit_provisioning_enabled, entity_id, sso_url, certificate_pem, attribute_mapping, scim_bearer_token_hash, created_at, updated_at"

// CreateIdentityConnection persists one enterprise identity connection scaffold.
func (p *PostgresStore) CreateIdentityConnection(ctx context.Context, connection IdentityConnection) (IdentityConnection, error) {
	normalized, err := NormalizeIdentityConnectionForWrite(connection)
	if err != nil {
		return IdentityConnection{}, err
	}
	groupRoleMap, err := json.Marshal(normalized.GroupRoleMap)
	if err != nil {
		return IdentityConnection{}, err
	}
	attributeMapping, err := json.Marshal(normalized.AttributeMapping)
	if err != nil {
		return IdentityConnection{}, err
	}
	saved, err := scanIdentityConnection(p.queryRowContext(
		ctx,
		`INSERT INTO identity_connections (
		     id, org_id, provider, type, workos_connection_id, status, group_role_map, sso_required,
		     jit_provisioning_enabled, entity_id, sso_url, certificate_pem, attribute_mapping,
		     scim_bearer_token_hash, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16)
		 RETURNING `+identityConnectionColumns,
		normalized.ID,
		normalized.OrgID,
		normalized.Provider,
		normalized.Type,
		nullString(normalized.WorkOSConnectionID),
		normalized.Status,
		string(groupRoleMap),
		normalized.SSORequired,
		normalized.JITProvisioningEnabled,
		nullString(normalized.EntityID),
		nullString(normalized.SSOURL),
		nullString(normalized.CertificatePEM),
		string(attributeMapping),
		nullString(normalized.SCIMBearerTokenHash),
		normalized.CreatedAt,
		normalized.UpdatedAt,
	))
	if err != nil {
		if isTenancyUniqueViolation(err) {
			return IdentityConnection{}, ErrConflict
		}
		return IdentityConnection{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity_connection.create",
		TenantID:     saved.OrgID,
		ResourceType: "identity_connection",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

// GetIdentityConnection returns one organization identity connection scaffold.
func (p *PostgresStore) GetIdentityConnection(ctx context.Context, orgID string, connectionID string) (IdentityConnection, error) {
	return scanIdentityConnection(p.queryRowContext(
		ctx,
		`SELECT `+identityConnectionColumns+`
		 FROM identity_connections
		 WHERE org_id = $1
		   AND id = NULLIF($2, '')::uuid`,
		strings.TrimSpace(orgID),
		strings.TrimSpace(connectionID),
	))
}

// ListIdentityConnections returns organization identity connection scaffolds ordered by newest first.
func (p *PostgresStore) ListIdentityConnections(ctx context.Context, orgID string, limit int) ([]IdentityConnection, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT `+identityConnectionColumns+`
		 FROM identity_connections
		 WHERE org_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		strings.TrimSpace(orgID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]IdentityConnection, 0)
	for rows.Next() {
		item, err := scanIdentityConnection(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// UpdateIdentityConnection replaces a persisted identity connection row keyed
// on (org_id, id). Returns ErrNotFound when no matching row exists.
func (p *PostgresStore) UpdateIdentityConnection(ctx context.Context, connection IdentityConnection) (IdentityConnection, error) {
	normalized, err := NormalizeIdentityConnectionForWrite(connection)
	if err != nil {
		return IdentityConnection{}, err
	}
	groupRoleMap, err := json.Marshal(normalized.GroupRoleMap)
	if err != nil {
		return IdentityConnection{}, err
	}
	attributeMapping, err := json.Marshal(normalized.AttributeMapping)
	if err != nil {
		return IdentityConnection{}, err
	}
	saved, err := scanIdentityConnection(p.queryRowContext(
		ctx,
		`UPDATE identity_connections SET
		     provider = $3,
		     type = $4,
		     workos_connection_id = $5,
		     status = $6,
		     group_role_map = $7::jsonb,
		     sso_required = $8,
		     jit_provisioning_enabled = $9,
		     entity_id = $10,
		     sso_url = $11,
		     certificate_pem = $12,
		     attribute_mapping = $13::jsonb,
		     scim_bearer_token_hash = COALESCE($14, scim_bearer_token_hash),
		     updated_at = $15
		 WHERE org_id = $1 AND id = NULLIF($2, '')::uuid
		 RETURNING `+identityConnectionColumns,
		normalized.OrgID,
		normalized.ID,
		normalized.Provider,
		normalized.Type,
		nullString(normalized.WorkOSConnectionID),
		normalized.Status,
		string(groupRoleMap),
		normalized.SSORequired,
		normalized.JITProvisioningEnabled,
		nullString(normalized.EntityID),
		nullString(normalized.SSOURL),
		nullString(normalized.CertificatePEM),
		string(attributeMapping),
		nullString(normalized.SCIMBearerTokenHash),
		normalized.UpdatedAt,
	))
	if err != nil {
		// Translate uniqueness constraint violations into ErrConflict so the
		// API can return 409 instead of 500. Mirrors the Create path and
		// matches the memory store's UpdateIdentityConnection behavior, so an
		// admin retyping an existing (org+provider+type) tuple — or moving a
		// workos_connection_id onto a row another connection already owns —
		// gets a user-correctable error.
		if isTenancyUniqueViolation(err) {
			return IdentityConnection{}, ErrConflict
		}
		return IdentityConnection{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity_connection.update",
		TenantID:     saved.OrgID,
		ResourceType: "identity_connection",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

// DeleteIdentityConnection removes one identity connection row keyed on
// (org_id, id). Returns ErrNotFound when no matching row exists.
func (p *PostgresStore) DeleteIdentityConnection(ctx context.Context, orgID, connectionID string) error {
	res, err := p.execContext(
		ctx,
		`DELETE FROM identity_connections WHERE org_id = $1 AND id = NULLIF($2, '')::uuid`,
		strings.TrimSpace(orgID),
		strings.TrimSpace(connectionID),
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity_connection.delete",
		TenantID:     strings.TrimSpace(orgID),
		ResourceType: "identity_connection",
		ResourceID:   strings.TrimSpace(connectionID),
		Outcome:      "success",
	})
	return nil
}

const scimProvisioningEventColumns = "id::text, org_id, connection_id::text, op, external_id, user_id::text, payload, occurred_at"

func scanSCIMProvisioningEvent(row rowScanner) (SCIMProvisioningEventRecord, error) {
	var event SCIMProvisioningEventRecord
	var externalID sql.NullString
	var userID sql.NullString
	var payload []byte
	if err := row.Scan(
		&event.ID,
		&event.OrgID,
		&event.ConnectionID,
		&event.Op,
		&externalID,
		&userID,
		&payload,
		&event.OccurredAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SCIMProvisioningEventRecord{}, ErrNotFound
		}
		if isTenancyFKViolation(err) {
			return SCIMProvisioningEventRecord{}, ErrNotFound
		}
		return SCIMProvisioningEventRecord{}, err
	}
	if externalID.Valid {
		event.ExternalID = externalID.String
	}
	if userID.Valid {
		event.UserID = userID.String
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &event.Payload); err != nil {
			return SCIMProvisioningEventRecord{}, err
		}
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	return event, nil
}

// CreateSCIMProvisioningEvent appends one SCIM provisioning event to the audit
// log scoped to the org + connection. Append-only by design.
func (p *PostgresStore) CreateSCIMProvisioningEvent(ctx context.Context, event SCIMProvisioningEventRecord) (SCIMProvisioningEventRecord, error) {
	normalized, err := NormalizeSCIMProvisioningEventForWrite(event)
	if err != nil {
		return SCIMProvisioningEventRecord{}, err
	}
	payload, err := json.Marshal(normalized.Payload)
	if err != nil {
		return SCIMProvisioningEventRecord{}, err
	}
	saved, err := scanSCIMProvisioningEvent(p.queryRowContext(
		ctx,
		`INSERT INTO scim_provisioning_events (
		     id, org_id, connection_id, op, external_id, user_id, payload, occurred_at
		 )
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::uuid, $7::jsonb, $8)
		 RETURNING `+scimProvisioningEventColumns,
		normalized.ID,
		normalized.OrgID,
		normalized.ConnectionID,
		normalized.Op,
		nullString(normalized.ExternalID),
		normalized.UserID,
		string(payload),
		normalized.OccurredAt,
	))
	if err != nil {
		if isTenancyUniqueViolation(err) {
			return SCIMProvisioningEventRecord{}, ErrConflict
		}
		return SCIMProvisioningEventRecord{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.scim_provisioning_event.create",
		TenantID:     saved.OrgID,
		ResourceType: "scim_provisioning_event",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

// ListSCIMProvisioningEvents returns events for one connection ordered newest
// first, capped at limit (default 100).
func (p *PostgresStore) ListSCIMProvisioningEvents(ctx context.Context, orgID string, connectionID string, limit int) ([]SCIMProvisioningEventRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT `+scimProvisioningEventColumns+`
		 FROM scim_provisioning_events
		 WHERE org_id = $1
		   AND connection_id = NULLIF($2, '')::uuid
		 ORDER BY occurred_at DESC
		 LIMIT $3`,
		strings.TrimSpace(orgID),
		strings.TrimSpace(connectionID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]SCIMProvisioningEventRecord, 0)
	for rows.Next() {
		item, err := scanSCIMProvisioningEvent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
