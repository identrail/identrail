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
	var groupRoleMap []byte
	if err := row.Scan(
		&connection.ID,
		&connection.OrgID,
		&connection.Provider,
		&connection.Type,
		&workOSConnectionID,
		&connection.Status,
		&groupRoleMap,
		&connection.SSORequired,
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
	if len(groupRoleMap) > 0 {
		if err := json.Unmarshal(groupRoleMap, &connection.GroupRoleMap); err != nil {
			return IdentityConnection{}, err
		}
	}
	if connection.GroupRoleMap == nil {
		connection.GroupRoleMap = map[string]string{}
	}
	return connection, nil
}

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
	saved, err := scanIdentityConnection(p.queryRowContext(
		ctx,
		`INSERT INTO identity_connections (
		     id, org_id, provider, type, workos_connection_id, status, group_role_map, sso_required, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
		 RETURNING id::text, org_id, provider, type, workos_connection_id, status, group_role_map, sso_required, created_at, updated_at`,
		normalized.ID,
		normalized.OrgID,
		normalized.Provider,
		normalized.Type,
		nullString(normalized.WorkOSConnectionID),
		normalized.Status,
		string(groupRoleMap),
		normalized.SSORequired,
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
		`SELECT id::text, org_id, provider, type, workos_connection_id, status, group_role_map, sso_required, created_at, updated_at
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
		`SELECT id::text, org_id, provider, type, workos_connection_id, status, group_role_map, sso_required, created_at, updated_at
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
