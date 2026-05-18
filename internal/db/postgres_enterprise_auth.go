package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

const samlRelayStateColumns = "handle, connection_id::text, saml_request_id, return_to, intent, expires_at, consumed_at, created_at"

func scanSAMLRelayState(row rowScanner) (SAMLRelayState, error) {
	var state SAMLRelayState
	var consumedAt sql.NullTime
	if err := row.Scan(
		&state.Handle,
		&state.ConnectionID,
		&state.SAMLRequestID,
		&state.ReturnTo,
		&state.Intent,
		&state.ExpiresAt,
		&consumedAt,
		&state.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SAMLRelayState{}, ErrNotFound
		}
		return SAMLRelayState{}, err
	}
	if consumedAt.Valid {
		t := consumedAt.Time
		state.ConsumedAt = &t
	}
	return state, nil
}

// CreateSAMLRelayState persists one SP-initiated SAML AuthnRequest record.
func (p *PostgresStore) CreateSAMLRelayState(ctx context.Context, state SAMLRelayState) (SAMLRelayState, error) {
	handle := strings.TrimSpace(state.Handle)
	if handle == "" {
		return SAMLRelayState{}, fmt.Errorf("saml relay handle is required")
	}
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now().UTC()
	}
	if state.ExpiresAt.IsZero() {
		return SAMLRelayState{}, fmt.Errorf("saml relay state requires expires_at")
	}
	// /auth/saml/login is unauthenticated, so the request context has no
	// db.WithScope. Use the AnyScope path so RLS-enforced deployments do not
	// short-circuit with ErrScopeRequired before the row is written.
	saved, err := scanSAMLRelayState(p.queryRowContextAnyScope(
		ctx,
		`INSERT INTO saml_relay_states (
		     handle, connection_id, saml_request_id, return_to, intent, expires_at, created_at
		 )
		 VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6, $7)
		 RETURNING `+samlRelayStateColumns,
		handle,
		strings.TrimSpace(state.ConnectionID),
		strings.TrimSpace(state.SAMLRequestID),
		state.ReturnTo,
		strings.TrimSpace(state.Intent),
		state.ExpiresAt.UTC(),
		state.CreatedAt.UTC(),
	))
	if err != nil {
		if isTenancyUniqueViolation(err) {
			return SAMLRelayState{}, ErrConflict
		}
		return SAMLRelayState{}, err
	}
	return saved, nil
}

// ConsumeSAMLRelayState atomically marks a relay row consumed and returns the
// persisted state. The UPDATE ... RETURNING with WHERE consumed_at IS NULL
// AND expires_at > now() guarantees one-shot consumption even under
// concurrent ACS POSTs hitting different API instances. A subsequent call
// with the same handle returns ErrNotFound.
func (p *PostgresStore) ConsumeSAMLRelayState(ctx context.Context, handle string, now time.Time) (SAMLRelayState, error) {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return SAMLRelayState{}, ErrNotFound
	}
	now = now.UTC()
	// Same RLS rationale as CreateSAMLRelayState — the ACS POST is
	// unauthenticated. The handle is opaque and cryptographically random,
	// so bypassing scope here does not expose cross-tenant relay rows.
	state, err := scanSAMLRelayState(p.queryRowContextAnyScope(
		ctx,
		`UPDATE saml_relay_states
		    SET consumed_at = $2
		  WHERE handle = $1
		    AND consumed_at IS NULL
		    AND expires_at > $2
		  RETURNING `+samlRelayStateColumns,
		handle,
		now,
	))
	if err != nil {
		return SAMLRelayState{}, err
	}
	_, err = p.execContextAnyScope(
		ctx,
		`DELETE FROM saml_relay_states
		  WHERE consumed_at IS NOT NULL
		     OR expires_at <= $1`,
		now,
	)
	if err != nil {
		return SAMLRelayState{}, err
	}
	return state, nil
}

const oauthTransactionColumns = "nonce, cookie_token, intent, return_to, expected_user_id, expected_session_id, expires_at, consumed_at, created_at"

func scanOAuthTransaction(row rowScanner) (OAuthTransaction, error) {
	var txn OAuthTransaction
	var consumedAt sql.NullTime
	if err := row.Scan(
		&txn.Nonce,
		&txn.CookieToken,
		&txn.Intent,
		&txn.ReturnTo,
		&txn.ExpectedUserID,
		&txn.ExpectedSessionID,
		&txn.ExpiresAt,
		&consumedAt,
		&txn.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OAuthTransaction{}, ErrNotFound
		}
		return OAuthTransaction{}, err
	}
	if consumedAt.Valid {
		t := consumedAt.Time
		txn.ConsumedAt = &t
	}
	return txn, nil
}

// CreateOAuthTransaction persists one in-flight WorkOS OAuth login keyed by
// the signed-state nonce.
func (p *PostgresStore) CreateOAuthTransaction(ctx context.Context, txn OAuthTransaction) (OAuthTransaction, error) {
	nonce := strings.TrimSpace(txn.Nonce)
	if nonce == "" {
		return OAuthTransaction{}, fmt.Errorf("oauth transaction nonce is required")
	}
	cookieToken := strings.TrimSpace(txn.CookieToken)
	if cookieToken == "" {
		return OAuthTransaction{}, fmt.Errorf("oauth transaction cookie token is required")
	}
	if txn.ExpiresAt.IsZero() {
		return OAuthTransaction{}, fmt.Errorf("oauth transaction requires expires_at")
	}
	if txn.CreatedAt.IsZero() {
		txn.CreatedAt = time.Now().UTC()
	}
	// /auth/login and /auth/callback are unauthenticated, so the request
	// context carries no db.WithScope. Use the AnyScope path so RLS-enforced
	// deployments do not short-circuit with ErrScopeRequired. The nonce and
	// cookie token are cryptographically random and opaque, so bypassing
	// scope here does not expose any cross-tenant data.
	saved, err := scanOAuthTransaction(p.queryRowContextAnyScope(
		ctx,
		`INSERT INTO oauth_transactions (
		     nonce, cookie_token, intent, return_to, expected_user_id, expected_session_id, expires_at, created_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING `+oauthTransactionColumns,
		nonce,
		cookieToken,
		strings.TrimSpace(txn.Intent),
		txn.ReturnTo,
		strings.TrimSpace(txn.ExpectedUserID),
		strings.TrimSpace(txn.ExpectedSessionID),
		txn.ExpiresAt.UTC(),
		txn.CreatedAt.UTC(),
	))
	if err != nil {
		if isTenancyUniqueViolation(err) {
			return OAuthTransaction{}, ErrConflict
		}
		return OAuthTransaction{}, err
	}
	return saved, nil
}

// ConsumeOAuthTransaction atomically consumes the row matching nonce and
// cookieToken. The UPDATE ... RETURNING with WHERE consumed_at IS NULL AND
// expires_at > now() guarantees one-shot consumption even under concurrent
// callbacks hitting different API instances. Any later, expired, missing, or
// cookie-mismatched call returns ErrNotFound.
func (p *PostgresStore) ConsumeOAuthTransaction(ctx context.Context, nonce string, cookieToken string, now time.Time) (OAuthTransaction, error) {
	nonce = strings.TrimSpace(nonce)
	cookieToken = strings.TrimSpace(cookieToken)
	if nonce == "" || cookieToken == "" {
		return OAuthTransaction{}, ErrNotFound
	}
	now = now.UTC()
	txn, err := scanOAuthTransaction(p.queryRowContextAnyScope(
		ctx,
		`UPDATE oauth_transactions
		    SET consumed_at = $3
		  WHERE nonce = $1
		    AND cookie_token = $2
		    AND consumed_at IS NULL
		    AND expires_at > $3
		  RETURNING `+oauthTransactionColumns,
		nonce,
		cookieToken,
		now,
	))
	if err != nil {
		return OAuthTransaction{}, err
	}
	_, err = p.execContextAnyScope(
		ctx,
		`DELETE FROM oauth_transactions
		  WHERE consumed_at IS NOT NULL
		     OR expires_at <= $1`,
		now,
	)
	if err != nil {
		return OAuthTransaction{}, err
	}
	return txn, nil
}

// BeginWebhookEvent atomically claims the (provider, event_id) row. It first
// tries to win the insert; on conflict it tries to reclaim a stale
// 'processing' row (claiming instance likely crashed); failing that it reads
// the current status. Every branch is a single atomic statement, so the
// claim holds across API restarts and concurrent instances.
func (p *PostgresStore) BeginWebhookEvent(ctx context.Context, event WebhookEvent, now time.Time) (WebhookEventStatus, string, error) {
	provider := strings.TrimSpace(event.Provider)
	eventID := strings.TrimSpace(event.EventID)
	if provider == "" || eventID == "" {
		return "", "", fmt.Errorf("webhook event requires provider and event_id")
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	staleBefore := now.Add(-WebhookProcessingReclaimAfter)
	eventType := strings.TrimSpace(event.EventType)

	// The webhook endpoint is unauthenticated (HMAC-verified, no
	// db.WithScope), so use the AnyScope path; the row is global
	// idempotency state, not tenant-scoped data. The loop only re-runs in
	// the rare race where a concurrent DeleteWebhookEvent rollback removed
	// the row between the conflicting insert and the status read.
	for attempt := 0; attempt < 3; attempt++ {
		claimToken, tokErr := newWebhookClaimToken()
		if tokErr != nil {
			return "", "", tokErr
		}
		var claimed string
		err := p.queryRowContextAnyScope(
			ctx,
			`INSERT INTO webhook_events (provider, event_id, event_type, status, claim_token, received_at)
			 VALUES ($1, $2, $3, 'processing', $4, $5)
			 ON CONFLICT (provider, event_id) DO NOTHING
			 RETURNING event_id`,
			provider,
			eventID,
			eventType,
			claimToken,
			now,
		).Scan(&claimed)
		if err == nil {
			p.pruneWebhookEvents(ctx, now)
			return WebhookEventClaimed, claimToken, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", err
		}

		// Row already exists. Atomically reclaim it only if it is still
		// 'processing' and the prior claim is stale (crashed instance). The
		// new claim token fences out the superseded handler's eventual
		// Complete/Delete.
		err = p.queryRowContextAnyScope(
			ctx,
			`UPDATE webhook_events
			    SET received_at = $3, event_type = $4, claim_token = $6
			  WHERE provider = $1 AND event_id = $2
			    AND status = 'processing' AND received_at < $5
			  RETURNING event_id`,
			provider,
			eventID,
			now,
			eventType,
			staleBefore,
			claimToken,
		).Scan(&claimed)
		if err == nil {
			p.pruneWebhookEvents(ctx, now)
			return WebhookEventClaimed, claimToken, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", err
		}

		var status string
		err = p.queryRowContextAnyScope(
			ctx,
			`SELECT status FROM webhook_events WHERE provider = $1 AND event_id = $2`,
			provider,
			eventID,
		).Scan(&status)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Raced with a rollback delete; retry the claim.
				continue
			}
			return "", "", err
		}
		if status == string(WebhookEventProcessed) {
			return WebhookEventProcessed, "", nil
		}
		return WebhookEventProcessing, "", nil
	}
	return WebhookEventProcessing, "", nil
}

// CompleteWebhookEvent marks a claimed event processed so later duplicate
// deliveries become no-op successes. The claim_token predicate makes a
// superseded stale handler's completion a no-op.
func (p *PostgresStore) CompleteWebhookEvent(ctx context.Context, provider string, eventID string, claimToken string, now time.Time) error {
	provider = strings.TrimSpace(provider)
	eventID = strings.TrimSpace(eventID)
	if provider == "" || eventID == "" || claimToken == "" {
		return nil
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := p.execContextAnyScope(
		ctx,
		`UPDATE webhook_events SET status = 'processed', received_at = $4
		  WHERE provider = $1 AND event_id = $2 AND claim_token = $3`,
		provider,
		eventID,
		claimToken,
		now,
	)
	return err
}

// DeleteWebhookEvent rolls back a claim so a provider retry can reprocess an
// event whose side effects failed transiently. The claim_token predicate
// makes a superseded stale handler's rollback a no-op so it cannot erase the
// successor's active claim.
func (p *PostgresStore) DeleteWebhookEvent(ctx context.Context, provider string, eventID string, claimToken string) error {
	provider = strings.TrimSpace(provider)
	eventID = strings.TrimSpace(eventID)
	if provider == "" || eventID == "" || claimToken == "" {
		return nil
	}
	_, err := p.execContextAnyScope(
		ctx,
		`DELETE FROM webhook_events WHERE provider = $1 AND event_id = $2 AND claim_token = $3`,
		provider,
		eventID,
		claimToken,
	)
	return err
}

// pruneWebhookEvents opportunistically removes idempotency rows past the
// retention window so the ledger does not grow unbounded. It is best-effort
// housekeeping invoked on the claim path: a failure here must not fail the
// claim, so the error is intentionally ignored.
func (p *PostgresStore) pruneWebhookEvents(ctx context.Context, now time.Time) {
	cutoff := now.UTC().Add(-WebhookEventRetention)
	_, _ = p.execContextAnyScope(
		ctx,
		`DELETE FROM webhook_events WHERE received_at < $1`,
		cutoff,
	)
}

// newWebhookClaimToken returns a random opaque token identifying one claim.
func newWebhookClaimToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// GetIdentityConnectionByID resolves a connection by its globally unique
// UUID, bypassing the org-scope filter applied by GetIdentityConnection.
// Used by entry points (SAML SP-initiated login) that do not know the org id
// in advance — the connection itself determines the org scope.
//
// Uses queryRowContextAnyScope so the lookup runs without requiring a
// db.WithScope context, matching FindFirstWorkspaceMemberByUserUUIDAndTenantID.
// Under IDENTRAIL_POSTGRES_RLS_ENFORCED=true, the scoped path would short-
// circuit with ErrScopeRequired before reading any row because /auth/saml
// routes are unauthenticated entry points.
func (p *PostgresStore) GetIdentityConnectionByID(ctx context.Context, connectionID string) (IdentityConnection, error) {
	return scanIdentityConnection(p.queryRowContextAnyScope(
		ctx,
		`SELECT `+identityConnectionColumns+`
		 FROM identity_connections
		 WHERE id = NULLIF($1, '')::uuid`,
		strings.TrimSpace(connectionID),
	))
}

// GetIdentityConnectionBySCIMBearerTokenHash resolves a connection by its
// stored SCIM bearer-token hash without requiring an org-scoped context.
func (p *PostgresStore) GetIdentityConnectionBySCIMBearerTokenHash(ctx context.Context, tokenHash string) (IdentityConnection, error) {
	rows, err := p.queryContextAnyScope(
		ctx,
		`SELECT `+identityConnectionColumns+`
		 FROM identity_connections
		 WHERE scim_bearer_token_hash = NULLIF($1, '')
		 LIMIT 2`,
		strings.TrimSpace(tokenHash),
	)
	if err != nil {
		return IdentityConnection{}, err
	}
	defer rows.Close()
	var match IdentityConnection
	found := false
	for rows.Next() {
		connection, scanErr := scanIdentityConnection(rows)
		if scanErr != nil {
			return IdentityConnection{}, scanErr
		}
		if found {
			return IdentityConnection{}, ErrConflict
		}
		match = connection
		found = true
	}
	if err := rows.Err(); err != nil {
		return IdentityConnection{}, err
	}
	if !found {
		return IdentityConnection{}, ErrNotFound
	}
	return match, nil
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
