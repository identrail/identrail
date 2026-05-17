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

func nullString(value string) sql.NullString {
	trimmed := strings.TrimSpace(value)
	return sql.NullString{String: trimmed, Valid: trimmed != ""}
}

func nullTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

func scanUser(row rowScanner) (User, error) {
	var user User
	var deletedAt sql.NullTime
	if err := row.Scan(
		&user.ID,
		&user.PrimaryEmail,
		&user.DisplayName,
		&user.AvatarURL,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}
	return user, nil
}

// UpsertUser persists one account row.
func (p *PostgresStore) UpsertUser(ctx context.Context, user User) (User, error) {
	normalized, err := NormalizeUserForWrite(user)
	if err != nil {
		return User{}, err
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`INSERT INTO users (id, primary_email, display_name, avatar_url, status, created_at, updated_at, deleted_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (id) DO UPDATE
		 SET primary_email = EXCLUDED.primary_email,
		     display_name = EXCLUDED.display_name,
		     avatar_url = EXCLUDED.avatar_url,
		     status = EXCLUDED.status,
		     updated_at = EXCLUDED.updated_at,
		     deleted_at = EXCLUDED.deleted_at
		 RETURNING id::text, primary_email::text, display_name, avatar_url, status, created_at, updated_at, deleted_at`,
		normalized.ID,
		normalized.PrimaryEmail,
		normalized.DisplayName,
		normalized.AvatarURL,
		normalized.Status,
		normalized.CreatedAt,
		normalized.UpdatedAt,
		nullTime(normalized.DeletedAt),
	)
	saved, err := scanUser(row)
	if err != nil {
		if isTenancyUniqueViolation(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.user.upsert",
		ResourceType: "user",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

// GetUser returns one account by UUID.
func (p *PostgresStore) GetUser(ctx context.Context, userID string) (User, error) {
	return scanUser(p.queryRowContextAnyScope(
		ctx,
		`SELECT id::text, primary_email::text, display_name, avatar_url, status, created_at, updated_at, deleted_at
		 FROM users
		 WHERE id = NULLIF($1, '')::uuid`,
		strings.TrimSpace(userID),
	))
}

// GetUserByPrimaryEmail returns one account by normalized primary email.
func (p *PostgresStore) GetUserByPrimaryEmail(ctx context.Context, email string) (User, error) {
	return scanUser(p.queryRowContextAnyScope(
		ctx,
		`SELECT id::text, primary_email::text, display_name, avatar_url, status, created_at, updated_at, deleted_at
		 FROM users
		 WHERE primary_email = NULLIF($1, '')::citext`,
		strings.ToLower(strings.TrimSpace(email)),
	))
}

// UpsertUserIdentity persists one provider identity mapping.
func (p *PostgresStore) UpsertUserIdentity(ctx context.Context, identity UserIdentity) (UserIdentity, error) {
	normalized, err := NormalizeUserIdentityForWrite(identity)
	if err != nil {
		return UserIdentity{}, err
	}
	rawClaims := normalized.RawClaims
	if len(rawClaims) == 0 {
		rawClaims = json.RawMessage(`{}`)
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`INSERT INTO user_identities (
		     id, user_id, provider, subject, email, email_verified, raw_claims, last_authenticated_at, created_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
		 ON CONFLICT (provider, subject) DO UPDATE
		 SET user_id = EXCLUDED.user_id,
		     email = EXCLUDED.email,
		     email_verified = EXCLUDED.email_verified,
		     raw_claims = EXCLUDED.raw_claims,
		     last_authenticated_at = EXCLUDED.last_authenticated_at
		 RETURNING id::text, user_id::text, provider, subject, COALESCE(email::text, ''), email_verified, raw_claims, last_authenticated_at, created_at`,
		normalized.ID,
		normalized.UserID,
		normalized.Provider,
		normalized.Subject,
		nullString(normalized.Email),
		normalized.EmailVerified,
		string(rawClaims),
		normalized.LastAuthenticatedAt,
		normalized.CreatedAt,
	)
	var saved UserIdentity
	if err := row.Scan(
		&saved.ID,
		&saved.UserID,
		&saved.Provider,
		&saved.Subject,
		&saved.Email,
		&saved.EmailVerified,
		&saved.RawClaims,
		&saved.LastAuthenticatedAt,
		&saved.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserIdentity{}, ErrNotFound
		}
		if isTenancyFKViolation(err) {
			return UserIdentity{}, ErrNotFound
		}
		return UserIdentity{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity.upsert",
		ResourceType: "user_identity",
		ResourceID:   saved.ID,
		Outcome:      "success",
	})
	return saved, nil
}

// GetUserIdentity returns one provider identity by provider and subject.
func (p *PostgresStore) GetUserIdentity(ctx context.Context, provider string, subject string) (UserIdentity, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`SELECT id::text, user_id::text, provider, subject, COALESCE(email::text, ''), email_verified, raw_claims, last_authenticated_at, created_at
		 FROM user_identities
		 WHERE provider = $1
		   AND subject = $2`,
		strings.ToLower(strings.TrimSpace(provider)),
		strings.TrimSpace(subject),
	)
	var identity UserIdentity
	if err := row.Scan(
		&identity.ID,
		&identity.UserID,
		&identity.Provider,
		&identity.Subject,
		&identity.Email,
		&identity.EmailVerified,
		&identity.RawClaims,
		&identity.LastAuthenticatedAt,
		&identity.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserIdentity{}, ErrNotFound
		}
		return UserIdentity{}, err
	}
	return identity, nil
}

// GetUserIdentityByProviderUserID returns one provider identity for a user.
func (p *PostgresStore) GetUserIdentityByProviderUserID(ctx context.Context, provider string, userID string) (UserIdentity, error) {
	rows, err := p.queryContextAnyScope(
		ctx,
		`SELECT id::text, user_id::text, provider, subject, COALESCE(email::text, ''), email_verified, raw_claims, last_authenticated_at, created_at
		 FROM user_identities
		 WHERE provider = $1
		   AND user_id = NULLIF($2, '')::uuid
		 LIMIT 2`,
		strings.ToLower(strings.TrimSpace(provider)),
		strings.TrimSpace(userID),
	)
	if err != nil {
		return UserIdentity{}, err
	}
	defer rows.Close()
	var match UserIdentity
	found := false
	for rows.Next() {
		var identity UserIdentity
		if err := rows.Scan(
			&identity.ID,
			&identity.UserID,
			&identity.Provider,
			&identity.Subject,
			&identity.Email,
			&identity.EmailVerified,
			&identity.RawClaims,
			&identity.LastAuthenticatedAt,
			&identity.CreatedAt,
		); err != nil {
			return UserIdentity{}, err
		}
		if found {
			return UserIdentity{}, ErrConflict
		}
		match = identity
		found = true
	}
	if err := rows.Err(); err != nil {
		return UserIdentity{}, err
	}
	if !found {
		return UserIdentity{}, ErrNotFound
	}
	return match, nil
}

// ListUserIdentitiesByProvider returns provider identities ordered by newest first.
// A non-positive limit returns all matching identities.
func (p *PostgresStore) ListUserIdentitiesByProvider(ctx context.Context, provider string, limit int) ([]UserIdentity, error) {
	query := `SELECT id::text, user_id::text, provider, subject, COALESCE(email::text, ''), email_verified, raw_claims, last_authenticated_at, created_at
		 FROM user_identities
		 WHERE provider = $1
		 ORDER BY created_at DESC`
	args := []any{strings.ToLower(strings.TrimSpace(provider))}
	if limit > 0 {
		query += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := p.queryContextAnyScope(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UserIdentity, 0)
	for rows.Next() {
		var identity UserIdentity
		if err := rows.Scan(
			&identity.ID,
			&identity.UserID,
			&identity.Provider,
			&identity.Subject,
			&identity.Email,
			&identity.EmailVerified,
			&identity.RawClaims,
			&identity.LastAuthenticatedAt,
			&identity.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// DeleteUserIdentity removes one provider identity by provider and subject.
func (p *PostgresStore) DeleteUserIdentity(ctx context.Context, provider string, subject string) error {
	result, err := p.execContextAnyScope(
		ctx,
		`DELETE FROM user_identities
		 WHERE provider = $1
		   AND subject = $2`,
		strings.ToLower(strings.TrimSpace(provider)),
		strings.TrimSpace(subject),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.identity.delete",
		ResourceType: "user_identity",
		ResourceID:   strings.ToLower(strings.TrimSpace(provider)) + ":" + strings.TrimSpace(subject),
		Outcome:      "success",
	})
	return nil
}

func scanSessionWithUser(row rowScanner) (Session, error) {
	var session Session
	var orgID, workspaceID, projectID, ip, userAgent sql.NullString
	var revokedAt, deletedAt sql.NullTime
	var user User
	if err := row.Scan(
		&session.ID,
		&session.UserID,
		&orgID,
		&workspaceID,
		&projectID,
		&session.AuthMethod,
		&ip,
		&userAgent,
		&session.IdleExpiresAt,
		&session.AbsoluteExpiresAt,
		&session.LastSeenAt,
		&revokedAt,
		&session.CreatedAt,
		&user.ID,
		&user.PrimaryEmail,
		&user.DisplayName,
		&user.AvatarURL,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	if orgID.Valid {
		session.CurrentOrgID = orgID.String
	}
	if workspaceID.Valid {
		session.CurrentWorkspaceID = workspaceID.String
	}
	if projectID.Valid {
		session.CurrentProjectID = projectID.String
	}
	if ip.Valid {
		session.IP = ip.String
	}
	if userAgent.Valid {
		session.UserAgent = userAgent.String
	}
	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}
	session.User = &user
	return session, nil
}

const sessionUserSelect = `s.id, s.user_id::text, s.current_org_id, s.current_workspace_id, s.current_project_id,
       s.auth_method, s.ip::text, s.user_agent, s.idle_expires_at, s.absolute_expires_at,
       s.last_seen_at, s.revoked_at, s.created_at,
       u.id::text, u.primary_email::text, u.display_name, u.avatar_url, u.status, u.created_at, u.updated_at, u.deleted_at`

// CreateSession persists one server-side session.
func (p *PostgresStore) CreateSession(ctx context.Context, session Session) (Session, error) {
	normalized, err := NormalizeSessionForWrite(session)
	if err != nil {
		return Session{}, err
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`WITH inserted AS (
		     INSERT INTO sessions (
		       id, user_id, current_org_id, current_workspace_id, current_project_id, auth_method,
		       ip, user_agent, idle_expires_at, absolute_expires_at, last_seen_at, revoked_at, created_at
		     )
		     VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')::inet, $8, $9, $10, $11, $12, $13)
		     RETURNING *
		   )
		   SELECT `+sessionUserSelect+`
		   FROM inserted s
		   JOIN users u ON u.id = s.user_id`,
		normalized.ID,
		normalized.UserID,
		nullString(normalized.CurrentOrgID),
		nullString(normalized.CurrentWorkspaceID),
		nullString(normalized.CurrentProjectID),
		normalized.AuthMethod,
		normalized.IP,
		nullString(normalized.UserAgent),
		normalized.IdleExpiresAt,
		normalized.AbsoluteExpiresAt,
		normalized.LastSeenAt,
		nullTime(normalized.RevokedAt),
		normalized.CreatedAt,
	)
	saved, err := scanSessionWithUser(row)
	if err != nil {
		if isTenancyFKViolation(err) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.create",
		ResourceType: "session",
		ResourceID:   sessionHashKey(saved.ID),
		Outcome:      "success",
	})
	return saved, nil
}

// TouchSession renews idle expiry and returns the joined session/user row.
func (p *PostgresStore) TouchSession(ctx context.Context, sessionIDHash []byte, now time.Time) (Session, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`WITH touched AS (
		     UPDATE sessions
		     SET idle_expires_at = LEAST($2::timestamptz + INTERVAL '15 minutes', absolute_expires_at),
		         last_seen_at = $2::timestamptz
		     WHERE id = $1
		       AND revoked_at IS NULL
		       AND idle_expires_at > $2::timestamptz
		       AND absolute_expires_at > $2::timestamptz
		     RETURNING *
		   )
		   SELECT `+sessionUserSelect+`
		   FROM touched s
		   JOIN users u ON u.id = s.user_id
		   WHERE u.deleted_at IS NULL
		     AND u.status = 'active'`,
		sessionIDHash,
		now.UTC(),
	)
	return scanSessionWithUser(row)
}

// UpdateSessionContext persists the active tenancy context for one browser session.
func (p *PostgresStore) UpdateSessionContext(ctx context.Context, userID string, sessionIDHash []byte, orgID string, workspaceID string, projectID string, now time.Time) (Session, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`WITH updated AS (
		     UPDATE sessions
		     SET current_org_id = NULLIF($3, ''),
		         current_workspace_id = NULLIF($4, ''),
		         current_project_id = NULLIF($5, ''),
		         last_seen_at = $6::timestamptz
		     WHERE user_id = NULLIF($1, '')::uuid
		       AND id = $2
		       AND revoked_at IS NULL
		       AND idle_expires_at > $6::timestamptz
		       AND absolute_expires_at > $6::timestamptz
		     RETURNING *
		   )
		   SELECT `+sessionUserSelect+`
		   FROM updated s
		   JOIN users u ON u.id = s.user_id
		   WHERE u.deleted_at IS NULL
		     AND u.status = 'active'`,
		strings.TrimSpace(userID),
		sessionIDHash,
		strings.TrimSpace(orgID),
		strings.TrimSpace(workspaceID),
		strings.TrimSpace(projectID),
		now.UTC(),
	)
	session, err := scanSessionWithUser(row)
	if err != nil {
		if isTenancyFKViolation(err) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.scope_update",
		ResourceType: "session",
		ResourceID:   sessionHashKey(session.ID),
		Outcome:      "success",
	})
	return session, nil
}

// ListUserSessions returns active sessions for one user.
func (p *PostgresStore) ListUserSessions(ctx context.Context, userID string, now time.Time, limit int) ([]Session, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queryContextAnyScope(
		ctx,
		`SELECT `+sessionUserSelect+`
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.user_id = NULLIF($1, '')::uuid
		   AND s.revoked_at IS NULL
		   AND s.idle_expires_at > $2::timestamptz
		   AND s.absolute_expires_at > $2::timestamptz
		 ORDER BY s.last_seen_at DESC
		 LIMIT $3`,
		strings.TrimSpace(userID),
		now.UTC(),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]Session, 0, limit)
	for rows.Next() {
		session, scanErr := scanSessionWithUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// RevokeUserSession revokes one active session if it belongs to the user.
func (p *PostgresStore) RevokeUserSession(ctx context.Context, userID string, sessionIDHash []byte, revokedAt time.Time) (Session, error) {
	row := p.queryRowContextAnyScope(
		ctx,
		`WITH revoked AS (
		     UPDATE sessions
		     SET revoked_at = $3::timestamptz
		     WHERE user_id = NULLIF($1, '')::uuid
		       AND id = $2
		       AND revoked_at IS NULL
		     RETURNING *
		   )
		   SELECT `+sessionUserSelect+`
		   FROM revoked s
		   JOIN users u ON u.id = s.user_id`,
		strings.TrimSpace(userID),
		sessionIDHash,
		revokedAt.UTC(),
	)
	session, err := scanSessionWithUser(row)
	if err != nil {
		return Session{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.revoke",
		ResourceType: "session",
		ResourceID:   sessionHashKey(session.ID),
		Outcome:      "success",
	})
	return session, nil
}

// RevokeOtherUserSessions revokes every active session except the caller's.
func (p *PostgresStore) RevokeOtherUserSessions(ctx context.Context, userID string, currentSessionIDHash []byte, revokedAt time.Time) (int, error) {
	result, err := p.execContextAnyScope(
		ctx,
		`UPDATE sessions
		 SET revoked_at = $3::timestamptz
		 WHERE user_id = NULLIF($1, '')::uuid
		   AND id <> $2
		   AND revoked_at IS NULL`,
		strings.TrimSpace(userID),
		currentSessionIDHash,
		revokedAt.UTC(),
	)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.revoke_others",
		ResourceType: "session",
		ResourceID:   strings.TrimSpace(userID),
		Outcome:      "success",
	})
	return int(affected), nil
}

// RevokeAllUserSessions revokes every active session for one user.
func (p *PostgresStore) RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) (int, error) {
	result, err := p.execContextAnyScope(
		ctx,
		`UPDATE sessions
		 SET revoked_at = $2::timestamptz
		 WHERE user_id = NULLIF($1, '')::uuid
		   AND revoked_at IS NULL`,
		strings.TrimSpace(userID),
		revokedAt.UTC(),
	)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "auth.session.revoke_all",
		ResourceType: "session",
		ResourceID:   strings.TrimSpace(userID),
		Outcome:      "success",
	})
	return int(affected), nil
}
