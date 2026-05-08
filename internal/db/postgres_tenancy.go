package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/domain"
)

// UpsertOrganization persists one scoped organization metadata row.
func (p *PostgresStore) UpsertOrganization(ctx context.Context, organization TenancyOrganization) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	organization.TenantID = scope.TenantID
	normalized, err := NormalizeTenancyOrganizationForWrite(organization)
	if err != nil {
		return err
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO tenancy_organizations (tenant_id, display_name, slug, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (tenant_id) DO UPDATE
		 SET display_name = EXCLUDED.display_name,
		     slug = EXCLUDED.slug,
		     updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.DisplayName,
		normalized.Slug,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	if isTenancyFKViolation(err) {
		return ErrNotFound
	}
	if err == nil {
		audit.WriteAction(ctx, audit.AuditEvent{
			Action:       "tenancy.organization.upsert",
			TenantID:     normalized.TenantID,
			ResourceType: "tenancy_organization",
			ResourceID:   normalized.TenantID,
			Outcome:      "success",
		})
	}
	return err
}

// GetOrganization returns one scoped organization record.
func (p *PostgresStore) GetOrganization(ctx context.Context) (TenancyOrganization, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyOrganization{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, display_name, slug, created_at, updated_at
		 FROM tenancy_organizations
		 WHERE tenant_id = $1`,
		scope.TenantID,
	)
	var organization TenancyOrganization
	if err := row.Scan(
		&organization.TenantID,
		&organization.DisplayName,
		&organization.Slug,
		&organization.CreatedAt,
		&organization.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TenancyOrganization{}, ErrNotFound
		}
		return TenancyOrganization{}, err
	}
	return organization, nil
}

// DeleteOrganization removes one scoped organization record.
func (p *PostgresStore) DeleteOrganization(ctx context.Context) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`DELETE FROM tenancy_organizations
		 WHERE tenant_id = $1`,
		scope.TenantID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.organization.delete",
		TenantID:     scope.TenantID,
		ResourceType: "tenancy_organization",
		ResourceID:   scope.TenantID,
		Outcome:      "success",
	})
	return nil
}

// UpsertWorkspace persists one scoped workspace record.
func (p *PostgresStore) UpsertWorkspace(ctx context.Context, workspace TenancyWorkspace) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	workspace.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspace.WorkspaceID)
	if err != nil {
		return err
	}
	workspace.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyWorkspaceForWrite(workspace)
	if err != nil {
		return err
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO tenancy_workspaces (tenant_id, workspace_id, display_name, slug, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, workspace_id) DO UPDATE
		 SET display_name = EXCLUDED.display_name,
		     slug = EXCLUDED.slug,
		     updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.DisplayName,
		normalized.Slug,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	if isTenancyFKViolation(err) {
		return ErrNotFound
	}
	if err == nil {
		audit.WriteAction(ctx, audit.AuditEvent{
			Action:       "tenancy.workspace.upsert",
			TenantID:     normalized.TenantID,
			WorkspaceID:  normalized.WorkspaceID,
			ResourceType: "tenancy_workspace",
			ResourceID:   normalized.WorkspaceID,
			Outcome:      "success",
		})
	}
	return err
}

// GetWorkspace returns one scoped workspace by id.
func (p *PostgresStore) GetWorkspace(ctx context.Context, workspaceID string) (TenancyWorkspace, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyWorkspace{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyWorkspace{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, display_name, slug, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`,
		scope.TenantID,
		resolvedWorkspaceID,
	)
	var workspace TenancyWorkspace
	if err := row.Scan(
		&workspace.TenantID,
		&workspace.WorkspaceID,
		&workspace.DisplayName,
		&workspace.Slug,
		&workspace.CreatedAt,
		&workspace.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TenancyWorkspace{}, ErrNotFound
		}
		return TenancyWorkspace{}, err
	}
	return workspace, nil
}

// ListWorkspaces returns all tenant-scoped workspaces ordered by creation time.
func (p *PostgresStore) ListWorkspaces(ctx context.Context, limit int) ([]TenancyWorkspace, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT tenant_id, workspace_id, display_name, slug, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		scope.TenantID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	workspaces := make([]TenancyWorkspace, 0, limit)
	for rows.Next() {
		var workspace TenancyWorkspace
		if err := rows.Scan(
			&workspace.TenantID,
			&workspace.WorkspaceID,
			&workspace.DisplayName,
			&workspace.Slug,
			&workspace.CreatedAt,
			&workspace.UpdatedAt,
		); err != nil {
			return nil, err
		}
		workspaces = append(workspaces, workspace)
	}
	return workspaces, rows.Err()
}

// DeleteWorkspace deletes one scoped workspace by id.
func (p *PostgresStore) DeleteWorkspace(ctx context.Context, workspaceID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`DELETE FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`,
		scope.TenantID,
		resolvedWorkspaceID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_workspace",
		ResourceID:   resolvedWorkspaceID,
		Outcome:      "success",
	})
	return nil
}

// UpsertWorkspaceMember persists one scoped workspace member record.
func (p *PostgresStore) UpsertWorkspaceMember(ctx context.Context, member TenancyWorkspaceMember) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	member.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, member.WorkspaceID)
	if err != nil {
		return err
	}
	member.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyWorkspaceMemberForWrite(member)
	if err != nil {
		return err
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO tenancy_workspace_members (
		     tenant_id, workspace_id, member_id, user_id, email, role, status, joined_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, workspace_id, member_id) DO UPDATE
		 SET user_id = EXCLUDED.user_id,
		     email = EXCLUDED.email,
		     role = EXCLUDED.role,
		     status = EXCLUDED.status,
		     updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.MemberID,
		normalized.UserID,
		normalized.Email,
		normalized.Role,
		normalized.Status,
		normalized.JoinedAt,
		normalized.UpdatedAt,
	)
	if isTenancyFKViolation(err) {
		return ErrNotFound
	}
	if err == nil {
		audit.WriteAction(ctx, audit.AuditEvent{
			Action:       "tenancy.workspace_member.upsert",
			TenantID:     normalized.TenantID,
			WorkspaceID:  normalized.WorkspaceID,
			ResourceType: "tenancy_workspace_member",
			ResourceID:   normalized.MemberID,
			Outcome:      "success",
		})
	}
	return err
}

// GetWorkspaceMember returns one scoped workspace member.
func (p *PostgresStore) GetWorkspaceMember(ctx context.Context, workspaceID string, memberID string) (TenancyWorkspaceMember, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyWorkspaceMember{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyWorkspaceMember{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, member_id, user_id, email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`,
		scope.TenantID,
		resolvedWorkspaceID,
		memberID,
	)
	var member TenancyWorkspaceMember
	if err := row.Scan(
		&member.TenantID,
		&member.WorkspaceID,
		&member.MemberID,
		&member.UserID,
		&member.Email,
		&member.Role,
		&member.Status,
		&member.JoinedAt,
		&member.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TenancyWorkspaceMember{}, ErrNotFound
		}
		return TenancyWorkspaceMember{}, err
	}
	return member, nil
}

// ListWorkspaceMembers lists members for one scoped workspace.
func (p *PostgresStore) ListWorkspaceMembers(ctx context.Context, workspaceID string, limit int) ([]TenancyWorkspaceMember, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT tenant_id, workspace_id, member_id, user_id, email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		 ORDER BY joined_at ASC
		 LIMIT $3`,
		scope.TenantID,
		resolvedWorkspaceID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := make([]TenancyWorkspaceMember, 0, limit)
	for rows.Next() {
		var member TenancyWorkspaceMember
		if err := rows.Scan(
			&member.TenantID,
			&member.WorkspaceID,
			&member.MemberID,
			&member.UserID,
			&member.Email,
			&member.Role,
			&member.Status,
			&member.JoinedAt,
			&member.UpdatedAt,
		); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

// DeleteWorkspaceMember removes one scoped member.
func (p *PostgresStore) DeleteWorkspaceMember(ctx context.Context, workspaceID string, memberID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`DELETE FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`,
		scope.TenantID,
		resolvedWorkspaceID,
		memberID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace_member.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_workspace_member",
		ResourceID:   memberID,
		Outcome:      "success",
	})
	return nil
}

// UpsertProject persists one scoped project record.
func (p *PostgresStore) UpsertProject(ctx context.Context, project TenancyProject) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	project.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, project.WorkspaceID)
	if err != nil {
		return err
	}
	project.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyProjectForWrite(project)
	if err != nil {
		return err
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO tenancy_projects (
		     tenant_id, workspace_id, project_id, name, slug, description, archived_at, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, workspace_id, project_id) DO UPDATE
		 SET name = EXCLUDED.name,
		     slug = EXCLUDED.slug,
		     description = EXCLUDED.description,
		     archived_at = EXCLUDED.archived_at,
		     updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.Name,
		normalized.Slug,
		normalized.Description,
		normalized.ArchivedAt,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	if isTenancyFKViolation(err) {
		return ErrNotFound
	}
	if err == nil {
		audit.WriteAction(ctx, audit.AuditEvent{
			Action:       "tenancy.project.upsert",
			TenantID:     normalized.TenantID,
			WorkspaceID:  normalized.WorkspaceID,
			ResourceType: "tenancy_project",
			ResourceID:   normalized.ProjectID,
			Outcome:      "success",
		})
	}
	return err
}

func isTenancyFKViolation(err error) bool {
	if err == nil {
		return false
	}
	var sqlStateErr interface{ SQLState() string }
	if errors.As(err, &sqlStateErr) {
		return sqlStateErr.SQLState() == "23503"
	}
	return strings.Contains(err.Error(), "violates foreign key constraint")
}

// GetProject returns one scoped project.
func (p *PostgresStore) GetProject(ctx context.Context, workspaceID string, projectID string) (TenancyProject, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyProject{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyProject{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`,
		scope.TenantID,
		resolvedWorkspaceID,
		projectID,
	)
	var project TenancyProject
	var archivedAt sql.NullTime
	if err := row.Scan(
		&project.TenantID,
		&project.WorkspaceID,
		&project.ProjectID,
		&project.Name,
		&project.Slug,
		&project.Description,
		&archivedAt,
		&project.CreatedAt,
		&project.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TenancyProject{}, ErrNotFound
		}
		return TenancyProject{}, err
	}
	if archivedAt.Valid {
		value := archivedAt.Time.UTC()
		project.ArchivedAt = &value
	}
	return project, nil
}

// ListProjects returns scoped projects for a workspace.
func (p *PostgresStore) ListProjects(ctx context.Context, workspaceID string, includeArchived bool, limit int) ([]TenancyProject, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	query := `SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2`
	args := []any{scope.TenantID, resolvedWorkspaceID}
	if !includeArchived {
		query += " AND archived_at IS NULL"
	}
	query += " ORDER BY created_at DESC LIMIT $3"
	args = append(args, limit)
	rows, err := p.queryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	projects := make([]TenancyProject, 0, limit)
	for rows.Next() {
		var project TenancyProject
		var archivedAt sql.NullTime
		if err := rows.Scan(
			&project.TenantID,
			&project.WorkspaceID,
			&project.ProjectID,
			&project.Name,
			&project.Slug,
			&project.Description,
			&archivedAt,
			&project.CreatedAt,
			&project.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if archivedAt.Valid {
			value := archivedAt.Time.UTC()
			project.ArchivedAt = &value
		}
		projects = append(projects, project)
	}
	return projects, rows.Err()
}

// DeleteProject removes one scoped project.
func (p *PostgresStore) DeleteProject(ctx context.Context, workspaceID string, projectID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`DELETE FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`,
		scope.TenantID,
		resolvedWorkspaceID,
		projectID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.project.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_project",
		ResourceID:   projectID,
		Outcome:      "success",
	})
	return nil
}

// UpsertTenancyConnector persists one connector and its latest state atomically.
func (p *PostgresStore) UpsertTenancyConnector(ctx context.Context, connector TenancyConnector, state TenancyConnectorState) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	connector.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, connector.WorkspaceID)
	if err != nil {
		return err
	}
	connector.WorkspaceID = resolvedWorkspaceID
	state.TenantID = scope.TenantID
	state.WorkspaceID = resolvedWorkspaceID
	state.ProjectID = connector.ProjectID
	state.ConnectorID = connector.ConnectorID
	normalizedConnector, err := NormalizeTenancyConnectorForWrite(connector)
	if err != nil {
		return err
	}
	normalizedState, err := NormalizeTenancyConnectorStateForWrite(state)
	if err != nil {
		return err
	}
	metadataPayload, err := json.Marshal(normalizedState.Metadata)
	if err != nil {
		return fmt.Errorf("marshal connector state metadata: %w", err)
	}

	tx, err := p.beginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO tenancy_connectors (
		     tenant_id, workspace_id, project_id, connector_id, type, display_name, status,
		     secret_provider, secret_ref_id, secret_ref_version, secret_last_rotated_at,
		     config_checksum, last_sync_at, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), $11, NULLIF($12, ''), $13, $14, $15)
		 ON CONFLICT (tenant_id, workspace_id, project_id, connector_id) DO UPDATE
		 SET type = EXCLUDED.type,
		     display_name = EXCLUDED.display_name,
		     status = EXCLUDED.status,
		     secret_provider = EXCLUDED.secret_provider,
		     secret_ref_id = EXCLUDED.secret_ref_id,
		     secret_ref_version = EXCLUDED.secret_ref_version,
		     secret_last_rotated_at = EXCLUDED.secret_last_rotated_at,
		     config_checksum = EXCLUDED.config_checksum,
		     last_sync_at = EXCLUDED.last_sync_at,
		     updated_at = EXCLUDED.updated_at`,
		normalizedConnector.TenantID,
		normalizedConnector.WorkspaceID,
		normalizedConnector.ProjectID,
		normalizedConnector.ConnectorID,
		string(normalizedConnector.Type),
		normalizedConnector.DisplayName,
		string(normalizedConnector.Status),
		normalizedConnector.SecretProvider,
		normalizedConnector.SecretRefID,
		normalizedConnector.SecretRefVersion,
		normalizedConnector.SecretLastRotatedAt,
		normalizedConnector.ConfigChecksum,
		normalizedConnector.LastSyncAt,
		normalizedConnector.CreatedAt,
		normalizedConnector.UpdatedAt,
	)
	if isTenancyFKViolation(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("upsert tenancy connector: %w", err)
	}
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO tenancy_connector_states (
		     tenant_id, workspace_id, project_id, connector_id, health_status, sync_cursor,
		     last_successful_sync_at, last_error_code, last_error_message, metadata, observed_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, NULLIF($8, ''), NULLIF($9, ''), $10::jsonb, $11, $12)
		 ON CONFLICT (tenant_id, workspace_id, project_id, connector_id) DO UPDATE
		 SET health_status = EXCLUDED.health_status,
		     sync_cursor = EXCLUDED.sync_cursor,
		     last_successful_sync_at = EXCLUDED.last_successful_sync_at,
		     last_error_code = EXCLUDED.last_error_code,
		     last_error_message = EXCLUDED.last_error_message,
		     metadata = EXCLUDED.metadata,
		     observed_at = EXCLUDED.observed_at,
		     updated_at = EXCLUDED.updated_at`,
		normalizedState.TenantID,
		normalizedState.WorkspaceID,
		normalizedState.ProjectID,
		normalizedState.ConnectorID,
		normalizedState.HealthStatus,
		normalizedState.SyncCursor,
		normalizedState.LastSuccessfulSyncAt,
		normalizedState.LastErrorCode,
		normalizedState.LastErrorMessage,
		metadataPayload,
		normalizedState.ObservedAt,
		normalizedState.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert tenancy connector state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenancy connector upsert: %w", err)
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.connector.upsert",
		TenantID:     normalizedConnector.TenantID,
		WorkspaceID:  normalizedConnector.WorkspaceID,
		ResourceType: "tenancy_connector",
		ResourceID:   normalizedConnector.ConnectorID,
		Outcome:      "success",
	})
	return nil
}

// GetTenancyConnector returns one connector and its latest state.
func (p *PostgresStore) GetTenancyConnector(ctx context.Context, workspaceID string, projectID string, connectorID string) (TenancyConnectorWithState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	rows, err := p.listTenancyConnectorRows(ctx, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), "", 1)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	if len(rows) == 0 {
		return TenancyConnectorWithState{}, ErrNotFound
	}
	return rows[0], nil
}

// ListTenancyConnectors returns scoped connectors ordered by most recent update.
func (p *PostgresStore) ListTenancyConnectors(ctx context.Context, workspaceID string, projectID string, connectorType domain.ConnectorType, limit int) ([]TenancyConnectorWithState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	return p.listTenancyConnectorRows(ctx, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), "", string(connectorType), limit)
}

func (p *PostgresStore) listTenancyConnectorRows(ctx context.Context, tenantID string, workspaceID string, projectID string, connectorID string, connectorType string, limit int) ([]TenancyConnectorWithState, error) {
	query := `SELECT
		     c.tenant_id, c.workspace_id, c.project_id, c.connector_id, c.type, c.display_name, c.status,
		     c.secret_provider, c.secret_ref_id, c.secret_ref_version, c.secret_last_rotated_at,
		     c.config_checksum, c.last_sync_at, c.created_at, c.updated_at,
		     COALESCE(s.health_status, 'unknown'), s.sync_cursor, s.last_successful_sync_at,
		     s.last_error_code, s.last_error_message, COALESCE(s.metadata, '{}'::jsonb), s.observed_at, s.updated_at
		 FROM tenancy_connectors c
		 LEFT JOIN tenancy_connector_states s
		   ON s.tenant_id = c.tenant_id
		  AND s.workspace_id = c.workspace_id
		  AND s.project_id = c.project_id
		  AND s.connector_id = c.connector_id
		 WHERE c.tenant_id = $1
		   AND c.workspace_id = $2`
	args := []any{tenantID, workspaceID}
	nextArg := 3
	if projectID != "" {
		query += fmt.Sprintf(" AND c.project_id = $%d", nextArg)
		args = append(args, projectID)
		nextArg++
	}
	if connectorID != "" {
		query += fmt.Sprintf(" AND c.connector_id = $%d", nextArg)
		args = append(args, connectorID)
		nextArg++
	}
	if trimmedType := strings.ToLower(strings.TrimSpace(connectorType)); trimmedType != "" {
		query += fmt.Sprintf(" AND c.type = $%d", nextArg)
		args = append(args, trimmedType)
		nextArg++
	}
	query += fmt.Sprintf(" ORDER BY c.updated_at DESC LIMIT $%d", nextArg)
	args = append(args, limit)

	rows, err := p.queryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query tenancy connectors: %w", err)
	}
	defer rows.Close()
	results := []TenancyConnectorWithState{}
	for rows.Next() {
		var item TenancyConnectorWithState
		var metadata []byte
		var secretProvider, secretRefID, secretRefVersion, configChecksum sql.NullString
		var secretLastRotatedAt, lastSyncAt, lastSuccessfulSyncAt, observedAt, stateUpdatedAt sql.NullTime
		var syncCursor, lastErrorCode, lastErrorMessage sql.NullString
		if err := rows.Scan(
			&item.Connector.TenantID,
			&item.Connector.WorkspaceID,
			&item.Connector.ProjectID,
			&item.Connector.ConnectorID,
			&item.Connector.Type,
			&item.Connector.DisplayName,
			&item.Connector.Status,
			&secretProvider,
			&secretRefID,
			&secretRefVersion,
			&secretLastRotatedAt,
			&configChecksum,
			&lastSyncAt,
			&item.Connector.CreatedAt,
			&item.Connector.UpdatedAt,
			&item.State.HealthStatus,
			&syncCursor,
			&lastSuccessfulSyncAt,
			&lastErrorCode,
			&lastErrorMessage,
			&metadata,
			&observedAt,
			&stateUpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenancy connector row: %w", err)
		}
		item.Connector.SecretProvider = secretProvider.String
		item.Connector.SecretRefID = secretRefID.String
		item.Connector.SecretRefVersion = secretRefVersion.String
		item.Connector.ConfigChecksum = configChecksum.String
		if secretLastRotatedAt.Valid {
			value := secretLastRotatedAt.Time.UTC()
			item.Connector.SecretLastRotatedAt = &value
		}
		if lastSyncAt.Valid {
			value := lastSyncAt.Time.UTC()
			item.Connector.LastSyncAt = &value
		}
		item.State.TenantID = item.Connector.TenantID
		item.State.WorkspaceID = item.Connector.WorkspaceID
		item.State.ProjectID = item.Connector.ProjectID
		item.State.ConnectorID = item.Connector.ConnectorID
		item.State.SyncCursor = syncCursor.String
		item.State.LastErrorCode = lastErrorCode.String
		item.State.LastErrorMessage = lastErrorMessage.String
		if lastSuccessfulSyncAt.Valid {
			value := lastSuccessfulSyncAt.Time.UTC()
			item.State.LastSuccessfulSyncAt = &value
		}
		if observedAt.Valid {
			item.State.ObservedAt = observedAt.Time.UTC()
		}
		if stateUpdatedAt.Valid {
			item.State.UpdatedAt = stateUpdatedAt.Time.UTC()
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &item.State.Metadata); err != nil {
				return nil, fmt.Errorf("decode connector state metadata: %w", err)
			}
		}
		if item.State.Metadata == nil {
			item.State.Metadata = map[string]any{}
		}
		results = append(results, item)
	}
	return results, rows.Err()
}
