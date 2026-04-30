package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/audit"
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
