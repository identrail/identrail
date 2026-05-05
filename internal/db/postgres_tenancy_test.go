package db

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

func TestPostgresStoreUpsertAndGetOrganizationScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_organizations (tenant_id, display_name, slug, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (tenant_id) DO UPDATE
		 SET display_name = EXCLUDED.display_name,
		     slug = EXCLUDED.slug,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "Tenant A", "tenant-a", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertOrganization(ctx, TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}

	rows := sqlmock.NewRows([]string{"tenant_id", "display_name", "slug", "created_at", "updated_at"}).
		AddRow("tenant-a", "Tenant A", "tenant-a", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, display_name, slug, created_at, updated_at
		 FROM tenancy_organizations
		 WHERE tenant_id = $1`)).
		WithArgs("tenant-a").
		WillReturnRows(rows)

	organization, err := store.GetOrganization(ctx)
	if err != nil {
		t.Fatalf("get organization: %v", err)
	}
	if organization.TenantID != "tenant-a" {
		t.Fatalf("unexpected organization: %+v", organization)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertAndGetTenancyConnector(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO tenancy_connectors").
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"aws-123456789012",
			"aws",
			"Production AWS",
			"active",
			"",
			"",
			"",
			nil,
			"",
			nil,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO tenancy_connector_states").
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"aws-123456789012",
			"healthy",
			"",
			nil,
			"",
			"",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-123456789012",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Production AWS",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "aws-123456789012",
		HealthStatus: "healthy",
		Metadata: map[string]any{
			"role_arn": "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}

	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "type", "display_name", "status",
		"secret_provider", "secret_ref_id", "secret_ref_version", "secret_last_rotated_at",
		"config_checksum", "last_sync_at", "created_at", "updated_at", "health_status", "sync_cursor",
		"last_successful_sync_at", "last_error_code", "last_error_message", "metadata", "observed_at", "state_updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-123456789012", "aws", "Production AWS", "active",
		nil, nil, nil, nil, nil, nil, now, now, "healthy", nil, nil, nil, nil,
		[]byte(`{"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly"}`),
		now, now,
	)
	mock.ExpectQuery(`(?s)SELECT.*FROM tenancy_connectors.*c\.connector_id = \$4.*LIMIT \$5`).
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-123456789012", 1).
		WillReturnRows(rows)

	connector, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-123456789012")
	if err != nil {
		t.Fatalf("get connector: %v", err)
	}
	if connector.Connector.Type != domain.ConnectorTypeAWS || connector.State.HealthStatus != "healthy" {
		t.Fatalf("unexpected connector: %+v", connector)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListTenancyConnectors(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "type", "display_name", "status",
		"secret_provider", "secret_ref_id", "secret_ref_version", "secret_last_rotated_at",
		"config_checksum", "last_sync_at", "created_at", "updated_at", "health_status", "sync_cursor",
		"last_successful_sync_at", "last_error_code", "last_error_message", "metadata", "observed_at", "state_updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-123456789012", "aws", "Production AWS", "active",
		nil, nil, nil, nil, nil, nil, now, now, "healthy", nil, nil, nil, nil,
		[]byte(`{"region":"us-west-2"}`), now, now,
	)
	mock.ExpectQuery(`(?s)SELECT.*FROM tenancy_connectors.*c\.type = \$3.*LIMIT \$4`).
		WithArgs("tenant-a", "workspace-a", "aws", 10).
		WillReturnRows(rows)

	connectors, err := store.ListTenancyConnectors(ctx, "workspace-a", "", domain.ConnectorTypeAWS, 10)
	if err != nil {
		t.Fatalf("list connectors: %v", err)
	}
	if len(connectors) != 1 || connectors[0].Connector.ConnectorID != "aws-123456789012" {
		t.Fatalf("unexpected connectors: %+v", connectors)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreWorkspaceScopeIsolation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	_, err = store.GetWorkspace(ctx, "workspace-b")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scoped workspace lookup to fail with ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertProjectRejectsCrossWorkspaceScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	err = store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-b",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-workspace upsert, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreDeleteProjectScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "project-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.DeleteProject(ctx, "workspace-a", "project-1"); err != nil {
		t.Fatalf("delete project: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "project-missing").
		WillReturnResult(sqlmock.NewResult(1, 0))

	if err := store.DeleteProject(ctx, "workspace-a", "project-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing project delete, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertsMapForeignKeyViolationToNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	fkErr := errors.New(`pq: insert or update on table "tenancy_projects" violates foreign key constraint "tenancy_projects_tenant_id_workspace_id_fkey"`)

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_workspaces (tenant_id, workspace_id, display_name, slug, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, workspace_id) DO UPDATE
		 SET display_name = EXCLUDED.display_name,
		     slug = EXCLUDED.slug,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "workspace-a", "Workspace A", "workspace-a", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fkErr)
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected workspace FK violation to map to ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_workspace_members (
		     tenant_id, workspace_id, member_id, user_id, email, role, status, joined_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, workspace_id, member_id) DO UPDATE
		 SET user_id = EXCLUDED.user_id,
		     email = EXCLUDED.email,
		     role = EXCLUDED.role,
		     status = EXCLUDED.status,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "workspace-a", "member-1", "user-1", "user@example.com", "admin", "active", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fkErr)
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-1",
		UserID:      "user-1",
		Email:       "user@example.com",
		Role:        "admin",
		Status:      "active",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected member FK violation to map to ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_projects (
		     tenant_id, workspace_id, project_id, name, slug, description, archived_at, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, workspace_id, project_id) DO UPDATE
		 SET name = EXCLUDED.name,
		     slug = EXCLUDED.slug,
		     description = EXCLUDED.description,
		     archived_at = EXCLUDED.archived_at,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "", nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fkErr)
	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected project FK violation to map to ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreDeleteOrganizationScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_organizations
		 WHERE tenant_id = $1`)).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.DeleteOrganization(ctx); err != nil {
		t.Fatalf("delete organization: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_organizations
		 WHERE tenant_id = $1`)).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(1, 0))
	if err := store.DeleteOrganization(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing organization delete, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListAndDeleteWorkspaceScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`)).
		WithArgs("tenant-a", 20).
		WillReturnRows(rows)

	workspaces, err := store.ListWorkspaces(ctx, 20)
	if err != nil {
		t.Fatalf("list workspaces: %v", err)
	}
	if len(workspaces) != 1 || workspaces[0].WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected workspaces: %+v", workspaces)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.DeleteWorkspace(ctx, "workspace-a"); err != nil {
		t.Fatalf("delete workspace: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreWorkspaceMemberCRUD(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	row := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "email", "role", "status", "joined_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "member-1", "user-1", "user@example.com", "admin", "active", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, member_id, user_id, email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "member-1").
		WillReturnRows(row)

	member, err := store.GetWorkspaceMember(ctx, "workspace-a", "member-1")
	if err != nil {
		t.Fatalf("get workspace member: %v", err)
	}
	if member.MemberID != "member-1" {
		t.Fatalf("unexpected member: %+v", member)
	}

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "email", "role", "status", "joined_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "member-1", "user-1", "user@example.com", "admin", "active", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, member_id, user_id, email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		 ORDER BY joined_at ASC
		 LIMIT $3`)).
		WithArgs("tenant-a", "workspace-a", 100).
		WillReturnRows(rows)

	members, err := store.ListWorkspaceMembers(ctx, "workspace-a", 100)
	if err != nil {
		t.Fatalf("list workspace members: %v", err)
	}
	if len(members) != 1 || members[0].MemberID != "member-1" {
		t.Fatalf("unexpected members: %+v", members)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "member-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.DeleteWorkspaceMember(ctx, "workspace-a", "member-1"); err != nil {
		t.Fatalf("delete workspace member: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreProjectReadPaths(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()
	archivedAt := now

	row := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "project_id", "name", "slug", "coalesce", "archived_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "desc", archivedAt, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "project-1").
		WillReturnRows(row)

	project, err := store.GetProject(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get project: %v", err)
	}
	if project.ProjectID != "project-1" || project.ArchivedAt == nil {
		t.Fatalf("unexpected project: %+v", project)
	}

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "project_id", "name", "slug", "coalesce", "archived_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "desc", nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2 AND archived_at IS NULL ORDER BY created_at DESC LIMIT $3`)).
		WithArgs("tenant-a", "workspace-a", 100).
		WillReturnRows(rows)

	projects, err := store.ListProjects(ctx, "workspace-a", false, 100)
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	if len(projects) != 1 || projects[0].ProjectID != "project-1" {
		t.Fatalf("unexpected projects: %+v", projects)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreWorkspaceAndMemberNotFoundPaths(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnError(sql.ErrNoRows)
	if _, err := store.GetWorkspace(ctx, "workspace-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing workspace to return ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "missing-member").
		WillReturnResult(sqlmock.NewResult(1, 0))
	if err := store.DeleteWorkspaceMember(ctx, "workspace-a", "missing-member"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing member delete to return ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(1, 0))
	if err := store.DeleteWorkspace(ctx, "workspace-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing workspace delete to return ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListProjectsIncludesArchivedBranch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "project_id", "name", "slug", "coalesce", "archived_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "desc", now, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2 ORDER BY created_at DESC LIMIT $3`)).
		WithArgs("tenant-a", "workspace-a", 10).
		WillReturnRows(rows)

	projects, err := store.ListProjects(ctx, "workspace-a", true, 10)
	if err != nil {
		t.Fatalf("list projects include archived: %v", err)
	}
	if len(projects) != 1 || projects[0].ArchivedAt == nil {
		t.Fatalf("expected archived project in result, got %+v", projects)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
