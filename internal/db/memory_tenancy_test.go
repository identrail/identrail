package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
)

func TestMemoryStoreTenancyCRUD(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.UpsertOrganization(ctx, TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if _, err := store.GetOrganization(ctx); err != nil {
		t.Fatalf("get organization: %v", err)
	}

	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if _, err := store.GetWorkspace(ctx, "workspace-a"); err != nil {
		t.Fatalf("get workspace: %v", err)
	}
	workspaces, err := store.ListWorkspaces(ctx, 20)
	if err != nil {
		t.Fatalf("list workspaces: %v", err)
	}
	if len(workspaces) != 1 {
		t.Fatalf("expected one workspace, got %+v", workspaces)
	}

	joinedAt := time.Now().UTC()
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-1",
		UserID:      "user-1",
		Email:       "user@example.com",
		Role:        "admin",
		Status:      "active",
		JoinedAt:    joinedAt,
	}); err != nil {
		t.Fatalf("upsert workspace member: %v", err)
	}
	members, err := store.ListWorkspaceMembers(ctx, "workspace-a", 20)
	if err != nil {
		t.Fatalf("list workspace members: %v", err)
	}
	if len(members) != 1 || members[0].MemberID != "member-1" {
		t.Fatalf("unexpected members: %+v", members)
	}

	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Payments",
		Slug:        "payments",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	projects, err := store.ListProjects(ctx, "workspace-a", false, 20)
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	if len(projects) != 1 || projects[0].ProjectID != "project-1" {
		t.Fatalf("unexpected projects: %+v", projects)
	}

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
	connector, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-123456789012")
	if err != nil {
		t.Fatalf("get connector: %v", err)
	}
	if connector.Connector.Status != domain.ConnectorStatusActive || connector.State.HealthStatus != "healthy" {
		t.Fatalf("unexpected connector: %+v", connector)
	}
	connectors, err := store.ListTenancyConnectors(ctx, "workspace-a", "", domain.ConnectorTypeAWS, 10)
	if err != nil {
		t.Fatalf("list connectors: %v", err)
	}
	if len(connectors) != 1 || connectors[0].Connector.ConnectorID != "aws-123456789012" {
		t.Fatalf("unexpected connectors: %+v", connectors)
	}

	if err := store.DeleteProject(ctx, "workspace-a", "project-1"); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	if _, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-123456789012"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected project delete to cascade connector, got %v", err)
	}
	if err := store.DeleteWorkspaceMember(ctx, "workspace-a", "member-1"); err != nil {
		t.Fatalf("delete workspace member: %v", err)
	}
	if err := store.DeleteWorkspace(ctx, "workspace-a"); err != nil {
		t.Fatalf("delete workspace: %v", err)
	}
	if err := store.DeleteOrganization(ctx); err != nil {
		t.Fatalf("delete organization: %v", err)
	}
}

func TestMemoryStoreListTenancyConnectorsUnscopedWithoutLimit(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	workspaceBCtx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-b"})

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace-a: %v", err)
	}
	if err := store.UpsertWorkspace(workspaceBCtx, TenancyWorkspace{WorkspaceID: "workspace-b", DisplayName: "Workspace B", Slug: "workspace-b"}); err != nil {
		t.Fatalf("upsert workspace-b: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
		t.Fatalf("upsert project-a: %v", err)
	}
	if err := store.UpsertProject(workspaceBCtx, TenancyProject{WorkspaceID: "workspace-b", ProjectID: "project-b", Name: "Project B", Slug: "project-b"}); err != nil {
		t.Fatalf("upsert project-b: %v", err)
	}

	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "github-a",
		Type:        domain.ConnectorTypeGitHub,
		DisplayName: "GitHub A",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{WorkspaceID: "workspace-a", ProjectID: "project-a", ConnectorID: "github-a", HealthStatus: "healthy"}); err != nil {
		t.Fatalf("upsert connector a: %v", err)
	}
	if err := store.UpsertTenancyConnector(workspaceBCtx, TenancyConnector{
		WorkspaceID: "workspace-b",
		ProjectID:   "project-b",
		ConnectorID: "github-b",
		Type:        domain.ConnectorTypeGitHub,
		DisplayName: "GitHub B",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{WorkspaceID: "workspace-b", ProjectID: "project-b", ConnectorID: "github-b", HealthStatus: "healthy"}); err != nil {
		t.Fatalf("upsert connector b: %v", err)
	}

	connectors, err := store.ListTenancyConnectorsUnscoped(context.Background(), domain.ConnectorTypeGitHub, 0)
	if err != nil {
		t.Fatalf("list unscoped connectors: %v", err)
	}
	if len(connectors) != 2 {
		t.Fatalf("expected both connectors without limit, got %+v", connectors)
	}
}

func TestMemoryStoreConnectorSecretEnvelopeCRUD(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	rotatedAt := time.Now().UTC().Truncate(time.Second)
	rotationDueAt := rotatedAt.Add(24 * time.Hour)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-1", Name: "Project 1", Slug: "project-1"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "github",
		Type:        domain.ConnectorTypeGitHub,
		DisplayName: "GitHub",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{WorkspaceID: "workspace-a", ProjectID: "project-1", ConnectorID: "github", HealthStatus: "healthy"}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}

	envelope := TenancyConnectorSecretEnvelope{
		WorkspaceID:     "workspace-a",
		ProjectID:       "project-1",
		ConnectorID:     "github",
		SecretName:      "webhook_secret",
		EnvelopeVersion: 1,
		Envelope: secretstore.Envelope{
			Version:    1,
			Algorithm:  secretstore.AlgorithmAES256GCM,
			KeyVersion: "v1",
			Nonce:      []byte("123456789012"),
			Ciphertext: []byte("ciphertext"),
		},
		SecretRefID:   "vault://secret/v1",
		RotatedAt:     rotatedAt,
		RotationDueAt: &rotationDueAt,
	}
	if err := store.UpsertTenancyConnectorSecretEnvelope(ctx, envelope); err != nil {
		t.Fatalf("upsert connector secret envelope: %v", err)
	}

	got, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "github", "webhook_secret")
	if err != nil {
		t.Fatalf("get connector secret envelope: %v", err)
	}
	if got.SecretRefID != "vault://secret/v1" || got.Envelope.KeyVersion != "v1" {
		t.Fatalf("unexpected connector secret envelope: %+v", got)
	}

	got.Envelope.Nonce[0] = 'X'
	reloaded, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "github", "webhook_secret")
	if err != nil {
		t.Fatalf("reload connector secret envelope: %v", err)
	}
	if string(reloaded.Envelope.Nonce) != "123456789012" {
		t.Fatalf("expected stored nonce copy to remain unchanged, got %q", string(reloaded.Envelope.Nonce))
	}
}

func TestMemoryStoreTenancyScopeIsolation(t *testing.T) {
	store := NewMemoryStore()
	tenantA := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	tenantAWorkspaceB := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-b"})
	tenantB := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	if err := store.UpsertOrganization(tenantA, TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("seed organization tenant-a: %v", err)
	}
	if err := store.UpsertWorkspace(tenantA, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("seed workspace tenant-a: %v", err)
	}
	if err := store.UpsertProject(tenantA, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Name:        "Project A",
		Slug:        "project-a",
	}); err != nil {
		t.Fatalf("seed project tenant-a: %v", err)
	}

	if _, err := store.GetOrganization(tenantB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected tenant-b organization to be isolated, got %v", err)
	}
	if _, err := store.GetWorkspace(tenantB, "workspace-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected tenant-b workspace to be isolated, got %v", err)
	}
	if _, err := store.GetProject(tenantB, "workspace-a", "project-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected tenant-b project to be isolated, got %v", err)
	}
	if _, err := store.GetWorkspace(tenantAWorkspaceB, "workspace-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-workspace lookup to be denied, got %v", err)
	}
	if _, err := store.GetProject(tenantAWorkspaceB, "workspace-a", "project-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-workspace project lookup to be denied, got %v", err)
	}
}

func TestMemoryStoreDeleteWorkspaceCascadesWithPaddedWorkspaceID(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.UpsertOrganization(ctx, TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-1",
		UserID:      "user-1",
		Email:       "user@example.com",
		Role:        "admin",
		Status:      "active",
	}); err != nil {
		t.Fatalf("upsert member: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Payments",
		Slug:        "payments",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	if err := store.DeleteWorkspace(ctx, "  workspace-a  "); err != nil {
		t.Fatalf("delete workspace with padded id: %v", err)
	}
	if _, err := store.GetWorkspaceMember(ctx, "workspace-a", "member-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected member to be cascade-deleted, got %v", err)
	}
	if _, err := store.GetProject(ctx, "workspace-a", "project-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected project to be cascade-deleted, got %v", err)
	}
}

func TestMemoryStoreListAllTenancyConnectorsByType(t *testing.T) {
	store := NewMemoryStore()
	ctxA := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	ctxB := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	seedProject := func(t *testing.T, ctx context.Context, workspaceID string, projectID string) {
		t.Helper()
		scope, err := RequireScope(ctx)
		if err != nil {
			t.Fatalf("require scope: %v", err)
		}
		if err := store.UpsertOrganization(ctx, TenancyOrganization{
			DisplayName: "Tenant " + scope.TenantID,
			Slug:        scope.TenantID,
		}); err != nil {
			t.Fatalf("upsert organization: %v", err)
		}
		if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
			WorkspaceID: workspaceID,
			DisplayName: "Workspace " + workspaceID,
			Slug:        workspaceID,
		}); err != nil {
			t.Fatalf("upsert workspace: %v", err)
		}
		if err := store.UpsertProject(ctx, TenancyProject{
			WorkspaceID: workspaceID,
			ProjectID:   projectID,
			Name:        "Project " + projectID,
			Slug:        projectID,
		}); err != nil {
			t.Fatalf("upsert project: %v", err)
		}
	}

	seedProject(t, ctxA, "workspace-a", "project-a")
	seedProject(t, ctxB, "workspace-b", "project-b")

	now := time.Now().UTC()
	if err := store.UpsertTenancyConnector(ctxA, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "github-a",
		Type:        domain.ConnectorTypeGitHub,
		DisplayName: "GitHub A",
		Status:      domain.ConnectorStatusActive,
		UpdatedAt:   now.Add(-time.Minute),
	}, TenancyConnectorState{
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-a",
		ConnectorID:  "github-a",
		HealthStatus: "healthy",
	}); err != nil {
		t.Fatalf("upsert github connector a: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctxB, TenancyConnector{
		WorkspaceID: "workspace-b",
		ProjectID:   "project-b",
		ConnectorID: "github-b",
		Type:        domain.ConnectorTypeGitHub,
		DisplayName: "GitHub B",
		Status:      domain.ConnectorStatusActive,
		UpdatedAt:   now,
	}, TenancyConnectorState{
		WorkspaceID:  "workspace-b",
		ProjectID:    "project-b",
		ConnectorID:  "github-b",
		HealthStatus: "healthy",
	}); err != nil {
		t.Fatalf("upsert github connector b: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctxA, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-a",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "AWS A",
		Status:      domain.ConnectorStatusActive,
		UpdatedAt:   now,
	}, TenancyConnectorState{
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-a",
		ConnectorID:  "aws-a",
		HealthStatus: "healthy",
	}); err != nil {
		t.Fatalf("upsert aws connector: %v", err)
	}

	connectors, err := store.ListAllTenancyConnectorsByType(context.Background(), domain.ConnectorTypeGitHub, 10)
	if err != nil {
		t.Fatalf("list all github connectors: %v", err)
	}
	if len(connectors) != 2 {
		t.Fatalf("expected two github connectors, got %+v", connectors)
	}
	if connectors[0].Connector.ConnectorID != "github-b" || connectors[1].Connector.ConnectorID != "github-a" {
		t.Fatalf("expected connectors ordered by recency, got %+v", connectors)
	}

	unlimited, err := store.ListAllTenancyConnectorsByType(context.Background(), domain.ConnectorTypeGitHub, 0)
	if err != nil {
		t.Fatalf("list all github connectors without limit: %v", err)
	}
	if len(unlimited) != 2 {
		t.Fatalf("expected unlimited query to return both github connectors, got %+v", unlimited)
	}
}

func TestMemoryStoreProjectReadsCloneArchivedPointer(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()
	archived := now

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Payments",
		Slug:        "payments",
		ArchivedAt:  &archived,
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	project, err := store.GetProject(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get project: %v", err)
	}
	if project.ArchivedAt == nil {
		t.Fatal("expected archived_at to be set")
	}
	mutated := archived.Add(24 * time.Hour)
	*project.ArchivedAt = mutated

	projectAgain, err := store.GetProject(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get project again: %v", err)
	}
	if projectAgain.ArchivedAt == nil || !projectAgain.ArchivedAt.Equal(archived) {
		t.Fatalf("expected stored archived_at to remain unchanged, got %+v want %v", projectAgain.ArchivedAt, archived)
	}

	listed, err := store.ListProjects(ctx, "workspace-a", true, 10)
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	if len(listed) != 1 || listed[0].ArchivedAt == nil {
		t.Fatalf("expected one archived project, got %+v", listed)
	}
	listMutated := archived.Add(48 * time.Hour)
	*listed[0].ArchivedAt = listMutated

	projectAfterList, err := store.GetProject(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get project after list mutation: %v", err)
	}
	if projectAfterList.ArchivedAt == nil || !projectAfterList.ArchivedAt.Equal(archived) {
		t.Fatalf("expected stored archived_at to remain unchanged after list mutation, got %+v want %v", projectAfterList.ArchivedAt, archived)
	}
}

func TestMemoryStoreWorkspaceMemberDefaultsStatusToInvited(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.UpsertOrganization(ctx, TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-1",
		UserID:      "user-1",
		Role:        "viewer",
	}); err != nil {
		t.Fatalf("upsert workspace member: %v", err)
	}

	member, err := store.GetWorkspaceMember(ctx, "workspace-a", "member-1")
	if err != nil {
		t.Fatalf("get workspace member: %v", err)
	}
	if member.Status != "invited" {
		t.Fatalf("expected default status invited, got %+v", member)
	}
}

func TestMemoryStoreTenancyKeysAvoidDelimiterCollision(t *testing.T) {
	store := NewMemoryStore()
	ctxA := WithScope(context.Background(), Scope{TenantID: "tenant", WorkspaceID: "a|b"})
	ctxB := WithScope(context.Background(), Scope{TenantID: "tenant|a", WorkspaceID: "b"})

	if err := store.UpsertOrganization(ctxA, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org A: %v", err)
	}
	if err := store.UpsertOrganization(ctxB, TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("upsert org B: %v", err)
	}
	if err := store.UpsertWorkspace(ctxA, TenancyWorkspace{WorkspaceID: "a|b", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace A: %v", err)
	}
	if err := store.UpsertWorkspace(ctxB, TenancyWorkspace{WorkspaceID: "b", DisplayName: "Workspace B", Slug: "workspace-b"}); err != nil {
		t.Fatalf("upsert workspace B: %v", err)
	}

	if err := store.UpsertProject(ctxA, TenancyProject{WorkspaceID: "a|b", ProjectID: "project-1", Name: "A", Slug: "a"}); err != nil {
		t.Fatalf("upsert project A: %v", err)
	}
	if err := store.UpsertProject(ctxB, TenancyProject{WorkspaceID: "b", ProjectID: "project-1", Name: "B", Slug: "b"}); err != nil {
		t.Fatalf("upsert project B: %v", err)
	}

	projectA, err := store.GetProject(ctxA, "a|b", "project-1")
	if err != nil {
		t.Fatalf("get project A: %v", err)
	}
	projectB, err := store.GetProject(ctxB, "b", "project-1")
	if err != nil {
		t.Fatalf("get project B: %v", err)
	}
	if projectA.Name == projectB.Name {
		t.Fatalf("expected isolated project records, got A=%q B=%q", projectA.Name, projectB.Name)
	}
}

func TestMemoryStoreTenancyNotFoundAndListBranches(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.DeleteOrganization(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing organization delete to return ErrNotFound, got %v", err)
	}

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}

	if _, err := store.GetWorkspaceMember(ctx, "workspace-a", "missing-member"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing workspace member to return ErrNotFound, got %v", err)
	}
	if err := store.DeleteWorkspaceMember(ctx, "workspace-a", "missing-member"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing workspace member delete to return ErrNotFound, got %v", err)
	}
	if err := store.DeleteProject(ctx, "workspace-a", "missing-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing project delete to return ErrNotFound, got %v", err)
	}

	archivedAt := time.Now().UTC()
	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "active-project",
		Name:        "Active",
		Slug:        "active",
	}); err != nil {
		t.Fatalf("upsert active project: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "archived-project",
		Name:        "Archived",
		Slug:        "archived",
		ArchivedAt:  &archivedAt,
	}); err != nil {
		t.Fatalf("upsert archived project: %v", err)
	}

	nonArchived, err := store.ListProjects(ctx, "workspace-a", false, 0)
	if err != nil {
		t.Fatalf("list non-archived projects: %v", err)
	}
	if len(nonArchived) != 1 || nonArchived[0].ProjectID != "active-project" {
		t.Fatalf("expected only active project, got %+v", nonArchived)
	}

	allProjects, err := store.ListProjects(ctx, "workspace-a", true, 0)
	if err != nil {
		t.Fatalf("list all projects: %v", err)
	}
	if len(allProjects) != 2 {
		t.Fatalf("expected both projects when includeArchived=true, got %+v", allProjects)
	}
}
