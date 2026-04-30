package db

import (
	"context"
	"errors"
	"testing"
	"time"
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

	if err := store.DeleteProject(ctx, "workspace-a", "project-1"); err != nil {
		t.Fatalf("delete project: %v", err)
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

func TestMemoryStoreTenancyScopeIsolation(t *testing.T) {
	store := NewMemoryStore()
	tenantA := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
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
