package db

import (
	"testing"
	"time"
)

func TestNormalizeTenancyOrganizationForWrite(t *testing.T) {
	normalized, err := NormalizeTenancyOrganizationForWrite(TenancyOrganization{
		TenantID:    " tenant-a ",
		DisplayName: " Core Org ",
		Slug:        " CORE ",
	})
	if err != nil {
		t.Fatalf("normalize organization: %v", err)
	}
	if normalized.TenantID != "tenant-a" {
		t.Fatalf("expected tenant id tenant-a, got %q", normalized.TenantID)
	}
	if normalized.Slug != "core" {
		t.Fatalf("expected lower slug, got %q", normalized.Slug)
	}
	if normalized.CreatedAt.IsZero() || normalized.UpdatedAt.IsZero() {
		t.Fatal("expected generated timestamps")
	}

	if _, err := NormalizeTenancyOrganizationForWrite(TenancyOrganization{}); err == nil {
		t.Fatal("expected required field validation error")
	}
	if _, err := NormalizeTenancyOrganizationForWrite(TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant a",
	}); err == nil {
		t.Fatal("expected invalid organization slug format error")
	}
}

func TestNormalizeTenancyWorkspaceMemberForWrite(t *testing.T) {
	joinedAt := time.Date(2026, 4, 1, 10, 0, 0, 0, time.FixedZone("WAT", 1*60*60))
	normalized, err := NormalizeTenancyWorkspaceMemberForWrite(TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		MemberID:    "member-1",
		UserID:      "user-1",
		Email:       " user@example.com ",
		Role:        "ADMIN",
		Status:      "ACTIVE",
		JoinedAt:    joinedAt,
	})
	if err != nil {
		t.Fatalf("normalize member: %v", err)
	}
	if normalized.Role != "admin" || normalized.Status != "active" {
		t.Fatalf("expected normalized role/status, got role=%q status=%q", normalized.Role, normalized.Status)
	}
	if normalized.Email != "user@example.com" {
		t.Fatalf("expected trimmed email, got %q", normalized.Email)
	}
	if normalized.JoinedAt.Location() != time.UTC {
		t.Fatalf("expected UTC joined_at, got %v", normalized.JoinedAt.Location())
	}

	if _, err := NormalizeTenancyWorkspaceMemberForWrite(TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		MemberID:    "member-1",
		UserID:      "user-1",
		Role:        "invalid",
		Status:      "active",
	}); err == nil {
		t.Fatal("expected invalid role error")
	}
}

func TestNormalizeTenancyProjectForWrite(t *testing.T) {
	archivedAt := time.Date(2026, 4, 2, 10, 0, 0, 0, time.FixedZone("WAT", 1*60*60))
	normalized, err := NormalizeTenancyProjectForWrite(TenancyProject{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Name:        " Payments ",
		Slug:        " PAYMENTS ",
		ArchivedAt:  &archivedAt,
	})
	if err != nil {
		t.Fatalf("normalize project: %v", err)
	}
	if normalized.Name != "Payments" || normalized.Slug != "payments" {
		t.Fatalf("expected normalized name/slug, got name=%q slug=%q", normalized.Name, normalized.Slug)
	}
	if normalized.ArchivedAt == nil || normalized.ArchivedAt.Location() != time.UTC {
		t.Fatalf("expected UTC archived_at, got %+v", normalized.ArchivedAt)
	}

	if _, err := NormalizeTenancyProjectForWrite(TenancyProject{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Name:        "",
		Slug:        "payments",
	}); err == nil {
		t.Fatal("expected project name required error")
	}
	if _, err := NormalizeTenancyProjectForWrite(TenancyProject{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Name:        "Payments",
		Slug:        "project/a",
	}); err == nil {
		t.Fatal("expected project slug format validation error")
	}
	if _, err := NormalizeTenancyProjectForWrite(TenancyProject{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Name:        "Payments",
		Slug:        "project-",
	}); err == nil {
		t.Fatal("expected trailing hyphen slug to fail")
	}
	if _, err := NormalizeTenancyProjectForWrite(TenancyProject{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Name:        "Payments",
		Slug:        "project--a",
	}); err == nil {
		t.Fatal("expected consecutive hyphen slug to fail")
	}
}

func TestNormalizeTenancyWorkspaceForWrite(t *testing.T) {
	now := time.Date(2026, 4, 4, 10, 0, 0, 0, time.FixedZone("WAT", 1*60*60))
	normalized, err := NormalizeTenancyWorkspaceForWrite(TenancyWorkspace{
		TenantID:    " tenant-a ",
		WorkspaceID: " workspace-a ",
		DisplayName: " Workspace A ",
		Slug:        " WORKSPACE-A ",
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatalf("normalize workspace: %v", err)
	}
	if normalized.TenantID != "tenant-a" || normalized.WorkspaceID != "workspace-a" {
		t.Fatalf("expected trimmed tenant/workspace ids, got tenant=%q workspace=%q", normalized.TenantID, normalized.WorkspaceID)
	}
	if normalized.DisplayName != "Workspace A" || normalized.Slug != "workspace-a" {
		t.Fatalf("expected normalized display name/slug, got display_name=%q slug=%q", normalized.DisplayName, normalized.Slug)
	}
	if normalized.CreatedAt.Location() != time.UTC || normalized.UpdatedAt.Location() != time.UTC {
		t.Fatalf("expected UTC timestamps, got created_at=%v updated_at=%v", normalized.CreatedAt.Location(), normalized.UpdatedAt.Location())
	}

	if _, err := NormalizeTenancyWorkspaceForWrite(TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace/a",
	}); err == nil {
		t.Fatal("expected workspace slug format validation error")
	}
}
