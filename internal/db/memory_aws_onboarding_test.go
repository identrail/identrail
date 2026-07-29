package db

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestMemoryAWSConnectorOnboardingAttemptLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	connector := TenancyConnector{
		TenantID: "tenant-a", WorkspaceID: "workspace-a", ProjectID: "project-a",
		ConnectorID: "aws-a", Type: domain.ConnectorTypeAWS, DisplayName: "AWS", Status: domain.ConnectorStatusPending,
	}
	state := TenancyConnectorState{TenantID: "tenant-a", WorkspaceID: "workspace-a", ProjectID: "project-a", ConnectorID: "aws-a", HealthStatus: "unknown", Metadata: map[string]any{}}
	if err := store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	attempt := AWSConnectorOnboardingAttempt{
		AttemptID: "attempt-a", WorkspaceID: "workspace-a", ProjectID: "project-a", ConnectorID: "aws-a",
		Status: AWSConnectorOnboardingAttemptWaiting, TokenHash: bytes.Repeat([]byte{7}, 32), TokenKeyVersion: "v1",
		ProviderTopicARN: "arn:aws:sns:us-east-1:123456789012:registration", TemplateVersion: "2.0.0",
		TemplateChecksum: "sha256:test", DeploymentRegion: "us-east-1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	created, err := store.CreateAWSConnectorOnboardingAttempt(ctx, attempt)
	if err != nil {
		t.Fatalf("create attempt: %v", err)
	}
	created.TokenHash[0] = 99
	loaded, err := store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-a", "attempt-a")
	if err != nil || loaded.TokenHash[0] != 7 {
		t.Fatalf("expected isolated token hash copy, got %+v err=%v", loaded.TokenHash, err)
	}
	wrongScope := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-a"})
	if _, err := store.GetAWSConnectorOnboardingAttempt(wrongScope, "workspace-a", "project-a", "attempt-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant lookup must not reveal attempt, got %v", err)
	}

	loaded.Status = AWSConnectorOnboardingAttemptConnected
	terminal, err := store.UpdateAWSConnectorOnboardingAttempt(ctx, loaded, loaded.Version)
	if err != nil {
		t.Fatalf("complete attempt: %v", err)
	}
	second := attempt
	second.AttemptID = "attempt-b"
	second.CreatedAt = now.Add(time.Minute)
	second.UpdatedAt = second.CreatedAt
	if _, err := store.CreateAWSConnectorOnboardingAttempt(ctx, second); err != nil {
		t.Fatalf("create replacement attempt: %v", err)
	}
	terminal.Status = AWSConnectorOnboardingAttemptValidating
	if _, err := store.UpdateAWSConnectorOnboardingAttempt(ctx, terminal, terminal.Version); !errors.Is(err, ErrConflict) {
		t.Fatalf("reactivating an old attempt must not bypass one-active invariant, got %v", err)
	}
	if _, err := store.UpdateAWSConnectorOnboardingAttempt(ctx, terminal, terminal.Version-1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update must fail, got %v", err)
	}
}
