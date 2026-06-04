package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
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
		UserUUID:    "00000000-0000-0000-0000-000000000001",
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
	memberByUser, err := store.GetWorkspaceMemberByUserUUID(ctx, "workspace-a", "00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("get workspace member by user uuid: %v", err)
	}
	if memberByUser.MemberID != "member-1" {
		t.Fatalf("unexpected member by user uuid: %+v", memberByUser)
	}
	if _, err := store.GetWorkspaceMemberByUserUUID(ctx, "workspace-a", "00000000-0000-0000-0000-000000000002"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing workspace member by user uuid to return ErrNotFound, got %v", err)
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

func TestMemoryStoreClaimKubernetesEnrollmentToken(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seededAt := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	tokenHash := "kubernetes-token-hash"

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	}); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "kubernetes-agent",
		Type:        domain.ConnectorTypeKubernetes,
		DisplayName: "Agent cluster",
		Status:      domain.ConnectorStatusPending,
		CreatedAt:   seededAt,
		UpdatedAt:   seededAt,
	}, TenancyConnectorState{
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "kubernetes-agent",
		HealthStatus: "unknown",
		Metadata: map[string]any{
			"enrollment_token_sha256": tokenHash,
		},
		ObservedAt: seededAt,
		UpdatedAt:  seededAt,
	}); err != nil {
		t.Fatalf("seed kubernetes connector: %v", err)
	}

	now := time.Now().UTC()
	payload := map[string]any{
		"enrollment_token_sha256":  tokenHash,
		"enrollment_token_used_at": now.Format(time.RFC3339Nano),
	}

	var wg sync.WaitGroup
	claims := make(chan bool, 2)
	errors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(claimIndex int) {
			defer wg.Done()
			claimed, err := store.ClaimKubernetesEnrollmentToken(
				ctx,
				"workspace-a",
				"project-1",
				"kubernetes-agent",
				tokenHash,
				payload,
				domain.ConnectorStatusActive,
				"healthy",
				"",
				"",
				now,
				now.Add(time.Duration(claimIndex)*time.Millisecond),
			)
			if err != nil {
				errors <- err
				return
			}
			claims <- claimed
		}(i)
	}
	wg.Wait()
	close(errors)
	close(claims)
	for err := range errors {
		if err != nil {
			t.Fatalf("claim kubernetes enrollment token: %v", err)
		}
	}

	successes := 0
	for claimed := range claims {
		if claimed {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one claim success, got %d", successes)
	}

	reloaded, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "kubernetes-agent")
	if err != nil {
		t.Fatalf("reload connector: %v", err)
	}
	usedAt, ok := reloaded.State.Metadata["enrollment_token_used_at"].(string)
	if !ok || usedAt == "" {
		t.Fatalf("expected enrollment_token_used_at to be persisted, got %+v", reloaded.State.Metadata["enrollment_token_used_at"])
	}
	if usedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("expected enrollment token used time to match claim payload, expected %s got %s", now.Format(time.RFC3339Nano), usedAt)
	}
	if reloaded.State.HealthStatus != "healthy" {
		t.Fatalf("expected connector health status to be persisted as healthy, got %q", reloaded.State.HealthStatus)
	}
	if reloaded.Connector.Status != domain.ConnectorStatusActive {
		t.Fatalf("expected connector status to be active, got %q", reloaded.Connector.Status)
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
	if err := store.DeleteTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "github", "webhook_secret"); err != nil {
		t.Fatalf("delete connector secret envelope: %v", err)
	}
	if _, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "github", "webhook_secret"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected deleted connector secret envelope to be missing, got %v", err)
	}
}

func TestMemoryStoreAWSAccountRegionCoverageRegistry(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	tenantB := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	for _, projectID := range []string{"project-1", "project-2"} {
		if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "workspace-a", ProjectID: projectID, Name: projectID, Slug: projectID}); err != nil {
			t.Fatalf("upsert project %s: %v", projectID, err)
		}
	}
	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Production AWS",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{WorkspaceID: "workspace-a", ProjectID: "project-1", ConnectorID: "aws-prod", HealthStatus: "healthy"}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-2",
		ConnectorID: "aws-prod",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Other AWS",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{WorkspaceID: "workspace-a", ProjectID: "project-2", ConnectorID: "aws-prod", HealthStatus: "healthy"}); err != nil {
		t.Fatalf("upsert project-2 connector: %v", err)
	}
	if err := store.UpsertOrganization(tenantB, TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("upsert tenant-b organization: %v", err)
	}
	if err := store.UpsertWorkspace(tenantB, TenancyWorkspace{WorkspaceID: "workspace-b", DisplayName: "Workspace B", Slug: "workspace-b"}); err != nil {
		t.Fatalf("upsert tenant-b workspace: %v", err)
	}
	if err := store.UpsertProject(tenantB, TenancyProject{WorkspaceID: "workspace-b", ProjectID: "project-1", Name: "Project B", Slug: "project-b"}); err != nil {
		t.Fatalf("upsert tenant-b project: %v", err)
	}
	if err := store.UpsertTenancyConnector(tenantB, TenancyConnector{
		WorkspaceID: "workspace-b",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Tenant B AWS",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{WorkspaceID: "workspace-b", ProjectID: "project-1", ConnectorID: "aws-prod", HealthStatus: "healthy"}); err != nil {
		t.Fatalf("upsert tenant-b connector: %v", err)
	}

	if _, err := store.UpsertAWSAccountRegionCoverage(ctx, AWSAccountRegionCoverage{
		WorkspaceID:          "workspace-a",
		ProjectID:            "project-1",
		ConnectorID:          "aws-prod",
		AccountID:            "222222222222",
		AccountAlias:         "Analytics",
		OrganizationID:       "o-example",
		OUPath:               "/Root/Prod",
		Partition:            "aws",
		Region:               "us-east-1",
		RoleARN:              "arn:aws:iam::222222222222:role/IdentrailReadOnly",
		CoverageStatus:       AWSAccountRegionCoverageCovered,
		LastSuccessfulScanAt: &now,
		ScanCursor:           map[string]any{"cursor": "one"},
	}); err != nil {
		t.Fatalf("upsert coverage: %v", err)
	}
	if _, err := store.UpsertAWSAccountRegionCoverage(ctx, AWSAccountRegionCoverage{
		WorkspaceID:              "workspace-a",
		ProjectID:                "project-1",
		ConnectorID:              "aws-prod",
		AccountID:                "111111111111",
		Region:                   "us-west-2",
		CoverageStatus:           AWSAccountRegionCoverageError,
		LastObservedErrorCode:    "access_denied",
		LastObservedErrorMessage: "AssumeRole denied for this account.",
		ScanCursor:               map[string]any{"cursor": "blocked"},
	}); err != nil {
		t.Fatalf("upsert errored coverage: %v", err)
	}
	updated, err := store.UpsertAWSAccountRegionCoverage(ctx, AWSAccountRegionCoverage{
		WorkspaceID:              "workspace-a",
		ProjectID:                "project-1",
		ConnectorID:              "aws-prod",
		AccountID:                "111111111111",
		Region:                   "us-west-2",
		CoverageStatus:           AWSAccountRegionCoverageUnreachable,
		LastObservedErrorCode:    "timeout",
		LastObservedErrorMessage: "Timed out listing IAM roles.",
		ScanCursor:               map[string]any{"retry_after": "2026-05-12T12:05:00Z"},
		Unreachable:              true,
	})
	if err != nil {
		t.Fatalf("update coverage: %v", err)
	}
	retryAfter, retryAfterOK := updated.ScanCursor["retry_after"].(string)
	if updated.LastObservedErrorCode != "timeout" || !retryAfterOK || retryAfter == "" {
		t.Fatalf("expected clean last-observed update, got %+v", updated)
	}
	if _, err := store.UpsertAWSAccountRegionCoverage(ctx, AWSAccountRegionCoverage{
		WorkspaceID:    "workspace-a",
		ProjectID:      "project-2",
		ConnectorID:    "aws-prod",
		AccountID:      "333333333333",
		Region:         "eu-west-1",
		CoverageStatus: AWSAccountRegionCoverageCovered,
	}); err != nil {
		t.Fatalf("upsert project-2 coverage: %v", err)
	}
	if _, err := store.UpsertAWSAccountRegionCoverage(tenantB, AWSAccountRegionCoverage{
		WorkspaceID:    "workspace-b",
		ProjectID:      "project-1",
		ConnectorID:    "aws-prod",
		AccountID:      "444444444444",
		Region:         "us-east-1",
		CoverageStatus: AWSAccountRegionCoverageCovered,
	}); err != nil {
		t.Fatalf("upsert tenant-b coverage: %v", err)
	}

	records, err := store.ListAWSAccountRegionCoverages(ctx, AWSAccountRegionCoverageFilter{WorkspaceID: "workspace-a", ProjectID: "project-1", ConnectorID: "aws-prod", Limit: 10})
	if err != nil {
		t.Fatalf("list coverage: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two project-scoped records, got %+v", records)
	}
	if records[0].AccountID != "111111111111" || records[1].AccountID != "222222222222" {
		t.Fatalf("expected deterministic account ordering, got %+v", records)
	}
	if records[0].CoverageStatus != AWSAccountRegionCoverageUnreachable {
		t.Fatalf("expected idempotent update to replace status, got %+v", records[0])
	}
	records[0].ScanCursor["retry_after"] = "mutated"
	reloaded, err := store.ListAWSAccountRegionCoverages(ctx, AWSAccountRegionCoverageFilter{WorkspaceID: "workspace-a", ProjectID: "project-1", AccountID: "111111111111"})
	if err != nil {
		t.Fatalf("reload coverage: %v", err)
	}
	if reloaded[0].ScanCursor["retry_after"] == "mutated" {
		t.Fatalf("expected scan cursor to be copied defensively")
	}
	if other, err := store.ListAWSAccountRegionCoverages(ctx, AWSAccountRegionCoverageFilter{WorkspaceID: "workspace-a", ProjectID: "project-2"}); err != nil || len(other) != 1 || other[0].AccountID != "333333333333" {
		t.Fatalf("expected project isolation, got records=%+v err=%v", other, err)
	}
	if tenantBRecords, err := store.ListAWSAccountRegionCoverages(tenantB, AWSAccountRegionCoverageFilter{WorkspaceID: "workspace-b", ProjectID: "project-1"}); err != nil || len(tenantBRecords) != 1 || tenantBRecords[0].AccountID != "444444444444" {
		t.Fatalf("expected tenant isolation, got records=%+v err=%v", tenantBRecords, err)
	}
	connector, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-prod")
	if err != nil {
		t.Fatalf("reload connector: %v", err)
	}
	if connector.Connector.Status != domain.ConnectorStatusActive || connector.State.HealthStatus != "healthy" {
		t.Fatalf("account-level coverage error should not disconnect connector, got %+v", connector)
	}
}

func TestMemoryStoreAWSPlatformBaselineResult(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	tenantB := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

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
		ConnectorID: "aws-prod",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Production AWS",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{WorkspaceID: "workspace-a", ProjectID: "project-1", ConnectorID: "aws-prod", HealthStatus: "healthy"}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	if err := store.UpsertOrganization(tenantB, TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("upsert tenant-b organization: %v", err)
	}
	if err := store.UpsertWorkspace(tenantB, TenancyWorkspace{WorkspaceID: "workspace-b", DisplayName: "Workspace B", Slug: "workspace-b"}); err != nil {
		t.Fatalf("upsert tenant-b workspace: %v", err)
	}
	if err := store.UpsertProject(tenantB, TenancyProject{WorkspaceID: "workspace-b", ProjectID: "project-1", Name: "Project B", Slug: "project-b"}); err != nil {
		t.Fatalf("upsert tenant-b project: %v", err)
	}

	result, err := store.UpsertAWSPlatformBaselineResult(ctx, AWSPlatformBaselineResult{
		WorkspaceID:          "workspace-a",
		ProjectID:            "project-1",
		ConnectorID:          "aws-prod",
		GitSHA:               "6dd631b1",
		SourceMode:           "fixture",
		FixtureOnly:          true,
		AccountID:            "123456789012",
		Region:               "US-WEST-2",
		Status:               AWSPlatformBaselineStatusReady,
		Confidence:           1.2,
		RequiredChecksPassed: true,
		EvidenceLinks:        []string{"/app/tenant-a/workspace-a/aws"},
		Checks: []AWSPlatformBaselineCheck{{
			Name:       "aws_connector_health",
			Required:   true,
			Status:     AWSPlatformBaselineCheckPassed,
			Message:    "ok",
			Confidence: 0.9,
			Evidence:   map[string]any{"connector_id": "aws-prod"},
			CheckedAt:  now,
		}},
		VerifiedAt: now,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("upsert baseline: %v", err)
	}
	if result.Region != "us-west-2" || result.Confidence != 1 {
		t.Fatalf("expected normalized baseline, got %+v", result)
	}
	result.Checks[0].Evidence["connector_id"] = "mutated"
	reloaded, err := store.GetAWSPlatformBaselineResult(ctx, AWSPlatformBaselineFilter{WorkspaceID: "workspace-a", ProjectID: "project-1", ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("reload baseline: %v", err)
	}
	if reloaded.Checks[0].Evidence["connector_id"] == "mutated" {
		t.Fatalf("expected baseline evidence to be copied defensively")
	}
	if _, err := store.GetAWSPlatformBaselineResult(tenantB, AWSPlatformBaselineFilter{WorkspaceID: "workspace-b", ProjectID: "project-1", ConnectorID: "aws-prod"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected tenant isolation, got %v", err)
	}
	if _, err := store.UpsertAWSPlatformBaselineResult(ctx, AWSPlatformBaselineResult{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "missing",
		Status:      AWSPlatformBaselineStatusBlocked,
		VerifiedAt:  now,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing connector to be rejected, got %v", err)
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

func TestMemoryStoreFindFirstWorkspaceMemberByUserUUID(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	userUUID := "11111111-1111-1111-1111-111111111111"
	ctx := context.Background()
	tenantA := WithScope(ctx, Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(tenantA, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert tenant a: %v", err)
	}
	if err := store.UpsertWorkspace(tenantA, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace a: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantA, TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "subject-a",
		UserUUID:    userUUID,
		Email:       "user@example.com",
		Role:        "admin",
		Status:      "active",
		JoinedAt:    now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("upsert member a: %v", err)
	}
	tenantB := WithScope(ctx, Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	if err := store.UpsertOrganization(tenantB, TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("upsert tenant b: %v", err)
	}
	if err := store.UpsertWorkspace(tenantB, TenancyWorkspace{WorkspaceID: "workspace-b", DisplayName: "Workspace B", Slug: "workspace-b"}); err != nil {
		t.Fatalf("upsert workspace b: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantB, TenancyWorkspaceMember{
		WorkspaceID: "workspace-b",
		MemberID:    "member-b",
		UserID:      "subject-b",
		UserUUID:    userUUID,
		Email:       "user@example.com",
		Role:        "viewer",
		Status:      "active",
		JoinedAt:    now,
	}); err != nil {
		t.Fatalf("upsert member b: %v", err)
	}

	latest, err := store.FindFirstWorkspaceMemberByUserUUID(ctx, userUUID)
	if err != nil {
		t.Fatalf("find latest member: %v", err)
	}
	if latest.TenantID != "tenant-b" || latest.WorkspaceID != "workspace-b" {
		t.Fatalf("expected newest membership, got %+v", latest)
	}
	selected, err := store.FindFirstWorkspaceMemberByUserUUIDAndTenantID(ctx, userUUID, "tenant-a")
	if err != nil {
		t.Fatalf("find selected tenant member: %v", err)
	}
	if selected.TenantID != "tenant-a" || selected.WorkspaceID != "workspace-a" {
		t.Fatalf("expected selected tenant membership, got %+v", selected)
	}
	if _, err := store.FindFirstWorkspaceMemberByUserUUIDAndTenantID(ctx, userUUID, "tenant-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing selected tenant to return ErrNotFound, got %v", err)
	}
}

func TestMemoryStoreScanPolicyCRUD(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-1", Name: "Project 1", Slug: "project-1"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		PolicyID:           "default",
		Name:               "Default policy",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeScheduled,
		Cron:               "0 * * * *",
		MaxConcurrentScans: 2,
		HistoryLimit:       300,
		MaxFindings:        120,
	}); err != nil {
		t.Fatalf("upsert scan policy: %v", err)
	}

	policy, err := store.GetTenancyScanPolicy(ctx, "workspace-a", "project-1", "default")
	if err != nil {
		t.Fatalf("get scan policy: %v", err)
	}
	if policy.TriggerMode != domain.ScanTriggerModeScheduled || policy.HistoryLimit != 300 || policy.MaxFindings != 120 {
		t.Fatalf("unexpected scan policy payload: %+v", policy)
	}

	enabled := true
	policies, err := store.ListTenancyScanPolicies(ctx, "workspace-a", "project-1", domain.ScanTriggerModeScheduled, &enabled, "created_at", false, 20)
	if err != nil {
		t.Fatalf("list scan policies: %v", err)
	}
	if len(policies) != 1 || policies[0].PolicyID != "default" {
		t.Fatalf("unexpected scan policy list payload: %+v", policies)
	}

	if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		PolicyID:           "alpha",
		Name:               "Alpha policy",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeManual,
		MaxConcurrentScans: 1,
	}); err != nil {
		t.Fatalf("upsert alpha scan policy: %v", err)
	}
	if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		PolicyID:           "zulu",
		Name:               "Zulu policy",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeManual,
		MaxConcurrentScans: 1,
	}); err != nil {
		t.Fatalf("upsert zulu scan policy: %v", err)
	}
	sorted, err := store.ListTenancyScanPolicies(ctx, "workspace-a", "project-1", "", nil, "name", false, 1)
	if err != nil {
		t.Fatalf("list scan policies sorted by name: %v", err)
	}
	if len(sorted) != 1 || sorted[0].PolicyID != "alpha" {
		t.Fatalf("expected name sort before limit to return alpha first, got %+v", sorted)
	}
	sorted, err = store.ListTenancyScanPolicies(ctx, "workspace-a", "project-1", "", nil, "name", true, 1)
	if err != nil {
		t.Fatalf("list scan policies sorted by name desc: %v", err)
	}
	if len(sorted) != 1 || sorted[0].PolicyID != "zulu" {
		t.Fatalf("expected descending name sort before limit to return zulu first, got %+v", sorted)
	}

	if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		PolicyID:           "secondary",
		Name:               "Default policy",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeManual,
		MaxConcurrentScans: 1,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate scan policy name conflict, got %v", err)
	}

	if err := store.DeleteTenancyScanPolicy(ctx, "workspace-a", "project-1", "default"); err != nil {
		t.Fatalf("delete scan policy: %v", err)
	}
	if _, err := store.GetTenancyScanPolicy(ctx, "workspace-a", "project-1", "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected deleted scan policy to return ErrNotFound, got %v", err)
	}
}

func TestMemoryStoreScheduledScanPolicyPaginationAndClaim(t *testing.T) {
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "workspace-a", DisplayName: "Workspace A", Slug: "workspace-a"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-1", Name: "Project 1", Slug: "project-1"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
			WorkspaceID:        "workspace-a",
			ProjectID:          "project-1",
			PolicyID:           "scheduled-" + string(rune('a'+i)),
			Name:               "Scheduled " + string(rune('A'+i)),
			Enabled:            true,
			TriggerMode:        domain.ScanTriggerModeScheduled,
			Cron:               "*/5 * * * *",
			MaxConcurrentScans: 1,
			CreatedAt:          createdAt.Add(time.Duration(i) * time.Minute),
			UpdatedAt:          createdAt.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("upsert scheduled policy %d: %v", i, err)
		}
	}
	if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		PolicyID:           "manual-1",
		Name:               "Manual 1",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeManual,
		MaxConcurrentScans: 1,
	}); err != nil {
		t.Fatalf("upsert manual policy: %v", err)
	}

	page, err := store.ListScheduledTenancyScanPolicies(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListScheduledTenancyScanPolicies page 1: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("expected first page length 2, got %d", len(page))
	}
	nextPage, err := store.ListScheduledTenancyScanPolicies(ctx, 2, 2)
	if err != nil {
		t.Fatalf("ListScheduledTenancyScanPolicies page 2: %v", err)
	}
	if len(nextPage) != 1 {
		t.Fatalf("expected second page length 1, got %d", len(nextPage))
	}

	claimTick := time.Date(2026, 5, 12, 12, 5, 0, 0, time.UTC)
	now := claimTick.Add(30 * time.Second)
	claimed, err := store.ClaimTenancyScanPolicySchedule(ctx, "workspace-a", "project-1", page[0].PolicyID, claimTick, now)
	if err != nil {
		t.Fatalf("ClaimTenancyScanPolicySchedule returned error: %v", err)
	}
	if !claimed {
		t.Fatal("expected initial claim to succeed")
	}
	claimed, err = store.ClaimTenancyScanPolicySchedule(ctx, "workspace-a", "project-1", page[0].PolicyID, claimTick, now.Add(time.Second))
	if err != nil {
		t.Fatalf("ClaimTenancyScanPolicySchedule duplicate returned error: %v", err)
	}
	if claimed {
		t.Fatal("expected duplicate claim to be rejected")
	}

	if _, err := store.SuspendWorkspace(ctx, "workspace-a", createdAt.Add(time.Hour)); err != nil {
		t.Fatalf("suspend workspace: %v", err)
	}
	suspendedPage, err := store.ListScheduledTenancyScanPolicies(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListScheduledTenancyScanPolicies suspended: %v", err)
	}
	if len(suspendedPage) != 0 {
		t.Fatalf("expected suspended workspace policies to be hidden, got %+v", suspendedPage)
	}
	claimed, err = store.ClaimTenancyScanPolicySchedule(ctx, "workspace-a", "project-1", page[1].PolicyID, claimTick.Add(time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimTenancyScanPolicySchedule suspended returned error: %v", err)
	}
	if claimed {
		t.Fatal("expected suspended workspace claim to be rejected")
	}
}

func TestMemoryStoreListWorkspaceMembershipsByUserUUIDAndTenantID(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)
	userUUID := "11111111-1111-1111-1111-111111111111"
	ctx := context.Background()

	tenantA := WithScope(ctx, Scope{TenantID: "tenant-a", WorkspaceID: "ws-1"})
	if err := store.UpsertOrganization(tenantA, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org a: %v", err)
	}
	for _, ws := range []string{"ws-1", "ws-2", "ws-3"} {
		wsCtx := WithScope(ctx, Scope{TenantID: "tenant-a", WorkspaceID: ws})
		if err := store.UpsertWorkspace(wsCtx, TenancyWorkspace{WorkspaceID: ws, DisplayName: ws, Slug: ws}); err != nil {
			t.Fatalf("upsert workspace %s: %v", ws, err)
		}
	}
	// Active in ws-1 and ws-2, suspended in ws-3 (must be excluded).
	for _, m := range []struct {
		ws, status string
	}{{"ws-1", "active"}, {"ws-2", "active"}, {"ws-3", "suspended"}} {
		wsCtx := WithScope(ctx, Scope{TenantID: "tenant-a", WorkspaceID: m.ws})
		if err := store.UpsertWorkspaceMember(wsCtx, TenancyWorkspaceMember{
			WorkspaceID: m.ws, MemberID: "member-" + m.ws, UserID: "subject", UserUUID: userUUID,
			Role: "viewer", Status: m.status, JoinedAt: now,
		}); err != nil {
			t.Fatalf("upsert member %s: %v", m.ws, err)
		}
	}
	// Different tenant membership must never leak in.
	tenantB := WithScope(ctx, Scope{TenantID: "tenant-b", WorkspaceID: "ws-b"})
	if err := store.UpsertOrganization(tenantB, TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("upsert org b: %v", err)
	}
	if err := store.UpsertWorkspace(tenantB, TenancyWorkspace{WorkspaceID: "ws-b", DisplayName: "ws-b", Slug: "ws-b"}); err != nil {
		t.Fatalf("upsert workspace b: %v", err)
	}
	if err := store.UpsertWorkspaceMember(tenantB, TenancyWorkspaceMember{
		WorkspaceID: "ws-b", MemberID: "member-b", UserID: "subject", UserUUID: userUUID,
		Role: "viewer", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert member b: %v", err)
	}

	memberships, err := store.ListWorkspaceMembershipsByUserUUIDAndTenantID(ctx, userUUID, "tenant-a")
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	got := []string{}
	for _, m := range memberships {
		got = append(got, m.WorkspaceID)
	}
	if len(got) != 2 || got[0] != "ws-1" || got[1] != "ws-2" {
		t.Fatalf("want active tenant-a memberships [ws-1 ws-2], got %v", got)
	}

	empty, err := store.ListWorkspaceMembershipsByUserUUIDAndTenantID(ctx, userUUID, "tenant-missing")
	if err != nil {
		t.Fatalf("missing tenant should not error: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no memberships for unknown tenant, got %v", empty)
	}
}

func TestMemoryStoreListSoleOwnerWorkspaces(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-1"})
	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	for _, workspaceID := range []string{"ws-sole", "ws-shared", "ws-other"} {
		scoped := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: workspaceID})
		if err := store.UpsertWorkspace(scoped, TenancyWorkspace{WorkspaceID: workspaceID, DisplayName: workspaceID, Slug: workspaceID}); err != nil {
			t.Fatalf("upsert workspace %s: %v", workspaceID, err)
		}
	}
	userUUID := "11111111-1111-1111-1111-111111111111"
	other := "22222222-2222-2222-2222-222222222222"

	scopedSole := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-sole"})
	if err := store.UpsertWorkspaceMember(scopedSole, TenancyWorkspaceMember{
		WorkspaceID: "ws-sole", MemberID: "m-sole", UserID: "subj-sole", UserUUID: userUUID,
		Role: "owner", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert sole owner: %v", err)
	}

	scopedShared := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-shared"})
	if err := store.UpsertWorkspaceMember(scopedShared, TenancyWorkspaceMember{
		WorkspaceID: "ws-shared", MemberID: "m-shared-1", UserID: "subj-shared-1", UserUUID: userUUID,
		Role: "owner", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert shared owner 1: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopedShared, TenancyWorkspaceMember{
		WorkspaceID: "ws-shared", MemberID: "m-shared-2", UserID: "subj-shared-2", UserUUID: other,
		Role: "owner", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert shared owner 2: %v", err)
	}

	scopedOther := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-other"})
	if err := store.UpsertWorkspaceMember(scopedOther, TenancyWorkspaceMember{
		WorkspaceID: "ws-other", MemberID: "m-other", UserID: "subj-other", UserUUID: other,
		Role: "owner", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert other workspace: %v", err)
	}

	results, err := store.ListSoleOwnerWorkspaces(context.Background(), userUUID)
	if err != nil {
		t.Fatalf("list sole owner: %v", err)
	}
	if len(results) != 1 || results[0].WorkspaceID != "ws-sole" {
		t.Fatalf("expected only ws-sole, got %+v", results)
	}
}

func TestMemoryStoreListSoleOwnerWorkspacesIgnoresDeletedOwners(t *testing.T) {
	// A workspace with one active owner (the caller) and one membership row
	// pointing at a soft-deleted user must be flagged as sole-owned by the
	// caller. A deleted user cannot transfer ownership, so counting them as
	// a live owner would let the caller delete their own account and leave
	// the workspace with zero live owners — exactly the invariant the
	// sole-owner guard exists to enforce.
	store := NewMemoryStore()
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	caller, err := store.UpsertUser(context.Background(), User{PrimaryEmail: "caller@example.com"})
	if err != nil {
		t.Fatalf("upsert caller: %v", err)
	}
	ghost, err := store.UpsertUser(context.Background(), User{PrimaryEmail: "ghost@example.com"})
	if err != nil {
		t.Fatalf("upsert ghost: %v", err)
	}
	if _, err := store.SoftDeleteUser(context.Background(), ghost.ID, now.Add(-24*time.Hour)); err != nil {
		t.Fatalf("soft delete ghost: %v", err)
	}

	scoped := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-shared"})
	if err := store.UpsertOrganization(scoped, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(scoped, TenancyWorkspace{WorkspaceID: "ws-shared", DisplayName: "Shared", Slug: "ws-shared"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scoped, TenancyWorkspaceMember{
		WorkspaceID: "ws-shared", MemberID: "m-caller", UserID: "subj-caller", UserUUID: caller.ID,
		Role: "owner", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert caller membership: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scoped, TenancyWorkspaceMember{
		WorkspaceID: "ws-shared", MemberID: "m-ghost", UserID: "subj-ghost", UserUUID: ghost.ID,
		Role: "owner", Status: "active", JoinedAt: now,
	}); err != nil {
		t.Fatalf("upsert ghost membership: %v", err)
	}

	results, err := store.ListSoleOwnerWorkspaces(context.Background(), caller.ID)
	if err != nil {
		t.Fatalf("list sole owner: %v", err)
	}
	if len(results) != 1 || results[0].WorkspaceID != "ws-shared" {
		t.Fatalf("expected ws-shared flagged with deleted co-owner excluded, got %+v", results)
	}
}

// setupWorkspaceLifecycleStore seeds tenant-a/workspace-a with one active
// owner member and returns the populated store + scoped context.
func setupWorkspaceLifecycleStore(t *testing.T) (*MemoryStore, context.Context, string) {
	t.Helper()
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-1"})
	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "ws-1", DisplayName: "Workspace 1", Slug: "ws-1"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	ownerUUID := "11111111-1111-1111-1111-111111111111"
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "ws-1", MemberID: "m-owner", UserID: "subj-owner", UserUUID: ownerUUID,
		Role: "owner", Status: "active",
	}); err != nil {
		t.Fatalf("upsert owner member: %v", err)
	}
	return store, ctx, ownerUUID
}

func TestMemoryStoreSuspendWorkspaceIsIdempotent(t *testing.T) {
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	first, err := store.SuspendWorkspace(ctx, "ws-1", now)
	if err != nil {
		t.Fatalf("first suspend: %v", err)
	}
	if first.Status != WorkspaceStatusSuspended || first.SuspendedAt == nil {
		t.Fatalf("expected suspended status with timestamp, got %+v", first)
	}
	later := now.Add(48 * time.Hour)
	second, err := store.SuspendWorkspace(ctx, "ws-1", later)
	if err != nil {
		t.Fatalf("second suspend: %v", err)
	}
	if !second.SuspendedAt.Equal(*first.SuspendedAt) {
		t.Fatalf("expected idempotent suspended_at, first=%v second=%v", first.SuspendedAt, second.SuspendedAt)
	}
}

func TestMemoryStoreSuspendWorkspaceRefusesDeleted(t *testing.T) {
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-1", now); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := store.SuspendWorkspace(ctx, "ws-1", now.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict when suspending deleted workspace, got %v", err)
	}
}

func TestMemoryStoreReactivateWorkspaceClearsTimestamp(t *testing.T) {
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.SuspendWorkspace(ctx, "ws-1", now); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	saved, err := store.ReactivateWorkspace(ctx, "ws-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if saved.Status != WorkspaceStatusActive || saved.SuspendedAt != nil {
		t.Fatalf("expected reactivate to clear suspended_at, got %+v", saved)
	}
}

func TestMemoryStoreReactivateWorkspaceRefusesDeleted(t *testing.T) {
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-1", now); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := store.ReactivateWorkspace(ctx, "ws-1", now.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict when reactivating deleted workspace, got %v", err)
	}
}

func TestMemoryStoreSoftDeleteWorkspacePreservesDeletedAt(t *testing.T) {
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	first, err := store.SoftDeleteWorkspace(ctx, "ws-1", now)
	if err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if first.Status != WorkspaceStatusDeleted || first.DeletedAt == nil {
		t.Fatalf("expected deleted status with timestamp, got %+v", first)
	}
	second, err := store.SoftDeleteWorkspace(ctx, "ws-1", now.Add(72*time.Hour))
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if !second.DeletedAt.Equal(*first.DeletedAt) {
		t.Fatalf("expected idempotent deleted_at, first=%v second=%v", first.DeletedAt, second.DeletedAt)
	}
}

func TestMemoryStoreCancelWorkspaceDeletionRestoresActive(t *testing.T) {
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-1", now); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	saved, err := store.CancelWorkspaceDeletion(ctx, "ws-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if saved.Status != WorkspaceStatusActive || saved.DeletedAt != nil {
		t.Fatalf("expected cancel to clear deleted_at, got %+v", saved)
	}
}

func TestMemoryStoreListSoleOwnerWorkspacesIgnoresDeleted(t *testing.T) {
	store, ctx, ownerUUID := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-1", now); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	workspaces, err := store.ListSoleOwnerWorkspaces(context.Background(), ownerUUID)
	if err != nil {
		t.Fatalf("list sole-owner workspaces: %v", err)
	}
	if len(workspaces) != 0 {
		t.Fatalf("expected deleted sole-owned workspace to be ignored, got %+v", workspaces)
	}
}

func TestMemoryStoreUpsertWorkspacePreservesLifecycleFields(t *testing.T) {
	// Casual UpsertWorkspace (e.g. a display-name rename) must not revive a
	// deleted or suspended row by accident — lifecycle fields are owned by
	// the dedicated Suspend/SoftDelete/Cancel/Reactivate paths.
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-1", now); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "ws-1",
		DisplayName: "Workspace 1 Renamed",
		Slug:        "ws-1",
	}); err != nil {
		t.Fatalf("rename upsert: %v", err)
	}
	saved, err := store.GetWorkspace(ctx, "ws-1")
	if err != nil {
		t.Fatalf("get workspace: %v", err)
	}
	if saved.Status != WorkspaceStatusDeleted || saved.DeletedAt == nil {
		t.Fatalf("expected lifecycle preserved after upsert, got %+v", saved)
	}
	if saved.DisplayName != "Workspace 1 Renamed" {
		t.Fatalf("expected rename to apply, got %q", saved.DisplayName)
	}
}

func TestMemoryStoreListWorkspacesPendingHardDeleteFiltersByGrace(t *testing.T) {
	// #1420 PR 2: only soft-deleted workspaces past the grace cutoff
	// show up in the pending list. Active workspaces, suspended
	// workspaces, and within-grace deletions must all be excluded so
	// the purge worker never touches data it shouldn't.
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))
	future := now.Add(-(WorkspaceDeletionGracePeriod / 2))

	// Soft-delete ws-1 past grace.
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-1", past); err != nil {
		t.Fatalf("soft delete ws-1: %v", err)
	}
	// Add ws-2 still within grace.
	scoped2 := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-2"})
	if err := store.UpsertWorkspace(scoped2, TenancyWorkspace{WorkspaceID: "ws-2", DisplayName: "Workspace 2", Slug: "ws-2"}); err != nil {
		t.Fatalf("upsert ws-2: %v", err)
	}
	if _, err := store.SoftDeleteWorkspace(scoped2, "ws-2", future); err != nil {
		t.Fatalf("soft delete ws-2: %v", err)
	}
	// Add ws-3 fully active.
	scoped3 := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-3"})
	if err := store.UpsertWorkspace(scoped3, TenancyWorkspace{WorkspaceID: "ws-3", DisplayName: "Workspace 3", Slug: "ws-3"}); err != nil {
		t.Fatalf("upsert ws-3: %v", err)
	}

	cutoff := now.Add(-WorkspaceDeletionGracePeriod)
	pending, err := store.ListWorkspacesPendingHardDelete(context.Background(), cutoff, 100)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 || pending[0].WorkspaceID != "ws-1" {
		t.Fatalf("expected only ws-1 in pending list, got %+v", pending)
	}
}

func TestMemoryStoreHardDeleteWorkspaceRefusesActive(t *testing.T) {
	// HardDeleteWorkspace refuses any row that is not in the
	// soft-deleted state. Defends against a programming error that
	// would otherwise silently destroy live data.
	store, _, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", now, now); err == nil {
		t.Fatal("expected hard delete to refuse active workspace")
	}
}

// hasMemoryKeyWithPrefix reports whether any key in m starts with the
// given prefix. Used by the HardDeleteWorkspace cascade test below.
func hasMemoryKeyWithPrefix[V any](m map[string]V, prefix string) bool {
	for key := range m {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func TestMemoryStoreHardDeleteWorkspaceCascadesScanArtifacts(t *testing.T) {
	// Codex round-4 P2 on #1450: the postgres backend cascades
	// scan/repo_scan child rows via FK ON DELETE CASCADE, but the
	// memory backend has no such cascade. The previous purge dropped
	// only the parent scan/repo_scan map entries and left every child
	// artifact map (rawAssets, identities, policies, relationships,
	// permissions, findings, scanFindings, events) populated for the
	// purged workspace's scans. Pin the explicit cascade so memory +
	// postgres reach the same hard-delete end state.
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	scanRecord, err := store.CreateScan(ctx, "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertArtifacts(ctx, scanRecord.ID, ScanArtifacts{
		RawAssets: []providers.RawAsset{{SourceID: "raw-1", Kind: "iam_role"}},
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "id-1"}},
			Policies:   []domain.Policy{{ID: "p-1"}},
		},
		Relationships: []domain.Relationship{{ID: "r-1", FromNodeID: "id-1", ToNodeID: "p-1"}},
	}); err != nil {
		t.Fatalf("upsert scan artifacts: %v", err)
	}

	saved, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
		t.Fatalf("hard delete: %v", err)
	}

	prefix := scanRecord.ID + "|"
	if hasMemoryKeyWithPrefix(store.rawAssets, prefix) {
		t.Fatalf("expected rawAssets entries for purged scan %s removed", scanRecord.ID)
	}
	if hasMemoryKeyWithPrefix(store.identities, prefix) {
		t.Fatalf("expected identities entries for purged scan %s removed", scanRecord.ID)
	}
	if hasMemoryKeyWithPrefix(store.policies, prefix) {
		t.Fatalf("expected policies entries for purged scan %s removed", scanRecord.ID)
	}
	if hasMemoryKeyWithPrefix(store.relationships, prefix) {
		t.Fatalf("expected relationships entries for purged scan %s removed", scanRecord.ID)
	}
	if _, ok := store.scanFindings[scanRecord.ID]; ok {
		t.Fatalf("expected scanFindings entry for %s removed", scanRecord.ID)
	}
	if _, ok := store.events[scanRecord.ID]; ok {
		t.Fatalf("expected events entry for %s removed", scanRecord.ID)
	}
}

func TestMemoryStoreHardDeleteWorkspacePurgesAuthzAndTriageMaps(t *testing.T) {
	// Codex round-3 P2 on #1450: the memory backend's authz + triage
	// maps live outside the cascade chain (they don't reference
	// tenancy_workspaces). Pin that HardDeleteWorkspace explicitly
	// drains every workspace-scoped entry so the in-memory store
	// matches the postgres purge behavior (and so scoped reads after
	// the purge correctly return ErrNotFound).
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	if err := store.UpsertAuthzEntityAttributes(ctx, AuthzEntityAttributes{
		EntityKind: "subject", EntityType: "user", EntityID: "u-1",
		OwnerTeam: "core",
	}); err != nil {
		t.Fatalf("upsert authz attrs: %v", err)
	}
	if err := store.UpsertAuthzPolicySet(ctx, AuthzPolicySet{PolicySetID: "default", DisplayName: "Default"}); err != nil {
		t.Fatalf("upsert authz policy set: %v", err)
	}
	if err := store.UpsertFindingTriageState(ctx, FindingTriageState{
		FindingID: "finding-1", Status: domain.FindingLifecycleOpen,
	}); err != nil {
		t.Fatalf("upsert triage state: %v", err)
	}

	saved, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
		t.Fatalf("hard delete: %v", err)
	}

	if _, err := store.GetAuthzEntityAttributes(ctx, "subject", "user", "u-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected authz attrs purged, got %v", err)
	}
	if _, err := store.GetAuthzPolicySet(ctx, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected authz policy set purged, got %v", err)
	}
	if _, err := store.GetFindingTriageState(ctx, "finding-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected triage state purged, got %v", err)
	}
}

func TestMemoryStoreHardDeleteWorkspacePurgesAuthzPolicyEventIDs(t *testing.T) {
	// Codex round-4 P2 on #1450: when hard-deleting an authz event
	// bucket, we must also clear the in-memory dedupe set of event IDs.
	// Otherwise, re-appending a historic event ID in the same process after
	// a purge returns ErrAlreadyExists and violates the contract that a hard
	// delete wipes all workspace-scoped authz state.
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	if err := store.UpsertAuthzPolicySet(ctx, AuthzPolicySet{PolicySetID: "default", DisplayName: "Default"}); err != nil {
		t.Fatalf("upsert authz policy set: %v", err)
	}
	versionOne := 1
	if err := store.AppendAuthzPolicyEvent(ctx, AuthzPolicyEvent{
		ID:          "event-delete-me",
		PolicySetID: "default",
		EventType:   "publish",
		ToVersion:   &versionOne,
		Actor:       "owner",
	}); err != nil {
		t.Fatalf("append policy event for deleted workspace: %v", err)
	}

	otherCtx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-2"})
	if err := store.UpsertWorkspace(otherCtx, TenancyWorkspace{WorkspaceID: "ws-2", DisplayName: "Workspace 2", Slug: "ws-2"}); err != nil {
		t.Fatalf("upsert other workspace: %v", err)
	}
	if err := store.UpsertAuthzPolicySet(otherCtx, AuthzPolicySet{PolicySetID: "other", DisplayName: "Other"}); err != nil {
		t.Fatalf("upsert other workspace authz policy set: %v", err)
	}
	if err := store.AppendAuthzPolicyEvent(otherCtx, AuthzPolicyEvent{
		ID:          "event-kept",
		PolicySetID: "other",
		EventType:   "publish",
		ToVersion:   &versionOne,
		Actor:       "owner",
	}); err != nil {
		t.Fatalf("append policy event for non-deleted workspace: %v", err)
	}

	saved, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
		t.Fatalf("hard delete: %v", err)
	}

	if _, exists := store.authzEventIDs["event-delete-me"]; exists {
		t.Fatalf("expected event id removed from dedupe set")
	}
	if _, exists := store.authzEventIDs["event-kept"]; !exists {
		t.Fatalf("expected unrelated event id to remain in dedupe set")
	}
}

func TestMemoryStoreHardDeleteWorkspaceClearsSessionAndOnboardingScope(t *testing.T) {
	// Codex unresolved on #1450: session and onboarding rows keep
	// workspace/project scope even after a hard workspace purge. Postgres
	// cascades those foreign keys to NULL, so memory store should mirror by
	// clearing matching scope fields only for the deleted tenant/workspace.
	store, ctx, ownerUUID := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	owner, err := store.UpsertUser(context.Background(), User{
		ID:           ownerUUID,
		PrimaryEmail: "owner@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("seed owner user: %v", err)
	}

	sessionHash := sha256.Sum256([]byte("workspace-deletion"))
	session, err := store.CreateSession(ctx, Session{
		ID:                sessionHash[:],
		UserID:            owner.ID,
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		LastSeenAt:        now,
		CreatedAt:         now,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := store.UpdateSessionContext(ctx, owner.ID, session.ID, "tenant-a", "ws-1", "project-a", now); err != nil {
		t.Fatalf("update session context: %v", err)
	}

	_, err = store.UpsertOnboardingState(ctx, OnboardingState{
		UserID:      owner.ID,
		CurrentStep: "connect",
		OrgID:       "tenant-a",
		WorkspaceID: "ws-1",
		ProjectID:   "project-a",
		StartedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("upsert onboarding state: %v", err)
	}

	tenantBCtx := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "ws-1"})
	if err := store.UpsertOrganization(tenantBCtx, TenancyOrganization{DisplayName: "Tenant B", Slug: "tenant-b"}); err != nil {
		t.Fatalf("seed tenant b org: %v", err)
	}
	if err := store.UpsertWorkspace(tenantBCtx, TenancyWorkspace{WorkspaceID: "ws-1", DisplayName: "Tenant B Workspace", Slug: "ws-1"}); err != nil {
		t.Fatalf("seed tenant b workspace: %v", err)
	}
	if err := store.UpsertProject(tenantBCtx, TenancyProject{
		WorkspaceID: "ws-1",
		ProjectID:   "project-b",
		Name:        "Back to work",
		Slug:        "project-b",
	}); err != nil {
		t.Fatalf("seed tenant b project: %v", err)
	}

	tenantBUserUUID := "22222222-2222-2222-2222-222222222222"
	tenantBUser, err := store.UpsertUser(context.Background(), User{
		ID:           tenantBUserUUID,
		PrimaryEmail: "tenant-b-owner@example.com",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("seed tenant b owner: %v", err)
	}
	tenantBSessionHash := sha256.Sum256([]byte("tenant-b-workspace-deletion"))
	tenantBSession, err := store.CreateSession(context.Background(), Session{
		ID:                tenantBSessionHash[:],
		UserID:            tenantBUser.ID,
		AuthMethod:        "manual",
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		LastSeenAt:        now,
		CreatedAt:         now,
	})
	if err != nil {
		t.Fatalf("create tenant b session: %v", err)
	}
	if _, err := store.UpdateSessionContext(tenantBCtx, tenantBUser.ID, tenantBSession.ID, "tenant-b", "ws-1", "project-b", now); err != nil {
		t.Fatalf("update tenant b session context: %v", err)
	}
	tenantBOnboardingState, err := store.UpsertOnboardingState(context.Background(), OnboardingState{
		UserID:      tenantBUser.ID,
		CurrentStep: "connect",
		OrgID:       "tenant-b",
		WorkspaceID: "ws-1",
		ProjectID:   "project-b",
		StartedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("upsert tenant b onboarding state: %v", err)
	}

	saved, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
		t.Fatalf("hard delete: %v", err)
	}

	sessions, err := store.ListUserSessions(context.Background(), owner.ID, now, 10)
	if err != nil {
		t.Fatalf("list user sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected one active session, got %d", len(sessions))
	}
	if sessions[0].CurrentWorkspaceID != "" || sessions[0].CurrentProjectID != "" {
		t.Fatalf("expected stale session scope cleared, got workspace=%q project=%q", sessions[0].CurrentWorkspaceID, sessions[0].CurrentProjectID)
	}
	if sessions[0].CurrentOrgID != "" {
		t.Fatalf("expected stale session tenant scope cleared, got org=%q", sessions[0].CurrentOrgID)
	}

	state, err := store.GetOnboardingState(context.Background(), owner.ID)
	if err != nil {
		t.Fatalf("get onboarding state: %v", err)
	}
	if state.OrgID != "" || state.WorkspaceID != "" || state.ProjectID != "" {
		t.Fatalf("expected stale onboarding scope cleared, got org=%q workspace=%q project=%q", state.OrgID, state.WorkspaceID, state.ProjectID)
	}

	tenantBSessions, err := store.ListUserSessions(context.Background(), tenantBUser.ID, now, 10)
	if err != nil {
		t.Fatalf("list tenant b user sessions: %v", err)
	}
	if len(tenantBSessions) != 1 {
		t.Fatalf("expected one active session for tenant b user, got %d", len(tenantBSessions))
	}
	if tenantBSessions[0].CurrentOrgID != "tenant-b" || tenantBSessions[0].CurrentWorkspaceID != "ws-1" || tenantBSessions[0].CurrentProjectID != "project-b" {
		t.Fatalf(
			"expected tenant b session to remain untouched, got org=%q workspace=%q project=%q",
			tenantBSessions[0].CurrentOrgID,
			tenantBSessions[0].CurrentWorkspaceID,
			tenantBSessions[0].CurrentProjectID,
		)
	}

	state, err = store.GetOnboardingState(context.Background(), tenantBUser.ID)
	if err != nil {
		t.Fatalf("get tenant b onboarding state: %v", err)
	}
	if state.OrgID != tenantBOnboardingState.OrgID || state.WorkspaceID != tenantBOnboardingState.WorkspaceID || state.ProjectID != tenantBOnboardingState.ProjectID {
		t.Fatalf(
			"expected tenant b onboarding scope to remain untouched after tenant a purge, got org=%q workspace=%q project=%q",
			state.OrgID,
			state.WorkspaceID,
			state.ProjectID,
		)
	}
}

func TestMemoryStoreHardDeleteWorkspaceRefusesDeletedAtDrift(t *testing.T) {
	// Race protection (#1450 round 2): the worker lists a workspace
	// past grace, then between the list and the purge call an owner
	// cancels deletion and re-deletes the workspace with a fresh
	// deleted_at. Calling HardDeleteWorkspace with the worker's
	// originally-observed deleted_at must refuse, so the new 30-day
	// grace window can run instead of being silently bypassed.
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))
	original, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete (original): %v", err)
	}
	// Cancel and re-soft-delete to simulate the race.
	if _, err := store.CancelWorkspaceDeletion(ctx, "ws-1", now); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-1", now); err != nil {
		t.Fatalf("soft delete (re-delete): %v", err)
	}
	// The worker still thinks the deletedAt is `original.DeletedAt`,
	// but the row now carries `now`. Purge must refuse.
	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *original.DeletedAt, now); err == nil {
		t.Fatal("expected hard delete to refuse stale deletedAt")
	}
	// Workspace must remain — refusal protected it.
	saved, err := store.GetWorkspace(ctx, "ws-1")
	if err != nil {
		t.Fatalf("get workspace: %v", err)
	}
	if saved.Status != WorkspaceStatusDeleted || saved.DeletedAt == nil {
		t.Fatalf("expected workspace to remain in soft-deleted state, got %+v", saved)
	}
}

func TestMemoryStoreHardDeleteWorkspaceMissingReturnsNotFound(t *testing.T) {
	store, _, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-missing", now, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing workspace, got %v", err)
	}
}

func TestMemoryStoreHardDeleteWorkspacePurgesChildRows(t *testing.T) {
	// Past-grace purge removes the workspace row and all child rows:
	// members, projects, connectors, scan policies, secret envelopes,
	// AWS coverage. Scan and repo-scan history (carried on tables
	// without a FK back to tenancy_workspaces) must also be purged so
	// workspace-scoped data does not outlive the 30-day grace window.
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	// Seed a project so cascade behavior is non-trivial.
	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	saved, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if _, err := store.GetWorkspace(ctx, "ws-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ws-1 purged, got %v", err)
	}
	if _, err := store.GetProject(ctx, "ws-1", "project-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected project purged with workspace, got %v", err)
	}
}

func TestMemoryStoreDeleteCascadesPurgeAWSPlatformBaselines(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	t.Run("project", func(t *testing.T) {
		store, ctx := setupMemoryBaselineCascadeStore(t)
		seedMemoryAWSPlatformBaseline(t, store, ctx, now)

		if err := store.DeleteProject(ctx, "ws-1", "project-a"); err != nil {
			t.Fatalf("delete project: %v", err)
		}
		if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
			t.Fatalf("recreate project: %v", err)
		}
		assertMemoryAWSPlatformBaselinePurged(t, store, ctx)
	})

	t.Run("workspace", func(t *testing.T) {
		store, ctx := setupMemoryBaselineCascadeStore(t)
		seedMemoryAWSPlatformBaseline(t, store, ctx, now)

		if err := store.DeleteWorkspace(ctx, "ws-1"); err != nil {
			t.Fatalf("delete workspace: %v", err)
		}
		if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "ws-1", DisplayName: "Workspace 1", Slug: "ws-1"}); err != nil {
			t.Fatalf("recreate workspace: %v", err)
		}
		if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
			t.Fatalf("recreate project: %v", err)
		}
		assertMemoryAWSPlatformBaselinePurged(t, store, ctx)
	})

	t.Run("organization", func(t *testing.T) {
		store, ctx := setupMemoryBaselineCascadeStore(t)
		seedMemoryAWSPlatformBaseline(t, store, ctx, now)

		if err := store.DeleteOrganization(ctx); err != nil {
			t.Fatalf("delete organization: %v", err)
		}
		if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
			t.Fatalf("recreate organization: %v", err)
		}
		if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "ws-1", DisplayName: "Workspace 1", Slug: "ws-1"}); err != nil {
			t.Fatalf("recreate workspace: %v", err)
		}
		if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
			t.Fatalf("recreate project: %v", err)
		}
		assertMemoryAWSPlatformBaselinePurged(t, store, ctx)
	})

	t.Run("hard delete workspace", func(t *testing.T) {
		store, ctx := setupMemoryBaselineCascadeStore(t)
		seedMemoryAWSPlatformBaseline(t, store, ctx, now)
		past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))
		saved, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
		if err != nil {
			t.Fatalf("soft delete workspace: %v", err)
		}
		if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
			t.Fatalf("hard delete workspace: %v", err)
		}
		if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "ws-1", DisplayName: "Workspace 1", Slug: "ws-1"}); err != nil {
			t.Fatalf("recreate workspace: %v", err)
		}
		if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
			t.Fatalf("recreate project: %v", err)
		}
		assertMemoryAWSPlatformBaselinePurged(t, store, ctx)
	})
}

func setupMemoryBaselineCascadeStore(t *testing.T) (*MemoryStore, context.Context) {
	t.Helper()
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-1"})
	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{WorkspaceID: "ws-1", DisplayName: "Workspace 1", Slug: "ws-1"}); err != nil {
		t.Fatalf("upsert workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	return store, ctx
}

func seedMemoryAWSPlatformBaseline(t *testing.T, store *MemoryStore, ctx context.Context, now time.Time) {
	t.Helper()
	if _, err := store.UpsertAWSPlatformBaselineResult(ctx, AWSPlatformBaselineResult{
		WorkspaceID:          "ws-1",
		ProjectID:            "project-a",
		Status:               AWSPlatformBaselineStatusReady,
		Confidence:           0.95,
		RequiredChecksPassed: true,
		Checks: []AWSPlatformBaselineCheck{{
			Name:       "aws_connector_health",
			Required:   true,
			Status:     AWSPlatformBaselineCheckPassed,
			Confidence: 0.96,
			CheckedAt:  now,
		}},
		VerifiedAt: now,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("seed aws baseline: %v", err)
	}
}

func assertMemoryAWSPlatformBaselinePurged(t *testing.T, store *MemoryStore, ctx context.Context) {
	t.Helper()
	_, err := store.GetAWSPlatformBaselineResult(ctx, AWSPlatformBaselineFilter{
		WorkspaceID: "ws-1",
		ProjectID:   "project-a",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected AWS baseline purged, got %v", err)
	}
}

// captureAuditSink records every audit event written through a
// db.WithSink context. Used in tests below to assert the hard-delete
// audit payload carries the anonymized workspace marker.
type captureAuditSink struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (c *captureAuditSink) Write(_ context.Context, event audit.AuditEvent) error {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
	return nil
}
func (c *captureAuditSink) Close() error { return nil }
func (c *captureAuditSink) snapshot() []audit.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.AuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

func TestMemoryStoreHardDeleteWorkspacePurgesEveryChildTable(t *testing.T) {
	// End-to-end purge against every child surface the store knows
	// about. Without this test the cascade branches in HardDeleteWorkspace
	// (connectors, secret envelopes, AWS coverage, scan history) are
	// unreached by the higher-level lifecycle tests, since those only
	// seed the workspace + project + member fixtures.
	store, ctx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	if err := store.UpsertProject(ctx, TenancyProject{WorkspaceID: "ws-1", ProjectID: "project-a", Name: "Project A", Slug: "project-a"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "ws-1", ProjectID: "project-a", ConnectorID: "aws-prod",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Production AWS",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{
		WorkspaceID: "ws-1", ProjectID: "project-a", ConnectorID: "aws-prod",
		HealthStatus: "healthy",
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	if err := store.UpsertTenancyConnectorSecretEnvelope(ctx, TenancyConnectorSecretEnvelope{
		WorkspaceID:     "ws-1",
		ProjectID:       "project-a",
		ConnectorID:     "aws-prod",
		SecretName:      "external-id",
		EnvelopeVersion: 1,
		Envelope: secretstore.Envelope{
			Version:    1,
			Algorithm:  secretstore.AlgorithmAES256GCM,
			KeyVersion: "v1",
			Nonce:      []byte("123456789012"),
			Ciphertext: []byte("ciphertext"),
		},
	}); err != nil {
		t.Fatalf("upsert secret envelope: %v", err)
	}
	if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID: "ws-1", ProjectID: "project-a", PolicyID: "default",
		Name: "Default", Enabled: true, TriggerMode: domain.ScanTriggerModeManual,
	}); err != nil {
		t.Fatalf("upsert scan policy: %v", err)
	}
	if _, err := store.UpsertAWSAccountRegionCoverage(ctx, AWSAccountRegionCoverage{
		WorkspaceID:    "ws-1",
		ProjectID:      "project-a",
		ConnectorID:    "aws-prod",
		AccountID:      "123456789012",
		Partition:      "aws",
		Region:         "us-east-1",
		CoverageStatus: "covered",
	}); err != nil {
		t.Fatalf("upsert AWS coverage: %v", err)
	}
	saved, err := store.SoftDeleteWorkspace(ctx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
		t.Fatalf("hard delete: %v", err)
	}

	// Workspace gone.
	if _, err := store.GetWorkspace(ctx, "ws-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected workspace purged, got %v", err)
	}
	// Connector + state + secret all gone.
	if _, err := store.GetTenancyConnector(ctx, "ws-1", "project-a", "aws-prod"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected connector purged with workspace, got %v", err)
	}
	if _, err := store.GetTenancyConnectorSecretEnvelope(ctx, "ws-1", "project-a", "aws-prod", "external-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected secret envelope purged with workspace, got %v", err)
	}
	// Scan policy gone.
	if _, err := store.GetTenancyScanPolicy(ctx, "ws-1", "project-a", "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scan policy purged with workspace, got %v", err)
	}
	// AWS coverage gone.
	coverages, err := store.ListAWSAccountRegionCoverages(ctx, AWSAccountRegionCoverageFilter{ProjectID: "project-a"})
	if err != nil {
		t.Fatalf("list AWS coverage: %v", err)
	}
	if len(coverages) != 0 {
		t.Fatalf("expected AWS coverage purged with workspace, got %+v", coverages)
	}
}

func TestMemoryStoreHardDeleteWorkspaceEmitsAuditAction(t *testing.T) {
	// The hard-delete code path must emit a `tenancy.workspace.hard_delete`
	// audit event with the right scope context. The downstream audit
	// pipeline fingerprints the resource id (which is why we cannot
	// assert against a raw marker here), but this test pins that the
	// audit call actually fires — a regression that drops it would
	// fail this test rather than silently breaking observability.
	store, scopedCtx, _ := setupWorkspaceLifecycleStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	past := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))
	saved, err := store.SoftDeleteWorkspace(scopedCtx, "ws-1", past)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	sink := &captureAuditSink{}
	purgeCtx := audit.WithSink(scopedCtx, sink)
	if _, err := store.HardDeleteWorkspace(purgeCtx, "tenant-a", "ws-1", *saved.DeletedAt, now); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	found := false
	for _, event := range sink.snapshot() {
		if event.Action == "tenancy.workspace.hard_delete" && event.ResourceType == "tenancy_workspace" && event.Outcome == "success" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected tenancy.workspace.hard_delete audit event, got %+v", sink.snapshot())
	}
}

func TestHardDeletedWorkspaceMarkerShape(t *testing.T) {
	// Direct unit test of the marker helper. The audit pipeline
	// fingerprints resource ids before writing, so the integration test
	// above only asserts the action emission. This test pins the
	// marker format itself — `deleted-workspace:<id>` — so a future
	// change to the prefix surfaces here rather than as a downstream
	// audit-consumer mismatch.
	if got := HardDeletedWorkspaceMarker("ws-1"); got != "deleted-workspace:ws-1" {
		t.Fatalf("unexpected marker: %q", got)
	}
	if got := HardDeletedWorkspaceMarker("  ws-2  "); got != "deleted-workspace:ws-2" {
		t.Fatalf("expected trimmed marker, got %q", got)
	}
	if !IsHardDeletedWorkspaceMarker("deleted-workspace:ws-1") {
		t.Fatal("expected marker to be detected")
	}
	if IsHardDeletedWorkspaceMarker("ws-1") {
		t.Fatal("expected raw id not to be detected as marker")
	}
}

func TestMemoryStoreLifecycleMissingWorkspaceReturnsNotFound(t *testing.T) {
	// All four memory-store lifecycle methods must surface ErrNotFound
	// when the workspace key is absent. Pin the contract so the service
	// layer can rely on the sentinel rather than each method inventing
	// its own shape.
	store := NewMemoryStore()
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "ws-1"})
	if err := store.UpsertOrganization(ctx, TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("upsert org: %v", err)
	}
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	if _, err := store.SuspendWorkspace(ctx, "ws-missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("suspend missing: expected ErrNotFound, got %v", err)
	}
	if _, err := store.ReactivateWorkspace(ctx, "ws-missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reactivate missing: expected ErrNotFound, got %v", err)
	}
	if _, err := store.SoftDeleteWorkspace(ctx, "ws-missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("soft delete missing: expected ErrNotFound, got %v", err)
	}
	if _, err := store.CancelWorkspaceDeletion(ctx, "ws-missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancel missing: expected ErrNotFound, got %v", err)
	}
	if _, err := store.ListWorkspaceStrandedActiveMembers(ctx, "ws-missing", "11111111-1111-1111-1111-111111111111"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("strand missing: expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStoreStrandedMembersIncludesNullUserUUID(t *testing.T) {
	// Legacy invited-only memberships can have an empty user_uuid. The
	// Postgres query uses IS DISTINCT FROM so NULL user_uuid is counted
	// as "not the caller"; this test pins the memory store to the same
	// invariant so a sole owner cannot silently bypass the stranding
	// guard when an unclaimed invitation is the only other member.
	store, ctx, ownerUUID := setupWorkspaceLifecycleStore(t)
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "ws-1", MemberID: "m-invited", UserID: "subj-invited",
		// UserUUID intentionally empty — invited but unclaimed.
		Role: "analyst", Status: "active",
	}); err != nil {
		t.Fatalf("add invited member: %v", err)
	}
	stranded, err := store.ListWorkspaceStrandedActiveMembers(ctx, "ws-1", ownerUUID)
	if err != nil {
		t.Fatalf("strand check: %v", err)
	}
	if len(stranded) != 1 || stranded[0].MemberID != "m-invited" {
		t.Fatalf("expected invited member in stranded list, got %+v", stranded)
	}
}

func TestMemoryStoreStrandedMembersExcludesDeletedCoOwner(t *testing.T) {
	// Codex round-10 cross-store parity pin: a co-owner whose user
	// account is soft-deleted is not a valid ownership-transfer target
	// (their access is gone), so they must not surface in the stranded
	// list. Postgres aligned on this behavior in round-10 of #1445;
	// this test pins the same invariant on the memory store so the two
	// backends keep stepping in lock-step on cross-store parity tests.
	store, ctx, ownerUUID := setupWorkspaceLifecycleStore(t)
	deletedAt := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	deletedUser, err := store.UpsertUser(context.Background(), User{
		PrimaryEmail: "ghost@example.com",
		DisplayName:  "Ghost",
		Status:       "deleted",
		DeletedAt:    &deletedAt,
	})
	if err != nil {
		t.Fatalf("upsert deleted user: %v", err)
	}
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "ws-1", MemberID: "m-ghost-owner", UserID: "subj-ghost",
		UserUUID: deletedUser.ID,
		Role:     "owner", Status: "active",
	}); err != nil {
		t.Fatalf("add deleted-user co-owner: %v", err)
	}
	stranded, err := store.ListWorkspaceStrandedActiveMembers(ctx, "ws-1", ownerUUID)
	if err != nil {
		t.Fatalf("strand check: %v", err)
	}
	if len(stranded) != 0 {
		t.Fatalf("expected deleted-user co-owner not to be stranded, got %+v", stranded)
	}
}

func TestMemoryStoreListWorkspaceStrandedActiveMembers(t *testing.T) {
	store, ctx, ownerUUID := setupWorkspaceLifecycleStore(t)
	// No other members yet — stranding should be empty so suspend/delete can proceed.
	stranded, err := store.ListWorkspaceStrandedActiveMembers(ctx, "ws-1", ownerUUID)
	if err != nil {
		t.Fatalf("strand check: %v", err)
	}
	if len(stranded) != 0 {
		t.Fatalf("expected no stranded members with single owner, got %+v", stranded)
	}

	// Add an active analyst. Sole owner with another active member → guard fires.
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "ws-1", MemberID: "m-analyst", UserID: "subj-analyst",
		UserUUID: "22222222-2222-2222-2222-222222222222",
		Role:     "analyst", Status: "active",
	}); err != nil {
		t.Fatalf("add analyst: %v", err)
	}
	stranded, err = store.ListWorkspaceStrandedActiveMembers(ctx, "ws-1", ownerUUID)
	if err != nil {
		t.Fatalf("strand check after analyst: %v", err)
	}
	if len(stranded) != 1 || stranded[0].MemberID != "m-analyst" {
		t.Fatalf("expected analyst in stranded list, got %+v", stranded)
	}

	// Add a co-owner. Guard no longer fires — ownership can transfer.
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "ws-1", MemberID: "m-coowner", UserID: "subj-coowner",
		UserUUID: "33333333-3333-3333-3333-333333333333",
		Role:     "owner", Status: "active",
	}); err != nil {
		t.Fatalf("add coowner: %v", err)
	}
	stranded, err = store.ListWorkspaceStrandedActiveMembers(ctx, "ws-1", ownerUUID)
	if err != nil {
		t.Fatalf("strand check after coowner: %v", err)
	}
	if len(stranded) != 0 {
		t.Fatalf("expected no stranded members with co-owner present, got %+v", stranded)
	}
}
