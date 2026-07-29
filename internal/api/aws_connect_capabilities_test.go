package api

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	awsconnector "github.com/identrail/identrail/internal/connectors/aws"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
)

func newAWSCapabilityService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{5}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID: "123456789012",
			Region:    "us-west-2",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			},
		},
	}
	svc.ConnectorSecretManager = manager
	return svc, ctx
}

func capabilitySet(capabilities []domain.ConnectorCapability) map[domain.ConnectorCapability]bool {
	set := make(map[domain.ConnectorCapability]bool, len(capabilities))
	for _, capability := range capabilities {
		set[capability] = true
	}
	return set
}

// Default read-only behavior: a connector created without requesting any extra
// tier stays at discovery, healthy, and reports no unavailable capabilities.
func TestUpsertAWSConnectionDefaultsToDiscoveryReadOnly(t *testing.T) {
	svc, ctx := newAWSCapabilityService(t)

	status, err := svc.UpsertAWSConnection(ctx, "workspace-a", "project-1", AWSConnectionUpsertRequest{
		RoleARN: "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		Region:  "us-west-2",
	})
	if err != nil {
		t.Fatalf("upsert aws connection: %v", err)
	}
	if !status.Connected || status.Status != domain.ConnectorStatusActive {
		t.Fatalf("expected active read-only connection, got %+v", status)
	}
	wantEffective := []domain.ConnectorCapability{domain.ConnectorCapabilityDiscovery}
	if got := status.Capabilities.Effective; len(got) != 1 || got[0] != domain.ConnectorCapabilityDiscovery {
		t.Fatalf("effective capabilities = %v, want %v", got, wantEffective)
	}
	if len(status.Capabilities.Unavailable) != 0 {
		t.Fatalf("expected no unavailable capabilities, got %+v", status.Capabilities.Unavailable)
	}
	for _, diagnostic := range status.Diagnostics {
		if strings.HasPrefix(diagnostic.Code, "aws_capability_unavailable_") {
			t.Fatalf("did not expect capability diagnostics for default connector, got %+v", status.Diagnostics)
		}
	}
}

// Requesting a gated write capability surfaces a capability-scoped diagnostic that
// names the tier, but does not degrade the otherwise-healthy read-only connector.
func TestUpsertAWSConnectionReportsUnavailableWriteCapability(t *testing.T) {
	svc, ctx := newAWSCapabilityService(t)

	status, err := svc.UpsertAWSConnection(ctx, "workspace-a", "project-1", AWSConnectionUpsertRequest{
		RoleARN:      "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		Region:       "us-west-2",
		Capabilities: []domain.ConnectorCapability{domain.ConnectorCapabilityApprovedRemediation},
	})
	if err != nil {
		t.Fatalf("upsert aws connection: %v", err)
	}

	// Discovery stays in force and the connector is still healthy.
	if !status.Connected || status.Status != domain.ConnectorStatusActive {
		t.Fatalf("expected healthy connector despite gated capability, got %+v", status)
	}
	effective := capabilitySet(status.Capabilities.Effective)
	if !effective[domain.ConnectorCapabilityDiscovery] || effective[domain.ConnectorCapabilityApprovedRemediation] {
		t.Fatalf("effective capabilities must keep discovery and exclude write tier, got %+v", status.Capabilities.Effective)
	}

	if len(status.Capabilities.Unavailable) != 1 {
		t.Fatalf("expected one unavailable capability, got %+v", status.Capabilities.Unavailable)
	}
	unavailable := status.Capabilities.Unavailable[0]
	if unavailable.Capability != domain.ConnectorCapabilityApprovedRemediation {
		t.Fatalf("unavailable capability = %q, want approved_remediation", unavailable.Capability)
	}
	if unavailable.Tier != domain.ConnectorCapabilityTierWrite {
		t.Fatalf("unavailable tier = %q, want write", unavailable.Tier)
	}

	var capabilityDiagnostic *AWSConnectionDiagnostic
	for i := range status.Diagnostics {
		if status.Diagnostics[i].Code == "capability_unavailable" &&
			status.Diagnostics[i].AffectedScope == string(domain.ConnectorCapabilityApprovedRemediation) {
			capabilityDiagnostic = &status.Diagnostics[i]
			break
		}
	}
	if capabilityDiagnostic == nil {
		t.Fatalf("expected a capability-scoped diagnostic, got %+v", status.Diagnostics)
	}
	if capabilityDiagnostic.Severity != "warning" {
		t.Fatalf("capability diagnostic severity = %q, want warning so it does not block a healthy connector", capabilityDiagnostic.Severity)
	}
	if capabilityDiagnostic.Remediation == "" {
		t.Fatalf("expected remediation guidance on capability diagnostic, got %+v", capabilityDiagnostic)
	}
	for _, diagnostic := range status.Diagnostics {
		if diagnostic.Code == "missing_read_only_permission_tier" {
			t.Fatalf("write-tier capability must not surface as a read-only permission blocker: %+v", diagnostic)
		}
	}
}

// A read-only tier enabled by the deployment gate is validated and becomes
// effective.
func TestUpsertAWSConnectionGrantsGatedReadOnlyCapability(t *testing.T) {
	svc, ctx := newAWSCapabilityService(t)
	svc.AWSConnectorCapabilityPolicy = awsconnector.NewCapabilityPolicy([]domain.ConnectorCapability{
		domain.ConnectorCapabilityRuntimeEvidence,
	})

	status, err := svc.UpsertAWSConnection(ctx, "workspace-a", "project-1", AWSConnectionUpsertRequest{
		RoleARN:      "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		Region:       "us-west-2",
		Capabilities: []domain.ConnectorCapability{domain.ConnectorCapabilityRuntimeEvidence},
	})
	if err != nil {
		t.Fatalf("upsert aws connection: %v", err)
	}
	effective := capabilitySet(status.Capabilities.Effective)
	if !effective[domain.ConnectorCapabilityDiscovery] || !effective[domain.ConnectorCapabilityRuntimeEvidence] {
		t.Fatalf("expected discovery + runtime_evidence effective, got %+v", status.Capabilities.Effective)
	}
	if len(status.Capabilities.Unavailable) != 0 {
		t.Fatalf("expected no unavailable capabilities, got %+v", status.Capabilities.Unavailable)
	}
}

func TestUpsertAWSConnectionRejectsInvalidCapability(t *testing.T) {
	svc, ctx := newAWSCapabilityService(t)

	_, err := svc.UpsertAWSConnection(ctx, "workspace-a", "project-1", AWSConnectionUpsertRequest{
		RoleARN:      "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		Region:       "us-west-2",
		Capabilities: []domain.ConnectorCapability{"bogus"},
	})
	if !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected invalid capability request error, got %v", err)
	}
}

// The one-click CloudFormation start flow only ever provisions the read-only role,
// so its connector always begins at the discovery baseline and advertises the
// gated tiers via the grouped permission preview.
func TestStartAWSConnectorIsDiscoveryOnly(t *testing.T) {
	svc, ctx := newAWSCapabilityService(t)
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly.yaml"
	svc.AWSAccountID = "999999999999"
	configureAWSRegistrationTestProvider(svc)

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	if got := started.Connection.Capabilities.Effective; len(got) != 1 || got[0] != domain.ConnectorCapabilityDiscovery {
		t.Fatalf("start flow must be discovery-only, got %+v", got)
	}
	if len(started.PermissionTiers) != len(domain.ConnectorCapabilityOrder()) {
		t.Fatalf("expected grouped permission tiers, got %d", len(started.PermissionTiers))
	}
	for _, tier := range started.PermissionTiers {
		wantAvailable := tier.Capability == domain.ConnectorCapabilityDiscovery
		if tier.Available != wantAvailable {
			t.Fatalf("tier %q available = %v, want %v", tier.Capability, tier.Available, wantAvailable)
		}
	}
}

// Existing connectors persisted before capability tracking still report the safe
// discovery baseline rather than an empty capability set.
func TestGetAWSConnectionBackfillsDefaultCapabilities(t *testing.T) {
	svc, ctx := newAWSCapabilityService(t)

	status, err := svc.GetAWSConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get aws connection: %v", err)
	}
	if got := status.Capabilities.Effective; len(got) != 1 || got[0] != domain.ConnectorCapabilityDiscovery {
		t.Fatalf("expected discovery baseline for empty connection, got %+v", got)
	}
	if status.Capabilities.Unavailable == nil {
		t.Fatalf("expected non-nil unavailable slice for stable JSON output")
	}
}
