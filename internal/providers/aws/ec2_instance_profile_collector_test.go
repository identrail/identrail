package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeEC2InstanceProfileAPI struct {
	pages []EC2InstanceProfilePage
	calls int
}

func (f *fakeEC2InstanceProfileAPI) ListInstanceProfiles(_ context.Context, nextToken string, pageSize int32) (EC2InstanceProfilePage, error) {
	f.calls++
	if pageSize != 2 {
		return EC2InstanceProfilePage{}, fakeRetryableError{message: "unexpected page size"}
	}
	switch f.calls {
	case 1:
		if nextToken != "" {
			return EC2InstanceProfilePage{}, fakeRetryableError{message: "unexpected first token"}
		}
	case 2:
		if nextToken != "page-2" {
			return EC2InstanceProfilePage{}, fakeRetryableError{message: "unexpected second token"}
		}
	}
	if f.calls > len(f.pages) {
		return EC2InstanceProfilePage{}, nil
	}
	return f.pages[f.calls-1], nil
}

func TestEC2InstanceProfileCollectorEmitsContractRecordsAndDiagnostics(t *testing.T) {
	fixedNow := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	api := &fakeEC2InstanceProfileAPI{
		pages: []EC2InstanceProfilePage{
			{
				Records: []EC2InstanceProfile{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "i-0abc",
							WorkloadType: "ec2_instance",
							WorkloadName: "payments-api",
							RoleARN:      "arn:aws:iam::123456789012:role/payments-ec2",
							Source:       "describeinstances",
							EvidenceRef:  "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
						},
						InstanceID:         "i-0abc",
						InstanceARN:        "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
						InstanceName:       "payments-api",
						InstanceProfileARN: "arn:aws:iam::123456789012:instance-profile/payments-profile",
						RoleName:           "payments-ec2",
						IMDSEndpoint:       "enabled",
						IMDSHTTPTokens:     "required",
						Tags:               map[string]string{"owner": "payments"},
					},
				},
				NextToken: "page-2",
			},
			{
				Records: []EC2InstanceProfile{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "i-0def",
							WorkloadType: "ec2_instance",
							WorkloadName: "batch-worker",
							Source:       "describeinstances",
							EvidenceRef:  "arn:aws:ec2:us-east-1:123456789012:instance/i-0def",
						},
						InstanceID:         "i-0def",
						InstanceARN:        "arn:aws:ec2:us-east-1:123456789012:instance/i-0def",
						InstanceName:       "batch-worker",
						InstanceProfileARN: "arn:aws:iam::123456789012:instance-profile/batch-profile",
					},
				},
			},
		},
	}
	collector := NewEC2InstanceProfileCollector(api, WithEC2InstanceProfilePageSize(2), WithEC2InstanceProfileClock(func() time.Time {
		return fixedNow
	}))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-123",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected two raw assets, got %d", len(assets))
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "missing_instance_profile_role" {
		t.Fatalf("expected missing role diagnostic, got %+v", diagnostics)
	}

	var payload EC2InstanceProfile
	if err := json.Unmarshal(assets[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.CollectedAt != fixedNow {
		t.Fatalf("expected collected_at %s, got %s", fixedNow, payload.CollectedAt)
	}
	if _, err := awscontract.NormalizeServiceCollectorRecord(payload.ServiceCollectorRecord); err != nil {
		t.Fatalf("expected payload to satisfy service collector contract: %v", err)
	}
}

func TestRoleNormalizerAddsEC2WorkloadProfileResourcesAndRunsAsEdge(t *testing.T) {
	record := EC2InstanceProfile{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "ec2",
			WorkloadID:    "i-0abc",
			WorkloadType:  "ec2_instance",
			WorkloadName:  "payments-api",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-ec2",
			Source:        "describeinstances",
			EvidenceRef:   "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
			Confidence:    0.98,
			ScanID:        "scan-123",
			CollectorName: ec2InstanceProfileCollectorName,
			CollectedAt:   time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
		},
		InstanceID:          "i-0abc",
		InstanceARN:         "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
		InstanceName:        "payments-api",
		InstanceState:       "running",
		InstanceProfileARN:  "arn:aws:iam::123456789012:instance-profile/payments-profile",
		InstanceProfileName: "payments-profile",
		RoleName:            "payments-ec2",
		Tags:                map[string]string{"owner": "payments"},
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindEC2InstanceProfile,
		SourceID: "ec2-profile",
		Payload:  payload,
	}})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("normalized bundle invalid: %v", err)
	}
	if len(bundle.Identities) != 1 || bundle.Identities[0].ARN != record.RoleARN {
		t.Fatalf("expected role identity from profile record, got %+v", bundle.Identities)
	}
	if len(bundle.Workloads) != 1 || !strings.Contains(bundle.Workloads[0].ID, "instance") {
		t.Fatalf("expected ec2 instance workload, got %+v", bundle.Workloads)
	}
	if len(bundle.Resources) != 2 {
		t.Fatalf("expected instance and profile resources, got %+v", bundle.Resources)
	}

	relationships, err := NewRelationshipBuilder(WithRelationshipClock(func() time.Time {
		return time.Date(2026, 6, 4, 12, 30, 0, 0, time.UTC)
	})).ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("graph contract invalid: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) {
		t.Fatalf("expected runs_as edge, got %+v", relationships)
	}
}

func TestRelationshipBuilderLinksLaunchTemplateRoleReference(t *testing.T) {
	record := EC2InstanceProfile{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "ec2",
			WorkloadID:    "lt-123:7",
			WorkloadType:  "ec2_launch_template",
			WorkloadName:  "prod-template",
			RoleARN:       "arn:aws:iam::123456789012:role/template-role",
			Source:        "describelaunchtemplateversions",
			EvidenceRef:   "lt-123",
			Confidence:    0.9,
			ScanID:        "scan-123",
			CollectorName: ec2InstanceProfileCollectorName,
			CollectedAt:   time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
		},
		LaunchTemplateID:      "lt-123",
		LaunchTemplateName:    "prod-template",
		LaunchTemplateVersion: "7",
		InstanceProfileARN:    "arn:aws:iam::123456789012:instance-profile/template-profile",
		RoleName:              "template-role",
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindEC2InstanceProfile,
		SourceID: "lt-profile",
		Payload:  payload,
	}})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipAttachedTo) {
		t.Fatalf("expected launch template attached_to edge, got %+v", relationships)
	}
}

func hasRelationshipType(relationships []domain.Relationship, relationshipType domain.RelationshipType) bool {
	for _, relationship := range relationships {
		if relationship.Type == relationshipType {
			return true
		}
	}
	return false
}
