package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeECRRepositoryMetadataAPI struct {
	pages     []ECRRepositoryMetadataPage
	calls     int
	err       error
	errOnCall int
}

func (f *fakeECRRepositoryMetadataAPI) ListRepositoryMetadata(ctx context.Context, nextToken string, pageSize int32) (ECRRepositoryMetadataPage, error) {
	f.calls++
	if f.err != nil && (f.errOnCall == 0 || f.calls >= f.errOnCall) {
		return ECRRepositoryMetadataPage{}, f.err
	}
	if len(f.pages) == 0 {
		return ECRRepositoryMetadataPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestECRRepositoryMetadataCollectorCollectsMetadataOnly(t *testing.T) {
	now := time.Date(2026, 6, 11, 18, 0, 0, 0, time.UTC)
	api := &fakeECRRepositoryMetadataAPI{pages: []ECRRepositoryMetadataPage{{
		Records: []ECRRepositoryMetadata{{
			RepositoryName:     "payments/api",
			RepositoryURI:      "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api",
			ImageTagMutability: "MUTABLE",
			EncryptionType:     "KMS",
			KMSKeyID:           "alias/payments-images",
			ScanOnPush:         false,
			ReferencedBy: []ImageWorkloadReference{{
				SourceService: "ecs",
				WorkloadID:    "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
				WorkloadType:  "ecs_service",
				WorkloadName:  "payments",
				ImageURI:      "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api:prod",
				ReferenceKind: "container_image",
			}},
		}},
	}}}
	collector := NewECRRepositoryMetadataCollector(api, WithECRRepositoryMetadataClock(func() time.Time { return now }))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		ConnectorID: "aws-prod",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diagnostics) != 0 || len(assets) != 1 {
		t.Fatalf("expected one clean asset, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	var record ECRRepositoryMetadata
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if record.RepositoryARN != "arn:aws:ecr:us-east-1:123456789012:repository/payments/api" {
		t.Fatalf("unexpected repository ARN: %s", record.RepositoryARN)
	}
	if record.ImageTagMutability != "mutable" || record.SensitivityClassification != "runtime_image_repository" {
		t.Fatalf("expected canonical mutable runtime repository, got %+v", record)
	}
	if record.ExposureClassification != "mutable_unscanned" || !containsString(record.ExposureReasons, "referenced_by_workloads") {
		t.Fatalf("expected mutable unscanned exposure with workload reference, got %+v", record)
	}
	payload := strings.ToLower(string(assets[0].Payload))
	for _, forbidden := range []string{"image_manifest", "manifestmedia", "layer", "authorizationtoken", "scan_findings"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("image payload or scan finding detail leaked into collector payload: %s", payload)
		}
	}
}

func TestECRRepositoryMetadataCollectorClassifiesMutableReferencedRepoWithEnhancedScanning(t *testing.T) {
	now := time.Date(2026, 6, 11, 18, 0, 0, 0, time.UTC)
	api := &fakeECRRepositoryMetadataAPI{pages: []ECRRepositoryMetadataPage{{
		Records: []ECRRepositoryMetadata{{
			RepositoryName:          "payments/api",
			RepositoryURI:           "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api",
			ImageTagMutability:      "MUTABLE",
			EncryptionType:          "KMS",
			KMSKeyID:                "alias/payments-images",
			ScanOnPush:              false,
			EnhancedScanningEnabled: true,
			ReferencedBy: []ImageWorkloadReference{{
				SourceService: "ecs",
				WorkloadID:    "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
				WorkloadType:  "ecs_service",
				WorkloadName:  "payments",
				ImageURI:      "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api:prod",
				ReferenceKind: "container_image",
			}},
		}},
	}}}
	collector := NewECRRepositoryMetadataCollector(api, WithECRRepositoryMetadataClock(func() time.Time { return now }))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		ConnectorID: "aws-prod",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diagnostics) != 0 || len(assets) != 1 {
		t.Fatalf("expected one clean asset, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	var record ECRRepositoryMetadata
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if record.EnhancedScanningEnabled != true {
		t.Fatalf("expected enhanced scanning enabled, got %+v", record)
	}
	if record.ExposureClassification != "referenced" {
		t.Fatalf("expected referenced exposure when enhanced scanning is enabled, got %+v", record)
	}
}

func TestECRRepositoryMetadataCollectorPartialFailureReturnsDiagnostics(t *testing.T) {
	api := &fakeECRRepositoryMetadataAPI{
		pages: []ECRRepositoryMetadataPage{{
			Records: []ECRRepositoryMetadata{{
				RepositoryARN: "arn:aws:ecr:us-east-1:123456789012:repository/payments/api",
			}},
			NextToken: "next",
		}},
		err:       errors.New("throttled"),
		errOnCall: 2,
	}
	collector := NewECRRepositoryMetadataCollector(api)

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err == nil {
		t.Fatalf("expected second-page error")
	}
	if len(assets) != 1 || len(diagnostics) == 0 {
		t.Fatalf("expected partial asset plus diagnostics, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	if diagnostics[0].Code != "ecr_repository_metadata_page_failed" {
		t.Fatalf("unexpected diagnostic: %+v", diagnostics)
	}
}

func TestECRRepositoryMetadataCollectorSkipsMalformedRecords(t *testing.T) {
	api := &fakeECRRepositoryMetadataAPI{pages: []ECRRepositoryMetadataPage{{
		Records: []ECRRepositoryMetadata{{ImageTagMutability: "MUTABLE"}},
	}}}
	collector := NewECRRepositoryMetadataCollector(api)

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 0 || len(diagnostics) != 1 || diagnostics[0].Code != "malformed_ecr_repository_record" {
		t.Fatalf("expected one malformed-record diagnostic, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
}

func TestECRRepositoryReferenceKeysFromRefStripsTagsAndDigests(t *testing.T) {
	tests := []struct {
		ref  string
		want []string
	}{
		{
			ref:  "IMAGE=123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api:prod",
			want: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api"},
		},
		{
			ref:  "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api@sha256:abcdef",
			want: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api"},
		},
	}
	for _, tc := range tests {
		keys := ecrRepositoryReferenceKeysFromRef(tc.ref)
		for _, want := range tc.want {
			if !containsString(keys, want) {
				t.Fatalf("expected key %q in %+v", want, keys)
			}
		}
		if containsString(keys, "payments/api") {
			t.Fatalf("unexpected cross-registry fallback key %q in %+v", "payments/api", keys)
		}
	}
}

func TestECRRepositoryMetadataNormalizeAndGraphUsesImage(t *testing.T) {
	repository := ECRRepositoryMetadata{
		RepositoryARN:  "arn:aws:ecr:us-east-1:123456789012:repository/payments/api",
		RepositoryName: "payments/api",
		RepositoryURI:  "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api",
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: "123456789012",
			Region:    "us-east-1",
			Service:   ecrServiceName,
		},
	}
	payload, err := json.Marshal(repository)
	if err != nil {
		t.Fatalf("marshal repository: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindECRRepositoryMetadata,
		SourceID: ecrRepositoryMetadataSourceID(repository),
		Payload:  payload,
	}, {
		Kind:     rawKindECSTaskRole,
		SourceID: "ecs-service",
		Payload: []byte(`{
			"account_id":"123456789012",
			"region":"us-east-1",
			"service":"ecs",
			"cluster_arn":"arn:aws:ecs:us-east-1:123456789012:cluster/prod",
			"service_arn":"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			"workload_id":"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			"workload_type":"ecs_service",
			"workload_name":"payments",
			"task_definition_arn":"arn:aws:ecs:us-east-1:123456789012:task-definition/payments:4",
			"role_arn":"arn:aws:iam::123456789012:role/payments-task",
			"container_images":["123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api:prod"]
		}`),
	}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	foundResource := false
	for _, resource := range bundle.Resources {
		if resource.Type == domain.ResourceTypeECRRepository {
			foundResource = true
			if resource.ID != ecrRepositoryResourceID(repository.RepositoryARN) {
				t.Fatalf("unexpected resource id: %+v", resource)
			}
		}
	}
	if !foundResource {
		t.Fatalf("expected normalized ecr repository resource, got %+v", bundle.Resources)
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("relationships: %v", err)
	}
	for _, relationship := range relationships {
		if relationship.Type == domain.RelationshipUsesImage {
			if relationship.ToNodeID != ecrRepositoryResourceID(repository.RepositoryARN) {
				t.Fatalf("unexpected target: %+v", relationship)
			}
			return
		}
	}
	t.Fatalf("expected uses_image relationship to ecr repository, got %+v", relationships)
}
