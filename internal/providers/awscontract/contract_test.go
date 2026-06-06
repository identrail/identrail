package awscontract

import (
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestAWSServiceCollectorContractIsComplete(t *testing.T) {
	contract := AWSServiceCollectorContract()
	if err := ValidateAWSServiceCollectorContract(contract); err != nil {
		t.Fatalf("expected valid service collector contract: %v", err)
	}
	if contract.Version != AWSServiceCollectorContractVersion {
		t.Fatalf("unexpected contract version %q", contract.Version)
	}
	for _, field := range []string{"connector_id", "account_id", "region", "service", "workload_id", "role_arn", "evidence_ref", "confidence", "scan_id"} {
		if !containsString(contract.NormalizedRecordFields, field) {
			t.Fatalf("missing normalized field %q in %+v", field, contract.NormalizedRecordFields)
		}
	}
	for _, state := range []ServiceCollectorFixtureState{
		ServiceCollectorFixturePagination,
		ServiceCollectorFixtureThrottling,
		ServiceCollectorFixturePartialFailure,
		ServiceCollectorFixtureUnsupportedRegion,
		ServiceCollectorFixturePermissionDenied,
	} {
		if !containsFixtureState(contract.FixtureCases, state) {
			t.Fatalf("missing fixture state %q in %+v", state, contract.FixtureCases)
		}
	}
	for _, edge := range []struct {
		name string
		rel  domain.RelationshipType
	}{
		{"runs-on", domain.RelationshipRunsAs},
		{"assumes", domain.RelationshipCanAssume},
		{"passes-role", domain.RelationshipCanPassRole},
		{"can-access", domain.RelationshipCanAccess},
		{"references-secret", domain.RelationshipUsesSecret},
		{"invokes", domain.RelationshipInvokes},
		{"observed-runtime-action", domain.RelationshipObservedAction},
	} {
		if !containsGraphEdge(contract.GraphEdges, edge.name, edge.rel) {
			t.Fatalf("missing graph edge %s/%s in %+v", edge.name, edge.rel, contract.GraphEdges)
		}
	}
}

func TestNormalizeServiceCollectorRecord(t *testing.T) {
	now := time.Date(2026, 6, 4, 16, 30, 0, 0, time.UTC)
	normalized, err := NormalizeServiceCollectorRecord(ServiceCollectorRecord{
		TenantID:      " tenant-a ",
		WorkspaceID:   " workspace-a ",
		ProjectID:     " project-a ",
		ConnectorID:   " aws-prod ",
		AccountID:     "123456789012",
		Region:        " us-east-1 ",
		Service:       " EC2 ",
		WorkloadID:    " i-123 ",
		WorkloadType:  " Instance ",
		WorkloadName:  " web-1 ",
		RoleARN:       " arn:aws:iam::123456789012:role/AppServer ",
		Source:        " DescribeInstances ",
		EvidenceRef:   " aws://ec2/us-east-1/i-123 ",
		Confidence:    0.96,
		ScanID:        " scan-a ",
		CollectorName: " aws_ec2 ",
		CollectedAt:   now,
		Metadata: map[string]string{
			" page ": " 1 ",
			"empty":  "",
		},
	})
	if err != nil {
		t.Fatalf("normalize record: %v", err)
	}
	if normalized.Service != "ec2" || normalized.Source != "describeinstances" || normalized.WorkloadType != "instance" {
		t.Fatalf("expected normalized service/source/workload type, got %+v", normalized)
	}
	if normalized.Metadata["page"] != "1" || normalized.Metadata["empty"] != "" {
		t.Fatalf("expected trimmed metadata without empty value, got %+v", normalized.Metadata)
	}
}

func TestNormalizeServiceCollectorRecordRejectsUnsafeShape(t *testing.T) {
	_, err := NormalizeServiceCollectorRecord(ServiceCollectorRecord{
		TenantID:      "tenant-a",
		WorkspaceID:   "workspace-a",
		ProjectID:     "project-a",
		ConnectorID:   "aws-prod",
		AccountID:     "123",
		Region:        "us-east-1",
		Service:       "lambda",
		WorkloadID:    "function-a",
		WorkloadType:  "lambda_function",
		WorkloadName:  "function-a",
		RoleARN:       "not-an-arn",
		Source:        "ListFunctions",
		EvidenceRef:   "aws://lambda/us-east-1/function-a",
		Confidence:    1.2,
		ScanID:        "scan-a",
		CollectorName: "aws_lambda",
		CollectedAt:   time.Now(),
	})
	if err == nil {
		t.Fatal("expected invalid account, ARN, or confidence error")
	}
	if !strings.Contains(err.Error(), "account_id") {
		t.Fatalf("expected account id validation to fail first, got %v", err)
	}
}

func TestValidateServiceCollectorRecordRejectsInvalidFields(t *testing.T) {
	valid := validServiceCollectorRecord()
	tests := []struct {
		name    string
		mutate  func(*ServiceCollectorRecord)
		wantErr string
	}{
		{
			name:    "missing required string field",
			mutate:  func(record *ServiceCollectorRecord) { record.WorkloadName = "" },
			wantErr: "workload_name is required",
		},
		{
			name:    "invalid role arn",
			mutate:  func(record *ServiceCollectorRecord) { record.RoleARN = "arn:aws:iam::123456789012:user/AppServer" },
			wantErr: "role_arn must be an AWS IAM role ARN",
		},
		{
			name:    "role arn account mismatch",
			mutate:  func(record *ServiceCollectorRecord) { record.RoleARN = "arn:aws:iam::210987654321:role/AppServer" },
			wantErr: "role_arn account id must match account_id",
		},
		{
			name:    "zero confidence",
			mutate:  func(record *ServiceCollectorRecord) { record.Confidence = 0 },
			wantErr: "confidence must be greater than 0 and at most 1",
		},
		{
			name:    "missing collected timestamp",
			mutate:  func(record *ServiceCollectorRecord) { record.CollectedAt = time.Time{} },
			wantErr: "collected_at is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := valid
			tt.mutate(&record)
			err := ValidateServiceCollectorRecord(record)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateServiceCollectorRecordAcceptsSupportedAWSPartitions(t *testing.T) {
	for _, roleARN := range []string{
		"arn:aws:iam::123456789012:role/IdentrailReadOnly",
		"arn:aws-us-gov:iam::123456789012:role/IdentrailReadOnly",
		"arn:aws-cn:iam::123456789012:role/path/IdentrailReadOnly",
	} {
		record := validServiceCollectorRecord()
		record.RoleARN = roleARN
		if err := ValidateServiceCollectorRecord(record); err != nil {
			t.Fatalf("expected supported role ARN partition %q to validate: %v", roleARN, err)
		}
	}
}

func TestValidateServiceCollectorRecordAllowsCodePipelineCrossAccountActionRoles(t *testing.T) {
	record := validServiceCollectorRecord()
	record.Service = "codepipeline"
	record.WorkloadType = "codepipeline_action"
	record.RoleARN = "arn:aws:iam::210987654321:role/CrossAccountDeploy"
	if err := ValidateServiceCollectorRecord(record); err != nil {
		t.Fatalf("expected CodePipeline action roles to allow cross-account role ARNs: %v", err)
	}
}

func TestValidateAWSServiceCollectorContractRejectsMalformedContract(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ServiceCollectorContract)
		wantErr string
	}{
		{
			name:    "version mismatch",
			mutate:  func(contract *ServiceCollectorContract) { contract.Version = "aws-service-collector-contract-v0" },
			wantErr: "unexpected aws service collector contract version",
		},
		{
			name: "missing record field",
			mutate: func(contract *ServiceCollectorContract) {
				contract.NormalizedRecordFields = contract.NormalizedRecordFields[:len(contract.NormalizedRecordFields)-1]
			},
			wantErr: "normalized record fields do not match required contract",
		},
		{
			name: "bad graph mapping",
			mutate: func(contract *ServiceCollectorContract) {
				contract.GraphEdges[0].RelationshipType = domain.RelationshipCanAccess
			},
			wantErr: "graph edge runs-on uses can_access",
		},
		{
			name:    "missing permissions",
			mutate:  func(contract *ServiceCollectorContract) { contract.RequiredPermissions = nil },
			wantErr: "required permissions are missing",
		},
		{
			name: "payload-reading permission",
			mutate: func(contract *ServiceCollectorContract) {
				contract.RequiredPermissions = append(contract.RequiredPermissions, "secretsmanager:GetSecretValue")
			},
			wantErr: "secretsmanager:GetSecretValue is outside the read-only metadata boundary",
		},
		{
			name: "batch payload-reading permission",
			mutate: func(contract *ServiceCollectorContract) {
				contract.RequiredPermissions = append(contract.RequiredPermissions, "secretsmanager:BatchGetSecretValue")
			},
			wantErr: "secretsmanager:BatchGetSecretValue is outside the read-only metadata boundary",
		},
		{
			name: "bedrock converse payload-reading permission",
			mutate: func(contract *ServiceCollectorContract) {
				contract.RequiredPermissions = append(contract.RequiredPermissions, "bedrock:ConverseStream")
			},
			wantErr: "bedrock:ConverseStream is outside the read-only metadata boundary",
		},
		{
			name:    "missing read only boundaries",
			mutate:  func(contract *ServiceCollectorContract) { contract.ReadOnlyBoundaries = nil },
			wantErr: "read-only boundaries are missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := AWSServiceCollectorContract()
			tt.mutate(&contract)
			err := ValidateAWSServiceCollectorContract(contract)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestAccountIDFromIAMRoleARN(t *testing.T) {
	accountID, ok := accountIDFromIAMRoleARN("arn:aws-us-gov:iam::123456789012:role/path/IdentrailReadOnly")
	if !ok || accountID != "123456789012" {
		t.Fatalf("expected gov partition role ARN account, got accountID=%q ok=%v", accountID, ok)
	}
	for _, roleARN := range []string{
		"arn:aws-iso:iam::123456789012:role/IdentrailReadOnly",
		"arn:aws:iam::123456789012:user/IdentrailReadOnly",
		"arn:aws:iam::123456789012:role/",
		"arn:aws:iam::123456789012:role/Bad Space",
		"arn:aws:ec2::123456789012:role/IdentrailReadOnly",
	} {
		if accountID, ok := accountIDFromIAMRoleARN(roleARN); ok {
			t.Fatalf("expected invalid role ARN %q to fail, got account id %q", roleARN, accountID)
		}
	}
}

func TestValidateServiceCollectorFixturesRequiresNegativeStates(t *testing.T) {
	fixtures := []ServiceCollectorFixtureCase{}
	for _, fixture := range RequiredServiceCollectorFixtureCases() {
		if fixture.State == ServiceCollectorFixturePermissionDenied {
			continue
		}
		fixtures = append(fixtures, fixture)
	}
	err := ValidateServiceCollectorFixtures(fixtures)
	if err == nil {
		t.Fatal("expected missing fixture validation error")
	}
	if !strings.Contains(err.Error(), "permission_denied") {
		t.Fatalf("expected missing permission_denied fixture, got %v", err)
	}
}

func TestValidateServiceCollectorFixturesRejectsMalformedFixtures(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ServiceCollectorFixtureCase)
		wantErr string
	}{
		{
			name:    "missing id",
			mutate:  func(fixture *ServiceCollectorFixtureCase) { fixture.ID = "" },
			wantErr: "fixture id is required",
		},
		{
			name:    "missing state",
			mutate:  func(fixture *ServiceCollectorFixtureCase) { fixture.State = "" },
			wantErr: "state is required",
		},
		{
			name:    "missing label",
			mutate:  func(fixture *ServiceCollectorFixtureCase) { fixture.Label = "" },
			wantErr: "label is required",
		},
		{
			name:    "invalid status",
			mutate:  func(fixture *ServiceCollectorFixtureCase) { fixture.ExpectedStatus = "unknown" },
			wantErr: "invalid expected status",
		},
		{
			name: "required failure fixture marked ready",
			mutate: func(fixture *ServiceCollectorFixtureCase) {
				*fixture = fixtureCaseByState(t, RequiredServiceCollectorFixtureCases(), ServiceCollectorFixturePermissionDenied)
				fixture.ExpectedStatus = ServiceCollectorStatusReady
			},
			wantErr: "fixture permission_denied expected status must remain blocked",
		},
		{
			name: "required retryable fixture marked nonretryable",
			mutate: func(fixture *ServiceCollectorFixtureCase) {
				*fixture = fixtureCaseByState(t, RequiredServiceCollectorFixtureCases(), ServiceCollectorFixtureThrottling)
				fixture.Retryable = false
			},
			wantErr: "fixture throttling retryable must remain true",
		},
		{
			name: "required failure fixture missing source error code",
			mutate: func(fixture *ServiceCollectorFixtureCase) {
				*fixture = fixtureCaseByState(t, RequiredServiceCollectorFixtureCases(), ServiceCollectorFixtureUnsupportedRegion)
				fixture.SourceErrorCode = ""
			},
			wantErr: `fixture unsupported_region source error code must remain "unsupported_region"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtures := RequiredServiceCollectorFixtureCases()
			tt.mutate(&fixtures[0])
			err := ValidateServiceCollectorFixtures(fixtures)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateServiceCollectorGraphEdgesRejectsMalformedEdges(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func([]ServiceCollectorGraphEdgeContract) []ServiceCollectorGraphEdgeContract
		wantErr string
	}{
		{
			name: "missing required edge",
			mutate: func(edges []ServiceCollectorGraphEdgeContract) []ServiceCollectorGraphEdgeContract {
				return edges[:len(edges)-1]
			},
			wantErr: "missing required observed-runtime-action graph edge",
		},
		{
			name: "wrong endpoint contract",
			mutate: func(edges []ServiceCollectorGraphEdgeContract) []ServiceCollectorGraphEdgeContract {
				edges[0].FromEndpoint = domain.RelationshipEndpointPolicy
				return edges
			},
			wantErr: "endpoint contract does not match canonical relationship contract",
		},
		{
			name: "missing evidence",
			mutate: func(edges []ServiceCollectorGraphEdgeContract) []ServiceCollectorGraphEdgeContract {
				edges[0].Evidence = ""
				return edges
			},
			wantErr: "graph edge runs-on evidence is required",
		},
		{
			name: "required edge marked optional",
			mutate: func(edges []ServiceCollectorGraphEdgeContract) []ServiceCollectorGraphEdgeContract {
				edges[0].Required = false
				return edges
			},
			wantErr: "graph edge runs-on must remain required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edges := RequiredServiceCollectorGraphEdges()
			err := ValidateServiceCollectorGraphEdges(tt.mutate(edges))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestServiceCollectorPermissionReadsPayload(t *testing.T) {
	for _, permission := range []string{
		" secretsmanager:GetSecretValue ",
		"secretsmanager:BatchGetSecretValue",
		"secretsmanager:*",
		"secretsmanager:Get*",
		"ssm:GetParameter",
		"ssm:GetParametersByPath",
		"ssm:Get*",
		"s3:GetObject*",
		"s3:Get*",
		"s3:*",
		"bedrock:GetPrompt",
		"bedrock:Converse",
		"bedrock:ConverseStream",
		"bedrock:Converse*",
		"bedrock:Invoke",
		"bedrock:InvokeModel",
		"bedrock:Inv*",
		"bedrock:*",
		"rds-data:Execute",
		"rds-data:*",
		"*:*",
		"*:Get*",
	} {
		if !ServiceCollectorPermissionReadsPayload(permission) {
			t.Fatalf("expected %q to be treated as a payload-reading permission", permission)
		}
	}
	if ServiceCollectorPermissionReadsPayload("iam:GetRolePolicy") {
		t.Fatal("expected IAM policy metadata read to stay inside collector boundary")
	}
	if ServiceCollectorPermissionReadsPayload("iam:Get*") {
		t.Fatal("expected IAM wildcard metadata reads to stay inside collector boundary")
	}
	if ServiceCollectorPermissionReadsPayload("s3-control:GetAccessPoint") {
		t.Fatal("expected adjacent service metadata reads to stay inside collector boundary")
	}
}

func validServiceCollectorRecord() ServiceCollectorRecord {
	return ServiceCollectorRecord{
		TenantID:      "tenant-a",
		WorkspaceID:   "workspace-a",
		ProjectID:     "project-a",
		ConnectorID:   "aws-prod",
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Service:       "ec2",
		WorkloadID:    "i-123",
		WorkloadType:  "instance",
		WorkloadName:  "web-1",
		RoleARN:       "arn:aws:iam::123456789012:role/AppServer",
		Source:        "describeinstances",
		EvidenceRef:   "aws://ec2/us-east-1/i-123",
		Confidence:    0.96,
		ScanID:        "scan-a",
		CollectorName: "aws_ec2",
		CollectedAt:   time.Date(2026, 6, 4, 17, 30, 0, 0, time.UTC),
	}
}

func fixtureCaseByState(t *testing.T, fixtures []ServiceCollectorFixtureCase, state ServiceCollectorFixtureState) ServiceCollectorFixtureCase {
	t.Helper()
	for _, fixture := range fixtures {
		if fixture.State == state {
			return fixture
		}
	}
	t.Fatalf("missing fixture state %s", state)
	return ServiceCollectorFixtureCase{}
}

func containsFixtureState(fixtures []ServiceCollectorFixtureCase, state ServiceCollectorFixtureState) bool {
	for _, fixture := range fixtures {
		if fixture.State == state {
			return true
		}
	}
	return false
}

func containsGraphEdge(edges []ServiceCollectorGraphEdgeContract, name string, rel domain.RelationshipType) bool {
	for _, edge := range edges {
		if edge.Name == name && edge.RelationshipType == rel {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
