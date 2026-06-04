package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

func TestGetAWSServiceCollectorContractBuildsCanonicalContract(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 16, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSServiceCollectorContract(ctx, "default", "project-a", AWSServiceCollectorContractRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get service collector contract: %v", err)
	}
	if result.Status != awsServiceCollectorContractStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready contract, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1476" || result.Version != awsServiceCollectorContractVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.ConnectorID != "aws-prod" || result.Region != "us-east-1" {
		t.Fatalf("expected connector context, got %+v", result)
	}
	if result.RequiredFieldCount != 17 || result.GraphEdgeCount != 7 || result.FixtureCaseCount != 8 || result.RequiredFixtureCaseCount != 8 {
		t.Fatalf("unexpected contract counts: %+v", result)
	}
	for _, field := range []string{"connector_id", "account_id", "region", "service", "workload_id", "role_arn", "evidence_ref", "confidence", "scan_id"} {
		if !containsString(result.NormalizedRecordFields, field) {
			t.Fatalf("missing normalized field %q in %+v", field, result.NormalizedRecordFields)
		}
	}
	for _, state := range []string{"pagination", "throttling", "partial_failure", "unsupported_region", "permission_denied", "degraded"} {
		if !containsAWSServiceCollectorFixtureState(result.FixtureCases, state) {
			t.Fatalf("missing fixture state %q in %+v", state, result.FixtureCases)
		}
	}
	for _, edge := range []string{"runs-on", "assumes", "passes-role", "can-access", "references-secret", "invokes", "observed-runtime-action"} {
		if !containsAWSServiceCollectorGraphEdge(result.GraphEdges, edge) {
			t.Fatalf("missing graph edge %q in %+v", edge, result.GraphEdges)
		}
	}
	for _, check := range result.Checks {
		if check.Status != awsServiceCollectorContractStatusReady {
			t.Fatalf("expected contract check %s ready, got %+v", check.Name, check)
		}
	}
	for _, permission := range []string{"iam:GetRole", "iam:GetInstanceProfile", "ec2:DescribeInstances", "ec2:DescribeLaunchTemplates", "ec2:DescribeLaunchTemplateVersions"} {
		if !containsString(result.RequiredPermissions, permission) {
			t.Fatalf("missing required permission %q in %+v", permission, result.RequiredPermissions)
		}
	}
	if len(result.ReadOnlyBoundaries) == 0 {
		t.Fatalf("expected read-only boundaries, got permissions=%+v boundaries=%+v", result.RequiredPermissions, result.ReadOnlyBoundaries)
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestSummarizeAWSServiceCollectorContractBlocksMissingFixtures(t *testing.T) {
	now := time.Date(2026, 6, 4, 17, 0, 0, 0, time.UTC)
	checks := []AWSServiceCollectorContractCheck{
		{
			Name:          "fixture_conventions",
			Category:      "fixtures",
			Required:      true,
			Status:        awsServiceCollectorContractStatusBlocked,
			Message:       "missing fixtures",
			FailureReason: "missing required permission_denied fixture",
			Remediation:   "Restore deterministic fixture states.",
			Confidence:    0.3,
			CheckedAt:     now,
		},
	}
	status, confidence, failures, remediations := summarizeAWSServiceCollectorContractChecks(checks)
	if status != awsServiceCollectorContractStatusBlocked || confidence >= 0.5 {
		t.Fatalf("expected blocked contract summary, got status=%s confidence=%f", status, confidence)
	}
	if !containsString(failures, "missing required permission_denied fixture") || len(remediations) == 0 {
		t.Fatalf("expected fixture failure and remediation, got failures=%+v remediations=%+v", failures, remediations)
	}
}

func TestAWSServiceCollectorContractChecksBlockInvalidInputs(t *testing.T) {
	now := time.Date(2026, 6, 4, 17, 15, 0, 0, time.UTC)
	canonical := awscontract.AWSServiceCollectorContract()
	tests := []struct {
		name        string
		check       AWSServiceCollectorContractCheck
		wantFailure string
	}{
		{
			name: "version mismatch",
			check: func() AWSServiceCollectorContractCheck {
				contract := canonical
				contract.Version = "aws-service-collector-contract-v0"
				return awsServiceCollectorContractRecordSchemaCheck(contract, now)
			}(),
			wantFailure: "version mismatch",
		},
		{
			name: "missing record field",
			check: func() AWSServiceCollectorContractCheck {
				contract := canonical
				contract.NormalizedRecordFields = contract.NormalizedRecordFields[:len(contract.NormalizedRecordFields)-1]
				return awsServiceCollectorContractRecordSchemaCheck(contract, now)
			}(),
			wantFailure: "normalized record fields are incomplete",
		},
		{
			name: "missing graph edge",
			check: func() AWSServiceCollectorContractCheck {
				contract := canonical
				contract.GraphEdges = contract.GraphEdges[:len(contract.GraphEdges)-1]
				return awsServiceCollectorContractGraphCheck(contract, now)
			}(),
			wantFailure: "observed-runtime-action",
		},
		{
			name: "missing fixture state",
			check: func() AWSServiceCollectorContractCheck {
				contract := canonical
				contract.FixtureCases = contract.FixtureCases[:len(contract.FixtureCases)-1]
				return awsServiceCollectorContractFixtureCheck(contract, now)
			}(),
			wantFailure: "degraded",
		},
		{
			name: "payload-reading permission",
			check: func() AWSServiceCollectorContractCheck {
				contract := canonical
				contract.RequiredPermissions = append(contract.RequiredPermissions, "secretsmanager:GetSecretValue")
				return awsServiceCollectorContractReadOnlyCheck(contract, now)
			}(),
			wantFailure: "secretsmanager:GetSecretValue is outside the read-only metadata boundary",
		},
		{
			name: "missing read-only evidence",
			check: func() AWSServiceCollectorContractCheck {
				contract := canonical
				contract.RequiredPermissions = nil
				return awsServiceCollectorContractReadOnlyCheck(contract, now)
			}(),
			wantFailure: "read-only boundary is incomplete",
		},
		{
			name: "missing scope",
			check: awsServiceCollectorContractScopeCheck(db.Scope{}, db.TenancyProject{
				ProjectID: "project-a",
			}, now),
			wantFailure: "tenant, workspace, or project scope is missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.check.Status != awsServiceCollectorContractStatusBlocked {
				t.Fatalf("expected blocked check, got %+v", tt.check)
			}
			if !strings.Contains(tt.check.FailureReason, tt.wantFailure) {
				t.Fatalf("expected failure to contain %q, got %q", tt.wantFailure, tt.check.FailureReason)
			}
			if tt.check.Remediation == "" || tt.check.Confidence <= 0 || tt.check.Confidence >= 0.5 {
				t.Fatalf("expected actionable low-confidence blocked check, got %+v", tt.check)
			}
		})
	}
}

func TestSummarizeAWSServiceCollectorContractHandlesEmptyAndDegraded(t *testing.T) {
	status, confidence, failures, remediations := summarizeAWSServiceCollectorContractChecks(nil)
	if status != awsServiceCollectorContractStatusBlocked || confidence != 0.25 {
		t.Fatalf("expected empty checks to block at default confidence, got status=%s confidence=%f", status, confidence)
	}
	if !containsString(failures, "service collector contract checks are missing") || len(remediations) == 0 {
		t.Fatalf("expected empty check failure/remediation, got failures=%+v remediations=%+v", failures, remediations)
	}

	now := time.Date(2026, 6, 4, 17, 20, 0, 0, time.UTC)
	checks := []AWSServiceCollectorContractCheck{
		{
			Name:       "normalized_record_schema",
			Required:   true,
			Status:     awsServiceCollectorContractStatusReady,
			Confidence: 0.98,
			CheckedAt:  now,
		},
		{
			Name:          "fixture_conventions",
			Required:      true,
			Status:        awsServiceCollectorContractStatusDegraded,
			FailureReason: "throttling fixture is retrying",
			Remediation:   "Keep degraded status visible until retry evidence completes.",
			Confidence:    0.7,
			CheckedAt:     now,
		},
	}
	status, confidence, failures, remediations = summarizeAWSServiceCollectorContractChecks(checks)
	if status != awsServiceCollectorContractStatusDegraded || confidence > 0.75 {
		t.Fatalf("expected degraded summary with capped confidence, got status=%s confidence=%f", status, confidence)
	}
	if !containsString(failures, "throttling fixture is retrying") || len(remediations) != 1 {
		t.Fatalf("expected degraded failure/remediation, got failures=%+v remediations=%+v", failures, remediations)
	}
}

func TestAWSServiceCollectorPermissionReadsPayload(t *testing.T) {
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
		"bedrock:Converse",
		"bedrock:ConverseStream",
		"bedrock:Converse*",
		"bedrock:Invoke",
		"bedrock:InvokeModel",
		"bedrock:Inv*",
		"bedrock:*",
		"rds-data:Execute",
		"rds-data:*",
	} {
		if !awscontract.ServiceCollectorPermissionReadsPayload(permission) {
			t.Fatalf("expected %q to be treated as a payload-reading permission", permission)
		}
	}
	if awscontract.ServiceCollectorPermissionReadsPayload("iam:GetRolePolicy") {
		t.Fatal("expected IAM policy metadata read to stay inside collector boundary")
	}
	if awscontract.ServiceCollectorPermissionReadsPayload("iam:Get*") {
		t.Fatal("expected IAM wildcard metadata reads to stay inside collector boundary")
	}
}

func TestRouterAWSServiceCollectorContract(t *testing.T) {
	r := newAWSConnectionTestRouter(t, &fakeAWSConnectorValidator{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/collector-contract", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected collector contract 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var body struct {
		Contract AWSServiceCollectorContractResult `json:"contract"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode collector contract response: %v", err)
	}
	if body.Contract.Status != awsServiceCollectorContractStatusReady || body.Contract.CurrentIssueRef != "#1476" {
		t.Fatalf("unexpected collector contract payload: %+v", body.Contract)
	}
	if body.Contract.RequiredFieldCount != 17 || !containsAWSServiceCollectorFixtureState(body.Contract.FixtureCases, "permission_denied") {
		t.Fatalf("expected record fields and permission denied fixture, got %+v", body.Contract)
	}
}

func containsAWSServiceCollectorFixtureState(fixtures []AWSServiceCollectorFixtureCase, state string) bool {
	for _, fixture := range fixtures {
		if fixture.State == state {
			return true
		}
	}
	return false
}

func containsAWSServiceCollectorGraphEdge(edges []AWSServiceCollectorGraphEdge, name string) bool {
	for _, edge := range edges {
		if edge.Name == name {
			return true
		}
	}
	return false
}
