package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newGovernanceAuditReportingService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSGovernanceAuditReportingBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 3, 18, 0, 0, 0, time.UTC)
	svc, ws := newGovernanceAuditReportingService(t, "project-governance-audit", now)

	result, err := svc.GetAWSGovernanceAuditReporting(defaultScopeContext(), ws, "project-governance-audit", AWSGovernanceAuditReportingRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get governance audit reporting: %v", err)
	}
	if result.CurrentIssueRef != "#1548" || result.Version != awsGovernanceAuditReportingVersion || result.PolicyVersion != awsGovernanceAuditReportingPolicyID {
		t.Fatalf("unexpected report metadata: %+v", result)
	}
	if len(result.Records) == 0 {
		t.Fatalf("expected governance audit records from upstream governance sources: %+v", result.Summary)
	}
	requiredCategories := map[string]bool{
		awsGovernanceAuditCategoryDecision:           false,
		awsGovernanceAuditCategoryApproval:           false,
		awsGovernanceAuditCategoryRemediation:        false,
		awsGovernanceAuditCategoryEnforcementOutcome: false,
	}
	for _, record := range result.Records {
		if _, ok := requiredCategories[record.Category]; ok {
			requiredCategories[record.Category] = true
		}
		if record.ReportID == "" || record.CalculationVersion != awsGovernanceAuditReportingVersion {
			t.Fatalf("record missing stable report metadata: %+v", record)
		}
		if record.PolicyVersion == "" || record.SourceID == "" || record.DecisionType == "" {
			t.Fatalf("record missing source/policy metadata: %+v", record)
		}
		if record.EvidenceBoundary != awsGovernanceAuditReportingEvidenceBoundary() || !record.ReadOnlyProjection {
			t.Fatalf("record crossed evidence boundary or is not read-only: %+v", record)
		}
		if len(record.EvidenceSummary) > 0 {
			for _, evidence := range record.EvidenceSummary {
				if !evidence.Exportable || !evidence.Redacted {
					t.Fatalf("evidence summary must be exportable and redacted: %+v", evidence)
				}
			}
		}
	}
	for category, seen := range requiredCategories {
		if !seen {
			t.Fatalf("expected category %s in governance audit report: %+v", category, result.Summary.CategoryCounts)
		}
	}
	if result.Summary.ExportableEvidenceCount == 0 || result.Summary.AuditEntryCount == 0 {
		t.Fatalf("expected exportable evidence and audit entries in summary: %+v", result.Summary)
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\"", "\"prompt\"", "\"completion\"", "\"database_rows\"", "\"object_contents\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("governance audit report serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestGetAWSGovernanceAuditReportingIncludesAllDiagnosticsAsExceptionRows(t *testing.T) {
	now := time.Date(2026, 7, 3, 18, 10, 0, 0, time.UTC)
	svc, ws := newGovernanceAuditReportingService(t, "project-governance-audit-diagnostics", now)

	result, err := svc.GetAWSGovernanceAuditReporting(defaultScopeContext(), ws, "project-governance-audit-diagnostics", AWSGovernanceAuditReportingRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
		Category:     awsGovernanceAuditCategoryException,
	})
	if err != nil {
		t.Fatalf("get governance audit reporting: %v", err)
	}
	if len(result.Diagnostics) == 0 {
		t.Fatalf("expected upstream diagnostics in permission_denied report")
	}
	expected := awsGovernanceAuditExceptionRecords(result.Diagnostics, now)
	if len(expected) == 0 {
		t.Fatalf("expected diagnostics to produce exception rows: %+v", result.Diagnostics)
	}
	seen := map[string]bool{}
	for _, record := range result.Records {
		seen[record.ReportID] = true
		if !record.Exception {
			t.Fatalf("category=exception should only return exception rows, got %+v", record)
		}
	}
	for _, record := range expected {
		if !seen[record.ReportID] {
			t.Fatalf("expected diagnostic exception row %q in filtered export, got %+v", record.ReportID, result.Records)
		}
	}
}

func TestAWSGovernanceAuditExceptionRecordsPreserveDiagnosticSource(t *testing.T) {
	now := time.Date(2026, 7, 3, 18, 20, 0, 0, time.UTC)

	records := awsGovernanceAuditExceptionRecords([]AWSGovernanceAuditReportingDiagnostic{
		{
			Collector: "scp_guardrail_executor",
			SourceID:  "aws-scp-guardrail-executor:payments",
			Code:      "permission_denied",
			Message:   "Organizations read access denied while building SCP executor evidence.",
		},
	}, now)
	if len(records) != 1 {
		t.Fatalf("expected one diagnostic exception row, got %+v", records)
	}
	if records[0].SourceType != "scp_guardrail_executor" || records[0].SourceID != "aws-scp-guardrail-executor:payments" {
		t.Fatalf("expected diagnostic collector/source metadata to be preserved, got %+v", records[0])
	}
}

func TestAWSGovernanceAuditReportingDiagnosticsDeduplicateTransitiveSources(t *testing.T) {
	duplicate := AWSGovernanceAuditReportingDiagnostic{
		Collector: "scp_guardrail_executor",
		SourceID:  "aws-scp-guardrail-executor:payments",
		Code:      "permission_denied",
		Message:   "Organizations read access denied while building SCP executor evidence.",
	}
	distinctCollector := duplicate
	distinctCollector.Collector = "post_remediation_verification"

	diagnostics := awsGovernanceAuditReportingDiagnostics(
		[]AWSGovernanceAuditReportingDiagnostic{duplicate},
		[]AWSGovernanceAuditReportingDiagnostic{duplicate, distinctCollector},
	)
	if len(diagnostics) != 2 {
		t.Fatalf("expected duplicate transitive diagnostics to collapse by collector/source/code/message, got %+v", diagnostics)
	}
	records := awsGovernanceAuditExceptionRecords(diagnostics, time.Date(2026, 7, 3, 18, 25, 0, 0, time.UTC))
	seen := map[string]bool{}
	for _, record := range records {
		if seen[record.ReportID] {
			t.Fatalf("expected distinct diagnostic exception report IDs after dedupe, got duplicate %q in %+v", record.ReportID, records)
		}
		seen[record.ReportID] = true
	}
}

func TestFilterAWSGovernanceAuditReportingByDecisionApproverAndTime(t *testing.T) {
	now := time.Date(2026, 7, 3, 18, 30, 0, 0, time.UTC)
	records := []AWSGovernanceAuditReportRecord{
		{
			ReportID:     "decision-a",
			Category:     awsGovernanceAuditCategoryDecision,
			DecisionType: "advisory_authorization",
			State:        "allow",
			SourceType:   "advisory_authorization",
			AccountID:    "111111111111",
			OccurredAt:   now.Add(-10 * time.Minute),
		},
		{
			ReportID:     "agent-a",
			Category:     awsGovernanceAuditCategoryDecision,
			DecisionType: "agentcore_gateway_policy_advisory",
			State:        "operator_review",
			SourceType:   "agentcore_gateway_policy_advisory",
			AgentID:      "agent-prod",
			AgentNodeID:  "aws:agent:agent-prod",
			OU:           "ou-prod/ou-payments",
			Region:       "us-east-1",
			OccurredAt:   now.Add(-20 * time.Minute),
		},
		{
			ReportID:     "approval-a",
			Category:     awsGovernanceAuditCategoryApproval,
			DecisionType: "remediation_approval",
			State:        "denied",
			SourceType:   "aws_permission_boundary_scp",
			Approver:     "security_admin,platform_owner",
			AccountID:    "222222222222",
			Region:       "us-west-2",
			Exception:    true,
			OccurredAt:   now.Add(-2 * time.Hour),
		},
		{
			ReportID:     "diagnostic-a",
			Category:     awsGovernanceAuditCategoryException,
			DecisionType: "diagnostic_exception",
			State:        "permission_denied",
			SourceType:   "diagnostic",
			Exception:    true,
			OccurredAt:   now.Add(-90 * time.Minute),
		},
	}

	filtered, applied := filterAWSGovernanceAuditReportRecords(records, AWSGovernanceAuditReportingRequest{
		Category:     awsGovernanceAuditCategoryApproval,
		DecisionType: "remediation_approval",
		Approver:     "security_admin",
		From:         now.Add(-3 * time.Hour).Format(time.RFC3339),
		To:           now.Add(-1 * time.Hour).Format(time.RFC3339),
	}, now.Add(-3*time.Hour), now.Add(-1*time.Hour))
	if len(filtered) != 1 || filtered[0].ReportID != "approval-a" {
		t.Fatalf("expected only approval record after filters, got %+v", filtered)
	}
	if applied["category"] == "" || applied["decision_type"] == "" || applied["approver"] == "" || applied["from"] == "" || applied["to"] == "" {
		t.Fatalf("expected applied filters to preserve operator query, got %+v", applied)
	}

	filtered, _ = filterAWSGovernanceAuditReportRecords(records, AWSGovernanceAuditReportingRequest{
		AgentID: "agent-prod",
		OU:      "ou-payments",
	}, time.Time{}, time.Time{})
	if len(filtered) != 1 || filtered[0].ReportID != "agent-a" {
		t.Fatalf("expected agent/OU filters to match agent governance record, got %+v", filtered)
	}

	filtered, _ = filterAWSGovernanceAuditReportRecords(records, AWSGovernanceAuditReportingRequest{
		Region: "us-east-1",
	}, time.Time{}, time.Time{})
	if len(filtered) != 1 || filtered[0].ReportID != "agent-a" {
		t.Fatalf("expected region filter to exclude empty or mismatched region rows, got %+v", filtered)
	}

	filtered, applied = filterAWSGovernanceAuditReportRecords(records, AWSGovernanceAuditReportingRequest{
		Category: awsGovernanceAuditCategoryException,
	}, time.Time{}, time.Time{})
	if len(filtered) != 2 {
		t.Fatalf("expected category=exception to keep flagged and diagnostic exception rows, got %+v", filtered)
	}
	seen := map[string]bool{}
	for _, record := range filtered {
		seen[record.ReportID] = true
		if !record.Exception {
			t.Fatalf("expected only exception rows from category=exception, got %+v", record)
		}
	}
	if !seen["approval-a"] || !seen["diagnostic-a"] || applied["category"] != awsGovernanceAuditCategoryException {
		t.Fatalf("expected flagged approval and diagnostic exception rows, filtered=%+v applied=%+v", filtered, applied)
	}
}

func TestRouterAWSGovernanceAuditReporting(t *testing.T) {
	now := time.Date(2026, 7, 3, 19, 0, 0, 0, time.UTC)
	svc, _ := newGovernanceAuditReportingService(t, "project-governance-audit-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	query := url.Values{}
	query.Set("connector_id", "aws-prod")
	query.Set("fixture_state", "success")
	query.Set("category", awsGovernanceAuditCategoryDecision)
	query.Set("decision_type", "agentcore_gateway_policy_advisory")
	query.Set("search", "agent")
	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-governance-audit-route/aws/governance-audit-reporting?"+query.Encode(), "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Report AWSGovernanceAuditReportingResult `json:"governance_audit_reporting"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Report.CurrentIssueRef != "#1548" || body.Report.AppliedFilters["decision_type"] == "" {
		t.Fatalf("unexpected route payload: %+v", body.Report)
	}
	for _, record := range body.Report.Records {
		if record.DecisionType != "agentcore_gateway_policy_advisory" {
			t.Fatalf("route did not apply decision_type filter: %+v", record)
		}
	}
}

func TestRouterAWSGovernanceAuditReportingRejectsInvalidTimeRange(t *testing.T) {
	now := time.Date(2026, 7, 3, 19, 30, 0, 0, time.UTC)
	svc, _ := newGovernanceAuditReportingService(t, "project-governance-audit-bad-time", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-governance-audit-bad-time/aws/governance-audit-reporting?connector_id=aws-prod&fixture_state=success&from=not-a-time", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid from time, got %d body=%s", resp.Code, resp.Body.String())
	}

	query := url.Values{}
	query.Set("connector_id", "aws-prod")
	query.Set("fixture_state", "success")
	query.Set("from", now.Format(time.RFC3339))
	query.Set("to", now.Add(-1*time.Hour).Format(time.RFC3339))
	resp = doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-governance-audit-bad-time/aws/governance-audit-reporting?"+query.Encode(), "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when from is after to, got %d body=%s", resp.Code, resp.Body.String())
	}
}
