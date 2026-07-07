package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newRemediationCenterService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSRemediationCenterBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center", now)

	result, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation center: %v", err)
	}
	if result.CurrentIssueRef != "#1552" || result.Version != awsRemediationCenterVersion || result.PolicyVersion != awsRemediationCenterPolicyID {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Cases) == 0 {
		t.Fatalf("expected case-keyed lifecycle rollups: %+v", result.Summary)
	}
	if result.Summary.TotalCases != len(result.RemediationCases.Cases) {
		t.Fatalf("summary total must match source case count: summary=%d cases=%d", result.Summary.TotalCases, len(result.RemediationCases.Cases))
	}
	if len(result.Tabs) == 0 {
		t.Fatalf("expected center tabs: %+v", result)
	}
	if len(result.EvidenceLinks) == 0 {
		t.Fatalf("expected evidence links: %+v", result)
	}
	validStages := map[string]bool{
		awsRemediationCenterStageCase: true, awsRemediationCenterStageApproval: true,
		awsRemediationCenterStageDryRun: true, awsRemediationCenterStageLiveAction: true,
		awsRemediationCenterStageVerification: true, awsRemediationCenterStageRollback: true,
	}
	for _, entry := range result.Cases {
		if entry.CaseID == "" || entry.Title == "" {
			t.Fatalf("case rollup missing identity fields: %+v", entry)
		}
		if !validStages[entry.Stage] {
			t.Fatalf("case rollup has unknown stage: %+v", entry)
		}
		if entry.EvidenceBoundary != awsRemediationCenterEvidenceBoundary() {
			t.Fatalf("case rollup crossed evidence boundary: %+v", entry)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_value\"", "\"policy_document_body\"", "\"rendered_policy\"", "\"secret_access_key\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("remediation center serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestGetAWSRemediationCenterStitchesLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 30, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center-lifecycle", now)

	result, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-lifecycle", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation center: %v", err)
	}
	advanced := 0
	sawVerification := false
	for _, entry := range result.Cases {
		if entry.Stage == awsRemediationCenterStageCase {
			continue
		}
		advanced++
		// A case that advanced past `case` must carry the stage evidence
		// that drove it there.
		if entry.ApprovalID == "" {
			t.Fatalf("advanced case must carry its approval ID: %+v", entry)
		}
		if entry.Stage == awsRemediationCenterStageVerification || entry.Stage == awsRemediationCenterStageRollback {
			sawVerification = true
			if entry.VerificationID == "" || entry.DryRunID == "" {
				t.Fatalf("verification-stage case must carry verification and dry-run IDs: %+v", entry)
			}
		}
		if len(entry.SafetyGates) == 0 {
			t.Fatalf("advanced case must consolidate safety gates: %+v", entry)
		}
	}
	if advanced == 0 || !sawVerification {
		t.Fatalf("expected fixture cases to advance through the lifecycle incl. verification, got advanced=%d verification=%v", advanced, sawVerification)
	}
	if result.Summary.DryRunCount == 0 || result.Summary.VerificationCount == 0 {
		t.Fatalf("summary must count dry-run and verification stages: %+v", result.Summary)
	}
	if result.Summary.VerificationCount != len(result.Verification.Entries) {
		t.Fatalf("verification count must match rendered verification rows: count=%d rows=%d", result.Summary.VerificationCount, len(result.Verification.Entries))
	}

	// The consolidated audit trail must match its own count and span more than the
	// verification stage, so the audit tab is not empty for earlier lifecycle
	// states that still recorded audit entries.
	if len(result.AuditTrail) != result.Summary.AuditEntryCount {
		t.Fatalf("consolidated audit trail must match audit_entry_count: trail=%d count=%d", len(result.AuditTrail), result.Summary.AuditEntryCount)
	}
	stages := map[string]int{}
	for _, audit := range result.AuditTrail {
		if audit.CaseID == "" || audit.EventID == "" {
			t.Fatalf("audit entry must carry its case and event id: %+v", audit)
		}
		stages[audit.Stage]++
	}
	nonVerification := 0
	for stage, count := range stages {
		if stage != awsRemediationCenterStageVerification {
			nonVerification += count
		}
	}
	if nonVerification == 0 {
		t.Fatalf("audit trail must include non-verification lifecycle stages, got %+v", stages)
	}
	auditByCaseEvent := map[string]struct{}{}
	for _, audit := range result.AuditTrail {
		auditByCaseEvent[audit.CaseID+"\x00"+audit.EventID] = struct{}{}
	}
	for _, verification := range result.Verification.Entries {
		for _, audit := range verification.AuditTrail {
			if strings.TrimSpace(audit.EventID) == "" {
				continue
			}
			if _, ok := auditByCaseEvent[verification.CaseID+"\x00"+audit.EventID]; !ok {
				t.Fatalf("consolidated audit trail omitted verification audit event %q for case %q", audit.EventID, verification.CaseID)
			}
		}
	}
}

func TestAWSRemediationCenterCaseDoesNotPromoteVerificationSourceExecution(t *testing.T) {
	source := AWSRemediationCase{
		CaseID:           "case-boundary",
		Title:            "Permission boundary verification",
		SourceType:       "permission_boundary_diff",
		Lifecycle:        "approved",
		Severity:         "high",
		Confidence:       0.91,
		ApprovalRequired: true,
		ApprovalState:    awsRemediationApprovalStateApproved,
		UpdatedAt:        time.Date(2026, 7, 4, 10, 45, 0, 0, time.UTC),
	}
	verify := AWSPostRemediationVerificationEntry{
		VerificationID:    "verify-boundary",
		SourceExecutionID: "exec-boundary-only",
		State:             awsPostRemediationVerificationStateVerified,
	}

	entry := awsRemediationCenterCaseFromLifecycle(
		source,
		AWSRemediationApprovalEntry{}, false,
		AWSRemediationDryRunEntry{}, false,
		AWSLowRiskRemediationEntry{}, false,
		verify, true,
	)
	if entry.ExecutionID != "" {
		t.Fatalf("verification source execution must not be counted as a live action execution: %+v", entry)
	}
	if entry.VerificationID != verify.VerificationID || entry.Stage != awsRemediationCenterStageVerification {
		t.Fatalf("verification evidence must still be retained on the case rollup: %+v", entry)
	}
	summary := summarizeAWSRemediationCenterCases([]AWSRemediationCenterCase{entry}, []AWSRemediationCenterCase{entry})
	if summary.LiveActionCount != 0 || summary.VerificationCount != 1 {
		t.Fatalf("verification-only case must not inflate live action count: %+v", summary)
	}
}

func TestAWSRemediationCenterSummaryCountsOnlyActionablePendingApprovals(t *testing.T) {
	entries := []AWSRemediationCenterCase{
		{CaseID: "requested", ApprovalID: "approval-requested", ApprovalState: awsRemediationApprovalStateRequested},
		{CaseID: "review", ApprovalID: "approval-review", ApprovalState: awsRemediationApprovalStateReview},
		{CaseID: "approved", ApprovalID: "approval-approved", ApprovalState: awsRemediationApprovalStateApproved},
		{CaseID: "denied", ApprovalID: "approval-denied", ApprovalState: awsRemediationApprovalStateDenied},
		{CaseID: "expired", ApprovalID: "approval-expired", ApprovalState: awsRemediationApprovalStateExpired},
		{CaseID: "blocked", ApprovalID: "approval-blocked", ApprovalState: awsRemediationApprovalStateBlocked},
		{CaseID: "live", ExecutionID: "exec-low-risk"},
		{CaseID: "verification-only", VerificationID: "verify-boundary", VerificationState: awsPostRemediationVerificationStateVerified},
	}

	summary := summarizeAWSRemediationCenterCases(entries, entries)
	if summary.ApprovalPendingCount != 2 {
		t.Fatalf("pending approvals must count only requested/under-review entries, got %+v", summary)
	}
	if summary.LiveActionCount != 1 || summary.VerificationCount != 1 {
		t.Fatalf("summary must keep live-action and verification counts distinct: %+v", summary)
	}
}

func TestAWSRemediationCenterAuditTrailDeduplicatesInheritedEvents(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 50, 0, 0, time.UTC)
	caseAudit := AWSRemediationAuditEntry{EventID: "case-created", EventType: "case_projected", Actor: "case-engine", OccurredAt: now}
	approvalAudit := AWSRemediationAuditEntry{EventID: "approval-requested", EventType: "approval_requested", Actor: "approval-engine", OccurredAt: now}
	dryRunAudit := AWSRemediationAuditEntry{EventID: "dry-run-simulated", EventType: "dry_run_simulated", Actor: "dry-run-engine", OccurredAt: now}
	liveAudit := AWSRemediationAuditEntry{EventID: "live-projected", EventType: "low_risk_execution_projected", Actor: "live-engine", OccurredAt: now}
	verifyAudit := AWSRemediationAuditEntry{EventID: "verification-projected", EventType: "post_remediation_verification_projected", Actor: "verification-engine", OccurredAt: now}

	entry := awsRemediationCenterCaseFromLifecycle(
		AWSRemediationCase{CaseID: "case-audit", Title: "Audit lifecycle", AuditTrail: []AWSRemediationAuditEntry{caseAudit}},
		AWSRemediationApprovalEntry{
			ApprovalID: "approval-audit",
			State:      awsRemediationApprovalStateApproved,
			AuditTrail: []AWSRemediationApprovalAuditEntry{caseAudit, approvalAudit},
		}, true,
		AWSRemediationDryRunEntry{
			DryRunID:   "dry-run-audit",
			Outcome:    "would_succeed",
			AuditTrail: []AWSRemediationApprovalAuditEntry{caseAudit, approvalAudit, dryRunAudit},
		}, true,
		AWSLowRiskRemediationEntry{
			ExecutionID: "exec-audit",
			State:       "projected",
			AuditTrail:  []AWSLowRiskRemediationAuditEntry{caseAudit, approvalAudit, dryRunAudit, liveAudit},
		}, true,
		AWSPostRemediationVerificationEntry{
			VerificationID: "verify-audit",
			State:          awsPostRemediationVerificationStateVerified,
			AuditTrail:     []AWSPostRemediationVerificationAuditEntry{caseAudit, approvalAudit, dryRunAudit, liveAudit, verifyAudit},
		}, true,
	)

	wantStages := map[string]string{
		"case-created":           awsRemediationCenterStageCase,
		"approval-requested":     awsRemediationCenterStageApproval,
		"dry-run-simulated":      awsRemediationCenterStageDryRun,
		"live-projected":         awsRemediationCenterStageLiveAction,
		"verification-projected": awsRemediationCenterStageVerification,
	}
	if len(entry.AuditTrail) != len(wantStages) || entry.AuditEntryCount != len(wantStages) {
		t.Fatalf("audit trail must keep only unique lifecycle events: count=%d trail=%+v", entry.AuditEntryCount, entry.AuditTrail)
	}
	seen := map[string]struct{}{}
	for _, audit := range entry.AuditTrail {
		if _, ok := seen[audit.EventID]; ok {
			t.Fatalf("audit event %s was duplicated: %+v", audit.EventID, entry.AuditTrail)
		}
		seen[audit.EventID] = struct{}{}
		if wantStages[audit.EventID] != audit.Stage {
			t.Fatalf("audit event %s stage=%s want=%s trail=%+v", audit.EventID, audit.Stage, wantStages[audit.EventID], entry.AuditTrail)
		}
	}
}

func TestAWSRemediationCenterCaseAggregatesAllVerificationAuditTrails(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 55, 0, 0, time.UTC)
	caseAudit := AWSRemediationAuditEntry{EventID: "case-created", EventType: "case_projected", Actor: "case-engine", OccurredAt: now}
	verifyA := AWSRemediationAuditEntry{EventID: "verify-target-a", EventType: "post_remediation_verification_projected", Actor: "verification-engine", OccurredAt: now}
	verifyB := AWSRemediationAuditEntry{EventID: "verify-target-b", EventType: "post_remediation_verification_projected", Actor: "verification-engine", OccurredAt: now}
	verifications := []AWSPostRemediationVerificationEntry{
		{
			VerificationID: "verify-a",
			CaseID:         "case-multi-verify",
			State:          awsPostRemediationVerificationStateVerified,
			AuditTrail:     []AWSPostRemediationVerificationAuditEntry{caseAudit, verifyA},
		},
		{
			VerificationID: "verify-b",
			CaseID:         "case-multi-verify",
			State:          awsPostRemediationVerificationStateFailed,
			AuditTrail:     []AWSPostRemediationVerificationAuditEntry{caseAudit, verifyB},
		},
	}
	selected, hasSelected := awsRemediationCenterSelectedVerification(verifications)
	if !hasSelected {
		t.Fatalf("expected selected verification")
	}
	entry := awsRemediationCenterCaseFromLifecycleWithVerifications(
		AWSRemediationCase{CaseID: "case-multi-verify", Title: "Multi-target verification", AuditTrail: []AWSRemediationAuditEntry{caseAudit}},
		AWSRemediationApprovalEntry{}, false,
		AWSRemediationDryRunEntry{}, false,
		AWSLowRiskRemediationEntry{}, false,
		selected, true,
		verifications,
	)

	if entry.VerificationID != "verify-b" || entry.Stage != awsRemediationCenterStageRollback {
		t.Fatalf("case rollup must keep the worst verification state, got %+v", entry)
	}
	if entry.VerificationEntryCount != len(verifications) {
		t.Fatalf("case rollup must retain rendered verification row count, got %+v", entry)
	}
	if got, want := strings.Join(entry.VerificationStates, ","), strings.Join([]string{awsPostRemediationVerificationStateVerified, awsPostRemediationVerificationStateFailed}, ","); got != want {
		t.Fatalf("case rollup must retain every verification state, got %q want %q", got, want)
	}
	wantEvents := map[string]bool{"case-created": true, "verify-target-a": true, "verify-target-b": true}
	for _, audit := range entry.AuditTrail {
		delete(wantEvents, audit.EventID)
	}
	if len(wantEvents) != 0 || entry.AuditEntryCount != 3 {
		t.Fatalf("case rollup must aggregate every unique verification audit event: missing=%+v trail=%+v", wantEvents, entry.AuditTrail)
	}
	summary := summarizeAWSRemediationCenterCases([]AWSRemediationCenterCase{entry}, []AWSRemediationCenterCase{entry})
	if summary.VerificationCount != len(verifications) || summary.AuditEntryCount != entry.AuditEntryCount {
		t.Fatalf("summary must count rendered verification rows and aggregated audit entries: %+v entry=%+v", summary, entry)
	}
}

func TestGetAWSRemediationCenterScopesPayloadsToFilteredCases(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 30, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center-scope", now)

	full, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-scope", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation center: %v", err)
	}
	if len(full.Cases) < 2 {
		t.Fatalf("expected multiple cases to scope against, got %d", len(full.Cases))
	}
	target := full.Cases[0].CaseID

	scoped, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-scope", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		CaseID:       target,
	})
	if err != nil {
		t.Fatalf("get remediation center (scoped): %v", err)
	}
	if len(scoped.Cases) != 1 || scoped.Cases[0].CaseID != target {
		t.Fatalf("case_id filter must scope cases to %s: %+v", target, scoped.Cases)
	}
	// Every embedded lifecycle payload rendered by the tabs must be reconciled to
	// the filtered case so a deep link never shows unrelated rows.
	for _, e := range scoped.ApprovalQueue.Entries {
		if e.CaseID != target {
			t.Errorf("approval queue leaked case %s under case_id=%s", e.CaseID, target)
		}
	}
	for _, e := range scoped.DryRuns.Entries {
		if e.CaseID != target {
			t.Errorf("dry-run leaked case %s under case_id=%s", e.CaseID, target)
		}
	}
	for _, e := range scoped.LiveActions.Entries {
		if e.CaseID != target {
			t.Errorf("live action leaked case %s under case_id=%s", e.CaseID, target)
		}
	}
	for _, e := range scoped.Verification.Entries {
		if e.CaseID != target {
			t.Errorf("verification leaked case %s under case_id=%s", e.CaseID, target)
		}
	}
	for _, e := range scoped.AuditTrail {
		if e.CaseID != target {
			t.Errorf("audit trail leaked case %s under case_id=%s", e.CaseID, target)
		}
	}
}

func TestAWSRemediationCenterScopesVerificationRowsToStatus(t *testing.T) {
	centerCases := []AWSRemediationCenterCase{
		{
			CaseID:                 "case-mixed",
			VerificationID:         "verify-failed",
			VerificationState:      awsPostRemediationVerificationStateFailed,
			VerificationEntryCount: 2,
			VerificationStates:     []string{awsPostRemediationVerificationStateFailed, awsPostRemediationVerificationStateVerified},
			AuditTrail: []AWSRemediationCenterAuditEntry{
				{CaseID: "case-mixed", Stage: awsRemediationCenterStageCase, EventID: "case-mixed-created"},
				{CaseID: "case-mixed", Stage: awsRemediationCenterStageVerification, EventID: "case-mixed-failed"},
				{CaseID: "case-mixed", Stage: awsRemediationCenterStageVerification, EventID: "case-mixed-verified"},
			},
			AuditEntryCount: 3,
		},
		{
			CaseID:                 "case-verified",
			VerificationID:         "verify-verified",
			VerificationState:      awsPostRemediationVerificationStateVerified,
			VerificationEntryCount: 1,
			VerificationStates:     []string{awsPostRemediationVerificationStateVerified},
			AuditTrail: []AWSRemediationCenterAuditEntry{
				{CaseID: "case-verified", Stage: awsRemediationCenterStageCase, EventID: "case-verified-created"},
				{CaseID: "case-verified", Stage: awsRemediationCenterStageVerification, EventID: "case-verified-verified"},
			},
			AuditEntryCount: 2,
		},
	}
	verificationRows := []AWSPostRemediationVerificationEntry{
		{CaseID: "case-mixed", VerificationID: "verify-failed", State: awsPostRemediationVerificationStateFailed, AuditTrail: []AWSPostRemediationVerificationAuditEntry{{EventID: "case-mixed-failed"}}},
		{CaseID: "case-mixed", VerificationID: "verify-verified", State: awsPostRemediationVerificationStateVerified, AuditTrail: []AWSPostRemediationVerificationAuditEntry{{EventID: "case-mixed-verified"}}},
		{CaseID: "case-verified", VerificationID: "verify-only-verified", State: awsPostRemediationVerificationStateVerified, AuditTrail: []AWSPostRemediationVerificationAuditEntry{{EventID: "case-verified-verified"}}},
		{CaseID: "case-unfiltered", VerificationID: "verify-outside-case-filter", State: awsPostRemediationVerificationStateVerified, AuditTrail: []AWSPostRemediationVerificationAuditEntry{{EventID: "case-unfiltered-verified"}}},
	}

	filtered, _ := filterAWSRemediationCenterCases(centerCases, AWSRemediationCenterRequest{Status: awsPostRemediationVerificationStateVerified})
	scopedRows := awsRemediationCenterScopeVerificationEntries(verificationRows, awsRemediationCenterCaseIDSet(filtered), awsPostRemediationVerificationStateVerified)
	filtered = awsRemediationCenterCasesWithScopedVerificationRows(filtered, scopedRows)
	summary := summarizeAWSRemediationCenterCases(centerCases, filtered)
	auditTrail := awsRemediationCenterAuditTrail(filtered)

	if len(filtered) != 2 {
		t.Fatalf("case-level status filter should keep both verified cases, got %+v", filtered)
	}
	if len(scopedRows) != 2 {
		t.Fatalf("status-scoped verification rows should keep only matching rows from filtered cases, got %+v", scopedRows)
	}
	for _, row := range scopedRows {
		if row.State != awsPostRemediationVerificationStateVerified {
			t.Errorf("verification row %s leaked state %s", row.VerificationID, row.State)
		}
		if row.CaseID == "case-unfiltered" {
			t.Errorf("verification row %s leaked outside filtered case set", row.VerificationID)
		}
	}
	countsByCase := map[string]int{}
	for _, row := range scopedRows {
		countsByCase[row.CaseID]++
	}
	for _, entry := range filtered {
		if entry.VerificationEntryCount != countsByCase[entry.CaseID] {
			t.Errorf("case %s verification_entry_count=%d want rendered rows=%d", entry.CaseID, entry.VerificationEntryCount, countsByCase[entry.CaseID])
		}
	}
	if summary.VerificationCount != len(scopedRows) {
		t.Fatalf("verification_count must match rendered status-scoped rows: count=%d rows=%d", summary.VerificationCount, len(scopedRows))
	}
	for _, audit := range auditTrail {
		if audit.EventID == "case-mixed-failed" || audit.EventID == "case-unfiltered-verified" {
			t.Errorf("audit event %s leaked outside status-scoped verification rows", audit.EventID)
		}
	}
	if got, want := summary.AuditEntryCount, len(auditTrail); got != want {
		t.Fatalf("audit_entry_count must match status-scoped audit rows: got=%d want=%d trail=%+v", got, want, auditTrail)
	}
}

func TestGetAWSRemediationCenterPreservesUnfilteredTotals(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 40, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center-unfiltered-totals", now)

	full, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-unfiltered-totals", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation center: %v", err)
	}
	if len(full.Cases) < 2 {
		t.Fatalf("expected multiple cases to filter, got %d", len(full.Cases))
	}

	severity := ""
	filteredCount := 0
	for value, count := range full.Summary.SeverityCounts {
		if count > 0 && count < full.Summary.TotalCases {
			severity = value
			filteredCount = count
			break
		}
	}
	if severity == "" {
		t.Fatalf("expected fixture to include a severity subset, got summary=%+v", full.Summary)
	}

	scoped, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-unfiltered-totals", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     severity,
	})
	if err != nil {
		t.Fatalf("get remediation center (severity scoped): %v", err)
	}
	if scoped.Summary.TotalCases != full.Summary.TotalCases {
		t.Fatalf("severity filter must preserve connector-wide total_cases: got=%d want=%d", scoped.Summary.TotalCases, full.Summary.TotalCases)
	}
	if scoped.Summary.FilteredCases != filteredCount || len(scoped.Cases) != filteredCount {
		t.Fatalf("severity filter must only narrow filtered cases: summary=%+v len=%d want=%d severity=%s", scoped.Summary, len(scoped.Cases), filteredCount, severity)
	}
	if scoped.Summary.SeverityCounts[severity] != filteredCount || len(scoped.Summary.SeverityCounts) != 1 {
		t.Fatalf("filtered severity facets must reflect the filtered case set: %+v severity=%s", scoped.Summary.SeverityCounts, severity)
	}
	for _, entry := range scoped.Cases {
		if entry.Severity != severity {
			t.Fatalf("severity filter leaked case %s with severity %s under severity=%s", entry.CaseID, entry.Severity, severity)
		}
	}
}

func TestFilterAWSRemediationCenterCases(t *testing.T) {
	entries := []AWSRemediationCenterCase{
		{CaseID: "c-1", Severity: "critical", Confidence: 0.95, IdentityType: "iam_role", ActionType: "iam_policy_diff", SourceType: "least_privilege", Lifecycle: "proposed", Stage: "dry_run", AccountID: "111111111111", Region: "us-east-1"},
		{CaseID: "c-2", Severity: "high", Confidence: 0.6, IdentityType: "iam_identity", ActionType: "secret_rotation", SourceType: "aws_secret_key_rotation", Lifecycle: "in_review", Stage: "verification", AccountID: "222222222222", Region: "us-west-2", VerificationState: "verification_failed", VerificationStates: []string{"verification_failed", "verification_verified"}},
	}

	// Each filter is independent of the others, so report every failure rather
	// than aborting on the first — a regression in one filter must not hide a
	// regression in the rest.
	expectSingleCase := func(name string, filtered []AWSRemediationCenterCase, wantCaseID string) {
		t.Helper()
		if len(filtered) != 1 || filtered[0].CaseID != wantCaseID {
			t.Errorf("%s filter did not scope to %s: %+v", name, wantCaseID, filtered)
		}
	}

	filtered, applied := filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Severity: "critical"})
	if applied["severity"] != normalizeAWSRuntimeEventFilterToken("critical") {
		t.Errorf("severity filter did not record applied token: applied=%+v", applied)
	}
	expectSingleCase("severity", filtered, "c-1")

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Stage: "verification"})
	expectSingleCase("stage", filtered, "c-2")

	filtered, applied = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Confidence: "0.9"})
	if applied["confidence"] != "0.9" {
		t.Errorf("numeric confidence floor did not record applied token: applied=%+v", applied)
	}
	expectSingleCase("numeric confidence floor", filtered, "c-1")

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Confidence: "high"})
	expectSingleCase("bucket confidence floor", filtered, "c-1")

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{IdentityType: "iam_role"})
	expectSingleCase("identity_type", filtered, "c-1")

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{ActionType: "secret_rotation"})
	expectSingleCase("action_type", filtered, "c-2")

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{AccountID: "222222222222"})
	expectSingleCase("account_id", filtered, "c-2")

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Status: "verification_verified"})
	expectSingleCase("status", filtered, "c-2")
}

func TestAWSRemediationCenterConfidenceFloor(t *testing.T) {
	cases := []struct {
		value string
		want  float64
		ok    bool
	}{
		{"", 0, false},
		{"high", 0.85, true},
		{"medium", 0.6, true},
		{"low", 0, true},
		{"0.75", 0.75, true},
		{"1", 1, true},
		{"0", 0, true},
		{"1.5", 0, false},
		{"-0.1", 0, false},
		{"bogus", 0, false},
	}
	for _, tc := range cases {
		got, ok := awsRemediationCenterConfidenceFloor(tc.value)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("value=%q got (%v,%v) want (%v,%v)", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

func TestGetAWSRemediationCenterFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 4, 11, 0, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-fixture", AWSRemediationCenterRequest{
			ConnectorID:  "aws-prod",
			FixtureState: state,
		})
		if err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		if result.FixtureState != state {
			t.Fatalf("%s: expected fixture_state echoed, got %q", state, result.FixtureState)
		}
		if result.Status == "" {
			t.Fatalf("%s: missing status", state)
		}
		if state == "permission_denied" && result.Status != "permission_denied" {
			t.Fatalf("permission denied must surface as explicit status, got %q", result.Status)
		}
	}
}

func TestGetAWSRemediationCenterMissingConnectorIsPermissionDenied(t *testing.T) {
	now := time.Date(2026, 7, 4, 11, 30, 0, 0, time.UTC)
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	projectID := "project-remediation-center-no-connector"
	seedDefaultProject(t, store, ctx, projectID)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSRemediationCenter(ctx, "default", projectID, AWSRemediationCenterRequest{})
	if err != nil {
		t.Fatalf("missing connector must return explicit remediation center payload: %v", err)
	}
	if result.FixtureState != "permission_denied" || result.Status != "permission_denied" {
		t.Fatalf("missing connector must surface permission_denied, got fixture=%q status=%q", result.FixtureState, result.Status)
	}
	if len(result.Cases) != 0 || len(result.ApprovalQueue.Entries) != 0 || len(result.DryRuns.Entries) != 0 || len(result.LiveActions.Entries) != 0 || len(result.Verification.Entries) != 0 {
		t.Fatalf("missing connector must not fabricate remediation lifecycle rows: %+v", result)
	}
}

func TestRouterAWSRemediationCenter(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	svc, _ := newRemediationCenterService(t, "project-remediation-center-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-center-route/aws/remediation-center?connector_id=aws-prod&fixture_state=success&stage=verification", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Center AWSRemediationCenterResult `json:"remediation_center"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Center.CurrentIssueRef != "#1552" || body.Center.AppliedFilters["stage"] != "verification" {
		t.Fatalf("unexpected route payload: %+v", body.Center)
	}
	for _, entry := range body.Center.Cases {
		if entry.Stage != awsRemediationCenterStageVerification {
			t.Fatalf("stage=verification route returned wrong stage: %+v", entry)
		}
	}

	badFixture := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-center-route/aws/remediation-center?connector_id=aws-prod&fixture_state=bogus", "")
	if badFixture.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid fixture state, got %d body=%s", badFixture.Code, badFixture.Body.String())
	}
}
