package api

import (
	"strings"
	"testing"
	"time"
)

func newLeastPrivilegeService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSLeastPrivilegeBuildsRecommendationContract(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 0, 0, 0, time.UTC)
	svc, ws := newLeastPrivilegeService(t, "project-least-privilege", now)

	result, err := svc.GetAWSLeastPrivilegeRecommendations(defaultScopeContext(), ws, "project-least-privilege", AWSLeastPrivilegeRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get least privilege recommendations: %v", err)
	}
	if result.CurrentIssueRef != "#1522" || result.Version != awsLeastPrivilegeVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Recommendations) == 0 || result.Summary.TotalRecommendations != len(result.Recommendations) {
		t.Fatalf("expected recommendations summary to match payload: %+v", result.Summary)
	}
	if result.Recommendations[0].Score < result.Recommendations[len(result.Recommendations)-1].Score {
		t.Fatalf("recommendations are not ranked by descending score: %+v", result.Recommendations)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected graph relationships: %+v", result.Relationships)
	}
	if result.Summary.RemediationPreviewCount == 0 || result.Summary.RuntimeEvidenceCount == 0 {
		t.Fatalf("expected remediation previews and evidence refs: %+v", result.Summary)
	}

	hasRemove := false
	hasKeep := false
	hasReview := false
	for _, recommendation := range result.Recommendations {
		if recommendation.RecommendationID == "" || recommendation.CalculationVersion != awsLeastPrivilegeVersion || recommendation.Rationale == "" {
			t.Fatalf("recommendation missing stable metadata: %+v", recommendation)
		}
		if recommendation.Decision == "" || recommendation.BreakagePrediction == "" || recommendation.Confidence <= 0 || len(recommendation.Evidence) == 0 {
			t.Fatalf("recommendation missing decision/breakage/evidence: %+v", recommendation)
		}
		if recommendation.RemediationCase.CaseID == "" || !recommendation.RemediationCase.ReadOnlyProjection {
			t.Fatalf("recommendation missing read-only remediation preview: %+v", recommendation.RemediationCase)
		}
		switch recommendation.Decision {
		case "remove":
			hasRemove = true
			if len(recommendation.RemoveActions) == 0 {
				t.Fatalf("remove recommendation must name removable actions: %+v", recommendation)
			}
		case "keep":
			hasKeep = true
			if recommendation.BreakagePrediction != "high" {
				t.Fatalf("keep recommendation must preserve high breakage prediction: %+v", recommendation)
			}
		case "review":
			hasReview = true
		}
	}
	if !hasRemove || !hasKeep || !hasReview {
		t.Fatalf("expected keep/remove/review recommendations, got decision counts %+v", result.Summary.DecisionCounts)
	}
}

func TestGetAWSLeastPrivilegeSuppressesImplicitRuntimeFixtures(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 5, 0, 0, time.UTC)
	svc, ws := newLeastPrivilegeService(t, "project-least-privilege-live-unavailable", now)

	result, err := svc.GetAWSLeastPrivilegeRecommendations(defaultScopeContext(), ws, "project-least-privilege-live-unavailable", AWSLeastPrivilegeRequest{
		ConnectorID: "aws-prod",
	})
	if err != nil {
		t.Fatalf("get implicit live least privilege recommendations: %v", err)
	}

	for _, recommendation := range result.Recommendations {
		for _, evidence := range recommendation.Evidence {
			switch evidence.Source {
			case "iam_last_used", "access_analyzer":
				t.Fatalf("implicit live request must not convert runtime fixtures into recommendations: %+v", recommendation)
			}
		}
	}

	hasSuppressionDiagnostic := false
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "runtime_fixture_records_suppressed" {
			hasSuppressionDiagnostic = true
			break
		}
	}
	if !hasSuppressionDiagnostic {
		t.Fatalf("expected runtime fixture suppression diagnostic, got %+v", result.Diagnostics)
	}
}

func TestGetAWSLeastPrivilegeFiltersByDecisionServiceAndResource(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 10, 0, 0, time.UTC)
	svc, ws := newLeastPrivilegeService(t, "project-least-privilege-filters", now)

	remove, err := svc.GetAWSLeastPrivilegeRecommendations(defaultScopeContext(), ws, "project-least-privilege-filters", AWSLeastPrivilegeRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Decision:     "remove",
		Service:      "lambda",
	})
	if err != nil {
		t.Fatalf("decision/service filter: %v", err)
	}
	if len(remove.Recommendations) == 0 {
		t.Fatalf("expected stale IAM last-used remove recommendation")
	}
	for _, recommendation := range remove.Recommendations {
		if recommendation.Decision != "remove" || recommendation.Service != "lambda" {
			t.Fatalf("decision/service filter leaked %+v", recommendation)
		}
	}
	if remove.AppliedFilters["decision"] != "remove" || remove.AppliedFilters["service"] != "lambda" {
		t.Fatalf("expected applied filters, got %+v", remove.AppliedFilters)
	}

	resource, err := svc.GetAWSLeastPrivilegeRecommendations(defaultScopeContext(), ws, "project-least-privilege-filters", AWSLeastPrivilegeRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Resource:     "prod/ai/openai-key",
	})
	if err != nil {
		t.Fatalf("resource filter: %v", err)
	}
	if len(resource.Recommendations) == 0 {
		t.Fatalf("expected resource label/ARN matched recommendations")
	}
	for _, recommendation := range resource.Recommendations {
		if !awsRuntimeEventMatchesAny("prod/ai/openai-key", awsLeastPrivilegeResourceMatchValues(recommendation)...) {
			t.Fatalf("resource filter leaked %+v", recommendation)
		}
	}

	tool, err := svc.GetAWSLeastPrivilegeRecommendations(defaultScopeContext(), ws, "project-least-privilege-filters", AWSLeastPrivilegeRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Tool:         "case-router",
	})
	if err != nil {
		t.Fatalf("tool filter: %v", err)
	}
	if len(tool.Recommendations) == 0 {
		t.Fatalf("expected agent-runtime tool recommendations")
	}
	if tool.AppliedFilters["tool"] != "case-router" {
		t.Fatalf("expected applied tool filter, got %+v", tool.AppliedFilters)
	}
	for _, recommendation := range tool.Recommendations {
		if !awsRuntimeEventMatchesAny("case-router", awsLeastPrivilegeToolMatchValues(recommendation)...) {
			t.Fatalf("tool filter leaked %+v", recommendation)
		}
	}
}

func TestAWSLeastPrivilegeToolMatchValuesUsesOnlyAgentToolCandidates(t *testing.T) {
	matches := awsLeastPrivilegeToolMatchValues(AWSLeastPrivilegeRecommendation{
		KeepActions:     []string{"agent-tool:case-router", "s3:GetObject"},
		RemoveActions:   []string{"agent-tool:api://tickets/search", "kms:Decrypt"},
		ObservedActions: []string{"agent-tool:case-router"},
		GrantedActions:  []string{"iam:DeleteRole"},
	})

	if !awsRuntimeEventMatchesAny("case-router", matches...) {
		t.Fatalf("expected tool name to match tool candidates: %v", matches)
	}
	if !awsRuntimeEventMatchesAny("api://tickets/search", matches...) {
		t.Fatalf("expected tool target ref to match tool candidates: %v", matches)
	}
	if awsRuntimeEventMatchesAny("s3:GetObject", matches...) {
		t.Fatalf("agent least-privilege tool filter should not match IAM actions: %v", matches)
	}
	if awsRuntimeEventMatchesAny("kms:Decrypt", matches...) {
		t.Fatalf("agent least-privilege tool filter should not match IAM actions: %v", matches)
	}
}

func TestAWSLeastPrivilegeRecommendationFromAgentRecordsIncludeToolTargetRefAndName(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 30, 0, 0, time.UTC)
	recommendation := awsLeastPrivilegeRecommendationFromAgent(AWSAgentRuntimeAccessRecord{
		CorrelationID:      "agent-runtime-filter-target-ref",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		AgentNodeID:        "agent-runtime-node",
		AgentID:            "agent-runtime-id",
		ToolName:           "case-router",
		ToolTargetRef:      "api://tickets/search",
		Status:             "declared-unused",
		ObservedCount:      2,
		Confidence:         0.94,
		ObservedEventIDs:   []string{"agent-runtime-filter-target-ref-1"},
		EvidenceRef:        "agent-runtime-access://agent-runtime-filter-target-ref",
		BackingRoleARNs:    []string{"arn:aws:iam::123456789012:role/agent-runtime"},
		BackingRoleNodeIDs: []string{"aws:identity:arn:aws:iam::123456789012:role/agent-runtime"},
		LastObservedAt:     now,
	}, now)
	matches := awsLeastPrivilegeToolMatchValues(recommendation)
	if !awsRuntimeEventMatchesAny("case-router", matches...) {
		t.Fatalf("expected recommendation tool candidates to include tool name: %+v", matches)
	}
	if !awsRuntimeEventMatchesAny("api://tickets/search", matches...) {
		t.Fatalf("expected recommendation tool candidates to include tool target ref: %+v", matches)
	}
}

func TestAWSLeastPrivilegeRecommendationFromAgentRecordsDoNotLeakAgentIdentifiersInToolFilterWhenToolAvailable(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 35, 0, 0, time.UTC)
	recommendation := awsLeastPrivilegeRecommendationFromAgent(AWSAgentRuntimeAccessRecord{
		CorrelationID:      "agent-runtime-filter-no-leak",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		AgentNodeID:        "agent-runtime-node",
		AgentID:            "agent-runtime-id",
		ToolName:           "case-router",
		ToolTargetRef:      "api://tickets/search",
		Status:             "declared-unused",
		ObservedCount:      2,
		Confidence:         0.94,
		ObservedEventIDs:   []string{"agent-runtime-filter-no-leak-1"},
		EvidenceRef:        "agent-runtime-access://agent-runtime-filter-no-leak",
		BackingRoleARNs:    []string{"arn:aws:iam::123456789012:role/agent-runtime"},
		BackingRoleNodeIDs: []string{"aws:identity:arn:aws:iam::123456789012:role/agent-runtime"},
		LastObservedAt:     now,
	}, now)
	matches := awsLeastPrivilegeToolMatchValues(recommendation)
	if awsRuntimeEventMatchesAny("agent-runtime-id", matches...) {
		t.Fatalf("tool matching should not leak agent identifier when tool is present: %+v", matches)
	}
	if awsRuntimeEventMatchesAny("agent-runtime-node", matches...) {
		t.Fatalf("tool matching should not leak agent node identifier when tool is present: %+v", matches)
	}
}

func TestAWSLeastPrivilegeRecommendationFromAgentRecordsFallbackToAgentIdentifiersWhenNoToolIsPresent(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 40, 0, 0, time.UTC)
	recommendation := awsLeastPrivilegeRecommendationFromAgent(AWSAgentRuntimeAccessRecord{
		CorrelationID:      "agent-runtime-filter-fallback",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		AgentNodeID:        "agent-runtime-node",
		AgentID:            "agent-runtime-id",
		Status:             "declared-unused",
		ObservedCount:      0,
		Confidence:         0.94,
		ObservedEventIDs:   []string{"agent-runtime-filter-fallback-1"},
		EvidenceRef:        "agent-runtime-access://agent-runtime-filter-fallback",
		BackingRoleARNs:    []string{"arn:aws:iam::123456789012:role/agent-runtime"},
		BackingRoleNodeIDs: []string{"aws:identity:arn:aws:iam::123456789012:role/agent-runtime"},
		LastObservedAt:     now,
	}, now)
	matches := awsLeastPrivilegeToolMatchValues(recommendation)
	if !awsRuntimeEventMatchesAny("agent-runtime-id", matches...) {
		t.Fatalf("expected fallback agent identifier in tool candidates: %+v", matches)
	}
	if !awsRuntimeEventMatchesAny("agent-runtime-node", matches...) {
		t.Fatalf("expected fallback agent node identifier in tool candidates: %+v", matches)
	}
}

func TestAWSLeastPrivilegeRecommendationFromRuntimeSignalKeepsAccessAnalyzerInReview(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 20, 0, 0, time.UTC)
	record := AWSRuntimeEventRecord{
		EventID:             "evt-access-analyzer-secret",
		AccountID:           "111111111111",
		Region:              "us-east-1",
		EventType:           "access-analyzer",
		EventSource:         "access-analyzer.amazonaws.com",
		EventName:           "Finding",
		Action:              "secretsmanager:GetSecretValue",
		ActorPrincipalARN:   "access-analyzer:external-principal",
		ActorIdentityNodeID: "aws:identity:external-principal",
		TargetResourceARN:   "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/ai/openai-key",
		TargetResourceType:  "AWS::SecretsManager::Secret",
		TargetResourceName:  "prod/ai/openai-key",
		ResourceNodeID:      "aws:runtime-resource:secret:prod-ai-openai-key",
		SignalCategory:      "access-analyzer",
		EvidenceRef:         "runtime-evidence://access-analyzer",
		Confidence:          0.91,
		ObservedAt:          now.Add(-time.Hour),
		Status:              "observed",
	}

	recommendation, ok := awsLeastPrivilegeRecommendationFromRuntimeSignal(record, now)
	if !ok {
		t.Fatal("expected Access Analyzer signal to produce a review recommendation")
	}
	if recommendation.Decision != "review" || recommendation.BreakagePrediction != "unknown" || len(recommendation.RemoveActions) != 0 {
		t.Fatalf("Access Analyzer must not become deterministic removal: %+v", recommendation)
	}
	if !strings.Contains(recommendation.NextAction, "analyzer scope") {
		t.Fatalf("expected analyzer-scope next action, got %q", recommendation.NextAction)
	}
}

func TestAWSLeastPrivilegeRecommendationFromRuntimeSignalDowngradesLowConfidenceIAMToReview(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 25, 0, 0, time.UTC)
	record := AWSRuntimeEventRecord{
		EventID:             "evt-iam-last-used-low-confidence",
		AccountID:           "111111111111",
		Region:              "us-east-1",
		EventType:           "iam-last-used",
		EventSource:         "iam.amazonaws.com",
		EventName:           "ServiceLastAccessed",
		Action:              "lambda:LastAuthenticated",
		ActorPrincipalARN:   "arn:aws:iam::111111111111:role/lambda-invoice-agent",
		ActorIdentityNodeID: "aws:identity:role:lambda-invoice-agent",
		TargetResourceName:  "Lambda",
		ResourceNodeID:      "aws-service://lambda",
		SignalCategory:      "iam-last-used",
		EvidenceRef:         "runtime-evidence://iam-low-confidence",
		Confidence:          0.62,
		ObservedAt:          now.Add(-120 * 24 * time.Hour),
		Status:              "stale",
	}

	recommendation, ok := awsLeastPrivilegeRecommendationFromRuntimeSignal(record, now)
	if !ok {
		t.Fatal("expected IAM last-used signal to produce a recommendation")
	}
	if recommendation.Decision != "review" || recommendation.BreakagePrediction != "unknown" || len(recommendation.RemoveActions) != 0 {
		t.Fatalf("low-confidence IAM last-used must stay in review without remove actions: %+v", recommendation)
	}
	if len(recommendation.KeepActions) == 0 || recommendation.RemediationCase.RecommendedAction == "Create a read-only case to remove unused grants after owner approval." {
		t.Fatalf("expected review-oriented action metadata, got %+v", recommendation)
	}
}

func TestAWSLeastPrivilegeRecommendationFromRuntimeSignalSkipsAccessKeyLastUsed(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 26, 0, 0, time.UTC)
	accessKeyID := "AKIA" + "ORDERS123456"
	record := AWSRuntimeEventRecord{
		EventID:             "evt-iam-last-used-access-key",
		AccountID:           "111111111111",
		Region:              "us-east-1",
		EventType:           "iam-last-used",
		EventSource:         "iam.amazonaws.com",
		EventName:           "AccessKeyLastUsed",
		Action:              "iam:AccessKeyLastUsed",
		ActorPrincipalARN:   "arn:aws:iam::111111111111:user/orders-ci",
		ActorIdentityNodeID: "aws:identity:user/orders-ci",
		TargetResourceName:  accessKeyID,
		TargetResourceType:  "iam_access_key",
		ResourceNodeID:      "aws:iam-access-key:" + accessKeyID,
		SignalCategory:      "iam-last-used",
		EvidenceRef:         "runtime-evidence://access-key/" + accessKeyID,
		Confidence:          0.86,
		ObservedAt:          now.Add(-120 * 24 * time.Hour),
		Status:              "stale",
		SignalScope:         "access-key",
	}

	if recommendation, ok := awsLeastPrivilegeRecommendationFromRuntimeSignal(record, now); ok {
		t.Fatalf("access-key last-used signals must stay out of service-action diffs: %+v", recommendation)
	}
}

func TestGetAWSLeastPrivilegePermissionDeniedAndEmptyStatesAreExplicit(t *testing.T) {
	now := time.Date(2026, 6, 20, 8, 30, 0, 0, time.UTC)
	svc, ws := newLeastPrivilegeService(t, "project-least-privilege-states", now)

	denied, err := svc.GetAWSLeastPrivilegeRecommendations(defaultScopeContext(), ws, "project-least-privilege-states", AWSLeastPrivilegeRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || denied.Confidence != 0 || len(denied.Recommendations) != 0 {
		t.Fatalf("expected blocked permission-denied state, got %+v", denied)
	}
	if len(denied.Diagnostics) == 0 || len(denied.CoverageGaps) == 0 {
		t.Fatalf("expected diagnostics and coverage gaps for denied state")
	}

	empty, err := svc.GetAWSLeastPrivilegeRecommendations(defaultScopeContext(), ws, "project-least-privilege-states", AWSLeastPrivilegeRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Recommendations) != 0 || empty.Summary.TotalRecommendations != 0 {
		t.Fatalf("expected degraded empty state, got %+v", empty)
	}
}

func TestNormalizeAWSLeastPrivilegeFixtureState(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSLeastPrivilegeFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected denied for disconnected default, got %q", got)
	}
	if got := normalizeAWSLeastPrivilegeFixtureState("PARTIAL_FAILURE", AWSConnectionStatus{}, false); got != "partial_failure" {
		t.Fatalf("expected normalized partial failure, got %q", got)
	}
	if got := normalizeAWSLeastPrivilegeFixtureState("invalid", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected invalid fixture state to return empty token, got %q", got)
	}
}
