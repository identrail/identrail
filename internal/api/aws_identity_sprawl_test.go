package api

import (
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
)

func newIdentitySprawlService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func newIdentitySprawlServiceWithoutConnector(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, project)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	return svc, "default"
}

func sprawlFindingTypeSet(findings []AWSIdentitySprawlFinding) map[string]bool {
	out := map[string]bool{}
	for _, finding := range findings {
		out[finding.FindingType] = true
	}
	return out
}

func TestGetAWSIdentitySprawlBuildsFindingContract(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl", now)

	result, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get identity sprawl: %v", err)
	}
	if result.CurrentIssueRef != "#1524" || result.Version != awsIdentitySprawlVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.Status != "ready" && result.Status != "degraded" {
		t.Fatalf("expected ready or degraded status, got %q", result.Status)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected at least one finding, got %+v", result.Summary)
	}
	if result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("summary total mismatch: summary=%d findings=%d", result.Summary.TotalFindings, len(result.Findings))
	}
	if result.Summary.UniqueIdentityCount == 0 || result.Summary.UniqueWorkloadCount == 0 {
		t.Fatalf("expected unique identity/workload counts: %+v", result.Summary)
	}
	if result.Summary.HighestScore <= 0 || result.Summary.AverageConfidencePct <= 0 {
		t.Fatalf("expected non-zero score/confidence aggregates: %+v", result.Summary)
	}
	// Findings must be sorted by descending score.
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Score < result.Findings[i].Score {
			t.Fatalf("findings not sorted by descending score at %d: %+v", i, result.Findings)
		}
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsIdentitySprawlVersion {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.IdentityNodeID == "" || finding.DisplayName == "" || finding.Rationale == "" {
			t.Fatalf("finding missing required fields: %+v", finding)
		}
		if finding.OwnerSource == "" {
			t.Fatalf("finding missing owner_source: %+v", finding)
		}
		if len(finding.ImpactedPath) < 1 || finding.ImpactedPath[0].NodeType != "identity" {
			t.Fatalf("finding impacted_path must start at identity: %+v", finding)
		}
		if len(finding.Evidence) == 0 {
			t.Fatalf("finding missing evidence: %+v", finding)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("relationship count mismatch: %d vs %d", result.Summary.RelationshipCount, len(result.Relationships))
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: caveats=%v gaps=%v", result.Caveats, result.CoverageGaps)
	}
}

func TestGetAWSIdentitySprawlSurfacesStaleAndStructuralFindings(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl-types", now)

	result, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-types", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get identity sprawl: %v", err)
	}
	types := sprawlFindingTypeSet(result.Findings)
	// Stale is guaranteed by the upstream fixtures: at least one IAM role is
	// attached to a workload but has no observed runtime correlation.
	if !types["stale_identity"] {
		t.Fatalf("expected at least one stale_identity finding, got types=%+v findings=%+v", types, result.Findings)
	}
	// Cluster aggregation must stay internally consistent: if the summary
	// reports duplicate clusters, the engine must emit matching findings.
	if result.Summary.DuplicateClusterCount > 0 && !types["duplicate_identity"] {
		t.Fatalf("duplicate clusters present but no duplicate findings: %+v", result)
	}
	if result.Summary.SharedRoleCount > 0 && !types["shared_role"] {
		t.Fatalf("shared role count > 0 but no shared findings: %+v", result)
	}
	if result.Summary.OwnerlessIdentityCount > 0 && !types["ownerless_identity"] {
		t.Fatalf("ownerless count > 0 but no ownerless findings: %+v", result)
	}
}

func TestGetAWSIdentitySprawlOwnerlessDetectorAndFilters(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl-filters", now)

	staleOnly, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-filters", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		FindingType:  "stale_identity",
	})
	if err != nil {
		t.Fatalf("get stale findings: %v", err)
	}
	if len(staleOnly.Findings) == 0 {
		t.Fatalf("expected at least one stale finding for filter check")
	}
	for _, finding := range staleOnly.Findings {
		if finding.FindingType != "stale_identity" {
			t.Fatalf("finding_type filter leaked: %+v", finding)
		}
	}
	if staleOnly.AppliedFilters["finding_type"] != "stale-identity" {
		t.Fatalf("expected normalized finding_type filter, got %+v", staleOnly.AppliedFilters)
	}

	// owner=none returns only ownerless findings — when none exist the
	// filter must return an empty (but still well-formed) result.
	noneSentinel, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-filters", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Owner:        "none",
	})
	if err != nil {
		t.Fatalf("get owner=none: %v", err)
	}
	for _, finding := range noneSentinel.Findings {
		if finding.OwnerSource != "no_owner_tag" {
			t.Fatalf("owner=none must only return ownerless findings: %+v", finding)
		}
	}
	if len(noneSentinel.Findings) == 0 && noneSentinel.Status != "ready" {
		t.Fatalf("healthy empty filtered result must stay ready, got %q with diagnostics=%+v", noneSentinel.Status, noneSentinel.Diagnostics)
	}

	// Owner detector unit-tests: confirms the engine produces an ownerless
	// finding when an aggregate has no owner tag, independent of the seed
	// fixtures (which tag every role).
	tagless := map[string]*identitySprawlAggregate{
		"arn:aws:iam::123456789012:role/untagged-role": {
			roleARN:         "arn:aws:iam::123456789012:role/untagged-role",
			roleName:        "untagged-role",
			accountID:       "123456789012",
			region:          "us-east-1",
			workloadNodeIDs: map[string]struct{}{"wl-1": {}},
			workloadTypes:   map[string]struct{}{"lambda_function": {}},
			workloadLabels:  map[string]struct{}{"orphan": {}},
			tagKeys:         map[string]struct{}{},
			evidenceRefs:    map[string]struct{}{"runtime-evidence://orphan": {}},
		},
	}
	findings, _ := awsIdentitySprawlFindingsAndClusters(tagless, now)
	foundOwnerless := false
	for _, finding := range findings {
		if finding.FindingType == "ownerless_identity" {
			foundOwnerless = true
			if finding.OwnerSource != "no_owner_tag" || finding.OwnerLabel != "" {
				t.Fatalf("ownerless finding must have no_owner_tag source and empty owner: %+v", finding)
			}
		}
	}
	if !foundOwnerless {
		t.Fatalf("synthetic tagless aggregate must produce ownerless_identity: %+v", findings)
	}
}

func TestGetAWSIdentitySprawlSeverityFilter(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl-severity", now)

	severity, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-severity", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "medium",
	})
	if err != nil {
		t.Fatalf("get severity=medium: %v", err)
	}
	for _, finding := range severity.Findings {
		if !strings.EqualFold(finding.Severity, "medium") {
			t.Fatalf("severity filter leaked: %+v", finding)
		}
	}
	if severity.AppliedFilters["severity"] != "medium" {
		t.Fatalf("expected applied severity filter, got %+v", severity.AppliedFilters)
	}
}

func TestGetAWSIdentitySprawlPermissionDeniedFixtureState(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl-denied", now)

	denied, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-denied", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("get permission_denied: %v", err)
	}
	if denied.Status != "blocked" && denied.Status != "degraded" {
		t.Fatalf("expected blocked or degraded status, got %q", denied.Status)
	}
	if denied.Status == "blocked" && denied.Confidence != 0 {
		t.Fatalf("expected zero confidence on blocked status, got %v", denied.Confidence)
	}
	// Blocked or degraded sources must not have masked findings without explicit diagnostics.
	if len(denied.Diagnostics) == 0 && len(denied.Findings) > 0 {
		t.Fatalf("permission_denied must surface diagnostics or no findings: diagnostics=%v findings=%d", denied.Diagnostics, len(denied.Findings))
	}
}

func TestGetAWSIdentitySprawlEmptyAndDegradedFixtureStates(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl-states", now)
	noConnectorSvc, noConnectorWS := newIdentitySprawlServiceWithoutConnector(t, "project-identity-sprawl-no-connector", now)

	fixtureWithoutConnector, err := noConnectorSvc.GetAWSIdentitySprawl(defaultScopeContext(), noConnectorWS, "project-identity-sprawl-no-connector", AWSIdentitySprawlRequest{
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get fixture without connector: %v", err)
	}
	if fixtureWithoutConnector.ConnectorID == "aws-fixture" {
		t.Fatalf("fixture call without connector_id must not use synthetic connector id: %+v", fixtureWithoutConnector)
	}
	if len(fixtureWithoutConnector.Findings) == 0 {
		t.Fatalf("fixture call without connector_id should still use internal fixture rows: %+v", fixtureWithoutConnector)
	}
	for _, diagnostic := range fixtureWithoutConnector.Diagnostics {
		if diagnostic.Code == "permission_denied" {
			t.Fatalf("explicit success fixture without connector must not degrade runtime sources: diagnostics=%+v", fixtureWithoutConnector.Diagnostics)
		}
	}

	defaultWithoutConnector, err := noConnectorSvc.GetAWSIdentitySprawl(defaultScopeContext(), noConnectorWS, "project-identity-sprawl-no-connector", AWSIdentitySprawlRequest{})
	if err != nil {
		t.Fatalf("get default without connector: %v", err)
	}
	if defaultWithoutConnector.FixtureState != "permission_denied" || len(defaultWithoutConnector.Findings) != 0 {
		t.Fatalf("default call without connector must not use success fixture rows: %+v", defaultWithoutConnector)
	}

	empty, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-states", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("get empty: %v", err)
	}
	if empty.Status == "" {
		t.Fatalf("empty fixture must surface a status: %+v", empty)
	}
	if empty.Summary.TotalFindings != len(empty.Findings) {
		t.Fatalf("summary total mismatch on empty: %+v", empty.Summary)
	}

	degraded, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-states", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get degraded: %v", err)
	}
	// Degraded sources must downgrade the envelope.
	if degraded.Status == "ready" && len(degraded.Diagnostics) == 0 {
		t.Fatalf("degraded fixture must report degraded status or diagnostics: %+v", degraded)
	}
	foundInventoryDiagnostic := false
	for _, diagnostic := range degraded.Diagnostics {
		if strings.HasPrefix(diagnostic.Collector, "aws_ec2/") || strings.HasPrefix(diagnostic.Collector, "aws_lambda/") || strings.HasPrefix(diagnostic.Collector, "aws_ecs/") {
			foundInventoryDiagnostic = true
			break
		}
	}
	if !foundInventoryDiagnostic {
		t.Fatalf("degraded fixture must forward inventory diagnostics: %+v", degraded.Diagnostics)
	}
}

func TestGetAWSIdentitySprawlLiveModeSuppressesFixtureInventories(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl-live", now)

	result, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-live", AWSIdentitySprawlRequest{
		ConnectorID: "aws-prod",
	})
	if err != nil {
		t.Fatalf("get live identity sprawl: %v", err)
	}
	if result.FixtureState != "" {
		t.Fatalf("live identity sprawl response must not expose fixture_state, got %q", result.FixtureState)
	}
	if len(result.Findings) != 0 || result.Summary.TotalFindings != 0 {
		t.Fatalf("live identity sprawl must not surface deterministic fixture findings: findings=%+v summary=%+v", result.Findings, result.Summary)
	}
	if result.Status != "degraded" {
		t.Fatalf("live identity sprawl without inventory must be degraded, got %q", result.Status)
	}
	foundDiagnostic := false
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "identity_inventory_live_unavailable" {
			foundDiagnostic = true
			break
		}
	}
	if !foundDiagnostic || len(result.CoverageGaps) == 0 {
		t.Fatalf("live identity sprawl must explain unavailable inventory: diagnostics=%+v gaps=%+v", result.Diagnostics, result.CoverageGaps)
	}
}

func TestGetAWSIdentitySprawlUsesNormalizedWorkloadNodeIDs(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	svc, ws := newIdentitySprawlService(t, "project-identity-sprawl-nodeids", now)

	result, err := svc.GetAWSIdentitySprawl(defaultScopeContext(), ws, "project-identity-sprawl-nodeids", AWSIdentitySprawlRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get identity sprawl: %v", err)
	}

	foundWorkloadNode := false
	for _, finding := range result.Findings {
		for _, nodeID := range finding.WorkloadNodeIDs {
			foundWorkloadNode = true
			if !strings.HasPrefix(nodeID, "aws:workload:") {
				t.Fatalf("expected normalized workload graph node id, got %q", nodeID)
			}
		}
	}
	if !foundWorkloadNode {
		t.Fatalf("expected findings to include workload node ids: %+v", result.Findings)
	}
}

func TestAWSIdentitySprawlRelationshipsFanOutFromIdentity(t *testing.T) {
	relationships := awsIdentitySprawlRelationships([]AWSIdentitySprawlFinding{{
		FindingID:      "finding-1",
		IdentityNodeID: "aws:identity:arn:aws:iam::123456789012:role/example",
		ImpactedPath: []AWSIdentitySprawlPathStep{
			{NodeID: "aws:identity:arn:aws:iam::123456789012:role/example", NodeType: "identity"},
			{NodeID: "aws:workload:lambda-function:fn-1", NodeType: "workload"},
			{NodeID: "aws:workload:ecs-service:svc-1", NodeType: "workload"},
		},
		Evidence: []AWSIdentitySprawlEvidence{{EvidenceRef: "evidence://identity-sprawl"}},
	}})

	if len(relationships) != 2 {
		t.Fatalf("expected two attachment relationships, got %+v", relationships)
	}
	for _, relationship := range relationships {
		if relationship.Type != "identity_sprawl_attachment" {
			t.Fatalf("expected attachment relationship, got %+v", relationship)
		}
		if relationship.FromNodeID != "aws:identity:arn:aws:iam::123456789012:role/example" {
			t.Fatalf("expected identity fan-out source, got %+v", relationship)
		}
		if relationship.ToNodeID == "aws:identity:arn:aws:iam::123456789012:role/example" {
			t.Fatalf("expected workload target, got %+v", relationship)
		}
	}
	if relationships[0].ToNodeID == relationships[1].ToNodeID {
		t.Fatalf("expected distinct workload targets, got %+v", relationships)
	}
}

func TestIdentitySprawlOwnerFromTagsCoversCommonKeys(t *testing.T) {
	cases := []struct {
		tags      map[string]string
		wantOwner string
	}{
		{map[string]string{"owner": "platform"}, "platform"},
		{map[string]string{"team": "billing"}, "billing"},
		{map[string]string{"service": "payments"}, "payments"},
		{map[string]string{"Owner": "Mixed"}, "Mixed"},
		{map[string]string{"identrail:owner": "rt-ai"}, "rt-ai"},
		{map[string]string{"environment": "prod"}, ""},
		{nil, ""},
	}
	for _, tc := range cases {
		owner, _ := identitySprawlOwnerFromTags(tc.tags)
		if owner != tc.wantOwner {
			t.Fatalf("identitySprawlOwnerFromTags(%v)=%q want %q", tc.tags, owner, tc.wantOwner)
		}
	}
}

func TestIdentitySprawlSignatureGroupsRelatedRoleNamesByWorkloadSurface(t *testing.T) {
	a := &identitySprawlAggregate{
		roleName:      "payments-lambda-execution",
		workloadTypes: map[string]struct{}{"lambda_function": {}},
	}
	b := &identitySprawlAggregate{
		roleName:      "payments-lambda-runtime",
		workloadTypes: map[string]struct{}{"lambda_function": {}},
	}
	c := &identitySprawlAggregate{
		roleName:      "image-resizer-lambda-execution",
		workloadTypes: map[string]struct{}{"lambda_function": {}},
	}
	d := &identitySprawlAggregate{
		roleName:      "payments-lambda-execution",
		workloadTypes: map[string]struct{}{"ecs_task": {}},
	}
	if awsIdentitySprawlSignature(a) != awsIdentitySprawlSignature(b) {
		t.Fatalf("same workload-types + name-fragment must share a signature: %q vs %q", awsIdentitySprawlSignature(a), awsIdentitySprawlSignature(b))
	}
	if awsIdentitySprawlSignature(a) == awsIdentitySprawlSignature(c) {
		t.Fatalf("distinct name fragments must not collide: %q", awsIdentitySprawlSignature(a))
	}
	if awsIdentitySprawlSignature(a) == awsIdentitySprawlSignature(d) {
		t.Fatalf("different workload-type sets must not collide: %q", awsIdentitySprawlSignature(a))
	}
}

func TestIdentitySprawlNameFragmentStripsCommonSuffixes(t *testing.T) {
	cases := map[string]string{
		"payments-lambda-execution": "payments",
		"payments-lambda-runtime":   "payments",
		"payments-ecs-task":         "payments",
		"image-resizer-lambda-prod": "image",
		"adhoc-operator-role":       "adhoc",
		"":                          "",
	}
	for input, want := range cases {
		got := awsIdentitySprawlNameFragment(input)
		if got != want {
			t.Fatalf("awsIdentitySprawlNameFragment(%q)=%q want %q", input, got, want)
		}
	}
}
