package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/runtime/cloudtrail"
)

// grantRuntimeEvidenceCapability extends a seeded connector's
// effective capability set with runtime_evidence so the live
// CloudTrail path in GetAWSRuntimeEvents is reachable in unit tests.
// The default seed only grants discovery; runtime_evidence is the
// operator-declared boundary this PR honors before assuming a role
// and calling cloudtrail:LookupEvents.
func grantRuntimeEvidenceCapability(t *testing.T, store db.Store, ctx context.Context, projectID string, connectorID string) {
	t.Helper()
	stored, err := store.GetTenancyConnector(ctx, "default", projectID, connectorID)
	if err != nil {
		t.Fatalf("load connector for capability grant: %v", err)
	}
	caps := AWSConnectorCapabilities{
		Requested:   []domain.ConnectorCapability{domain.ConnectorCapabilityDiscovery, domain.ConnectorCapabilityRuntimeEvidence},
		Validated:   []domain.ConnectorCapability{domain.ConnectorCapabilityDiscovery, domain.ConnectorCapabilityRuntimeEvidence},
		Effective:   []domain.ConnectorCapability{domain.ConnectorCapabilityDiscovery, domain.ConnectorCapabilityRuntimeEvidence},
		Unavailable: []AWSConnectorCapabilityUnavailable{},
	}
	if stored.State.Metadata == nil {
		stored.State.Metadata = map[string]any{}
	}
	stored.State.Metadata["capabilities"] = caps
	if err := store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
		t.Fatalf("upsert connector capability grant: %v", err)
	}
}

type fakeCloudTrailIngester struct {
	calls  []AWSCloudTrailIngestRequest
	result AWSCloudTrailIngestResult
	err    error
}

func (f *fakeCloudTrailIngester) Ingest(_ context.Context, request AWSCloudTrailIngestRequest) (AWSCloudTrailIngestResult, error) {
	f.calls = append(f.calls, request)
	return f.result, f.err
}

type fakeRuntimeSignalIngester struct {
	calls  []AWSRuntimeSignalIngestRequest
	result AWSRuntimeSignalIngestResult
	err    error
}

func (f *fakeRuntimeSignalIngester) Ingest(_ context.Context, request AWSRuntimeSignalIngestRequest) (AWSRuntimeSignalIngestResult, error) {
	f.calls = append(f.calls, request)
	return f.result, f.err
}

func liveRuntimeRecord(t *testing.T, id string, eventType string, name string, source string, action string, owner string, evidence string, actorARN string, resourceARN string, resourceType string, observed time.Time) AWSRuntimeEventRecord {
	t.Helper()
	return AWSRuntimeEventRecord{
		EventID:             id,
		AccountID:           "123456789012",
		Region:              "us-east-1",
		EventType:           eventType,
		EventSource:         source,
		EventName:           name,
		Action:              action,
		ActorPrincipalARN:   actorARN,
		ActorPrincipalType:  "assumed_role",
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(actorARN),
		Session: AWSRuntimeEventSession{
			SessionID:    "ASIAEXAMPLESESSION",
			PrincipalARN: actorARN,
			StartedAt:    observed.Add(-5 * time.Minute),
		},
		TargetResourceARN:  resourceARN,
		TargetResourceType: resourceType,
		TargetResourceName: displayNameFromARN(resourceARN),
		ResourceNodeID:     awsRuntimeEventResourceNodeID(resourceARN, resourceType),
		Owner:              owner,
		EvidenceCategory:   evidence,
		EvidenceRef:        "runtime-evidence://123456789012/us-east-1/" + id,
		Confidence:         0.9,
		ObservedAt:         observed,
		CollectedAt:        observed.Add(2 * time.Minute),
		Status:             "observed",
		NextAction:         awsRuntimeEventNextAction(eventType),
		RedactionBoundary:  "metadata_only_no_payloads_no_secret_values",
	}
}

func liveSignalRuntimeRecord(t *testing.T, id string, eventType string, actorARN string, resourceARN string, observed time.Time) AWSRuntimeEventRecord {
	t.Helper()
	record := liveRuntimeRecord(t, id, eventType, "Finding", "access-analyzer.amazonaws.com", "secretsmanager:GetSecretValue", "security", eventType, actorARN, resourceARN, "AWS::SecretsManager::Secret", observed)
	record.SignalCategory = eventType
	record.SignalScope = "account"
	record.AnalyzerARN = "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account"
	record.SignalStaleAt = observed
	record.Session = AWSRuntimeEventSession{
		PrincipalARN:  actorARN,
		PrincipalType: "external_principal",
	}
	return record
}

func TestGetAWSRuntimeEventsUsesLiveCloudTrailWhenFactoryReturnsIngester(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 19, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-live")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-live", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-live", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess-runtime-reader"
	fake := &fakeCloudTrailIngester{
		result: AWSCloudTrailIngestResult{
			Status: "ready",
			Records: []AWSRuntimeEventRecord{
				liveRuntimeRecord(t, "evt-live-secret", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "cloudtrail", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", "AWS::SecretsManager::Secret", now.Add(-10*time.Minute)),
				liveRuntimeRecord(t, "evt-live-kms", "kms-decrypt", "Decrypt", "kms.amazonaws.com", "kms:Decrypt", "platform", "cloudtrail", role, "arn:aws:kms:us-east-1:123456789012:key/abcd-ef", "AWS::KMS::Key", now.Add(-5*time.Minute)),
			},
		},
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, connection AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		if connection.ConnectorID != "aws-prod" {
			t.Fatalf("factory invoked for wrong connector: %+v", connection)
		}
		return fake, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-live", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "ready" {
		t.Fatalf("expected live ready status, got %+v", result)
	}
	if len(fake.calls) != 1 || fake.calls[0].AccountID != "123456789012" {
		t.Fatalf("expected one ingestion call scoped to the connector account, got %+v", fake.calls)
	}
	if result.Summary.TotalEvents != 2 || result.Summary.SecretReadCount != 1 || result.Summary.KMSDecryptCount != 1 {
		t.Fatalf("expected live records to drive summary, got %+v", result.Summary)
	}
	if result.FixtureState != "success" {
		t.Fatalf("expected live ready run to report fixture_state=success, got %q", result.FixtureState)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 live records in response, got %+v", result.Records)
	}
	for _, record := range result.Records {
		if record.RedactionBoundary != "metadata_only_no_payloads_no_secret_values" {
			t.Fatalf("live record leaked unsafe redaction boundary: %+v", record)
		}
	}
}

func TestRuntimeEventRecordFromNormalizedCarriesSTSLineage(t *testing.T) {
	now := time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC)
	caller := "arn:aws:sts::123456789012:assumed-role/ci-deploy/deploy-session"
	targetRole := "arn:aws:iam::123456789012:role/payments-runtime"
	record := runtimeEventRecordFromNormalized(cloudtrail.NormalizedEvent{
		EventID:            "evt-assume-payments",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		EventType:          "sts-session",
		EventSource:        "sts.amazonaws.com",
		EventName:          "AssumeRole",
		Action:             "sts:AssumeRole",
		ActorPrincipalARN:  caller,
		ActorPrincipalType: "assumed_role",
		SessionID:          "AROAEXAMPLE:deploy-session",
		AssumedRoleARN:     targetRole,
		SessionIssuerARN:   "arn:aws:iam::123456789012:role/ci-deploy",
		SourceIdentity:     "github-actions:deploy",
		RoleSessionName:    "payments-job-42",
		SessionTagKeys:     []string{"environment", "owner"},
		TransitiveTagKeys:  []string{"owner"},
		OriginalActorARN:   caller,
		ChainedFromARN:     caller,
		LineageStatus:      "resolved",
		LineageReason:      "CloudTrail SourceIdentity and session issuer metadata resolved this STS lineage.",
		TargetResourceARN:  targetRole,
		TargetResourceType: "iam_role",
		TargetResourceName: "payments-runtime",
		Owner:              "security",
		EvidenceCategory:   "cloudtrail",
		Confidence:         0.9,
		ObservedAt:         now.Add(-time.Minute),
		CollectedAt:        now,
		Status:             "observed",
		RedactionBoundary:  "metadata_only_no_payloads_no_secret_values",
	}, "123456789012", "us-east-1")

	if record.Session.SessionNodeID == "" || !strings.Contains(record.Session.SessionNodeID, "runtime-session") {
		t.Fatalf("expected session node id, got %+v", record.Session)
	}
	wantTargetSessionNodeID := "aws:runtime-session:" + sanitizeCredentialReferenceToken("123456789012") + ":" + sanitizeCredentialReferenceToken("us-east-1") + ":" + sanitizeCredentialReferenceToken(targetRole+"/payments-job-42")
	if record.Session.SessionNodeID != wantTargetSessionNodeID {
		t.Fatalf("expected AssumeRole event to key the target session node %q, got %q", wantTargetSessionNodeID, record.Session.SessionNodeID)
	}
	targetActivity := runtimeEventRecordFromNormalized(cloudtrail.NormalizedEvent{
		EventID:            "evt-payments-secret",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		EventType:          "secret-read",
		EventSource:        "secretsmanager.amazonaws.com",
		EventName:          "GetSecretValue",
		Action:             "secretsmanager:GetSecretValue",
		ActorPrincipalARN:  "arn:aws:sts::123456789012:assumed-role/payments-runtime/payments-job-42",
		ActorPrincipalType: "assumed_role",
		SessionID:          "AROAEXAMPLE:payments-job-42",
		AssumedRoleARN:     targetRole,
		SessionIssuerARN:   targetRole,
		RoleSessionName:    "payments-job-42",
		LineageStatus:      "source_identity_missing",
		TargetResourceARN:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/payments",
		TargetResourceType: "AWS::SecretsManager::Secret",
		Owner:              "application",
		EvidenceCategory:   "cloudtrail",
		Confidence:         0.9,
		ObservedAt:         now.Add(time.Minute),
		CollectedAt:        now,
		Status:             "observed",
		RedactionBoundary:  "metadata_only_no_payloads_no_secret_values",
	}, "123456789012", "us-east-1")
	if targetActivity.Session.SessionNodeID != record.Session.SessionNodeID {
		t.Fatalf("expected target session activity to join AssumeRole session node %q, got %q", record.Session.SessionNodeID, targetActivity.Session.SessionNodeID)
	}
	if record.Session.SourceIdentity != "github-actions:deploy" || record.Session.RoleSessionName != "payments-job-42" {
		t.Fatalf("expected source identity and role session name, got %+v", record.Session)
	}
	if record.Session.LineageStatus != "resolved" || record.Session.OriginalActorNodeID == "" || record.Session.ChainedFromNodeID == "" {
		t.Fatalf("expected resolved original/chained lineage nodes, got %+v", record.Session)
	}
	if got := strings.Join(record.Session.SessionTagKeys, ","); got != "environment,owner" {
		t.Fatalf("expected session tag keys to pass through, got %q", got)
	}
	relationships := awsRuntimeEventRelationships([]AWSRuntimeEventRecord{record})
	wantTypes := map[string]bool{
		"observed_runtime_action":          false,
		"has_runtime_session":              false,
		"runtime_session_performed_action": false,
		"role_chained_into_session":        false,
	}
	for _, rel := range relationships {
		if _, ok := wantTypes[rel.Type]; ok {
			wantTypes[rel.Type] = true
		}
	}
	for relType, found := range wantTypes {
		if !found {
			t.Fatalf("expected relationship %s in %+v", relType, relationships)
		}
	}
	summary := summarizeAWSRuntimeEvents([]AWSRuntimeEventRecord{record}, 1, len(relationships))
	if summary.LineageResolvedCount != 1 || summary.MissingSourceIDCount != 0 || summary.AmbiguousLineageCount != 0 {
		t.Fatalf("expected lineage summary counts, got %+v", summary)
	}
}

func TestGetAWSRuntimeEventsCapabilityGatedConnectorDoesNotCallFactory(t *testing.T) {
	// A connector with the default discovery-only capability set must
	// not enter the live CloudTrail path even when a factory is wired
	// and the connector is otherwise active and healthy: the
	// operator-declared capability boundary is the single gate that
	// permits assuming the role and calling cloudtrail:LookupEvents.
	// The response stays fixture-shaped but carries the
	// runtime_evidence_capability_unavailable diagnostic + coverage
	// gap so operators see why live ingestion was skipped.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 19, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-no-runtime-evidence")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-no-runtime-evidence", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	called := false
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		called = true
		return &fakeCloudTrailIngester{}, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-no-runtime-evidence", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if called {
		t.Fatalf("discovery-only connector must not trigger the CloudTrail factory")
	}
	foundDiag := false
	for _, diag := range result.Diagnostics {
		if diag.Code == "runtime_evidence_capability_unavailable" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected runtime_evidence_capability_unavailable diagnostic, got %+v", result.Diagnostics)
	}
	foundGap := false
	for _, gap := range result.CoverageGaps {
		if gap.Status == "capability_unavailable" {
			foundGap = true
		}
	}
	if !foundGap {
		t.Fatalf("expected capability_unavailable coverage gap, got %+v", result.CoverageGaps)
	}
	// The fixture path classified the synthetic records as ready
	// with high confidence, but the operator-declared capability
	// boundary blocked live ingestion. The response must be
	// downgraded so the UI does not let operators believe live
	// coverage is active when it is not.
	if result.Status != "degraded" {
		t.Fatalf("expected capability-gated fallback status=degraded, got %q (%+v)", result.Status, result)
	}
	if result.FixtureState != "capability_unavailable" {
		t.Fatalf("expected fixture_state=capability_unavailable, got %q", result.FixtureState)
	}
	if result.Confidence > 0.6 {
		t.Fatalf("expected confidence capped at 0.6, got %v", result.Confidence)
	}
	foundReason := false
	for _, reason := range result.FailureReasons {
		if strings.Contains(reason, "runtime_evidence") {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("expected runtime_evidence failure reason, got %+v", result.FailureReasons)
	}
}

func TestGetAWSRuntimeEventsFixtureOverrideBypassesLiveFactory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 19, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-fixture-override")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-fixture-override", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	called := false
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		called = true
		return &fakeCloudTrailIngester{}, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-fixture-override", AWSRuntimeEventRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if called {
		t.Fatalf("explicit fixture_state must bypass live CloudTrail factory")
	}
	if result.FixtureState != "degraded" || result.Status != "degraded" {
		t.Fatalf("expected fixture override to render degraded contract, got %+v", result)
	}
}

func TestGetAWSRuntimeEventsFactoryErrorAttachesDiagnosticAndFallsBackToFixture(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 20, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-factory-error")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-factory-error", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-factory-error", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return nil, errors.New("assume role refused")
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-factory-error", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Summary.TotalEvents == 0 {
		t.Fatalf("expected fixture fallback to keep returning records, got %+v", result)
	}
	// When the factory fails the fixture path's synthetic "ready"
	// status would otherwise tell the operator that live coverage is
	// healthy even though no live CloudTrail data was collected. The
	// fallback must downgrade so the partial-failure state is visible.
	if result.Status != "degraded" {
		t.Fatalf("expected fallback status=degraded after factory failure, got %q (%+v)", result.Status, result)
	}
	if result.FixtureState != "partial_failure" {
		t.Fatalf("expected fixture_state=partial_failure after factory failure, got %q", result.FixtureState)
	}
	if result.Confidence > 0.6 {
		t.Fatalf("expected confidence capped at 0.6 after factory failure, got %v", result.Confidence)
	}
	foundFactoryDiagnostic := false
	for _, diag := range result.Diagnostics {
		if diag.Code == "cloudtrail_ingester_unavailable" {
			foundFactoryDiagnostic = true
		}
	}
	if !foundFactoryDiagnostic {
		t.Fatalf("expected factory failure diagnostic on fallback response, got %+v", result.Diagnostics)
	}
	foundFactoryReason := false
	for _, reason := range result.FailureReasons {
		if strings.Contains(reason, "CloudTrail LookupEvents ingester is not available") {
			foundFactoryReason = true
		}
	}
	if !foundFactoryReason {
		t.Fatalf("expected factory failure reason on fallback response, got %+v", result.FailureReasons)
	}
}

func TestRuntimeEventRecordFromNormalizedUsesCanonicalAgentNodeID(t *testing.T) {
	// The runtime evidence graph must key agent nodes on the same
	// shape (aws:agent:<account>:<region>:<type>/<id>) the
	// AI-agent inventory and provider normalizer use, otherwise
	// live runtime evidence and the agent inventory won't join.
	got := runtimeEventRecordFromNormalized(cloudtrail.NormalizedEvent{
		EventID:             "evt-agent",
		AccountID:           "123456789012",
		Region:              "us-east-1",
		EventType:           "agent-tool",
		EventSource:         "bedrock-agentcore.amazonaws.com",
		EventName:           "InvokeTool",
		Action:              "bedrock-agentcore:InvokeTool",
		AgentID:             "runtime-case-triage",
		AgentType:           "agentcore_runtime",
		AgentRuntimeVersion: "blue",
		TargetResourceARN:   "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/runtime-case-triage/blue",
		ObservedAt:          time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC),
		RedactionBoundary:   "metadata_only_no_payloads_no_secret_values",
	}, "123456789012", "us-east-1")
	// The version must be included in the canonical node id so live
	// relationships join the AI-agent inventory nodes that already
	// stamp the runtime version. With "blue", the canonical helper
	// appends it to produce `...:agentcore_runtime/runtime-case-triage/blue`.
	want := awsAIAgentNodeID("123456789012", "us-east-1", "agentcore_runtime", "runtime-case-triage", "blue")
	if got.AgentNodeID != want {
		t.Fatalf("expected canonical AgentNodeID %q, got %q", want, got.AgentNodeID)
	}
	if !strings.Contains(got.AgentNodeID, "/blue") {
		t.Fatalf("expected runtime version segment in AgentNodeID, got %q", got.AgentNodeID)
	}

	// Non-agent-tool events leave AgentNodeID empty.
	got = runtimeEventRecordFromNormalized(cloudtrail.NormalizedEvent{
		EventID:     "evt-secret",
		AccountID:   "123456789012",
		Region:      "us-east-1",
		EventType:   "secret-read",
		EventSource: "secretsmanager.amazonaws.com",
	}, "123456789012", "us-east-1")
	if got.AgentNodeID != "" {
		t.Fatalf("expected empty AgentNodeID for non-agent event, got %q", got.AgentNodeID)
	}
}

func TestRuntimeEventRecordFromNormalizedKeysAssumedRoleIdentityByIssuerARN(t *testing.T) {
	sessionARN := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess-runtime-reader"
	issuerARN := "arn:aws:iam::123456789012:role/identrail-runtime-reader"
	// Assumed-role events must key the identity graph by the issuer
	// role ARN so the observed_runtime_action relationship joins the
	// same role node the IAM identity collector emits. Building the
	// node ID from the STS session ARN would create an orphan node
	// that never matches any role in the discovered graph.
	got := runtimeEventRecordFromNormalized(cloudtrail.NormalizedEvent{
		EventID:            "evt-assume",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		EventType:          "sts-session",
		EventSource:        "sts.amazonaws.com",
		EventName:          "AssumeRole",
		Action:             "sts:AssumeRole",
		ActorPrincipalARN:  sessionARN,
		ActorPrincipalType: "assumed_role",
		SessionIssuerARN:   issuerARN,
		AssumedRoleARN:     issuerARN,
		ObservedAt:         time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC),
		RedactionBoundary:  "metadata_only_no_payloads_no_secret_values",
	}, "123456789012", "us-east-1")
	if want, have := awsIdentityNodeIDForAPI(issuerARN), got.ActorIdentityNodeID; want != have {
		t.Fatalf("expected ActorIdentityNodeID to use issuer ARN %q (got %q)", want, have)
	}
	if got.ActorPrincipalARN != sessionARN {
		t.Fatalf("expected principal ARN to remain the STS session ARN, got %q", got.ActorPrincipalARN)
	}
	if got.Session.SessionIssuerARN != issuerARN || got.Session.AssumedRoleARN != issuerARN {
		t.Fatalf("expected session block to preserve issuer/role ARN, got %+v", got.Session)
	}

	// Non-assumed-role event (no SessionIssuerARN): identity node ID
	// must still use the actor principal ARN so root/IAM-user/service
	// events do not regress.
	rootARN := "arn:aws:iam::123456789012:root"
	got = runtimeEventRecordFromNormalized(cloudtrail.NormalizedEvent{
		EventID:           "evt-root",
		AccountID:         "123456789012",
		Region:            "us-east-1",
		EventType:         "api-call",
		EventSource:       "iam.amazonaws.com",
		EventName:         "CreateUser",
		ActorPrincipalARN: rootARN,
	}, "123456789012", "us-east-1")
	if want, have := awsIdentityNodeIDForAPI(rootARN), got.ActorIdentityNodeID; want != have {
		t.Fatalf("expected non-assumed-role event to key identity by principal ARN, got %q want %q", have, want)
	}
}

func TestGetAWSRuntimeEventsIngestionScopeIsConnectorNotRequestFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 20, 7, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-scope")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-scope", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-scope", "aws-prod")

	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{Status: "ready"}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	// Caller asks the API to *filter* by a different account and region
	// than the connector. Those values are caller-side filters; they
	// must never become the ingestion scope, because a CloudTrailEvent
	// payload missing recipientAccountId/awsRegion would otherwise
	// inherit them and a filter for a different account could match
	// and return mislabeled runtime evidence.
	if _, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-scope", AWSRuntimeEventRequest{
		ConnectorID: "aws-prod",
		AccountID:   "999999999999",
		Region:      "eu-central-1",
	}); err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected one ingestion call, got %d", len(fake.calls))
	}
	if fake.calls[0].AccountID == "999999999999" || fake.calls[0].Region == "eu-central-1" {
		t.Fatalf("request filter account/region must not become ingestion scope, got %+v", fake.calls[0])
	}
}

func TestGetAWSRuntimeEventsAgentToolEventTypeDoesNotPushdownSingleSource(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 20, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-agent-pushdown")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-agent-pushdown", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-agent-pushdown", "aws-prod")

	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{Status: "ready"}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	if _, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-agent-pushdown", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "agent-tool"}); err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].EventSourceFilter != "" {
		t.Fatalf("agent-tool spans bedrock-agentcore + bedrock-agent and must not push a single-source CloudTrail filter, got %+v", fake.calls)
	}
}

func TestGetAWSRuntimeEventsLiveEventSourceFilterIsPushedToIngester(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 20, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-source-filter")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-source-filter", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-source-filter", "aws-prod")

	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{Status: "ready"}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	if _, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-source-filter", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "kms-decrypt"}); err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].EventSourceFilter != "kms.amazonaws.com" {
		t.Fatalf("expected event_type=kms-decrypt to push CloudTrail event source filter, got %+v", fake.calls)
	}
}

func TestGetAWSRuntimeEventsLiveBlockedStatusKeepsContractShape(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-live-blocked")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-live-blocked", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-live-blocked", "aws-prod")

	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "blocked",
		Diagnostics: []AWSRuntimeEventDiagnostic{{
			Collector: "aws_cloudtrail_lookup_events",
			SourceID:  "cloudtrail",
			Code:      "permission_denied",
			Message:   "CloudTrail LookupEvents permission is not available for runtime event ingestion: AccessDeniedException",
			Retryable: true,
		}},
		CoverageGaps: []AWSRuntimeEventCoverageGap{{
			Capability:  "cloudtrail_lookup_events",
			Status:      "permission_denied",
			Reason:      "Runtime event source cannot be queried with the current connector permissions.",
			Remediation: "Add read-only CloudTrail LookupEvents permissions and retry.",
		}},
		FailureReasons:   []string{"runtime event sources are not authorized for this connector"},
		RemediationHints: []string{"Grant metadata-only CloudTrail LookupEvents and service audit permissions; do not grant payload, secret-value, decrypt, or object-body reads."},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-live-blocked", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "blocked" || result.FixtureState != "permission_denied" {
		t.Fatalf("expected blocked/permission_denied contract on live denial, got %+v", result)
	}
	if len(result.Records) != 0 {
		t.Fatalf("blocked status must not leak any live records: %+v", result.Records)
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].Status != "permission_denied" {
		t.Fatalf("expected permission_denied coverage gap, got %+v", result.CoverageGaps)
	}
	if len(result.FailureReasons) == 0 || !strings.Contains(strings.Join(result.FailureReasons, "|"), "not authorized") {
		t.Fatalf("expected blocked failure reasons surfaced to operators, got %+v", result.FailureReasons)
	}
	// Regression: a blocked response carries zero records, so the
	// permission_denied diagnostic (SourceID="cloudtrail") must survive
	// scopeAWSRuntimeEventDiagnostics. Without that, the operator
	// would lose the structured diagnostic that explains the state.
	foundCollectorDiagnostic := false
	for _, diag := range result.Diagnostics {
		if diag.Code == "permission_denied" && diag.SourceID == "cloudtrail" {
			foundCollectorDiagnostic = true
		}
	}
	if !foundCollectorDiagnostic {
		t.Fatalf("expected collector-level permission_denied diagnostic to survive in blocked response, got %+v", result.Diagnostics)
	}
}

func TestGetAWSRuntimeEventsSignalPermissionDeniedDowngradesLiveCloudTrail(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-signal-denied")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-signal-denied", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-signal-denied", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess"
	cloudTrail := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "ready",
		Records: []AWSRuntimeEventRecord{
			liveRuntimeRecord(t, "evt-live-secret", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "cloudtrail", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", "AWS::SecretsManager::Secret", now.Add(-10*time.Minute)),
		},
	}}
	signals := &fakeRuntimeSignalIngester{result: AWSRuntimeSignalIngestResult{
		Status: "blocked",
		Diagnostics: []AWSRuntimeEventDiagnostic{{
			Collector: "aws_iam_access_signals",
			SourceID:  "iam",
			Code:      "iam_last_used_permission_denied",
			Message:   "IAM last-used collection is not authorized.",
			Retryable: true,
		}},
		CoverageGaps: []AWSRuntimeEventCoverageGap{{
			Capability: "iam_last_used",
			Status:     "permission_denied",
			Reason:     "IAM last-used collection is not authorized.",
		}},
		FailureReasons:   []string{"IAM last-used and Access Analyzer permissions are unavailable"},
		RemediationHints: []string{"Grant metadata-only signal permissions."},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return cloudTrail, nil
	}
	svc.AWSRuntimeSignalFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSRuntimeSignalIngester, error) {
		return signals, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-signal-denied", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "degraded" || result.FixtureState != "partial_failure" || result.Confidence > 0.72 {
		t.Fatalf("expected blocked signal coverage to downgrade live CloudTrail result, got %+v", result)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-live-secret" {
		t.Fatalf("expected CloudTrail evidence to remain visible, got %+v", result.Records)
	}
	if len(result.Diagnostics) == 0 || !strings.Contains(strings.Join(result.FailureReasons, "|"), "permissions are unavailable") {
		t.Fatalf("expected signal denial diagnostics/failures, got diagnostics=%+v failures=%+v", result.Diagnostics, result.FailureReasons)
	}
}

func TestGetAWSRuntimeEventsSignalPermissionDeniedRespectsSourceFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 25, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-signal-source-filter")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-signal-source-filter", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-signal-source-filter", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess"
	cloudTrail := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "ready",
		Records: []AWSRuntimeEventRecord{
			liveRuntimeRecord(t, "evt-live-kms", "kms-decrypt", "Decrypt", "kms.amazonaws.com", "kms:Decrypt", "application", "cloudtrail", role, "arn:aws:kms:us-east-1:123456789012:key/example", "AWS::KMS::Key", now.Add(-10*time.Minute)),
		},
	}}
	signals := &fakeRuntimeSignalIngester{result: AWSRuntimeSignalIngestResult{
		Status: "blocked",
		Diagnostics: []AWSRuntimeEventDiagnostic{{
			Collector: "aws_iam_access_signals",
			SourceID:  "iam",
			Code:      "iam_last_used_permission_denied",
			Message:   "IAM last-used collection is not authorized.",
			Retryable: true,
		}},
		CoverageGaps: []AWSRuntimeEventCoverageGap{{
			Capability: "iam_last_used",
			Status:     "permission_denied",
			Reason:     "IAM last-used collection is not authorized.",
		}},
		FailureReasons:   []string{"IAM last-used and Access Analyzer permissions are unavailable"},
		RemediationHints: []string{"Grant metadata-only signal permissions."},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return cloudTrail, nil
	}
	svc.AWSRuntimeSignalFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSRuntimeSignalIngester, error) {
		return signals, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-signal-source-filter", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "secret-read"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "degraded" || result.FixtureState != "degraded" || result.Confidence != 0.5 {
		t.Fatalf("expected empty CloudTrail filter state to survive out-of-scope signal denial, got %+v", result)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected source filter to exclude CloudTrail and signal records, got %+v", result.Records)
	}
	if strings.Contains(strings.Join(result.FailureReasons, "|"), "permissions are unavailable") {
		t.Fatalf("out-of-scope signal denial should not override filtered view failures, got %+v", result.FailureReasons)
	}
}

func TestGetAWSRuntimeEventsSkipsSignalFactoryForCloudTrailOnlyFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 27, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-signal-factory-source-filter")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-signal-factory-source-filter", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-signal-factory-source-filter", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess"
	cloudTrail := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "ready",
		Records: []AWSRuntimeEventRecord{
			liveRuntimeRecord(t, "evt-live-secret", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "cloudtrail", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", "AWS::SecretsManager::Secret", now.Add(-10*time.Minute)),
		},
	}}
	signalFactoryCalls := 0
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return cloudTrail, nil
	}
	svc.AWSRuntimeSignalFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSRuntimeSignalIngester, error) {
		signalFactoryCalls++
		return nil, errors.New("signal factory unavailable")
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-signal-factory-source-filter", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "secret-read"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if signalFactoryCalls != 0 {
		t.Fatalf("CloudTrail-only filters should not initialize signal factory, got %d calls", signalFactoryCalls)
	}
	if result.Status != "ready" || result.Confidence != 0.92 {
		t.Fatalf("expected healthy CloudTrail-only result to stay ready, got %+v", result)
	}
	if len(result.Diagnostics) != 0 || strings.Contains(strings.Join(result.FailureReasons, "|"), "signal") {
		t.Fatalf("out-of-scope signal factory failure should not leak into response, diagnostics=%+v failures=%+v", result.Diagnostics, result.FailureReasons)
	}
}

func TestGetAWSRuntimeEventsSignalsClearEmptyFilterState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-signal-filter")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-signal-filter", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-signal-filter", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess"
	cloudTrail := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "ready",
		Records: []AWSRuntimeEventRecord{
			liveRuntimeRecord(t, "evt-live-secret", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "cloudtrail", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", "AWS::SecretsManager::Secret", now.Add(-10*time.Minute)),
		},
	}}
	signalRecord := liveSignalRuntimeRecord(t, "evt-live-analyzer", "access-analyzer", "access-analyzer:external-principal", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", now.Add(-5*time.Minute))
	signals := &fakeRuntimeSignalIngester{result: AWSRuntimeSignalIngestResult{
		Status:  "ready",
		Records: []AWSRuntimeEventRecord{signalRecord},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return cloudTrail, nil
	}
	svc.AWSRuntimeSignalFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSRuntimeSignalIngester, error) {
		return signals, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-signal-filter", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "access-analyzer"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "ready" || result.FixtureState != "success" || result.Confidence != 0.92 {
		t.Fatalf("expected signal match to clear stale empty-filter state, got %+v", result)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-live-analyzer" {
		t.Fatalf("expected filtered signal record, got %+v", result.Records)
	}
	if strings.Contains(strings.Join(result.FailureReasons, "|"), "filters matched no records") || strings.Contains(strings.Join(result.RemediationHints, "|"), "Clear filters") {
		t.Fatalf("empty-filter messages should be cleared after signal match, failures=%+v remediations=%+v", result.FailureReasons, result.RemediationHints)
	}
}

func TestGetAWSRuntimeEventsSignalDiagnosticsRespectRequestedSignalSource(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 35, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-signal-source-diagnostics")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-signal-source-diagnostics", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-signal-source-diagnostics", "aws-prod")

	role := "arn:aws:iam::123456789012:role/identrail-runtime-reader"
	cloudTrail := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{Status: "ready"}}
	iamRecord := liveRuntimeRecord(t, "evt-live-iam-last-used", "iam-last-used", "ServiceLastAccessed", "iam.amazonaws.com", "lambda:LastAuthenticated", "platform", "iam-last-used", role, "aws-service://lambda", "aws_service", now.Add(-120*24*time.Hour))
	iamRecord.SignalCategory = "iam-last-used"
	iamRecord.SignalScope = "service"
	iamRecord.SignalStaleAt = now
	signals := &fakeRuntimeSignalIngester{result: AWSRuntimeSignalIngestResult{
		Status:  "degraded",
		Records: []AWSRuntimeEventRecord{iamRecord},
		Diagnostics: []AWSRuntimeEventDiagnostic{{
			Collector: "aws_iam_access_signals",
			SourceID:  "access-analyzer:account",
			Code:      "access_analyzer_permission_denied",
			Message:   "Access Analyzer findings could not be listed.",
			Retryable: true,
		}},
		CoverageGaps: []AWSRuntimeEventCoverageGap{{
			Capability: "access_analyzer",
			Status:     "permission_denied",
			Reason:     "Access Analyzer findings could not be listed.",
		}},
		FailureReasons:   []string{"Access Analyzer signal permissions are unavailable"},
		RemediationHints: []string{"Grant metadata-only Access Analyzer permissions."},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return cloudTrail, nil
	}
	svc.AWSRuntimeSignalFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSRuntimeSignalIngester, error) {
		return signals, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-signal-source-diagnostics", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "iam-last-used"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "ready" || result.FixtureState != "success" {
		t.Fatalf("expected IAM-only signal view to ignore Access Analyzer diagnostics, got %+v", result)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-live-iam-last-used" {
		t.Fatalf("expected IAM signal record to remain visible, got %+v", result.Records)
	}
	if len(result.Diagnostics) != 0 || len(result.CoverageGaps) != 0 || strings.Contains(strings.Join(result.FailureReasons, "|"), "Access Analyzer") {
		t.Fatalf("Access Analyzer diagnostics should not leak into IAM-only view, diagnostics=%+v gaps=%+v failures=%+v", result.Diagnostics, result.CoverageGaps, result.FailureReasons)
	}
	if result.Summary.AccessAnalyzerCount != 0 || result.Summary.IAMLastUsedSignalCount != 1 {
		t.Fatalf("summary should be scoped to IAM signals, got %+v", result.Summary)
	}
}

func TestGetAWSRuntimeEventsCloudTrailDeniedWithSignalsIsPartialCoverage(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 40, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-cloudtrail-denied-signals")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-cloudtrail-denied-signals", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-cloudtrail-denied-signals", "aws-prod")

	cloudTrail := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "blocked",
		Diagnostics: []AWSRuntimeEventDiagnostic{{
			Collector: "aws_cloudtrail_lookup_events",
			SourceID:  "cloudtrail",
			Code:      "permission_denied",
			Message:   "CloudTrail LookupEvents permission is not available.",
			Retryable: true,
		}},
		CoverageGaps: []AWSRuntimeEventCoverageGap{{
			Capability: "cloudtrail_lookup_events",
			Status:     "permission_denied",
			Reason:     "CloudTrail LookupEvents permission is not available.",
		}},
		FailureReasons:   []string{"runtime event sources are not authorized for this connector"},
		RemediationHints: []string{"Grant metadata-only CloudTrail LookupEvents."},
	}}
	signalRecord := liveSignalRuntimeRecord(t, "evt-live-analyzer", "access-analyzer", "access-analyzer:external-principal", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", now.Add(-5*time.Minute))
	signals := &fakeRuntimeSignalIngester{result: AWSRuntimeSignalIngestResult{
		Status:  "ready",
		Records: []AWSRuntimeEventRecord{signalRecord},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return cloudTrail, nil
	}
	svc.AWSRuntimeSignalFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSRuntimeSignalIngester, error) {
		return signals, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-cloudtrail-denied-signals", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "access-analyzer"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "degraded" || result.FixtureState != "partial_failure" || result.Confidence > 0.72 {
		t.Fatalf("expected mixed CloudTrail-denied/signal-visible result to be partial coverage, got %+v", result)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-live-analyzer" {
		t.Fatalf("expected signal evidence to remain visible, got %+v", result.Records)
	}
	if len(result.CoverageGaps) == 0 || !strings.Contains(strings.Join(result.FailureReasons, "|"), "not authorized") {
		t.Fatalf("expected CloudTrail denial context to remain visible, gaps=%+v failures=%+v", result.CoverageGaps, result.FailureReasons)
	}
}

func TestGetAWSRuntimeEventsFactoryContextCancellationPropagates(t *testing.T) {
	// Context cancellation / deadline expiry inside the factory
	// (loading AWS config, assuming the role) is a caller-driven
	// abort, not a CloudTrail partial-coverage state. The handler
	// must return the context error to the caller — letting the
	// fixture fallback render a "degraded" response would mislead
	// an HTTP client that already disconnected.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-factory-cancel")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-factory-cancel", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-factory-cancel", "aws-prod")

	for _, ctxErr := range []error{context.Canceled, context.DeadlineExceeded} {
		svc := NewService(store, fakeScanner{}, "aws")
		svc.Now = func() time.Time { return now }
		svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
			return nil, ctxErr
		}
		_, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-factory-cancel", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
		if !errors.Is(err, ctxErr) {
			t.Fatalf("expected %v to propagate, got %v", ctxErr, err)
		}
	}
}

func TestGetAWSRuntimeEventsRecomputesStatusReadyWhenFilterDropsAllDiagnostics(t *testing.T) {
	// If the unfiltered ingester is degraded only because of a
	// normalization diagnostic on a record that the filter then drops,
	// the response the operator sees has no diagnostic, no coverage
	// gap, and clean records. The handler must recompute to ready so
	// the UI does not show degraded for a clean filtered slice.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 22, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-recompute")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-recompute", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-recompute", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess"
	cleanSecret := liveRuntimeRecord(t, "evt-clean-secret", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "cloudtrail", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/clean", "AWS::SecretsManager::Secret", now.Add(-10*time.Minute))
	dirtyAPI := liveRuntimeRecord(t, "evt-dirty-api", "api-call", "DescribeInstances", "ec2.amazonaws.com", "ec2:DescribeInstances", "application", "cloudtrail", role, "arn:aws:ec2:us-east-1:123456789012:instance/i-1", "AWS::EC2::Instance", now.Add(-5*time.Minute))
	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		// Ingester is degraded only because of the diagnostic
		// attached to the dirty-api record. No coverage gaps, no
		// truncation, two records.
		Status:           "degraded",
		Records:          []AWSRuntimeEventRecord{cleanSecret, dirtyAPI},
		FailureReasons:   []string{"CloudTrail LookupEvents ingestion returned diagnostics"},
		RemediationHints: []string{"Review diagnostics before treating runtime coverage as complete."},
		Diagnostics: []AWSRuntimeEventDiagnostic{{
			Collector: "aws_cloudtrail_lookup_events",
			SourceID:  "evt-dirty-api",
			Code:      "cloudtrail_event_payload_unparseable",
			Message:   "synthetic test diagnostic",
		}},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	// Filter scopes the response to the clean secret-read record only.
	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-recompute", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "secret-read"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-clean-secret" {
		t.Fatalf("expected only the clean secret record in filtered response, got %+v", result.Records)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("expected scoped-out diagnostics to be absent, got %+v", result.Diagnostics)
	}
	if result.Status != "ready" {
		t.Fatalf("expected status to be recomputed to ready when all diagnostics scoped out, got %q (%+v)", result.Status, result)
	}
	if result.FixtureState != "success" {
		t.Fatalf("expected fixture_state=success on recomputed ready, got %q", result.FixtureState)
	}
}

func TestAWSRuntimeEventSessionOmitsUnknownTimestamps(t *testing.T) {
	// IAM/root/service events do not carry a CloudTrail session,
	// and even assumed-role events where STS rotated the credential
	// do not expose a real expiration. The JSON response must omit
	// the field entirely rather than emit the bogus year-0001 zero
	// literal ("0001-01-01T00:00:00Z") that encoding/json would
	// produce by default for a zero time.Time.
	session := AWSRuntimeEventSession{
		SessionID:     "ASIAEXAMPLE",
		PrincipalARN:  "arn:aws:iam::123456789012:root",
		PrincipalType: "root",
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(encoded)
	if strings.Contains(body, "started_at") {
		t.Fatalf("expected started_at to be omitted when zero, got %s", body)
	}
	if strings.Contains(body, "expires_at") {
		t.Fatalf("expected expires_at to be omitted when zero, got %s", body)
	}
	if strings.Contains(body, "0001-01-01") {
		t.Fatalf("expected no year-0001 zero-time literal, got %s", body)
	}

	// When the times are populated they must round-trip back.
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	session.StartedAt = now
	session.ExpiresAt = now.Add(time.Hour)
	encoded, err = json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal populated: %v", err)
	}
	if !strings.Contains(string(encoded), "\"started_at\":\"2026-06-14T18:00:00Z\"") {
		t.Fatalf("expected populated started_at in response, got %s", encoded)
	}
}

func TestScopeAWSRuntimeEventDiagnosticsKeepsBaseDiagnosticForFannedOutRecords(t *testing.T) {
	// A multi-resource CloudTrail event normalizes into base + `#N`
	// suffixed records but the engine emits a single diagnostic keyed
	// to the base EventID. If the filter retains only `evt#1`, the
	// scope helper must still keep the base-keyed diagnostic — the
	// fan-out children belong to the same CloudTrail event family.
	allRecords := []AWSRuntimeEventRecord{
		{EventID: "evt-bad"},
		{EventID: "evt-bad#1"},
		{EventID: "evt-bad#2"},
	}
	filtered := []AWSRuntimeEventRecord{{EventID: "evt-bad#1"}}
	diagnostics := []AWSRuntimeEventDiagnostic{
		{Collector: "aws_cloudtrail_lookup_events", SourceID: "evt-bad", Code: "cloudtrail_event_payload_unparseable"},
	}
	scoped := scopeAWSRuntimeEventDiagnostics(diagnostics, allRecords, filtered)
	if len(scoped) != 1 || scoped[0].Code != "cloudtrail_event_payload_unparseable" {
		t.Fatalf("expected base diagnostic preserved when fan-out child retained, got %+v", scoped)
	}

	// When NO fan-out child of the family survives the filter, the
	// diagnostic is dropped — matching the existing per-event behavior.
	filteredNone := []AWSRuntimeEventRecord{{EventID: "evt-other"}}
	scoped = scopeAWSRuntimeEventDiagnostics(diagnostics, allRecords, filteredNone)
	if len(scoped) != 0 {
		t.Fatalf("expected base diagnostic dropped when no fan-out child retained, got %+v", scoped)
	}
}

func TestScopeAWSRuntimeEventDiagnosticsPreservesCollectorLevelSourceIDs(t *testing.T) {
	allRecords := []AWSRuntimeEventRecord{
		{EventID: "evt-a"},
		{EventID: "evt-b"},
	}
	filtered := []AWSRuntimeEventRecord{{EventID: "evt-a"}}
	diagnostics := []AWSRuntimeEventDiagnostic{
		// Collector-level: SourceID does not match any record EventID.
		{Collector: "aws_cloudtrail_lookup_events", SourceID: "cloudtrail", Code: "permission_denied"},
		// Collector-level via factory wrapper.
		{Collector: "aws_cloudtrail_lookup_events", SourceID: "factory", Code: "cloudtrail_ingester_unavailable"},
		// Per-event diagnostic for a record that survived filtering.
		{Collector: "aws_runtime_events", SourceID: "evt-a", Code: "runtime_event_delivery_delayed"},
		// Per-event diagnostic for a record that was filtered out.
		{Collector: "aws_runtime_events", SourceID: "evt-b", Code: "runtime_event_delivery_delayed"},
		// Empty SourceID — always preserved.
		{Collector: "aws_runtime_events", Code: "unknown"},
	}
	scoped := scopeAWSRuntimeEventDiagnostics(diagnostics, allRecords, filtered)
	codes := map[string]bool{}
	for _, diag := range scoped {
		codes[diag.SourceID+":"+diag.Code] = true
	}
	for _, want := range []string{"cloudtrail:permission_denied", "factory:cloudtrail_ingester_unavailable", "evt-a:runtime_event_delivery_delayed", ":unknown"} {
		if !codes[want] {
			t.Fatalf("expected diagnostic %q to be preserved, got %+v", want, scoped)
		}
	}
	if codes["evt-b:runtime_event_delivery_delayed"] {
		t.Fatalf("per-record diagnostic for filtered-out event must be dropped, got %+v", scoped)
	}
}

func TestAWSRuntimeEventRelationshipsSkipRoleLastUsedSelfActions(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/never-used"
	record := AWSRuntimeEventRecord{
		EventID:             "evt-role-never-used",
		EventType:           "iam-last-used",
		SignalCategory:      "iam-last-used",
		SignalScope:         "role",
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(roleARN),
		ResourceNodeID:      awsRuntimeEventResourceNodeID(roleARN, "iam_role"),
		EvidenceRef:         "runtime-evidence://123456789012/us-east-1/evt-role-never-used",
	}
	relationships := awsRuntimeEventRelationships([]AWSRuntimeEventRecord{record})
	for _, relationship := range relationships {
		if relationship.Type == "observed_runtime_action" {
			t.Fatalf("role last-used metadata must not create observed action self-edge, got %+v", relationships)
		}
	}
}

func TestAWSRuntimeEventRelationshipsSkipServiceNeverAccessedActions(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/never-used"
	record := AWSRuntimeEventRecord{
		EventID:             "evt-service-never-accessed",
		EventType:           "iam-last-used",
		EventName:           "ServiceNeverAccessed",
		SignalCategory:      "iam-last-used",
		SignalScope:         "service",
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(roleARN),
		ResourceNodeID:      awsRuntimeEventResourceNodeID("aws-service://sqs", "aws_service"),
		EvidenceRef:         "runtime-evidence://123456789012/us-east-1/evt-service-never-accessed",
	}
	relationships := awsRuntimeEventRelationships([]AWSRuntimeEventRecord{record})
	for _, relationship := range relationships {
		if relationship.Type == "observed_runtime_action" {
			t.Fatalf("service-never-accessed metadata must not create observed action edge, got %+v", relationships)
		}
	}
}
