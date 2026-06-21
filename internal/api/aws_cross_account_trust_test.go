package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func newCrossAccountTrustService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSCrossAccountTrustBuildsFindingContract(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	svc, ws := newCrossAccountTrustService(t, "project-cross-account-trust", now)

	result, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get cross-account trust: %v", err)
	}
	if result.CurrentIssueRef != "#1526" || result.Version != awsCrossAccountTrustVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready status, got %q with diagnostics=%+v", result.Status, result.Diagnostics)
	}
	if len(result.Findings) == 0 || result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("expected findings summary to match payload: %+v", result.Summary)
	}
	if result.Summary.PublicPrincipalCount == 0 || result.Summary.CrossAccountGrantCount == 0 {
		t.Fatalf("expected public and cross-account grant findings: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected graph relationships: %+v", result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 || len(result.EvidenceLinks) == 0 {
		t.Fatalf("expected caveats, coverage gaps, and evidence links: %+v", result)
	}
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Score < result.Findings[i].Score {
			t.Fatalf("findings are not ranked by descending score: %+v", result.Findings)
		}
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsCrossAccountTrustVersion {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.FindingType == "" || finding.Severity == "" || finding.Status == "" || finding.Rationale == "" {
			t.Fatalf("finding missing classification fields: %+v", finding)
		}
		if finding.Score <= 0 || finding.Confidence <= 0 {
			t.Fatalf("finding missing score/confidence: %+v", finding)
		}
		if finding.ResourceLabel == "" || len(finding.ImpactedPath) < 2 || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing path/evidence fields: %+v", finding)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
}

func TestGetAWSCrossAccountTrustFiltersByTypeServicePrincipalAndResource(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 5, 0, 0, time.UTC)
	svc, ws := newCrossAccountTrustService(t, "project-cross-account-trust-filters", now)

	kms, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-filters", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Service:      "kms",
		FindingType:  "cross_account_resource_access",
		Principal:    "partner-ingest",
		Resource:     "partner-feed",
	})
	if err != nil {
		t.Fatalf("kms filter: %v", err)
	}
	if len(kms.Findings) == 0 {
		t.Fatalf("expected filtered KMS cross-account findings")
	}
	for _, finding := range kms.Findings {
		if finding.Service != "kms" || finding.FindingType != "cross_account_resource_access" {
			t.Fatalf("filter leaked unrelated finding: %+v", finding)
		}
		if !strings.Contains(finding.ExternalPrincipalARN, "partner-ingest") {
			t.Fatalf("principal filter leaked: %+v", finding)
		}
		if !strings.Contains(strings.ToLower(finding.ResourceLabel), "partner") && !strings.Contains(strings.ToLower(finding.ResourceARN), "partner") {
			t.Fatalf("resource filter leaked: %+v", finding)
		}
	}
	if kms.AppliedFilters["service"] != "kms" || kms.AppliedFilters["finding_type"] != "cross-account-resource-access" {
		t.Fatalf("expected normalized applied filters, got %+v", kms.AppliedFilters)
	}
}

func TestAWSCrossAccountTrustFindingsSuppressExplicitDenyOverrides(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 7, 0, 0, time.UTC)
	fullyDeniedPrincipal := "arn:aws:iam::999999999999:role/fully-denied"
	partiallyDeniedPrincipal := "arn:aws:iam::999999999999:role/partially-denied"
	conditionallyDeniedPrincipal := "arn:aws:iam::999999999999:role/conditionally-denied"
	publicBucket := "arn:aws:s3:::public-denied"
	findings := awsCrossAccountTrustFindings(awsCrossAccountTrustSources{
		s3: AWSS3BucketReachabilityInventoryResult{Records: []AWSS3BucketReachabilityRecord{
			{
				AccountID:   "123456789012",
				Region:      "us-east-1",
				BucketARN:   "arn:aws:s3:::fully-denied",
				BucketName:  "fully-denied",
				FromNodeID:  "aws:s3:fully-denied",
				EvidenceRef: "aws-evidence://s3/fully-denied",
				Confidence:  0.9,
				CollectedAt: now,
				IdentityGrants: []AWSS3IdentityGrant{
					{PrincipalARN: fullyDeniedPrincipal, Effect: "Allow", Actions: []string{"s3:GetObject"}, IsCrossAccount: true},
					{PrincipalARN: fullyDeniedPrincipal, Effect: "Deny", Actions: []string{"s3:GetObject"}},
				},
			},
			{
				AccountID:   "123456789012",
				Region:      "us-east-1",
				BucketARN:   "arn:aws:s3:::partially-denied",
				BucketName:  "partially-denied",
				FromNodeID:  "aws:s3:partially-denied",
				EvidenceRef: "aws-evidence://s3/partially-denied",
				Confidence:  0.9,
				CollectedAt: now,
				IdentityGrants: []AWSS3IdentityGrant{
					{PrincipalARN: partiallyDeniedPrincipal, Effect: "Allow", Actions: []string{"s3:GetObject", "s3:PutObject"}, IsCrossAccount: true},
					{PrincipalARN: partiallyDeniedPrincipal, Effect: "Deny", Actions: []string{"s3:GetObject"}},
				},
			},
			{
				AccountID:   "123456789012",
				Region:      "us-east-1",
				BucketARN:   "arn:aws:s3:::conditionally-denied",
				BucketName:  "conditionally-denied",
				FromNodeID:  "aws:s3:conditionally-denied",
				EvidenceRef: "aws-evidence://s3/conditionally-denied",
				Confidence:  0.9,
				CollectedAt: now,
				IdentityGrants: []AWSS3IdentityGrant{
					{PrincipalARN: conditionallyDeniedPrincipal, Effect: "Allow", Actions: []string{"s3:GetObject"}, IsCrossAccount: true},
					{PrincipalARN: conditionallyDeniedPrincipal, Effect: "Deny", Actions: []string{"s3:GetObject"}, HasCondition: true, ConditionKeys: []string{"aws:SecureTransport"}},
				},
			},
			{
				AccountID:   "123456789012",
				Region:      "us-east-1",
				BucketARN:   publicBucket,
				BucketName:  "public-denied",
				FromNodeID:  "aws:s3:public-denied",
				EvidenceRef: "aws-evidence://s3/public-denied",
				Confidence:  0.9,
				CollectedAt: now,
				IdentityGrants: []AWSS3IdentityGrant{
					{PrincipalARN: "*", Effect: "Allow", Actions: []string{"s3:GetObject"}, IsPublic: true, WildcardPrincipal: true},
					{PrincipalARN: "*", Effect: "Deny", Actions: []string{"s3:*"}, WildcardPrincipal: true},
				},
			},
		}},
	}, now)

	for _, finding := range findings {
		if finding.ExternalPrincipalARN == fullyDeniedPrincipal {
			t.Fatalf("fully denied external grant should not produce a finding: %+v", finding)
		}
		if finding.ResourceARN == publicBucket {
			t.Fatalf("wildcard public grant fully denied by wildcard Deny should not produce a finding: %+v", finding)
		}
	}
	foundPartial := false
	foundConditional := false
	for _, finding := range findings {
		if finding.ExternalPrincipalARN == partiallyDeniedPrincipal {
			foundPartial = true
		}
		if finding.ExternalPrincipalARN == conditionallyDeniedPrincipal {
			foundConditional = true
		}
	}
	if !foundPartial {
		t.Fatalf("partial Deny should not suppress the remaining allowed cross-account grant: %+v", findings)
	}
	if !foundConditional {
		t.Fatalf("conditional Deny should not suppress the cross-account grant outside the denied condition: %+v", findings)
	}
}

func TestGetAWSCrossAccountTrustFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 10, 0, 0, time.UTC)
	svc, ws := newCrossAccountTrustService(t, "project-cross-account-trust-states", now)

	denied, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-states", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || denied.Confidence != 0 || len(denied.Findings) != 0 {
		t.Fatalf("expected blocked permission-denied state with no findings: %+v", denied)
	}

	degraded, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-states", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("degraded: %v", err)
	}
	if degraded.Status != "degraded" || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded status with diagnostics: %+v", degraded)
	}
	if len(degraded.Findings) == 0 {
		t.Fatalf("degraded sources should keep partial external-access evidence visible: %+v", degraded)
	}

	empty, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-states", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "ready" || len(empty.Findings) != 0 || empty.Summary.TotalFindings != 0 {
		t.Fatalf("empty fixture should be a ready no-findings result: %+v", empty)
	}
}

func TestAWSCrossAccountTrustRuntimeAssumptionFinding(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 15, 0, 0, time.UTC)
	record := AWSRuntimeEventRecord{
		EventID:             "evt-cross-account-assume",
		AccountID:           "222222222222",
		Region:              "us-east-1",
		EventName:           "AssumeRole",
		Action:              "sts:AssumeRole",
		ActorPrincipalARN:   "arn:aws:iam::111111111111:role/partner-deployer",
		ActorIdentityNodeID: "aws:identity:arn:aws:iam::111111111111:role/partner-deployer",
		Session: AWSRuntimeEventSession{
			OriginalActorARN: "arn:aws:iam::111111111111:role/partner-deployer",
			AssumedRoleARN:   "arn:aws:iam::222222222222:role/prod-deploy",
			SourceIdentity:   "partner-change-123",
		},
		EvidenceRef: "runtime-evidence://evt-cross-account-assume",
		Confidence:  0.9,
		ObservedAt:  now,
	}

	finding, ok := awsCrossAccountTrustFindingFromRuntimeAssumption(record, nil, now)
	if !ok {
		t.Fatalf("expected cross-account AssumeRole runtime event to produce finding")
	}
	if finding.FindingType != "runtime_cross_account_assumption" || !finding.RuntimeObserved {
		t.Fatalf("unexpected runtime finding: %+v", finding)
	}
	if finding.ExternalPrincipalAccount != "111111111111" || finding.AccountID != "222222222222" {
		t.Fatalf("expected actor/target accounts to be preserved, got %+v", finding)
	}
	if !finding.HasCondition || len(finding.ConditionKeys) == 0 {
		t.Fatalf("expected SourceIdentity to be surfaced as trust context, got %+v", finding)
	}

	federated := record
	federated.EventID = "evt-cross-account-assume-saml"
	federated.EventName = "AssumeRoleWithSAML"
	federated.Action = "sts:AssumeRoleWithSAML"
	federated.ActorPrincipalARN = "saml:namequalifier:corp"
	federated.ActorIdentityNodeID = "aws:identity:saml:namequalifier:corp"
	federated.Session.OriginalActorARN = "saml:namequalifier:corp"
	federated.Session.AssumedRoleARN = "arn:aws:iam::222222222222:role/prod-deploy"
	finding, ok = awsCrossAccountTrustFindingFromRuntimeAssumption(federated, nil, now)
	if !ok {
		t.Fatalf("expected cross-account federated AssumeRole event to produce finding")
	}
	if finding.ExternalPrincipalARN != "saml:namequalifier:corp" || finding.ExternalPrincipalAccount != "" {
		t.Fatalf("expected SAML provider identity without AWS account, got %+v", finding)
	}

	webIdentity := record
	webIdentity.EventID = "evt-cross-account-assume-web-identity"
	webIdentity.EventName = "AssumeRoleWithWebIdentity"
	webIdentity.Action = "sts:AssumeRoleWithWebIdentity"
	webIdentity.ActorPrincipalARN = "arn:aws:iam::222222222222:oidc-provider/accounts.google.com"
	webIdentity.ActorIdentityNodeID = "aws:identity:arn:aws:iam::222222222222:oidc-provider/accounts.google.com"
	webIdentity.Session.OriginalActorARN = "arn:aws:iam::222222222222:oidc-provider/accounts.google.com"
	webIdentity.Session.SourceIdentity = "oidc:alice"
	finding, ok = awsCrossAccountTrustFindingFromRuntimeAssumption(webIdentity, nil, now)
	if !ok {
		t.Fatalf("expected same-account WebIdentity provider ARN to produce runtime finding")
	}
	if finding.ExternalPrincipalARN != "arn:aws:iam::222222222222:oidc-provider/accounts.google.com" || finding.ExternalPrincipalAccount != "" {
		t.Fatalf("expected WebIdentity provider ARN without AWS account attribution, got %+v", finding)
	}
}

func TestGetAWSCrossAccountTrustRequestsSTSSessionRuntimeEvidence(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 20, 0, 0, time.UTC)
	projectID := "project-cross-account-trust-live-runtime"
	ctx := defaultScopeContext()
	store := db.NewMemoryStore()
	seedDefaultProject(t, store, ctx, projectID)
	seedAWSConnectorForScanTest(t, store, ctx, projectID, "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, projectID, "aws-prod")

	actorARN := "arn:aws:iam::111111111111:role/partner-deployer"
	targetARN := "arn:aws:iam::222222222222:role/prod-deploy"
	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "ready",
		Records: []AWSRuntimeEventRecord{{
			EventID:             "evt-live-cross-account-assume",
			AccountID:           "222222222222",
			Region:              "us-east-1",
			EventType:           "sts-session",
			EventSource:         "sts.amazonaws.com",
			EventName:           "AssumeRole",
			Action:              "sts:AssumeRole",
			ActorPrincipalARN:   actorARN,
			ActorPrincipalType:  "assumed_role",
			ActorIdentityNodeID: awsIdentityNodeIDForAPI(actorARN),
			Session: AWSRuntimeEventSession{
				SessionID:        "ASIAEXAMPLESESSION",
				PrincipalARN:     actorARN,
				AssumedRoleARN:   targetARN,
				OriginalActorARN: actorARN,
				SourceIdentity:   "partner-change-123",
				StartedAt:        now.Add(-5 * time.Minute),
			},
			TargetResourceARN:  targetARN,
			TargetResourceType: "AWS::IAM::Role",
			TargetResourceName: "prod-deploy",
			ResourceNodeID:     awsRuntimeEventResourceNodeID(targetARN, "AWS::IAM::Role"),
			Owner:              "security",
			EvidenceCategory:   "cloudtrail",
			EvidenceRef:        "runtime-evidence://222222222222/us-east-1/evt-live-cross-account-assume",
			Confidence:         0.9,
			ObservedAt:         now.Add(-3 * time.Minute),
			CollectedAt:        now,
			Status:             "observed",
			NextAction:         awsRuntimeEventNextAction("sts-session"),
			RedactionBoundary:  "metadata_only_no_payloads_no_secret_values",
		}},
	}}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	result, err := svc.GetAWSCrossAccountTrust(ctx, "default", projectID, AWSCrossAccountTrustRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get cross-account trust: %v", err)
	}
	if len(fake.calls) == 0 || fake.calls[0].EventSourceFilter != "sts.amazonaws.com" {
		t.Fatalf("expected cross-account trust runtime source to request STS sessions, got %+v", fake.calls)
	}
	if result.Summary.RuntimeObservedCount == 0 || result.Summary.FindingTypeCounts["runtime_cross_account_assumption"] == 0 {
		t.Fatalf("expected live STS session to produce a runtime cross-account finding, got summary=%+v", result.Summary)
	}
}

func TestGetAWSCrossAccountTrustSuppressesFixturesForLiveRequests(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 25, 0, 0, time.UTC)
	svc, ws := newCrossAccountTrustService(t, "project-cross-account-trust-no-runtime-fixtures", now)

	result, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-no-runtime-fixtures", AWSCrossAccountTrustRequest{
		ConnectorID: "aws-prod",
	})
	if err != nil {
		t.Fatalf("get cross-account trust: %v", err)
	}
	if result.FixtureState != "" {
		t.Fatalf("live request should not report an explicit fixture state, got %q", result.FixtureState)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("live request without live trust sources should not promote fixture findings: %+v", result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.FindingType == "runtime_cross_account_assumption" {
			t.Fatalf("live request without CloudTrail ingester should not promote runtime fixtures: %+v", finding)
		}
	}
}
