package awssignals

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeIAMAPI struct {
	listRolesErr error
	getStatus    iamtypes.JobStatusType
	truncated    bool
}

func (f fakeIAMAPI) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if f.listRolesErr != nil {
		return nil, f.listRolesErr
	}
	lastUsed := time.Date(2026, 6, 17, 9, 0, 0, 0, time.UTC)
	return &iam.ListRolesOutput{
		Roles: []iamtypes.Role{{
			Arn:      awsv2.String("arn:aws:iam::123456789012:role/payments-worker"),
			RoleName: awsv2.String("payments-worker"),
			RoleLastUsed: &iamtypes.RoleLastUsed{
				LastUsedDate: &lastUsed,
				Region:       awsv2.String("us-east-1"),
			},
		}},
	}, nil
}

func (f fakeIAMAPI) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: awsv2.String("job-123")}, nil
}

func (f fakeIAMAPI) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	status := f.getStatus
	if status == "" {
		status = iamtypes.JobStatusTypeCompleted
	}
	completedAt := time.Date(2026, 6, 18, 8, 0, 0, 0, time.UTC)
	lastAuthenticated := time.Date(2026, 6, 16, 7, 30, 0, 0, time.UTC)
	return &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus:         status,
		JobCompletionDate: &completedAt,
		IsTruncated:       f.truncated,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{{
			ServiceName:             awsv2.String("Amazon S3"),
			ServiceNamespace:        awsv2.String("s3"),
			LastAuthenticated:       &lastAuthenticated,
			LastAuthenticatedEntity: awsv2.String("arn:aws:iam::123456789012:role/payments-worker"),
			LastAuthenticatedRegion: awsv2.String("us-east-1"),
		}},
	}, nil
}

type fakeAccessAnalyzerAPI struct {
	listAnalyzersErr error
	listFindingsErr  error
}

func (f fakeAccessAnalyzerAPI) ListAnalyzers(context.Context, *accessanalyzer.ListAnalyzersInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
	if f.listAnalyzersErr != nil {
		return nil, f.listAnalyzersErr
	}
	createdAt := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	return &accessanalyzer.ListAnalyzersOutput{
		Analyzers: []accessanalyzertypes.AnalyzerSummary{{
			Arn:       awsv2.String("arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account"),
			CreatedAt: &createdAt,
			Name:      awsv2.String("account"),
			Status:    accessanalyzertypes.AnalyzerStatusActive,
			Type:      accessanalyzertypes.TypeAccount,
		}},
	}, nil
}

func (f fakeAccessAnalyzerAPI) ListFindings(context.Context, *accessanalyzer.ListFindingsInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListFindingsOutput, error) {
	if f.listFindingsErr != nil {
		return nil, f.listFindingsErr
	}
	createdAt := time.Date(2026, 6, 12, 11, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 6, 18, 6, 30, 0, 0, time.UTC)
	analyzedAt := time.Date(2026, 6, 18, 6, 0, 0, 0, time.UTC)
	return &accessanalyzer.ListFindingsOutput{
		Findings: []accessanalyzertypes.FindingSummary{{
			AnalyzedAt:           &analyzedAt,
			CreatedAt:            &createdAt,
			Id:                   awsv2.String("finding-1"),
			ResourceOwnerAccount: awsv2.String("123456789012"),
			ResourceType:         accessanalyzertypes.ResourceTypeAwsSecretsmanagerSecret,
			Status:               accessanalyzertypes.FindingStatusActive,
			UpdatedAt:            &updatedAt,
			Action:               []string{"secretsmanager:GetSecretValue"},
			IsPublic:             awsv2.Bool(true),
			Principal:            map[string]string{"AWS": "arn:aws:iam::210987654321:root"},
			Resource:             awsv2.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/payments"),
		}},
	}, nil
}

func TestIngesterCollectsIAMLastUsedAndAccessAnalyzerSignals(t *testing.T) {
	collectedAt := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	result, err := New(fakeIAMAPI{}, fakeAccessAnalyzerAPI{}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: collectedAt,
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	if result.Status != "ready" || len(result.Diagnostics) != 0 || len(result.CoverageGaps) != 0 {
		t.Fatalf("expected ready metadata-only signal result, got %+v", result)
	}
	var roleLastUsed, serviceLastUsed, analyzerFinding *Signal
	for idx := range result.Signals {
		signal := &result.Signals[idx]
		switch {
		case signal.EventID == "iam-role-last-used:arn-aws-iam-123456789012-role-payments-worker":
			roleLastUsed = signal
		case signal.EventID == "iam-service-last-used:arn-aws-iam-123456789012-role-payments-worker:s3":
			serviceLastUsed = signal
		case strings.HasPrefix(signal.EventID, "access-analyzer:"):
			analyzerFinding = signal
		}
	}
	if roleLastUsed == nil || serviceLastUsed == nil || analyzerFinding == nil {
		t.Fatalf("expected role, service, and analyzer signals, got %+v", result.Signals)
	}
	if roleLastUsed.Category != "iam-last-used" || roleLastUsed.Scope != "role" || !roleLastUsed.StaleAt.Equal(collectedAt) {
		t.Fatalf("unexpected role last-used signal: %+v", roleLastUsed)
	}
	if serviceLastUsed.TargetResourceARN != "aws-service://s3" || serviceLastUsed.Scope != "service" || serviceLastUsed.StaleAt.IsZero() {
		t.Fatalf("unexpected service last-used signal: %+v", serviceLastUsed)
	}
	if analyzerFinding.Category != "access-analyzer" || analyzerFinding.Scope != "account" || analyzerFinding.AnalyzerARN == "" || analyzerFinding.StaleAt.IsZero() || analyzerFinding.Confidence < 0.89 {
		t.Fatalf("unexpected Access Analyzer signal: %+v", analyzerFinding)
	}
}

func TestIngesterDegradesWhenCoverageGapsAreEmitted(t *testing.T) {
	collectedAt := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	result, err := New(fakeIAMAPI{truncated: true}, fakeAccessAnalyzerAPI{}).Ingest(context.Background(), IngestRequest{
		AccountID:          "123456789012",
		Region:             "us-east-1",
		CollectedAt:        collectedAt,
		MaxServicesPerRole: 1,
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected coverage gap to degrade signal result, got %+v", result)
	}
	foundServiceGap := false
	for _, gap := range result.CoverageGaps {
		if gap.Capability == "iam_last_used" && gap.Status == "history_truncated" && strings.Contains(gap.Reason, "service budget") {
			foundServiceGap = true
		}
	}
	if !foundServiceGap {
		t.Fatalf("expected service report truncation coverage gap, got %+v", result.CoverageGaps)
	}
	if len(result.Signals) == 0 {
		t.Fatalf("expected retained signal rows alongside degraded coverage, got %+v", result)
	}
}

type pollingIAMAPI struct {
	fakeIAMAPI
	statuses []iamtypes.JobStatusType
	calls    int
}

func (f *pollingIAMAPI) GetServiceLastAccessedDetails(ctx context.Context, input *iam.GetServiceLastAccessedDetailsInput, options ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	f.calls++
	status := iamtypes.JobStatusTypeInProgress
	if f.calls <= len(f.statuses) {
		status = f.statuses[f.calls-1]
	}
	if status != iamtypes.JobStatusTypeCompleted {
		return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: status}, nil
	}
	return f.fakeIAMAPI.GetServiceLastAccessedDetails(ctx, input, options...)
}

func TestIngesterPollsPendingIAMLastUsedReport(t *testing.T) {
	iamAPI := &pollingIAMAPI{statuses: []iamtypes.JobStatusType{
		iamtypes.JobStatusTypeInProgress,
		iamtypes.JobStatusTypeCompleted,
	}}
	result, err := New(iamAPI, fakeAccessAnalyzerAPI{}).Ingest(context.Background(), IngestRequest{
		AccountID:          "123456789012",
		Region:             "us-east-1",
		CollectedAt:        time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
		MaxReportPolls:     2,
		ReportPollInterval: -1,
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	if iamAPI.calls != 2 {
		t.Fatalf("expected pending report to be polled with the same job ID, got %d calls", iamAPI.calls)
	}
	for _, signal := range result.Signals {
		if signal.EventID == "iam-service-last-used:arn-aws-iam-123456789012-role-payments-worker:s3" {
			return
		}
	}
	t.Fatalf("expected service last-used signal after polling, got %+v", result.Signals)
}

func TestIngesterReportsPermissionDeniedCoverage(t *testing.T) {
	result, err := New(fakeIAMAPI{listRolesErr: errors.New("AccessDenied: not authorized")}, fakeAccessAnalyzerAPI{listAnalyzersErr: errors.New("AccessDeniedException")}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ingest denied signals: %v", err)
	}
	if result.Status != "blocked" || len(result.Signals) != 0 {
		t.Fatalf("expected blocked result without partial signal leakage, got %+v", result)
	}
	if len(result.Diagnostics) != 2 || len(result.CoverageGaps) != 2 {
		t.Fatalf("expected IAM and Access Analyzer diagnostics/gaps, got %+v", result)
	}
	for _, diagnostic := range result.Diagnostics {
		if !strings.Contains(diagnostic.Code, "permission_denied") {
			t.Fatalf("expected permission-aware diagnostic, got %+v", diagnostic)
		}
	}
}
