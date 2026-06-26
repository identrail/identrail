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
	listRolesErr     error
	listUsersErr     error
	listAccessKeyErr error
	getAccessKeyErr  error
	getStatus        iamtypes.JobStatusType
	truncated        bool
	emptyRoles       bool
	emptyUsers       bool
	neverUsedRole    bool
	neverUsedService bool
	roleCreationDate *time.Time
	keyLastUsedDate  *time.Time
}

func (f fakeIAMAPI) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if f.listRolesErr != nil {
		return nil, f.listRolesErr
	}
	if f.emptyRoles {
		return &iam.ListRolesOutput{}, nil
	}
	role := iamtypes.Role{
		Arn:        awsv2.String("arn:aws:iam::123456789012:role/payments-worker"),
		RoleName:   awsv2.String("payments-worker"),
		CreateDate: f.roleCreationDate,
	}
	if !f.neverUsedRole {
		lastUsed := time.Date(2026, 6, 17, 9, 0, 0, 0, time.UTC)
		role.RoleLastUsed = &iamtypes.RoleLastUsed{
			LastUsedDate: &lastUsed,
			Region:       awsv2.String("us-east-1"),
		}
	}
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{role}}, nil
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
	service := iamtypes.ServiceLastAccessed{
		ServiceName:      awsv2.String("Amazon S3"),
		ServiceNamespace: awsv2.String("s3"),
	}
	if !f.neverUsedService {
		service.LastAuthenticated = &lastAuthenticated
		service.LastAuthenticatedEntity = awsv2.String("arn:aws:iam::123456789012:role/payments-worker")
		service.LastAuthenticatedRegion = awsv2.String("us-east-1")
	}
	return &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus:            status,
		JobCompletionDate:    &completedAt,
		IsTruncated:          f.truncated,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{service},
	}, nil
}

func (f fakeIAMAPI) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	if f.listUsersErr != nil {
		return nil, f.listUsersErr
	}
	if f.emptyUsers {
		return &iam.ListUsersOutput{}, nil
	}
	return &iam.ListUsersOutput{Users: []iamtypes.User{{
		Arn:      awsv2.String("arn:aws:iam::123456789012:user/orders-ci"),
		UserName: awsv2.String("orders-ci"),
	}}}, nil
}

func (f fakeIAMAPI) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if f.listAccessKeyErr != nil {
		return nil, f.listAccessKeyErr
	}
	createdAt := time.Date(2026, 1, 8, 9, 0, 0, 0, time.UTC)
	accessKeyID := "AKIA" + "ORDERS123456"
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: []iamtypes.AccessKeyMetadata{{
		AccessKeyId: awsv2.String(accessKeyID),
		CreateDate:  &createdAt,
		Status:      iamtypes.StatusTypeActive,
		UserName:    awsv2.String("orders-ci"),
	}}}, nil
}

func (f fakeIAMAPI) GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if f.getAccessKeyErr != nil {
		return nil, f.getAccessKeyErr
	}
	lastUsed := f.keyLastUsedDate
	if lastUsed == nil {
		defaultLastUsed := time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)
		lastUsed = &defaultLastUsed
	}
	return &iam.GetAccessKeyLastUsedOutput{
		UserName: awsv2.String("orders-ci"),
		AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{
			LastUsedDate: lastUsed,
			Region:       awsv2.String("us-east-1"),
			ServiceName:  awsv2.String("Amazon S3"),
		},
	}, nil
}

type fakeAccessAnalyzerAPI struct {
	listAnalyzersErr  error
	listFindingsErr   error
	listFindingsV2Err error
	emptyAnalyzers    bool
	analyzerType      accessanalyzertypes.Type
	findings          []accessanalyzertypes.FindingSummary
	findingsV2        []accessanalyzertypes.FindingSummaryV2
}

func (f fakeAccessAnalyzerAPI) ListAnalyzers(context.Context, *accessanalyzer.ListAnalyzersInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
	if f.listAnalyzersErr != nil {
		return nil, f.listAnalyzersErr
	}
	if f.emptyAnalyzers {
		return &accessanalyzer.ListAnalyzersOutput{}, nil
	}
	createdAt := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	return &accessanalyzer.ListAnalyzersOutput{
		Analyzers: []accessanalyzertypes.AnalyzerSummary{{
			Arn:       awsv2.String("arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account"),
			CreatedAt: &createdAt,
			Name:      awsv2.String("account"),
			Status:    accessanalyzertypes.AnalyzerStatusActive,
			Type:      firstNonEmptyAnalyzerType(f.analyzerType, accessanalyzertypes.TypeAccount),
		}},
	}, nil
}

func (f fakeAccessAnalyzerAPI) ListFindings(context.Context, *accessanalyzer.ListFindingsInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListFindingsOutput, error) {
	if f.listFindingsErr != nil {
		return nil, f.listFindingsErr
	}
	if f.findings != nil {
		return &accessanalyzer.ListFindingsOutput{Findings: f.findings}, nil
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

func (f fakeAccessAnalyzerAPI) ListFindingsV2(context.Context, *accessanalyzer.ListFindingsV2Input, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListFindingsV2Output, error) {
	if f.listFindingsV2Err != nil {
		return nil, f.listFindingsV2Err
	}
	if f.findingsV2 != nil {
		return &accessanalyzer.ListFindingsV2Output{Findings: f.findingsV2}, nil
	}
	createdAt := time.Date(2026, 6, 12, 11, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 6, 18, 6, 30, 0, 0, time.UTC)
	analyzedAt := time.Date(2026, 6, 18, 6, 0, 0, 0, time.UTC)
	return &accessanalyzer.ListFindingsV2Output{
		Findings: []accessanalyzertypes.FindingSummaryV2{{
			AnalyzedAt:           &analyzedAt,
			CreatedAt:            &createdAt,
			Id:                   awsv2.String("finding-v2-1"),
			ResourceOwnerAccount: awsv2.String("123456789012"),
			ResourceType:         accessanalyzertypes.ResourceTypeAwsIamRole,
			Status:               accessanalyzertypes.FindingStatusActive,
			UpdatedAt:            &updatedAt,
			FindingType:          accessanalyzertypes.FindingTypeInternalAccess,
			Resource:             awsv2.String("arn:aws:iam::123456789012:role/payments-worker"),
		}},
	}, nil
}

func firstNonEmptyAnalyzerType(values ...accessanalyzertypes.Type) accessanalyzertypes.Type {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
	var roleLastUsed, serviceLastUsed, accessKeyLastUsed, analyzerFinding *Signal
	for idx := range result.Signals {
		signal := &result.Signals[idx]
		switch {
		case signal.EventID == "iam-role-last-used:arn-aws-iam-123456789012-role-payments-worker":
			roleLastUsed = signal
		case signal.EventID == "iam-service-last-used:arn-aws-iam-123456789012-role-payments-worker:s3":
			serviceLastUsed = signal
		case signal.EventID == "iam-access-key-last-used:"+"akia"+"orders123456":
			accessKeyLastUsed = signal
		case strings.HasPrefix(signal.EventID, "access-analyzer:"):
			analyzerFinding = signal
		}
	}
	if roleLastUsed == nil || serviceLastUsed == nil || accessKeyLastUsed == nil || analyzerFinding == nil {
		t.Fatalf("expected role, service, access-key, and analyzer signals, got %+v", result.Signals)
	}
	if roleLastUsed.Category != "iam-last-used" || roleLastUsed.Scope != "role" || !roleLastUsed.StaleAt.Equal(collectedAt) {
		t.Fatalf("unexpected role last-used signal: %+v", roleLastUsed)
	}
	if serviceLastUsed.TargetResourceARN != "aws-service://s3" || serviceLastUsed.Scope != "service" || serviceLastUsed.StaleAt.IsZero() {
		t.Fatalf("unexpected service last-used signal: %+v", serviceLastUsed)
	}
	if accessKeyLastUsed.Scope != "access-key" || accessKeyLastUsed.TargetResourceType != "iam_access_key" || accessKeyLastUsed.TargetResourceName != "AKIA"+"ORDERS123456" {
		t.Fatalf("unexpected access-key last-used signal: %+v", accessKeyLastUsed)
	}
	if analyzerFinding.Category != "access-analyzer" || analyzerFinding.Scope != "account" || analyzerFinding.AnalyzerARN == "" || analyzerFinding.StaleAt.IsZero() || analyzerFinding.Confidence < 0.89 {
		t.Fatalf("unexpected Access Analyzer signal: %+v", analyzerFinding)
	}
}

func TestIngesterSkipsCrossAccountAccessAnalyzerFindings(t *testing.T) {
	collectedAt := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	createdAt := time.Date(2026, 6, 12, 11, 0, 0, 0, time.UTC)
	findings := []accessanalyzertypes.FindingSummary{
		{
			CreatedAt:            &createdAt,
			Id:                   awsv2.String("same-account"),
			ResourceOwnerAccount: awsv2.String("123456789012"),
			ResourceType:         accessanalyzertypes.ResourceTypeAwsSecretsmanagerSecret,
			Status:               accessanalyzertypes.FindingStatusActive,
			Action:               []string{"secretsmanager:GetSecretValue"},
			Principal:            map[string]string{"AWS": "arn:aws:iam::210987654321:root"},
			Resource:             awsv2.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/payments"),
		},
		{
			CreatedAt:            &createdAt,
			Id:                   awsv2.String("member-account"),
			ResourceOwnerAccount: awsv2.String("999999999999"),
			ResourceType:         accessanalyzertypes.ResourceTypeAwsSecretsmanagerSecret,
			Status:               accessanalyzertypes.FindingStatusActive,
			Action:               []string{"secretsmanager:GetSecretValue"},
			Principal:            map[string]string{"AWS": "arn:aws:iam::210987654321:root"},
			Resource:             awsv2.String("arn:aws:secretsmanager:us-east-1:999999999999:secret:prod/other"),
		},
	}
	result, err := New(fakeIAMAPI{emptyRoles: true, emptyUsers: true}, fakeAccessAnalyzerAPI{
		analyzerType: accessanalyzertypes.TypeOrganization,
		findings:     findings,
	}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: collectedAt,
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready same-account analyzer result, got %+v", result)
	}
	if len(result.Signals) != 1 {
		t.Fatalf("expected only same-account analyzer finding, got %+v", result.Signals)
	}
	if result.Signals[0].AccountID != "123456789012" || !strings.Contains(result.Signals[0].EventID, "same-account") {
		t.Fatalf("expected retained finding to belong to connector account, got %+v", result.Signals[0])
	}
}

func TestIngesterUsesFindingsV2ForInternalAccessAnalyzers(t *testing.T) {
	collectedAt := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	result, err := New(fakeIAMAPI{emptyRoles: true, emptyUsers: true}, fakeAccessAnalyzerAPI{
		analyzerType:    accessanalyzertypes.TypeAccountInternalAccess,
		listFindingsErr: errors.New("legacy ListFindings should not be called"),
	}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: collectedAt,
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready internal analyzer result, got %+v", result)
	}
	if len(result.Signals) != 1 {
		t.Fatalf("expected one internal analyzer finding, got %+v", result.Signals)
	}
	finding := result.Signals[0]
	if finding.EventName != string(accessanalyzertypes.FindingTypeInternalAccess) || finding.Scope != strings.ToLower(string(accessanalyzertypes.TypeAccountInternalAccess)) {
		t.Fatalf("expected internal analyzer finding from ListFindingsV2, got %+v", finding)
	}
	if finding.ActorPrincipalType != "access_analyzer" || finding.ActorPrincipalARN == "access-analyzer:external-principal" {
		t.Fatalf("expected V2 internal analyzer finding to stay analyzer-scoped, got %+v", finding)
	}
	if finding.TargetResourceARN != "arn:aws:iam::123456789012:role/payments-worker" || finding.TargetResourceType != string(accessanalyzertypes.ResourceTypeAwsIamRole) {
		t.Fatalf("expected normalized V2 resource details, got %+v", finding)
	}
}

func TestIngesterDoesNotMarkNewNeverUsedRolesStale(t *testing.T) {
	collectedAt := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	createdAt := collectedAt.Add(-2 * time.Hour)
	result, err := New(fakeIAMAPI{neverUsedRole: true, roleCreationDate: &createdAt}, fakeAccessAnalyzerAPI{emptyAnalyzers: true}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: collectedAt,
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	var neverUsedRole *Signal
	for idx := range result.Signals {
		if strings.HasPrefix(result.Signals[idx].EventID, "iam-role-never-used:") {
			neverUsedRole = &result.Signals[idx]
			break
		}
	}
	if neverUsedRole == nil {
		t.Fatalf("expected role-never-used signal, got %+v", result.Signals)
	}
	if neverUsedRole.Status != "unknown" {
		t.Fatalf("new never-used role should remain unknown until dormant threshold, got %+v", neverUsedRole)
	}
	if !neverUsedRole.ObservedAt.Equal(createdAt) {
		t.Fatalf("expected creation date as observed_at, got %+v", neverUsedRole)
	}
}

func TestIngesterDoesNotMarkNewNeverAccessedServicesStale(t *testing.T) {
	collectedAt := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	createdAt := collectedAt.Add(-2 * time.Hour)
	result, err := New(fakeIAMAPI{neverUsedRole: true, neverUsedService: true, roleCreationDate: &createdAt}, fakeAccessAnalyzerAPI{emptyAnalyzers: true}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: collectedAt,
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	var neverAccessedService *Signal
	for idx := range result.Signals {
		if result.Signals[idx].EventName == "ServiceNeverAccessed" {
			neverAccessedService = &result.Signals[idx]
			break
		}
	}
	if neverAccessedService == nil {
		t.Fatalf("expected service-never-accessed signal, got %+v", result.Signals)
	}
	if neverAccessedService.Status != "unknown" {
		t.Fatalf("new never-accessed service should remain unknown until dormant threshold, got %+v", neverAccessedService)
	}
	if !neverAccessedService.ObservedAt.Equal(createdAt) {
		t.Fatalf("expected role creation date as observed_at, got %+v", neverAccessedService)
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

func TestIngesterDegradesWhenAccessAnalyzerHasNoAnalyzers(t *testing.T) {
	result, err := New(fakeIAMAPI{}, fakeAccessAnalyzerAPI{emptyAnalyzers: true}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ingest signals: %v", err)
	}
	if result.Status != "degraded" || len(result.Signals) == 0 {
		t.Fatalf("expected IAM signals with degraded analyzer coverage, got %+v", result)
	}
	if !hasCoverageGap(result.CoverageGaps, "access_analyzer", "empty") {
		t.Fatalf("expected empty Access Analyzer coverage gap, got %+v", result.CoverageGaps)
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

func TestIngesterPropagatesContextCancellation(t *testing.T) {
	for _, wantErr := range []error{context.Canceled, context.DeadlineExceeded} {
		result, err := New(fakeIAMAPI{listRolesErr: wantErr}, fakeAccessAnalyzerAPI{}).Ingest(context.Background(), IngestRequest{
			AccountID:   "123456789012",
			Region:      "us-east-1",
			CollectedAt: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v to propagate, got err=%v result=%+v", wantErr, err, result)
		}
	}
}

func TestIngesterReportsPermissionDeniedCoverage(t *testing.T) {
	result, err := New(fakeIAMAPI{listRolesErr: errors.New("AccessDenied: not authorized"), listUsersErr: errors.New("AccessDenied: not authorized")}, fakeAccessAnalyzerAPI{listAnalyzersErr: errors.New("AccessDeniedException")}).Ingest(context.Background(), IngestRequest{
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
	if len(result.Diagnostics) != 3 || len(result.CoverageGaps) != 3 {
		t.Fatalf("expected IAM and Access Analyzer diagnostics/gaps, got %+v", result)
	}
	for _, diagnostic := range result.Diagnostics {
		if !strings.Contains(diagnostic.Code, "permission_denied") {
			t.Fatalf("expected permission-aware diagnostic, got %+v", diagnostic)
		}
	}
}

func TestIngesterCollectsAccessKeysWhenRoleListingDenied(t *testing.T) {
	result, err := New(fakeIAMAPI{listRolesErr: errors.New("AccessDenied: not authorized")}, fakeAccessAnalyzerAPI{emptyAnalyzers: true}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ingest role-denied signals: %v", err)
	}
	if result.Status != "degraded" || len(result.Signals) == 0 {
		t.Fatalf("expected degraded result with access-key signals, got %+v", result)
	}
	for _, signal := range result.Signals {
		if signal.Scope == "access-key" && signal.TargetResourceType == "iam_access_key" {
			return
		}
	}
	t.Fatalf("expected access-key signal despite role listing denial, got %+v", result.Signals)
}

func TestIngesterBlocksWhenIAMAndAnalyzerFindingsAreDenied(t *testing.T) {
	result, err := New(fakeIAMAPI{listRolesErr: errors.New("AccessDenied: not authorized"), listUsersErr: errors.New("AccessDenied: not authorized")}, fakeAccessAnalyzerAPI{listFindingsErr: errors.New("AccessDeniedException")}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ingest denied findings signals: %v", err)
	}
	if result.Status != "blocked" || len(result.Signals) != 0 {
		t.Fatalf("expected blocked result when both sources are permission denied, got %+v", result)
	}
	if !hasCoverageGap(result.CoverageGaps, "iam_last_used", "permission_denied") || !hasCoverageGap(result.CoverageGaps, "access_analyzer", "permission_denied") {
		t.Fatalf("expected IAM and Access Analyzer permission coverage gaps, got %+v", result.CoverageGaps)
	}
}

func TestIngesterDoesNotBlockWhenOnlyOneCollectorIsDenied(t *testing.T) {
	result, err := New(fakeIAMAPI{emptyRoles: true, emptyUsers: true}, fakeAccessAnalyzerAPI{listAnalyzersErr: errors.New("AccessDeniedException")}).Ingest(context.Background(), IngestRequest{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		CollectedAt: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ingest mixed coverage signals: %v", err)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected partial coverage to stay degraded instead of blocked, got %+v", result)
	}
	if !hasCoverageGap(result.CoverageGaps, "access_analyzer", "permission_denied") {
		t.Fatalf("expected denied Access Analyzer coverage gap, got %+v", result.CoverageGaps)
	}
	if hasCoverageGap(result.CoverageGaps, "iam_last_used", "permission_denied") {
		t.Fatalf("IAM collector was reachable and must not be treated as denied, got %+v", result.CoverageGaps)
	}
}

func hasCoverageGap(gaps []CoverageGap, capability string, status string) bool {
	for _, gap := range gaps {
		if gap.Capability == capability && gap.Status == status {
			return true
		}
	}
	return false
}
