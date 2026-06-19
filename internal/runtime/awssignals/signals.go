package awssignals

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	CollectorName     = "aws_iam_access_signals"
	RedactionBoundary = "metadata_only_no_payloads_no_secret_values"
	dormantAccessAge  = 90 * 24 * time.Hour
)

type IAMAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error)
	GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error)
}

type AccessAnalyzerAPI interface {
	ListAnalyzers(context.Context, *accessanalyzer.ListAnalyzersInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error)
	ListFindings(context.Context, *accessanalyzer.ListFindingsInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListFindingsOutput, error)
	ListFindingsV2(context.Context, *accessanalyzer.ListFindingsV2Input, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListFindingsV2Output, error)
}

type IngestRequest struct {
	AccountID          string
	Region             string
	MaxRoles           int32
	MaxServicesPerRole int32
	MaxAnalyzers       int32
	MaxFindings        int32
	MaxReportPolls     int
	ReportPollInterval time.Duration
	CollectedAt        time.Time
}

type IngestResult struct {
	Signals          []Signal
	Diagnostics      []Diagnostic
	CoverageGaps     []CoverageGap
	Status           string
	FailureReasons   []string
	RemediationHints []string
}

type Signal struct {
	EventID            string
	AccountID          string
	Region             string
	Category           string
	Scope              string
	EventSource        string
	EventName          string
	Action             string
	ActorPrincipalARN  string
	ActorPrincipalType string
	TargetResourceARN  string
	TargetResourceType string
	TargetResourceName string
	AnalyzerARN        string
	AnalyzerName       string
	Status             string
	Confidence         float64
	ObservedAt         time.Time
	CollectedAt        time.Time
	StaleAt            time.Time
}

type Diagnostic struct {
	SourceID    string
	Code        string
	Message     string
	Remediation string
	Retryable   bool
}

type CoverageGap struct {
	Capability  string
	Status      string
	Reason      string
	Remediation string
}

type accessAnalyzerFinding struct {
	ID                   string
	Resource             string
	ResourceOwnerAccount string
	ResourceType         accessanalyzertypes.ResourceType
	Status               accessanalyzertypes.FindingStatus
	Error                string
	FindingType          accessanalyzertypes.FindingType
	Action               []string
	Principal            map[string]string
	IsPublic             *bool
	AnalyzedAt           *time.Time
	CreatedAt            *time.Time
	UpdatedAt            *time.Time
}

type Ingester struct {
	IAM            IAMAPI
	AccessAnalyzer AccessAnalyzerAPI
	Now            func() time.Time
}

func New(iamAPI IAMAPI, analyzerAPI AccessAnalyzerAPI) *Ingester {
	return &Ingester{IAM: iamAPI, AccessAnalyzer: analyzerAPI}
}

func (i *Ingester) Ingest(ctx context.Context, request IngestRequest) (IngestResult, error) {
	now := request.CollectedAt
	if now.IsZero() {
		if i.Now != nil {
			now = i.Now().UTC()
		} else {
			now = time.Now().UTC()
		}
	}
	request.CollectedAt = now
	request.AccountID = firstNonEmpty(request.AccountID, "unknown-account")
	request.Region = firstNonEmpty(request.Region, "global")
	if request.MaxRoles <= 0 {
		request.MaxRoles = 8
	}
	if request.MaxServicesPerRole <= 0 {
		request.MaxServicesPerRole = 8
	}
	if request.MaxAnalyzers <= 0 {
		request.MaxAnalyzers = 4
	}
	if request.MaxFindings <= 0 {
		request.MaxFindings = 20
	}
	if request.MaxReportPolls <= 0 {
		request.MaxReportPolls = 4
	}
	if request.ReportPollInterval == 0 {
		request.ReportPollInterval = 100 * time.Millisecond
	} else if request.ReportPollInterval < 0 {
		request.ReportPollInterval = 0
	}

	result := IngestResult{Status: "ready"}
	if i.IAM != nil {
		signals, diagnostics, gaps, err := i.collectIAMLastUsed(ctx, request)
		if err != nil {
			return IngestResult{}, err
		}
		result.Signals = append(result.Signals, signals...)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
		result.CoverageGaps = append(result.CoverageGaps, gaps...)
	} else {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			SourceID:    "iam",
			Code:        "iam_last_used_source_unavailable",
			Message:     "IAM last-used collection is not configured for this connector.",
			Remediation: "Wire the IAM metadata API before relying on dormant-access signals.",
			Retryable:   true,
		})
		result.CoverageGaps = append(result.CoverageGaps, CoverageGap{
			Capability:  "iam_last_used",
			Status:      "source_unavailable",
			Reason:      "IAM last-used API client is not configured.",
			Remediation: "Configure metadata-only iam:ListRoles and iam:GetServiceLastAccessedDetails access.",
		})
	}
	if i.AccessAnalyzer != nil {
		signals, diagnostics, gaps, err := i.collectAccessAnalyzer(ctx, request)
		if err != nil {
			return IngestResult{}, err
		}
		result.Signals = append(result.Signals, signals...)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
		result.CoverageGaps = append(result.CoverageGaps, gaps...)
	} else {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			SourceID:    "access-analyzer",
			Code:        "access_analyzer_source_unavailable",
			Message:     "Access Analyzer collection is not configured for this connector.",
			Remediation: "Wire the Access Analyzer API before relying on analyzer findings.",
			Retryable:   true,
		})
		result.CoverageGaps = append(result.CoverageGaps, CoverageGap{
			Capability:  "access_analyzer",
			Status:      "source_unavailable",
			Reason:      "Access Analyzer API client is not configured.",
			Remediation: "Configure metadata-only access-analyzer:ListAnalyzers and access-analyzer:ListFindings access.",
		})
	}

	sort.SliceStable(result.Signals, func(a, b int) bool {
		return result.Signals[a].ObservedAt.After(result.Signals[b].ObservedAt)
	})
	if len(result.Signals) == 0 && len(result.Diagnostics) == 0 {
		result.Status = "degraded"
		result.FailureReasons = []string{"IAM last-used and Access Analyzer returned no signals"}
		result.RemediationHints = []string{"Confirm IAM Access Advisor and Access Analyzer are enabled for the account and region."}
		result.CoverageGaps = append(result.CoverageGaps, CoverageGap{
			Capability:  "iam_access_signals",
			Status:      "empty",
			Reason:      "No IAM last-used or Access Analyzer records were available in the bounded scan.",
			Remediation: "Confirm roles exist, Access Analyzer is enabled, and retry collection.",
		})
	}
	if len(result.Diagnostics) > 0 && result.Status == "ready" {
		result.Status = "degraded"
		result.FailureReasons = dedupeStrings(append(result.FailureReasons, "IAM last-used or Access Analyzer returned diagnostics"))
		result.RemediationHints = dedupeStrings(append(result.RemediationHints, "Review signal diagnostics before using runtime evidence for least-privilege decisions."))
	}
	if len(result.CoverageGaps) > 0 && result.Status == "ready" {
		result.Status = "degraded"
		result.FailureReasons = dedupeStrings(append(result.FailureReasons, "IAM last-used or Access Analyzer coverage is partial"))
		result.RemediationHints = dedupeStrings(append(result.RemediationHints, "Review signal coverage gaps before using runtime evidence for least-privilege decisions."))
	}
	if len(result.Signals) == 0 && allSignalCollectorsPermissionDenied(result.CoverageGaps) {
		result.Status = "blocked"
		result.FailureReasons = []string{"IAM last-used and Access Analyzer permissions are unavailable"}
		result.RemediationHints = []string{"Grant metadata-only iam:ListRoles, iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails, access-analyzer:ListAnalyzers, and access-analyzer:ListFindings."}
	}
	return result, nil
}

func (i *Ingester) collectIAMLastUsed(ctx context.Context, request IngestRequest) ([]Signal, []Diagnostic, []CoverageGap, error) {
	out, err := i.IAM.ListRoles(ctx, &iam.ListRolesInput{MaxItems: awsv2.Int32(request.MaxRoles)})
	if err != nil {
		if isContextCancellation(err) {
			return nil, nil, nil, err
		}
		return nil, []Diagnostic{permissionAwareDiagnostic("iam", "iam_last_used_permission_denied", "iam_last_used_failed", fmt.Sprintf("IAM role listing failed: %v", err), "Grant metadata-only iam:ListRoles and retry.", err)}, []CoverageGap{{
			Capability:  "iam_last_used",
			Status:      permissionAwareStatus(err),
			Reason:      "IAM roles could not be listed for last-used collection.",
			Remediation: "Grant iam:ListRoles plus service last-accessed read APIs.",
		}}, nil
	}
	signals := []Signal{}
	diagnostics := []Diagnostic{}
	gaps := []CoverageGap{}
	for idx, role := range out.Roles {
		if int32(idx) >= request.MaxRoles {
			break
		}
		roleARN := awsv2.ToString(role.Arn)
		roleName := awsv2.ToString(role.RoleName)
		if roleARN == "" {
			continue
		}
		if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
			region := firstNonEmpty(awsv2.ToString(role.RoleLastUsed.Region), request.Region)
			lastUsed := role.RoleLastUsed.LastUsedDate.UTC()
			signals = append(signals, Signal{
				EventID:            "iam-role-last-used:" + sanitizeToken(roleARN),
				AccountID:          request.AccountID,
				Region:             region,
				Category:           "iam-last-used",
				Scope:              "role",
				EventSource:        "iam.amazonaws.com",
				EventName:          "RoleLastUsed",
				Action:             "iam:RoleLastUsed",
				ActorPrincipalARN:  roleARN,
				ActorPrincipalType: "iam_role",
				TargetResourceARN:  roleARN,
				TargetResourceType: "iam_role",
				TargetResourceName: roleName,
				Status:             iamLastUsedStatus(lastUsed, request.CollectedAt),
				Confidence:         0.82,
				ObservedAt:         lastUsed,
				CollectedAt:        request.CollectedAt,
				StaleAt:            request.CollectedAt,
			})
		} else {
			status := iamNeverUsedStatus(role.CreateDate, request.CollectedAt)
			confidence := 0.52
			observedAt := request.CollectedAt
			if role.CreateDate != nil {
				observedAt = role.CreateDate.UTC()
			}
			if status == "stale" {
				confidence = 0.68
			}
			signals = append(signals, Signal{
				EventID:            "iam-role-never-used:" + sanitizeToken(roleARN),
				AccountID:          request.AccountID,
				Region:             request.Region,
				Category:           "iam-last-used",
				Scope:              "role",
				EventSource:        "iam.amazonaws.com",
				EventName:          "RoleNeverUsed",
				Action:             "iam:RoleNeverUsed",
				ActorPrincipalARN:  roleARN,
				ActorPrincipalType: "iam_role",
				TargetResourceARN:  roleARN,
				TargetResourceType: "iam_role",
				TargetResourceName: roleName,
				Status:             status,
				Confidence:         confidence,
				ObservedAt:         observedAt,
				CollectedAt:        request.CollectedAt,
				StaleAt:            request.CollectedAt,
			})
		}
		job, genErr := i.IAM.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
			Arn:         awsv2.String(roleARN),
			Granularity: iamtypes.AccessAdvisorUsageGranularityTypeServiceLevel,
		})
		if genErr != nil {
			if isContextCancellation(genErr) {
				return nil, nil, nil, genErr
			}
			diagnostics = append(diagnostics, permissionAwareDiagnostic("iam:"+roleName, "iam_last_used_permission_denied", "iam_last_used_generation_failed", fmt.Sprintf("IAM service last-used report could not be generated for %s: %v", roleName, genErr), "Grant iam:GenerateServiceLastAccessedDetails and retry.", genErr))
			continue
		}
		details, truncated, getErr := i.getServiceLastAccessedDetails(ctx, job.JobId, request)
		if getErr != nil {
			if isContextCancellation(getErr) {
				return nil, nil, nil, getErr
			}
			diagnostics = append(diagnostics, permissionAwareDiagnostic("iam:"+roleName, "iam_last_used_permission_denied", "iam_last_used_report_failed", fmt.Sprintf("IAM service last-used report could not be read for %s: %v", roleName, getErr), "Grant iam:GetServiceLastAccessedDetails and retry.", getErr))
			continue
		}
		if details.JobStatus != iamtypes.JobStatusTypeCompleted {
			diagnostics = append(diagnostics, Diagnostic{
				SourceID:    "iam:" + roleName,
				Code:        "iam_last_used_report_pending",
				Message:     fmt.Sprintf("IAM service last-used report for %s is %s.", roleName, details.JobStatus),
				Remediation: "Retry collection after IAM finishes the report; existing role-last-used evidence remains visible.",
				Retryable:   true,
			})
			gaps = append(gaps, CoverageGap{
				Capability:  "iam_last_used",
				Status:      "partial_failure",
				Reason:      fmt.Sprintf("Service last-used report for %s was not complete.", roleName),
				Remediation: "Retry collection after IAM report completion.",
			})
			continue
		}
		staleAt := request.CollectedAt
		if details.JobCompletionDate != nil {
			staleAt = details.JobCompletionDate.UTC()
		}
		if truncated {
			gaps = append(gaps, CoverageGap{
				Capability:  "iam_last_used",
				Status:      "history_truncated",
				Reason:      fmt.Sprintf("Service last-used report for %s exceeded the bounded per-role service budget.", roleName),
				Remediation: "Rerun with a larger IAM last-used service budget or add paginated report reuse.",
			})
		}
		for svcIdx, service := range details.ServicesLastAccessed {
			if int32(svcIdx) >= request.MaxServicesPerRole {
				break
			}
			serviceNamespace := awsv2.ToString(service.ServiceNamespace)
			serviceName := firstNonEmpty(awsv2.ToString(service.ServiceName), serviceNamespace)
			actor := firstNonEmpty(awsv2.ToString(service.LastAuthenticatedEntity), roleARN)
			region := firstNonEmpty(awsv2.ToString(service.LastAuthenticatedRegion), request.Region)
			lastAuthenticated := request.CollectedAt
			status := iamNeverUsedStatus(role.CreateDate, request.CollectedAt)
			confidence := 0.52
			if service.LastAuthenticated != nil {
				lastAuthenticated = service.LastAuthenticated.UTC()
				status = iamLastUsedStatus(lastAuthenticated, request.CollectedAt)
				confidence = 0.86
				if status == "stale" {
					confidence = 0.78
				}
			} else {
				if role.CreateDate != nil {
					lastAuthenticated = role.CreateDate.UTC()
				}
				if status == "stale" {
					confidence = 0.68
				}
			}
			signals = append(signals, Signal{
				EventID:            "iam-service-last-used:" + sanitizeToken(roleARN) + ":" + sanitizeToken(serviceNamespace),
				AccountID:          request.AccountID,
				Region:             region,
				Category:           "iam-last-used",
				Scope:              "service",
				EventSource:        "iam.amazonaws.com",
				EventName:          serviceLastAccessedEventName(service.LastAuthenticated != nil),
				Action:             serviceLastAccessedAction(serviceNamespace, service.LastAuthenticated != nil),
				ActorPrincipalARN:  actor,
				ActorPrincipalType: principalTypeFromARN(actor),
				TargetResourceARN:  "aws-service://" + serviceNamespace,
				TargetResourceType: "aws_service",
				TargetResourceName: serviceName,
				Status:             status,
				Confidence:         confidence,
				ObservedAt:         lastAuthenticated,
				CollectedAt:        request.CollectedAt,
				StaleAt:            staleAt,
			})
		}
	}
	if out.IsTruncated {
		gaps = append(gaps, CoverageGap{
			Capability:  "iam_last_used",
			Status:      "history_truncated",
			Reason:      "IAM role listing exceeded the bounded per-run role budget.",
			Remediation: "Rerun with a larger IAM last-used role budget or shard by path prefix.",
		})
	}
	return signals, diagnostics, gaps, nil
}

func (i *Ingester) getServiceLastAccessedDetails(ctx context.Context, jobID *string, request IngestRequest) (*iam.GetServiceLastAccessedDetailsOutput, bool, error) {
	var details *iam.GetServiceLastAccessedDetailsOutput
	for attempt := 0; attempt < request.MaxReportPolls; attempt++ {
		out, err := i.IAM.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId:    jobID,
			MaxItems: awsv2.Int32(request.MaxServicesPerRole),
		})
		if err != nil {
			return nil, false, err
		}
		details = out
		if out.JobStatus == iamtypes.JobStatusTypeCompleted {
			return out, out.IsTruncated || out.Marker != nil, nil
		}
		if attempt == request.MaxReportPolls-1 {
			break
		}
		if err := waitForIAMReportPoll(ctx, request.ReportPollInterval); err != nil {
			return nil, false, err
		}
	}
	if details == nil {
		details = &iam.GetServiceLastAccessedDetailsOutput{}
	}
	return details, details.IsTruncated || details.Marker != nil, nil
}

func waitForIAMReportPoll(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return nil
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func iamLastUsedStatus(observedAt time.Time, collectedAt time.Time) string {
	if observedAt.IsZero() || collectedAt.IsZero() {
		return "stale"
	}
	if collectedAt.Sub(observedAt) >= dormantAccessAge {
		return "stale"
	}
	return "observed"
}

func iamNeverUsedStatus(createdAt *time.Time, collectedAt time.Time) string {
	if createdAt == nil || collectedAt.IsZero() {
		return "unknown"
	}
	if collectedAt.Sub(createdAt.UTC()) >= dormantAccessAge {
		return "stale"
	}
	return "unknown"
}

func serviceLastAccessedEventName(hasLastAuthenticated bool) string {
	if hasLastAuthenticated {
		return "ServiceLastAccessed"
	}
	return "ServiceNeverAccessed"
}

func serviceLastAccessedAction(namespace string, hasLastAuthenticated bool) string {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		if hasLastAuthenticated {
			return "iam:ServiceLastAccessed"
		}
		return "iam:ServiceNeverAccessed"
	}
	if hasLastAuthenticated {
		return namespace + ":LastAuthenticated"
	}
	return namespace + ":NeverAccessed"
}

func (i *Ingester) collectAccessAnalyzer(ctx context.Context, request IngestRequest) ([]Signal, []Diagnostic, []CoverageGap, error) {
	analyzers, err := i.AccessAnalyzer.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{MaxResults: awsv2.Int32(request.MaxAnalyzers)})
	if err != nil {
		if isContextCancellation(err) {
			return nil, nil, nil, err
		}
		return nil, []Diagnostic{permissionAwareDiagnostic("access-analyzer", "access_analyzer_permission_denied", "access_analyzer_list_failed", fmt.Sprintf("Access Analyzer analyzers could not be listed: %v", err), "Grant access-analyzer:ListAnalyzers and retry.", err)}, []CoverageGap{{
			Capability:  "access_analyzer",
			Status:      permissionAwareStatus(err),
			Reason:      "Access Analyzer analyzers could not be listed.",
			Remediation: "Grant access-analyzer:ListAnalyzers and access-analyzer:ListFindings.",
		}}, nil
	}
	signals := []Signal{}
	diagnostics := []Diagnostic{}
	gaps := []CoverageGap{}
	if len(analyzers.Analyzers) == 0 {
		gaps = append(gaps, CoverageGap{
			Capability:  "access_analyzer",
			Status:      "empty",
			Reason:      "Access Analyzer returned no analyzers for this account and region.",
			Remediation: "Enable an account or organization analyzer before relying on external-access findings.",
		})
		return signals, diagnostics, gaps, nil
	}
	for idx, analyzer := range analyzers.Analyzers {
		if int32(idx) >= request.MaxAnalyzers {
			break
		}
		analyzerARN := awsv2.ToString(analyzer.Arn)
		analyzerName := awsv2.ToString(analyzer.Name)
		if analyzerARN == "" {
			continue
		}
		findings, nextToken, findErr := i.listAccessAnalyzerFindings(ctx, analyzerARN, analyzer.Type, request.MaxFindings)
		if findErr != nil {
			if isContextCancellation(findErr) {
				return nil, nil, nil, findErr
			}
			diagnostics = append(diagnostics, permissionAwareDiagnostic("access-analyzer:"+analyzerName, "access_analyzer_permission_denied", "access_analyzer_findings_failed", fmt.Sprintf("Access Analyzer findings could not be listed for %s: %v", analyzerName, findErr), "Grant access-analyzer:ListFindings and retry.", findErr))
			gaps = append(gaps, CoverageGap{
				Capability:  "access_analyzer",
				Status:      permissionAwareStatus(findErr),
				Reason:      fmt.Sprintf("Access Analyzer findings could not be listed for %s.", analyzerName),
				Remediation: "Grant access-analyzer:ListFindings for every analyzer used by runtime evidence collection.",
			})
			continue
		}
		for findingIdx, finding := range findings {
			if int32(findingIdx) >= request.MaxFindings {
				break
			}
			observed := request.CollectedAt
			if finding.UpdatedAt != nil {
				observed = finding.UpdatedAt.UTC()
			} else if finding.CreatedAt != nil {
				observed = finding.CreatedAt.UTC()
			}
			staleAt := observed
			if finding.AnalyzedAt != nil {
				staleAt = finding.AnalyzedAt.UTC()
			}
			resourceARN := finding.Resource
			ownerAccount := strings.TrimSpace(finding.ResourceOwnerAccount)
			if ownerAccount != "" && request.AccountID != "" && ownerAccount != request.AccountID {
				continue
			}
			eventName := firstNonEmpty(string(finding.FindingType), "Finding")
			actorPrincipal, actorType := accessAnalyzerActor(finding, analyzerARN)
			signals = append(signals, Signal{
				EventID:            "access-analyzer:" + sanitizeToken(firstNonEmpty(finding.ID, resourceARN, analyzerARN)),
				AccountID:          firstNonEmpty(ownerAccount, request.AccountID),
				Region:             request.Region,
				Category:           "access-analyzer",
				Scope:              strings.ToLower(strings.TrimSpace(string(analyzer.Type))),
				EventSource:        "access-analyzer.amazonaws.com",
				EventName:          eventName,
				Action:             accessAnalyzerAction(finding),
				ActorPrincipalARN:  actorPrincipal,
				ActorPrincipalType: actorType,
				TargetResourceARN:  resourceARN,
				TargetResourceType: firstNonEmpty(string(finding.ResourceType), "access_analyzer_resource"),
				TargetResourceName: displayNameFromARN(resourceARN),
				AnalyzerARN:        analyzerARN,
				AnalyzerName:       analyzerName,
				Status:             accessAnalyzerStatus(finding),
				Confidence:         accessAnalyzerConfidence(finding),
				ObservedAt:         observed,
				CollectedAt:        request.CollectedAt,
				StaleAt:            staleAt,
			})
		}
		if nextToken != nil {
			gaps = append(gaps, CoverageGap{
				Capability:  "access_analyzer",
				Status:      "history_truncated",
				Reason:      fmt.Sprintf("Access Analyzer findings for %s exceeded the bounded per-run finding budget.", analyzerName),
				Remediation: "Rerun with a larger findings budget or analyzer-specific pagination.",
			})
		}
	}
	if analyzers.NextToken != nil {
		gaps = append(gaps, CoverageGap{
			Capability:  "access_analyzer",
			Status:      "history_truncated",
			Reason:      "Access Analyzer listing exceeded the bounded per-run analyzer budget.",
			Remediation: "Rerun with a larger analyzer budget or shard by analyzer type.",
		})
	}
	return signals, diagnostics, gaps, nil
}

func (i *Ingester) listAccessAnalyzerFindings(ctx context.Context, analyzerARN string, analyzerType accessanalyzertypes.Type, maxFindings int32) ([]accessAnalyzerFinding, *string, error) {
	if accessAnalyzerUsesFindingsV2(analyzerType) {
		out, err := i.AccessAnalyzer.ListFindingsV2(ctx, &accessanalyzer.ListFindingsV2Input{
			AnalyzerArn: awsv2.String(analyzerARN),
			MaxResults:  awsv2.Int32(maxFindings),
		})
		if err != nil {
			return nil, nil, err
		}
		findings := make([]accessAnalyzerFinding, 0, len(out.Findings))
		for _, finding := range out.Findings {
			findings = append(findings, accessAnalyzerFinding{
				ID:                   awsv2.ToString(finding.Id),
				Resource:             awsv2.ToString(finding.Resource),
				ResourceOwnerAccount: awsv2.ToString(finding.ResourceOwnerAccount),
				ResourceType:         finding.ResourceType,
				Status:               finding.Status,
				Error:                awsv2.ToString(finding.Error),
				FindingType:          finding.FindingType,
				AnalyzedAt:           finding.AnalyzedAt,
				CreatedAt:            finding.CreatedAt,
				UpdatedAt:            finding.UpdatedAt,
			})
		}
		return findings, out.NextToken, nil
	}
	out, err := i.AccessAnalyzer.ListFindings(ctx, &accessanalyzer.ListFindingsInput{
		AnalyzerArn: awsv2.String(analyzerARN),
		MaxResults:  awsv2.Int32(maxFindings),
	})
	if err != nil {
		return nil, nil, err
	}
	findings := make([]accessAnalyzerFinding, 0, len(out.Findings))
	for _, finding := range out.Findings {
		findings = append(findings, accessAnalyzerFinding{
			ID:                   awsv2.ToString(finding.Id),
			Resource:             awsv2.ToString(finding.Resource),
			ResourceOwnerAccount: awsv2.ToString(finding.ResourceOwnerAccount),
			ResourceType:         finding.ResourceType,
			Status:               finding.Status,
			Error:                awsv2.ToString(finding.Error),
			FindingType:          accessanalyzertypes.FindingTypeExternalAccess,
			Action:               finding.Action,
			Principal:            finding.Principal,
			IsPublic:             finding.IsPublic,
			AnalyzedAt:           finding.AnalyzedAt,
			CreatedAt:            finding.CreatedAt,
			UpdatedAt:            finding.UpdatedAt,
		})
	}
	return findings, out.NextToken, nil
}

func accessAnalyzerUsesFindingsV2(analyzerType accessanalyzertypes.Type) bool {
	switch analyzerType {
	case accessanalyzertypes.TypeAccount, accessanalyzertypes.TypeOrganization:
		return false
	default:
		return true
	}
}

func permissionAwareDiagnostic(sourceID string, permissionCode string, fallbackCode string, message string, remediation string, err error) Diagnostic {
	code := fallbackCode
	if isPermissionDenied(err) {
		code = permissionCode
	}
	return Diagnostic{SourceID: sourceID, Code: code, Message: message, Remediation: remediation, Retryable: true}
}

func permissionAwareStatus(err error) string {
	if isPermissionDenied(err) {
		return "permission_denied"
	}
	return "partial_failure"
}

func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "accessdenied") || strings.Contains(msg, "access denied") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "not authorized")
}

func isContextCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func allSignalCollectorsPermissionDenied(gaps []CoverageGap) bool {
	denied := map[string]bool{}
	for _, gap := range gaps {
		if gap.Status == "permission_denied" {
			denied[gap.Capability] = true
		}
	}
	return denied["iam_last_used"] && denied["access_analyzer"]
}

func accessAnalyzerStatus(finding accessAnalyzerFinding) string {
	switch finding.Status {
	case accessanalyzertypes.FindingStatusActive:
		return "observed"
	case accessanalyzertypes.FindingStatusResolved:
		return "resolved"
	case accessanalyzertypes.FindingStatusArchived:
		return "archived"
	default:
		return strings.ToLower(strings.TrimSpace(string(finding.Status)))
	}
}

func accessAnalyzerConfidence(finding accessAnalyzerFinding) float64 {
	if strings.TrimSpace(finding.Error) != "" {
		return 0.54
	}
	if finding.IsPublic != nil && *finding.IsPublic {
		return 0.9
	}
	if finding.Status == accessanalyzertypes.FindingStatusActive {
		return 0.84
	}
	return 0.72
}

func accessAnalyzerAction(finding accessAnalyzerFinding) string {
	if len(finding.Action) > 0 {
		return strings.Join(finding.Action, ",")
	}
	eventName := strings.TrimSpace(string(finding.FindingType))
	if eventName == "" {
		return "access-analyzer:Finding"
	}
	return "access-analyzer:" + eventName
}

func accessAnalyzerActor(finding accessAnalyzerFinding, analyzerARN string) (string, string) {
	if len(finding.Principal) > 0 || finding.FindingType == accessanalyzertypes.FindingTypeExternalAccess {
		return principalFromFinding(finding.Principal), "external_principal"
	}
	switch finding.FindingType {
	case accessanalyzertypes.FindingTypeUnusedIamRole,
		accessanalyzertypes.FindingTypeUnusedIamUserAccessKey,
		accessanalyzertypes.FindingTypeUnusedIamUserPassword,
		accessanalyzertypes.FindingTypeUnusedPermission:
		if strings.TrimSpace(finding.Resource) != "" {
			return finding.Resource, principalTypeFromARN(finding.Resource)
		}
	}
	return firstNonEmpty(analyzerARN, "access-analyzer:"+strings.ToLower(strings.TrimSpace(string(finding.FindingType)))), "access_analyzer"
}

func principalFromFinding(principal map[string]string) string {
	if len(principal) == 0 {
		return "access-analyzer:external-principal"
	}
	keys := make([]string, 0, len(principal))
	for key := range principal {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+principal[key])
	}
	return strings.Join(parts, ";")
}

func principalTypeFromARN(arn string) string {
	switch {
	case strings.Contains(arn, ":role/"):
		return "iam_role"
	case strings.Contains(arn, ":user/"):
		return "iam_user"
	case strings.Contains(arn, ":assumed-role/"):
		return "assumed_role"
	default:
		return "aws_principal"
	}
}

func displayNameFromARN(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if slash := strings.LastIndex(ref, "/"); slash >= 0 && slash < len(ref)-1 {
		return ref[slash+1:]
	}
	if colon := strings.LastIndex(ref, ":"); colon >= 0 && colon < len(ref)-1 {
		return ref[colon+1:]
	}
	return ref
}

func sanitizeToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(":", "-", "/", "-", "_", "-", " ", "-", ".", "-", "@", "-")
	value = replacer.Replace(value)
	parts := strings.Split(value, "-")
	kept := parts[:0]
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "-")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
