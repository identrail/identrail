package awssignals

import (
	"context"
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
}

type IngestRequest struct {
	AccountID          string
	Region             string
	MaxRoles           int32
	MaxServicesPerRole int32
	MaxAnalyzers       int32
	MaxFindings        int32
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

	result := IngestResult{Status: "ready"}
	if i.IAM != nil {
		signals, diagnostics, gaps := i.collectIAMLastUsed(ctx, request)
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
		signals, diagnostics, gaps := i.collectAccessAnalyzer(ctx, request)
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
	if len(result.Signals) == 0 && hasPermissionDeniedDiagnostic(result.Diagnostics) {
		result.Status = "blocked"
		result.FailureReasons = []string{"IAM last-used and Access Analyzer permissions are unavailable"}
		result.RemediationHints = []string{"Grant metadata-only iam:ListRoles, iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails, access-analyzer:ListAnalyzers, and access-analyzer:ListFindings."}
	}
	return result, nil
}

func (i *Ingester) collectIAMLastUsed(ctx context.Context, request IngestRequest) ([]Signal, []Diagnostic, []CoverageGap) {
	out, err := i.IAM.ListRoles(ctx, &iam.ListRolesInput{MaxItems: awsv2.Int32(request.MaxRoles)})
	if err != nil {
		return nil, []Diagnostic{permissionAwareDiagnostic("iam", "iam_last_used_permission_denied", "iam_last_used_failed", fmt.Sprintf("IAM role listing failed: %v", err), "Grant metadata-only iam:ListRoles and retry.", err)}, []CoverageGap{{
			Capability:  "iam_last_used",
			Status:      permissionAwareStatus(err),
			Reason:      "IAM roles could not be listed for last-used collection.",
			Remediation: "Grant iam:ListRoles plus service last-accessed read APIs.",
		}}
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
				Status:             "stale",
				Confidence:         0.68,
				ObservedAt:         request.CollectedAt,
				CollectedAt:        request.CollectedAt,
				StaleAt:            request.CollectedAt,
			})
		}
		job, genErr := i.IAM.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
			Arn:         awsv2.String(roleARN),
			Granularity: iamtypes.AccessAdvisorUsageGranularityTypeServiceLevel,
		})
		if genErr != nil {
			diagnostics = append(diagnostics, permissionAwareDiagnostic("iam:"+roleName, "iam_last_used_permission_denied", "iam_last_used_generation_failed", fmt.Sprintf("IAM service last-used report could not be generated for %s: %v", roleName, genErr), "Grant iam:GenerateServiceLastAccessedDetails and retry.", genErr))
			continue
		}
		details, getErr := i.IAM.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId:    job.JobId,
			MaxItems: awsv2.Int32(request.MaxServicesPerRole),
		})
		if getErr != nil {
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
		for svcIdx, service := range details.ServicesLastAccessed {
			if int32(svcIdx) >= request.MaxServicesPerRole {
				break
			}
			serviceNamespace := awsv2.ToString(service.ServiceNamespace)
			serviceName := firstNonEmpty(awsv2.ToString(service.ServiceName), serviceNamespace)
			actor := firstNonEmpty(awsv2.ToString(service.LastAuthenticatedEntity), roleARN)
			region := firstNonEmpty(awsv2.ToString(service.LastAuthenticatedRegion), request.Region)
			lastAuthenticated := request.CollectedAt
			status := "stale"
			confidence := 0.64
			if service.LastAuthenticated != nil {
				lastAuthenticated = service.LastAuthenticated.UTC()
				status = iamLastUsedStatus(lastAuthenticated, request.CollectedAt)
				confidence = 0.86
				if status == "stale" {
					confidence = 0.78
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
	return signals, diagnostics, gaps
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

func (i *Ingester) collectAccessAnalyzer(ctx context.Context, request IngestRequest) ([]Signal, []Diagnostic, []CoverageGap) {
	analyzers, err := i.AccessAnalyzer.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{MaxResults: awsv2.Int32(request.MaxAnalyzers)})
	if err != nil {
		return nil, []Diagnostic{permissionAwareDiagnostic("access-analyzer", "access_analyzer_permission_denied", "access_analyzer_list_failed", fmt.Sprintf("Access Analyzer analyzers could not be listed: %v", err), "Grant access-analyzer:ListAnalyzers and retry.", err)}, []CoverageGap{{
			Capability:  "access_analyzer",
			Status:      permissionAwareStatus(err),
			Reason:      "Access Analyzer analyzers could not be listed.",
			Remediation: "Grant access-analyzer:ListAnalyzers and access-analyzer:ListFindings.",
		}}
	}
	signals := []Signal{}
	diagnostics := []Diagnostic{}
	gaps := []CoverageGap{}
	for idx, analyzer := range analyzers.Analyzers {
		if int32(idx) >= request.MaxAnalyzers {
			break
		}
		analyzerARN := awsv2.ToString(analyzer.Arn)
		analyzerName := awsv2.ToString(analyzer.Name)
		if analyzerARN == "" {
			continue
		}
		findings, findErr := i.AccessAnalyzer.ListFindings(ctx, &accessanalyzer.ListFindingsInput{
			AnalyzerArn: awsv2.String(analyzerARN),
			MaxResults:  awsv2.Int32(request.MaxFindings),
		})
		if findErr != nil {
			diagnostics = append(diagnostics, permissionAwareDiagnostic("access-analyzer:"+analyzerName, "access_analyzer_permission_denied", "access_analyzer_findings_failed", fmt.Sprintf("Access Analyzer findings could not be listed for %s: %v", analyzerName, findErr), "Grant access-analyzer:ListFindings and retry.", findErr))
			continue
		}
		for findingIdx, finding := range findings.Findings {
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
			resourceARN := awsv2.ToString(finding.Resource)
			signals = append(signals, Signal{
				EventID:            "access-analyzer:" + sanitizeToken(firstNonEmpty(awsv2.ToString(finding.Id), resourceARN, analyzerARN)),
				AccountID:          firstNonEmpty(awsv2.ToString(finding.ResourceOwnerAccount), request.AccountID),
				Region:             request.Region,
				Category:           "access-analyzer",
				Scope:              strings.ToLower(strings.TrimSpace(string(analyzer.Type))),
				EventSource:        "access-analyzer.amazonaws.com",
				EventName:          "Finding",
				Action:             firstNonEmpty(strings.Join(finding.Action, ","), "access-analyzer:Finding"),
				ActorPrincipalARN:  principalFromFinding(finding.Principal),
				ActorPrincipalType: "external_principal",
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
		if findings.NextToken != nil {
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
	return signals, diagnostics, gaps
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

func hasPermissionDeniedDiagnostic(diagnostics []Diagnostic) bool {
	if len(diagnostics) == 0 {
		return false
	}
	for _, diagnostic := range diagnostics {
		if !strings.Contains(diagnostic.Code, "permission_denied") {
			return false
		}
	}
	return true
}

func accessAnalyzerStatus(finding accessanalyzertypes.FindingSummary) string {
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

func accessAnalyzerConfidence(finding accessanalyzertypes.FindingSummary) float64 {
	if finding.Error != nil && strings.TrimSpace(*finding.Error) != "" {
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
