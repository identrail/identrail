package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	rawKindECRRepositoryMetadata       = "ecr_repository_metadata"
	ecrRepositoryMetadataCollectorName = "ecr_repository_metadata"
	ecrServiceName                     = "ecr"
)

// ECRRepositoryMetadata is the metadata-only view of one ECR repository. It
// intentionally excludes image layers, manifests, SBOM contents, scan finding
// details, and image payloads.
type ECRRepositoryMetadata struct {
	awscontract.ServiceCollectorRecord

	RepositoryARN  string `json:"repository_arn,omitempty"`
	RepositoryName string `json:"repository_name,omitempty"`
	RegistryID     string `json:"registry_id,omitempty"`
	RepositoryURI  string `json:"repository_uri,omitempty"`

	ImageTagMutability        string `json:"image_tag_mutability,omitempty"`
	EncryptionType            string `json:"encryption_type,omitempty"`
	KMSKeyID                  string `json:"kms_key_id,omitempty"`
	ScanOnPush                bool   `json:"scan_on_push,omitempty"`
	EnhancedScanningKnown     bool   `json:"enhanced_scanning_known,omitempty"`
	EnhancedScanningEnabled   bool   `json:"enhanced_scanning_enabled,omitempty"`
	HasRepositoryPolicy       bool   `json:"has_repository_policy,omitempty"`
	RepositoryPolicyStatement int    `json:"repository_policy_statement_count,omitempty"`
	HasLifecyclePolicy        bool   `json:"has_lifecycle_policy,omitempty"`
	LifecycleRuleCount        int    `json:"lifecycle_rule_count,omitempty"`
	ImageCount                int    `json:"image_count,omitempty"`
	TaggedImageCount          int    `json:"tagged_image_count,omitempty"`
	UntaggedImageCount        int    `json:"untagged_image_count,omitempty"`
	LastPushedAt              string `json:"last_pushed_at,omitempty"`
	CreatedAt                 string `json:"created_at,omitempty"`

	Tags map[string]string `json:"tags,omitempty"`

	SensitivityClassification string   `json:"sensitivity_classification,omitempty"`
	ExposureClassification    string   `json:"exposure_classification,omitempty"`
	ExposureReasons           []string `json:"exposure_reasons,omitempty"`

	ReferenceCount       int                      `json:"reference_count,omitempty"`
	ReferencedBy         []ImageWorkloadReference `json:"referenced_by,omitempty"`
	UnresolvedReferences []ImageWorkloadReference `json:"unresolved_references,omitempty"`
}

type ImageWorkloadReference struct {
	SourceService string  `json:"source_service,omitempty"`
	WorkloadID    string  `json:"workload_id,omitempty"`
	WorkloadType  string  `json:"workload_type,omitempty"`
	WorkloadName  string  `json:"workload_name,omitempty"`
	ResourceARN   string  `json:"resource_arn,omitempty"`
	ResourceID    string  `json:"resource_id,omitempty"`
	ImageURI      string  `json:"image_uri"`
	ReferenceKind string  `json:"reference_kind"`
	Confidence    float64 `json:"confidence"`
}

type ECRRepositoryMetadataPage struct {
	Records     []ECRRepositoryMetadata
	NextToken   string
	Diagnostics []providers.SourceError
}

type ECRRepositoryMetadataAPI interface {
	ListRepositoryMetadata(ctx context.Context, nextToken string, pageSize int32) (ECRRepositoryMetadataPage, error)
}

type ECRRepositoryMetadataCollector struct {
	client   ECRRepositoryMetadataAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

type ECRRepositoryMetadataOption func(*ECRRepositoryMetadataCollector)

func WithECRRepositoryMetadataClock(now func() time.Time) ECRRepositoryMetadataOption {
	return func(c *ECRRepositoryMetadataCollector) {
		if now != nil {
			c.now = now
		}
	}
}

func NewECRRepositoryMetadataCollector(client ECRRepositoryMetadataAPI, opts ...ECRRepositoryMetadataOption) *ECRRepositoryMetadataCollector {
	c := &ECRRepositoryMetadataCollector{
		client:   client,
		pageSize: defaultPageSize,
		maxPages: defaultMaxPages,
		retry: RetryPolicy{
			MaxRetries: defaultRetryCount,
			BaseDelay:  defaultBaseDelay,
			MaxDelay:   defaultMaxDelay,
		},
		jitter: defaultRetryJitterRatio,
		sleep:  defaultSleeper,
		randFn: rand.Float64,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *ECRRepositoryMetadataCollector) ServiceName() string { return ecrServiceName }

func (c *ECRRepositoryMetadataCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: ecrServiceName})
	return assets, err
}

func (c *ECRRepositoryMetadataCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("ecr repository metadata collector requires client")
	}
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	assets := []providers.RawAsset{}
	issues := []providers.SourceError{}
	addIssue := func(issue providers.SourceError) {
		if strings.TrimSpace(issue.Code) != "" && strings.TrimSpace(issue.Message) != "" {
			issues = append(issues, issue)
		}
	}
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()
	for page := 1; ; page++ {
		if page > c.maxPages {
			addIssue(ecrRepositoryMetadataDiagnostic("ecr_repository_metadata_page_limit_exceeded", firstNonEmptyAWSValue(nextToken, "page"), fmt.Sprintf("ecr repository metadata collection exceeded max pages (%d)", c.maxPages), false))
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("ecr repository metadata collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (ECRRepositoryMetadataPage, error) {
			return c.client.ListRepositoryMetadata(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list ecr repository metadata page %d: %w", page, err)
			addIssue(ecrRepositoryMetadataDiagnostic("ecr_repository_metadata_page_failed", firstNonEmptyAWSValue(nextToken, "page"), wrapped.Error(), isRetryable(err)))
			if len(assets) > 0 {
				return assets, append([]providers.SourceError(nil), issues...), wrapped
			}
			return nil, append([]providers.SourceError(nil), issues...), wrapped
		}
		for _, diagnostic := range response.Diagnostics {
			addIssue(diagnostic)
		}
		for _, record := range response.Records {
			normalized := normalizeECRRepositoryMetadataScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.RepositoryARN) == "" && strings.TrimSpace(normalized.RepositoryURI) == "" {
				addIssue(ecrRepositoryMetadataDiagnostic("malformed_ecr_repository_record", "", "skipped ecr repository record without ARN or URI", false))
				continue
			}
			sourceID := ecrRepositoryMetadataSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal ecr repository metadata %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindECRRepositoryMetadata,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}
		if strings.TrimSpace(response.NextToken) == "" {
			break
		}
		nextToken = strings.TrimSpace(response.NextToken)
	}
	return assets, append([]providers.SourceError(nil), issues...), nil
}

func normalizeECRRepositoryMetadataScope(scope AWSCollectorScope, record ECRRepositoryMetadata, collectedAt time.Time) ECRRepositoryMetadata {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID, accountIDFromARN(record.RepositoryARN), ecrAccountIDFromURI(record.RepositoryURI))
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region, regionFromARN(record.RepositoryARN), ecrRegionFromURI(record.RepositoryURI))
	normalized.Service = firstNonEmptyAWSValue(record.Service, ecrServiceName)
	normalized.RepositoryName = firstNonEmptyAWSValue(record.RepositoryName, ecrRepositoryNameFromARN(record.RepositoryARN), ecrRepositoryNameFromURI(record.RepositoryURI))
	normalized.RegistryID = firstNonEmptyAWSValue(record.RegistryID, normalized.AccountID)
	normalized.RepositoryURI = firstNonEmptyAWSValue(record.RepositoryURI, ecrRepositoryURI(normalized.AccountID, normalized.Region, normalized.RepositoryName))
	normalized.RepositoryARN = firstNonEmptyAWSValue(record.RepositoryARN, ecrRepositoryARN(normalized.AccountID, normalized.Region, normalized.RepositoryName))
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "ecr_repository")
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.RepositoryName, normalized.RepositoryURI)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.RepositoryARN, normalized.RepositoryURI)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "ecr_repository_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.RepositoryARN, normalized.RepositoryURI)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, ecrRepositoryMetadataCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-ecr-repository-metadata-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.ImageTagMutability = canonicalECRMutability(record.ImageTagMutability)
	normalized.EncryptionType = strings.ToLower(strings.TrimSpace(record.EncryptionType))
	normalized.KMSKeyID = strings.TrimSpace(record.KMSKeyID)
	normalized.Tags = copyTags(record.Tags)
	normalized.ReferencedBy = normalizeImageWorkloadReferences(record.ReferencedBy)
	normalized.UnresolvedReferences = normalizeImageWorkloadReferences(record.UnresolvedReferences)
	normalized.ReferenceCount = len(normalized.ReferencedBy)
	normalized.SensitivityClassification = classifyECRRepositorySensitivity(normalized)
	normalized.ExposureClassification, normalized.ExposureReasons = classifyECRRepositoryExposure(normalized)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = ecrRepositoryMetadataConfidence(normalized)
	}
	return normalized
}

func normalizeImageWorkloadReferences(refs []ImageWorkloadReference) []ImageWorkloadReference {
	if len(refs) == 0 {
		return nil
	}
	out := make([]ImageWorkloadReference, 0, len(refs))
	seen := map[string]struct{}{}
	for _, ref := range refs {
		ref.ImageURI = strings.TrimSpace(ref.ImageURI)
		if ref.ImageURI == "" {
			continue
		}
		ref.SourceService = strings.TrimSpace(ref.SourceService)
		ref.WorkloadID = strings.TrimSpace(ref.WorkloadID)
		ref.WorkloadType = strings.TrimSpace(ref.WorkloadType)
		ref.WorkloadName = strings.TrimSpace(ref.WorkloadName)
		ref.ResourceARN = strings.TrimSpace(ref.ResourceARN)
		ref.ResourceID = strings.TrimSpace(ref.ResourceID)
		ref.ReferenceKind = firstNonEmptyAWSValue(ref.ReferenceKind, "container_image")
		if ref.Confidence <= 0 {
			ref.Confidence = 0.82
		}
		key := strings.ToLower(strings.Join([]string{ref.SourceService, ref.WorkloadID, ref.ResourceID, ref.ImageURI}, "|"))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ImageURI+out[i].WorkloadID < out[j].ImageURI+out[j].WorkloadID
	})
	return out
}

func classifyECRRepositorySensitivity(record ECRRepositoryMetadata) string {
	switch {
	case record.ReferenceCount > 0:
		return "runtime_image_repository"
	case strings.EqualFold(record.EncryptionType, "kms"):
		return "customer_encrypted_repository"
	default:
		return "image_repository"
	}
}

func classifyECRRepositoryExposure(record ECRRepositoryMetadata) (string, []string) {
	reasons := []string{}
	if record.HasRepositoryPolicy {
		reasons = append(reasons, "repository_policy_present")
	}
	if record.ImageTagMutability != "immutable" {
		reasons = append(reasons, "mutable_tags")
	}
	if !record.ScanOnPush && !record.EnhancedScanningEnabled {
		reasons = append(reasons, "scan_on_push_disabled")
	}
	if record.ReferenceCount > 0 {
		reasons = append(reasons, "referenced_by_workloads")
	}
	switch {
	case !record.ScanOnPush && !record.EnhancedScanningEnabled && record.ImageTagMutability != "immutable":
		return "mutable_unscanned", reasons
	case record.ReferenceCount > 0 && record.HasRepositoryPolicy:
		return "referenced_policy_controlled", reasons
	case record.ReferenceCount > 0:
		return "referenced", reasons
	default:
		return "metadata_only", reasons
	}
}

func ecrRepositoryMetadataConfidence(record ECRRepositoryMetadata) float64 {
	switch {
	case strings.TrimSpace(record.RepositoryARN) != "" && strings.TrimSpace(record.RepositoryURI) != "" && record.ReferenceCount > 0:
		return 0.94
	case strings.TrimSpace(record.RepositoryARN) != "" && strings.TrimSpace(record.RepositoryURI) != "":
		return 0.9
	default:
		return 0.72
	}
}

func canonicalECRMutability(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "IMMUTABLE":
		return "immutable"
	case "MUTABLE":
		return "mutable"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func ecrRepositoryMetadataSourceID(record ECRRepositoryMetadata) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.RepositoryARN,
		record.RepositoryURI,
		record.Region,
	}), "|")
}

func ecrRepositoryResourceID(repositoryARN string) string {
	return "aws:resource:ecr-repository:" + strings.TrimSpace(repositoryARN)
}

func ecrRepositoryARN(accountID string, region string, name string) string {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(region) == "" || strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:ecr:%s:%s:repository/%s", awsPartitionForRegion(region), region, accountID, strings.TrimSpace(name))
}

func ecrRepositoryURI(accountID string, region string, name string) string {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(region) == "" || strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", strings.TrimSpace(accountID), strings.TrimSpace(region), strings.TrimSpace(name))
}

func ecrRepositoryNameFromARN(arn string) string {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return strings.TrimPrefix(parts[5], "repository/")
}

func ecrAccountIDFromURI(uri string) string {
	host := strings.SplitN(strings.TrimSpace(uri), "/", 2)[0]
	parts := strings.Split(host, ".")
	if len(parts) > 0 && len(parts[0]) == 12 {
		return parts[0]
	}
	return ""
}

func ecrRegionFromURI(uri string) string {
	host := strings.SplitN(strings.TrimSpace(uri), "/", 2)[0]
	parts := strings.Split(host, ".")
	if len(parts) >= 4 && parts[1] == "dkr" && parts[2] == "ecr" {
		return parts[3]
	}
	return ""
}

func ecrRepositoryNameFromURI(uri string) string {
	parts := strings.SplitN(strings.TrimSpace(uri), "/", 2)
	if len(parts) < 2 {
		return ""
	}
	repository := parts[1]
	if idx := strings.IndexAny(repository, ":@"); idx > 0 {
		repository = repository[:idx]
	}
	return strings.TrimSpace(repository)
}

func ecrRepositoryMetadataDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: ecrRepositoryMetadataCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

var _ AWSServiceCollector = (*ECRRepositoryMetadataCollector)(nil)
var _ providers.Collector = (*ECRRepositoryMetadataCollector)(nil)
